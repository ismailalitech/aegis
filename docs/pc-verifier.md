# The fleet loop on an ordinary Linux host

`gateway/aegisd/fleet.py` runs on any Linux machine with Python 3, the repository's `.venv` (the `cryptography`
package with OpenSSL 3.5 or later for ML-DSA-65 and ML-KEM-768, or liboqs) and the `openssl` tool. On such a host it
runs as `--platform linux` (the default anywhere but the PolarFire). Three things change compared with the gateway:

| | gateway (`--platform polarfire`) | Linux host (`--platform linux`) |
|---|---|---|
| state (identity, credentials, verdicts) | `/var/lib/aegis` | `$AEGIS_STATE_DIR`, else `/var/lib/aegis` as root, else `~/.local/state/aegis` |
| `enforce_cmd` in the policy | run | not run unless `--enforce` (observe-only) |
| credentials (`"provision": true`) | issued | issued only where the entry's `verifier_pin_sha256` is this host's key |

Attestation and the admission decision are the same code on both. A host verifier needs no identity of its own to
attest; it needs one only to issue credentials.

## What works today, without touching any firmware

The host attests both STM32H573 boards and the FRDM-RW612 and decides admission exactly as the gateway does: fresh
challenge, ML-DSA-65 quote signature against the pinned endpoint key, challenge match, every measurement in the
allowed list, the RW612's profile pinned (`aegis-rw612-tfm-v1`, trust `trustzone`). It does not issue credentials,
because no current endpoint image would accept one from it.

## Credentials: why the host does not issue them

Every endpoint image pins one verifier key at build time: `gateway_pk.h`, written by `tools/gen_gateway_pin.py` and
included by the STM32 partition, the RW612 TF-M partition and prover, and the ZynqMP TA. `PQKEMFIN` is accepted only
with a credential signed by that key. Today that is the gateway's key (sha256 of the public key `0c1d7820...`).

- A credential signed by the host's key is refused (`PSA_ERROR_INVALID_SIGNATURE`, `ERR cred signature` on the
  RW612); the endpoint keeps its established session.
- Trying is not free: `PQKEMINIT` cancels whatever exchange is pending, so a host that tried while the gateway was
  between its own `PQKEMINIT` and `PQKEMFIN` would break the gateway's provisioning.
- Copying the gateway's secret key to the host is not an option: two machines would then speak as one verifier.

So `fleet.py --platform linux` never starts a KEM exchange unless the policy entry says the endpoint pins this host's
key: `"verifier_pin_sha256": "<sha256 of this host's ML-DSA-65 public key>"`. Without it, or with another key's hash,
the verdict carries `credential: not issued: ...` and the endpoint gets nothing but the quote request. `fleet.py
check` shows the decision per entry without contacting anything.

The pin is the SHA-256 of the public key, not the identity record digest that `aegisd.py init` prints:

    .venv/bin/python tools/gen_gateway_pin.py --sha256-only --identity ~/.local/state/aegis/identity.json

To make the host the credential issuer (a firmware change, not done here):

1. `aegisd.py init --platform linux --state ~/.local/state/aegis` (once; the key is a 0600 file, software trust, until
   a TPM backend exists);
2. `tools/gen_gateway_pin.py --identity ~/.local/state/aegis/identity.json` writes `gateway_pk.h` with the host's key;
3. rebuild and reflash each endpoint (STM32 secure image, RW612 TF-M image);
4. in the host's policy set `"provision": true` and `"verifier_pin_sha256"` for those endpoints, and remove
   `"provision"` from the gateway's policy for them (the gateway's credentials would now be refused).

An image pins one key, so exactly one verifier issues credentials to a given endpoint; any number can attest it.
Pinning a short list of keys is possible in firmware, but each endpoint holds one session, so two issuers would
replace each other's session every cycle. One issuer per endpoint is the design to keep.

## Two verifiers on one endpoint

What the endpoint code says (`aegis_pq_attest.c`, `rw612/tfm/aegis_pq/aegis_pq.c`, the two provers' `main.c`):

- `PQCHAL` (quote) reads no session state and changes none (every message lets the STM32 partition end a session
  that has already outlived its credential, which the next message of any kind would do as well). Attesting from a
  second verifier cannot disturb the first one's session, credential or heartbeat counter.
- `PQKEMINIT` cancels a pending exchange (not an established session); a foreign `PQKEMFIN` is refused and the session
  kept. The host never sends either without the pin (above).
- `PQHB` needs the session key; the counter is shared but only rises, so another verifier's heartbeat would not
  break the gateway's "counter must rise" check. The host sends none without a session of its own.
- The network side is the problem: both provers serve one TCP connection at a time and reset a second one at once
  (`tcp_abort` in `on_accept`). A verifier that connects while the other is being served gets a reset. With the
  gateway's current `fleet.py`, that fails the cycle's attestation: the endpoint is reported QUARANTINED for one
  cycle, its credential is revoked on the gateway and provisioned again in the next cycle (a new session; no network
  effect while the gateway policy has no `enforce_cmd`).

This branch's `fleet.py` retries requests that change nothing on the endpoint (quote, key, session id, heartbeat)
when the endpoint resets or closes the connection without a byte: up to 3 more attempts, 0.4 to 1.2 s apart.
Provisioning steps are never retried. Once both verifiers run it, attesting the same endpoint concurrently is
harmless. Until the gateway runs it, use one of the two procedures below.

## Runbook

Addresses come from `bench.env` (`GATEWAY`, `STM32`, `STM32_2`, `RW612`; see `bench.env.example`). Run from the
checkout.

### Set up (once)

    set -a; . ./bench.env; set +a
    mkdir -p ~/.config/aegis/keys ~/.local/state/aegis
    sed -e "s/192.0.2.20/${STM32%:*}/" -e "s/192.0.2.21/${STM32_2%:*}/" -e "s/192.0.2.22/${RW612%:*}/" \
        gateway/policy/fleet.pc.example.json > ~/.config/aegis/fleet.pc.json
    for k in stm32h573-dk stm32h573-dk-2 frdm-rw612; do
        scp -o BatchMode=yes root@$GATEWAY:/root/aegis/gateway/policy/keys/$k.mldsa65.pub ~/.config/aegis/keys/
    done
    cp gateway/policy/keys/tfm-dev-iak.pub.pem ~/.config/aegis/keys/
    .venv/bin/python gateway/aegisd/fleet.py check ~/.config/aegis/fleet.pc.json --platform linux

The endpoint keys are the gateway's pins (public keys), so the host trusts the same keys the gateway enrolled; do not
re-enrol them from the network (`enroll-pq` is trust on first use). If the measurements in the example are stale
(new firmware), copy the `allowed` lists from the gateway's policy. `check` must print `ok` for all three and
`observe-only`.

### One attestation round, gateway untouched

The gateway writes `/var/lib/aegis/fleet-state.json` at the end of each cycle and then sleeps 30 s. Start right after
a write, and the host's round (under a second) falls inside the sleep:

    until [ "$(ssh -o BatchMode=yes root@$GATEWAY 'echo $(( $(date +%s) - $(stat -c %Y /var/lib/aegis/fleet-state.json) ))')" -le 4 ]; do sleep 1; done
    .venv/bin/python gateway/aegisd/fleet.py once ~/.config/aegis/fleet.pc.json --platform linux --no-credentials

(Following `journalctl -f` over ssh is not a reliable trigger: through a pipe its output arrives late.)

### The loop, continuously

Stop the gateway's loop for the duration (and the guard timer `tools/regression.sh` may have left, which would start
it again):

    ssh -o BatchMode=yes root@$GATEWAY 'systemctl stop aegis-expiry-guard.timer 2>/dev/null; systemctl stop aegis-fleet'
    .venv/bin/python gateway/aegisd/fleet.py watch ~/.config/aegis/fleet.pc.json --platform linux --interval 30
    # Ctrl-C to end, then:
    ssh -o BatchMode=yes root@$GATEWAY 'systemctl start aegis-fleet'

While the gateway's loop is stopped the endpoints keep their sessions (they end them on their own clock, an hour and a
sixteenth after provisioning); a gateway stopped for more than about 55 minutes provisions again when it restarts. If
the gateway policy had an `enforce_cmd`, stopping its loop would also drop every endpoint from the admitted set within
the admission TTL; the bench policy has none.

As a service (systemd user unit; paths inside assume the checkout in `~/aegis`):

    install -D -m 0644 gateway/systemd/aegis-fleet-pc.service ~/.config/systemd/user/aegis-fleet-pc.service
    systemctl --user daemon-reload && systemctl --user start aegis-fleet-pc
    journalctl --user -u aegis-fleet-pc -f

## What "admitted" looks like

`once` prints a JSON list; an admitted endpoint has `"admitted": true`, `"reasons": []` and
`"pq_signature": "ML-DSA-65 valid"`, plus the reported `measurements`; the RW612 also has `"trust": "trustzone"`.
There is no `credential` field in an attestation-only run.

    [{"endpoint": "stm32h573-dk",   "kind": "aegis-pq",     "admitted": true, "reasons": [], "pq_signature": "ML-DSA-65 valid", ...},
     {"endpoint": "stm32h573-dk-2", "kind": "aegis-pq",     "admitted": true, "reasons": [], ...},
     {"endpoint": "frdm-rw612",     "kind": "aegis-device", "admitted": true, "reasons": [], "trust": "trustzone", ...}]

`watch` prints one line per endpoint and cycle (and writes `~/.local/state/aegis/fleet-state.json`):

    aegis-fleet: platform linux, observe-only, credentials only where verifier_pin_sha256 names this verifier, state ...
    07:17:46 stm32h573-dk ADMITTED
    07:17:46 stm32h573-dk-2 ADMITTED
    07:17:46 frdm-rw612 ADMITTED (trustzone trust)

Anything else is QUARANTINED with the reasons on the same line: `no attestation: ...` (no answer, or `busy with another
verifier` after the retries), `ML-DSA-65 quote signature invalid` (wrong key pinned), `component NSPE not allowed
(measurement ...)` (firmware not in the policy), `challenge mismatch` (replay).

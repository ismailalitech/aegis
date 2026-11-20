# Endorsed enrolment

How a verifier comes to trust a device's ML-DSA-65 key, since plan step 8 (WP4). Before it, enrolment was trust on
first use: `fleet.py enroll-pq` asked an address for a key and pinned whatever came back, and nothing said that the
key in `keys/<name>.mldsa65.pub` belonged to a device anyone had looked at. Now a verifier can require an
**endorsement**: a record, signed by an endorser it trusts, that names one device, its family and exactly one key.

| Piece | Where | Runs on |
|---|---|---|
| record format, checks | `common/endorsement.py` | everywhere (standard library and `common/mldsa.py` only) |
| the endorser's tool | `provision/aegis_provision.py` | the bench PC |
| the verifier's rules, `enroll-endorsed` | `gateway/aegisd/fleet.py` | the gateway and the PC verifier (`--platform polarfire` and `linux`: the same code) |
| the check on real boards | `tests/board/endorsement_check.py` | wherever a policy is |

No firmware changed for this. The tool uses two commands every endpoint image has had from the start, `PQKEY` and
`PQCHAL`; the Prover SDK's core is untouched (`tests/host/test_endorsement.py`, `SdkCore`, enrols the core as built).

## What an endorsement proves on this bench, and what it does not

Read this before relying on one.

**What the endorser does.** It connects to an address, asks for the identity key, sends a fresh 32-byte challenge and
gets a quote. It checks that the quote is signed by that key for that challenge, that it is of the entry's kind and
profile, and that every component it reports is in the reference list. Then it signs: *this key answered for this
device at this time and reported these components*. Before it hands the record out it asks for a second quote and
runs the verifier's own attestation with that record required.

**What follows from that.** Whatever answered at that address holds the private key (it signed a challenge nobody
could have known) and reported the reference firmware. If the only thing that could answer there was the board on the
operator's desk, the key is that board's key. The verifier then refuses any other key under that device's name: a key
file that was replaced, a record made for another device, a record nobody it trusts signed.

**What does not follow.**

- **That the thing was a genuine chip.** Nothing in a quote is rooted in a manufacturer's credential. The RW612's and
  the ZynqMP's quotes are claims signed by the device key alone, and the STM32's token is signed with TF-M's
  published development key, so a program that knows the reference measurements can produce a quote the endorser
  accepts, under a key of its own. The appraisal at the bench catches a wrong or broken image, not an impostor. What
  keeps an impostor out is the cable: **the endorsement is exactly as good as the operator's knowledge of what was
  on the other end.** Endorse on a direct cable or on a LAN where nothing else can answer at that address.
- **That the key cannot be used by other code.** The keys are derived inside the secure world (the STM32's DHUK
  through SAES, the RW612's die key in ELS, the ZynqMP's PUF-protected device key), and they depend on the chip, not
  on the firmware. All three boards are in their open, development state: anyone with the debugger can load a secure
  image that uses the same key and reports whatever it likes (threat model, limitation 1). So an endorsement here
  says **"this key was on this device when the bench endorsed it"**, and how far the key can be trusted afterwards
  still depends on the device's lifecycle. Closing the devices is WP5: not done, irreversible, and the owner's
  decision. Every record carries `"device_state"`, the operator's statement of that lifecycle (`development` for
  every board here); the verifier shows it and does not act on it.
- **That the firmware is still what was endorsed.** The record names the components the device reported. The verifier
  compares every later quote with them, so other firmware under the endorsed key is refused until someone endorses
  it; but the quote is the device's own word, with the limits above.
- **Anything against someone who can edit the verifier's policy.** The policy file decides which endorsers are
  trusted and which entries require an endorsement. Root on the gateway can add an endorser or delete the
  requirement. An endorsement protects the key files and the records, the network path at enrolment (as far as the
  cable goes), and the operator from mixing up files. It moves the trust from "whatever was in `keys/`" to "whoever
  holds the endorser's key or can write the policy".
- **That the endorser's key is safe.** Whoever can use it can make any key a trusted device key at every verifier
  that lists it. It is sealed to the bench PC's TPM when one is usable (`common/keystore.py`: useless off that
  machine, usable by root on it), else a 0600 file.

## The record

One JSON file per device, about 11 kB. It is the whole enrolment: the signed claims, the signature and the device's
public key.

```json
{
 "format": "aegis-endorsement-v1",
 "body": {
  "v": 1,
  "type": "endorsement",
  "device": "stm32h573-dk",
  "serial": "ST-LINK 0042...",
  "kind": "aegis-pq",
  "device_pk_alg": "ML-DSA-65",
  "device_pk_sha256": "9f1c...",
  "measurements": [
   {"type": "NSPE", "measurement_value": "1f41...", "signer_id": "82a5..."},
   {"type": "SPE", "measurement_value": "0254...", "signer_id": "e304..."}
  ],
  "instance_id": "01fa...",
  "evidence": {"challenge": "5b0e...", "token_sha3_256": "77aa..."},
  "device_state": "development",
  "endorser": "bench-pc",
  "endorser_pk_sha256": "0758...",
  "issued": 1795190400,
  "expires": 1826726400,
  "notes": "bench LAN, direct"
 },
 "sig": "<ML-DSA-65 signature, hex>",
 "device_pk": "<the device's public key, hex>"
}
```

| Claim | Meaning | Required |
|---|---|---|
| `device` | the device's name at the verifier: the policy entry's `name` | yes |
| `serial` | the operator's serial number or label for the board | no |
| `kind`, `profile` | the family: the policy kind, and the claims profile for kinds whose quote has one (`aegis-device`, `aegis-tee`, `aegis-linux`); `aegis-pq` has no profile | kind yes |
| `device_pk_alg`, `device_pk_sha256` | the key: ML-DSA-65, SHA-256 of the 1952-byte public key | yes |
| `measurements` | the components the device reported at the bench and the endorser found in its reference (`type`, `measurement_value`, and `signer_id` where the reference names one); one per type | yes |
| `instance_id` | the quote's instance ID, if it had one | no |
| `evidence` | the quote that was appraised: its challenge and SHA3-256 of the signed token | yes |
| `device_state` | `development` or `closed`: the operator's statement | yes |
| `endorser`, `endorser_pk_sha256` | the endorser's own name, and SHA-256 of its public key: which trusted key the signature is checked with | yes |
| `issued`, `expires` | Unix times on the endorser's clock; without `expires` the record does not expire | issued yes |
| `notes` | free text | no |

The signature is ML-DSA-65 by the endorser over `canonical(body)` (`common/wire.py`: JSON, keys sorted, no white
space) with the label `aegis-endorsement-v1`, so the endorser's key signing the same bytes as anything else is not an
endorsement. `device_pk` is outside the signature; the body names its hash, and a record whose key does not match is
malformed. A version 1 verifier refuses a body with a claim it does not know: a later version cannot add a
restriction that an old verifier would silently drop.

**Towards EAT and COSE (WP10).** The body is a flat claims set so that it can move into an EAT without being
redesigned: a CBOR claims map in a COSE_Sign1 with ML-DSA-65, the endorser's key hash as `kid`. The intended mapping
(not implemented, and not checked against a profile yet): `endorser` to `iss`, `device` to `sub`, `issued` to `iat`,
`expires` to `exp`, `profile` to `eat_profile`, `instance_id` to `ueid`, `evidence.challenge` to `eat_nonce`,
`device_pk_sha256` to a key-confirmation claim (`cnf` with a thumbprint), `measurements` to the software-components
list the PSA token already uses (`common/psa_token.py`, claim 2399, keys 1, 2, 5), and `kind`, `serial`,
`device_state`, `evidence.token_sha3_256`, `notes` to private claims. `format` is what a verifier will switch on.

## The verifier's rules

Policy, at the top level, the endorsers this verifier trusts:

```json
"endorsers": [
 {"name": "bench-pc", "pk_file": "endorsers/bench-pc.mldsa65.pub", "pk_sha256": "0758..."}
]
```

`pk_sha256` is required: the policy itself says which keys it trusts, and a key file that does not match is an error
that refuses every endorsement (one bad entry must not leave the rest looking like the whole list).
`"revoked": true` on an entry refuses every record that endorser signed.

Per endpoint: `"endorsement": "required"`. Optional `"endorsement_file"`; the default is
`endorsements/<name>.json` beside the policy.

With `"endorsement": "required"`, an endpoint is admitted only if all of this holds, and the first six are decided
**before the endpoint is contacted**:

1. the policy lists at least one trusted endorser, and its list is well formed;
2. a key is pinned (`pq_pub_file`) and a record exists, is a JSON object of the known format, and every claim in it
   is known and of its type;
3. the record's `endorser_pk_sha256` is a trusted endorser that is not revoked, and its ML-DSA-65 signature over the
   body verifies with that key;
4. the record names this entry's `name`, its kind and (for kinds that have one) its pinned profile;
5. the record names exactly the pinned key: SHA-256 of the key file equals `device_pk_sha256`. A key file that was
   replaced is refused here (`substituted key`);
6. the record has not expired on this verifier's clock;
7. the quote is signed by that key for this cycle's challenge (as before);
8. every component of the quote is in the policy's `allowed` list (as before), **and** the quote's components are
   exactly the endorsed ones: each reported component is an endorsed one, by the endorsed signer where the record
   names one, and every endorsed component is reported.

A session is issued only to the key the cycle's quote was verified with (`provision()` takes the key through the
same check and refuses if the key file changed in between). `"endorsement"` with a value other than `"required"`, on
a kind without a post-quantum key, or on a development profile whose key is the same on every chip, is a policy
error: the entry is refused, never treated as if the key were absent. `fleet.py enroll-pq` skips entries that
require an endorsement.

Without the key in an entry, nothing changes: the pinned key is trusted as it is. That is logged as the weaker
choice: the verdict has `"enrolment": "trust-on-first-use"`, every journal line of an admitted endpoint ends
`[trust on first use]`, the loop prints one line per such endpoint at warning priority when it starts, and
`fleet.py check` says so. An endorsed endpoint's verdict has `"enrolment": "endorsed"` and the endorser, the record's
hash, the key's hash and the device state under `"endorsement"`; its line ends `[endorsed by <name>]`.

Rule 8 means new firmware needs a new endorsement (and a new reference in `allowed`), which takes the same minute.
The other way to build this, a signed list of reference values kept apart from the per-device record, is an open
question (see the end).

Limits of the rules: the verifier's clock decides expiry, so a gateway whose clock is behind accepts a record
longer; `issued` is not checked against the clock at all (a gateway that boots with a clock in the past must not
lock its fleet out). Revocation is per endorser; to drop one device, delete its record or its entry.

## Atomic enrolment

A partial or failed enrolment leaves no trusted entry. There are two places where something is written.

**The endorser** (`aegis_provision.py endorse`) writes one file per device and nothing else. The record is built and
signed in memory and checked the way a verifier will check it: the bytes that will be written, parsed again,
against the endorser's own public key and the device key just read; then the whole of it, with a second quote from
the device attested by the verifier's code with the record required. Only then is it logged in the endorser's
ledger, written under a temporary name in the destination directory, flushed, and renamed. A device that does not
answer, a quote that is not admitted, a record that fails its own check or would not admit the device it was made
from, a disk that is full: no file.

**The verifier** (`fleet.py enroll-endorsed POLICY RECORD...`) has two files per device, the record and the key.
It checks the record against the policy's trusted endorsers and the entry it names, refuses if another key is
already pinned for that entry (`--force` replaces it), writes both files under temporary names, reads those back and
checks them once more, and renames the record first and the key last. The order is the point:

| Stopped | On disk | Trusted |
|---|---|---|
| before the first rename | nothing new | nothing new |
| between the renames, by an error | the record is removed again (or the previous record put back) | what was trusted before |
| between the renames, by a crash or power cut | the new record, and no key or the old key | nothing new: a required endorsement finds no key, or a key the record does not name; an entry without the requirement finds no key, or the key it had |
| after the second rename | record and key | the endorsed key |

The key file is what an entry without `"endorsement": "required"` trusts, so it goes in last, after everything has
been checked. Run the command again to finish an interrupted enrolment (with `--force` if it stopped a
re-enrolment half way).

## Procedure for the bench operator

Once per endorser (the bench PC):

    .venv/bin/python provision/aegis_provision.py init --name bench-pc     # TPM-sealed key if a TPM is usable
    .venv/bin/python provision/aegis_provision.py show                     # its pk_sha256 and the policy entry

The key and the ledger live in `~/.local/state/aegis-endorser` (`$AEGIS_ENDORSER_DIR`, `--state`). `init` refuses
to replace an existing key without `--force`; a new key means every verifier's `endorsers` list has to change.
With the TPM, the rules of `docs/pc-verifier.md` apply unchanged: nothing is stored in the TPM, nothing is cleared,
no hierarchy auth is touched.

Per device:

1. Put the device where only it can answer at its address: a direct cable, or the bench LAN with nothing unknown on
   it. Note the board's serial number.
2. Have a policy file with an entry for the device: its address, kind, profile and the reference measurements in
   `allowed`. The gateway's policy is the natural one; the tool only reads it.
3. Endorse:

       .venv/bin/python provision/aegis_provision.py endorse POLICY.json DEVICE --out records/ \
           --serial "<board serial>" --notes "<where and how it was connected>"

   It prints one JSON object. `"endorsed": true` with the key's hash, the family, the components and `elapsed_s`,
   or `"endorsed": false` with the reasons and no file. `--valid-days N` makes the record expire;
   `--device-state closed` is for a device whose debug port and boot chain have been closed (none here).
4. Give the record to each verifier and let it enrol:

       python3 fleet.py enroll-endorsed POLICY.json records/DEVICE.json

   `enrolled DEVICE: ...` or `REFUSED ...: <why> (nothing was enrolled from it)`. If it says another key is
   already pinned, stop: the device shows another key than the one this verifier has been trusting. Find out why
   before `--force`.
5. Add `"endorsement": "required"` to the entry (once the verifier's policy lists the endorser), and look at
   `fleet.py check POLICY.json`: `enrolment: endorsed by bench-pc (record ..., device key ..., device state
   development)`.

A whole enrolment is three requests to the device (its key and two quotes) and a handful of signature checks: about
15 ms against the SDK's core on the PC, and the device's own time for two ML-DSA-65 signatures on a board. The tool reports `elapsed_s` per
device; the target is under a minute including the operator's typing.

## Runbook: this bench (two STM32H573I-DK, FRDM-RW612, PolarFire gateway)

Run from the checkout on the bench PC. Addresses come from `bench.env` (git-ignored: a fresh worktree has none, so
source the one of the main checkout); only `GATEWAY` is used, the endpoints' addresses are the ones in the gateway's
policy. Nothing here touches a board's flash, a programmer or a device's lifecycle; every step on the gateway has its undo at the end. The entries are assumed to be
named as in `gateway/policy/fleet.pc.example.json`: `stm32h573-dk`, `stm32h573-dk-2`, `frdm-rw612`.

**1. The endorser, and the gateway's policy as the reference.**

    set -a; . ./bench.env; set +a
    PY=.venv/bin/python; W=~/.local/state/aegis-endorser/bench; GW=root@$GATEWAY; GP=/root/aegis/gateway/policy
    BK=/root/aegis-backup-endorsement-$(date +%Y%m%d-%H%M%S); IN=/root/aegis-incoming/endorsement; echo $BK
    $PY provision/aegis_provision.py init --name bench-pc
    $PY provision/aegis_provision.py show
    mkdir -p $W/keys && scp -o BatchMode=yes $GW:$GP/fleet.json $W/fleet.json
    scp -o BatchMode=yes $GW:$GP/keys/tfm-dev-iak.pub.pem $W/keys/

**2. Endorse the three devices** (the fleet service may keep running: the tool asks for a key and two quotes; if a
request meets the service's, it is retried, and `"busy"` in the reasons means run the line again):

    for n in stm32h573-dk stm32h573-dk-2 frdm-rw612; do
        $PY provision/aegis_provision.py endorse $W/fleet.json $n --out $W/records --notes "bench LAN"
    done

Three objects with `"endorsed": true` and `elapsed_s`; three files in `$W/records`. Add `--serial` per board if the
serials should be in the records (they stay on the bench: do not publish them).

**3. The new verifier code on the gateway, old files kept.** The first line shows whether the gateway runs the
`fleet.py` of `main` (the two hashes are equal) or something newer that this would overwrite; the backup is taken
either way.

    ssh -o BatchMode=yes $GW "sha256sum < /root/aegis/gateway/aegisd/fleet.py"; git show origin/main:gateway/aegisd/fleet.py | sha256sum
    ssh -o BatchMode=yes $GW "mkdir -p $BK $IN/records && cp -p /root/aegis/gateway/aegisd/fleet.py $GP/fleet.json $BK/"
    scp -o BatchMode=yes common/endorsement.py $GW:/root/aegis/common/
    scp -o BatchMode=yes gateway/aegisd/fleet.py $GW:/root/aegis/gateway/aegisd/
    $PY provision/aegis_provision.py export $W/endorsers
    scp -o BatchMode=yes -r $W/endorsers $GW:$GP/
    scp -o BatchMode=yes $W/records/*.json $GW:$IN/records/

**4. Trust the endorser, enrol the records, restart the loop on the new code.** The policy is edited on the PC and
put in place on the gateway by a rename, because the loop reads it every cycle.

    PIN=$($PY provision/aegis_provision.py show | $PY -c 'import json,sys; print(json.load(sys.stdin)["pk_sha256"])')
    scp -o BatchMode=yes $GW:$GP/fleet.json $W/fleet.gw.json
    $PY -c 'import json,sys; f,pin=sys.argv[1:]; p=json.load(open(f)); p["endorsers"]=[{"name":"bench-pc","pk_file":"endorsers/bench-pc.mldsa65.pub","pk_sha256":pin}]; json.dump(p,open(f,"w"),indent=1)' $W/fleet.gw.json $PIN
    scp -o BatchMode=yes $W/fleet.gw.json $GW:$GP/fleet.json.new && ssh -o BatchMode=yes $GW "mv $GP/fleet.json.new $GP/fleet.json"
    ssh -o BatchMode=yes $GW "cd /root/aegis/gateway/aegisd && python3 fleet.py enroll-endorsed ../policy/fleet.json $IN/records/*.json"
    ssh -o BatchMode=yes $GW "systemctl restart aegis-fleet && sleep 75 && journalctl -u aegis-fleet -o cat --no-pager -n 14"

Expected: three `enrolled ...` lines, none needing `--force` (the key each device showed at the bench is the key the
gateway has pinned all along; if one is refused with `another key is already pinned`, stop here and find out why).
After the restart there is one warning line per endpoint (`enrolment: trust on first use: ...`), and the three
endpoints are `ADMITTED ... [credential: valid, heartbeat N ...] [trust on first use]`: their sessions were kept.

**5. The refusals, on the real boards, before the switch.** The check asks for the requirement itself, only sends
quote requests and changes nothing (the head of the file lists what it does).

    ssh -o BatchMode=yes $GW "python3 - $GP/fleet.json stm32h573-dk stm32h573-dk-2" < tests/board/endorsement_check.py
    ssh -o BatchMode=yes $GW "python3 - $GP/fleet.json frdm-rw612 stm32h573-dk" < tests/board/endorsement_check.py

Both exit 0 with `"ok": true`. In the first, `E9_control_trust_on_first_use` is `"admitted": true`: board 2 under
board 1's name with board 2's key is admitted when the key is only pinned, and refused at E3 to E5 when it must be
endorsed. In the second E9 is not applicable (two families).

**6. The switch.**

    $PY -c 'import json,sys; f=sys.argv[1]; p=json.load(open(f)); [e.update(endorsement="required") for e in p["endpoints"] if e["name"] in sys.argv[2:]]; json.dump(p,open(f,"w"),indent=1)' $W/fleet.gw.json stm32h573-dk stm32h573-dk-2 frdm-rw612
    scp -o BatchMode=yes $W/fleet.gw.json $GW:$GP/fleet.json.new && ssh -o BatchMode=yes $GW "mv $GP/fleet.json.new $GP/fleet.json"
    ssh -o BatchMode=yes $GW "cd /root/aegis/gateway/aegisd && python3 fleet.py check ../policy/fleet.json; sleep 75; journalctl -u aegis-fleet -o cat --no-pager -n 10"

`check` prints `enrolment: endorsed by bench-pc (...)` under each of the three and exits 0; the journal's next cycle
has `ADMITTED ... [credential: valid, heartbeat N ...] [endorsed by bench-pc]` for each: the sessions are kept.

**7. A substituted key and a missing record, through the running service.** Optional, and it costs board 2 its
session for a cycle (the gateway revokes it and provisions again; there is no enforcement hook on the bench, so the
network sees nothing). Each change is undone at the end of its own line. The pauses are 75 s so that a whole cycle
of the loop falls inside them (30 s of sleep, and up to 20 s for an endpoint that does not answer).

    ssh -o BatchMode=yes $GW "cd $GP && cp -p keys/stm32h573-dk-2.mldsa65.pub $IN/dk2.pub.keep && cp keys/stm32h573-dk.mldsa65.pub keys/dk2.sub && mv keys/dk2.sub keys/stm32h573-dk-2.mldsa65.pub && sleep 75; journalctl -u aegis-fleet -o cat --no-pager -n 14 | grep dk-2 | tail -1; cp -p $IN/dk2.pub.keep keys/dk2.back && mv keys/dk2.back keys/stm32h573-dk-2.mldsa65.pub"
    ssh -o BatchMode=yes $GW "cd $GP && mv endorsements/stm32h573-dk-2.json $IN/dk2.json.keep && sleep 75; journalctl -u aegis-fleet -o cat --no-pager -n 14 | grep dk-2 | tail -1; mv $IN/dk2.json.keep endorsements/stm32h573-dk-2.json; sleep 75; journalctl -u aegis-fleet -o cat --no-pager -n 14 | grep dk-2 | tail -1"
    ssh -o BatchMode=yes $GW "cd /root/aegis/gateway/aegisd && python3 fleet.py check ../policy/fleet.json"

Expected, in order: `stm32h573-dk-2 QUARANTINED endorsement required: the pinned key (sha256 ...) is not the endorsed
key (...): substituted key [credential: revoked]`; `... QUARANTINED endorsement required: no endorsement record
(...)`; then `ADMITTED ... [credential: issued session ...] [endorsed by bench-pc]`, and `check` as in step 6.

**8. The PC verifier** (if it is in use, `docs/pc-verifier.md`): the same records, no key files copied by hand.

    mkdir -p ~/.config/aegis && $PY provision/aegis_provision.py export ~/.config/aegis/endorsers
    # add the "endorsers" entry and "endorsement": "required" to ~/.config/aegis/fleet.pc.json, then:
    $PY gateway/aegisd/fleet.py enroll-endorsed ~/.config/aegis/fleet.pc.json $W/records/*.json
    $PY gateway/aegisd/fleet.py check ~/.config/aegis/fleet.pc.json --platform linux

**9. Record it.** The tool's three outputs (with `elapsed_s`), the two check outputs of step 5, `fleet.py check`
and the journal lines of steps 6 and 7 go to `evidence/endorsed-enrolment/`, with LAN addresses and serial numbers
written out of them; a line in `docs/board-changes.md`.

**Undo.** `ssh $GW "cp -p $BK/fleet.json $GP/fleet.json.new && mv $GP/fleet.json.new $GP/fleet.json"` puts the
policy back (the loop picks it up in its next cycle; the old `fleet.py` ignores the keys it does not know, so code
and policy can go back in either order); `ssh $GW "cp -p $BK/fleet.py /root/aegis/gateway/aegisd/ && systemctl
restart aegis-fleet"` puts the code back. `$BK` is a new directory at every run of step 1, so note the one that was
printed. `endorsements/`, `endorsers/` and `$IN` can stay or be deleted. No device was changed at any point.

## Tests

| What | Where |
|---|---|
| endorsed accepted; unendorsed, substituted, another device's record, another family, untrusted or revoked endorser, tampered, wrong label, unknown claim, expired, other or missing components: refused; the same substitution admitted under trust on first use | `tests/host/test_endorsement.py` (`Accepted`, `Refused`) |
| partial enrolment: failed appraisal, silent device, unwritable record, a record that fails its own check or would not admit its own device, an install that fails or dies between its two files, a failed re-enrolment | `tests/host/test_endorsement.py` (`Enrolment`) |
| the SDK's core as built, enrolled with the commands it has, then a session bound by the transcript | `tests/host/test_endorsement.py` (`SdkCore`) |
| the endorser's key: a 0600 file, or sealed to a TPM (swtpm) | `tests/host/test_endorsement.py` (`EndorserKey`) |
| 2000 hostile record files (mutated bytes, edited claims, a key the policy does not list, the endorser's signature under other labels or for another device, family or key, random JSON): none makes a key trusted, nothing but `Refused` is raised, the endpoint is never contacted | `tests/redteam/fuzz_host.py`, section 5 |
| the refusals on real boards | `tests/board/endorsement_check.py`; run on simulated devices by `test_endorsement.py` (`BoardCheck`), including a verifier that fails it |

## Open questions

1. **Reference values in the per-device record, or apart from it.** Today the record names the components, so new
   firmware means endorsing each device again. A signed reference manifest per firmware release, with the device
   record naming only key and family, would separate the two roles (RATS calls them endorser and reference value
   provider) at the price of a second signed format.
2. **Expiry by default.** Records do not expire unless the operator asks. A default lifetime would bound a stolen
   endorser key's reach in time, and would make an unattended fleet fail closed on a date.
3. **Revoking one device, and old records.** There is no signed revocation: a device is dropped by removing its
   record or entry at each verifier. Nor is there a sequence number: an older record by the same endorser for the
   same device and key is as valid as the newest one, so whoever can write the verifier's `endorsements/` can put
   an earlier record back (earlier firmware, which the policy's `allowed` list then has to refuse on its own).
4. **The policy file is not signed.** Whoever can write it decides everything (above). A policy signed by the
   endorser, or by a second key, would be the next step.
5. **Rooting the device key in the manufacturer's identity** (ST's device certificate, NXP's, the ZynqMP's device
   DNA and PUF) instead of in the cable. That, with closed devices, is what would make an endorsement say "a genuine
   chip running our code".
6. **Where the device learns about it.** Nothing is stored on the device. An endorsement the device carries and
   hands out itself, and a credential chain in place of the one pinned verifier key, are the SDK seams listed in
   `sdk/README.md`.

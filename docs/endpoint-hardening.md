# Endpoint hardening: hedged ML-DSA signing and KMAC heartbeats (deployed on the bench 17 November 2026)

Status: checked on the PC first, then deployed on the STM32 on 17 November 2026 ("Deployed on the bench" below).

## Change 1: hedged ML-DSA signing (branch `hedged-signing`)

The secure partition signed with `rnd` = 32 zero bytes, which is the deterministic variant of ML-DSA (FIPS 204). It now
fills `rnd` with 32 fresh bytes from TF-M's crypto service (`psa_generate_random`, backed by the STM32H5 RNG) before
each of its two signatures: the quote, and the signed ML-KEM encapsulation key. If the service fails, the partition
refuses to sign (returns the PSA error) instead of falling back to the deterministic variant. `rnd` is wiped after use.
Building with `AEGIS_DETERMINISTIC_SIGNING=1` restores the deterministic variant, for example to compare signatures
with known-answer vectors.

Files: `aegis_pq_attest.c` (the helper `signing_rnd` and its two call sites), `aegis_pq_attest.yaml` (dependency on
`TFM_CRYPTO`), `CMakeLists.txt` (links `psa_crypto_config`).

The gateway needs no change: ML-DSA verification is the same for hedged and deterministic signatures.

## Checked on the PC

| Check | Result |
|---|---|
| `tests/host/test_hedged_signing.py`: the partition's ML-DSA-65 configuration, built for the PC, signs one message twice with fresh randomness | both signatures verify with liboqs (what the gateway uses); the two differ; a wrong message is refused |
| TF-M v2.3.0 secure image with the changed partition (`OUT=~/aegis-tools/tfm-aegis-build-hedged build_tfm.sh`) | builds; `psa_generate_random` linked into the image |
| Secure-gateway veneers | unchanged: `.gnu.sgstubs` at `0x0C085FC0`, size `0x40`, the same as the running build, so prover 0.4.0 needs no rebuild |
| Measurement of the new secure image | `3bcce95adcf8c602eaedc79b8507f31e275e4b6df63821b805d141f529d2bc43`, signer `e30466f6...` (the running image is `1793b3fb...`, same signer) |

The NIST vectors already covered both variants: the STM32 ACVP run (265/265) included hedged signature generation.

## Change 2: KMAC256 heartbeats (branch `kmac-heartbeat`, on top of change 1)

The heartbeat tag was SHA3-256 over `"aegis-hb-v1" || session || nonce || counter || status`. That is sound for SHA-3,
which has no length extension, but it is a home-made MAC. It is now the standard one, KMAC256 from NIST SP 800-185:

    tag = KMAC256(K = session key, X = nonce || counter || status, L = 256, S = "aegis-hb-v2")

- **Endpoint:** `aegis_kmac.c` (self-contained, its own Keccak-f[1600]), used by the partition's HEARTBEAT; the build flag
  `AEGIS_HB_KMAC=0` keeps the first version.
- **Gateway:** `common/kmac.py` (standard library only; Python has no cSHAKE) and a per-endpoint policy key
  `"heartbeat_mac": "kmac256"`. Without the key the gateway uses the first version, so the gateway and each endpoint can
  be switched together, one endpoint at a time. An unknown value is refused.

| Check | Result |
|---|---|
| `tests/host/test_kmac.py`: `common/kmac.py` against NIST's KMAC samples 1-6 (as reproduced in pycryptodome's test suite, which cites NIST's KMAC_samples.pdf) | all six equal |
| The same against pycryptodome on 600 random inputs (keys of 32 to 200 bytes, data up to 600 bytes, outputs up to 300 bytes) | equal |
| `tests/host/test_kmac_c.py`: the partition's C code, built for the PC with `-Wall -Wextra -Werror`, against NIST samples 4-6 and 150 random inputs at the 136-byte block edges | equal |
| `tests/host/test_fleet.py`: a KMAC endpoint with a KMAC policy is accepted; a KMAC endpoint with the old policy is refused; an unknown MAC name is refused | pass |
| TF-M image with both changes (`OUT=~/aegis-tools/tfm-aegis-build-kmac build_tfm.sh`) | builds without warnings from these files; veneers unchanged at `0x0C085FC0`; SPE measurement `a5997cc3c61af12d780ac4a8d62a2cd574c3343f077a179759f7efd36355750e` |
| KMAC256 on the gateway's CPU, pure Python, one heartbeat | 46.5 ms (SHA3-256 with hashlib: 35 us). One heartbeat per endpoint every 30 s: about 0.15 % of one core per endpoint |

## Deployed on the bench (17 November 2026)

Baseline before any change: `tools/regression.sh --board` 12 of 12. Then, in this order, each step checked before the next:

| Step | Result |
|---|---|
| Backup of the STM32 under reset: both 2 MiB flash views and the option bytes (`backups/stm32h573/20261117-181152-ep1-before-hardening`, checksummed) | the secure slot in the backup is byte-identical to `tfm-s-v2.3.0-aegis-pq-hb.bin`, so the rollback image is the right one |
| Gateway: old `fleet.py` and `fleet.json` copied aside; new `fleet.py` and `common/kmac.py` installed, policy unchanged | KMAC on the gateway gives NIST sample 4; the endpoint, still on the old image, stays ADMITTED with valid heartbeats (the new gateway code defaults to the first heartbeat) |
| Secure image `tfm-s-v2.3.0-aegis-pq-hb-hedged-kmac.hex` written to the secure slot (ST-LINK chosen by serial number: a second board is connected) | download verified; `PQKEY` returns the same 1,952-byte key as before (SHA-256 `29b953e6...`): the key comes from the chip, not from the image |
| Before the policy change | `QUARANTINED component SPE not allowed (measurement a5997cc3...) [credential: revoked]`: an image the policy does not know is refused, as it must be |
| Policy: SPE measurement `a5997cc3...`, `"heartbeat_mac": "kmac256"`; service restarted | `ADMITTED [credential: issued session cd1126...]`, then `valid, heartbeat 1`, `2`, ... with KMAC256 |
| Hedged signing | the image running is the hedged build (its measurement is in the policy); the partition's code signs one message twice with two different signatures, both valid with liboqs, on the PC (`tests/host/test_hedged_signing.py`, 3 of 3). **It cannot be seen from outside the board:** two quotes for one challenge always differ, because the PSA token inside each carries TF-M's randomized ECDSA signature, so the message ML-DSA signs changes too (`tools/board/hedged_quotes.py`, `evidence/console/quote-variation.txt`). An earlier version of this table said the quotes "were identical before"; that was never measured, and it is not true. |
| `tools/regression.sh --board` | 12 of 12 |

## To deploy both, with someone at the board

1. Back up both STM32 flash slots.
2. Copy `common/kmac.py` and the new `gateway/aegisd/fleet.py` to `/root/aegis` on the gateway (the running service does
   not change until it is restarted).
3. Write `endpoints/stm32h573/artifacts/tfm-s-v2.3.0-aegis-pq-hb-hedged-kmac.hex` to the STM32's secure slot with
   STM32CubeProgrammer. Keep the non-secure prover 0.4.0.
4. In the gateway policy, set the STM32's SPE measurement to `a5997cc3...` (above) and add `"heartbeat_mac": "kmac256"`
   to its entry; then `systemctl restart aegis-fleet`.
5. Check: `PQKEY` returns the same key as before; the secure image's measurement is the hedged build's; the journal
   shows `ADMITTED [credential: issued ...]` then `valid, heartbeat 1, 2 ...`; `tools/regression.sh --board` 12 of 12.
6. If anything fails: write `tfm-s-v2.3.0-aegis-pq-hb.hex` back, restore the policy entry (measurement `1793b3fb...`,
   no `heartbeat_mac`) and the old `fleet.py`, and restart the service.

To deploy only change 1, use `tfm-s-v2.3.0-aegis-pq-hb-hedged.hex` (SPE `3bcce95a...`) and leave the gateway as it is.

## Not done

- **Credential expiry on the endpoint.** The gateway enforces it. Since 19 November 2026 the endpoints' secure sides
  have a clock of their own and end the session themselves, verified on both STM32s and the RW612
  ([endpoint-expiry.md](endpoint-expiry.md), `evidence/endpoint-expiry/bench.txt`,
  `evidence/console/regression-14of14-20261119.txt`).

# Endpoint hardening: hedged ML-DSA signing and KMAC heartbeats (branches `hedged-signing` and `kmac-heartbeat`, not deployed)

Status 2026-11-17: built and checked on the PC. **Not flashed, not tested on the STM32.** Do not merge before the board
checks below pass.

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

## To deploy both, with someone at the board

1. Back up both STM32 flash slots.
2. Copy `common/kmac.py` and the new `gateway/aegisd/fleet.py` to `/root/aegis` on the gateway (the running service does
   not change until it is restarted).
3. Write `endpoints/stm32h573/artifacts/tfm-s-v2.3.0-aegis-pq-hb-hedged-kmac.hex` to the STM32's secure slot with
   STM32CubeProgrammer. Keep the non-secure prover 0.4.0.
4. In the gateway policy, set the STM32's SPE measurement to `a5997cc3...` (above) and add `"heartbeat_mac": "kmac256"`
   to its entry; then `systemctl restart aegis-fleet`.
5. Check: `PQKEY` returns the same key as before; two quotes for one challenge have different signatures; the journal
   shows `ADMITTED [credential: issued ...]` then `valid, heartbeat 1, 2 ...`; `tools/regression.sh --board` 12 of 12.
6. If anything fails: write `tfm-s-v2.3.0-aegis-pq-hb.hex` back, restore the policy entry (measurement `1793b3fb...`,
   no `heartbeat_mac`) and the old `fleet.py`, and restart the service.

To deploy only change 1, use `tfm-s-v2.3.0-aegis-pq-hb-hedged.hex` (SPE `3bcce95a...`) and leave the gateway as it is.

## Not done

- **Credential expiry on the endpoint.** The gateway enforces it; the endpoint has no trusted clock to do the same.

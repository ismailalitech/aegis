# Hedged ML-DSA signing on the endpoint (branch `hedged-signing`, not deployed)

Status 2026-11-17: built and checked on the PC. **Not flashed, not tested on the STM32.** Do not merge before the board
checks below pass.

## Change

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

## To deploy, with someone at the board

1. Back up both flash slots (the existing backup is from before Aegis; take a fresh one).
2. Write `endpoints/stm32h573/artifacts/tfm-s-v2.3.0-aegis-pq-hb-hedged.hex` to the secure slot with STM32CubeProgrammer.
   Keep the non-secure prover 0.4.0.
3. Put the new SPE measurement above into the gateway policy (`fleet.json`, type SPE). The service reloads it each cycle.
4. Check: `PQKEY` returns the same key as before (it comes from the hardware-unique key, not from the image); two quotes
   for the same challenge have different signatures; the gateway admits the endpoint; `tools/regression.sh --board`
   passes 12 of 12.
5. If anything fails: write `tfm-s-v2.3.0-aegis-pq-hb.hex` back and restore the old SPE measurement.

## Not done in this branch

- **KMAC for the heartbeat MAC.** The heartbeat uses SHA3-256 over key-prefixed data, which is sound for SHA-3 (no
  length extension), but KMAC256 is the standard construction. It needs a KMAC implementation on both sides; Python's
  standard library has none. Left for later.
- **Credential expiry on the endpoint.** The gateway enforces it; the endpoint has no trusted clock to do the same.

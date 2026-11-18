# Security review of the RW612 TrustZone prover (18 November 2026)

Scope: the TF-M secure partition (`endpoints/rw612/tfm/aegis_pq`), the protocol code it runs on non-secure input
(`endpoints/rw612/prover/src/aegis_proto.c`), the ELS key derivation, the hardened `target_cfg.c`, the gateway's
verifier for this endpoint, and the build, flash and probe tooling. Threat model: the non-secure image is fully
compromised (arbitrary code, arbitrary `psa_call` arguments, every peripheral `target_cfg.c` leaves it). Out of scope:
physical attacks and reflashing the secure image with a debugger (no secure boot is fused on this bench).

Method: four independent reviewers, one angle each (memory safety; cryptography and protocol; isolation and hardening;
the verifier side). Each finding then went to a separate skeptic who tried to refute it from the code, and where
possible with a test built on the PC. Only findings the skeptic could not refute were fixed; the others are listed
with the reason.

## Confirmed and fixed

| Severity | Finding | Fix | Checked by |
|---|---|---|---|
| critical | The pin mux (`MCI_IO_MUX`, IOCON rule) was non-secure: the non-secure side could mux the QSPI flash pins to GPIO and bit-bang the flash, rewriting the secure image without FlexSPI | the pin mux is secure-only; the secure partition muxes the Ethernet and PHY pins before the non-secure image runs | `probe.sh`: MCI_IO_MUX faults from the non-secure side; the prover still reaches the network |
| medium | SOC_TOP (PLLs, trims, pad control, the SoC OTP controller) entirely non-secure | all eight SOC_TOP rules secure-only | `probe.sh`: SOCCTRL and SOC_OTP_CTRL fault |
| medium | PMU non-secure: core voltage, brown-out and reset settings, a glitch path while the secure side signs | PMU secure-only | `probe.sh`: PMU faults |
| low | SYSCTL2 non-secure (memory timing, clock gates) | secure-only; the secure partition sets the Ethernet reference clock there | `probe.sh`: SYSCTL2 faults |
| medium | `fleet.py enroll-pq` re-fetched every endpoint's key over the network and overwrote existing pins: not trust on first use | an existing pin is kept; `--force` replaces it | PC test `test_5_enroll_keeps_an_existing_pin` |
| low | The credential bound the ML-KEM ciphertext but not the pending encapsulation key: an old `PQKEMFIN` replayed after a new `PQKEMINIT` replaced a working session (denial of service; reproduced on the PC) | the gateway names `kem_ek_sha3_256` in the credential, the device requires it (the RW612 and the Linux prover; the STM32 partition accepts the longer credential unchanged) | PC test: the replay gets `ERR cred other-key` and the session stays; STM32 board 2 re-provisioned with the new format |
| low | `probe.sh` counted "no console output" as a pass | three outcomes: read allowed, fault (the probe ran and the chip restarted, at least twice), inconclusive | runs above |

Also taken, as hardening the skeptic suggested for a finding it rejected: 32 fresh bytes from the RNG go into each
ML-KEM key generation, so an exchange's key cannot be regenerated after a reboot.

## Rejected by the skeptic (not changed)

- **KEM keys reproducible after a reboot:** true of the code, but it gains a compromised non-secure side nothing in
  the threat model. The gateway keeps only the latest session per endpoint and re-attests every cycle (taken anyway
  as hardening, above).
- **A derived key left in an ELS slot when a CKDF wait fails:** the skeptic found no way for the non-secure side to
  make that wait fail, and the next derivation picks a slot pair that is empty, so a leftover key is never reused.
- **Isolation level 2** (PSA-RoT partitions share privileged memory): this is TF-M's design for the profile, not a
  defect. Level 3 is not set up in NXP's SDK for this board. Recorded as a limitation.
- **Environment variables that change a build** (`AEGIS_EXTRA_DEFINES`, `AEGIS_NXP_TARGET_CFG`): they are explicit
  and documented, and a changed image changes the SPE measurement, which the gateway checks.
- **FlexSPI rule sets for the other flash windows never programmed:** the non-secure side cannot reach FlexSPI's
  registers now; the reads it could make do not let it change secure flash.

## Not found

The memory-safety reviewer found no defect in the partition's request handling or in `aegis_proto.c` running on
non-secure input: request and reply sizes, hex decoding, the CBOR encoder within `CLAIMS_MAX`, the signing buffer and
the credential length arithmetic all hold for the worst case.

## After the review: fuzzing and the stack (0.2.1)

The "not found" above was a reading of the code. To test it, `tests/fuzz` runs `aegis_proto.c` under libFuzzer with
AddressSanitizer and UndefinedBehaviorSanitizer, called exactly as the partition calls it, with a harness that also
plays the gateway and checks every answer against a model of the protocol (details in `tests/fuzz/fuzz_rw612_proto.c`).

- **Found and fixed (low):** a `PQKEMINIT` refused after the ML-KEM key was made (`ERR sign`, `ERR kem`) left the
  older exchange pending with the new key and nonce in it, unusable, and the new decapsulation key stayed in memory.
  The review had read past it. Fixed in 0.2.1: a valid `PQKEMINIT` cancels the pending exchange and wipes its
  decapsulation key first. The STM32 partition had the same pattern, and worse: without the encapsulation-key check,
  it accepted a credential into the half-replaced exchange. Fixed there too, with that check added, and deployed on
  STM32 board 2 (`evidence/stm32-kemfix/`).
- **No memory error, no undefined behaviour, no other disagreement with the model** in the runs recorded in
  `evidence/rw612-tfm/fuzzing.txt`.
- **Stack:** the partition reports the high-water mark of its 32 KB stack in every heartbeat: 19,368 bytes on the
  board (`evidence/rw612-tfm/upgrade-0.2.1.txt`).

## Still true after the review

The key is bound to the chip, not to the firmware: someone who reflashes the secure image with a debugger can still
use it. That needs secure boot fused on, which this bench does not do (irreversible). The gateway's profile pin keeps
the chip's single-image prover from passing as the TrustZone one.

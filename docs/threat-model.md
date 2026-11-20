# Aegis threat model (state of 2026-11-18)

Scope: the bench system as it runs today.
- **Gateway and verifier:** PolarFire SoC Discovery Kit (MPFS095T, non-S).
- **Endpoints:** two STM32H573I-DK (TF-M v2.3.0, product state Open) and an NXP FRDM-RW612 (NXP's TF-M v2.1.4, with
  the Aegis prover in a TrustZone secure partition).
- **Legacy node:** an Arduino Uno that cannot attest.
- **PC:** on the same LAN.

Every "tested" entry names the test or log that shows it; everything else is marked as a design intent or a known
gap. Nothing here is a certification claim.

## 1. Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Gateway identity key (ML-DSA-65) | `/var/lib/aegis/identity.sk`, mode 0600, PolarFire Linux | signs gateway quotes and endpoint credentials |
| STM32 device key (ML-DSA-65) | derived at boot from the STM32H5 DHUK inside the TF-M secure partition; never leaves secure RAM | signs endpoint quotes and its ML-KEM keys |
| RW612 device key (ML-DSA-65) | derived at the first request from the die key in ELS (CKDF, HMAC) inside the Aegis TF-M partition; ELS is secure-privileged only | the same, for the RW612 |
| Session keys (from ML-KEM-768) | endpoint secure RAM, wiped by the endpoint when the credential's lifetime is over (T22); gateway `/var/lib/aegis/credentials/*.session` (0600) | authenticate heartbeats between attestations |
| Policy (allowed measurements, enrolled keys, pinned profiles) | `gateway/policy/fleet.json`, `keys/` on the gateway | decides admission |
| Measurements | STM32: TF-M BL2 (MCUboot) boot records in the PSA token. RW612: SHA-256 of the whole secure and non-secure flash partitions, taken by the secure partition before non-secure code runs | evidence of what software runs |
| Gateway platform state | PolarFire fabric design and digests, design info, security locks, aegisd code hash | evidence in the gateway's own quote |

## 2. Adversaries considered

- **Network attacker on the LAN:** can read, drop, replay, modify and inject traffic, and connect to any open port
  (gateway 7443, endpoints 7444).
- **Compromised endpoint non-secure software:** arbitrary code in the non-secure world, arbitrary `psa_call`
  arguments, and every peripheral the TrustZone configuration leaves to it.
- **Endpoint running modified firmware** that still boots (signed with a key the bootloader trusts, or with no secure
  boot at all on the RW612).
- **Legacy or foreign node** that cannot attest.

Not considered, being out of scope or not achievable on this bench:
- physical attackers with lab tools (side channels, fault injection, probing);
- an attacker with root on the gateway;
- an attacker with debug access to an endpoint: the STM32 product state is Open, and the RW612 has no secure boot
  fused;
- supply-chain attacks on the toolchains.

## 3. Trust boundaries and what is enforced

| Boundary | Mechanism | Status |
|---|---|---|
| STM32 non-secure / secure (TrustZone) | keys and session state only in the TF-M partition; NS can request quotes, provisioning, heartbeats but never reads keys; SAES (the DHUK) and RNG secure-only in the GTZC | tested: non-secure reads of secure flash and SRAM (both aliases), SAES and RNG fault or read as zero with the GTZC's illegal-access flag; the partition's DHUK derivation run from the non-secure side is refused; a non-secure code word is the control (`evidence/stm32-tz/tz-probes.txt`) |
| RW612 non-secure / secure (TrustZone) | the non-secure prover only passes lines to the Aegis partition; ELS, the fuse controller, FlexSPI, flash caches, TRNG, ROM control, debug mailbox, the reset, clock and system controllers, the pin mux, PMU and SOC_TOP are secure-only | tested: a non-secure read of each of 12 protected blocks faults, the ENET register still reads (`evidence/rw612-tfm/hardening-probes.txt`) |
| STM32 boot | BL2 verifies image signatures (EC-P256) and records measurements | from TF-M; with **published development keys** |
| RW612 boot | no secure boot; the secure partition hashes both flash partitions whole before non-secure code runs | the non-secure image cannot change its measurement; the secure image can be replaced with a debugger (limitation 1) |
| Endpoint -> gateway | quote signed with the ML-DSA-65 device key; nonce; every measurement in policy; profile pinned where one chip key serves two firmwares | tested (phase 3 notes; `tests/host/test_rw612_proto.py`) |
| Gateway -> endpoint | credential signed with the gateway ML-DSA-65 key pinned in the endpoint's secure image, naming SHA3-256 of the ML-KEM ciphertext and of the pending encapsulation key | tested (mutual auth checks; `evidence/stm32-kemfix/`) |
| PC verifier -> gateway | gateway quote (ML-DSA-65, nonce, platform measurements) | tested (phase 1 board checks) |
| Gateway services -> system controller | read-only whitelist of services | tested on host; module never unloaded (kernel hazard) |

## 4. Threats, mitigations, evidence

| # | Threat | Mitigation | Evidence | Status |
|---|---|---|---|---|
| T1 | Replay of an old endpoint quote | fresh 32-byte challenge in every token; verifier compares | `test_replayed_token_quarantined`, `phase1_board_checks` | tested |
| T2 | Modified token / quote in transit | ML-DSA-65 signature over the whole token (and ES256 inside) | `test_tampered_*`, `fuzz_host` (3000 mutations, 0 accepted) | tested |
| T3 | Endpoint boots modified firmware signed with a trusted key | measurement not in policy -> QUARANTINED, credential revoked | STM32: tampered NS image quarantined, credential revoked, re-issued when the good image returned; RW612: a non-secure image changed by one byte quarantined on `NSPE` (`evidence/rw612-tfm/trustzone-prover.txt`) | tested |
| T4 | Node that cannot attest (legacy, foreign) | no valid quote -> QUARANTINED | host tests (silent, garbage, no service); the Arduino Uno quarantined on every cycle (`evidence/console/two-endpoints-demo.txt`) | tested |
| T5 | Downgrade: PQ endpoint answers with a classic-only token | aegis-pq endpoints must return the ML-DSA quote | `fuzz_host` downgrade case | tested |
| T6 | Swap of the endpoint's ML-KEM key (MITM on provisioning) | ek signed by the device ML-DSA key together with the gateway nonce | host test `kem-mitm`; `fuzz_host` KEM-key replay | tested |
| T7 | Fake gateway issuing credentials | endpoint verifies the pinned gateway key | board: foreign-key credential refused (-149) | tested |
| T8 | Replayed credential from another exchange | credential must name SHA3-256 of this ciphertext and of the pending encapsulation key | board: unbound credential refused (-149); STM32 board 2: the gateway's own `KEM_FINISH`, captured and replayed after a new `KEM_INIT`, refused and the session kept (`evidence/stm32-kemfix/board2-kemfix.txt`) | tested |
| T9 | Tearing down a session by starting a new exchange | session replaced only when an exchange completes; a refused `KEM_INIT` leaves no exchange pending | board: session unchanged after two refused exchanges; fuzz seeds `rng-fails-at-sign`, `replay-after-new-init` on both partitions | tested |
| T10 | Replay of session proofs | heartbeat: fresh nonce, rising counter, KMAC256 under the session key (SP 800-185) | board journal; host test counter check; `tests/host/test_kmac*.py` | tested |
| T11 | DoS on the gateway quote service by slow/malformed clients | thread per connection, 8 max, 3 s timeout | `fuzz_host`, `fuzz_devices` (half-open client, 240 frames) | tested |
| T12 | Parser and memory bugs on hostile input | strict COSE field types; bounded line lengths; endpoint protocol code fuzzed with ASan and UBSan against a model of the protocol | `fuzz_host`, `fuzz_devices`; `tests/fuzz` (RW612: 1,049,515 executions; STM32: 892,774; no finding after the fixes; both in CI) | tested |
| T13 | Gateway software or FPGA changed | gateway quote carries code hash, design info and digests | board: PC verifier refused after fabric reprogram and after code update until re-enrolled | tested |
| T14 | Cloning the endpoint key to another chip, or rebuilding it from non-secure code | STM32: key from the per-chip DHUK in SAES, which the GTZC makes secure-only; RW612: key from the die key in ELS | STM32: a second chip with identical firmware has a different key, and its quote under the first chip's name is refused ([second-board.md](second-board.md)); the PSA identity, by contrast, is the same on both (TF-M dummy provisioning) | shown on two STM32 chips |
| T15 | Wrong cryptography | NIST ACVP vectors: PC, PolarFire with fabric Keccak, STM32 code | 265/265 each (phase 2 and 3 notes) | tested |
| T16 | Unattested node keeps network access | rules tested in network namespaces (13 of 13, including cutting open connections and attesting a quarantined endpoint); the one-port VLAN design tested with a VLAN-filtering bridge (16 of 16, including the ways around a VLAN); kernel with netfilter and 802.1Q on the gateway | `tests/host/test_enforcement*.sh`, `docs/vlan-enforcement.md`; on the bench the gateway is not yet in the traffic path: needs a switch with 802.1Q VLANs | **partly closed: rules and design proven, placement not** |
| T17 | Compromised RW612 non-secure code rewrites the secure image or reaches ELS | the peripheral rules of section 3, including the pin mux (otherwise the QSPI flash pins could be remuxed to GPIO and the flash driven by hand) | `probe.sh` on the board, before and after each rule; `docs/rw612-security-review.md` | tested |
| T18 | One chip, two firmwares: the RW612's single-image prover (same chip key) passes as the TrustZone one | the gateway pins the claims profile per endpoint | `test_rw612_proto.py`: a valid signature refused by the pin | tested |
| T19 | Re-enrolment silently replaces a pinned key | `enroll-pq` keeps existing pins unless `--force` | `test_5_enroll_keeps_an_existing_pin` | tested |
| T20 | An endpoint's secure partition stack overflows into another partition | TF-M's stack limit register faults first; the high-water mark is reported in every heartbeat, under the MAC | RW612 `stack=19368/32768` (`evidence/rw612-tfm/upgrade-0.2.1.txt`); STM32 `sstack=19088/26624` in every heartbeat on both boards, the same as read over SWD (`evidence/stm32-sstack/heartbeat-sstack.txt`, `evidence/stm32-tz/tz-probes.txt`) | measured |
| T21 | Cloning the ZynqMP endpoint's key, or using it from Linux | key derived in the FSBL under the device key (the boot header's black key, decrypted only by this chip's PUF), handed to OP-TEE before the normal world runs; the TA signs in the secure world | the same key across a power cycle; the gateway refused the new key under the old pin; partition measurements equal to the PC's (`evidence/zynqmp/puf-phase-b.txt`). Linux-side probes and the PMU firmware's AES lock-down are phase C | **partly tested** |
| T22 | A session outlives its credential: the gateway is gone, or the endpoint's non-secure side is taken over and keeps asking for heartbeat proofs | the endpoint's secure side ends the session on its own clock, the credential's signed lifetime plus a sixteenth after it accepted it, and wipes the key; a clock that fails, runs backwards or was reconfigured ends it too, and then no session starts. The clock is out of the non-secure side's reach: the RTC on the LSI, made secure, on the STM32; the secure SysTick on the RW612; the physical counter through OP-TEE on the ZynqMP ([endpoint-expiry.md](endpoint-expiry.md)) | PC: `test_rw612_proto.py` and `test_linux_prover.py` (accepted a second before the end, refused at it, the session gone, no clock, credentials without a lifetime), `test_fleet.py` (the gateway provisions again), `tests/fuzz` (both partitions against a model holding the clock, with clock faults), the TA's tests. Boards: both STM32s and the RW612 refuse a 32 s credential after its end, attestation still answering; clock rates 0.941 (STM32 LSI) and 1.000 (RW612) (`evidence/endpoint-expiry/bench.txt`). The Zynq TA: built, with phase C | **tested on the STM32s and the RW612** |
| T23 | Reset and replay: a recorded `PQKEMINIT` and `PQKEMFIN`, sent again after the endpoint was reset, give it the old session back for a new lifetime (found by review on the STM32 partition, 20 November 2026: its ML-KEM key came from a device secret, the nonce and a counter that starts again at reset, so the same exchange since reset with the same nonce made the same key, and the recorded credential names that key) | 32 bytes from the chip's random number generator go into every ML-KEM key; if the generator fails or gives zero bytes the exchange is refused. The RW612 partition, the Linux prover and the Zynq TA already drew their keys from random bytes | PC: `test_stm32_partition.py` and the fuzz seeds `reset-and-replay*`, `rng-*-at-kem-*` (the partition against a model that keeps every key issued and the last accepted `KEM_FINISH` across resets; the image before the fix fails them), `test_reset_replay_check.py` (the board check against the RW612 code, and against a generator that starts again at reset). Boards: `tests/board/reset_replay_check.py`; both STM32s on 20 November 2026: the old image (SPE 02549860) reissued the recorded key and accepted the replayed finish, the new one (SPE 67a452b1) refused it (`evidence/stm32-freshkem/`) | **tested on the boards** |
| T24 | One key, two firmware images: attestation and session provisioning were separate exchanges tied only by the endpoint's key, so the gateway could appraise image A's quote and finish the ML-KEM session with image B (audit finding 2). On this bench: the RW612's two firmwares (T18), an STM32 secure image before and after an upgrade, a changed non-secure image under the same secure one. **Scope:** handled where image B follows the protocol (any image of this repository, old or new), e.g. a rollback to an image from before the transcript between the quote and the exchange. Not handled, and not changed by this: image B written by an attacker who can flash it, which on this bench is anyone with the debugger (the RW612 has no secure boot; the STM32s are in the Open state with TF-M's public development signing keys). Such an image holds the key and signs T2 for a quote it saw; closing that needs a device key that depends on the measured code (limitation 10) | one signed transcript (`architecture.md`, "One transcript"): with `"transcript": "v2"` in the policy entry the endpoint's signature on the ML-KEM key covers the challenge and the hash of the quote it signed in this boot, the gateway's credential names that transcript, and the confirmation tag and session key depend on all of it. The gateway refuses anything else before it sends a credential, including the first version's exchange, and replaces a stored session made that way. Without the policy key the first version still runs and is marked `unbound` in the journal | PC: `test_transcript.py` (the swap refused whether or not the other image knows the transcript and whether or not it signed its own quote for the same challenge; reordered and replayed pieces; the policy; both platforms), `test_rw612_proto.py` (`test_6_one_key_two_firmwares`: the C code of both RW612 firmwares), `test_stm32_partition.py` (the partition's transcript against the gateway's code; a build whose quote outlives a reset fails the swap seed), the fuzz models with the `transcript-*` seeds, `fuzz_host` (220 validly signed pieces that are not the transcript: none given a credential), `test_transcript_swap_check.py`, `test_limit_a_firmware_that_holds_the_key_and_lies_is_accepted` (the boundary above). Boards: `tests/board/transcript_swap_check.py` on both STM32s, 20 November 2026 (`evidence/transcript-v2/`): the image before the transcript (SPE 67a452b1) refused the bound exchange; the new one (SPE 3183f74a) passed `live` on both; on board 2 a quote on 3183f74a, then 67a452b1 flashed with the same key and a reset: the swap refused (S1, S2, S3). RW612: image built, not yet flashed; ZynqMP TA and Linux prover: source only | **tested on the STM32s and the RW612 (images of this repository); not a defence against attacker-built images** |

## 5. Known limitations (state these with any claim)

1. **Development keys, no closed devices.**
   - **STM32:** product state Open, with TF-M's published signing keys. Anyone with the debugger or those keys can
     replace the secure image, and any secure code can use the DHUK.
   - **RW612:** no secure boot fused, so someone who reflashes the secure image with a debugger can use the chip's
     key. The profile pin (T18) keeps the single-image prover from passing as the TrustZone one, but not a modified
     TrustZone image.
   - A product would close both devices (irreversible; deliberately not done on this bench) and use its own keys.
2. **TF-M attestation key (ES256) is TF-M's published development key** on the STM32. Only the ML-DSA signature from
   the DHUK-derived key is security-relevant.
3. **Gateway identity key is held in software.** The MPFS095T (non-S) has no data-security services (no PUF-held
   keys, no signature with the factory key). The key is protected by Linux file permissions only, and enrolment is
   trust on first use.
4. **TF-M isolation.**
   - **STM32:** isolation level 1, so no isolation between secure partitions.
   - **RW612:** level 2, so the Aegis partition shares privileged memory with TF-M's other PSA-RoT services; NXP's
     SDK does not set up level 3 for this board.
5. **Side channels and fault injection are not evaluated.** ML-DSA signing is hedged on both endpoint types: fresh
   randomness in every signature, refused if randomness fails.
   One assumption of the PQ code was measured: the Cortex-M33's multiplies (SMULL, UMULL, SMLAL, UMLAL, MUL, MLA) take
   a fixed number of cycles whatever the operands, on both STM32s and the RW612 (`tools/m33_mul_timing/`).
6. **No network enforcement on the real gateway yet** (T16): the ruleset and the one-port VLAN design are tested in
   network namespaces (`docs/vlan-enforcement.md`), but the bench has no VLAN switch in place. With one, endpoints on
   the same VLAN still see each other unless the switch isolates its ports. A device that takes an absent admitted
   endpoint's address passes until the next cycle quarantines it.
7. **Credential expiry** (one hour, renewed five minutes before) is checked by the gateway, and since 19 November by
   the STM32s' and the RW612's secure side too (T22; the Zynq's with phase C). Its limits:
   - The endpoints have no wall clock: they measure how long a session has lasted, not whether a credential is
     current. The session's life counts from the endpoint's acceptance, on the endpoint's clock: an hour's credential
     gives 63 minutes 45 seconds of that clock, and a clock that runs slow (the STM32's is an RC oscillator, good to a
     few per cent) lengthens it by its error.
   - A clock that someone else can slow lengthens the session: a debugger on any endpoint (limitation 1); on the
     ZynqMP the normal world, through the counter's clock control, until phase C locks it; on the RW612, if the
     partition had to fall back to the processor clock (its status says so), a non-secure image that keeps TF-M's
     flash erasing.
   - An endpoint that is switched off or reset is not detected by this; the reset loses the session.
8. **The PolarFire fabric accelerator is a performance block, not a security mechanism.** Version 2 (the SHA-3 sponge
   kept in the fabric) passes ACVP and makes liboqs 1.2-1.5 times faster (`docs/accelerator-v2.md`). The gateway's
   services do not enable it: they run in software.
9. Both STM32 boards run the secure image with the T8/T9 fix (board 1 since 19 November).
10. **The transcript (T24) ties a session to a quote, not the key to the code.** It shows that one boot of the code
    that holds the device key signed the appraised quote and then made the session's key. No endpoint measures again
    for it (the measurements are the boot's, or the files' at the time of the quote), and an image that holds the key
    and signs a transcript for a quote it did not make is not stopped: the keys depend on the chip, not on the
    measured code. With limitation 1 (anyone with the debugger can replace the secure image), that is the same
    boundary as for the quote itself: the transcript stops a swap to an unmodified image of this repository between
    the quote and the exchange (such as a rollback to one from before the transcript), and adds nothing against
    someone who can flash code of their own, which on this bench (RW612 without secure boot, STM32s in the Open state
    with public TF-M development keys) is anyone with the debugger.

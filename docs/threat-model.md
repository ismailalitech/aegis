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
| Session keys (from ML-KEM-768) | endpoint secure RAM; gateway `/var/lib/aegis/credentials/*.session` (0600) | authenticate heartbeats between attestations |
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
| STM32 non-secure / secure (TrustZone) | keys and session state only in the TF-M partition; NS can request quotes, provisioning, heartbeats but never reads keys | implemented; NS cannot address secure RAM by TrustZone design (not separately tested) |
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
| T14 | Cloning the endpoint key to another chip | STM32: key from the per-chip DHUK in SAES; RW612: key from the die key in ELS | STM32: a second chip with identical firmware has a different key, and its quote under the first chip's name is refused ([second-board.md](second-board.md)); the PSA identity, by contrast, is the same on both (TF-M dummy provisioning) | shown on two STM32 chips |
| T15 | Wrong cryptography | NIST ACVP vectors: PC, PolarFire with fabric Keccak, STM32 code | 265/265 each (phase 2 and 3 notes) | tested |
| T16 | Unattested node keeps network access | rules tested in network namespaces (10 of 10, including cutting open connections); kernel with netfilter installed on the gateway | the gateway is not in the traffic path: needs a managed 802.1Q switch | **partly closed: rules proven, placement not** |
| T17 | Compromised RW612 non-secure code rewrites the secure image or reaches ELS | the peripheral rules of section 3, including the pin mux (otherwise the QSPI flash pins could be remuxed to GPIO and the flash driven by hand) | `probe.sh` on the board, before and after each rule; `docs/rw612-security-review.md` | tested |
| T18 | One chip, two firmwares: the RW612's single-image prover (same chip key) passes as the TrustZone one | the gateway pins the claims profile per endpoint | `test_rw612_proto.py`: a valid signature refused by the pin | tested |
| T19 | Re-enrolment silently replaces a pinned key | `enroll-pq` keeps existing pins unless `--force` | `test_5_enroll_keeps_an_existing_pin` | tested |
| T20 | The RW612 secure partition's stack overflows into another partition | TF-M's stack limit register faults first; the high-water mark is reported in every heartbeat | `stack=19368/32768` on the board (`evidence/rw612-tfm/upgrade-0.2.1.txt`) | measured |

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
6. **No network enforcement on the real gateway** (T16): the ruleset is tested, but one Ethernet port cannot
   separate networks. A switch with 802.1Q VLANs would let the one port do it.
7. **Credential expiry** (one hour, renewed five minutes before) is checked by the gateway only; the endpoints have
   no trusted time.
8. **The PolarFire fabric accelerator is a performance block, not a security mechanism.** Version 2 (the SHA-3 sponge
   kept in the fabric) passes ACVP and makes liboqs 1.2-1.5 times faster (`docs/accelerator-v2.md`). The gateway's
   services do not enable it: they run in software.
9. **STM32 board 1 runs the previous secure image** (without the T8/T9 fix of 18 November) until it is reconnected
   and reflashed; board 2 runs the fixed one.

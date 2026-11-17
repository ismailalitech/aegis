# Aegis threat model (state of 2026-11-16)

Scope: the bench system as it runs today: PolarFire SoC Discovery Kit (MPFS095T, non-S) as gateway
and verifier, STM32H573I-DK (TF-M v2.3.0, product state Open) as the attested endpoint, a PC on the
same LAN. Every "tested" entry names the test or log that shows it; everything else is marked as a
design intent or a known gap. Nothing here is a certification claim.

## 1. Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Gateway identity key (ML-DSA-65) | `/var/lib/aegis/identity.sk`, mode 0600, PolarFire Linux | signs gateway quotes and endpoint credentials |
| Endpoint device key (ML-DSA-65) | derived at boot from the STM32H5 DHUK inside the TF-M secure partition; never leaves secure RAM | signs endpoint quotes and its ML-KEM keys |
| Session keys (from ML-KEM-768) | STM32 secure RAM; gateway `/var/lib/aegis/credentials/*.session` (0600) | authenticate heartbeats between attestations |
| Policy (allowed measurements, enrolled keys) | `gateway/policy/fleet.json`, `keys/` on the gateway | decides admission |
| Boot measurements | recorded by TF-M BL2 (MCUboot), reported in the PSA token | evidence of what software runs |
| Gateway platform state | PolarFire fabric design and digests, design info, security locks, aegisd code hash | evidence in the gateway's own quote |

## 2. Adversaries considered

- **Network attacker** on the LAN: can read, drop, replay, modify and inject traffic, and connect to
  any open port (gateway 7443, endpoint 7444).
- **Compromised endpoint Non-Secure software**: arbitrary code in the STM32 Non-Secure world.
- **Endpoint running modified firmware** that still boots (signed with a key the bootloader trusts).
- **Legacy or foreign node** that cannot attest.

Not considered (out of scope or not achievable on this bench): physical attackers with lab tools
(side channels, fault injection, probing), an attacker with root on the gateway, an attacker with
debug access to the STM32 (product state is Open), supply-chain attacks on the toolchains.

## 3. Trust boundaries and what is enforced

| Boundary | Mechanism | Status |
|---|---|---|
| Endpoint NS / Secure (TrustZone) | keys and session state only in the TF-M partition; NS can request quotes, provisioning, heartbeats but never reads keys | implemented; NS cannot address secure RAM by TrustZone design (not separately tested) |
| Endpoint boot | BL2 verifies image signatures (EC-P256) and records measurements | from TF-M; with **published development keys** |
| Endpoint -> gateway | PSA token (challenge, measurements) signed with ML-DSA-65 device key; policy match | tested (phase 3 notes) |
| Gateway -> endpoint | credential signed with the gateway ML-DSA-65 key pinned in the endpoint's secure image, bound to the ML-KEM ciphertext | tested (mutual auth checks) |
| PC verifier -> gateway | gateway quote (ML-DSA-65, nonce, platform measurements) | tested (phase 1 board checks) |
| Gateway services -> system controller | read-only whitelist of services | tested on host; module never unloaded (kernel hazard) |

## 4. Threats, mitigations, evidence

| # | Threat | Mitigation | Evidence | Status |
|---|---|---|---|---|
| T1 | Replay of an old endpoint quote | fresh 32-byte challenge in every token; verifier compares | `test_replayed_token_quarantined`, `phase1_board_checks` | tested |
| T2 | Modified token / quote in transit | ML-DSA-65 signature over the whole token (and ES256 inside) | `test_tampered_*`, `fuzz_host` (3000 mutations, 0 accepted) | tested |
| T3 | Endpoint boots modified firmware signed with a trusted key | measurement not in policy -> QUARANTINED, credential revoked | board: tampered NS image quarantined, credential revoked, re-issued when good image returned | tested |
| T4 | Node that cannot attest (legacy, foreign) | no valid quote -> QUARANTINED | host tests (silent, garbage, no service); Arduino not yet on the bench | partly tested |
| T5 | Downgrade: PQ endpoint answers with a classic-only token | aegis-pq endpoints must return the ML-DSA quote | `fuzz_host` downgrade case | tested |
| T6 | Swap of the endpoint's ML-KEM key (MITM on provisioning) | ek signed by the device ML-DSA key together with the gateway nonce | host test `kem-mitm`; `fuzz_host` KEM-key replay | tested |
| T7 | Fake gateway issuing credentials | endpoint verifies the pinned gateway key | board: foreign-key credential refused (-149) | tested |
| T8 | Replayed credential from another exchange | credential must name SHA3-256 of this ciphertext | board: unbound credential refused (-149) | tested |
| T9 | Tearing down a session by starting a new exchange | session replaced only when an exchange completes | board: session unchanged after two refused exchanges | tested |
| T10 | Replay of session proofs | heartbeat: fresh nonce, rising counter, key-prefixed SHA3 MAC | board journal; host test counter check | tested |
| T11 | DoS on the gateway quote service by slow/malformed clients | thread per connection, 8 max, 3 s timeout | `fuzz_host`, `fuzz_devices` (half-open client, 240 frames) | tested |
| T12 | Parser bugs on hostile input | strict COSE field types; bounded line lengths | `fuzz_host`, `fuzz_devices` (76 malformed STM32 commands -> ERR) | tested |
| T13 | Gateway software or FPGA changed | gateway quote carries code hash, design info and digests | board: PC verifier refused after fabric reprogram and after code update until re-enrolled | tested |
| T14 | Cloning the endpoint key to another chip | key derived from the per-chip DHUK in SAES | device key not equal to keys from trivial SAES keys; a second chip with identical firmware, option bytes and BL2 has a different key, and its quote under the first chip's name is refused ([second-board.md](second-board.md)); the PSA identity, by contrast, is the same on both (TF-M dummy provisioning) | shown on two chips |
| T15 | Wrong cryptography | NIST ACVP vectors: PC, PolarFire with fabric Keccak, STM32 code | 265/265 each (phase 2 and 3 notes) | tested |
| T16 | Unattested node keeps network access | rules tested in network namespaces (10 of 10, including cutting open connections); kernel with netfilter installed on the gateway | the gateway is not in the traffic path: needs a managed 802.1Q switch | **partly closed: rules proven, placement not** |

## 5. Known limitations (state these with any claim)

1. **Development keys and product state Open on the STM32.** Anyone with the debugger or the
   published TF-M signing keys can replace the secure image, and any secure code can use the DHUK.
   A product would close the device (irreversible; deliberately not done on this bench) and use
   its own keys.
2. **TF-M attestation key (ES256) is TF-M's published development key.** Only the ML-DSA signature
   from the DHUK-derived key is security-relevant.
3. **Gateway identity key is held in software.** The MPFS095T (non-S) has no data-security
   services (no PUF-held keys, no signature with the factory key); the key is protected by Linux
   file permissions only, and enrolment is trust on first use.
4. **Isolation level 1** in TF-M: no isolation between secure partitions.
5. **Deterministic ML-DSA** on the endpoint (no hedged randomness); side-channel resistance of the
   implementations on these cores is not evaluated.
6. **No network enforcement on the real gateway** (T16): the ruleset is tested, but one Ethernet port cannot separate networks.
7. **Credential expiry** is checked by the gateway only; the endpoint has no trusted time.
8. **The PolarFire fabric Keccak/NTT accelerator** is correct (ACVP with fabric Keccak) but slower
   than software end to end; it is not a security mechanism.

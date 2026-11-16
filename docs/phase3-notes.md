# Phase 3/4 notes: STM32H573 endpoint attestation (working log)

## Endpoint: STM32H573I-DK with TF-M

- The board already ran TF-M v2.3.0 BL2 (MCUboot, OEM-iRoT, development keys, product state Open)
  with the Initial Attestation partition enabled. BL2 measures the secure (SPE) and non-secure (NSPE)
  images at boot; TF-M puts those measurements in every attestation token.
- The installed secure image (Zephyr's TF-M, 47b9f07b9) was not reproducible from a local build: its
  secure-gateway veneers sit at 0x0C085F00..40, the local upstream build's at 0x0C085FC0..E0, so an NS
  app linked against the local build faulted on its first secure call. Installed the matching pair
  instead: upstream TF-M v2.3.0 secure image + the Aegis prover (security counter 1 on all images,
  so rollback protection is not affected).
- Build trap: the api_ns signing step does not rerun on incremental builds; `prover-ns/build.sh`
  always builds from clean and checks the banner is inside the signed image.

## Prover (`endpoints/stm32h573/prover-ns`)

Bare-metal NS image. Line protocol on the ST-LINK console and on TCP 7444:
`CHAL <32-byte hex>` -> `TOKEN <len> <hex> END`. The NS side holds no key: the token is a PSA
attestation token (COSE_Sign1, ES256) made by TF-M's Initial Attestation service, 517 bytes,
0.2 s on the console (0.46 s end to end through the gateway and the relay).

Token contents seen on the board: challenge, instance ID, implementation ID (dummy), boot seed
(dummy), lifecycle 0x3000, profile PSA_IOT_PROFILE_1, and two software components whose
measurement values and signer IDs equal the SHA-256 hash TLV and key hash of the signed images
(`tools/image_measurement.py`).

**Key caveat:** the attestation key (IAK) is TF-M's published development key
(`platform/ext/common/template/tfm_initial_attestation_key.pem`), compiled into BL2's OTP
emulation. Anyone can forge tokens for it. The flow is real; the key is not. A per-device key
(for example derived from the STM32H5's hardware unique key in SAES) is the next step.

Ethernet: lwIP 2.2.1 (NO_SYS, polled) + ST HAL ETH, RMII, LAN8742A at MDIO 0 (ID 0007:c131 read
correctly). PHY reports no link (BSR 0x7809): the board's Ethernet port has no live cable yet.
Until it has, `host/serial_bridge.py` on the PC relays the same line protocol from TCP 7444 to the
console. The relay adds no trust; it can only drop or delay answers.

## Gateway fleet verifier (`gateway/aegisd/fleet.py`, runs on the PolarFire)

Standard-library Python + the board's openssl tool. Admits an endpoint only if the token verifies
with the enrolled IAK, carries the challenge just sent, and every software component matches the
policy (`gateway/policy/fleet.json`). Otherwise quarantined with reasons.

Board results 2026-11-16 (logs/stm32/):

| Case | Verdict |
|---|---|
| good prover 0.1.0 | ADMITTED |
| prover rebuilt as "0.1.0-tampered", signed with the trusted dev key, boots normally | QUARANTINED: component NSPE not allowed |
| re-attestation every 10 s while swapping good -> tampered -> good | ADMITTED x4, QUARANTINED x3 (first one about 6 s after the tampered image booted), 1 timeout during the reflash, ADMITTED x3 |

Host tests (`tests/host/test_fleet.py`): good node, tampered NS, replayed token, wrong key,
garbage reply, silent node, no service; same verifier with the openssl path.

Not done yet: enforcement (needs the gateway in the traffic path), Arduino node, ML-DSA on the
endpoint, per-device IAK.

## Post-quantum quote with a per-device key (2026-11-16)

New secure image: TF-M v2.3.0 (same configuration as before) plus the out-of-tree partition
`endpoints/stm32h573/tfm-aegis-partition` (built by its `build_tfm.sh`, reusing the SecureBench
build's fetched dependencies). Secure-gateway veneers stay at 0x0C085FC0..E0; secure RAM bss
100 KB of 127 KB; text 147 KB.

- Key: at partition init, seed = AES-256-ECB under the STM32H5 DHUK (SAES, KEYSEL=HW) of a fixed
  32-byte label; ML-DSA-65 key pair = KeyGen_internal(seed) with mldsa-native v2.0.0 (reduced RAM,
  deterministic signing, empty context). The seed is wiped after key generation.
- Quote: TF-M PSA token for the verifier's challenge + ML-DSA-65 signature over
  "aegis-endpoint-quote-v1\0" || token.
- Checks done: mldsa-native config interoperates with liboqs (PC); device key identical on 3 boots;
  device key differs from the keys an all-zero, all-ones or label key in SAES would give, and from
  the raw label as seed (consistent with the hidden DHUK being used; per-chip uniqueness needs a
  second chip and is not shown).
- Gateway (`fleet.py`, kind aegis-pq, ML-DSA verify with liboqs on the PolarFire): enroll-pq by
  trust on first use, then: good image ADMITTED (1.07 s through the relay); tampered NS image
  QUARANTINED (signature valid, NSPE measurement not allowed); wrong enrolled key QUARANTINED
  (signature invalid); real key restored -> ADMITTED.

Limits to state with every claim: product state Open with TF-M development keys, so anyone with
the debugger or the published image-signing key can replace the secure image, and any secure code
can use the DHUK; isolation level 1 (no isolation between secure partitions); enrolment is
trust on first use; deterministic ML-DSA (no hedged randomness).

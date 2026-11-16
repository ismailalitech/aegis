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

## ML-KEM-768 provisioning and the zero-trust credential loop (2026-11-16)

Secure partition (types 3-5): KEM_INIT derives a fresh ML-KEM-768 key pair (mlkem-native v2.0.0,
deterministic API) from prov_root (second DHUK-derived secret), the gateway's nonce and a counter,
and signs nonce || ek with the device ML-DSA-65 key. KEM_FINISH decapsulates, wipes the
decapsulation key and K, keeps session = SHA3-256("aegis-session-v1" || K || nonce || SHA3(ct)) in
secure RAM, and returns the confirmation tag SHA3-256("aegis-confirm-v1" || K || nonce || SHA3(ct)
|| SHA3(credential)). SESSION returns SHA3-256 of the session key (an identifier, not the key) and
SHA3-256 of the credential. The partition's SHA3-256 was checked against hashlib (lengths 0-5000,
block boundaries). Secure image: text 158 KB, bss 112 KB of 127 KB. The device ML-DSA key is the
same before and after the image update (derived from the DHUK, not from the image).

Gateway (`fleet.py`, `"provision": true` in the policy): after an ADMITTED verdict, if no valid
credential, run provisioning: verify the ML-DSA signature on ek, encapsulate (liboqs on the U54),
send ct plus a credential signed with the gateway's own ML-DSA-65 identity key (endpoint, key hash,
measurements, ct hash, issued, expires +1 h), check the confirmation tag, keep the session key
(mode 0600) and credential metadata in /var/lib/aegis/credentials/. On QUARANTINED the credential
and session key are deleted.

Board run (logs/stm32/kem-*/, gateway service journal, re-attestation every 30 s):

| Time (UTC) | Event | Verdict / credential |
|---|---|---|
| 14:51:19 | good image | ADMITTED, credential issued, session fc7f6742... |
| 14:51:50 | | ADMITTED, credential valid |
| 14:52:22 to 14:53:24 | tampered NS image (signed with the trusted dev key) | QUARANTINED, NSPE not allowed, credential revoked |
| 14:53:57 | good image again | ADMITTED, new credential, session 2abdaeed... |

`fleet.py session`: the session identifier reported by the STM32's secure side equals the gateway's,
and so does the credential hash (both runs). Host tests add: key-swap on the KEM key refused, wrong
confirmation tag refused, credential issued then revoked (34 host tests in total).

Limits: the endpoint does not yet verify the gateway's signature on the credential (only hashes it),
so authentication is one-way (gateway authenticates endpoint). The session key is not yet used for
traffic. The NS image is reproducible (same measurement on rebuild); only its ECDSA signature differs.

## NIST ACVP vectors on the STM32 (2026-11-16)

`endpoints/stm32h573/kat-ns`: a TEMPORARY Non-Secure test image running `kat_core.c`, which links
mldsa-native and mlkem-native with exactly the secure partition's configuration headers
(ML-DSA-65 reduced RAM, ML-KEM-768), built by the same toolchain for the same Cortex-M33 (64 KB stack
via a copied linker script). It is the same source and configuration as the secure image, not the
same binary. `tools/acvp_device.py` reads the ACVP JSON directly (independent of liboqs' driver) and
builds each FIPS 204 request (internal, external pure, pre-hash with OID, external mu;
deterministic and hedged).

| Target | Cases | Failed |
|---|---|---|
| PC harness (same core) | 265 | 0 |
| STM32H573 Cortex-M33 over the console (357 s) | 265 | 0 |

ML-KEM-768 keyGen 25, encaps 25, decaps 10; ML-DSA-65 keyGen 25, sigGen 120 (8 groups),
sigVer 60 (4 groups). Afterwards the prover image was written back; the gateway had quarantined the
STM32 (credential revoked) while the test image ran, then re-admitted it with a new session.

## Mutual authentication (2026-11-16)

The STM32 secure partition now accepts a provisioning credential only if it is signed with the
gateway's ML-DSA-65 key, pinned into the secure image at build time (`tools/gen_gateway_pin.py`,
key sha256 0c1d7820...), and its canonical body names SHA3-256 of this exchange's ciphertext.
Otherwise PSA_ERROR_INVALID_SIGNATURE (-149), no session.

Found while preparing the negative tests: a new KEM_INIT used to drop the established session, so
anyone reaching the prover's port could tear a session down. Fixed: the session is replaced only
when a new exchange completes. The gateway also re-checks the endpoint's session every cycle and
re-provisions on mismatch. And `fleet.py watch` now reloads the policy file every cycle (the
service kept quarantining with an outdated SPE measurement after an image update until restarted).

`tests/board/mutual_auth_checks.py` on the real STM32 (logs/stm32/mutual-*/):

| Case | Result |
|---|---|
| credential signed by a foreign key (from the PC) | refused, ERR pq -149 |
| credential signed by the real gateway key, bound to another ciphertext (on the gateway) | refused, ERR pq -149 |
| established session after both | unchanged (fac9a735...), gateway and STM32 agree |

## Session-key heartbeats (2026-11-16)

Partition type 6 HEARTBEAT: counter (8 bytes, rising) and SHA3-256("aegis-hb-v1" || session ||
nonce || counter || status), where status is a short text from the Non-Secure side
(uptime, link, firmware). Prover command `PQHB <nonce>`. The gateway uses it every cycle to check
that a valid credential's session is still held by the endpoint (replaces the session-id query,
which was not bound to a fresh challenge and could be replayed); a failed heartbeat triggers
re-provisioning. MAC construction: SHA3-256 over key-prefixed data (SHA-3 has no length
extension; KMAC256 would be the standard choice).

Board: after provisioning, the gateway journal shows "valid, heartbeat 1, 2, 3 ..." with the
authenticated status ("uptime_s=81;link=0;..."). Timing on the gateway through the relay
(median of 5): heartbeat 0.131 s, full ML-DSA-65 re-attestation 1.064 s (the 7.7 KB quote crosses the
115200-baud console; over Ethernet both will be shorter).

## STM32 over its own Ethernet (2026-11-16, cable connected)

DHCP gave the STM32 192.0.2.20 (MAC <mac>); the policy now points there and the PC
relay is retired (it had just died with a USB serial I/O error when the cables were moved; the
gateway correctly quarantined the STM32 during that cycle). From the PC over Ethernet: PQKEY in
6 ms, a full PQ quote (515-byte token + 3309-byte ML-DSA-65 signature) in 0.30 s, signature valid,
key equal to the enrolled one. The gateway service admitted the STM32, issued a new ML-KEM
session, heartbeats report link=1. `tools/demo.sh` over Ethernet: same verdicts as before, 1 min 56 s
(logs/demo/20261116-190610). Regression with STM32=192.0.2.20:7444: see logs/regression.

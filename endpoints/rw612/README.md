# NXP FRDM-RW612: an Aegis endpoint with a chip-bound key (kind `aegis-device`)

The FRDM-RW612 carries an NXP RW612 (Arm Cortex-M33 at 260 MHz with TrustZone, the EdgeLock Secure Subsystem
"ELS", Wi-Fi 6 and BLE radios) and a 100 Mb/s Ethernet port (KSZ8081 PHY). Here it runs a Zephyr application that
speaks the same Aegis line protocol as the STM32 and Linux endpoints, on TCP 7444.

## What it does

At start-up (`prover/src/main.c`, `prover/src/aegis_els.c`):

    seed      = HMAC-SHA256(CKDF(die master key, "AEGIS-RW612\1"), "aegis-rw612-mldsa65-seed-v1")    inside ELS
    prov_root = HMAC-SHA256(CKDF(die master key, "AEGIS-RW612\1"), "aegis-rw612-provision-root-v1")  inside ELS
    (pk, sk)  = ML-DSA-65.KeyGen_internal(seed)           mldsa-native v2.0.0; the seed is wiped
    MAC       = 02:ae + the first 4 bytes of pk           as on the STM32 endpoints

The die master key sits in ELS slots 0 and 1 (`0x60010161`, `0x60010121`: 256-bit, CKDF only, device-unique). The
boot ROM loads it from the PUF; software can never read it. The intermediate key `CKDF(...)` exists only in an ELS
slot and is deleted after the two HMACs. So the same chip gives the same ML-DSA-65 key on every boot, and another
chip gives another key, with no secret stored in flash.

Then DHCP, and the protocol (the Prover SDK's core, `sdk/src/aegis_proto.c`, no RTOS code in it, so the PC tests build
the same file; `prover/src/main.c` is the SDK's port to this firmware):

| Request | Reply |
|---|---|
| `PQKEY` | the ML-DSA-65 public key |
| `PQCHAL <32 bytes>` | CBOR claims (PSA claim numbers, profile `aegis-rw612-els-v1`, the challenge, one measurement `APP` = SHA-256 of the firmware image as it sits in flash) and an ML-DSA-65 signature over `"aegis-endpoint-quote-v1\0" ‖ claims` (hedged: 32 bytes from the RW612's hardware TRNG in every signature) |
| `PQKEMINIT <nonce>` | an ML-KEM-768 key for this exchange, derived from `prov_root`, signed; with the challenge of the last quote as the nonce, signed over that quote's transcript (`docs/architecture.md`, "One transcript"; in source, this firmware not rebuilt) |
| `PQKEMFIN <ct> <credential>` | the confirmation tag, only if the credential is signed by the gateway key pinned in the image (`gateway_pk.h`) and names this exchange's ciphertext and this device's key |
| `PQHB <nonce>` | a KMAC256 heartbeat over the session (`"aegis-hb-v2"`) |
| `PQSESSION` | the session ID and the credential hash |

The constructions are those of every Aegis device (the core's head comment gives them); the PQ library
configurations and KMAC256 are the SDK's (`sdk/crypto`, `sdk/src`), and the pinned gateway key is the one header all
device builds include (`endpoints/stm32h573/tfm-aegis-partition/gateway_pk.h`, `tools/gen_gateway_pin.py`).

## What it proves, and what it does not

The key proves **the chip**: a quote signed with the enrolled key comes from this RW612 and no other. The
measurement is computed **by the firmware itself**: a modified firmware that wanted to lie could report the good
image hash, because ELS hands the same derived secret to any code running on this chip. The gateway labels the
verdict accordingly (`"trust": "device-key"`), between the Linux endpoint (`software`) and the STM32 with TF-M, where
the measurement comes from the secure boot chain and the key from the secure side.

What would close the gap, in order: put the prover in the TrustZone secure side (TF-M exists for the RW612 in NXP's
Zephyr tree), and have a measured boot stage give the secure side the image hash; with secure boot fused on, the
ROM would also verify that stage. Neither is done here: no fuse of this board is written.

## Results (2026-11-18, evidence/console/rw612-endpoint.txt)

- Same key (`sha256 219414c5…`) across resets and across two different images; the image measurement equals
  `sha256sum zephyr.bin` (146 308 bytes).
- 20 attestations back to back from the PC with the gateway's verifier: 20 admitted, 73 to 302 ms per quote
  (one ML-DSA-65 signature on the Cortex-M33 plus the network).
- On the real gateway (PolarFire SoC, `aegis-fleet`): admitted with device-key trust, a credential issued over
  ML-KEM-768 and accepted by the board, KMAC256 heartbeats verified.
- Tamper test: the same prover rebuilt with one configuration value changed (`CONFIG_NET_HOSTNAME`) gives another
  image. The key still signs validly, but the gateway quarantines the board (`component APP not allowed`) and
  revokes its credential. With the good image flashed back: admitted again, a new session, heartbeats.
- PC tests: `tests/host/test_rw612_proto.py` builds `sdk/src/aegis_proto.c` for the PC (through the reference port,
  `sdk/ports/host`) and runs the gateway code against it
  (attestation, key derivation determinism, provisioning, heartbeats, forged and misbound credentials, malformed
  requests): 7 of 7.

## Figures and the recording

The diagrams are in `docs/diagrams/rw612.yaml` (key derivation, the endpoint, the three trust levels, the ELS slots)
and the console figures come from `evidence/console/rw612-endpoint.txt` (`tools/make_console_figures.py`, then
`tools/gen_diagrams.py`). `tools/rw612/record_demo.sh` records the tamper demo on screen: an xterm with three tmux
panes (the gateway journal, the board console with LAN addresses masked, the steps), grabbed by ffmpeg, then encoded at
4x speed. The site's lab 57 shows the result.

## Build and flash

    endpoints/rw612/build.sh          # build only
    endpoints/rw612/build.sh flash    # build and flash through the board's MCU-Link (J-Link firmware)

Needs a Zephyr v4.5.0 workspace with the `hal_nxp`, `cmsis` and `cmsis_6` modules
(`west init -m https://github.com/zephyrproject-rtos/zephyr --mr v4.5.0`, then
`west config manifest.project-filter -- '-.*,+hal_nxp,+cmsis,+cmsis_6'` and `west update`), Zephyr SDK 1.0.1 (the
minimal bundle plus the `arm-zephyr-eabi` toolchain), mldsa-native and mlkem-native v2.0.0, and the SEGGER J-Link
software. The board's on-board MCU-Link shows SEGGER's terms of use for MCU-Link once per day; they must be accepted
on the PC's screen before the first connection.

Gateway side: kind `aegis-device` in `gateway/aegisd/fleet.py`, and a policy entry such as

    {"name": "frdm-rw612", "kind": "aegis-device", "host": "<board address>", "port": 7444,
     "pq_pub_file": "keys/frdm-rw612.mldsa65.pub",
     "allowed": [{"type": "APP", "measurement_value": "<sha256 of zephyr.bin>"}],
     "provision": true, "heartbeat_mac": "kmac256"}

The key file is enrolled on first use (`fleet.py enroll-pq`), as for the other PQ endpoints.

## Pitfalls met on the way (all on this board)

- **A 256-bit ELS key takes two slots.** The target of a 256-bit CKDF must be an even base slot with the next slot
  free. The first version asked for slot 19 (the last): the board then reset over and over. With Zephyr's default
  deferred logging nothing reached the console, not even the boot banner, so it looked like a silent hang (the
  debugger showed the kernel timer standing still); `CONFIG_LOG_MODE_IMMEDIATE=y` showed the reset loop, and a
  trace of each step placed it in the CKDF.
- ELS is already on when the application starts (the boot ROM uses it), so the prover does not call
  `mcuxClEls_Enable_Async()`, which writes the whole `ELS_CTRL` register.
- **Connection contexts.** Every closed TCP connection keeps its context through TIME_WAIT, and the gateway opens
  several in a row (a provisioning is three): `CONFIG_NET_MAX_CONN=24`.
- **The debug link.** A charge-only or weak USB-C cable makes the MCU-Link drop off the bus (`error -71`) or reboot
  when it powers the debug port; use a data cable straight into the PC.
- The factory Wi-Fi demo was backed up before the first flash (the first 16 MB of the 64 MB flash, outside the
  repository).

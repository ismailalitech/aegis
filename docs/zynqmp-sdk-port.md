# ZynqMP: the trusted application on the Prover SDK (transcript v2, endorsement)

The ZynqMP endpoint (`zynqmp-te0808`, kind `aegis-tee`, profile `aegis-zynqmp-optee-v1`) is admitted with the
PUF-bound key, but its session is unbound and its key is not endorsed. The reason: the card still runs TA 0.1.1,
built before the Prover SDK, and that TA does not speak transcript v2. TA 0.2.0 is the same trusted application
built on the SDK's core (`sdk/src/aegis_proto.c`), the source the STM32 and RW612 images run. With it the gateway
can require `"transcript": "v2"` and `"endorsement": "required"` for this board, as it already does for the other
three. This page has the build, the host tests, the boot image request for the Windows PC, the card swap and the
gateway steps. The gateway steps are described here, not applied.

## What changes on the board

| Part | Changes? | Why |
|---|---|---|
| TA `b56a99ca-1c3c-40c8-af55-b8dd5ee03213` | 0.1.1 to 0.2.0 | the SDK core: quote, exchange bound to the quote (transcript v2), KMAC256 heartbeats, the session ended on the secure clock |
| OP-TEE (`tee-raw.bin`, TEE partition of BOOT.BIN) | yes, only the TA embedded in it | the TA is an early TA (`EARLY_TA_PATHS`), see below |
| Linux bridge `aegis_tee_bridge` (rootfs) | no | it passes lines and has not changed since phase A; the line protocol is the SDK's |
| FSBL, PMU firmware, bitstream, TF-A, U-Boot, kernel, rootfs | no | |
| Identity key | no | the key comes from the HUK (from the PUF-derived seed) and the TA's UUID, and neither changes; it stays sha256 `c02f156d609116a6632675fcad8cdae46cfc9267fdd1baab1567ceeb5e5527c9` |
| Measurement `TEE` | yes | the FSBL measures the TEE partition, which now holds the new TA |

### Why BOOT.BIN has to change

We would have preferred to change only files on the card's root file system and keep BOOT.BIN `ff57c4fd...`. With
this OP-TEE that is not possible without giving away the key:

- The TA is built into OP-TEE as an early TA. OP-TEE looks for a TA in its stores in a fixed order: the early TA store
  (priority 2) comes before the REE file system store (priority 9) (`core/kernel/early_ta.c` and `ree_fs_ta.c` in
  4.7.0). A `.ta` file in `/lib/optee_armtz` with the same UUID would never be loaded.
- Loading the new TA from the REE file system under a new UUID would work, but this OP-TEE checks TA signatures with
  the public development key (`keys/default_ta.pem`). Anyone who is root on Linux could then sign their own TA with
  that UUID, and it would get the same `PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY` output, that is the identity seed. The
  early TA rules this out: OP-TEE always loads the built-in TA for its UUID.

So the TEE partition changes, and with it BOOT.BIN. The Windows PC has to assemble the new BOOT.BIN, because it alone
holds the red key, and it uses the request below. Nothing else in the boot image changes.

## The port

The OP-TEE port of the SDK sits next to its build system, as the STM32 and RW612 ports do (`sdk/README.md`, "The
ports to chips live with their build systems"). `sdk/ports/` holds only the PC and Linux ports.

- `endpoints/zynqmp/optee/ta/aegis_ta.c`: `struct aegis_platform` for OP-TEE.
  - Random numbers: `TEE_GenerateRandom`.
  - Clock: `TEE_GetSystemTime`, which is CNTPCT-based on this platform. When `gpd.tee.systemTime.protectionLevel`
    is below 1000 the TA reports no clock, so no session starts.
  - Measurements: the FSBL's hand-off, read through the `aegis.boot` PTA.
  - Profile: `aegis-zynqmp-optee-v1` only with a valid hand-off and the PUF black-key flags; `-devhuk-v1` otherwise.
  - Status text for the heartbeat: `requests=N;fw=zynqmp-optee-0.2.0`.
  - Identity seed and exchange root: from the system PTA. They are wiped after `AEGIS_PROVER_INIT`.
  - Transport: one TA command, `AEGIS_TA_CMD_LINE`. The TA copies each line out of shared memory before the core
    reads it. It is the SDK's line protocol (`PQKEY`, `PQCHAL`, `PQKEMINIT`, `PQKEMFIN`, `PQHB`, `PQSESSION`).
- `endpoints/zynqmp/optee/bridge/aegis_tee_bridge.c`: on TCP 7444, one request line per connection, passed to that
  command unchanged.
- `ta/sub.mk` sets version 0.2.0 and the TA's limits: 8 measurements, claims of up to 1440 bytes. `aegis_ta.c`
  checks at build time that the claims fit and that the `PQCHAL` reply fits.

## Build (Linux PC, done)

The OP-TEE source tree and configuration are those of the TEE now on the card. The two `conf.mk` files are
identical, apart from the output path. Only the TA source differs:

    GATEWAY_PK_HEX=~/work/zynqmp/gateway.mldsa65.pub endpoints/zynqmp/optee/build_optee.sh <OP-TEE tree> ~/work/zynqmp/optee-sdk1

The verifier key built in is the gateway's ML-DSA-65 key, sha256 `0c1d78209c0be236...a1f4841f`, the same key as in the TA
now on the card. The TA source is this branch's: `aegis_ta.c`, `sub.mk`, `user_ta_header_defines.h` and the SDK
files staged in the build are byte for byte the repository's. A second build of the TA alone
(`build_ta.sh` into `~/work/zynqmp/ta-sdk2`) gave the same stripped ELF.

| File (`~/work/zynqmp/sdk-port-transfer/`, with `SHA256SUMS`) | Size | sha256 |
|---|---|---|
| `tee-raw.bin`: OP-TEE with TA 0.2.0 built in; **the only new BOOT.BIN input** | 576984 | `b7435d9a90fa332bea8e3f338b917ee3c75036c528a4e254f4a766fa2b0659a7` |
| `b56a99ca-1c3c-40c8-af55-b8dd5ee03213.stripped.elf`: the TA as embedded | 162664 | `96e10945975f8091787becabcd2b7a250a598170f54789c7d07027b5b11ade45` |
| `b56a99ca-1c3c-40c8-af55-b8dd5ee03213.ta`: the signed TA, for the record; **not copied to the card** | 163248 | `17350b2712f897e67a8427561308106891e115830d755998ee2082e73bebf062` |

For comparison, the TEE now on the card is `~/work/zynqmp/optee-c7-expiry/optee/core/tee-raw.bin`: 572888 bytes,
sha256 `257cc9dcb39958f7a88fece034c1166f4e634c420da74f1555a65919e1042c3e`, OP-TEE build `Thu Nov 19 13:39:27 UTC 2026`.
The new one is build `Fri Nov 20 19:03:12 UTC 2026`.

The FSBL measures a partition as the first 32 bytes of SHA3-384 over the partition as stored. The phase B evidence
confirms this: TEE `53352832...` = SHA3-384 of `optee-b4`'s `tee-raw.bin`. So the board will report:

| Measurement | Now (TA 0.1.1) | After the swap (TA 0.2.0) |
|---|---|---|
| `TEE` | 572888 bytes, `5600620f3e1e352b1ca4783817a77995b594b35e6dcfb2c3a479579251be1bd5` | 576984 bytes, `011989d769a3f8f6a0028d19dc398b1ef3af0a0b45c56c59270630bb5c69c1da` |
| the other six | unchanged | unchanged |

## Host tests (done)

- `tests/host/test_zynqmp_ta_port.py`: the board's bridge (its `main()` and socket code) and the TA with the SDK
  core, built with the TA's `sub.mk` flags and joined by an OP-TEE stand-in (`endpoints/zynqmp/optee/tests/ta_board.c`,
  `stub/`). They are run against the gateway's `fleet.py` and the endorser's `aegis_provision.py`. It checks:
  - attestation with `aegis-zynqmp-optee-v1`, "trustzone", the seven partitions in the hand-off's order;
  - a changed TEE partition quarantined under the same key;
  - the development profile without the hand-off, refused without `allow_dev_profile`;
  - transcript v2: an exchange that continues the quote, KMAC256 heartbeats with `fw=zynqmp-optee-0.2.0;ttl=`,
    `PQSESSION`, a second exchange on the same quote refused with the session kept;
  - the session ended by the TA's own clock: alive at +3800 s, `ERR pq expired` at +3826 s (3600 s plus the core's
    1/16 margin);
  - no session on a time of protection level 100;
  - the key endorsed with `prov.endorse`, `enroll-endorsed`, then attestation and a bound exchange with
    `"endorsement": "required"` (enrolment "endorsed"), and the same image with another chip's seed refused;
  - the TA's peak stack on a stack of `TA_STACK_SIZE` (64 KiB) through a whole cycle;
  - line limits.
- `endpoints/zynqmp/optee/tests/run.sh`: OP-TEE's real key derivation against Python's HMAC, the hand-off parser,
  and the TA on the stand-in. It passes.
- `tests/host`: all of it passes. `tests/host/test_sdk_golden.py` shows 0 differences (the SDK core is untouched).

## Request for the Windows PC session: BOOT.BIN with the new TEE partition

Only the Windows PC can do this, because only it holds the red key. Do not build or sign BOOT.BIN on the Linux PC.

**Inputs.** Use the six partition inputs of the image now on the card (BOOT.BIN `ff57c4fd...`), as staged on the
Windows PC with their `SHA256SUMS`. Replace exactly one of them:

| Input | sha256 | Note |
|---|---|---|
| `tee-raw.bin` (new) | `b7435d9a90fa332bea8e3f338b917ee3c75036c528a4e254f4a766fa2b0659a7` | from `~/work/zynqmp/sdk-port-transfer/` (Linux PC), 576984 bytes |
| `tee-raw.bin` (replaced) | `257cc9dcb39958f7a88fece034c1166f4e634c420da74f1555a65919e1042c3e` | must be the one staged for `ff57c4fd`; if it is not, stop and report |
| `fsbl.elf`, `pmufw.elf`, `system.bit`, `bl31.elf`, `u-boot.elf` | as for `ff57c4fd` | unchanged; check them against that image's `SHA256SUMS` |

**BIF.** `endpoints/zynqmp/windows/puf/boot-encrypted.bif.template`, filled in by `make_boot_encrypted.ps1` with the
same `-RegDir` (the same PUF registration, helper data and black key) and the same `-Auth` as `ff57c4fd`. It is
**boot-header PUF mode only**: `[fsbl_config] ... puf4kmode, shutter=..., pufhd_bh`, `[keysrc_encryption] bh_blk_key`.
**No eFUSE and no OTP programming of any kind.** The partition line that takes the new file is unchanged:

    [destination_cpu=a53-0, exception_level=el-1, trustzone, load=0x60000000, startup=0x60000000] tee-raw.bin

**Expected output.** `make_boot_encrypted.py` reports the boot header's key source `0xA35C7C53` (black key in the
boot header), the output holds no key, and there is a `SHA256SUMS`. Send the BOOT.BIN's sha256 to the Linux session
before the file itself.

**Expected on COM11 after the swap**, which the Windows session reads; JTAG stays off with this secure image:

    <the same FSBL banner as with ff57c4fd>
    NOTICE:  BL31: v2.12.0(release):xilinx-v2025.2
    I/TC: OP-TEE version: 4.7.0-dev (gcc version 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1)) #1 Fri Nov 20 19:03:12 UTC 2026 aarch64
    I/TC: Aegis hand-off: flags <as with ff57c4fd>, 7 measurements, keys from the device seed
    I/TA: Aegis TA: key ready, profile aegis-zynqmp-optee-v1, hand-off status 1 flags <same> bh_key_src 0xa35c7c53 csu_status <same>, 7 measurements, session clock trusted (level 1000)

The OP-TEE build date is what shows that the new TEE runs: `Fri Nov 20 19:03:12`, where the old one shows
`Thu Nov 19 13:39:27`. If the TA line says `devhuk` or `key FAILED`, or there is no FSBL banner, recover as below.

## Card swap (Linux session; the user presses S1)

Only BOOT.BIN on the card's FAT partition changes. The bridge, the service and the rootfs stay as they are.

1. Copy the new BOOT.BIN to the board's `/root/incoming/`. Compare its sha256 with the value the Windows session
   reported.
2. On the board, keep the current image and put in the new one:

       cat /proc/sys/kernel/random/boot_id                    # write this down: the baseline
       mount -o remount,rw /boot/firmware
       cd /boot/firmware && sha256sum BOOT.BIN                # ff57c4fd...
       test -e boot-c7-on-c3.bin || cp BOOT.BIN boot-c7-on-c3.bin
       cp /root/incoming/BOOT.BIN BOOT.BIN.new && sync && sha256sum BOOT.BIN.new   # the Windows value
       mv BOOT.BIN.new BOOT.BIN && sync && sha256sum BOOT.BIN boot-c7-on-c3.bin
       mount -o remount,ro /boot/firmware

3. Ask the user for S1, a full power cycle. Do not reboot from Linux.
4. Proof of the new boot, which needs both of these. A file's sha256 or a small `uptime` proves nothing.
   - `/proc/sys/kernel/random/boot_id` differs from the baseline.
   - The Windows session sees a fresh FSBL banner and the OP-TEE line with `Fri Nov 20 19:03:12` on COM11.
5. From the Linux PC, through the bridge:

       printf 'PQKEY\n' | nc -q 3 <board> 7444 | python3 -c 'import sys,hashlib; print(hashlib.sha256(bytes.fromhex(sys.stdin.read().split()[2])).hexdigest())'
       # c02f156d609116a6632675fcad8cdae46cfc9267fdd1baab1567ceeb5e5527c9  (the same key)

   `systemctl status aegis-tee-bridge` should be active. The gateway's next cycle will **quarantine** the board,
   because `TEE` no longer matches. That is expected until step 1 of the next section.

**Recovery.** If the board does not come up, the user moves the card to the Linux PC's reader, and
`cp boot-c7-on-c3.bin BOOT.BIN; sync` on its first partition. Do not use JTAG; it is off with this image.

## Gateway policy and endorsement (described, not applied)

All of this is on the gateway's `fleet.json` (`/root/aegis/gateway/policy/fleet.json`) and the bench PC. Back up
the policy first. Edit it on the PC and put it in place with a rename, as in `docs/enrolment.md`, "Runbook".

1. **The new TEE value.** In the entry `zynqmp-te0808`, set the `allowed` item of type `TEE` to
   `011989d769a3f8f6a0028d19dc398b1ef3af0a0b45c56c59270630bb5c69c1da`, and leave the other six as they are. Next cycle:
   `zynqmp-te0808 ADMITTED (trustzone trust)`, heartbeat status `fw=zynqmp-optee-0.2.0;ttl=...`. The session is still
   unbound.
2. **Transcript v2.** Add `"transcript": "v2"` to the entry. Next cycle: the gateway provisions a new session that
   continues the quote (`fleet.py session` shows transcript `v2`), and the unbound note is gone from the verdict.
3. **Endorse at the bench**, as for the STM32s and the RW612. The endorser's key is sealed to this PC's TPM, so run
   the tool under the `tss` group. `$W` is the endorser's working directory of the runbook, holding the policy you
   edited in step 1.

       sg tss -c ".venv/bin/python provision/aegis_provision.py reference $W/fleet.json zynqmp-te0808 --reference $W/reference-zynqmp.json"
       # review: kind aegis-tee, profile aegis-zynqmp-optee-v1, TEE = 011989d7..., the other six as in phase B
       sg tss -c ".venv/bin/python provision/aegis_provision.py endorse zynqmp-te0808 --reference $W/reference-zynqmp.json \
           --host <board>:7444 --out $W/records --notes 'bench LAN, TA 0.2.0' \
           --expect-key-sha256 c02f156d609116a6632675fcad8cdae46cfc9267fdd1baab1567ceeb5e5527c9"

   Type `yes` only if the address is the ZynqMP's, as you know it from its console or its DHCP lease. Expected:
   `"endorsed": true`, family `aegis-tee/aegis-zynqmp-optee-v1`, seven components.
4. **Enrol it on the gateway.** Copy `$W/records/zynqmp-te0808.json` to the gateway, then
   `python3 fleet.py enroll-endorsed ../policy/fleet.json <record>`. Expected: `enrolled zynqmp-te0808: ... pins record
   <record_sha256>`. If it says that another key is pinned, stop.
5. **Require it.** Add `"endorsement": "required"` to the entry, then run `fleet.py check ../policy/fleet.json`:
   `enrolment: endorsed by bench-pc (record ..., pinned by endorsement_sha256, ...)`. Next cycle:
   `zynqmp-te0808 ADMITTED ... [endorsed by bench-pc]`, and the session is kept.

**Undo.** Restore the backed-up `fleet.json`. The board itself can stay on TA 0.2.0: under the old entry with its
`TEE` value it is quarantined, so for a full undo also put `boot-c7-on-c3.bin` back.

## Not tested

- TA 0.2.0 on the board. It is built and runs on the PC stand-in only. Still to see: the stack and heap inside OP-TEE
  (the PC measures the stack against the same 64 KiB), and timing on the A53.
- The new BOOT.BIN, which does not exist yet; that is the Windows request above.
- The endorsement and transcript v2 against the real board and the real gateway.
- The stand-in's key derivation is a hash of a seed text. OP-TEE's real derivation is checked separately against
  known answers (`run.sh`), and "same key after the swap" is an argument from the design (same HUK, same UUID). Step 5
  of the swap checks it.

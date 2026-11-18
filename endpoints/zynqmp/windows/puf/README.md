# ZynqMP phase B, step 1: PUF registration in boot-header mode and the encrypted BOOT.BIN

This is the recipe for the bench's Windows PC (Vivado/Vitis 2025.2 in `C:\AMDDesignTools\2025.2`, xsdb, the green-dot
TE0790 on J12, console on COM11). It covers phase B of `docs/zynqmp-key-design.md` up to a BOOT.BIN whose FSBL the
boot ROM decrypts with the PUF-recovered key. It does not cover the FSBL hook that derives the seed (a later step).

Status: **not run yet.** The Python tools were tested on the Linux PC with dummy keys: source preparation,
preprocessor guard, ELF check, log parser, and BIF + bootgen (built from tag `xilinx_v2025.2`) with a check of the
boot header. The PowerShell, Vitis and xsdb scripts have not been run. "Untested and uncertain" at the end lists
what has to be checked on the bench.

Hard rules (as in `../../README.md`): no eFUSE is written, no BBRAM is programmed, no FTDI EEPROM tool is run. No key
material goes into the repository or to the Linux PC.

## Where the keys go

| Item | Where it exists | Secret? |
|---|---|---|
| red key (`red_key.hex`, AES-256) | `C:\tz\aegis-keys` on the Windows PC only (owner-only ACL). During the build, also in `C:\tz\aegis-keys\build` (patched header, Vitis workspace, ELF). Once, in the board's RAM and AES engine during the JTAG registration run, because the PUF can only encrypt a key it is given. bootgen's temporary `.nky` file. | yes |
| black-key IV (`black_key_iv.hex`) | key folder; ends up in the boot header | no (public in BOOT.BIN) |
| helper data, black key | `C:\tz\aegis-keys\reg-<time>\`; ends up in the boot header | no: useless on another chip, and on this chip it only yields the device key inside the boot ROM |
| encrypted BOOT.BIN | `C:\tz\stage\boot-enc-<time>\`, then the SD card | no |

The red key never reaches the Linux PC. That is why the encrypted BOOT.BIN is built on the Windows PC. The Linux-side
partitions (TF-A, OP-TEE, U-Boot, plus the bitstream) are copied *to* the Windows PC, not the other way round.
The build directory and every bootgen temp directory are deleted automatically (`cleanup_puf_build.ps1` deletes them
too if a script stopped half-way). The board keeps nothing: the app runs from DDR, and the power cycle after the run
clears DDR and the AES key registers.

## Files

| File | Role | Runs |
|---|---|---|
| `gen_keys.ps1` | A: red key + IV from .NET `RandomNumberGenerator`, ACL owner-only, never overwrites | PowerShell |
| `prepare_puf_src.py` | copies the two example files (SHA-256 pinned to `xilinx_v2025.2`), sets the switches, inserts key, IV and the guard block, removes the red-key print; `--verify` re-checks a copy | Python 3 |
| `vitis_puf_app.py` | Vitis 2025.2: throw-away platform from the XSA, xilsecure + xilskey in the A53 domain, app `puf_reg` | `vitis -s` |
| `build_puf_app.ps1` | B1: runs the two above, then `check_puf_elf.py`; writes `build\BUILD_OK.txt` | PowerShell |
| `check_puf_elf.py` | static check of the ELF: no eFUSE/BBRAM writer reachable (call graph over BL/B/B.cond/CBZ/TBZ, address-taken functions as extra roots), eFUSE blocks compiled out, key compiled in once | Python 3 |
| `run_puf_registration.ps1` | B2: re-checks everything, checklist + typed confirmation, COM11 capture, xsdb run, log parse, deletes the build; `-PostCheck` for B3 | PowerShell |
| `run_puf_registration.tcl` | xsdb: read-only eFUSE snapshot, refuse if the PUF eFUSEs are not blank, JTAG RAM boot as `../jtag_boot.tcl` (PMU fw, FSBL), then the app | xsdb |
| `efuse_status.tcl` | read-only: eFUSE cache registers and boot status registers | xsdb |
| `parse_puf_log.py` | COM11 log to `helperdata.txt`, `black_key.txt`, `black_iv.txt`, `puf_info.txt`, with self-checks | Python 3 |
| `boot-encrypted.bif.template`, `make_boot_encrypted.py`, `make_boot_encrypted.ps1` | C: fresh `.nky` (Key 0 = red key, fresh IV 0), BIF, bootgen, then checks of the boot header fields and the partition table; output has no key | Python 3, bootgen |
| `cleanup_puf_build.ps1` | deletes the build directory and bootgen temp directories | PowerShell |
| `puf_common.ps1` | paths (`C:\tz\aegis-keys`, COM11, the AMD tools), Python lookup, ACL checks | dot-sourced |

Python 3 is needed on the Windows PC (`py -3`, a `python.exe` on PATH, or one found inside the AMD install).
Scripts run as `powershell -ExecutionPolicy Bypass -File <script>` from this folder (the repository checkout,
`C:\tz\repo\endpoints\zynqmp\windows\puf`).

## eFUSE safety of the example (Vitis 2025.2 sources)

Reviewed: `lib/sw_services/xilskey/examples/xilskey_puf_registration_example.c` (sha256 `77c8b879...`) and
`xilskey_puf_registration.h` (sha256 `6db0dc3b...`), embeddedsw tag `xilinx_v2025.2`, and the library functions it
calls (`xilskey/src`). `prepare_puf_src.py` refuses any other version of the two files.

Every call in the example that can write an eFUSE:

| Line (`.c`) | Call | Compiled only if |
|---|---|---|
| 210 | `XilSKey_ZynqMp_EfusePs_WritePufHelprData` | `XPUF_FUSE_SYN_DATA` (block 194-312) |
| 245 | `XilSKey_ZynqMp_EfusePs_WritePufAux` | same block |
| 257 | `XilSKey_ZynqMp_EfusePs_WritePufChash` | same block |
| 269 -> 641 | `XilSkey_Program_Black_Key` -> `XilSKey_ZynqMp_EfusePs_Write` (AES key row), then `CacheLoad` (651) | same block; the function itself (624-675) and `XilSKey_Generate_FuseFormat` (402-608) sit in `#if defined XPUF_FUSE_SYN_DATA` (389-677), prototypes 82-85 |
| 323 | `XilSKey_Write_Puf_EfusePs_SecureBits` (SYN_INVALID, SYN_WRLK, REGISTER_DISABLE, RESERVED) | `XSK_PUF_PROGRAM_SECUREBITS == TRUE` (block 314-330) |

`XPUF_FUSE_SYN_DATA` is defined only by header lines 169-173, when `XSK_PUF_PROGRAM_EFUSE == TRUE`. The four
secure-bit values are only defined inside `#if (XSK_PUF_PROGRAM_SECUREBITS == TRUE)` (header 144-149). With
`XSK_PUF_PROGRAM_EFUSE FALSE` and `XSK_PUF_PROGRAM_SECUREBITS FALSE`, neither block is compiled.

The code that does run writes no eFUSE:
- 105-128 (`XSK_PUF_IF_CONTRACT_MANUFACTURER`, FALSE here): `XilSKey_ZynqMp_EfusePs_ReadSecCtrlBits`, a read.
- 131 `XilSKey_Puf_Registration` (`xilskey_eps_zynqmp_puf.c` 623-731) writes only CSU PUF registers: CFG0, CFG1,
  SHUT and CMD at 0xFFCA4004/4008/400C/4000 (lines 647-671). It reads the PUF word and status registers. Its access check
  `XilSkey_Puf_Validate_Access_Rules` (1095-1165) reads the eFUSE *cache* through `ReadSecCtrlBits`
  (`xilskey_eps_zynqmp.c` 536-557), `Read_Puf_EfusePs_SecureBits` (920-941), `ReadPufAux` (546-570) and `ReadPufChash`
  (414-436), all `XSK_EFUSEPS_READ_FROM_CACHE`, all plain register reads. It refuses to register if the PUF eFUSEs
  already hold data and RSA is not enabled (1142-1150).
- 147-170: UART prints. 173 `XilSKey_Puf_Encrypt_Key` (780-900): hex conversion, CSU DMA, `XSecure_AesInitialize`
  with the device key (`XSK_PUF_DEVICE_KEY` = 1) and `XSecure_AesEncryptData`, which is AES only.
- 332-371 (`XSK_PUF_READ_SECUREBITS`, FALSE here): cache reads only.

The library's own eFUSE options (`XILSKEY_access_*`, xilskey.cmake) stay at their default OFF. Those options do not
remove `XilSKey_ZynqMp_EfusePs_Write`, so nothing is assumed from them.

There is no doubt left in the source. Three guards are added anyway, so a wrong header or a different version cannot
slip through:
1. **Source guard** (`prepare_puf_src.py`, inserted after the includes): `#error` unless `XSK_PUF_INFO_ON_UART` is TRUE,
   `PROGRAM_EFUSE`, `PROGRAM_SECUREBITS`, `READ_SECUREBITS` and `IF_CONTRACT_MANUFACTURER` are FALSE, the four secure
   bits are FALSE if defined, `XPUF_FUSE_SYN_DATA` and `XPUF_CONTRACT_MANUFACTURER` are undefined, and the mode is 4K.
   After that, each of the 13 eFUSE/BBRAM write APIs becomes a macro that expands to an undeclared identifier, so any
   compiled call fails the build. Tested with `aarch64-linux-gnu-gcc -E` on the patched files and stub BSP headers.
   The real settings pass, and the calls left in `main` and its helpers are `XilSKey_Puf_Registration`,
   `XSecure_AesInitialize`/`EncryptData`, `XCsuDma_*`, `Xil_DCache*` and prints. Flipping any of the four switches
   to TRUE stops the preprocessor with the guard's `#error`. With the `#error` removed, the five write calls of the
   eFUSE block turn into the forbidden identifiers.
2. **Header check before the run**: `prepare_puf_src.py --verify` re-reads the header copy that Vitis compiled and
   prints every switch value. It also checks that the key and IV are the ones in the key files, that the guard is
   present, and that the red-key print is gone.
3. **Binary check** (`check_puf_elf.py`, run after the build and again before the run): `XilSkey_Program_Black_Key`
   and `XilSKey_Generate_FuseFormat` must be absent, and the strings that only exist in the eFUSE blocks
   ("App: Programming eFUSE", "... write successful", "Writing eFUSE PUF secure bits", ...) must be absent. No
   eFUSE/BBRAM writer of the linked library may be reachable from the entry point, from `main`, or from any function
   whose address is taken. Tested on synthetic AArch64 ELFs: unreachable writer passes; a direct call chain, a stored
   function pointer and an address passed as an argument all fail, with the call chain printed.

The red key is the one thing the example would print (line 798-802, "App: Red key - ..."). That print is replaced,
so the COM11 log holds no red key, and the parser checks this.

## Checklist before the registration run

Tick each point; `run_puf_registration.ps1` prints this list again and needs `BOOT-HEADER-ONLY` typed to go on.

- [ ] Board at 12 V on **one** input only (J20 or J25), S1 pressed, booted from the card's **plain** BOOT.BIN (Linux on
      COM11). The boot is non-secure, so JTAG is enabled.
- [ ] Green-dot TE0790 on J12. No terminal holds COM11. No Vivado hardware manager, `hw_server` or other xsdb is open.
- [ ] No FTDI EEPROM tool (FT_Prog or similar) is open, and none will be.
- [ ] `gen_keys.ps1` ended with `GEN_KEYS_OK`; `icacls C:\tz\aegis-keys` lists only your account.
- [ ] `build_puf_app.ps1` ended with `BUILD_OK`; its output shows `SOURCE_OK` (both pins), `VERIFY_OK` and
      `ELF_CHECK_PASS`, and no `FAIL` line.
- [ ] The switch printout reads: `XSK_PUF_INFO_ON_UART TRUE`; `PROGRAM_EFUSE`, `IF_CONTRACT_MANUFACTURER`,
      `READ_SECUREBITS`, `PROGRAM_SECUREBITS`, `SYN_INVALID`, `SYN_WRLK`, `REGISTER_DISABLE`, `RESERVED` all `FALSE`;
      `REG_MODE XSK_PUF_MODE4K`.
- [ ] No other xilskey example (eFUSE, BBRAM) is built or run, and no Vivado/xsdb eFUSE or BBRAM command is used.
- [ ] You will power-cycle (S1 twice) right after the run and then run `-PostCheck`.

## Steps

### 0. Inputs on the Windows PC

Copy the six inputs of the current plain BOOT.BIN (aab8d7b9, phase A) and their `SHA256SUMS` into
`C:\tz\stage\linux-side`: `fsbl.elf`, `pmufw.elf`, `system.bit`, `bl31.elf`, `tee-raw.bin` and `u-boot.elf`, from the Linux
PC's `~/work/zynqmp/bootimg/v3`. None of them is secret. The JTAG run uses this FSBL and PMU firmware: the TE0807 FSBL sets up
the Si5345 and DDR. The encrypted image uses all six, and the sums are checked.

### A. Keys

```
powershell -ExecutionPolicy Bypass -File gen_keys.ps1
```
Creates `C:\tz\aegis-keys\red_key.hex` (64 hex) and `black_key_iv.hex` (24 hex). The folder ACL is set to the current
user only, inheritance removed. Prints a key id (SHA-256 of a label and the key, 12 hex), never the key. Back the
folder up only to a medium that stays with this PC. If the red key is lost, the chip needs a new registration and a
new BOOT.BIN (harmless, nothing is fused).

### B1. Build the registration app

```
powershell -ExecutionPolicy Bypass -File build_puf_app.ps1            # -Xsa / -ExampleDir if the defaults miss
```
The script finds the example in `C:\AMDDesignTools\2025.2\Vitis\data\embeddedsw` (or takes `-ExampleDir`, for example a copy
of the Linux PC's `embeddedsw/lib/sw_services/xilskey/examples`, which matches the pins). It then prepares the patched
copies in `C:\tz\aegis-keys\build\src`. Vitis builds a throw-away workspace `build\ws` with a platform from the XSA,
xilsecure and xilskey added to `standalone_a53_0`, and the app `puf_reg` from the `empty_application` template. Last,
the ELF check runs. No `-D` define carries the key, so it does not show up in compiler command lines or Vitis logs.

### B2. Run it

```
powershell -ExecutionPolicy Bypass -File run_puf_registration.ps1
```
1. All checks again: ACL, key files, `BUILD_OK` hash, ELF check, header `--verify`, COM11 present, no hw_server/Vivado.
2. Checklist, typed confirmation.
3. COM11 capture (60 s, sends nothing), then xsdb `run_puf_registration.tcl`:
   - read-only eFUSE snapshot, saved as `reg-<time>\efuse_before.txt`;
   - **stops** if the PUF eFUSEs are not blank (CHASH, AUX or the PUF secure bits);
   - `../jtag_boot.tcl`'s sequence: `BOOT_MODE_USER` = JTAG (volatile), `rst -system`, PMU firmware, FSBL (6 s, it
     initialises clocks and DDR and waits), stop;
   - `dow` the app, `con`, 20 s, stop.
4. `parse_puf_log.py` writes the bootgen files into `reg-<time>\`, then the build directory is deleted.

Expected console lines (the order of the example): `App:PUF Registration Completed:0x00000000`, the syndrome block,
`App: AUX-...`, `App: CHASH -...`, `App: ShutterValue -0100005e`, `App: Red key - (not printed, Aegis build)`,
`App: Black key IV - ...`, `App: Black key - ...`, `Successfully ran xilskey puf registration example...`.

### B3. Power cycle and eFUSE comparison

Press S1 twice (off, on). The board boots its plain card image again. Then:
```
powershell -ExecutionPolicy Bypass -File run_puf_registration.ps1 -PostCheck C:\tz\aegis-keys\reg-<time>
```
This reads the eFUSE cache again, read-only. The cache is reloaded from the fuses at power-on. Expected:
`EFUSE_UNCHANGED`. Any difference: stop and report.

### C. Encrypted BOOT.BIN

```
powershell -ExecutionPolicy Bypass -File make_boot_encrypted.ps1 -RegDir C:\tz\aegis-keys\reg-<time>
```
`make_boot_encrypted.py` checks the input sums, writes `red.nky` and the BIF into `C:\tz\aegis-keys\bootgen-<time>`,
and runs `bootgen -arch zynqmp -image boot-encrypted.bif -o BOOT.BIN -w on`. It then checks the result byte by byte:
- 0x28 = 0xA35C7C53 (black key in the boot header);
- attributes: helper data in the boot header, PUF 4K, boot-header RSA off, no `auth_only`;
- 0x4C = black key, 0x6C = shutter, 0xAC = black-key IV, 0x8B8 = the 1544 bytes of helper data;
- `bootgen -read ... pht`: only `fsbl.elf` encrypted;
- the red key in neither binary nor hex form.

The temp directory is deleted. Output: `C:\tz\stage\boot-enc-<time>\` with `BOOT.BIN`, `boot-encrypted.bif`, `report.txt`,
`bootgen.log` and `SHA256SUMS`.

Expected bootgen warnings: `[keysrc_encryption] not supported for the specified architecture` (a parser bug, see
the template), the KDF Seed / Fixed Input Data notes (no key rolling is used, so no extra keys are derived), and,
with `-Auth bh`, the ES1 padding note.

### D. Test on the card (no JTAG needed, and none available)

An encrypted FSBL is decrypted by the boot ROM, and a JTAG RAM boot loads the plain FSBL, so JTAG cannot test this
image. After any secure boot attempt the boot ROM leaves JTAG disabled: "After the BootROM runs, the system enables JTAG
if the boot mode is non-secure" ([UG1283 2025.2, Boot Time Security](https://docs.amd.com/r/en-US/ug1283-bootgen-user-guide/Boot-Time-Security)).
So the test is done on the card, with the plain image kept next to it:

1. Copy `BOOT.BIN` to the board (it is not secret), for example `scp BOOT.BIN root@<board>:/root/incoming/BOOT-enc.bin`.
2. On the board (SSH or the COM11 console; check the FAT partition with `lsblk` first, `/dev/mmcblk0p1` with our
   kernel):
   ```
   mount /dev/mmcblk0p1 /mnt && cd /mnt && ls -l && sha256sum BOOT.BIN   # aab8d7b9... (plain, phase A)
   ls BOOT0*.BIN 2>/dev/null && echo "remove BOOTnnnn.BIN files first"    # none: no silent multiboot fallback
   test -e boot-2025.2-optee.bin || cp BOOT.BIN boot-2025.2-optee.bin
   sha256sum boot-2025.2-optee.bin                                       # aab8d7b9...
   cp /root/incoming/BOOT-enc.bin BOOT.BIN.new && sha256sum BOOT.BIN.new # = SHA256SUMS from step C
   mv BOOT.BIN.new BOOT.BIN && sync && cd / && umount /mnt
   ```
3. Start a passive COM11 capture (as `../run_test.ps1` does, or any terminal that only reads), then power-cycle (S1 twice).
   - **FSBL banner** "Zynq MP First Stage Boot Loader (TE0807 hooks, Aegis 2025.2)", then TF-A, OP-TEE, U-Boot, Linux:
     the boot ROM regenerated the PUF KEK from the header, decrypted the black key and the FSBL. With no `BOOTnnnn.BIN`
     on the card there is no other image it could have booted. Check on Linux that `/mnt/BOOT.BIN` is the encrypted one.
   - **Nothing at all on COM11**: the boot ROM refused the image. This is the expected result for `-Auth none` if
     UG1085 applies as written (see below). Recover (next section), then build with `-Auth bh` from the same
     `reg-<time>` (no new registration) and try again.
   - **FSBL banner, then an FSBL error**: recover, keep the log.
4. From now on (as long as the card holds the encrypted BOOT.BIN), xsdb cannot reach the chip after power-on.
   `../jtag_boot.tcl`, `../pl_status.tcl` and `efuse_status.tcl` need the plain image back, or the card out at
   power-on.

### Recovery

- **Card in the Linux PC's USB reader** (always works, needs no JTAG and no key): power off, take the card out, mount
  its first (FAT) partition, `cp boot-2025.2-optee.bin BOOT.BIN`, check `sha256sum BOOT.BIN` = aab8d7b9..., `sync`,
  unmount, card back, S1. The Linux PC only sees the encrypted image and the plain one, never the red key.
- **JTAG RAM boot of the plain chain, then SSH** (untested): JTAG is disabled while the card holds the encrypted image,
  so power on **without the card**. The carrier falls back to QSPI, a non-secure boot, and JTAG comes up; the QSPI FSBL
  boot-loops, which does not matter. Insert the card, run `../run_test.ps1` (or `../jtag_boot.tcl`) with the plain FSBL,
  PMU firmware, TF-A and U-Boot; its `rst -system` with `BOOT_MODE_USER` = JTAG stops the loop. Once Linux is up from
  the card's root file system: `mount /dev/mmcblk0p1 /mnt; cp /mnt/boot-2025.2-optee.bin /mnt/BOOT.BIN; sync;
  umount /mnt`. Note that this JTAG chain has no OP-TEE unless `tee-raw.bin` is loaded too.

## Formats and BIF syntax (with sources)

| bootgen input | Format | Source of the format |
|---|---|---|
| `[puf_file] helperdata.txt` | 1544 bytes as 3088 hex chars: all 386 words the example prints between `App:PUF Syndrome data Start!!!` and `End!!!`, bytes in memory order (the example prints each `u32` byte by byte, so little-endian). CHASH is word 384 and AUX word 385 (library lines 709-712), which the parser cross-checks against the printed values | bootgen `PUF_DATA_LENGTH 1544` (`common/include/bootheader.h:58`), `SetPufData` (`zynqmp/src/bootheader-zynqmp.cpp:554-571`); [UG1209 2025.2, PUF Registration in Boot Header Mode](https://docs.amd.com/r/2025.2-English/ug1209-embedded-design-tutorial/PUF-Registration-in-Boot-Header-Mode): helperdata.txt is the text between the two syndrome markers |
| `[bh_keyfile] black_key.txt` | 32 bytes, 64 hex chars, as printed after `App: Black key - ` | `SetGreyOrBlackKey` (`bootheader-zynqmp.cpp:457-473`, "Expected length for Grey/Black key is 32 bytes"); UG1209 black_key.txt |
| `[bh_key_iv] black_iv.txt` | 12 bytes, 24 hex chars, as printed after `App: Black key IV - ` (= `black_key_iv.hex`) | `SetGreyOrBlackKekIV` (`bootheader-zynqmp.cpp:529-551`; mandatory with `bh_blk_key`); UG1209 black_iv.txt |
| `[fsbl_config] shutter=` | the printed `ShutterValue`, 0x0100005E in xilskey 2025.2 (`XSK_ZYNQMP_PUF_SHUTTER_VALUE`, `xilskey_eps_zynqmp_puf.h:75`) | UG1209 "Using PUF in Boot Header Mode" uses `shutter=0x0100005E` |
| `aeskeyfile=red.nky` | `Device xczu4eg;` / `Key 0 <64 hex>;` / `IV 0 <24 hex>;`. Key 0 = red key = `XSK_PUF_AES_KEY`; IV 0 random per build | bootgen `ReadEncryptionKeyFile`/`WriteEncryptionKeyFile` (`zynqmp/src/encryption-zynqmp.cpp:161-243, 246+`); UG1209: `XSK_PUF_AES_KEY` "must be Key 0 from the fsbl_a53.nky file" |

All hex files are read by `FileImport::LoadHexData` (`utils/include/fileutils.h:87-139`): `fscanf("%2X")`, so whitespace
is ignored, no `0x` prefix, and the byte count must be exact.

BIF (template `boot-encrypted.bif.template`; the filled-in file is copied next to each BOOT.BIN):
```
[fsbl_config] puf4kmode, shutter=0x0100005E, pufhd_bh
[keysrc_encryption] bh_blk_key
[bh_keyfile] black_key.txt
[bh_key_iv] black_iv.txt
[puf_file] helperdata.txt
[bootloader, destination_cpu=a53-0, encryption=aes, aeskeyfile=red.nky] fsbl.elf
[pmufw_image] pmufw.elf
... bitstream, bl31.elf, tee-raw.bin (load=startup=0x60000000), u-boot.elf exactly as ../../boot.bif, unencrypted
```
Sources: [UG1283 2025.2, Attributes](https://docs.amd.com/r/2025.2-English/ug1283-bootgen-user-guide/Attributes)
(`fsbl_config`: `pufhd_bh`, `puf4kmode`, `shutter`, `bh_auth_enable`; `keysrc_encryption` `bh_blk_key`; `bh_keyfile`;
`bh_key_iv`; `puf_file`; `aeskeyfile`; `pmufw_image`);
[UG1283, Encryption Flow: Black Key Stored in Boot Header](https://docs.amd.com/r/en-US/ug1283-bootgen-user-guide/Encryption-Flow-Black-Key-Stored-in-Boot-Header);
[UG1209 2025.2, Using PUF in Boot Header Mode](https://docs.amd.com/r/2025.2-English/ug1209-embedded-design-tutorial/Using-PUF-in-Boot-Header-Mode)
(`[fsbl_config]a53_x64, bh_auth_enable, opt_key, puf4kmode, shutter=0x0100005E,pufhd_bh`); and
`bootgen -arch zynqmp -bif_help fsbl_config|puf_file|bh_keyfile|bh_key_iv|aeskeyfile|pmufw_image`. Tested with bootgen
built from tag `xilinx_v2025.2` (it reports itself as "v2025.1-Merged") on dummy keys, with the real partition
files of BOOT.BIN aab8d7b9: both variants build, and the header fields are as listed in step C.

- **PMU firmware:** with `[pmufw_image]` the boot ROM loads it from the boot-loader partition, and bootgen encrypts it
  together with the FSBL under the same `.nky` (`encryption-zynqmp.cpp` lines 1177-1223, "Encrypting the PMU
  Firmware"). It needs no attribute of its own. UG1209's example also lists the PMU firmware as AES-encrypted. Keeping
  it plain would mean loading it from the FSBL (`[destination_cpu=pmu]`), a different boot flow; not done.
- **`a53_x64`, `opt_key`, `blocks=`** (key rolling) from UG1209 are left out. The current boot.bif runs the FSBL in
  64-bit without `a53_x64`, and the header shows the same core bits. `opt_key` and key rolling are DPA counter-measures
  that change nothing for this step.
- **Authentication:** none in the default build. `-Auth bh` adds `bh_auth_enable`, `[pskfile] psk.pem`,
  `[sskfile] ssk.pem`, `[auth_params] ppk_select=0; spk_id=0x00000000` and `authentication=rsa` on the boot loader.
  The keys come from `bootgen -generate_keys auth pem` into `C:\tz\aegis-keys\auth`. This is boot-header
  authentication: no PPK hash in eFUSE, nothing fused. It only works while RSA_EN is not programmed (`SEC_CTRL` in the
  snapshot). It proves nothing against someone who rewrites the card (they can sign with their own key), as the
  design notes say.

## Untested and uncertain

1. **Authentication may be required by the boot ROM.** UG1085 says "PUF regeneration can only be performed when
   authentication is enabled" and that the black key is stored "as part of the authenticated boot header"
   ([UG1085, Storing Keys in Encrypted Form (Black)](https://docs.amd.com/r/en-US/ug1085-zynq-ultrascale-trm/Storing-Keys-in-Encrypted-Form-Black)).
   UG1209 says "RSA authentication is required when the PUF is used"
   ([UG1209 2025.2, Using the PUF](https://docs.amd.com/r/2025.2-English/ug1209-embedded-design-tutorial/Using-the-PUF)),
   and UG1283's black-key example says the boot image must be authenticated. bootgen does not enforce it (it builds the
   no-auth image). So `-Auth none` probably gives a silent boot ROM failure, and `-Auth bh` (still no fuse) is probably
   needed. This also bears on the design note that calls `bh_auth_enable` optional.
2. Whether the CSU ROM serves the PUF registration command when the chip was booted in JTAG mode by our sequence.
   AMD's tutorial runs the app from an SD BOOT.BIN on the R5. If the app reports a PUF timeout, the fallback is to
   run the same app as a partition of a plain SD BOOT.BIN, with the FSBL and the app on A53-0. That puts the red key on
   the card, so the card would need to be wiped after it; a decision for later.
3. Vitis 2025.2 Python API: `domain.set_lib(lib_name=...)`, `get_config(option="lib", ...)`,
   `template="empty_application"`, `import_files(..., dest_dir_in_cmp="src")`. If `set_lib` does not exist,
   `vitis_puf_app.py` lists the domain's methods and stops. Also whether xiltimer (for `usleep`) comes in on its own.
4. The paths `C:\AMDDesignTools\2025.2\Vitis\bin\bootgen.bat` and `...\Vitis\data\embeddedsw`, the location of
   `puf_reg.elf` in the workspace, and the Python interpreter on the Windows PC.
5. Whether `xil_printf` pads `%08x`/`%02x` as expected. The parser accepts 1-8 digits for the 32-bit values, but the
   syndrome and keys need exact `%02x`, which the FSBL relies on as well.
6. The JTAG-recovery path (power on without the card, then insert it) has not been tried; the card-reader path has no
   such dependency.
7. Encrypting the FSBL changes nothing in its code, but it is now decrypted into OCM by the boot ROM. The FSBL sets the
   "FSBL encrypted" bit in PMU `GLOB_GEN_STORAGE5`, which later software can read.

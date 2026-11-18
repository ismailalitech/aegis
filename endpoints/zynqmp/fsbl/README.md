# ZynqMP endpoint: the FSBL hook that fills the hand-off page (phase B)

Design: `docs/zynqmp-key-design.md`. Interface: `../handoff/aegis_zynqmp_handoff.h` (one 4 KiB page at
0x6FFF_F000, the end of OP-TEE's secure memory).

Not run on the board yet: the code compiles against AMD's 2025.2 sources and its logic was run on a PC against a
BOOT.BIN with the CSU calls replaced. "Check on the board" below lists what that cannot show.

## What it does

`aegis_fsbl_handoff.c` adds two calls to the Vitis 2025.2 `zynqmp_fsbl` (A53, 64-bit). Neither can fail the boot.

1. `AegisFsbl_Measure()`, in `xfsbl_main.c` when the last partition is loaded. For every partition the FSBL loaded it
   reads the bytes back from the boot device (the FSBL's own `DeviceOps.DeviceCopy`, 64 KiB at a time) and takes the
   CSU's SHA3-384 over them; the entry keeps the first 32 bytes, the length and the attribute word. It also reads the
   boot header's key-source word (offset 0x28) and attributes (0x44).
2. `AegisFsbl_BeforeHandoff()`, in `XFsbl_HookBeforeHandoff`. It derives the seed, AES-256-GCM of `AEGIS_SEED_LABEL`
   with `AEGIS_SEED_IV` under the CSU's device key (`XSECURE_CSU_AES_KEY_SRC_DEV`), writes the page with its SHA3-384,
   clears the AES and KUP keys (`XSecure_AesKeyZero`) and wipes its copy of the seed.

The measurement is in `xfsbl_main.c` and not in the hook because `XFsbl_Handoff` switches the data cache off and gives
the SD card-detect signal back to the pin before it calls the hook.

No eFUSE, BBRAM or PUF code. The boot device is only read. The seed is never printed.

### Measurements

A range is hashed as stored in BOOT.BIN, so `hashlib.sha3_384(image[offset:offset+length]).digest()[:32]` on the build
PC gives the expected value. Offset and length are the partition header's data offset and total length (words × 4).

| Label | Partition |
|---|---|
| `PMUFW`, `FSBL` | partition 0, what the boot ROM loaded. With `[pmufw_image]` it holds the PMU firmware, then the FSBL; the boot header's total PMU firmware length (0x38) is where it is split. Without one, a single `FSBL` entry |
| `PL` | destination device PL |
| `PMUFW` | destination PMU, when the FSBL loads the PMU firmware |
| `TFA` | A53, EL3 |
| `TEE` | A53, EL1, TrustZone |
| `UBOOT` | A53, EL2 or EL1, not TrustZone |
| `P<n>` | partition n, loaded by the FSBL, none of the above |

A second partition with the same label (an ELF with two load segments, as `bl31.elf`) is `TFA.1`, and so on.
Partitions the FSBL does not own are not loaded by it and are left out. An entry with length 0 and a zero value
could not be read back. If the image has more than eight entries the last one is `TRUNCATED`, with the number of
entries left out as its length. This repository's `boot.bif` gives seven: `PMUFW`, `FSBL`, `PL`, `TFA`, `TFA.1`,
`TEE`, `UBOOT`.

The FSBL measures what is on the card, read a second time, not the bytes it loaded. `FSBL` is the FSBL's own
statement about itself.

### Flags

- `AEGIS_HO_SEED_VALID` (1): the AES operation succeeded. On its own this says nothing about which key was used.
- `AEGIS_HO_KEY_BH_BLACK` (2): set only with the first, and only if the boot header names the boot-header black key
  (0xA35C7C53), its attributes are not "authenticate only", and `CSU_STATUS` (0xFFCA0000) bit 1 says the boot ROM
  decrypted the FSBL. OP-TEE must use the seed as the chip's key only with both bits. The comment at
  `aegis_key_is_bh_black()` says what this indicator can and cannot show.
- `AEGIS_HO_AES_CLEARED` (4): `XSecure_AesKeyZero` reported both keys zeroed.

## Build (Windows PC, after the steps in `../windows/README.txt`)

Both scripts on the same FSBL source directory, in this order:

```
powershell -File ..\windows\patch_fsbl_te.ps1 -d C:\tz\aegis\ws_pqc\aegis_zu4eg\zynqmp_fsbl
powershell -File patch_fsbl_aegis.ps1         -d C:\tz\aegis\ws_pqc\aegis_zu4eg\zynqmp_fsbl
```

then rebuild the platform. `patch_fsbl_aegis.ps1` copies `aegis_fsbl_handoff.c/.h` and `aegis_zynqmp_handoff.h` into
the directory, adds the include and the call to `xfsbl_hooks.c` and `xfsbl_main.c`, and stops with "PATCH FAILED" if
the Trenz port or one of its anchors is missing. It prints `AEGIS_PATCH_OK`; a second run changes nothing.

If the link fails:
- undefined `AegisFsbl_...`: CMake has not seen the new file. Delete the FSBL's `build` directory and rebuild.
- `region psu_ocm_ram_0_S_AXI_BASEADDR overflowed`: the FSBL has 167 KiB of OCM. The hook adds about 3 KiB of code,
  1 KiB of data and xilsecure's AES encryption functions.

## On the console

One line, the last the FSBL prints before it hands off:

```
AEGIS: hand-off flags=0x7 meas=7 bh_key_src=0xa35c7c53 csu_status=0x2
```

- `flags=0x7`: phase B as designed (encrypted FSBL, black key in the boot header).
- `flags=0x5`: a seed, but not under the black key. Expected with today's unencrypted BOOT.BIN (`bh_key_src=0x0`).
- bit 0 clear (`0x4`, `0x0`): the AES operation failed, there is no seed. Bit 2 clear: the key clear failed.
- `meas=`: entries written. 0 means `AegisFsbl_Measure()` did not run or found no partitions.
- `AEGIS: hand-off page not written (no free DDR at 0x6ffff000)`: a partition is loaded over the page, or the DDR
  does not reach it.

A JTAG RAM boot (`jtag_boot.tcl`) prints nothing: the FSBL stops before the hook and loads no partitions.

## Check on the board

1. The FSBL still links (OCM size) and the boot reaches U-Boot as before, with the line above.
2. Unencrypted BOOT.BIN: `flags=0x5` (or `0x4`), `csu_status` bit 1 clear, `meas=7`, and the seven values equal to
   the SHA3-384 computed from BOOT.BIN on the PC. The extra boot time is the second read of the image.
3. Whether the AES operation works at all without an encrypted boot, and what key `KEY_SRC_DEV` selects then, is not
   documented. Either result is handled; it decides what the phase A fallback sees.
4. `AEGIS_HO_AES_CLEARED`: the hook takes the AES core out of reset for the key-clear request, as xilsecure does in
   its own calls. If the bit stays clear with a valid seed, that step is where to look.
5. Encrypted FSBL with the black key: `flags=0x7`, `csu_status=0x2`, and the same seed on every boot (seen as the same
   public key from OP-TEE, never as the seed).
6. The seed is standard AES-256-GCM: the engine takes a fourth IV word (zero here) and is taken to ignore it, as it
   must for the FSBL's own partitions. With the red key on the build PC,
   `AESGCM(red).encrypt(b"aegis-zynqmp", AEGIS_SEED_LABEL, None)[:32]` should give the key pair the board reports.
7. Phase C: the hook runs after `XFsbl_ProtectionConfig`. Once XMPU/XPPU are set up, the FSBL must still reach the CSU
   and 0x6FFF_F000 at that point.

## What the FSBL touches in DDR

- 0x6FFF_F000-0x6FFF_FFFF: the hand-off page (zeroed, then written).
- 0x6FFE_F000-0x6FFF_EFFF: scratch for reading the image back, zeroed afterwards. The FSBL's own chunk buffer is in
  the OCM where TF-A may be loaded, so it cannot be used. If a partition is loaded over the scratch, nothing is read
  and every entry has length 0.

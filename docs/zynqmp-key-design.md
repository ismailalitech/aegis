# ZynqMP endpoint: a chip-bound key and the secure world, without fuses (design, 18 November 2026)

Goal: the same evidence as the STM32 and the RW612 on the Zynq UltraScale+ (`endpoints/zynqmp`). The ML-DSA-65 key
belongs to this chip, it is used only in the secure world, and the quotes come from there, not from Linux. Rule of
the bench: no eFUSE, no BBRAM, nothing irreversible (`endpoints/zynqmp/README.md`).

## What the hardware and AMD's 2025.2 software allow (checked in the sources)

1. **PUF in boot-header mode.** The registration tool (xilskey `xilskey_puf_registration`, run over JTAG with
   `XSK_PUF_INFO_ON_UART TRUE` and every eFUSE switch `FALSE`) prints the helper data, and the "black key": a
   256-bit key we choose (the red key), encrypted under the PUF's key-encryption key (KEK). bootgen puts both in
   the boot header (`pufhd_bh`, `keysrc_encryption bh_blk_key`). At power-on the boot ROM regenerates the KEK from
   the header and decrypts the black key into the AES engine's **device key**. A different chip regenerates a
   different KEK, so the same boot image gives it a wrong key, and its encrypted FSBL does not decrypt.
2. **The PUF cannot be regenerated later from boot-header data.** xilskey refuses to regenerate when the helper
   data is not in eFUSEs, and OP-TEE's ZynqMP HUK driver regenerates from eFUSEs. So the key has to be used
   **during boot**, by the FSBL. OP-TEE's own HUK path is no use without fuses: with authentication off it falls
   back to SHA-256 of the device DNA, which Linux can read.
3. **The FSBL decrypts partitions with `XSECURE_CSU_AES_KEY_SRC_DEV`** (`xfsbl_partition_load.c`): with (1), that is
   our red key. A hook in the FSBL can therefore run one more AES-GCM operation under the device key.
4. **The PMU firmware serves AES to Linux by default.** `PM_SECURE_AES` (and `PM_SECURE_IMAGE`, which decrypts with
   the device key) are `PMU_API_FULL_ACCESS` in `pm_binding.c`. The permission table also has secure-only access,
   checked by the IPI channel's TrustZone bit and TF-A's secure flag (`isApiAllowed`). So the PMU firmware must be
   built with those APIs secure-only.
5. **The FSBL can clear the AES key register and the KUP key** (`XSecure_AesKeyZero`), but no documented control
   clears the device (boot) key after boot. So non-secure software must also be kept away from the CSU AES
   registers (0xFFCA2000), and the probes check that rather than assume it.

## Design

```
power-on: boot ROM regenerates the PUF KEK (helper data from the boot header), decrypts the black key into the
          device key, decrypts the FSBL (encrypted with the red key)
FSBL:     psu_init, Trenz hooks; loads PMU firmware, bitstream, TF-A, OP-TEE, U-Boot (each hashed with the CSU's
          SHA3-384 into a measurement list)
          hook before hand-off: seed = AES-256-GCM(device key, IV = fixed, "aegis-zynqmp-mldsa65-seed-v1")
          writes {seed, measurement list} to a hand-off page inside OP-TEE's secure memory; clears the AES and
          KUP key registers
TF-A:     BL31 with SPD=opteed; OP-TEE as BL32 at 0x6000_0000
OP-TEE:   platform hook reads the hand-off page once, wipes it, keeps the seed as the hardware unique key (HUK)
          trusted application "aegis": the protocol code of the other endpoints (aegis_proto.c, as in the RW612's
          TF-M partition): key pair = ML-DSA-65.KeyGen(derived from the HUK), quotes with the measurement list,
          ML-KEM provisioning, KMAC heartbeats
Linux:    a bridge (TCP 7444, one line in, one line out, as the RW612's non-secure prover) calls the trusted
          application through /dev/tee0; Linux holds no key and takes no measurement
PMU fw:   PM_SECURE_AES, PM_SECURE_IMAGE secure-only
```

The gateway gets a profile `aegis-zynqmp-optee-v1` with trust label `trustzone`, pinned like the RW612's. The claims
carry the FSBL's measurements: `BOOT` (FSBL), `PMUFW`, `PL` (bitstream), `TFA`, `TEE`, `UBOOT`, plus the kernel that
U-Boot loads, hashed by U-Boot into the hand-off (or by OP-TEE from memory, if U-Boot cannot reach the page).

## What this does and does not give (to state with any claim)

- **Chip binding:** the red key exists only in the boot header (encrypted under this chip's PUF) and on the build
  PC, which needs it to encrypt the FSBL. Anyone with that file can rebuild the key, so it stays off the board and
  out of the repository. That is the same class of limit as the STM32's published development keys and the
  RW612's unfused boot.
- **Without RSA_EN (a fuse), the boot ROM does not check who signed the image.** An attacker who rewrites the card
  cannot make an FSBL that the device key decrypts without the red key. Whether the boot ROM loads the device key
  for an unencrypted FSBL that names the black-key source is not documented, so it gets tested before the claim is
  made (test 4 below). Boot-header authentication (`bh_auth_enable`) adds an RSA signature with a key in the boot
  header. It proves nothing against an attacker who writes the card, so it is optional here.
- **Secure memory:** OP-TEE's 0x6000_0000-0x7FFF_FFFF is withheld from Linux by the device tree. Against root on
  Linux that holds only if the DDR's XMPU is configured for it (FSBL hook) and `/dev/mem` is restricted
  (`CONFIG_STRICT_DEVMEM`). Both are part of phase C and are tested by probes.

## Phases

| Phase | Content | Hardware risk |
|---|---|---|
| A | OP-TEE 4.7 (`PLATFORM=zynqmp`, UART0, 4 GiB) + TF-A `SPD=opteed` + the Linux side (DT node, reserved memory, tee-supplicant); the trusted application with the protocol and a development HUK; the bridge; the gateway profile. Tested with a JTAG RAM boot first. | none: RAM boot, then the card's BOOT.BIN with the previous one kept |
| B | PUF registration in boot-header mode (JTAG; the app's eFUSE switches read back and checked before it runs); encrypted FSBL (bootgen); the FSBL hook that derives the seed and the hand-off to OP-TEE; the key pair then belongs to the chip | none if the switches are as listed: registration in boot-header mode writes nothing |
| C | Lock-down: PMU firmware permissions; XPPU/TrustZone for the CSU; XMPU for OP-TEE's memory; `STRICT_DEVMEM`. Probes from Linux, as on the STM32: device-key AES through the PMU firmware, CSU AES registers, OP-TEE memory, each with a control | a probe that faults can hang Linux until a power cycle (S1 twice) |

Tests that decide the claims:
1. the same boot image on this chip gives the same public key on every boot (and the gateway pin holds);
2. a quote's signature verifies only under that pinned key; Linux has no key file;
3. non-secure probes: PMU-firmware AES with the device key refused; CSU AES registers not writable; OP-TEE memory
   not readable;
4. an unencrypted FSBL in a header that names the black key: does it get the device key? (decides the second point
   of the limits above);
5. a modified kernel, bitstream or U-Boot is quarantined on its measurement, now taken by the boot chain.

# Zynq UltraScale+ endpoint (steps 1-3 done on 18 November 2026: admitted with software trust)

The board: a Trenz **TEBF0808-04A** UltraITX+ carrier with a **TE0808 (XCZU4EG)** module under a fan, plus two TE0790
JTAG adapters (the one with the licence, green dot, on J12 for the MPSoC's JTAG and UART). This endpoint replaces the
Zybo (`../zybo`). Its Linux prover runs here unchanged for the "software trust" step, and the chip adds what the
Zynq-7010 lacks: a PUF, the CSU's AES and SHA-3, and TrustZone on the Cortex-A53s.

Status and evidence: `evidence/zynqmp/software-trust.txt`. Files here:
- `setup_rootfs.sh`: configures a Debian 12 arm64 root file system (after debootstrap) with the prover, the gateway's
  key and liboqs 0.16.0 built for aarch64.
- `make_sd.sh`: writes the card: BOOT.BIN and image.ub on a FAT partition, the root file system on the second.
- `aegis-linux-prover.service`: the prover on TCP 7444, measuring BOOT.BIN, image.ub and itself.

Power-on: 12 V, then press **S1** (the 12 V input alone powers only the carrier's controller). Boot mode is SD; with
no card the carrier falls back to the QSPI flash.

## Rules (as for the other boards: nothing irreversible)

- **No eFUSE is written.**
  - No xilskey eFUSE example is built or run, and no Vivado or XSDB eFUSE command is used.
  - PUF registration is done in **boot header mode** only: the helper data and the black key live in the boot image,
    not in the fuses. AMD documents this mode as allowing development without programming the OTP eFUSEs
    ([UG1209](https://docs.amd.com/r/2025.2-English/ug1209-embedded-design-tutorial/PUF-Registration-in-Boot-Header-Mode)).
- **The BBRAM key is not programmed.** It can be cleared again, but nothing needs it.
- **Never run FTDI's EEPROM tools (FT_Prog and the like) on the TE0790 adapters.** They erase the adapter's stored
  Xilinx JTAG licence (Trenz's TE0790 page).
- **Power at 12 V, on one input only:** the ATX connector J20 or the 2.1 mm jack J25, never both. Revision 04A has
  no TVS diodes on the input; revision 05 added them
  ([Trenz PCN 2024-06-11](https://shop.trenz-electronic.de/trenzdownloads/Trenz_Electronic/Modules_and_Module_Carriers/5.2x7.6/5.2x7.6_Carriers/TEBF0808/PCN/PCN-20240611%20TEBF0808-04A%20to%20TEBF0808-05%20Hardware%20Revision%20Change.pdf)).
  Check the adapter's label before the first power-on.

## Steps

1. **Identify the chip.** Done: XCZU4EG (IDCODE 04721093; eFUSE IPDISABLE shows the VCU disabled and the GPU
   present), read with xsdb over the TE0790.
2. **Boot Linux and join the network.** Done: the boot files of the card the board came with (Trenz FSBL 2019.2,
   U-Boot 2019.01, Linux 4.19) and Debian 12 from `setup_rootfs.sh`, DHCP on `end0`. Our own boot chain (built with
   Vitis 2025.2) comes with step 4, since the PUF registration lives in the boot image.
3. **Software trust.** Done: `../zybo/aegis_linux_prover.py`, enrolled as `zynqmp-te0808` (kind `aegis-linux`),
   admitted with "software trust", ML-KEM credential issued, KMAC heartbeats checked. This is the baseline the next
   steps improve on.
4. **A key from the chip.** Run PUF registration in boot header mode with a random user key, keeping its black key and
   helper data in the boot image. At start-up the CSU regenerates the PUF key and decrypts the black key into the
   device key, and AES-GCM over a fixed label gives the ML-DSA-65 seed. This is the STM32's DHUK construction, and
   the key belongs to this chip: the same boot image on another chip gives another key.
   - Still to check on the board: which software (FSBL, PMU firmware or TF-A) may use the CSU AES with the device key
     after boot, and that no step needs RSA_EN or another fuse.
5. **Keep the key and the proofs away from Linux.** The secure world on the A53s (TF-A plus OP-TEE, with a trusted
   application running `aegis_proto.c`, as the RW612's TF-M partition does) holds the key, and Linux only carries the
   network. OP-TEE can already take a hardware unique key from the PUF
   ([Foundries.io](https://docs.foundries.io/92/reference-manual/security/secure-boot-zynq.html)).
6. **Measurements from the boot chain.** FSBL hashes what it loads (PMU firmware, TF-A, OP-TEE, U-Boot, the
   bitstream) with the CSU's SHA-3. The secure world reports those values, so a modified Linux cannot report false
   ones.
7. **The same evidence as the other boards:**
   - tamper tests (a modified Linux image, a modified bitstream) quarantined on their measurements;
   - the fuzz harness of the RW612 against the trusted application's protocol code;
   - probes that Linux cannot reach the CSU;
   - a lab page on the site.

## What it will not prove without fuses

As on the RW612: without RSA_EN fused, the boot ROM does not check who signed the boot image, so someone who rewrites
the boot medium can run other secure-world code with the same PUF-derived device key. The gateway's profile pin and
the measurements narrow that down; only secure boot closes it, and that is irreversible.

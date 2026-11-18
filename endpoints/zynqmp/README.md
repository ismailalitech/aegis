# Zynq UltraScale+ endpoint (18 November 2026: our own boot chain, admitted with software trust)

The board: a Trenz **TEBF0808-04A** UltraITX+ carrier with a **TE0807 (XCZU4EG-1E, 4 GB DDR4)** module under a fan, plus two TE0790
JTAG adapters (the one with the licence, green dot, on J12 for the MPSoC's JTAG and UART). This endpoint replaces the
Zybo (`../zybo`). Its Linux prover runs here unchanged for the "software trust" step, and the chip adds what the
Zynq-7010 lacks: a PUF, the CSU's AES and SHA-3, and TrustZone on the Cortex-A53s.

Status and evidence: `evidence/zynqmp/software-trust.txt`, `evidence/zynqmp/boot-chain.txt`. (The gateway names
it `zynqmp-te0808`, from before the module was identified; it is a TE0807.) Files here:
- `setup_rootfs.sh`: configures a Debian 12 arm64 root file system (after debootstrap) with the prover, the gateway's
  key and liboqs 0.16.0 built for aarch64.
- `make_sd.sh`: writes the card: BOOT.BIN and image.ub on a FAT partition, the root file system on the second.
- `aegis-linux-prover.service`: the prover on TCP 7444, measuring BOOT.BIN, the kernel (Image, the dtb, boot.scr)
  and itself.
- Kernel: linux-xlnx xilinx-v2025.2 (6.12), `make ARCH=arm64 xilinx_defconfig`, plus `CONFIG_TEE`/`CONFIG_OPTEE`, and
  `xilinx/zynqmp-te0807-aegis.dtb` from `dts/`. Image and the dtb go on the FAT partition. The modules go in with
  `tar xzf modules.tgz --keep-directory-symlink --no-same-owner -C /`, because without `--keep-directory-symlink` tar
  replaces Debian's `/lib -> usr/lib` link and nothing can start any more.
- `windows/`: the Vivado/Vitis 2025.2 build (XSA, bitstream, FSBL with Trenz's TE0807 hooks, PMU firmware) and the
  JTAG boot test, run on the bench's Windows PC; its README gives the order and the Trenz download it expects.
- `boot.bif`, `boot.cmd`, `dts/zynqmp-te0807-aegis.dts`, `u-boot-aegis.config`: BOOT.BIN (bootgen), the U-Boot
  script, and U-Boot (u-boot-xlnx xilinx-v2025.2, `xilinx_zynqmp_virt_defconfig` plus the fragment). TF-A is
  xilinx-v2025.2 with `make PLAT=zynqmp RESET_TO_BL31=1 bl31`. U-Boot keeps no environment and has the eMMC and
  QSPI disabled, so it writes neither.
- `../../hw/rtl/aegis_pqc2_zynqmp.v`, `../../hw/vivado/aegis_pqc2_zynqmp_bd.tcl`, `windows/build_hw_pqc.tcl`: the
  Aegis accelerator in the PL (registers at 0x8000_0000 through an AXI APB bridge on HPM0_LPD, DMA into DDR on
  HP0), 100 MHz, in the card's BOOT.BIN; `gateway/pqc/pqc_selftest` with `AEGIS_PQC_DEVMEM=0x80000000` passes on the
  board (`evidence/zynqmp/pl-accelerator.txt`). Only read 0x8000_0000 with this bitstream loaded: with an empty PL
  the read is never answered and the CPU hangs.

A new BOOT.BIN is tried over JTAG into RAM first (`windows/jtag_boot.tcl`), and only then written to the card; the
previous ones stay on the card (`boot-2019.bin`, the one the board came with; `boot-2025.2-nopl.bin`).

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
2. **Boot Linux and join the network.** Done: Debian 12 from `setup_rootfs.sh`, DHCP on `end0`. First on the boot
   files the card came with; then on our own boot chain: FSBL and PMU firmware from Vitis 2025.2, TF-A and U-Boot
   xilinx-v2025.2, and our kernel, linux-xlnx 6.12 (`evidence/zynqmp/boot-chain.txt`). Nothing from the card the
   board came with is used any more except as a fallback (`boot-2019.bin`, `image.ub`).
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

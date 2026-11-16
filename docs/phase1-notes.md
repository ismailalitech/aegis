# Phase 1 notes (private working log)

## 2026-11-16, first board run (logs/phase1/20261116-123454)

Tool: `gateway/sysserv/aegis_sysserv.py`, read-only whitelist over `/dev/mpfs_generic_service`.

| Service | Result |
|---|---|
| serial (0x00) | ok, 16 bytes; equals the programmer's DSN byte-reversed |
| usercode (0x01) | ok |
| design_info (0x02) | ok, design name "MPFS_DISCOVERY_KIT", version 6 |
| security (0x05) | ok, 36 bytes, not decoded yet |
| nonce (0x21) | ok, 32 bytes |
| device_cert (0x03) | ok, 976-byte X.509 DER inside the 1024-byte response; subject MPFS095TS, P-384 key, issuer CN=<20 hex>,O=MCHP,OU=PRO; ECDSA-SHA384 |
| puf_emu (0x20) | **status 255**, three challenges |
| sign_raw / sign_der (0x19 / 0x1A) | **status 255** |

Request layout equals Microchip's Linux example (`refs/linux-examples/system-services`). Status is the low byte of the 16-bit SERVICES_SR status; 255 is not among the documented error codes for these services. Cause still open.

## Hazard found: never rmmod mpfs-generic-service

`mpfs-generic-service.c` calls `misc_register()` in probe and has no remove callback, so `rmmod` frees the module but leaves the misc device registered (`/dev/mpfs_generic_service` stays after rmmod). After the rmmod, SSH to the board stopped completing its banner, while ping and the serial login prompt still answered. Confirmed on the serial console: a second `modprobe` registered the misc device again on top of the stale entry, and the next open spun forever in `misc_open` (soft lockup on CPU#1, `[python3:630]`, `misc_open+0x5c`). Console logins then failed ("Login incorrect", later no prompt at all). There is no SysRq in this kernel, so the board cannot be rebooted remotely without JTAG.

Rule from now on: load the module once and leave it loaded; to remove it, reboot. Rollback of this phase on the board = `rm -rf /root/aegis` and a reboot.

## Open

- Board needs a reset (button or power) to recover SSH.
- Status 255 of PUF emulation and signature services.
- Device certificate chain: the Microchip issuing CA certificate is not on this PC.

## 2026-11-16, PC-side work while the board waits

**Signing key (from Microchip's security docs, onlinedocs "2.2.5 Factory ECC Key"):** the device certificate certifies the public half of the Factory ECC Key (KFP), a device-unique P-384 key protected by the SRAM-PUF. The Digital Signature service signs with KFP, so its signatures should verify against the certificate's public key. That is the identity anchor to test once the service answers (it returned status 255 today).

**Certificate chain:** Microchip signs the certificate with the MCPK. The docs say MCPK is stored in the device (pNVM) and give no published copy, so the chain cannot be checked on the PC yet. Ask Microchip for the MCPK or issuing CA certificate together with the crypto library request.

**STM32 endpoint, read over the STLINK with pyocd (core halted about 1 s, then resumed):**

| Item | Value |
|---|---|
| Board | STM32H573I-DK (STLINK-V3E, pyocd target stm32h573iitx) |
| DBGMCU_IDCODE | 0x10076484 (DEV_ID 0x484 = STM32H56x/H57x) |
| FLASH_OPTSR_CUR | 0x2d30edf8: PRODUCT_STATE 0xED = Open; BOOT_UBE 0xB4 |
| FLASH_OPTSR2_CUR | 0xb4000134: TZEN 0xB4 = TrustZone enabled |

Product state Open means regression is possible. Before the first flash: dump all flash (secure and non-secure) and all option bytes, and keep them in `backups/stm32h573/` (not in git). Never set Closed or Locked.

**Host tools (`tools/setup_host.sh`, no root):** venv with pyocd 0.46.1, cmake 4.4.5, ninja, cryptography 50.0.2; Arm GNU toolchain 14.2.rel1 (SHA-256 matches Arm's); liboqs 0.16.0 (ML-KEM/ML-DSA only).

**NIST vectors:** ACVP-Server tag v1.1.0.41 JSON files in `vectors/acvp` (SHA256SUMS kept in git). liboqs's ACVP driver `tests/test_acvp_vectors.py`: ML-KEM-768 keyGen, encapDecap AFT and VAL; ML-DSA-65 keyGen, sigGen, sigVer: 6 passed. This is the software reference for Phase 2.

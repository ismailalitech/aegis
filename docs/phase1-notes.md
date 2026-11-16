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

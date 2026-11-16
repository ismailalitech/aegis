# What Aegis changes on each board, and how to undo it

## PolarFire SoC Discovery Kit (gateway)

| Change | Undo |
|---|---|
| `/root/aegis/` (aegisd, sysserv tool, common, liboqs.so.9, liboqs test binaries in `oqs/`) | `rm -rf /root/aegis` |
| `/var/lib/aegis/` (identity.json, identity.sk, serve.log) | `rm -rf /var/lib/aegis` |
| `aegisd.py serve` running (started by hand, not a systemd unit) | `kill $(pgrep -f '[a]egisd.py serve')` or reboot |
| `mpfs-generic-service` module loaded | **reboot only. Never rmmod it** (see phase1-notes.md) |
| Fabric reprogrammed 2026-11-16 with the identical pfdaq v0.5.1 job to recover from the hang | nothing to undo: same job, digests unchanged |

Nothing written to eNVM, keys, locks or the SD card's boot and payload partitions.

## STM32H573I-DK

Backup: `backups/stm32h573/20261116-135718-cubeprog-UR/` (all 2 MB of flash read under reset in both
security views, merged image, all option bytes). The board held a TF-M v2.3.0 BL2 + secure image
(Zephyr's TF-M, commit 47b9f07b9) and a non-secure test app.

| Change | Undo |
|---|---|
| Secure slot 0x0C038000 replaced by TF-M v2.3.0 + the Aegis PQ partition (`artifacts/tfm-s-v2.3.0-aegis-pq.hex`, security counter 1, same as before) | `endpoints/stm32h573/restore_from_backup.sh` |
| Non-secure slot 0x08088000 replaced by the Aegis prover (`endpoints/stm32h573/artifacts/`) | same script |

Not touched: BL2, option bytes (product state Open, TrustZone on, WRP on BL2), NV counters, OTP.
Restore tested 2026-11-16: both slots read back byte-identical to the backup and the old firmware booted;
then the Aegis images were written again.

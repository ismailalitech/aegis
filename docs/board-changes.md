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

Nothing changed yet (read-only register reads, core halted about 1 s and resumed).
Before the first flash: back up all flash and option bytes to `backups/stm32h573/`.

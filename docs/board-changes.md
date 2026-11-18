# What Aegis changes on each board, and how to undo it

## PolarFire SoC Discovery Kit (gateway)

| Change | Undo |
|---|---|
| `/root/aegis/` (aegisd, sysserv tool, common, liboqs.so.9, liboqs test binaries in `oqs/`) | `rm -rf /root/aegis` |
| `/var/lib/aegis/` (identity.json, identity.sk, fleet-state.json, credentials/) | `rm -rf /var/lib/aegis` |
| systemd units aegisd.service and aegis-fleet.service (enabled, start at boot) | `/root/aegis/gateway/systemd/install.sh remove`, then reboot |
| `mpfs-generic-service` module loaded | **reboot only. Never rmmod it** (see phase1-notes.md) |
| Fabric reprogrammed 2026-11-16 with the identical pfdaq v0.5.1 job to recover from the hang | nothing to undo: same job, digests unchanged |
| Fabric now AEGIS dv101 = pfdaq v0.5.1 + aegis_pqc in APB slot 14 (`build/libero/AEGIS_dv101.job`, digest dbd6625d...b229) | program `images/pfdaq-v051/PFDAQ_v0_5_1.job` (pfdaq repo) |
| Kernel: Aegis build with nf_tables/bridge/VLAN/USB Ethernet (boot partition fitImage; modules in /usr/lib/modules) | `/root/aegis/kernel-netfilter/rollback.sh`, reboot (old kernel kept as fitImage.pre-aegis, proven one as fitImage.good) |
| `/root/aegis/oqs-fabric/`, `/root/aegis/pqc_selftest`, `/root/aegis/stub_probe` | `rm -rf` them |
| Journal kept on the SD card (17 November 2026): `aegis-journal-link.service` links `/var/volatile/log/journal` to `/var/lib/journal` before the flush, `/etc/systemd/journald.conf.d/aegis.conf` (persistent, 50 MB). Checked: after a reboot the previous boot's fleet lines are readable. Note: `logger` on this image writes to busybox `syslogd`, not to the journal; use `systemd-cat` | `systemctl disable aegis-journal-link`; remove the unit, the drop-in and `/var/lib/journal`; reboot |
| Fabric design 102 (accelerator v2), `build/libero/AEGIS_dv102.job`; gateway re-enrolled on the PC (old record kept) | program `AEGIS_dv101.job`; restore the enrolment record |
| Policy: two STM32 entries (prover 0.5.0, KMAC heartbeats), backups `/root/aegis-backup-fleet-*.json` | copy a backup back to `gateway/policy/fleet.json`; restart `aegis-fleet` |
| 18 November 2026: `fleet.py` and `common/psa_token.py` with the plain-claims kinds (aegis-linux, aegis-device); policy entry `frdm-rw612` and its key `keys/frdm-rw612.mldsa65.pub`. Backup `/root/aegis-backup-20261118-004725/` (gateway clock) | copy the three files back from the backup; restart `aegis-fleet` |
| 18 November 2026, later: `fleet.py` with profile `aegis-rw612-tfm-v1` ("trustzone") and profile pinning; the `frdm-rw612` entry pins that profile and allows SPE and NSPE. Backup `/root/aegis-backup-20261118-063344/` (gateway clock) | copy `fleet.py` and `fleet.json` back from the backup; restart `aegis-fleet` |
| 18 November 2026, after the security review: `fleet.py` names the ML-KEM key in credentials (`kem_ek_sha3_256`) and `enroll-pq` keeps existing pins; `frdm-rw612` references updated for the reviewed firmware; STM32 board 2's session moved to `/root/aegis-backup-session-20261118-073735/` to re-provision it in the new format. Backup `/root/aegis-backup-20261118-073649/` | copy the files back; restart `aegis-fleet` |

Nothing written to eNVM, keys, locks or the SD card's boot and payload partitions.

## STM32H573I-DK

Backup: `backups/stm32h573/20261116-135718-cubeprog-UR/` (all 2 MB of flash read under reset in both
security views, merged image, all option bytes). The board held a TF-M v2.3.0 BL2 + secure image
(Zephyr's TF-M, commit 47b9f07b9) and a non-secure test app.

| Change | Undo |
|---|---|
| Secure slot 0x0C038000 replaced by TF-M v2.3.0 + the Aegis PQ partition (`artifacts/tfm-s-v2.3.0-aegis-pq.hex`, security counter 1, same as before) | `endpoints/stm32h573/restore_from_backup.sh` |
| Non-secure slot 0x08088000 replaced by the Aegis prover (`endpoints/stm32h573/artifacts/`) | same script |
| Board 2, 18 November 2026: secure slot 0x0C038000 replaced by the build with the KEM_INIT fix and the encapsulation-key check (`~/aegis-tools/tfm-aegis-build-kemfix`, SPE `3cacd9d0...`, version 2.3.0, same signer and security counter, veneers unchanged); gateway policy for `stm32h573-dk-2` updated (backup `fleet.json.bak-stm32-kemfix` on the gateway); `evidence/stm32-kemfix/` | `STM32_SN=<board 2> endpoints/stm32h573/restore_from_backup.sh backups/stm32h573/20261118-100835-board2-before-kemfix` (its secure slot is the previous build), then the old SPE back in the policy |

To replace the secure image of a board, with backup, policy and checks: `endpoints/stm32h573/upgrade_secure.sh <endpoint>
<ST-LINK serial> <signed .hex>` (tested on board 2 up to the write, and its gateway steps against the live gateway). For
board 1, the image with the KEM_INIT fix is `endpoints/stm32h573/artifacts/tfm-s-v2.3.0-aegis-pq-hb-hedged-kmac-kemfix.hex`
(like every image there, kept on the bench PC, not in git; its checksum is in `artifacts/SHA256SUMS`; `build_tfm.sh`
rebuilds it).

Not touched: BL2, option bytes (product state Open, TrustZone on, WRP on BL2), NV counters, OTP.
Restore tested 2026-11-16: both slots read back byte-identical to the backup and the old firmware booted;
then the Aegis images were written again.

## Arduino Uno R3

| Change | Undo |
|---|---|
| Flash: legacy-sensor sketch (`endpoints/arduino-uno/legacy_sensor`) | `avrdude -p atmega328p -c arduino -P <port> -b 115200 -U flash:w:backups/arduino-uno/<time>/flash-before-aegis.hex:i` (avrdude from ~/.arduino15) |

## NXP FRDM-RW612

| Change | Undo |
|---|---|
| Flash (external, 64 MB): Aegis prover 0.1.0 (`endpoints/rw612/artifacts/aegis-rw612-prover-0.1.0.bin` at 0x08000000) in place of the factory Wi-Fi demo. The first 16 MB were saved before (`~/aegis-tools/nxp-backup/frdm-rw612-flash-16M.bin`, sha256 103769ad...; data only in 0x08000000-0x08070000, 0x08400000-0x08490000 and 0x085e0000-0x08630000) | write the backup back with J-Link: `loadbin frdm-rw612-flash-16M.bin 0x08000000` |
| Flash, since 18 November 2026: TF-M (NXP v2.1.4) with the Aegis partition, 0x08000400-0x0809FFFF, and the non-secure prover, 0x080A0000-0x0839FFFF, each written whole by `endpoints/rw612/tfm/flash.sh`. TF-M writes its storage at run time: PS 0x083A0000, ITS 0x083C0000, emulated OTP 0x083E0000-0x083E3FFF (flash, not fuses: `OCOTP_NV_COUNTERS_RAM_EMULATION=1`) | the Zephyr prover back: halt under reset, `loadbin aegis-rw612-prover-0.1.0.bin 0x08000000`; the TF-M areas can stay or be erased |

No fuse, OTP word or key was written: the prover only reads ELS key properties and uses slot 0 for CKDF into a
temporary slot it deletes again.

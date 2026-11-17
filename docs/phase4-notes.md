# Phase 4 notes: enforcement on the gateway (working log)

## Gateway kernel with packet filtering (built 2026-11-16, NOT installed)

The running gateway kernel has no netfilter, bridge or 802.1Q support, so the gateway can decide
(admit / quarantine) but not block traffic. Built a kernel with those features:

- Fragment `yocto/files/aegis-netfilter.cfg` (nf_tables inet/bridge/netdev, conntrack, NAT, log,
  limit, reject; bridge + br_netfilter + VLAN filtering; 802.1Q; advanced routing; USB Ethernet:
  CDC-ECM/NCM, ASIX AX88772/AX88179, Realtek RTL8152/8153), all built in.
- Applied with a post-read config file, so the pfdaq layer and bblayers.conf are unchanged:
  `MACHINE=mpfs-disco-kit-amp bitbake -R yocto/aegis-kernel.conf linux-mchp udmabuf-module pfdaq-uio`
  (1683 tasks, 1555 from cache, all succeeded; kernel .config shows the options set).
- Bundle in `build/gateway-kernel-netfilter/`: fitImage (kernel 6,568,303 bytes + the same device tree
  as the running fitImage, sha256 of the extracted DTB identical, + the unchanged boot.scr), the
  in-tree modules (`modules.tgz`), rebuilt out-of-tree `pfdaq_uio.ko` and `u-dma-buf.ko` (vermagic
  6.18.17-linux4microchip-2026.04.1-g7fbe4f69684d-dirty), SHA256SUMS, `install.sh`, `rollback.sh`.
- Board boot partition (mmcblk0p1, FAT, read-only look): boot.scr, fitImage (Nov 15 rebuild,
  sha256 0feccfc0...), fitImage.good (proven, fb0d8fe4...), uboot.env.

**Install only with someone at the board.** If the new kernel does not boot, recovery needs the SD
card in a PC (copy fitImage.pre-aegis or fitImage.good over fitImage). install.sh keeps
fitImage.good untouched, saves the current fitImage as fitImage.pre-aegis and the module tree as
/root/modules-pre-aegis.tgz; rollback.sh restores both.

Side effect in the pfdaq Yocto tree: `tmp-glibc/deploy/images/mpfs-disco-kit-amp/fitImage` now
points to this kernel. A plain pfdaq kernel build (without -R) restores the pfdaq kernel from sstate.

## Enforcement ruleset (prepared, needs the kernel above and the gateway in the path)

`gateway/enforce/aegis.nft` + `aegis-enforce.sh` (fleet.py `enforce_cmd` hook):
- forward chain policy drop; an endpoint segment interface ($ENDPOINT_IF: a USB Ethernet port or a
  quarantine VLAN) may forward only from addresses in the set @admitted;
- quarantined endpoints may reach only the gateway's quote port; DHCP allowed (udhcpd exists on
  the board);
- fleet.py calls `aegis-enforce.sh <endpoint> admit|quarantine` after every verdict.
Syntax checked with `nft -c` (nftables 1.0.9, same version as the board) on the PC; nothing applied.

## Installed on the gateway (2026-11-16, user at the board)

**Install incident, fixed before reboot.** On this rootfs `/lib` is a symlink to `usr/lib` (merged
/usr). `tar xzf modules.tgz -C /` replaced that symlink with a real `/lib` holding only the new
modules (GNU tar's default when an archive has a `lib/` directory entry), and the script then
stopped at the next step. The old modules in /usr/lib/modules were untouched and running programs
were unaffected (the loader lives in /usr/lib). Repair: one python process renamed the stray /lib
and recreated the symlink (no instant without /lib), the modules were then extracted under /usr,
the out-of-tree modules copied, depmod run, and the stray tree removed after checking it matched.
`install.sh` now extracts under /usr when /lib is a symlink. The boot partition and the module
backup were correct throughout (fitImage = new 00d049ab..., fitImage.pre-aegis = 0feccfc0...,
fitImage.good = fb0d8fe4..., /root/modules-pre-aegis.tgz with the old 111 files).

**Result:** booted in about 25 s; CONFIG_NF_TABLES/BRIDGE/VLAN_8021Q=y; `nft` works; remote core
attached; all modules loaded; no kernel warnings; Aegis services active; after a further reboot the
STM32 stayed admitted with its session (heartbeat 103) and `tools/regression.sh --board` passed 12/12
(logs/regression/20261116-200158).

**pfdaq suite on the new kernel** (detached run, 315 s, logs/kernel/*-install/): 32 of 42 lines pass,
same count as the baseline (logs/m5/m0809/suite-after.txt); two measurement lines swapped
(T6-rt-12500 now passes, T8-linux-uio-fifo-idle now fails). The first attempt was cut by my
15-minute SSH timeout and left the suite's load generators running; they were stopped by hand.

**Linux user-space latency spikes: cause found, mitigation measured (2026-11-17).**
The 4-5 ms maxima are scheduling delays of a normal-priority process, not slow interrupt delivery.
The kernel is `PREEMPT_NONE` with `HZ=250` (one tick = 4 ms), all device interrupts (Ethernet, SD
card, mailbox) land on CPU0, and a `SCHED_OTHER` task waits behind whatever runs there. Moving the
latency interrupt (IRQ 80, PLIC 119) and the process to another core did not remove the spikes by
itself; adding `SCHED_FIFO` 80 did. Channel 0, 500 us period, 100,000 events per run, gateway
services running (`tools/board/latency_ab.sh`, `latency_load.sh`; runtime-only, affinity restored on exit):

| Configuration | Overruns (2 runs) | Mean us | p99.9 <= us | Max us |
|---|---|---|---|---|
| default (IRQ and task free) | 24, 37 | 79-81 | 164 | 3595-4945 |
| IRQ and task pinned to CPU2, normal priority | 64, 152 | 62 | 123 | 4705-5105 |
| pinned to CPU2, SCHED_FIFO 80 | 0, 0 | 54 | 123 | 413-447 |
| pinned to CPU1, SCHED_FIFO 80 | 0, 0 | 54 | 82-123 | 359-469 |
| CPU2, SCHED_FIFO 80, busy loop on every core | 3, 0 | 51 | 123 | 1473, 408 |

Recipe: `echo 4 > /proc/irq/<pfdaq_stream_src>/smp_affinity; taskset -c 2 pfdaq_lat -R 80`.
Limits: idle-to-loaded CPU only (no heavy network or SD traffic), two runs per row, not hard
real-time (a 1.47 ms maximum with 3 overruns occurred under load). The earlier note that the
Aegis kernel change caused the spikes is not supported: the old baseline was simply a quieter
period. For hard bounds use the hart-4 FreeRTOS path (0.50 us handler, no overruns).

## Legacy node: Arduino Uno R3 (2026-11-16)

The Uno has no network interface, no keys and no measured boot, so it stands for the "device that
cannot attest". Backup first: avrdude read all 32 KB of flash (bootloader included) to
`backups/arduino-uno/<time>/flash-before-aegis.hex` (restore:
`avrdude -p atmega328p -c arduino -P <port> -b 115200 -U flash:w:flash-before-aegis.hex:i`).
Sketch `endpoints/arduino-uno/legacy_sensor` (3.7 KB): prints a reading every 2 s and answers any
request with "LEGACY-SENSOR uno v1 cannot attest". The PC exposes its serial port on TCP 7445
(`host/serial_bridge.py --tty <Uno> --port 7445 --replies LEGACY-SENSOR,...`); the policy lists it
as a normal endpoint. Gateway journal, every 30 s next to the admitted STM32:
"arduino-uno-legacy QUARANTINED no attestation: no token in reply: 'LEGACY-SENSOR uno v1 cannot attest...'".
This shows the decision; blocking its traffic does not apply (it has no traffic of its own).

## Why no USB-Ethernet adapter on the gateway

The Discovery Kit does not route the MSS USB controller to a connector (reference design MSS
configuration: USB UNUSED; device tree usb@20201000 disabled); its USB-C port goes to the on-board
FTDI debug chip. With one Ethernet port, real L2 separation needs a managed switch with 802.1Q
(the new kernel has VLAN support). Without one, only a routed-subnet setup is possible, which a
compromised endpoint could bypass on the shared L2 segment.

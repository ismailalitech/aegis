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

**Open: Linux user-space latency spikes.** Channel 0 (Linux UIO, 500 us period, 100,000 events):
on the new kernel 2 of 3 idle runs had overruns and maximum latencies of 4.1-5.1 ms (p99.9 unchanged
at 123-246 us); earlier baselines had maxima of 0.26-0.66 ms. Not explained by the Aegis services
(one spike happened with them stopped, one clean run with them running). Whether the kernel change
causes it needs repeated A/B runs against the old kernel (rollback.sh, then back). The hart-4
FreeRTOS latency path is not affected (pfdaq_cap -L 0 passes).

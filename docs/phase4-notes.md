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

# Phase 2 notes: PQC datapath in the PolarFire fabric (working log)

## Integration (proven with a stub, 2026-11-16)

- Fabric = pfdaq v0.5.x design (unchanged, from <pfdaq-repo>) + `aegis_pqc` as an APB3 slave
  in FIC3 APB slot 14 (0x40000E00, 256 bytes, PCLK = FIC3 clock 50 MHz). Overlay
  `hw/libero/AEGIS_PQC.tcl`, sourced right after PFDAQ.tcl; build `hw/libero/build.sh <ver> [rtl dir]`.
  Jobs contain FABRIC + SNVM only.
- Linux access: the kernel has IO_STRICT_DEVMEM, so /dev/mem cannot map the 0x40000000 page
  (drivers own parts of it). The pfdaq UIO device `pfdaq_stream_src` already maps that whole page;
  the core is at offset 0xE00. No kernel or device-tree change needed.
- Stub build dv100 (ID + scratch register only): timing met (max/min, multi-corner), 24,385 LE
  (pfdaq alone 24,334). Programmed (PROGRAM/VERIFY passed, eNVM digest unchanged 55b85278...).
  On the board: ID 0xAE150000, scratch write/read back, pfdaq slot 15 still answers, pfdaq
  supervised capture 16 MiB pass at 29.5 MB/s, remote core attached.
  Rollback: program `images/pfdaq-v051/PFDAQ_v0_5_1.job` (pfdaq repo) the same way.

## Gateway kernel limits found

No netfilter/nftables, no bridge, no 802.1Q VLAN in the running kernel: enforcement on the gateway
needs a kernel rebuild (fitImage on the SD card's boot partition; keep the current one as
fitImage.good for rollback).

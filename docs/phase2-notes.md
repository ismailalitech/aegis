# Phase 2 notes: PQC datapath in the PolarFire fabric (working log)

## Integration (proven with a stub, 2026-11-16)

- Fabric = pfdaq v0.5.x design (unchanged, from the pfdaq repository) + `aegis_pqc` as an APB3 slave
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

## The real core: aegis_pqc dv101 (2026-11-16)

RTL `hw/rtl` (Keccak-f[1600] one round per clock; one NTT unit for the ML-KEM FIPS 203 and
ML-DSA FIPS 204 transforms, one butterfly per clock, Barrett reduction proven exhaustively in the
model; register map in `hw/README.md` / `hw/sw/aegis_pqc_regs.h`; lanes at 0x38..0xFF).
Simulation: `hw/tb/run_all.sh` all pass (rerun here: 49 s with --fast). My C references in
`gateway/pqc/pqc_selftest.c` and the Python models agree on 80 random transforms.

**Build** (`hw/libero/build.sh 101`): timing met, max and min, all corners; FIC3/APB 50 MHz domain
worst slack 2.056 ns. Whole design 36,373 LE (38.9 %); the core adds about 11,844 4LUT,
3,087 DFF, 2 LSRAM, 26 Math blocks (difference to the stub build). Programmed: PROGRAM/VERIFY
passed, design version 0x65, checksum c2a3, fabric digest dbd6625d...b229, eNVM digest unchanged
(55b85278...b0e3).

**On the board** (`logs/fabric/*-dv101/`):

| Check | Result |
|---|---|
| `pqc_selftest 500`: Keccak vs C reference, zero-state KAT | 0 mismatches, KAT ok |
| ML-KEM NTT / NTT^-1, ML-DSA NTT / NTT^-1 vs C reference | 0 mismatches each (500 each) |
| forward-then-inverse entirely in hardware | 0 failures |
| liboqs KAT digests with every Keccak permutation in the fabric (`AEGIS_PQC_KECCAK=hw`) | ML-KEM-768 5352...17c3 and ML-DSA-65 7cb9...f072 = reference |
| `AEGIS_PQC_KECCAK=check` (fabric and software compared on every call): test_sig | 4,657,147 permutations, 0 differences |
| pfdaq on the same fabric: latency mode, supervised 16 MiB capture | pass, 29.6 MB/s |

**Timing (honest):**

| Operation | Core cycles (50 MHz) | Wall time seen by Linux, incl. MMIO |
|---|---|---|
| Keccak-f[1600] | 24 (0.48 us) | 16.7 us |
| ML-KEM NTT / NTT^-1 | 904 (18.1 us) | 113 us |
| ML-DSA NTT / NTT^-1 | 1032 (20.6 us) | 116 us |

liboqs `speed_kem`/`speed_sig` on one U54 core, software Keccak vs fabric Keccak:
ML-KEM-768 keygen 1.219 -> 1.315 ms, encaps 1.417 -> 1.508 ms, decaps 1.755 -> 1.870 ms;
ML-DSA-65 keypair 3.99 -> 4.48 ms, sign 14.3 -> 15.5 ms (mean), verify 4.12 -> 4.57 ms.
The fabric is about 8-12 % slower end to end: each permutation moves 100 uncached 32-bit words
over FIC3 APB; compute is 0.48 us of the 16.7 us. The NTT unit is not wired into liboqs (its
transfer cost, 512 words, exceeds a software NTT).

What would make it faster (not done): keep data in the fabric across calls (whole sponge
absorb/squeeze, or whole polynomial-matrix steps), move data by DMA or over the 64-bit FIC0 AXI
instead of APB, or let the hart-4 real-time context drive the core without Linux overhead.

Rollback of the fabric: program `<pfdaq-repo>/images/pfdaq-v051/PFDAQ_v0_5_1.job`
(FABRIC + SNVM) with `hw/libero/program.sh` from the pfdaq repo; the JTAG channel must be detached
from ftdi_sio first.

## NIST ACVP vectors with the fabric doing Keccak (2026-11-16)

`tools/acvp_commands.py` imports liboqs' own `tests/test_acvp_vectors.py` unchanged and records the
exact `vectors_kem`/`vectors_sig` command lines it would run (ACVP-Server v1.1.0.41 files from
`vectors/acvp`, checksummed). `tools/run_acvp_commands.py` (stdlib) runs them anywhere.

| Where | Keccak | Cases | Failed |
|---|---|---|---|
| PC (x86 liboqs build) | software | 265 | 0 |
| PolarFire, liboqs-rv64-fabric | fabric (`AEGIS_PQC_KECCAK=hw`) | 265 | 0 |
| PolarFire, liboqs-rv64-fabric | fabric + software compared on every call (`check`) | 265 | 0 |

Cases: ML-KEM-768 keyGen 25, encapsulation 25, decapsulation 10; ML-DSA-65 keyGen 25, sigGen 120
(internal, external, pre-hash), sigVer 60 (30 of them expected to reject). Negative controls on the
PC: a corrupted key, ciphertext, signature or expected value makes the case fail. Fabric use
confirmed with AEGIS_PQC_STATS (e.g. one ML-DSA sigGen case: 278 fabric permutations, 0 software).
Wording: "passes the NIST ACVP vectors", not "validated".

## Where the time goes (measured 2026-11-16)

`gateway/pqc/mmio_cost.c` on the board (200,000 accesses, 3 runs, identical to 0.5 ns):
one 32-bit read from Linux user space to the core = 222 ns, one write = 141 ns (APB clock 20 ns).
A Keccak permutation moves 50 words in and 50 out: about 7.1 + 11.1 = 18 us of transfers against
0.48 us of compute (observed 16.7 us per call, writes partly posted).

liboqs `speed_common` (one-block hashes, 1 s each) on one U54 core:
SHA3-256 17.3 us software vs 19.0 us with fabric Keccak; SHAKE128 17.3 vs 19.1 us. So the software
permutation itself costs about 15 us here (the U54 has no rotate instruction), and the fabric core
computes it about 30 times faster, but the APB transfers eat all of that.
`test_sha3` (liboqs SHA-3 known answers, incl. four-way SHAKE) passes with fabric Keccak.

Consequence for a faster design: the data path, not the core, must change: keep state in the fabric
across a whole sponge or a whole matrix expansion, or move it by DMA / 64-bit AXI on FIC0.

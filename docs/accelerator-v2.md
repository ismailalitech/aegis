# Accelerator v2: the sponge stays in the fabric (on the board since 17 November 2026, fabric design 102)

The first core (`aegis_pqc`, phase 2) computes a Keccak-f[1600] permutation 30 times faster than the U54, but every
permutation moves the whole 200-byte state over the 32-bit APB bus, and that makes liboqs **6-12 % slower** than
software. Version 2 keeps the state in the fabric and moves only the bytes that enter or leave the sponge, with full
squeezed blocks written into DDR by DMA.

**Measured on the board: ML-KEM-768 1.26-1.29 times faster than software, ML-DSA-65 1.19-1.54 times faster**, with
every SHA-3/SHAKE call of liboqs running on the core, the known-answer outputs byte-identical to plain liboqs and the
265 NIST ACVP cases passing. The cost model, fed with the constants measured on the core, predicts these times within
2.5 % (section 6).

## 1. Where the time goes, and the choice of design

`tools/accel/profile_keccak.sh` counts liboqs 0.16.0's permutations per operation by phase (absorb or squeeze), rate
and API (one-way or four-way). ML-DSA-65 verify does 174 permutations, 150 of them squeezing SHAKE128 to expand the
matrix A; signing does about 330.

`tools/accel/cost_model.py` turns counts into times with costs measured on the board: an APB read 222 ns, a write
141 ns, a software permutation 15.0 us (from liboqs `speed_common`), the existing core 16.7 us per permutation, a
non-cached DDR read 113 ns per 8 bytes (pfdaq's capture buffer copy, 70.5 MB/s). **Check: it predicts the existing
core's measured times within 4 %.**

| Design | Speed against software |
|---|---|
| A: permutation per call over APB (built) | 0.89-0.96 (measured; predicted 0.93-0.96) |
| B: state kept in the fabric, APB only | 1.18-1.37 |
| C: B plus full squeezed blocks by DMA into DDR | 1.42-2.42 |

C was chosen; its one unmeasured constant (DMA latency, assumed 1 us) changes a signature by less than 0.1 ms even if
it is three times larger.

## 2. Hardware (`hw/rtl/aegis_sponge.v`, `hw/rtl/aegis_pqc2.v`)

- 1600-bit state, one Keccak round per clock (the verified `aegis_keccak_round`).
- State words can be written plain or **XORed** in (absorbing a block = XOR-writing it).
- **8 slots** in block RAM; `SELECT n` saves the working state and loads slot n in 51 clocks.
- **`SQUEEZE_DMA`**: N times { permute; write the rate lanes as one AXI4 INCR burst of 64-bit beats }. Refuses
  misaligned addresses, bursts that would cross 4 KiB, a rate of 0 or above 21 lanes, zero blocks. Stops on an error
  response. Reports blocks written in STATUS, so software copies block i while block i+1 is computed.
- APB accesses wait (PREADY low) while the engine is busy, so software never polls between a command and the next
  state access. STATUS never waits.
- The register map is a superset of the first core's: the first driver keeps working. ID `0xAE150002`.

**Simulation** (`hw/tb/run_all.sh`, Icarus Verilog, no warnings): a Python model of the core writes a
4,500-operation script (`hw/tb/gen_sponge_vectors.py`); every hash in it is also checked against `hashlib`. The
testbench replays it against the RTL, behind an AXI4 slave model with random back-pressure, an error-response window
and protocol checks: 3,251 checks, 835 DMA beats, all pass. **Five deliberate RTL bugs** (slot load off by one, XOR
ignored, WLAST one beat early, no 4 KiB check, error response ignored) are each caught.

**Synthesis** (Libero 2026.1 / Synplify, MPFS095T-1, `hw/libero/synth_core.tcl`): estimated 95.9 MHz against the 50 MHz
APB clock (worst path in the NTT multiplier, not the sponge); about 18,300 LUTs, 3,400 flip-flops, 4 block RAMs and 27
math blocks with the NTT included, about 6,500 LUTs more than the first core. With the rest of the design that is under
half of the device.

## 3. Software (`gateway/pqc/aegis_sponge_drv.c`)

A liboqs SHA-3 provider (both the one-way and the four-way callback tables). It installs itself from a library
constructor when `AEGIS_PQC_SPONGE=hw` (the core) or `model` (a C model of the registers, for the PC), so liboqs' own
programs use it unchanged. Contexts are mapped to slots, least recently used first out (spilled: 50 words read, written
back later). Full blocks are squeezed by DMA when a non-cached buffer exists (u-dma-buf), otherwise over APB.

`tests/host/test_sponge_provider.sh`, 18 checks, all pass (also in CI):

- the C model replays the RTL's test script with no difference (so testing on the model tests against the RTL's
  behaviour);
- liboqs `test_sha3` (SHA3-256/384/512, SHAKE128/256, four-way) passes through the provider, with 8 slots and with 1;
- ML-KEM-768 and ML-DSA-65 known-answer outputs are **byte-identical** to plain liboqs with 8 slots, with 1 slot (every
  context switch spills: hundreds of spills per run) and without DMA;
- the **265 NIST ACVP cases** pass with 8 slots and with 1;
- the four corrupted ACVP cases give the same exit codes as plain liboqs (the corrupted signature-verification case
  exits 0 in all three, plain liboqs included);
- every program above is checked to have really gone through the provider (a silent fallback to liboqs' own SHA-3 would
  otherwise pass everything; this check caught exactly that once during development).

The provider adds no permutations: the counts per operation are the same as plain liboqs'.

## 4. The prediction, from the real driver's traffic

`tools/accel/count_main.c` counts the provider's reads, writes, slot switches, DMA commands and bytes per operation.
The driver's own CPU time was **measured on the gateway**: liboqs with the provider on the model (the model using liboqs'
own permutation) minus plain liboqs, minus the model's emulation cost, itself measured in the same build on the board
(write 143 ns, read 87 ns, DMA beat 79 ns).

| Operation | perms | software (measured) | bus + core | + driver CPU | **predicted** |
|---|---|---|---|---|---|
| ML-KEM-768 keygen | 45 | 1.22 ms | 0.83 ms | 0.08 ms (measured) | **0.91 ms (x1.34)** |
| ML-KEM-768 encaps | 45 | 1.42 ms | 1.03 ms | 0.08 ms (measured) | **1.11 ms (x1.28)** |
| ML-KEM-768 decaps | 54 | 1.75 ms | 1.28 ms | 0.08 ms (measured) | **1.35 ms (x1.30)** |
| ML-DSA-65 keygen | 190 | 3.99 ms | 1.95 ms | 0.34 ms (measured) | **2.29 ms (x1.74)** |
| ML-DSA-65 sign | 334 | 14.30 ms | 10.61 ms | 0.52 ms (scaled from verify) | **11.13 ms (x1.29)** |
| ML-DSA-65 verify | 174 | 4.12 ms | 2.21 ms | 0.28 ms (measured) | **2.49 ms (x1.65)** |

Signing gains least because most of its time is not Keccak but polynomial arithmetic (NTTs, about 9.5 ms). The next
step for signing would be keeping polynomials in the fabric too (the NTT unit with data resident across a whole
matrix-vector product), not a faster sponge.

## 5. Into the board design (fabric design 102)

- **Libero overlay** `hw/libero/AEGIS_PQC2.tcl` (`AEGIS_OVERLAY=AEGIS_PQC2.tcl hw/libero/build.sh 102`): the core,
  through the port wrapper `hw/rtl/aegis_pqc2_fic0.v` (32-bit addresses, the FIC0 interconnect's ID/lock/user widths,
  read channel tied off), in FIC3 APB slot 14 as before; its AXI4 master on a **second master port of the FIC0
  interconnect `DMA_INITIATOR`** (whose slave port is the MSS's FIC0 target, i.e. DDR), with the interconnect's clock
  crossing from the 50 MHz core clock to the 125 MHz FIC0 clock. `DESIGN_ONLY=1` builds only the SmartDesign (2 minutes)
  to check wiring before a full build.
- **Build:** timing met, max and min, all corners; 44,191 logic elements (47.3 % of the device; design 101: 38.9 %).
- **Programmed** with the gateway shut down: PROGRAM and VERIFY passed, design version `0x0066`, eNVM digest unchanged
  (`55b85278...`). The gateway came back in about 30 s with both Aegis services running; the core reads ID
  `0xAE150002` at `0x40000E00`, pfdaq's block still answers in the next slot.
- **DMA buffer:** no kernel or device-tree change. The core writes into the last 4 KiB page of pfdaq's existing
  non-cached buffer `udmabuf-ddr-nc0` (`0xC9FFF000`), far from where pfdaq's captures start.
- **The gateway's own attestation saw the change**: after programming, its quotes were refused with
  `measurement changed: design_digests_sha256, design_info` until the new design was enrolled on purpose
  (`host/aegis_verify.py enroll`; checked that the identity key is unchanged and only those two fields moved; the old
  record is kept as `host/enrolled/<dsn>.dv101.json.bak`, which the verifier ignores). A fabric change is visible to the verifier, as designed.
- **The first driver still works on the new core** (its register map is a superset): it now accepts both IDs and
  clears XOR mode before its plain writes; the board's `pqc_selftest` and fabric liboqs were rebuilt (old copies kept on
  the gateway in `/root/aegis-backup-v1-fabric-binaries`).
- `tools/regression.sh --board`: **13 of 13**, with a new stage `fabric-sponge-acvp` (the 265 ACVP cases with the
  provider on the core).
- **Rollback:** program `build/libero/AEGIS_dv101.job` (or pfdaq's `PFDAQ_v0_5_1.job`) the same way and restore the
  enrolment record from the backup.

## 6. Results on the board (`tools/accel/board_sponge_test.sh`, `evidence/accel-v2/`)

**A bug only the hardware could show, found and fixed.** The first run passed everything with one slot and failed the
known-answer tests and ACVP with eight. The core's current slot survives between processes (only a reset sets it to
0), while the driver assumed slot 0 at start; on the PC every process got a fresh model, so the tests could not see it.
The driver now reads the current slot from STATUS at start, and the PC test has a new case that starts the model in
slot 5: it fails without the fix and passes with it.

After the fix, all 11 checks pass: raw DMA output equal to APB squeezes; `test_sha3` with 8 slots and 1; ML-KEM-768 and
ML-DSA-65 known-answer outputs byte-identical to plain liboqs with 8 slots, 1 slot and without DMA; the 265 NIST ACVP
cases with 8 slots and 1.

**Raw timings** (`sponge_bench`, against what the first prediction assumed):

| | Measured | Assumed before |
|---|---|---|
| state word write / STATUS read | 0.143 / 0.221 us | 0.141 / 0.222 us (from the first core) |
| PERMUTE, then the first read (waits on PREADY) | 0.74 us | |
| slot switch, then the first read | 1.30 us | 1.24 us |
| first DMA block reported after the command | 2.90 us | 2.2 us |
| each further DMA block (168 bytes) | 1.13 us | 1.2 us |
| non-cached read from the DMA page | 0.174 us per 8 bytes | 0.113 us (pfdaq's copy rate) |

**liboqs speed on one U54 core** (`speed_kem` / `speed_sig`, two runs each, mean), and the cost model with the measured
constants (`tools/accel/cost_model.py --counts`):

| Operation | Software | With the core | Speed-up | Model, measured constants | First prediction |
|---|---|---|---|---|---|
| ML-KEM-768 keygen | 1.22 ms | 0.94 ms | **x1.29** | 0.95 ms | x1.34 |
| ML-KEM-768 encaps | 1.44 ms | 1.14 ms | **x1.26** | 1.15 ms | x1.28 |
| ML-KEM-768 decaps | 1.78 ms | 1.40 ms | **x1.27** | 1.40 ms | x1.30 |
| ML-DSA-65 keygen | 3.95 ms | 2.57 ms | **x1.54** | 2.54 ms | x1.74 |
| ML-DSA-65 sign | 13.87 ms | 11.63 ms | **x1.19** | 11.52 ms | x1.29 |
| ML-DSA-65 verify | 4.09 ms | 2.78 ms | **x1.47** | 2.71 ms | x1.65 |

The first prediction was optimistic only through the two constants it had to assume (DMA latency and the non-cached read
cost); with them measured, the model is within 2.5 % on every operation. Signing varies between runs (its rejection
loop); one earlier run gave x1.27.

**Where the next gain is:** the non-cached copy is now the largest Keccak-related cost (0.174 us per 8 bytes). Reading
the DMA page through a cached mapping with cache maintenance, or keeping polynomial sampling in the fabric so fewer
bytes come back at all, are the two directions; for signing, the polynomial arithmetic (about 9.5 ms) is the bigger
target.

## Reproduce

    hw/tb/run_all.sh --fast                                    # RTL simulation, both cores
    tests/host/test_sponge_provider.sh                         # provider on the model: 18 checks
    tools/accel/profile_keccak.sh 200                          # permutation profile
    .venv/bin/python tools/accel/cost_model.py                 # design comparison
    tools/build_liboqs_sponge.sh x86 && L=~/aegis-tools/liboqs-x86-sponge && \
      cc -O2 -I$L/include tools/accel/count_main.c -L$L/lib -loqs -Wl,-rpath,$L/lib -o build/accel/count && \
      AEGIS_PQC_SPONGE=model build/accel/count 200 > build/accel/sponge-counts.json
    .venv/bin/python tools/accel/cost_model.py --counts build/accel/sponge-counts.json
    libero SCRIPT:hw/libero/synth_core.tcl "SCRIPT_ARGS:<dir> aegis_pqc2 hw/rtl 50"   # synthesis estimate
    AEGIS_OVERLAY=AEGIS_PQC2.tcl hw/libero/build.sh 102                                 # board design
    <pfdaq repo>/hw/libero/program.sh build/libero/AEGIS_dv102.job                      # gateway shut down first
    tools/build_liboqs_sponge.sh rv64 && GATEWAY=<address> tools/accel/board_sponge_test.sh

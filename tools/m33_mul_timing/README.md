# Cortex-M33 multiply timing (19 November 2026)

The question: mldsa-native and mlkem-native v2.0.0 (portable C, as all Aegis endpoints build them) assume that a
32x32->64 multiply takes the same time for every operand (upstream issue pq-code-package/mldsa-native#1436). The
Cortex-M3 does not: its long multiplies end early on small operands. Arm documents no cycle count for the M33's.

What our images run (disassembly of the deployed secure images, both built with `-mcpu=cortex-m33+nodsp`):
ML-DSA's Montgomery reduction is inlined as SMULL (NTT, inverse NTT, pointwise); ML-KEM uses 32-bit MLA/MULS and one
UMULL in `poly_compress_d10`. No SMLAL/UMLAL, no DSP multiplies, no division in the PQ code.

The test: blocks of 128 identical instructions, timed with DWT CYCCNT, interrupts off, in the Secure state, loaded
into SRAM over the debugger with the core halted (nothing written to flash). 26 operand classes, from 0 and small
values to 0x80000000 and 0xFFFFFFFF, plus the value ranges ML-DSA and ML-KEM use. UDIV/SDIV, whose time depends on
the operands, are the positive control. Also mldsa-native's `montgomery_reduce` compiled with the endpoint flags,
and a 256-coefficient pointwise multiply.

    build.sh <name> <base> <length>        # the SRAM image (GCC= to choose the compiler)
    run_pyocd.py <ST-LINK serial> out/stm32.elf out/stm32.bin results/<run>.json --secure
    run_jlink.py out/rw612.elf out/rw612.bin results/<run>.json --mpu-off     # DISPLAY unset
    analyze.py results/<run>*.json

Reset the board afterwards (the gateway quarantines it while it is halted, and admits it again after the reset).

Result on STM32H573 boards 1 and 2 and the FRDM-RW612 (all Cortex-M33 r0p4, CPUID 0x410FD214): SMULL, UMULL, SMLAL,
UMLAL, MUL and MLA took the same number of cycles for every operand class, in every run (min = max). UDIV/SDIV took
1 to 11 cycles each, so the harness sees operand-dependent timing where it exists. `montgomery_reduce`: 17 cycles per
call for every input class; pointwise multiply: 5909 cycles for every input class. Records: `evidence/m33-mul-timing/`.

This is a measurement over these operand classes on this core revision, not a proof for every input.

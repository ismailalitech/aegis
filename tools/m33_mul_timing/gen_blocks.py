#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate blocks.S: one timed straight-line block per (instruction, mode).
Each block: uint32_t blk(a, b, acc_lo, acc_hi) -> CYCCNT delta over N instructions (plus a fixed overhead,
measured by the EMPTY block). Operands sit in r2 (a) and r3 (b); destinations/accumulators in r4-r11."""
import sys
N = int(sys.argv[1]) if len(sys.argv) > 1 else 128
PAIRS = [("r4", "r5"), ("r6", "r7"), ("r8", "r9"), ("r10", "r11")]
SINGLES = ["r4", "r6", "r8", "r10"]

def body(name):
    out = []
    for i in range(N):
        lo, hi = PAIRS[i % 4]
        s = SINGLES[i % 4]
        if name == "EMPTY":
            return []
        elif name in ("SMULL_T", "UMULL_T", "SMLAL_T", "UMLAL_T"):      # 4 rotating independent dest pairs
            out.append(f"{name[:5].lower()} {lo}, {hi}, r2, r3")
        elif name in ("SMULL_D", "UMULL_D"):                              # result consumed immediately
            out.append(f"{name[:5].lower()} r4, r5, r2, r3")
            out.append("eor r12, r4, r5")
        elif name in ("SMLAL_D", "UMLAL_D"):                              # one accumulator chain
            out.append(f"{name[:5].lower()} r4, r5, r2, r3")
        elif name == "MUL_T":
            out.append(f"mul {s}, r2, r3")
        elif name == "MUL_D":
            out.append("mul r4, r2, r3")
            out.append("eor r12, r12, r4")
        elif name == "MLA_T":
            out.append(f"mla {s}, r2, r3, {s}")
        elif name == "MLA_D":
            out.append("mla r4, r2, r3, r4")
        elif name == "UDIV_T":                                           # positive control: early-terminating divider
            out.append(f"udiv {s}, r2, r3")
        elif name == "SDIV_T":
            out.append(f"sdiv {s}, r2, r3")
        elif name == "ADDW_T":                                           # 32-bit 1-cycle control (fetch bound?)
            out.append(f"add.w {s}, r2, r3")
        elif name == "ADDW_D":
            out.append("add.w r4, r4, r3")
        else:
            raise SystemExit(name)
    return out

NAMES = ["EMPTY", "SMULL_T", "SMULL_D", "UMULL_T", "UMULL_D", "SMLAL_T", "SMLAL_D", "UMLAL_T", "UMLAL_D",
         "MUL_T", "MUL_D", "MLA_T", "MLA_D", "ADDW_T", "ADDW_D", "UDIV_T", "SDIV_T"]
print("\t.syntax unified\n\t.thumb\n\t.text")
print(f"\t.global block_count\n\t.section .rodata\n\t.align 2\nblock_count: .word {len(NAMES)}\n"
      f"\t.global block_n\nblock_n: .word {N}\n\t.global block_table\nblock_table:")
for n in NAMES:
    print(f"\t.word blk_{n}+1")
print("\t.global block_names\nblock_names: .asciz \"" + ",".join(NAMES) + "\"\n\t.text")
for n in NAMES:
    print(f"\t.align 2\n\t.thumb_func\nblk_{n}:")
    print("\tpush {r4-r11, lr}\n\tmov r12, r0\n\tmov r4, r2\n\tmov r5, r3\n\tmov r6, r2\n\tmov r7, r3\n"
          "\tmov r8, r2\n\tmov r9, r3\n\tmov r10, r2\n\tmov r11, r3\n\tmov r2, r12\n\tmov r3, r1\n"
          "\tmov r12, #0\n\tmovw r1, #0x1004\n\tmovt r1, #0xE000\n\tdsb\n\tisb\n\tldr r0, [r1]")
    for ins in body(n):
        print("\t" + ins)
    print("\tldr r12, [r1]\n\tsub r0, r12, r0\n\tpop {r4-r11, pc}")

/* SPDX-License-Identifier: Apache-2.0
 *
 * Aegis hook for the Zynq UltraScale+ FSBL (Vitis 2025.2 zynqmp_fsbl, A53 64-bit): fills the hand-off page for OP-TEE
 * (endpoints/zynqmp/handoff/aegis_zynqmp_handoff.h, docs/zynqmp-key-design.md phase B).
 *
 * Two calls, both added by patch_fsbl_aegis.ps1:
 *   AegisFsbl_Measure()        in xfsbl_main.c, once all partitions are loaded (boot device still in use by the FSBL);
 *   AegisFsbl_BeforeHandoff()  in XFsbl_HookBeforeHandoff (xfsbl_hooks.c), just before the FSBL leaves.
 * Neither can fail the boot: both return nothing, and the hand-off page says what worked.
 */
#ifndef AEGIS_FSBL_HANDOFF_H
#define AEGIS_FSBL_HANDOFF_H

#include "xil_types.h"
#include "aegis_zynqmp_handoff.h"

/* Scratch for reading the boot image back in chunks: the 64 KiB of DDR just below the hand-off page, inside OP-TEE's
 * secure memory (its TA pool, unused until OP-TEE runs). The FSBL's own chunk buffer (ReadBuffer, .bitstream_buffer)
 * cannot be used: it lies in the OCM at 0xFFFF0040, where TF-A has been loaded by then. Zeroed after use. */
#define AEGIS_FSBL_SCRATCH_SIZE 0x10000u
#define AEGIS_FSBL_SCRATCH_PA   (AEGIS_HANDOFF_PA - AEGIS_FSBL_SCRATCH_SIZE)

/* Labels this hook writes besides "FSBL", "PMUFW", "PL", "TFA", "TEE", "UBOOT":
 *   "<label>.<n>"  second and later partitions with the same destination (an ELF with several load segments);
 *   "P<index>"     a partition the FSBL loads whose destination is none of the above;
 *   "TRUNCATED"    last entry when the image has more partitions than entries: value zero, length = partitions left
 *                  out. A verifier that pins the list rejects it, as it should.
 * An entry with length 0 and a zero value means the partition could not be read back or hashed. */
#define AEGIS_FSBL_LABEL_TRUNCATED "TRUNCATED"

void AegisFsbl_Measure(void);
void AegisFsbl_BeforeHandoff(u32 EarlyHandoff);

#endif

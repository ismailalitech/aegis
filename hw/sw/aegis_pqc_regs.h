/* SPDX-License-Identifier: Apache-2.0 */
/*
 * aegis_pqc register map (APB slave, 256-byte slot, 32-bit registers).
 * Offsets are bytes from AEGIS_PQC_BASE; access with 32-bit loads/stores
 * (e.g. mmap of /dev/mem and volatile uint32_t pointers).
 *
 * Matches hw/rtl/aegis_pqc.v.
 */
#ifndef AEGIS_PQC_REGS_H
#define AEGIS_PQC_REGS_H

#define AEGIS_PQC_BASE              0x40000E00u
#define AEGIS_PQC_SPAN              0x100u

#define AEGIS_PQC_ID                0x00u   /* R  */
#define AEGIS_PQC_CTRL              0x04u   /* W  pulses */
#define AEGIS_PQC_STATUS            0x08u   /* R  */
#define AEGIS_PQC_KECCAK_CYCLES     0x0Cu   /* R  */
#define AEGIS_PQC_NTT_CYCLES        0x10u   /* R  */
#define AEGIS_PQC_NTT_INDEX         0x14u   /* RW */
#define AEGIS_PQC_NTT_DATA          0x18u   /* RW, auto-increments NTT_INDEX */

/* Keccak lane i (i = x + 5*y, 0..24): state bytes 8i..8i+7, little-endian */
#define AEGIS_PQC_LANE_BASE         0x38u
#define AEGIS_PQC_LANE_LO(i)        (AEGIS_PQC_LANE_BASE + 8u * (unsigned)(i))       /* bits 31:0  */
#define AEGIS_PQC_LANE_HI(i)        (AEGIS_PQC_LANE_BASE + 8u * (unsigned)(i) + 4u)  /* bits 63:32 */
#define AEGIS_PQC_LANES             25u

#define AEGIS_PQC_ID_VALUE          0xAE150001u

/* CTRL bits (write-only; starts are ignored while the unit is busy) */
#define AEGIS_PQC_CTRL_KECCAK_START (1u << 0)
#define AEGIS_PQC_CTRL_NTT_FWD      (1u << 1)
#define AEGIS_PQC_CTRL_NTT_INV      (1u << 2)   /* if FWD and INV are both set, FWD runs */
#define AEGIS_PQC_CTRL_NTT_MODE_DSA (1u << 8)   /* latched on an NTT start: 0 ML-KEM, 1 ML-DSA */

/* STATUS bits */
#define AEGIS_PQC_STATUS_KECCAK_BUSY (1u << 0)
#define AEGIS_PQC_STATUS_NTT_BUSY    (1u << 1)
#define AEGIS_PQC_STATUS_KECCAK_DONE (1u << 4)  /* sticky, cleared by KECCAK_START */
#define AEGIS_PQC_STATUS_NTT_DONE    (1u << 5)  /* sticky, cleared by an NTT start */
#define AEGIS_PQC_STATUS_NTT_MODE    (1u << 8)

/* NTT coefficients */
#define AEGIS_PQC_NTT_N             256u
#define AEGIS_PQC_NTT_DATA_MASK     0x007FFFFFu  /* 23 bits */
#define AEGIS_PQC_Q_MLKEM           3329u
#define AEGIS_PQC_Q_MLDSA           8380417u

#endif /* AEGIS_PQC_REGS_H */

/* SPDX-License-Identifier: Apache-2.0 */
#ifndef AEGIS_PQC_DRV_H
#define AEGIS_PQC_DRV_H

#include <stdint.h>

#define AEGIS_PQC_ID 0xAE150001u

int aegis_pqc_open(void);
uint32_t aegis_pqc_id(void);
/* In-place Keccak-f[1600] on 25 lanes (FIPS 202 order, no lane complementing). */
int aegis_pqc_keccak_f1600(uint64_t lanes[25], uint32_t *cycles);
/* mode 0 = ML-KEM (q = 3329), 1 = ML-DSA (q = 8380417); coefficients canonical [0, q). */
int aegis_pqc_ntt(int mode, int inverse, uint32_t coeffs[256], uint32_t *cycles);
int aegis_pqc_keccak_hook(void *state, void (*sw)(void *));

#endif

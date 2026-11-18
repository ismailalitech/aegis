/* SPDX-License-Identifier: Apache-2.0 */
#ifndef AEGIS_ELS_H
#define AEGIS_ELS_H
#include <stdint.h>

int aegis_els_init(void);
void aegis_els_dump_slots(void);
/* 32 bytes = HMAC-SHA256(CKDF(die master key), label), computed inside ELS. 0 on success. */
int aegis_els_derive(const char *label, uint8_t out[32]);
#endif

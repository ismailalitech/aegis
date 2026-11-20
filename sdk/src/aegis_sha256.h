/* SPDX-License-Identifier: Apache-2.0 */
#ifndef AEGIS_SHA256_H
#define AEGIS_SHA256_H
#include <stddef.h>
#include <stdint.h>

void aegis_sha256(const uint8_t *p, size_t n, uint8_t out[32]);
#endif

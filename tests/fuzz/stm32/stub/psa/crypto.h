/* SPDX-License-Identifier: Apache-2.0 */
/* PC stand-in for TF-M's psa/crypto.h (tests/fuzz/stm32). */
#ifndef FZ_PSA_CRYPTO_H
#define FZ_PSA_CRYPTO_H
#include "psa/client.h"
psa_status_t psa_generate_random(uint8_t *output, size_t output_size);
#endif

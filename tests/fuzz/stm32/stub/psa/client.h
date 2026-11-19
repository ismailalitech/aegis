/* SPDX-License-Identifier: Apache-2.0 */
/* PC stand-in for TF-M's psa/client.h: only what aegis_pq_attest.c uses (tests/fuzz/stm32). */
#ifndef FZ_PSA_CLIENT_H
#define FZ_PSA_CLIENT_H
#include <stddef.h>
#include <stdint.h>
typedef int32_t psa_status_t;
typedef int32_t psa_handle_t;
typedef struct { const void *base; size_t len; } psa_invec;
typedef struct { void *base; size_t len; } psa_outvec;
#define PSA_SUCCESS                  ((psa_status_t)0)
#define PSA_ERROR_PROGRAMMER_ERROR   ((psa_status_t)-129)
#define PSA_ERROR_GENERIC_ERROR      ((psa_status_t)-132)
#define PSA_ERROR_NOT_PERMITTED      ((psa_status_t)-133)
#define PSA_ERROR_NOT_SUPPORTED      ((psa_status_t)-134)
#define PSA_ERROR_INVALID_ARGUMENT   ((psa_status_t)-135)
#define PSA_ERROR_BAD_STATE          ((psa_status_t)-137)
#define PSA_ERROR_BUFFER_TOO_SMALL   ((psa_status_t)-138)
#define PSA_ERROR_DOES_NOT_EXIST     ((psa_status_t)-140)
#define PSA_ERROR_HARDWARE_FAILURE   ((psa_status_t)-147)
#define PSA_ERROR_INSUFFICIENT_ENTROPY ((psa_status_t)-148)
#define PSA_ERROR_INVALID_SIGNATURE  ((psa_status_t)-149)
psa_status_t psa_call(psa_handle_t handle, int32_t type, const psa_invec *in_vec, size_t in_len,
		      psa_outvec *out_vec, size_t out_len);
#endif

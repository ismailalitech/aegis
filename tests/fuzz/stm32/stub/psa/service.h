/* SPDX-License-Identifier: Apache-2.0 */
/* PC stand-in for TF-M's psa/service.h (tests/fuzz/stm32). psa_write beyond the caller's output size is a
 * programmer error that TF-M answers with a panic; the stub aborts, so the fuzzer reports it. */
#ifndef FZ_PSA_SERVICE_H
#define FZ_PSA_SERVICE_H
#include "psa/client.h"
#define PSA_MAX_IOVEC 4
typedef struct {
	int32_t type;
	psa_handle_t handle;
	size_t in_size[PSA_MAX_IOVEC];
	size_t out_size[PSA_MAX_IOVEC];
} psa_msg_t;
size_t psa_read(psa_handle_t msg_handle, uint32_t invec_idx, void *buffer, size_t num_bytes);
void psa_write(psa_handle_t msg_handle, uint32_t outvec_idx, const void *buffer, size_t num_bytes);
#endif

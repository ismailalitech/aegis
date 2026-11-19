/* SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT (mldsa-native's licence) */
/* mld_montgomery_reduce from mldsa-native v2.0.0 mldsa/src/reduce.h (contracts/asserts dropped, casts inlined),
 * compiled with the endpoints' flags: -Os -std=gnu11 -mcpu=cortex-m33+nodsp+nofp -mthumb -mfloat-abi=soft. */
#include <stdint.h>
#define MLDSA_Q 8380417
static inline int32_t mld_montgomery_reduce(int64_t a)
{
  const uint64_t QINV = 58728449;
  const uint32_t a_reduced = (uint32_t)(a & UINT32_MAX);
  const uint32_t a_inverted = (a_reduced * QINV) & UINT32_MAX;
  const int32_t t = (int32_t)a_inverted;
  int64_t r;
  r = a - (int64_t)t * MLDSA_Q;
  r = r >> 32;
  return (int32_t)r;
}
__attribute__((noinline)) int32_t mont_mul(int32_t a, int32_t b) { return mld_montgomery_reduce((int64_t)a * b); }
/* mld_poly_pointwise_montgomery_c from mldsa-native v2.0.0 mldsa/src/poly.c (loop body only) */
__attribute__((noinline)) void pointwise(int32_t *c, const int32_t *a, const int32_t *b)
{
  unsigned int i;
  for (i = 0; i < 256; ++i)
    c[i] = mld_montgomery_reduce((int64_t)a[i] * b[i]);
}

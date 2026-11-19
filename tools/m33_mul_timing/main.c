/* SPDX-License-Identifier: Apache-2.0 */
#include <stdint.h>
#define DEMCR (*(volatile uint32_t *)0xE000EDFC)
#define DWT_CTRL (*(volatile uint32_t *)0xE0001000)
#define DWT_CYCCNT (*(volatile uint32_t *)0xE0001004)
typedef uint32_t (*blk_fn)(uint32_t, uint32_t, uint32_t, uint32_t);
extern const uint32_t block_count, block_n;
extern const blk_fn block_table[];
int32_t mont_mul(int32_t a, int32_t b);
void pointwise(int32_t *c, const int32_t *a, const int32_t *b);

struct cls { uint32_t a, b, lo, hi; };
#define NC 26
const struct cls classes[NC] = {
  {0, 0, 0, 0},                          /* 0 both zero */
  {1, 1, 0, 0},                          /* 1 small */
  {0x7F, 0x7F, 0, 0},                    /* 2 */
  {0xFFFF, 0xFFFF, 0, 0},                /* 3 */
  {0x7FFFFFFF, 0x7FFFFFFF, 0, 0},        /* 4 large */
  {0x80000000, 0x80000000, 0, 0},        /* 5 */
  {0xFFFFFFFF, 0xFFFFFFFF, 0, 0},        /* 6 */
  {0x9E3779B9, 0x6A09E667, 0, 0},        /* 7 random */
  {0xC2B2AE35, 0x27D4EB2F, 0x85EBCA6B, 0x165667B1}, /* 8 random + random accumulator */
  {1, 0xFFFFFFFF, 0, 0},                 /* 9 mixed */
  {0xFFFFFFFF, 1, 0, 0},                 /* 10 */
  {0x7F, 0x80000000, 0, 0},              /* 11 */
  {0x80000000, 0x7F, 0, 0},              /* 12 */
  {0xFFFF, 0x7FFFFFFF, 0, 0},            /* 13 */
  {0x7FFFFFFF, 0xFFFF, 0, 0},            /* 14 */
  {0, 0xFFFFFFFF, 0, 0},                 /* 15 */
  {0xFFFFFFFF, 0, 0, 0},                 /* 16 */
  {0x007FE000, 0xFFC97E01, 0, 0},        /* 17 mldsa: coeff q-1 (8380416) x zeta -3572223 */
  {0x9E3779B9, 0xFF801FFF, 0, 0},        /* 18 mldsa: t (any int32) x -q */
  {0x00000001, 0xFF801FFF, 0, 0},        /* 19 mldsa: t=1 x -q */
  {0xFFF7E3A3, 0x003A0B5E, 0, 0},        /* 20 mldsa: small negative coeff x coeff */
  {0xFFFFF97F, 0x00000681, 0, 0},        /* 21 mlkem: -1665 x 1665 (int16 sign-extended) */
  {0x00000D00, 0xFFFFF2FF, 0, 0},        /* 22 mlkem: 3328 x -3329 */
  {0x00000D00, 0x00013AFB, 0, 0},        /* 23 mlkem compress_d10: coeff x 80635-ish constant */
  {0x00010000, 0x00010000, 0, 0},        /* 24 2^16 x 2^16 */
  {0xFFFF8000, 0x00007FFF, 0xFFFFFFFF, 0x7FFFFFFF}, /* 25 int16 extremes, accumulator near overflow */
};
#define R 8
#define MAXB 18
#define NM 8      /* montgomery input classes */
#define MPER 64   /* inputs per class */
volatile uint32_t status;
volatile uint32_t cpuid_seen, dwt_ctrl_seen, demcr_seen;
volatile uint32_t results[MAXB][NC][R];
volatile uint32_t mont_cyc[NM][MPER];
volatile int32_t mont_out[NM][MPER];
volatile uint32_t mont_empty[MPER];
volatile int32_t mont_a[NM * MPER], mont_b[NM * MPER];
#define NPW 5
volatile int32_t pw_a[256], pw_b[256], pw_c[256];
volatile uint32_t pw_cyc[NPW][4];

static uint32_t rng = 0x12345678;
static uint32_t xs(void) { rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5; return rng; }

__attribute__((noinline)) static int32_t empty_call(int32_t a, int32_t b) { __asm volatile("" ::: "memory"); return a ^ b; }

int main(void)
{
  status = 1;
  *(volatile uint32_t *)0xE000ED14 &= ~(1u << 4);   /* CCR.DIV_0_TRP off: the UDIV/SDIV control blocks divide by 0 in some classes */
  DEMCR |= 1u << 24;          /* TRCENA */
  DWT_CYCCNT = 0;
  DWT_CTRL |= 1u;             /* CYCCNTENA */
  demcr_seen = DEMCR; dwt_ctrl_seen = DWT_CTRL; cpuid_seen = *(volatile uint32_t *)0xE000ED00;
  { uint32_t c0 = DWT_CYCCNT; for (volatile int i = 0; i < 10; i++) ; if (DWT_CYCCNT == c0) { status = 0xDEAD0001; return 0; } }
  status = 2;
  for (uint32_t b = 0; b < block_count && b < MAXB; b++)
    for (uint32_t c = 0; c < NC; c++)
      for (uint32_t r = 0; r < R; r++)
        results[b][c][r] = block_table[b](classes[c].a, classes[c].b, classes[c].lo, classes[c].hi);
  status = 3;
  /* montgomery: inputs are generated first, then one timing loop (same code, same addresses) calls
     mont_mul(A[i], B[i]) for every input, in an interleaved order (class = i % NM) so position effects show.
     Classes: 0 zeros, 1 small, 2 +-(q-1), 3 random coeff x coeff, 4 random int24 x coeff, 5 near the 2^31*q bound,
     6 a = 0 with random b, 7 random int32 x random int32 (out of contract, stresses the multiplier) */
  const int32_t Q = 8380417;
  for (int i = 0; i < NM * MPER; i++) {
      int c = i % NM, k = i / NM;
      int32_t a, b;
      switch (c) {
        case 0: a = 0; b = 0; break;
        case 1: a = 1 + (k & 7); b = 1 + (k >> 3); break;
        case 2: a = (k & 1) ? Q - 1 : -(Q - 1); b = (k & 2) ? Q - 1 : -(Q - 1); break;
        case 3: a = (int32_t)(xs() % (2u * Q - 1)) - (Q - 1); b = (int32_t)(xs() % (2u * Q - 1)) - (Q - 1); break;
        case 4: a = (int32_t)xs() >> 8; b = (int32_t)(xs() % (2u * Q - 1)) - (Q - 1); break;
        case 5: a = (k & 1) ? 0x7FFFFFFF : (int32_t)0x80000001; b = (k & 2) ? Q - 1 : -(Q - 1); break;
        case 6: a = 0; b = (int32_t)xs(); break;
        default: a = (int32_t)xs(); b = (int32_t)xs(); break;
      }
      mont_a[i] = a; mont_b[i] = b;
  }
  for (int pass = 0; pass < 2; pass++)       /* pass 0 warms up; pass 1 is recorded */
    for (int i = 0; i < NM * MPER; i++) {
      int32_t a = mont_a[i], b = mont_b[i];
      __asm volatile("dsb\n isb" ::: "memory");
      uint32_t t0 = DWT_CYCCNT;
      int32_t o = mont_mul(a, b);
      uint32_t t1 = DWT_CYCCNT;
      mont_cyc[i % NM][i / NM] = t1 - t0; mont_out[i % NM][i / NM] = o;
    }
  for (int i = 0; i < MPER; i++) {
    int32_t a = mont_a[i], b = mont_b[i];
    __asm volatile("dsb\n isb" ::: "memory");
    uint32_t t0 = DWT_CYCCNT; int32_t o = empty_call(a, b); uint32_t t1 = DWT_CYCCNT;
    mont_empty[i] = t1 - t0; (void)o;
  }
  /* whole pointwise multiplication (256 coefficients), as mld_poly_pointwise_montgomery_c does it, per input poly
     class: 0 zeros, 1 all +-(q-1), 2 random coeffs, 3 small (|x| < 8), 4 random int32 x coeff */
  for (int c = 0; c < NPW; c++) {
    for (int i = 0; i < 256; i++) {
      switch (c) {
        case 0: pw_a[i] = 0; pw_b[i] = 0; break;
        case 1: pw_a[i] = (i & 1) ? Q - 1 : -(Q - 1); pw_b[i] = (i & 2) ? Q - 1 : -(Q - 1); break;
        case 2: pw_a[i] = (int32_t)(xs() % (2u * Q - 1)) - (Q - 1); pw_b[i] = (int32_t)(xs() % (2u * Q - 1)) - (Q - 1); break;
        case 3: pw_a[i] = (int32_t)(xs() % 15) - 7; pw_b[i] = (int32_t)(xs() % 15) - 7; break;
        default: pw_a[i] = (int32_t)xs(); pw_b[i] = (int32_t)(xs() % (2u * Q - 1)) - (Q - 1); break;
      }
    }
    for (int r = 0; r < 4; r++) {
      __asm volatile("dsb\n isb" ::: "memory");
      uint32_t t0 = DWT_CYCCNT;
      pointwise((int32_t *)pw_c, (const int32_t *)pw_a, (const int32_t *)pw_b);
      uint32_t t1 = DWT_CYCCNT;
      pw_cyc[c][r] = t1 - t0;
    }
  }
  status = 0x600D;
  return 0;
}

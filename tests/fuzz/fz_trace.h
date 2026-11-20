/* SPDX-License-Identifier: Apache-2.0
 *
 * With -DFZ_TRACE the harnesses print one line for every message they send to the code under test: what went in
 * and, as SHA3-256 hashes, every byte that came out. Two builds that print the same lines for the same input answer
 * byte for byte alike. tools/sdk_golden.py uses it to hold the SDK's core to the implementations it replaced: it
 * builds the harnesses of an older commit with this same file and compares.
 * Included after the code under test, whose sha3_256() it uses.
 */
#ifndef FZ_TRACE_H
#define FZ_TRACE_H
#if defined(FZ_TRACE)
#include <stdio.h>

static void fz_trace_hash(const void *p, size_t n)
{
	uint8_t h[32];

	sha3_256(p, n, h);
	for (int i = 0; i < 8; i++) printf("%02x", h[i]); /* 64 bits: enough to tell answers apart */
}

/* a PSA message: type, input and output sizes, status, the bytes written to each output */
__attribute__((unused)) static void fz_trace_msg(int type, size_t l0, size_t l1, size_t o0, size_t o1, int st, const uint8_t *w0, size_t n0,
			 const uint8_t *w1, size_t n1)
{
	printf("M %d in=%zu,%zu out=%zu,%zu st=%d w=%zu,%zu ", type, l0, l1, o0, o1, st, n0, n1);
	fz_trace_hash(w0, n0);
	putchar(' ');
	fz_trace_hash(w1, n1);
	putchar('\n');
}

/* a request line and its reply */
__attribute__((unused)) static void fz_trace_line(const uint8_t *req, size_t n, const char *reply, int r)
{
	printf("L %zu ", n);
	fz_trace_hash(req, n);
	printf(" %d %.24s ", r, r > 0 ? reply : "");
	fz_trace_hash(reply, r > 0 ? (size_t)r : 0);
	putchar('\n');
}

/* an operation of the core called directly: its name, result and what it gave back */
__attribute__((unused)) static void fz_trace_op(const char *name, int rc, const void *a, size_t an, const void *b, size_t bn)
{
	printf("O %s rc=%d w=%zu,%zu ", name, rc, an, bn);
	fz_trace_hash(a, an);
	putchar(' ');
	fz_trace_hash(b, bn);
	putchar('\n');
}
#endif
#endif

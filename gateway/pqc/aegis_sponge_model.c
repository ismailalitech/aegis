/* SPDX-License-Identifier: Apache-2.0
 * C model of the aegis_pqc2 sponge registers, for testing the driver on a PC. Same behaviour as hw/rtl/aegis_sponge.v
 * at the register level (no timing: the engine is never busy). Checked equal to the RTL by replaying the RTL test script
 * (tools/accel/replay_model.c with hw/tb/vectors/sponge_ops.txt). The NTT registers are not modelled. */
#include <stdlib.h>
#include <string.h>
#include "aegis_sponge_hw.h"

struct aegis_sponge_model {
	uint64_t st[25], slot[SP_SLOTS][25];
	unsigned cur, xor_mode, rate, nblk, err, done_blk;
	uint64_t addr;
	uint32_t perms;
	int (*mem_write)(void *, uint64_t, uint64_t);
	void *ctx;
	void (*perm)(uint64_t a[25]);
};

static const uint64_t RC[24] = {
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL, 0x8000000080008000ULL,
	0x000000000000808BULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
	0x000000000000008AULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
	0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
	0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800AULL, 0x800000008000000AULL,
	0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
static const unsigned ROT[25] = {0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14};

static uint64_t rol(uint64_t v, unsigned n) { return n ? (v << n) | (v >> (64 - n)) : v; }

static void keccak_f(uint64_t a[25])
{
	uint64_t b[25], c[5], d;
	for (int r = 0; r < 24; r++) {
		for (int x = 0; x < 5; x++) c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
		for (int x = 0; x < 5; x++) {
			d = c[(x + 4) % 5] ^ rol(c[(x + 1) % 5], 1);
			for (int y = 0; y < 25; y += 5) a[y + x] ^= d;
		}
		for (int x = 0; x < 5; x++)
			for (int y = 0; y < 5; y++) b[y + 5 * ((2 * x + 3 * y) % 5)] = rol(a[x + 5 * y], ROT[x + 5 * y]);
		for (int y = 0; y < 25; y += 5)
			for (int x = 0; x < 5; x++) a[y + x] = b[y + x] ^ (~b[y + (x + 1) % 5] & b[y + (x + 2) % 5]);
		a[0] ^= RC[r];
	}
}

struct aegis_sponge_model *aegis_sponge_model_new(int (*mem_write)(void *, uint64_t, uint64_t), void *ctx)
{
	struct aegis_sponge_model *m = calloc(1, sizeof(*m));
	if (m) {
		m->mem_write = mem_write;
		m->ctx = ctx;
	}
	return m;
}

void aegis_sponge_model_free(struct aegis_sponge_model *m) { free(m); }

void aegis_sponge_model_set_permute(struct aegis_sponge_model *m, void (*f)(uint64_t a[25])) { m->perm = f; }

static void permute(struct aegis_sponge_model *m)
{
	if (m->perm) m->perm(m->st);
	else keccak_f(m->st);
	m->perms++;
}

static void squeeze(struct aegis_sponge_model *m)
{
	m->done_blk = 0;
	if ((m->addr & 7) || m->rate == 0 || m->rate > 21 || m->nblk == 0 ||
	    (m->addr & 0xFFF) + (uint64_t)m->nblk * m->rate * 8 > 4096) {
		m->err = 1;
		return;
	}
	m->err = 0;
	uint64_t a = m->addr;
	for (unsigned k = 0; k < m->nblk; k++) {
		permute(m);
		int bad = 0;
		for (unsigned i = 0; i < m->rate; i++) bad |= m->mem_write(m->ctx, a + 8 * i, m->st[i]);
		if (bad) {
			m->err = 1;
			return;
		}
		m->done_blk++;
		a += m->rate * 8;
	}
}

void aegis_sponge_model_wr(void *mv, uint32_t off, uint32_t v)
{
	struct aegis_sponge_model *m = mv;
	if (off == SP_SCFG) {
		m->xor_mode = v & 1;
		m->rate = (v >> 8) & 0x1F;
		m->nblk = (v >> 16) & 0xFF;
	} else if (off == SP_DMALO) {
		m->addr = (m->addr & ~0xFFFFFFFFULL) | v;
	} else if (off == SP_DMAHI) {
		m->addr = (m->addr & 0xFFFFFFFFULL) | ((uint64_t)(v & 0x3F) << 32);
	} else if (off == SP_CTRL) {
		if (v & 1) permute(m);
	} else if (off == SP_SCMD) {
		unsigned c = v & 7, s = (v >> 4) & 7;
		if (c == SP_CMD_PERMUTE) permute(m);
		else if (c == SP_CMD_CLEAR) memset(m->st, 0, sizeof(m->st));
		else if (c == SP_CMD_SELECT && s != m->cur) {
			memcpy(m->slot[m->cur], m->st, sizeof(m->st));
			memcpy(m->st, m->slot[s], sizeof(m->st));
			m->cur = s;
		} else if (c == SP_CMD_SQUEEZE) squeeze(m);
	} else if (off >= SP_LANE && off < SP_LANE + 200 && !(off & 3)) {
		unsigned w = (off - SP_LANE) / 4, sh = 32 * (w & 1);
		uint64_t mask = 0xFFFFFFFFULL << sh, nv = (uint64_t)v << sh;
		m->st[w / 2] = m->xor_mode ? (m->st[w / 2] ^ nv) : ((m->st[w / 2] & ~mask) | nv);
	}
}

uint32_t aegis_sponge_model_rd(void *mv, uint32_t off)
{
	struct aegis_sponge_model *m = mv;
	if (off == SP_ID) return SP_ID_V2;
	if (off == SP_STATUS) return (m->done_blk << 24) | (m->cur << 18) | (m->err << 17) | (1u << 4);
	if (off == SP_KCOUNT) return m->perms;
	if (off == SP_SCFG) return (m->nblk << 16) | (m->rate << 8) | m->xor_mode;
	if (off == SP_DMALO) return (uint32_t)m->addr;
	if (off == SP_DMAHI) return (uint32_t)(m->addr >> 32);
	if (off >= SP_LANE && off < SP_LANE + 200 && !(off & 3)) {
		unsigned w = (off - SP_LANE) / 4;
		return (uint32_t)(m->st[w / 2] >> (32 * (w & 1)));
	}
	return 0;
}

/* SPDX-License-Identifier: Apache-2.0
 *
 * liboqs SHA-3 provider backed by the aegis_pqc2 sponge (hw/rtl/aegis_sponge.v): the Keccak state of each incremental
 * SHA-3/SHAKE context lives in one of the core's 8 slots, so only the bytes absorbed or squeezed cross the bus. Full
 * squeezed blocks come back by DMA into a non-cached buffer when one is available, partial ones over APB.
 *
 * Installed from a library constructor, so liboqs' own programs use it unchanged. Environment:
 *   AEGIS_PQC_SPONGE=hw      the core on the board (pfdaq UIO device; DMA buffer from u-dma-buf, see below)
 *   AEGIS_PQC_SPONGE=model   the C register model (aegis_sponge_model.c), for testing on a PC
 *   (unset)                  liboqs' own SHA-3, nothing installed
 *   AEGIS_PQC_DMABUF=<name>  u-dma-buf device for squeeze by DMA (default udmabuf-aegis); absent = APB only
 *   AEGIS_PQC_NODMA=1        do not use DMA even if a buffer exists
 *   AEGIS_PQC_STATS=1        print bus access counts at exit
 *   AEGIS_PQC_SLOTS=<1..8>   use only that many slots (tests the spill path)
 *   AEGIS_PQC_MODEL_PERM=liboqs  the model permutes with liboqs' own Keccak (so that model minus plain liboqs = the
 *                            driver's own CPU time plus the model's emulation, when timing on the board)
 *   AEGIS_PQC_MODEL_BENCH=1  print the model's emulation cost per register write, read and DMA beat (same build)
 *
 * Contexts above 8 are spilled: the least recently used one is read out (50 words) and written back when needed.
 * Single-threaded, like the liboqs programs it serves.
 */
#include <dirent.h>
#include <time.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <oqs/oqs.h>
#include <oqs/sha3_ops.h>
#include <oqs/sha3x4_ops.h>

#include "aegis_sponge_hw.h"

/* ------------------------------------------------------------------ bus access with counters */
static struct aegis_sponge_io io;
static struct {
	unsigned long rd, wr, polls, selects, spills, refills, dma_cmds, dma_bytes, apb_blocks, contexts;
} stat;

static inline uint32_t rd(uint32_t off)
{
	stat.rd++;
	return io.rd(io.priv, off);
}
static inline void wr(uint32_t off, uint32_t v)
{
	stat.wr++;
	io.wr(io.priv, off, v);
}

/* shadows of write-only state in the core, to skip redundant writes */
static unsigned hw_slot;              /* 0 after reset */
static uint32_t hw_scfg = 0xFFFFFFFFu; /* unknown */
static uint64_t hw_dma = ~0ULL;

static void scfg(uint32_t v)
{
	if (v != hw_scfg) {
		wr(SP_SCFG, v);
		hw_scfg = v;
	}
}

static void select_slot(unsigned s)
{
	if (s != hw_slot) {
		wr(SP_SCMD, SP_CMD_SELECT | (s << 4));
		hw_slot = s;
		stat.selects++;
	}
}

/* ------------------------------------------------------------------ contexts and slots */
struct sp {
	int slot;          /* -1: not in the core */
	int fresh;         /* state is all zero (not yet in the core, nothing saved) */
	int squeezing;
	unsigned rate;     /* bytes */
	unsigned pos;      /* absorbing: bytes in the current block; squeezing: bytes used of the current block */
	uint8_t pad;       /* 0x1F SHAKE, 0x06 SHA3 */
	unsigned long lru;
	uint64_t saved[25];
};

static struct sp *owner[SP_SLOTS];
static unsigned long tick;
static int n_slots = SP_SLOTS;

static void spill(struct sp *c)
{
	select_slot((unsigned)c->slot);
	for (unsigned w = 0; w < 50; w++) {
		uint32_t v = rd(SP_LANE + 4 * w);
		if (w & 1) c->saved[w / 2] |= (uint64_t)v << 32;
		else c->saved[w / 2] = v;
	}
	owner[c->slot] = NULL;
	c->slot = -1;
	c->fresh = 0;
	stat.spills++;
}

/* make c the working state of the core */
static void bind(struct sp *c)
{
	c->lru = ++tick;
	if (c->slot >= 0) {
		select_slot((unsigned)c->slot);
		return;
	}
	int s = -1;
	for (int i = 0; i < n_slots; i++)
		if (!owner[i] && (s < 0 || (unsigned)i == hw_slot)) s = i;   /* prefer the current slot: no switch */
	if (s < 0) {
		struct sp *v = NULL;
		for (int i = 0; i < n_slots; i++)
			if (!v || owner[i]->lru < v->lru) v = owner[i];
		s = v->slot;
		spill(v);
	}
	select_slot((unsigned)s);
	owner[s] = c;
	c->slot = s;
	wr(SP_SCMD, SP_CMD_CLEAR);
	if (!c->fresh) {
		scfg(1);     /* XOR into the cleared state = load it */
		for (unsigned w = 0; w < 50; w++) {
			uint32_t v = (uint32_t)(c->saved[w / 2] >> (32 * (w & 1)));
			if (v) wr(SP_LANE + 4 * w, v);
		}
		stat.refills++;
	}
	c->fresh = 0;
}

static struct sp *sp_new(unsigned rate, uint8_t pad)
{
	struct sp *c = calloc(1, sizeof(*c));
	if (!c) {
		fprintf(stderr, "aegis_sponge: out of memory\n");
		abort();
	}
	c->slot = -1;
	c->fresh = 1;
	c->rate = rate;
	c->pad = pad;
	stat.contexts++;
	return c;
}

static void sp_free(struct sp *c)
{
	if (!c) return;
	if (c->slot >= 0) owner[c->slot] = NULL;
	free(c);
}

static void sp_reset(struct sp *c)
{
	c->squeezing = 0;
	c->pos = 0;
	if (c->slot >= 0) {
		select_slot((unsigned)c->slot);
		wr(SP_SCMD, SP_CMD_CLEAR);
	} else {
		c->fresh = 1;
	}
}

static void sp_clone(struct sp *d, const struct sp *s)
{
	if (d->slot >= 0) {
		owner[d->slot] = NULL;
		d->slot = -1;
	}
	d->rate = s->rate;
	d->pad = s->pad;
	d->pos = s->pos;
	d->squeezing = s->squeezing;
	d->fresh = s->fresh;
	if (s->slot >= 0) {
		select_slot((unsigned)s->slot);
		for (unsigned w = 0; w < 50; w++) {
			uint32_t v = rd(SP_LANE + 4 * w);
			if (w & 1) d->saved[w / 2] |= (uint64_t)v << 32;
			else d->saved[w / 2] = v;
		}
		d->fresh = 0;
	} else {
		memcpy(d->saved, s->saved, sizeof(d->saved));
	}
}

/* XOR len bytes at byte offset pos of the state (pos + len <= rate) */
static void xor_bytes(unsigned pos, const uint8_t *p, size_t len)
{
	scfg(1);
	/* whole words: one 32-bit little-endian load each (the U54 and x86 are little-endian) */
	if (!(pos & 3)) {
		while (len >= 4) {
			uint32_t v;
			memcpy(&v, p, 4);
			if (v) wr(SP_LANE + pos, v);
			pos += 4;
			p += 4;
			len -= 4;
		}
	}
	while (len) {
		unsigned w = pos / 4, b = pos % 4, n = 4 - b;
		if (n > len) n = (unsigned)len;
		uint32_t v = 0;
		for (unsigned i = 0; i < n; i++) v |= (uint32_t)p[i] << (8 * (b + i));
		if (v) wr(SP_LANE + 4 * w, v);
		pos += n;
		p += n;
		len -= n;
	}
}

static void sp_absorb(struct sp *c, const uint8_t *in, size_t len)
{
	bind(c);
	while (len) {
		size_t n = c->rate - c->pos;
		if (n > len) n = len;
		xor_bytes(c->pos, in, n);
		c->pos += (unsigned)n;
		in += n;
		len -= n;
		if (c->pos == c->rate) {
			wr(SP_SCMD, SP_CMD_PERMUTE);
			c->pos = 0;
		}
	}
}

static void sp_finalize(struct sp *c)
{
	uint8_t a = c->pad, b = 0x80;
	bind(c);
	xor_bytes(c->pos, &a, 1);
	xor_bytes(c->rate - 1, &b, 1);
	c->squeezing = 1;
	c->pos = c->rate;
}

static void read_bytes(unsigned pos, uint8_t *out, size_t len)
{
	if (!(pos & 3)) {
		while (len >= 4) {
			uint32_t v = rd(SP_LANE + pos);
			memcpy(out, &v, 4);
			pos += 4;
			out += 4;
			len -= 4;
		}
	}
	while (len) {
		unsigned w = pos / 4, b = pos % 4, n = 4 - b;
		if (n > len) n = (unsigned)len;
		uint32_t v = rd(SP_LANE + 4 * w);
		for (unsigned i = 0; i < n; i++) out[i] = (uint8_t)(v >> (8 * (b + i)));
		pos += n;
		out += n;
		len -= n;
	}
}

static int use_dma;

static void dma_blocks(struct sp *c, uint8_t *out, unsigned k)
{
	if (hw_dma != io.dma_pa) {
		wr(SP_DMALO, (uint32_t)io.dma_pa);
		wr(SP_DMAHI, (uint32_t)(io.dma_pa >> 32));
		hw_dma = io.dma_pa;
	}
	scfg(1u | ((c->rate / 8) << 8) | (k << 16));
	wr(SP_SCMD, SP_CMD_SQUEEZE);
	/* copy each block as soon as the core reports it written (its write response has come back), while the core
	 * computes the next one; non-cached buffer, 64-bit loads */
	const volatile uint64_t *src = (const volatile uint64_t *)io.dma_va;
	unsigned lanes = c->rate / 8, copied = 0;
	while (copied < k) {
		uint32_t st = rd(SP_STATUS);
		unsigned done = st >> 24;
		stat.polls++;
		if (st & SP_ST_DMA_ERR) {
			fprintf(stderr, "aegis_sponge: DMA error (status 0x%08x)\n", st);
			abort();
		}
		if (!(st & SP_ST_DMA_BUSY) && done < k) {
			fprintf(stderr, "aegis_sponge: DMA stopped after %u of %u blocks\n", done, k);
			abort();
		}
		for (; copied < done; copied++)
			for (unsigned i = 0; i < lanes; i++) {
				uint64_t v = src[copied * lanes + i];
				memcpy(out + 8 * (copied * lanes + i), &v, 8);
			}
	}
	stat.dma_cmds++;
	stat.dma_bytes += (unsigned long)k * c->rate;
}

static void sp_squeeze(struct sp *c, uint8_t *out, size_t len)
{
	bind(c);
	while (len) {
		if (c->pos == c->rate) {
			size_t full = len / c->rate;
			if (use_dma && full) {
				unsigned maxk = (unsigned)(io.dma_len / c->rate);
				unsigned k = full < maxk ? (unsigned)full : maxk;
				if (k > 255) k = 255;
				dma_blocks(c, out, k);
				out += (size_t)k * c->rate;
				len -= (size_t)k * c->rate;
				continue;              /* pos stays rate: the last block was used whole */
			}
			wr(SP_SCMD, SP_CMD_PERMUTE);
			c->pos = 0;
			stat.apb_blocks++;
		}
		size_t n = c->rate - c->pos;
		if (n > len) n = len;
		read_bytes(c->pos, out, n);
		c->pos += (unsigned)n;
		out += n;
		len -= n;
	}
}

/* ------------------------------------------------------------------ liboqs callbacks */
#define CTX(s) ((struct sp *)(s)->ctx)

#define ONE_WAY(name, rate, pad)                                                                         \
	static void name##_inc_init(OQS_SHA3_##name##_inc_ctx *s) { s->ctx = sp_new(rate, pad); }        \
	static void name##_inc_absorb(OQS_SHA3_##name##_inc_ctx *s, const uint8_t *in, size_t n)       \
	{                                                                                                \
		sp_absorb(CTX(s), in, n);                                                                \
	}                                                                                                \
	static void name##_inc_ctx_release(OQS_SHA3_##name##_inc_ctx *s)                               \
	{                                                                                                \
		sp_free(CTX(s));                                                                         \
		s->ctx = NULL;                                                                           \
	}                                                                                                \
	static void name##_inc_ctx_reset(OQS_SHA3_##name##_inc_ctx *s) { sp_reset(CTX(s)); }             \
	static void name##_inc_ctx_clone(OQS_SHA3_##name##_inc_ctx *d, const OQS_SHA3_##name##_inc_ctx *s) \
	{                                                                                                \
		sp_clone(CTX(d), CTX(s));                                                                \
	}

ONE_WAY(sha3_256, 136, 0x06)
ONE_WAY(sha3_384, 104, 0x06)
ONE_WAY(sha3_512, 72, 0x06)
ONE_WAY(shake128, 168, 0x1F)
ONE_WAY(shake256, 136, 0x1F)

#define SHA3_FIXED(name, outlen)                                                                       \
	static void name##_inc_finalize(uint8_t *out, OQS_SHA3_##name##_inc_ctx *s)                     \
	{                                                                                                \
		sp_finalize(CTX(s));                                                                     \
		sp_squeeze(CTX(s), out, outlen);                                                         \
	}                                                                                                \
	static void name(uint8_t *out, const uint8_t *in, size_t n)                                     \
	{                                                                                                \
		OQS_SHA3_##name##_inc_ctx s;                                                             \
		name##_inc_init(&s);                                                                     \
		name##_inc_absorb(&s, in, n);                                                            \
		name##_inc_finalize(out, &s);                                                            \
		name##_inc_ctx_release(&s);                                                              \
	}

SHA3_FIXED(sha3_256, 32)
SHA3_FIXED(sha3_384, 48)
SHA3_FIXED(sha3_512, 64)

#define SHAKE(name)                                                                                     \
	static void name##_inc_finalize(OQS_SHA3_##name##_inc_ctx *s) { sp_finalize(CTX(s)); }          \
	static void name##_inc_squeeze(uint8_t *out, size_t n, OQS_SHA3_##name##_inc_ctx *s)            \
	{                                                                                                \
		sp_squeeze(CTX(s), out, n);                                                              \
	}                                                                                                \
	static void name(uint8_t *out, size_t outlen, const uint8_t *in, size_t n)                      \
	{                                                                                                \
		OQS_SHA3_##name##_inc_ctx s;                                                             \
		name##_inc_init(&s);                                                                     \
		name##_inc_absorb(&s, in, n);                                                            \
		name##_inc_finalize(&s);                                                                 \
		name##_inc_squeeze(out, outlen, &s);                                                     \
		name##_inc_ctx_release(&s);                                                              \
	}

SHAKE(shake128)
SHAKE(shake256)

/* four-way: four independent contexts */
struct x4 {
	struct sp *l[4];
};
#define X4(name, rate)                                                                                  \
	static void name##_x4_inc_init(OQS_SHA3_##name##_x4_inc_ctx *s)                                  \
	{                                                                                                \
		struct x4 *x = calloc(1, sizeof(*x));                                                    \
		if (!x) abort();                                                                         \
		for (int i = 0; i < 4; i++) x->l[i] = sp_new(rate, 0x1F);                                \
		s->ctx = x;                                                                              \
	}                                                                                                \
	static void name##_x4_inc_absorb(OQS_SHA3_##name##_x4_inc_ctx *s, const uint8_t *i0,            \
					 const uint8_t *i1, const uint8_t *i2, const uint8_t *i3, size_t n) \
	{                                                                                                \
		struct x4 *x = s->ctx;                                                                   \
		const uint8_t *in[4] = {i0, i1, i2, i3};                                                 \
		for (int i = 0; i < 4; i++) sp_absorb(x->l[i], in[i], n);                                \
	}                                                                                                \
	static void name##_x4_inc_finalize(OQS_SHA3_##name##_x4_inc_ctx *s)                              \
	{                                                                                                \
		struct x4 *x = s->ctx;                                                                   \
		for (int i = 0; i < 4; i++) sp_finalize(x->l[i]);                                        \
	}                                                                                                \
	static void name##_x4_inc_squeeze(uint8_t *o0, uint8_t *o1, uint8_t *o2, uint8_t *o3, size_t n, \
					  OQS_SHA3_##name##_x4_inc_ctx *s)                               \
	{                                                                                                \
		struct x4 *x = s->ctx;                                                                   \
		uint8_t *out[4] = {o0, o1, o2, o3};                                                      \
		for (int i = 0; i < 4; i++) sp_squeeze(x->l[i], out[i], n);                              \
	}                                                                                                \
	static void name##_x4_inc_ctx_release(OQS_SHA3_##name##_x4_inc_ctx *s)                          \
	{                                                                                                \
		struct x4 *x = s->ctx;                                                                   \
		if (!x) return;                                                                          \
		for (int i = 0; i < 4; i++) sp_free(x->l[i]);                                            \
		free(x);                                                                                 \
		s->ctx = NULL;                                                                           \
	}                                                                                                \
	static void name##_x4_inc_ctx_clone(OQS_SHA3_##name##_x4_inc_ctx *d,                             \
					    const OQS_SHA3_##name##_x4_inc_ctx *s)                       \
	{                                                                                                \
		struct x4 *a = d->ctx, *b = s->ctx;                                                      \
		for (int i = 0; i < 4; i++) sp_clone(a->l[i], b->l[i]);                                  \
	}                                                                                                \
	static void name##_x4_inc_ctx_reset(OQS_SHA3_##name##_x4_inc_ctx *s)                             \
	{                                                                                                \
		struct x4 *x = s->ctx;                                                                   \
		for (int i = 0; i < 4; i++) sp_reset(x->l[i]);                                           \
	}                                                                                                \
	static void name##_x4(uint8_t *o0, uint8_t *o1, uint8_t *o2, uint8_t *o3, size_t outlen,        \
			      const uint8_t *i0, const uint8_t *i1, const uint8_t *i2, const uint8_t *i3,     \
			      size_t n)                                                                  \
	{                                                                                                \
		OQS_SHA3_##name##_x4_inc_ctx s;                                                          \
		name##_x4_inc_init(&s);                                                                  \
		name##_x4_inc_absorb(&s, i0, i1, i2, i3, n);                                             \
		name##_x4_inc_finalize(&s);                                                              \
		name##_x4_inc_squeeze(o0, o1, o2, o3, outlen, &s);                                       \
		name##_x4_inc_ctx_release(&s);                                                           \
	}

X4(shake128, 168)
X4(shake256, 136)

#define F1(n) .SHA3_##n = n, .SHA3_##n##_inc_init = n##_inc_init, .SHA3_##n##_inc_absorb = n##_inc_absorb, \
	.SHA3_##n##_inc_finalize = n##_inc_finalize, .SHA3_##n##_inc_ctx_release = n##_inc_ctx_release,   \
	.SHA3_##n##_inc_ctx_reset = n##_inc_ctx_reset, .SHA3_##n##_inc_ctx_clone = n##_inc_ctx_clone
#define FS(n) F1(n), .SHA3_##n##_inc_squeeze = n##_inc_squeeze

static struct OQS_SHA3_callbacks cb1 = {F1(sha3_256), F1(sha3_384), F1(sha3_512), FS(shake128), FS(shake256)};

#define FX(n) .SHA3_##n##_x4 = n##_x4, .SHA3_##n##_x4_inc_init = n##_x4_inc_init,                         \
	.SHA3_##n##_x4_inc_absorb = n##_x4_inc_absorb, .SHA3_##n##_x4_inc_finalize = n##_x4_inc_finalize,  \
	.SHA3_##n##_x4_inc_squeeze = n##_x4_inc_squeeze, .SHA3_##n##_x4_inc_ctx_release = n##_x4_inc_ctx_release, \
	.SHA3_##n##_x4_inc_ctx_clone = n##_x4_inc_ctx_clone, .SHA3_##n##_x4_inc_ctx_reset = n##_x4_inc_ctx_reset

static struct OQS_SHA3_x4_callbacks cb4 = {FX(shake128), FX(shake256)};

/* ------------------------------------------------------------------ back ends */
static int model_mem_write(void *ctx, uint64_t pa, uint64_t v)
{
	(void)ctx;
	if (pa < io.dma_pa || pa + 8 > io.dma_pa + io.dma_len) return 1;
	memcpy((uint8_t *)io.dma_va + (pa - io.dma_pa), &v, 8);
	return 0;
}

/* liboqs' plain-64bits permutation works on lane-complemented states (lanes 1, 2, 8, 12, 17, 20) */
void KeccakP1600_Permute_24rounds(void *state);
static void liboqs_perm(uint64_t a[25])
{
	static const uint8_t cl[6] = {1, 2, 8, 12, 17, 20};
	for (int i = 0; i < 6; i++) a[cl[i]] = ~a[cl[i]];
	KeccakP1600_Permute_24rounds(a);
	for (int i = 0; i < 6; i++) a[cl[i]] = ~a[cl[i]];
}

static int open_model(void)
{
	static uint64_t buf[512] __attribute__((aligned(4096)));
	io.priv = aegis_sponge_model_new(model_mem_write, NULL);
	io.rd = aegis_sponge_model_rd;
	io.wr = aegis_sponge_model_wr;
	io.dma_va = (volatile uint8_t *)buf;
	io.dma_pa = 0x1400800000ULL;        /* any address: the model maps it to buf */
	io.dma_len = sizeof(buf);
	if (io.priv && getenv("AEGIS_PQC_MODEL_BENCH")) {
		struct timespec a, b;
		const int n = 200000;
		double t[3];
		volatile uint32_t sink = 0;
		for (int k = 0; k < 3; k++) {
			clock_gettime(CLOCK_MONOTONIC, &a);
			for (int i = 0; i < n; i++) {
				if (k == 0) io.wr(io.priv, SP_LANE + 4 * (i % 34), (uint32_t)i);
				else if (k == 1) sink += io.rd(io.priv, SP_LANE + 4 * (i % 34));
				else model_mem_write(NULL, io.dma_pa + 8 * (i % 512), (uint64_t)i);
			}
			clock_gettime(CLOCK_MONOTONIC, &b);
			t[k] = ((b.tv_sec - a.tv_sec) * 1e9 + (b.tv_nsec - a.tv_nsec)) / n;
		}
		fprintf(stderr, "aegis_sponge model emulation: write %.1f ns, read %.1f ns, DMA beat %.1f ns\n", t[0], t[1], t[2]);
		(void)sink;
	}
	if (io.priv && getenv("AEGIS_PQC_MODEL_PERM") && strcmp(getenv("AEGIS_PQC_MODEL_PERM"), "liboqs") == 0)
		aegis_sponge_model_set_permute(io.priv, liboqs_perm);
	return io.priv ? 0 : -1;
}

static uint32_t mmio_rd(void *p, uint32_t off) { return ((volatile uint32_t *)p)[off / 4]; }
static void mmio_wr(void *p, uint32_t off, uint32_t v) { ((volatile uint32_t *)p)[off / 4] = v; }

static int find_uio(char *path, size_t n)
{
	DIR *d = opendir("/sys/class/uio");
	struct dirent *e;
	int found = -1;
	if (!d) return -1;
	while (found && (e = readdir(d)) != NULL) {
		char p[288], name[64] = {0};
		FILE *f;
		if (strncmp(e->d_name, "uio", 3) != 0) continue;
		snprintf(p, sizeof(p), "/sys/class/uio/%s/name", e->d_name);
		if (!(f = fopen(p, "r"))) continue;
		if (fgets(name, sizeof(name), f) && strncmp(name, "pfdaq_stream_src", 16) == 0) {
			snprintf(path, n, "/dev/%s", e->d_name);
			found = 0;
		}
		fclose(f);
	}
	closedir(d);
	return found;
}

static int open_hw(void)
{
	char dev[300];
	int fd;
	void *m;
	if (find_uio(dev, sizeof(dev)) != 0 || (fd = open(dev, O_RDWR | O_SYNC)) < 0) return -1;
	m = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if (m == MAP_FAILED) return -1;
	io.priv = (uint8_t *)m + 0xE00;
	io.rd = mmio_rd;
	io.wr = mmio_wr;
	if (io.rd(io.priv, SP_ID) != SP_ID_V2) {
		fprintf(stderr, "aegis_sponge: core ID 0x%08x, need 0x%08x (fabric with aegis_pqc2)\n",
			io.rd(io.priv, SP_ID), SP_ID_V2);
		return -2;
	}
	/* optional DMA buffer: u-dma-buf, opened with O_SYNC for a non-cached mapping */
	const char *name = getenv("AEGIS_PQC_DMABUF") ? getenv("AEGIS_PQC_DMABUF") : "udmabuf-aegis";
	char p[256];
	unsigned long long pa = 0;
	FILE *f;
	snprintf(p, sizeof(p), "/sys/class/u-dma-buf/%s/phys_addr", name);
	if ((f = fopen(p, "r")) != NULL) {
		if (fscanf(f, "%llx", &pa) != 1) pa = 0;
		fclose(f);
	}
	snprintf(p, sizeof(p), "/dev/%s", name);
	if (pa && (pa & 0xFFF) == 0 && (fd = open(p, O_RDWR | O_SYNC)) >= 0) {
		m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		close(fd);
		if (m != MAP_FAILED) {
			io.dma_va = m;
			io.dma_pa = pa;
			io.dma_len = 4096;
		}
	}
	return 0;
}

static void print_stats(void)
{
	fprintf(stderr,
		"aegis_sponge: reads=%lu writes=%lu polls=%lu selects=%lu spills=%lu refills=%lu dma_cmds=%lu "
		"dma_bytes=%lu apb_blocks=%lu permutations=%u contexts=%lu\n",
		stat.rd, stat.wr, stat.polls, stat.selects, stat.spills, stat.refills, stat.dma_cmds, stat.dma_bytes,
		stat.apb_blocks, io.rd(io.priv, SP_KCOUNT), stat.contexts);
}

/* referenced from liboqs' sha3.c by tools/build_liboqs_sponge.sh so that static links take this file (and its
 * constructor) along; not exported, so a static link cannot resolve it from the shared library instead */
void aegis_sponge_anchor(void);
void aegis_sponge_anchor(void) {}

/* counters for programs that measure one operation at a time (tools/accel/count_main.c) */
__attribute__((visibility("default"))) void aegis_sponge_counts(unsigned long c[8])
{
	c[0] = stat.rd; c[1] = stat.wr; c[2] = stat.polls; c[3] = stat.dma_cmds;
	c[4] = stat.dma_bytes; c[5] = stat.selects; c[6] = stat.spills; c[7] = io.priv ? io.rd(io.priv, SP_KCOUNT) : 0;
}

extern struct OQS_SHA3_callbacks sha3_default_callbacks;
extern struct OQS_SHA3_x4_callbacks sha3_x4_default_callbacks;

__attribute__((constructor)) static void aegis_sponge_install(void)
{
	const char *e = getenv("AEGIS_PQC_SPONGE");
	int r;
	if (!e) return;
	if (strcmp(e, "model") == 0) r = open_model();
	else if (strcmp(e, "hw") == 0) r = open_hw();
	else return;
	if (r != 0) {
		fprintf(stderr, "aegis_sponge: AEGIS_PQC_SPONGE=%s but the core is not usable (%d)\n", e, r);
		exit(3);
	}
	use_dma = io.dma_len >= 4096 && !getenv("AEGIS_PQC_NODMA");
	if (getenv("AEGIS_PQC_SLOTS")) {
		n_slots = atoi(getenv("AEGIS_PQC_SLOTS"));
		if (n_slots < 1 || n_slots > SP_SLOTS) n_slots = SP_SLOTS;
	}
	/* replace liboqs' default tables too: programs that start from them (test_sha3 does) then use this provider */
	sha3_default_callbacks = cb1;
	sha3_x4_default_callbacks = cb4;
	OQS_SHA3_set_callbacks(&cb1);
	OQS_SHA3_x4_set_callbacks(&cb4);
	if (getenv("AEGIS_PQC_STATS")) atexit(print_stats);
}

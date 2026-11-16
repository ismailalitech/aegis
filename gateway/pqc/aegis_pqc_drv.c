/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * User-space driver for the aegis_pqc fabric core (FIC3 APB slot 14, 0x40000E00) on the
 * PolarFire SoC Discovery Kit.
 *
 * Access path: the pfdaq UIO device (name "pfdaq_stream_src") maps the whole 4 KiB page
 * 0x40000000-0x40000FFF; the core sits at offset 0xE00 of that page. The kernel's
 * IO_STRICT_DEVMEM blocks /dev/mem for that page because drivers own parts of it, so UIO is
 * the only route that needs no kernel or device-tree change.
 *
 * Environment for the liboqs hook (aegis_pqc_keccak_hook):
 *   AEGIS_PQC_KECCAK=hw     every Keccak-f[1600] permutation runs in the fabric
 *   AEGIS_PQC_KECCAK=check  run both fabric and software, abort on any difference
 *   (unset)                 software only
 *   AEGIS_PQC_STATS=1       print counters at exit
 */
#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "aegis_pqc_drv.h"

#define PAGE_OFFSET_IN_UIO 0xE00u
#define R_ID      (0x00 / 4)
#define R_CTRL    (0x04 / 4)
#define R_STATUS  (0x08 / 4)
#define R_KCYC    (0x0C / 4)
#define R_NCYC    (0x10 / 4)
#define R_NIDX    (0x14 / 4)
#define R_NDATA   (0x18 / 4)
#define R_LANES   (0x40 / 4)

static volatile uint32_t *regs;
static unsigned long n_hw, n_checked, n_sw;

static int find_uio(char *path, size_t n)
{
	DIR *d = opendir("/sys/class/uio");
	struct dirent *e;
	int found = -1;

	if (!d) {
		return -1;
	}
	while ((e = readdir(d)) != NULL) {
		char p[288], name[64] = {0};
		FILE *f;

		if (strncmp(e->d_name, "uio", 3) != 0) {
			continue;
		}
		snprintf(p, sizeof(p), "/sys/class/uio/%s/name", e->d_name);
		f = fopen(p, "r");
		if (!f) {
			continue;
		}
		if (fgets(name, sizeof(name), f) && strncmp(name, "pfdaq_stream_src", 16) == 0) {
			snprintf(path, n, "/dev/%s", e->d_name);
			found = 0;
		}
		fclose(f);
		if (!found) {
			break;
		}
	}
	closedir(d);
	return found;
}

int aegis_pqc_open(void)
{
	char dev[300];
	int fd;
	void *m;

	if (regs) {
		return 0;
	}
	if (find_uio(dev, sizeof(dev)) != 0) {
		return -1;
	}
	fd = open(dev, O_RDWR | O_SYNC);
	if (fd < 0) {
		return -1;
	}
	m = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if (m == MAP_FAILED) {
		return -1;
	}
	regs = (volatile uint32_t *)((volatile uint8_t *)m + PAGE_OFFSET_IN_UIO);
	if (regs[R_ID] != AEGIS_PQC_ID) {
		fprintf(stderr, "aegis_pqc: unexpected ID 0x%08x\n", (unsigned int)regs[R_ID]);
		munmap(m, 0x1000);
		regs = NULL;
		return -2;
	}
	return 0;
}

uint32_t aegis_pqc_id(void)
{
	return regs ? regs[R_ID] : 0;
}

int aegis_pqc_keccak_f1600(uint64_t lanes[25], uint32_t *cycles)
{
	if (!regs) {
		return -1;
	}
	for (int i = 0; i < 25; i++) {
		regs[R_LANES + 2 * i] = (uint32_t)lanes[i];
		regs[R_LANES + 2 * i + 1] = (uint32_t)(lanes[i] >> 32);
	}
	regs[R_CTRL] = 1u;
	while (regs[R_STATUS] & 1u) {
	}
	for (int i = 0; i < 25; i++) {
		lanes[i] = (uint64_t)regs[R_LANES + 2 * i] | ((uint64_t)regs[R_LANES + 2 * i + 1] << 32);
	}
	if (cycles) {
		*cycles = regs[R_KCYC];
	}
	return 0;
}

int aegis_pqc_ntt(int mode, int inverse, uint32_t coeffs[256], uint32_t *cycles)
{
	if (!regs) {
		return -1;
	}
	regs[R_NIDX] = 0;
	for (int i = 0; i < 256; i++) {
		regs[R_NDATA] = coeffs[i];
	}
	regs[R_CTRL] = (inverse ? 4u : 2u) | (mode ? 0x100u : 0u);
	while (regs[R_STATUS] & 2u) {
	}
	regs[R_NIDX] = 0;
	for (int i = 0; i < 256; i++) {
		coeffs[i] = regs[R_NDATA];
	}
	if (cycles) {
		*cycles = regs[R_NCYC];
	}
	return 0;
}

/* ---- liboqs hook ------------------------------------------------------------------------ */

/* liboqs' plain-64 Keccak keeps lanes 1, 2, 8, 12, 17, 20 complemented ("bebigokimisa"). */
static const uint8_t complemented[6] = {1, 2, 8, 12, 17, 20};

static void print_stats(void)
{
	fprintf(stderr, "aegis_pqc keccak: fabric=%lu checked=%lu software=%lu\n", n_hw, n_checked, n_sw);
}

/* 0 = not decided, 1 = hw, 2 = check, -1 = software */
static int hook_mode;

static void hook_init(void)
{
	const char *e = getenv("AEGIS_PQC_KECCAK");

	hook_mode = -1;
	if (e && (strcmp(e, "hw") == 0 || strcmp(e, "check") == 0)) {
		if (aegis_pqc_open() != 0) {
			fprintf(stderr, "aegis_pqc: AEGIS_PQC_KECCAK=%s but the core is not reachable\n", e);
			exit(3);
		}
		hook_mode = (strcmp(e, "hw") == 0) ? 1 : 2;
	}
	if (getenv("AEGIS_PQC_STATS")) {
		atexit(print_stats);
	}
}

/* Called by the patched KeccakP1600_Permute_24rounds. Returns 1 if the permutation was done
 * (state updated in place), 0 if the caller must run the software permutation. `sw` is the
 * software permutation, used in check mode. */
int aegis_pqc_keccak_hook(void *state, void (*sw)(void *))
{
	uint64_t *st = state, a[25], ref[25];

	if (!hook_mode) {
		hook_init();
	}
	if (hook_mode < 0) {
		n_sw++;
		return 0;
	}
	memcpy(a, st, sizeof(a));
	for (int i = 0; i < 6; i++) {
		a[complemented[i]] = ~a[complemented[i]];
	}
	if (hook_mode == 2) {
		memcpy(ref, st, sizeof(ref));
		sw(ref);
	}
	aegis_pqc_keccak_f1600(a, NULL);
	for (int i = 0; i < 6; i++) {
		a[complemented[i]] = ~a[complemented[i]];
	}
	if (hook_mode == 2) {
		if (memcmp(a, ref, sizeof(a)) != 0) {
			fprintf(stderr, "aegis_pqc: fabric Keccak differs from software (after %lu checks)\n", n_checked);
			abort();
		}
		n_checked++;
	} else {
		n_hw++;
	}
	memcpy(st, a, sizeof(a));
	return 1;
}

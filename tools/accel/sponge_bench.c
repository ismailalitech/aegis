/* SPDX-License-Identifier: Apache-2.0
 * On the gateway: raw timings of the aegis_pqc2 sponge, to replace the cost model's assumed constants with measured ones.
 * Uses the same access path as the driver (pfdaq UIO page, u-dma-buf udmabuf-ddr-nc0, last page) and checks every DMA
 * result against a squeeze over APB of the same sponge, so a timing is only printed for a correct transfer.
 *   sponge_bench [repeats]
 */
#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include "aegis_sponge_hw.h"

static volatile uint32_t *r;
static volatile uint64_t *buf;
static uint64_t buf_pa;

static double now_us(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}

static int open_all(void)
{
	DIR *d = opendir("/sys/class/uio");
	struct dirent *e;
	char dev[300] = "", p[300], name[64];
	FILE *f;
	unsigned long long pa = 0, size = 0;
	while (d && (e = readdir(d))) {
		snprintf(p, sizeof(p), "/sys/class/uio/%s/name", e->d_name);
		if ((f = fopen(p, "r"))) {
			if (fgets(name, sizeof(name), f) && !strncmp(name, "pfdaq_stream_src", 16))
				snprintf(dev, sizeof(dev), "/dev/%s", e->d_name);
			fclose(f);
		}
	}
	if (d) closedir(d);
	int fd = dev[0] ? open(dev, O_RDWR | O_SYNC) : -1;
	if (fd < 0) return -1;
	void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if (m == MAP_FAILED) return -1;
	r = (volatile uint32_t *)((uint8_t *)m + 0xE00);
	if ((f = fopen("/sys/class/u-dma-buf/udmabuf-ddr-nc0/phys_addr", "r"))) { if (fscanf(f, "%llx", &pa) != 1) pa = 0; fclose(f); }
	if ((f = fopen("/sys/class/u-dma-buf/udmabuf-ddr-nc0/size", "r"))) { if (fscanf(f, "%llu", &size) != 1) size = 0; fclose(f); }
	if (!pa || size < 4096 || (fd = open("/dev/udmabuf-ddr-nc0", O_RDWR | O_SYNC)) < 0) return -2;
	m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)(size - 4096));
	close(fd);
	if (m == MAP_FAILED) return -2;
	buf = m;
	buf_pa = pa + size - 4096;
	return 0;
}

#define W(o, v) (r[(o) / 4] = (v))
#define R(o) (r[(o) / 4])

/* a fresh SHAKE128 sponge in the current slot: absorb "bench" + padding */
static void fresh(void)
{
	W(SP_SCMD, SP_CMD_CLEAR);
	W(SP_SCFG, 1);
	W(SP_LANE + 0, 0x636e6562u); /* "benc" */
	W(SP_LANE + 4, 0x00001f68u); /* "h" + 0x1F */
	W(SP_LANE + 4 * 41, 0x80000000u);
}

int main(int argc, char **argv)
{
	int n = argc > 1 ? atoi(argv[1]) : 2000, bad = 0;
	if (open_all() != 0 || R(SP_ID) != SP_ID_V2) {
		fprintf(stderr, "core or buffer not reachable (ID 0x%08x)\n", r ? R(SP_ID) : 0);
		return 2;
	}
	printf("core ID 0x%08x, DMA buffer at 0x%llx\n", R(SP_ID), (unsigned long long)buf_pa);
	volatile uint32_t sink = 0;
	double t;

	t = now_us();
	for (int i = 0; i < n; i++) sink += R(SP_STATUS);
	printf("STATUS read:                      %.3f us\n", (now_us() - t) / n);
	t = now_us();
	for (int i = 0; i < n; i++) W(SP_LANE, (uint32_t)i);
	sink += R(SP_STATUS);
	printf("state word write:                 %.3f us\n", (now_us() - t) / n);
	t = now_us();
	for (int i = 0; i < n; i++) { W(SP_SCMD, SP_CMD_PERMUTE); sink += R(SP_LANE); }
	printf("PERMUTE + first read (waits):     %.3f us\n", (now_us() - t) / n);
	t = now_us();
	for (int i = 0; i < n; i++) { W(SP_SCMD, SP_CMD_SELECT | ((i & 1) << 4)); sink += R(SP_LANE); }
	printf("SELECT + first read (waits):      %.3f us\n", (now_us() - t) / n);
	W(SP_SCMD, SP_CMD_SELECT);

	/* correctness and timing of DMA squeezes, against APB squeezes of the same sponge */
	uint64_t ref[24 * 21];
	fresh();
	for (int j = 0; j < 24; j++) {
		W(SP_SCMD, SP_CMD_PERMUTE);
		for (int i = 0; i < 21; i++)
			ref[21 * j + i] = R(SP_LANE + 8 * i) | ((uint64_t)R(SP_LANE + 8 * i + 4) << 32);
	}
	W(SP_DMALO, (uint32_t)buf_pa);
	W(SP_DMAHI, (uint32_t)(buf_pa >> 32));
	int sizes[] = {1, 5, 24};
	for (unsigned s = 0; s < 3; s++) {
		int k = sizes[s];
		double tot = 0, first = 0;
		for (int it = 0; it < n / 10; it++) {
			fresh();
			for (int i = 0; i < 21 * k; i++) buf[i] = 0;
			W(SP_SCFG, 1 | (21u << 8) | ((uint32_t)k << 16));
			double t0 = now_us(), t1 = 0;
			W(SP_SCMD, SP_CMD_SQUEEZE);
			uint32_t st;
			do {
				st = R(SP_STATUS);
				if (!t1 && (st >> 24)) t1 = now_us();
			} while (st & SP_ST_DMA_BUSY);
			double t2 = now_us();
			if (!t1) t1 = t2;
			tot += t2 - t0;
			first += t1 - t0;
			if ((st & SP_ST_DMA_ERR) || (int)(st >> 24) != k) bad++;
			for (int i = 0; i < 21 * k && !bad; i++)
				if (buf[i] != ref[i]) { bad++; printf("  DMA block %d word %d differs\n", i / 21, i % 21); }
		}
		printf("SQUEEZE_DMA %2d block(s) of 168 B:  %.2f us total, first block reported after %.2f us\n",
		       k, tot / (n / 10), first / (n / 10));
	}
	t = now_us();
	uint64_t acc = 0;
	for (int it = 0; it < n / 10; it++)
		for (int i = 0; i < 21 * 24; i++) acc += buf[i];
	printf("non-cached copy:                  %.3f us per 8 bytes\n", (now_us() - t) / (n / 10) / (21 * 24));
	printf("DMA results equal to APB squeezes: %s\n", bad ? "NO" : "yes");
	return bad != 0 || (sink == 1 && acc == 1);
}

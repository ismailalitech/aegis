/* SPDX-License-Identifier: Apache-2.0
 * Cost of one 32-bit access from Linux user space to the aegis_pqc core (FIC3 APB, 50 MHz),
 * through the pfdaq UIO page. Reads the ID register and writes the NTT_INDEX register. */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1e9 + t.tv_nsec; }
int main(void)
{
	int fd = open("/dev/uio1", O_RDWR | O_SYNC);
	volatile uint32_t *p = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	volatile uint32_t *r = p + 0xE00 / 4;
	const int N = 200000;
	uint32_t s = 0;
	double t0, t1, t2, t3;
	if (fd < 0 || p == MAP_FAILED || r[0] != 0xAE150001u) { fprintf(stderr, "core not reachable\n"); return 1; }
	t0 = now(); for (int i = 0; i < N; i++) s += r[0];
	t1 = now(); for (int i = 0; i < N; i++) r[0x14 / 4] = (uint32_t)i & 0xFF;
	t2 = now(); for (int i = 0; i < N; i++) { r[0x14 / 4] = 0; s += r[0x14 / 4]; }
	t3 = now();
	printf("{\"reads_ns\":%.1f,\"writes_ns\":%.1f,\"write_then_read_ns\":%.1f,\"apb_clock_ns\":20.0,\"checksum\":%u}\n",
	       (t1 - t0) / N, (t2 - t1) / N, (t3 - t2) / N, s);
	return 0;
}

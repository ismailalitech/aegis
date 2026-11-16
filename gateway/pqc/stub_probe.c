/* SPDX-License-Identifier: Apache-2.0
 * Read the ID and the scratch register of the aegis_pqc integration stub through the pfdaq UIO page. */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
int main(int argc, char **argv)
{
	const char *dev = argc > 1 ? argv[1] : "/dev/uio1";
	int fd = open(dev, O_RDWR | O_SYNC);
	if (fd < 0) { perror(dev); return 1; }
	volatile uint32_t *p = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) { perror("mmap"); return 1; }
	volatile uint32_t *r = p + 0xE00 / 4;
	printf("id=0x%08x\n", (unsigned)r[0]);
	r[1] = 0x12345678u;
	printf("scratch=0x%08x\n", (unsigned)r[1]);
	printf("pfdaq_slot15_word0=0x%08x\n", (unsigned)p[0xF00 / 4]);
	return 0;
}

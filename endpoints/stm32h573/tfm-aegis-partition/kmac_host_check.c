/* SPDX-License-Identifier: Apache-2.0
 * PC harness for aegis_kmac.c: kmac_host_check KEYHEX DATAHEX CUSTOMHEX OUTLEN. The data is fed in three
 * updates of uneven size to exercise the streaming path. Prints the MAC as hex. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aegis_kmac.h"

static size_t unhex(const char *s, uint8_t *b)
{
	size_t n = strlen(s) / 2;
	for (size_t i = 0; i < n; i++) sscanf(s + 2 * i, "%2hhx", &b[i]);
	return n;
}

int main(int argc, char **argv)
{
	static uint8_t key[4096], data[65536], custom[4096], out[4096];
	struct aegis_kmac k;
	if (argc != 5) return 2;
	size_t kl = unhex(argv[1], key), dl = unhex(argv[2], data), cl = unhex(argv[3], custom);
	size_t ol = (size_t)atoi(argv[4]), a = dl / 3, b = dl / 2;
	aegis_kmac256_init(&k, key, kl, custom, cl);
	aegis_kmac256_update(&k, data, a);
	aegis_kmac256_update(&k, data + a, b - a);
	aegis_kmac256_update(&k, data + b, dl - b);
	aegis_kmac256_final(&k, out, ol);
	for (size_t i = 0; i < ol; i++) printf("%02x", out[i]);
	printf("\n");
	return 0;
}

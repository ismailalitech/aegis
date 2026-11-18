/* SPDX-License-Identifier: Apache-2.0
 * The RW612 prover's protocol code (src/aegis_proto.c) on the PC, for tests/host/test_rw612_proto.py.
 *   aegis_rw612_host <port> <seed hex> <provisioning root hex> <gateway pk hex file> <image file>
 * Prints "READY <pk sha256>" when it listens. One request per connection, as on the board. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#include "aegis_proto.h"
#include "aegis_sha256.h"

static const char *image_path;
static time_t t0;

static int host_random(uint8_t *out, size_t n)
{
	return getrandom(out, n, 0) == (ssize_t)n ? 0 : -1;
}

static void host_measure(uint8_t out[32], size_t *len)
{
	static uint8_t img[1 << 20];
	FILE *f = fopen(image_path, "rb");
	size_t n = f ? fread(img, 1, sizeof(img), f) : 0;

	if (f) fclose(f);
	sha256(img, n, out);
	*len = n;
}

static uint32_t host_uptime(void)
{
	return (uint32_t)(time(NULL) - t0);
}

static void unhex(const char *s, uint8_t *o, size_t n)
{
	for (size_t i = 0; i < n; i++) sscanf(s + 2 * i, "%2hhx", &o[i]);
}

int main(int argc, char **argv)
{
	static const struct aegis_proto_platform pl = {
		.random = host_random, .measure = host_measure, .uptime_s = host_uptime};
	static char line[AEGIS_LINE_MAX + 2], reply[AEGIS_REPLY_MAX];
	static char gwhex[2 * 1952 + 8];
	uint8_t seed[32], root[32], gw[1952], fp[32];
	struct sockaddr_in a = {0};
	int s, one = 1;
	FILE *f;

	if (argc != 6) return 2;
	image_path = argv[5];
	t0 = time(NULL);
	unhex(argv[2], seed, 32);
	unhex(argv[3], root, 32);
	f = fopen(argv[4], "r");
	if (!f || !fgets(gwhex, sizeof(gwhex), f)) return 2;
	fclose(f);
	unhex(gwhex, gw, sizeof(gw));
	if (aegis_proto_init(&pl, seed, root, gw) != 0) return 3;
	s = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	a.sin_family = AF_INET;
	a.sin_port = htons((uint16_t)atoi(argv[1]));
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(s, 8) != 0) return 4;
	sha256(aegis_proto_pk(), 1952, fp);
	printf("READY ");
	for (int i = 0; i < 32; i++) printf("%02x", fp[i]);
	printf("\n");
	fflush(stdout);
	for (;;) {
		int c = accept(s, NULL, NULL);
		size_t got = 0;
		ssize_t r;
		int n;

		if (c < 0) continue;
		while (got < AEGIS_LINE_MAX && (r = recv(c, line + got, AEGIS_LINE_MAX - got, 0)) > 0) {
			got += (size_t)r;
			if (memchr(line, '\n', got)) break;
		}
		line[got] = 0;
		if (memchr(line, '\n', got) == NULL && got >= AEGIS_LINE_MAX) {
			n = snprintf(reply, sizeof(reply), "ERR too-long");
		} else {
			*strchrnul(line, '\n') = 0;
			n = aegis_proto_handle(line, reply, sizeof(reply));
		}
		memcpy(reply + n, "\r\n", 2);
		send(c, reply, (size_t)n + 2, 0);
		close(c);
	}
}

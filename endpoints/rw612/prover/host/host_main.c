/* SPDX-License-Identifier: Apache-2.0
 * The RW612 prover's protocol code (src/aegis_proto.c) on the PC, for tests/host/test_rw612_proto.py.
 *   aegis_rw612_host <port> <seed hex> <provisioning root hex> <gateway pk hex file> <image file> [<second image>]
 * With a second image it behaves like the TF-M partition (endpoints/rw612/tfm/aegis_pq): profile aegis-rw612-tfm-v1,
 * measurements SPE (the first file) and NSPE (the second).
 * Prints "READY <pk sha256>" when it listens. One request per connection, as on the board.
 * The session clock is CLOCK_MONOTONIC; a test moves it through the file named by the environment variable
 * AEGIS_TEST_CLOCK: seconds to add (negative: the clock runs backwards), or "fail" for a clock that cannot be read. */
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

static const char *image_path, *image2_path;
static time_t t0;

/* With AEGIS_TEST_STALE_RNG in the environment (tests/host/test_reset_replay_check.py and nothing else): the bytes of
 * a generator that starts again at every start of the program, to show what the reset-and-replay check sees on an
 * endpoint whose keys are not new after a reset. */
/* With AEGIS_TEST_RNG naming a file that says "fail" (tests/host/test_rw612_proto.py): a generator that fails, so
 * that every signature and every ML-KEM key is refused while the file says so. PC build only. */
static int rng_fails(void)
{
	const char *path = getenv("AEGIS_TEST_RNG");
	char buf[8] = "";
	FILE *f = path ? fopen(path, "r") : NULL;

	if (f) {
		if (!fgets(buf, sizeof(buf), f)) buf[0] = 0;
		fclose(f);
	}
	return !strncmp(buf, "fail", 4);
}

static int host_random(uint8_t *out, size_t n)
{
	static uint64_t x = 0x9e3779b97f4a7c15ull;

	if (rng_fails()) return -1;
	if (!getenv("AEGIS_TEST_STALE_RNG")) {
		return getrandom(out, n, 0) == (ssize_t)n ? 0 : -1;
	}
	for (size_t i = 0; i < n; i++) {
		x ^= x << 13; x ^= x >> 7; x ^= x << 17;
		out[i] = (uint8_t)(x >> 24);
	}
	return 0;
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

static size_t hash_file(const char *path, uint8_t out[32])
{
	static uint8_t img[4 << 20];
	FILE *f = fopen(path, "rb");
	size_t n = f ? fread(img, 1, sizeof(img), f) : 0;

	if (f) fclose(f);
	sha256(img, n, out);
	return n;
}

static size_t host_measure_all(struct aegis_measurement *m, size_t max)
{
	size_t n1, n2;

	if (max < 2) return 0;
	n1 = hash_file(image_path, m[0].value);
	n2 = hash_file(image2_path, m[1].value);
	m[0].label = "SPE";
	m[1].label = "NSPE";
	snprintf(m[0].desc, sizeof(m[0].desc), "SHA256 of the secure partition (%u bytes)", (unsigned)n1);
	snprintf(m[1].desc, sizeof(m[1].desc), "SHA256 of the non-secure partition (%u bytes)", (unsigned)n2);
	return 2;
}

static int host_status(char *buf, size_t cap)
{
	return snprintf(buf, cap, "requests=0;stack=na;fw=rw612-tfm-0.2.2");
}

static uint32_t host_uptime(void)
{
	return (uint32_t)(time(NULL) - t0);
}

static int host_monotonic(uint64_t *now)
{
	const char *path = getenv("AEGIS_TEST_CLOCK");
	char buf[32] = "";
	struct timespec ts;
	FILE *f = path ? fopen(path, "r") : NULL;

	if (f) {
		if (!fgets(buf, sizeof(buf), f)) buf[0] = 0;
		fclose(f);
	}
	if (!strncmp(buf, "fail", 4) || clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return -1;
	*now = (uint64_t)((long long)ts.tv_sec + 1000000000LL + atoll(buf));
	return 0;
}

static void unhex(const char *s, uint8_t *o, size_t n)
{
	for (size_t i = 0; i < n; i++) sscanf(s + 2 * i, "%2hhx", &o[i]);
}

int main(int argc, char **argv)
{
	static const struct aegis_proto_platform pl = {
		.random = host_random, .measure = host_measure, .uptime_s = host_uptime, .monotonic_s = host_monotonic};
	static const struct aegis_proto_platform pl_tfm = {
		.random = host_random, .measure = host_measure, .uptime_s = host_uptime, .monotonic_s = host_monotonic,
		.profile = "aegis-rw612-tfm-v1", .measure_all = host_measure_all, .status = host_status};
	static char line[AEGIS_LINE_MAX + 2], reply[AEGIS_REPLY_MAX];
	static char gwhex[2 * 1952 + 8];
	uint8_t seed[32], root[32], gw[1952], fp[32];
	struct sockaddr_in a = {0};
	int s, one = 1;
	FILE *f;

	if (argc != 6 && argc != 7) return 2;
	image_path = argv[5];
	image2_path = argc == 7 ? argv[6] : NULL;
	t0 = time(NULL);
	unhex(argv[2], seed, 32);
	unhex(argv[3], root, 32);
	f = fopen(argv[4], "r");
	if (!f || !fgets(gwhex, sizeof(gwhex), f)) return 2;
	fclose(f);
	unhex(gwhex, gw, sizeof(gw));
	if (aegis_proto_init(image2_path ? &pl_tfm : &pl, seed, root, gw) != 0) return 3;
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

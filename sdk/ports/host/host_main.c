/* SPDX-License-Identifier: Apache-2.0
 * The SDK's core on the PC behind a TCP socket, through the reference port (aegis_port_host.c): what the host tests
 * talk to (tests/host/test_rw612_proto.py and others), and the smallest complete integration to read.
 *   aegis_host_prover <port> <seed hex> <provisioning root hex> <gateway pk hex file> <image file> [<second image>]
 * One image: a single-image device (profile aegis-rw612-els-v1, one measurement APP). With a second image it reports
 * like a TF-M device (endpoints/rw612/tfm/aegis_pq): profile aegis-rw612-tfm-v1, measurements SPE and NSPE.
 * Prints "READY <pk sha256>" when it listens. One request per connection, as on the boards.
 * For tests, from the environment:
 *   AEGIS_TEST_CLOCK=<file>   the session clock is CLOCK_MONOTONIC plus the seconds in that file (negative: the
 *                             clock runs backwards), or cannot be read while the file says "fail"
 *   AEGIS_TEST_RNG=<file>     the random generator fails while the file says "fail"
 *   AEGIS_TEST_STALE_RNG      the bytes of a generator that starts again at every start of the program, to show what
 *                             the reset-and-replay check sees on a device whose keys are not new after a reset
 *                             (tests/host/test_reset_replay_check.py and nothing else)
 *   AEGIS_HOST_PLATFORM_KEY   the identity key is held by the port, not by the core (struct aegis_platform's
 *                             identity functions) */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "aegis_port_host.h"
#include "aegis_sha256.h"

/* With AEGIS_TEST_RNG naming a file that says "fail" (tests/host/test_rw612_proto.py): a generator that fails, so
 * that every signature and every ML-KEM key is refused while the file says so. */
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

static int test_random(uint8_t *out, size_t n)
{
	static uint64_t x = 0x9e3779b97f4a7c15ull;

	if (rng_fails()) return -1;
	if (!getenv("AEGIS_TEST_STALE_RNG")) return getrandom(out, n, 0) == (ssize_t)n ? 0 : -1;
	for (size_t i = 0; i < n; i++) {
		x ^= x << 13; x ^= x >> 7; x ^= x << 17;
		out[i] = (uint8_t)(x >> 24);
	}
	return 0;
}

static int test_clock(uint64_t *now)
{
	char buf[32] = "";
	struct timespec ts;
	FILE *f = fopen(getenv("AEGIS_TEST_CLOCK"), "r");

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
	static struct aegis_host host;
	static char line[AEGIS_LINE_MAX + 2], reply[AEGIS_REPLY_MAX];
	static char gwhex[2 * AEGIS_PK_LEN + 8];
	static uint8_t gw[AEGIS_PK_LEN];
	uint8_t seed[32], root[32], fp[32];
	struct sockaddr_in a = {0};
	int s, one = 1;
	FILE *f;

	if (argc != 6 && argc != 7) return 2;
	unhex(argv[2], seed, 32);
	unhex(argv[3], root, 32);
	f = fopen(argv[4], "r");
	if (!f || !fgets(gwhex, sizeof(gwhex), f)) return 2;
	fclose(f);
	unhex(gwhex, gw, sizeof(gw));
	if (argc == 6) {
		aegis_host_prepare(&host, "aegis-rw612-els-v1", "rw612", "0.1.0");
		aegis_host_add_image(&host, "APP", argv[5], "firmware image");
	} else {
		aegis_host_prepare(&host, "aegis-rw612-tfm-v1", "rw612", "0.1.0");
		aegis_host_add_image(&host, "SPE", argv[5], "secure partition");
		aegis_host_add_image(&host, "NSPE", argv[6], "non-secure partition");
		host.status = "requests=0;stack=na;fw=rw612-tfm-0.2.2";
	}
	if (getenv("AEGIS_TEST_STALE_RNG") || getenv("AEGIS_TEST_RNG")) aegis_host_test_random = test_random;
	if (getenv("AEGIS_TEST_CLOCK")) aegis_host_test_clock = test_clock;
	if (aegis_host_start(&host, seed, root, gw, getenv("AEGIS_HOST_PLATFORM_KEY") != NULL) != AEGIS_OK) return 3;
	aegis_wipe(seed, sizeof(seed)); /* the core has made the key and copied the root: the port keeps neither */
	aegis_wipe(root, sizeof(root));
	s = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	a.sin_family = AF_INET;
	a.sin_port = htons((uint16_t)atoi(argv[1]));
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(s, 8) != 0) return 4;
	aegis_sha256(aegis_prover_public_key(&host.prover), AEGIS_PK_LEN, fp);
	printf("READY ");
	for (int i = 0; i < 32; i++) printf("%02x", fp[i]);
	printf("\n");
	fflush(stdout);
	/* The transport is the integrator's: here one line per TCP connection. */
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
			n = aegis_prover_handle_line(&host.prover, line, reply, sizeof(reply));
		}
		memcpy(reply + n, "\r\n", 2);
		send(c, reply, (size_t)n + 2, 0);
		close(c);
	}
}

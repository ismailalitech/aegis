/* SPDX-License-Identifier: Apache-2.0
 *
 * A simulated device on the Aegis Prover SDK: the smallest complete integration an outside device maker can read
 * from top to bottom, built only against the installed SDK (aegis_sdk.h, aegis_sha256.h, libaegis_sdk.a).
 *
 *   aegis_sim_device --verifier-pk FILE --secret FILE --image LABEL=FILE [--image ...] [--listen PORT]
 *
 *   --verifier-pk  the verifier's ML-DSA-65 public key in hex (1952 bytes): the key this device pins
 *   --secret       32 bytes in hex: stands in for the chip's hardware unique key
 *   --image        a "firmware component", measured once at start (as a boot stage would), at most 4
 *   --listen       TCP port on 127.0.0.1 (0, the default, picks a free one)
 *
 * Prints "READY <port> <sha256 of the identity public key>" when it listens, then serves the Aegis line protocol,
 * one request line per connection (kind "aegis-linux" in the verifier's policy). Stop it with SIGINT or SIGTERM.
 *
 * It protects nothing: the "secret" is a file, the keys are in process memory, the clock belongs to the operating
 * system. So it reports the software profile (aegis-linux-software-v1), and the verifier says trust "software".
 * docs/sdk-porting-guide.md says what each function below becomes on a real chip.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "aegis_sdk.h"
#include "aegis_sha256.h"

#define SIM_PROFILE    "aegis-linux-software-v1" /* the honest profile: key and measurements held by software */
#define SIM_VERSION    "sim-1.0.0"
#define SIM_MAX_IMAGES 4u
#define SIM_EVIDENCE_MAX 1024u

/* ---- the device's state: all of it in one place, as it would be in a secure partition --------------------------- */
static struct aegis_prover prover;                         /* the core's context (13 kB) */
static uint8_t work[AEGIS_WORK_LEN(SIM_EVIDENCE_MAX)];     /* the core's work buffer */
static uint8_t verifier_pk[AEGIS_PK_LEN];                  /* pinned; on a chip: const, in the measured image */
static struct aegis_measurement meas[SIM_MAX_IMAGES];
static size_t n_meas;
static unsigned long requests;
static char line[AEGIS_LINE_MAX + 2], reply[AEGIS_REPLY_MAX + 2];
static volatile sig_atomic_t stop;

/* ---- 1. randomness: the TRNG on a chip; here the kernel's generator --------------------------------------------- */
static int sim_random(void *user, uint8_t *out, size_t n)
{
	(void)user;
	return getrandom(out, n, 0) == (ssize_t)n ? 0 : -1;
}

/* ---- 2. time: a counter nothing less trusted can set or stop; here CLOCK_MONOTONIC in milliseconds -------------- */
static int sim_clock(void *user, uint64_t *now)
{
	struct timespec ts;

	(void)user;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return -1;
	*now = (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
	return 0;
}

/* ---- 3. measurements: taken once at start by code the measured code cannot change; here, hashed files ------------ */
static int sim_measurements(void *user, const struct aegis_measurement **list, size_t *count)
{
	(void)user;
	*list = meas;
	*count = n_meas;
	return 0;
}

static int measure_image(const char *spec)
{
	static uint8_t buf[16u << 20]; /* images up to 16 MiB */
	const char *eq = strchr(spec, '=');
	struct aegis_measurement *m = &meas[n_meas];
	size_t n;
	FILE *f;

	if (eq == NULL || eq == spec || n_meas >= SIM_MAX_IMAGES) return -1;
	f = fopen(eq + 1, "rb");
	if (f == NULL) return -1;
	n = fread(buf, 1, sizeof(buf), f);
	if (ferror(f) || !feof(f)) n = (size_t)-1; /* unreadable, or larger than the buffer */
	fclose(f);
	if (n == (size_t)-1) return -1;
	m->label = strndup(spec, (size_t)(eq - spec));
	if (m->label == NULL) return -1;
	aegis_sha256(buf, n, m->value);
	snprintf(m->desc, sizeof(m->desc), "simulated component %s", m->label);
	n_meas++;
	return 0;
}

/* ---- 5. status text for heartbeats (MACed, not secret; never a "ttl=" key) -------------------------------------- */
static int sim_status(void *user, char *buf, size_t cap)
{
	int n;

	(void)user;
	n = snprintf(buf, cap, "fw=%s;requests=%lu", SIM_VERSION, requests);
	return n < 0 || (size_t)n >= cap ? -1 : n;
}

/* The platform layer: const, so that nothing can change a function pointer once the core holds it. */
static const struct aegis_platform platform = {
	.random = sim_random,
	.clock = sim_clock,
	.clock_hz = 1000,
	.measurements = sim_measurements,
	.profile = SIM_PROFILE,
	.version = SIM_VERSION,
	.status = sim_status,
};

/* ---- 4. identity: two secrets derived from the device's hardware key. On a chip: a KDF in the key store (the
 * STM32's DHUK through SAES, the RW612's ELS, OP-TEE's HUK), never visible outside the secure world. ------------- */
static void derive(const uint8_t secret[32], const char *label, uint8_t out[AEGIS_SEED_LEN])
{
	uint8_t msg[64 + 32];
	size_t l = strlen(label) + 1; /* with its terminator: labels cannot run into the secret */

	memcpy(msg, label, l);
	memcpy(msg + l, secret, 32);
	aegis_sha256(msg, l + 32, out);
	aegis_wipe(msg, sizeof(msg));
}

static int read_hex(const char *path, uint8_t *out, size_t n)
{
	FILE *f = fopen(path, "r");
	int ok = f != NULL;

	for (size_t i = 0; ok && i < n; i++) ok = fscanf(f, "%2hhx", &out[i]) == 1;
	if (f) fclose(f);
	return ok ? 0 : -1;
}

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
}

static int usage(void)
{
	fprintf(stderr, "usage: aegis_sim_device --verifier-pk FILE --secret FILE --image LABEL=FILE [--image ...] "
			"[--listen PORT]\n");
	return 2;
}

/* ---- 6. the transport: one line per TCP connection in, one reply out ------------------------------------------- */
static void serve_one(int c)
{
	struct timeval tv = {.tv_sec = 10};
	size_t got = 0;
	ssize_t r;
	char *nl = NULL;
	int n;

	setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	while (got < AEGIS_LINE_MAX && (r = recv(c, line + got, AEGIS_LINE_MAX - got, 0)) > 0) {
		got += (size_t)r;
		if ((nl = memchr(line, '\n', got)) != NULL) break;
	}
	line[got] = '\0';
	if (nl) *nl = '\0';
	if (nl && nl > line && nl[-1] == '\r') nl[-1] = '\0';
	requests++;
	if (!nl && got >= AEGIS_LINE_MAX) {
		n = snprintf(reply, sizeof(reply), "ERR too-long"); /* the transport's own answer (sdk/README.md) */
		while (recv(c, line, AEGIS_LINE_MAX, MSG_DONTWAIT) > 0) {
		}
	} else {
		n = aegis_prover_handle_line(&prover, line, reply, AEGIS_REPLY_MAX);
		if (n < 0) n = snprintf(reply, sizeof(reply), "ERR internal");
	}
	memcpy(reply + n, "\r\n", 2);
	for (size_t off = 0; off < (size_t)n + 2; off += (size_t)r) {
		r = send(c, reply + off, (size_t)n + 2 - off, MSG_NOSIGNAL);
		if (r <= 0) break;
	}
}

int main(int argc, char **argv)
{
	const char *pk_file = NULL, *secret_file = NULL;
	uint8_t secret[32], seed[AEGIS_SEED_LEN], root[AEGIS_SEED_LEN], fp[32];
	struct sockaddr_in a = {0};
	socklen_t alen = sizeof(a);
	struct sigaction sa = {0};
	long port = 0;
	int s, one = 1, rc;

	for (int i = 1; i < argc; i++) {
		const char *v = i + 1 < argc ? argv[i + 1] : NULL;

		if (v == NULL) return usage();
		if (!strcmp(argv[i], "--verifier-pk")) pk_file = v;
		else if (!strcmp(argv[i], "--secret")) secret_file = v;
		else if (!strcmp(argv[i], "--listen")) port = strtol(v, NULL, 10);
		else if (!strcmp(argv[i], "--image")) {
			if (measure_image(v) != 0) {
				fprintf(stderr, "--image %s: not LABEL=readable file of at most 16 MiB, or more than %u images\n",
					v, SIM_MAX_IMAGES);
				return 2;
			}
		} else return usage();
		i++;
	}
	if (pk_file == NULL || secret_file == NULL || n_meas == 0 || port < 0 || port > 65535) return usage();
	if (read_hex(pk_file, verifier_pk, sizeof(verifier_pk)) != 0) {
		fprintf(stderr, "%s: not an ML-DSA-65 public key in hex\n", pk_file);
		return 2;
	}
	if (read_hex(secret_file, secret, sizeof(secret)) != 0) {
		fprintf(stderr, "%s: not 32 bytes in hex\n", secret_file);
		return 2;
	}

	/* Start the core: the seed and the root are derived, handed over, and wiped. */
	derive(secret, "aegis-sim-identity-v1", seed);
	derive(secret, "aegis-sim-exchange-root-v1", root);
	aegis_wipe(secret, sizeof(secret));
	{
		const struct aegis_config cfg = {
			.platform = &platform,
			.verifier_pk = verifier_pk,
			.identity_seed = seed,
			.exchange_root = root,
			.work = work,
			.work_len = sizeof(work),
		};
		rc = AEGIS_PROVER_INIT(&prover, &cfg);
	}
	aegis_wipe(seed, sizeof(seed));
	aegis_wipe(root, sizeof(root));
	if (rc != AEGIS_OK) {
		fprintf(stderr, "aegis_prover_init: %d\n", rc);
		return 3;
	}

	sa.sa_handler = on_signal; /* no SA_RESTART: accept() returns, and the loop ends */
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	signal(SIGPIPE, SIG_IGN);
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) return 4;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	a.sin_family = AF_INET;
	a.sin_port = htons((uint16_t)port);
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(s, 8) != 0 ||
	    getsockname(s, (struct sockaddr *)&a, &alen) != 0) {
		perror("listen");
		return 4;
	}
	aegis_sha256(aegis_prover_public_key(&prover), AEGIS_PK_LEN, fp);
	printf("READY %u ", (unsigned)ntohs(a.sin_port));
	for (int i = 0; i < 32; i++) printf("%02x", fp[i]);
	printf("\n");
	fflush(stdout);

	while (!stop) {
		int c = accept(s, NULL, NULL);

		if (c < 0) {
			if (errno != EINTR) perror("accept");
			continue;
		}
		serve_one(c);
		close(c);
		aegis_prover_poll(&prover); /* end an overdue session now, not at the next request */
	}
	close(s);
	aegis_wipe(&prover, sizeof(prover)); /* the session key and the identity key do not outlive the device */
	return 0;
}

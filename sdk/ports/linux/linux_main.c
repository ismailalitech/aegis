/* SPDX-License-Identifier: Apache-2.0
 * The Aegis prover for a Linux device, in C on the Prover SDK's core (aegis_port_linux.c is the port; its header
 * says what this protects and what it does not). The command line of the Python prover:
 *   aegis_linux_prover --state DIR --gateway-pk FILE --measure LABEL=file[,file...] [--measure ...] [--port 7444]
 * --gateway-pk: the gateway's ML-DSA-65 identity public key in hex. The Aegis line protocol on TCP, one request per
 * connection (kind "aegis-linux" in the gateway's policy). The device's public key is also written to
 * <state>/mldsa65.pub in hex, for the gateway's enrolment. */
#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <getopt.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "aegis_port_linux.h"
#include "aegis_sha256.h"

static struct aegis_linux dev;
static char line[AEGIS_LINE_MAX + 2], reply[AEGIS_REPLY_MAX + 2];
static uint8_t gateway_pk[AEGIS_PK_LEN];

static int read_hex_file(const char *path, uint8_t *out, size_t n)
{
	FILE *f = fopen(path, "r");
	int ok = f != NULL;

	for (size_t i = 0; ok && i < n; i++) ok = fscanf(f, "%2hhx", &out[i]) == 1;
	if (f) fclose(f);
	return ok ? 0 : -1;
}

static void write_public_key(const char *state)
{
	char path[600];
	FILE *f;

	snprintf(path, sizeof(path), "%s/mldsa65.pub", state);
	f = fopen(path, "w");
	if (f == NULL) return;
	for (size_t i = 0; i < AEGIS_PK_LEN; i++) fprintf(f, "%02x", aegis_prover_public_key(&dev.prover)[i]);
	fputc('\n', f);
	fclose(f);
}

static int usage(void)
{
	fprintf(stderr, "usage: aegis_linux_prover --gateway-pk FILE [--state DIR] [--measure LABEL=file[,file...]]... "
			"[--port 7444]\n");
	return 2;
}

int main(int argc, char **argv)
{
	static const struct option opts[] = {{"state", 1, NULL, 's'}, {"gateway-pk", 1, NULL, 'g'},
					     {"measure", 1, NULL, 'm'}, {"port", 1, NULL, 'p'}, {NULL, 0, NULL, 0}};
	const char *state = "/var/lib/aegis-prover", *gw = NULL;
	struct sockaddr_in a = {0};
	uint8_t fp[32];
	int port = 7444, s, one = 1, o, rc;

	if (aegis_linux_prepare(&dev) != 0) return 3;
	while ((o = getopt_long(argc, argv, "", opts, NULL)) != -1) {
		if (o == 's') state = optarg;
		else if (o == 'g') gw = optarg;
		else if (o == 'p') port = atoi(optarg);
		else if (o != 'm' || aegis_linux_add_measure(&dev, optarg) != 0) return usage();
	}
	if (gw == NULL || optind != argc || port <= 0 || port > 65535) return usage();
	if (read_hex_file(gw, gateway_pk, sizeof(gateway_pk)) != 0) {
		fprintf(stderr, "%s: not an ML-DSA-65 public key in hex\n", gw);
		return 2;
	}
	rc = aegis_linux_start(&dev, state, gateway_pk);
	if (rc != AEGIS_OK) {
		fprintf(stderr, "no identity key from %s (%d)\n", state, rc);
		return 3;
	}
	write_public_key(state);
	signal(SIGPIPE, SIG_IGN);
	s = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	a.sin_family = AF_INET;
	a.sin_port = htons((uint16_t)port);
	a.sin_addr.s_addr = htonl(INADDR_ANY);
	if (s < 0 || bind(s, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(s, 8) != 0) {
		perror("listen");
		return 4;
	}
	aegis_sha256(aegis_prover_public_key(&dev.prover), AEGIS_PK_LEN, fp);
	printf("AEGIS-LINUX-PROVER %s (C, SDK API %u) ready on %d, key sha256 ", AEGIS_LINUX_VERSION,
	       (unsigned)AEGIS_SDK_API_VERSION, port);
	for (int i = 0; i < 8; i++) printf("%02x", fp[i]);
	printf("\n");
	fflush(stdout);
	/* The transport: one line per TCP connection. The core sees a terminated line and a reply buffer. */
	for (;;) {
		struct timeval tv = {.tv_sec = 10};
		int c = accept(s, NULL, NULL), n;
		size_t got = 0;
		ssize_t r;
		char *nl = NULL;

		if (c < 0) continue;
		setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
		while (got < AEGIS_LINE_MAX && (r = recv(c, line + got, AEGIS_LINE_MAX - got, 0)) > 0) {
			got += (size_t)r;
			nl = memchr(line, '\n', got);
			if (nl) break;
		}
		line[got] = '\0';
		if (nl) *nl = '\0';
		if (!nl && got >= AEGIS_LINE_MAX) {
			n = snprintf(reply, sizeof(reply), "ERR too-long");
			/* take what else has arrived off the socket: closing over unread data would reset the connection
			 * and could lose this reply */
			while (recv(c, line, AEGIS_LINE_MAX, MSG_DONTWAIT) > 0) {
			}
		} else {
			n = aegis_prover_handle_line(&dev.prover, line, reply, AEGIS_REPLY_MAX);
			if (n < 0) n = snprintf(reply, sizeof(reply), "ERR internal");
		}
		memcpy(reply + n, "\r\n", 2);
		for (size_t off = 0; off < (size_t)n + 2; off += (size_t)r) {
			r = send(c, reply + off, (size_t)n + 2 - off, MSG_NOSIGNAL);
			if (r <= 0) break;
		}
		close(c);
	}
}

// SPDX-License-Identifier: Apache-2.0
/*
 * Linux side of the Zynq UltraScale+ Aegis endpoint with OP-TEE: TCP port 7444, one request line per connection,
 * passed unchanged to the Aegis trusted application (endpoints/zynqmp/optee/ta), whose reply goes back with a line
 * end. Like the RW612's non-secure prover, this program holds no key, no seed and no session, and takes no
 * measurement: it is a pipe.
 *   aegis_tee_bridge [port]
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <tee_client_api.h>

#include "aegis_ta.h"

static char line[AEGIS_TA_LINE_MAX + 2];
static char reply[AEGIS_TA_REPLY_MAX + 1];

static int send_all(int fd, const char *p, size_t n)
{
	while (n) {
		ssize_t k = send(fd, p, n, MSG_NOSIGNAL);

		if (k <= 0) {
			if (k < 0 && errno == EINTR)
				continue;
			return -1;
		}
		p += k;
		n -= (size_t)k;
	}
	return 0;
}

/* read up to the first line end; returns the line length, -1 if too long or the peer closed early */
static long read_line(int fd)
{
	size_t n = 0;

	while (n < sizeof(line)) {
		ssize_t k = recv(fd, line + n, sizeof(line) - n, 0);
		char *nl;

		if (k <= 0)
			return -1;
		nl = memchr(line + n, '\n', (size_t)k);
		n += (size_t)k;
		if (nl) {
			size_t len = (size_t)(nl - line);

			if (len && line[len - 1] == '\r')
				len--;
			return len <= AEGIS_TA_LINE_MAX ? (long)len : -1;
		}
	}
	return -1;
}

int main(int argc, char **argv)
{
	const TEEC_UUID uuid = AEGIS_TA_UUID;
	int port = argc > 1 ? atoi(argv[1]) : 7444;
	TEEC_Context ctx;
	TEEC_Session sess;
	uint32_t origin = 0;
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_ANY) };
	int one = 1, srv;
	TEEC_Result r;

	signal(SIGPIPE, SIG_IGN);
	r = TEEC_InitializeContext(NULL, &ctx);
	if (r != TEEC_SUCCESS) {
		fprintf(stderr, "aegis-tee-bridge: TEEC_InitializeContext 0x%x\n", r);
		return 1;
	}
	r = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (r != TEEC_SUCCESS) {
		fprintf(stderr, "aegis-tee-bridge: TEEC_OpenSession 0x%x (origin %u)\n", r, origin);
		return 1;
	}
	srv = socket(AF_INET, SOCK_STREAM, 0);
	a.sin_port = htons((uint16_t)port);
	setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (srv < 0 || bind(srv, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(srv, 8) != 0) {
		perror("aegis-tee-bridge: listen");
		return 1;
	}
	printf("AEGIS-TEE-BRIDGE ready on %d\n", port);
	fflush(stdout);
	for (;;) {
		struct timeval tv = { .tv_sec = 5 };
		TEEC_Operation op = { 0 };
		size_t out_len;
		long n;
		int c = accept(srv, NULL, NULL);

		if (c < 0)
			continue;
		setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		n = read_line(c);
		if (n < 0) {
			send_all(c, "ERR too-long\n", 13);
			close(c);
			continue;
		}
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = line;
		op.params[0].tmpref.size = (size_t)n;
		op.params[1].tmpref.buffer = reply;
		op.params[1].tmpref.size = AEGIS_TA_REPLY_MAX;
		r = TEEC_InvokeCommand(&sess, AEGIS_TA_CMD_LINE, &op, &origin);
		if (r == TEEC_SUCCESS) {
			out_len = op.params[1].tmpref.size;
		} else {
			out_len = (size_t)snprintf(reply, sizeof(reply), "ERR secure 0x%x", r);
		}
		reply[out_len++] = '\n';
		send_all(c, reply, out_len);
		close(c);
	}
}

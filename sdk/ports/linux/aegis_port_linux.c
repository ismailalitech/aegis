/* SPDX-License-Identifier: Apache-2.0
 *
 * Aegis Prover SDK, port to Linux user space (see aegis_port_linux.h for what it does and does not protect). The
 * platform layer in the order of struct aegis_platform, then the state directory and the start.
 */
#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "aegis_port_linux.h"
#include "aegis_sha256.h"

/* Randomness: the kernel's generator, which blocks until it is seeded. */
static int linux_random(void *user, uint8_t *out, size_t n)
{
	(void)user;
	return getrandom(out, n, 0) == (ssize_t)n ? 0 : -1;
}

/* Time: seconds that only advance and that setting the date does not move; CLOCK_BOOTTIME also counts the time
 * suspended. Root can do worse than move a clock: software trust, like the key. */
static int linux_clock(void *user, uint64_t *now)
{
	struct timespec ts;
	int rc = -1;

	(void)user;
#if defined(CLOCK_BOOTTIME)
	rc = clock_gettime(CLOCK_BOOTTIME, &ts);
#endif
	if (rc != 0 && clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return -1;
	*now = (uint64_t)ts.tv_sec;
	return 0;
}

/* Append a whole file to *buf (which grows). 0, or -1 if it cannot be read. */
static int slurp(const char *path, uint8_t **buf, size_t *len, size_t *cap)
{
	FILE *f = fopen(path, "rb");
	size_t n;

	if (f == NULL) return -1;
	for (;;) {
		if (*cap - *len < (1u << 16)) {
			size_t want = *cap ? 2 * *cap : (1u << 20);
			uint8_t *p = realloc(*buf, want);

			if (p == NULL) break;
			*buf = p;
			*cap = want;
		}
		n = fread(*buf + *len, 1, *cap - *len, f);
		*len += n;
		if (n == 0) break;
	}
	n = (size_t)(feof(f) && !ferror(f));
	fclose(f);
	return n ? 0 : -1;
}

/* Measurements: for each group SHA-256 over its files, in order, as they are on disk now; last the prover's own
 * executable. The same values as the Python prover's measure() for the same arguments. A file that cannot be read
 * refuses the quote: no value is made up. (The SDK's SHA-256 takes one buffer, so a group is read into memory
 * first.) */
static int linux_measurements(void *user, const struct aegis_measurement **list, size_t *count)
{
	struct aegis_linux *l = user;
	uint8_t *buf = NULL;
	size_t cap = 0;
	int rc = 0;

	for (size_t g = 0; g < l->groups && rc == 0; g++) {
		struct aegis_measurement *m = &l->meas[g];
		size_t len = 0, d;

		d = (size_t)snprintf(m->desc, sizeof(m->desc), "SHA256 of ");
		for (size_t i = 0; i < l->group[g].paths && rc == 0; i++) {
			const char *path = l->group[g].path[i], *base = strrchr(path, '/');

			rc = slurp(path, &buf, &len, &cap);
			if (d < sizeof(m->desc)) {
				d += (size_t)snprintf(m->desc + d, sizeof(m->desc) - d, "%s%s", i ? ", " : "", base ? base + 1 : path);
			}
		}
		m->label = l->group[g].label;
		if (rc == 0) aegis_sha256(buf, len, m->value);
	}
	free(buf);
	*list = l->meas;
	*count = l->groups;
	return rc;
}

/* Status text for the heartbeat, in the Python prover's form. The core adds the session's time left. */
static int linux_status(void *user, char *buf, size_t cap)
{
	struct aegis_linux *l = user;
	uint64_t now = l->started;

	(void)linux_clock(user, &now);
	return snprintf(buf, cap, "uptime_s=%u;link=1;fw=%s-%s", (unsigned)(now - l->started), AEGIS_LINUX_FW,
			AEGIS_LINUX_VERSION);
}

int aegis_linux_prepare(struct aegis_linux *l)
{
	ssize_t n;

	memset(l, 0, sizeof(*l));
	(void)linux_clock(l, &l->started);
	l->platform.user = l;
	l->platform.random = linux_random;
	l->platform.clock = linux_clock;
	l->platform.clock_hz = 1;
	l->platform.measurements = linux_measurements;
	l->platform.profile = AEGIS_LINUX_PROFILE;
	l->platform.version = AEGIS_LINUX_VERSION;
	l->platform.status = linux_status;
	/* the program measures itself, as the Python prover does: the component PROVER, always the last */
	n = readlink("/proc/self/exe", l->self, sizeof(l->self) - 1);
	if (n <= 0) return -1;
	l->self[n] = '\0';
	strcpy(l->group[0].label, "PROVER");
	l->group[0].path[0] = l->self;
	l->group[0].paths = 1;
	l->groups = 1;
	return 0;
}

int aegis_linux_add_measure(struct aegis_linux *l, char *spec)
{
	char *eq = strchr(spec, '='), *p;
	size_t prover = l->groups - 1, paths = 0;
	const char *path[AEGIS_LINUX_MAX_FILES];

	if (eq == NULL || eq == spec || (size_t)(eq - spec) > AEGIS_LINUX_LABEL_MAX || l->groups > AEGIS_LINUX_MAX_GROUPS) {
		return -1;
	}
	for (p = eq + 1; p != NULL;) {
		char *comma = strchr(p, ',');

		if (comma != NULL) *comma++ = '\0';
		if (*p == '\0' || paths == AEGIS_LINUX_MAX_FILES) return -1;
		path[paths++] = p;
		p = comma;
	}
	/* in front of PROVER, which stays the last component */
	l->group[prover + 1] = l->group[prover];
	memset(&l->group[prover], 0, sizeof(l->group[prover]));
	memcpy(l->group[prover].label, spec, (size_t)(eq - spec));
	memcpy(l->group[prover].path, path, paths * sizeof(path[0]));
	l->group[prover].paths = paths;
	l->groups++;
	return 0;
}

/* One 32-byte secret of the state directory (dir is open on it): read it, or at the first start make it from the
 * kernel's generator. Written to a new file that only the owner can read and then renamed, so a half-written secret
 * is never used. A file that is not this user's own, that anyone else can read or write, that is a link or of
 * another length is refused rather than trusted. */
static int secret(int dir, const char *name, uint8_t out[AEGIS_SEED_LEN])
{
	char tmp[64];
	struct stat st;
	int fd, ok;

	if (snprintf(tmp, sizeof(tmp), "%s.new", name) >= (int)sizeof(tmp)) return -1;
	fd = openat(dir, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0 && errno == ENOENT) {
		if (getrandom(out, AEGIS_SEED_LEN, 0) != (ssize_t)AEGIS_SEED_LEN) return -1;
		(void)unlinkat(dir, tmp, 0);
		fd = openat(dir, tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
		if (fd < 0) return -1;
		ok = write(fd, out, AEGIS_SEED_LEN) == (ssize_t)AEGIS_SEED_LEN && fsync(fd) == 0;
		ok = close(fd) == 0 && ok;
		aegis_wipe(out, AEGIS_SEED_LEN); /* what is used is what is read back below */
		if (!ok || renameat(dir, tmp, dir, name) != 0) return -1;
		fd = openat(dir, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	}
	if (fd < 0) return -1;
	ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == geteuid() && (st.st_mode & 077) == 0 &&
	     st.st_size == (off_t)AEGIS_SEED_LEN && read(fd, out, AEGIS_SEED_LEN) == (ssize_t)AEGIS_SEED_LEN;
	close(fd);
	return ok ? 0 : -1;
}

/* The state directory, made 0700 at the first start. One that exists must be this user's own and writable by
 * nobody else: whoever can write it can replace the secrets in it. Returns it open, or -1. */
static int state_dir_open(const char *path)
{
	struct stat st;
	int fd;

	if (mkdir(path, 0700) != 0 && errno != EEXIST) return -1;
	fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0) return -1;
	if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 022) != 0) {
		close(fd);
		return -1;
	}
	return fd;
}

int aegis_linux_start(struct aegis_linux *l, const char *state_dir, const uint8_t *verifier_pk)
{
	uint8_t seed[AEGIS_SEED_LEN], root[AEGIS_SEED_LEN];
	struct aegis_config cfg = {
		.platform = &l->platform,
		.verifier_pk = verifier_pk,
		.identity_seed = seed,
		.exchange_root = root,
		.work = l->work,
		.work_len = sizeof(l->work),
	};
	int rc = AEGIS_ERR_IDENTITY, dir = state_dir_open(state_dir);

	if (dir < 0) return rc;
	if (secret(dir, "identity.seed", seed) == 0 && secret(dir, "exchange.root", root) == 0) {
		rc = AEGIS_PROVER_INIT(&l->prover, &cfg);
	}
	close(dir);
	aegis_wipe(seed, sizeof(seed)); /* the core has made the key pair and copied the root */
	aegis_wipe(root, sizeof(root));
	return rc;
}

/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Minimal newlib system-call stubs for a bare-metal image. Output goes through
 * _write(), provided by the TF-M platform's uart_stdout.c.
 */
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

int _close(int fd) { (void)fd; return -1; }
int _fstat(int fd, struct stat *st) { (void)fd; st->st_mode = S_IFCHR; return 0; }
int _isatty(int fd) { (void)fd; return 1; }
off_t _lseek(int fd, off_t off, int whence) { (void)fd; (void)off; (void)whence; return 0; }
int _read(int fd, char *buf, int len) { (void)fd; (void)buf; (void)len; return 0; }
int _kill(int pid, int sig) { (void)pid; (void)sig; errno = EINVAL; return -1; }
int _getpid(void) { return 1; }
void _exit(int status) { (void)status; for (;;) { } }

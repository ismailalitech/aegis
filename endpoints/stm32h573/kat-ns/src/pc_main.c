/* SPDX-License-Identifier: Apache-2.0
 * PC harness of kat_core: one request per stdin line, replies on stdout. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kat_core.h"
static void out(const char *s) { fputs(s, stdout); }
int main(void)
{
	static char line[1 << 16];
	while (fgets(line, sizeof(line), stdin)) {
		line[strcspn(line, "\r\n")] = 0;
		if (line[0]) { kat_handle(line, out); fflush(stdout); }
	}
	return 0;
}

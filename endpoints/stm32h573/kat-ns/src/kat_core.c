/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * ACVP test core for the Aegis STM32 crypto configuration: mldsa-native (ML-DSA-65, reduced RAM)
 * and mlkem-native (ML-KEM-768) with exactly the configuration headers of the secure partition.
 * Platform independent: the PC build reads lines from stdin, the STM32 build from the UART.
 *
 * Requests (hex fields, "-" for an empty field) -> reply "OK <fields>" or "ERR <reason>":
 *   KEMKG  <d||z>                 -> OK <ek> <dk>
 *   KEMENC <ek> <m>               -> OK <c> <k>
 *   KEMDEC <dk> <c>               -> OK <k>
 *   DSAKG  <seed>                 -> OK <pk> <sk>
 *   DSASIG <sk> <rnd> <ext> <pre> <m>   -> OK <sig>      (ML-DSA.Sign_internal on pre || m, or mu if ext=1)
 *   DSAVER <pk> <sig> <ext> <pre> <m>   -> OK <0|1>      (1 = signature valid)
 */
#include <stdint.h>
#include <string.h>

#include "kat_core.h"
#define MLD_CONFIG_FILE "aegis_mldsa_config.h"
#include "mldsa_native.h"
#define MLK_CONFIG_FILE "aegis_mlkem_config.h"
#include "mlkem_native.h"

#define MAXF 8448u /* largest binary field: an 8192-byte message (+ margin) */

static uint8_t f[6][MAXF];
static size_t fl[6];
static uint8_t o1[MLDSA_SECRETKEYBYTES(65)], o2[MLDSA_SECRETKEYBYTES(65)];

static int nib(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/* Split "CMD a b c" into hex fields; returns field count or -1. */
static int parse(const char *s, int want)
{
	int n = 0;

	while (*s && *s != ' ') s++;
	while (*s == ' ') {
		size_t k = 0;

		s++;
		if (n >= want) return -1;
		if (*s == '-' && (s[1] == ' ' || s[1] == '\0')) {
			s++;
		} else {
			while (*s && *s != ' ') {
				int h = nib(s[0]), l = s[1] ? nib(s[1]) : -1;

				if (h < 0 || l < 0 || k >= MAXF) return -1;
				f[n][k++] = (uint8_t)((h << 4) | l);
				s += 2;
			}
		}
		fl[n++] = k;
	}
	return n == want ? n : -1;
}

static void emit_hex(kat_out_fn out, const uint8_t *p, size_t n)
{
	static const char d[] = "0123456789abcdef";
	char b[129];
	size_t k = 0;

	for (size_t i = 0; i < n; i++) {
		b[k++] = d[p[i] >> 4];
		b[k++] = d[p[i] & 15];
		if (k == 128) {
			b[k] = 0;
			out(b);
			k = 0;
		}
	}
	b[k] = 0;
	out(b);
}

void kat_handle(const char *line, kat_out_fn out)
{
	if (!strncmp(line, "KEMKG ", 6)) {
		if (parse(line, 1) != 1 || fl[0] != 64 || aegis_mlkem_keypair_derand(o1, o2, f[0])) goto bad;
		out("OK "); emit_hex(out, o1, MLKEM_PUBLICKEYBYTES(768)); out(" ");
		emit_hex(out, o2, MLKEM_SECRETKEYBYTES(768)); out("\r\n");
	} else if (!strncmp(line, "KEMENC ", 7)) {
		if (parse(line, 2) != 2 || fl[0] != MLKEM_PUBLICKEYBYTES(768) || fl[1] != 32 ||
		    aegis_mlkem_enc_derand(o1, o2, f[0], f[1])) goto bad;
		out("OK "); emit_hex(out, o1, MLKEM_CIPHERTEXTBYTES(768)); out(" "); emit_hex(out, o2, 32); out("\r\n");
	} else if (!strncmp(line, "KEMDEC ", 7)) {
		if (parse(line, 2) != 2 || fl[0] != MLKEM_SECRETKEYBYTES(768) || fl[1] != MLKEM_CIPHERTEXTBYTES(768) ||
		    aegis_mlkem_dec(o1, f[1], f[0])) goto bad;
		out("OK "); emit_hex(out, o1, 32); out("\r\n");
	} else if (!strncmp(line, "DSAKG ", 6)) {
		if (parse(line, 1) != 1 || fl[0] != 32 || aegis_mldsa_keypair_internal(o1, o2, f[0])) goto bad;
		out("OK "); emit_hex(out, o1, MLDSA_PUBLICKEYBYTES(65)); out(" ");
		emit_hex(out, o2, MLDSA_SECRETKEYBYTES(65)); out("\r\n");
	} else if (!strncmp(line, "DSASIG ", 7)) {
		if (parse(line, 5) != 5 || fl[0] != MLDSA_SECRETKEYBYTES(65) || fl[1] != 32 || fl[2] != 1) goto bad;
		if (aegis_mldsa_signature_internal(o1, f[4], fl[4], f[3], fl[3], f[1], f[0], f[2][0])) goto bad;
		out("OK "); emit_hex(out, o1, MLDSA_BYTES(65)); out("\r\n");
	} else if (!strncmp(line, "DSAVER ", 7)) {
		if (parse(line, 5) != 5 || fl[0] != MLDSA_PUBLICKEYBYTES(65) || fl[2] != 1) goto bad;
		out(fl[1] == MLDSA_BYTES(65) &&
				    aegis_mldsa_verify_internal(f[1], f[4], fl[4], f[3], fl[3], f[0], f[2][0]) == 0
			    ? "OK 1\r\n"
			    : "OK 0\r\n");
	} else {
		goto bad;
	}
	return;
bad:
	out("ERR bad-request\r\n");
}

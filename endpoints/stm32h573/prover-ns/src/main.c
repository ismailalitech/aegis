/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Aegis prover, Non-Secure image for TF-M on the STM32H573I-DK (step 1: serial transport).
 *
 * The Non-Secure side never holds a key. It forwards a verifier's challenge to the
 * TF-M Initial Attestation service, which returns a PSA attestation token (COSE_Sign1,
 * ES256) containing the challenge and the boot measurements that BL2 (MCUboot)
 * recorded for the Secure and Non-Secure images.
 *
 * The same line protocol is served on the ST-LINK virtual COM port (115200 8N1) and on
 * TCP port 7444 (one request per connection, DHCP address printed on the console):
 *   device -> "AEGIS-PROVER <ver> ready"            (console only)
 *   host   -> "CHAL <64 hex digits>"                32-byte challenge
 *   device -> "TOKEN <length> <hex> END"  or  "ERR <reason>"
 *   host   -> "PQKEY"
 *   device -> "PQKEY <length> <hex> END"            ML-DSA-65 public key of this chip
 *   host   -> "PQCHAL <64 hex digits>"
 *   device -> "PQTOKEN <toklen> <hex> <siglen> <hex> END"
 *             token from TF-M, signature by the Aegis secure partition (ML-DSA-65 key derived
 *             from the chip's DHUK) over "aegis-endpoint-quote-v1\0" || token
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "board.h"
#include "ethernetif.h"
#include "lwip/dhcp.h"
#include "lwip/init.h"
#include "lwip/tcp.h"
#include "lwip/timeouts.h"
#include "psa/crypto.h"
#include "psa/client.h"
#include "psa/initial_attestation.h"
#include "psa_manifest/sid.h"
#include "stm32h5xx.h"
#include "tfm_ns_interface.h"
#include "uart_stdout.h"

extern uint32_t tfm_ns_interface_init(void);

#define CHALLENGE_LEN 32u
#define REQ_LINE_MAX      96u

static uint8_t token[PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE];

#define PROVER_PORT 7444u

static volatile uint32_t ticks_ms;

void SysTick_Handler(void)
{
	ticks_ms++;
	HAL_IncTick();
}

u32_t sys_now(void)
{
	return ticks_ms;
}

uint32_t aegis_rand32(void)
{
	uint32_t r = 0;

	(void)psa_generate_random((uint8_t *)&r, sizeof(r));
	return r;
}

void aegis_lwip_assert(const char *msg)
{
	(void)stdio_output_string("LWIP-ASSERT ", 12);
	(void)stdio_output_string(msg, strlen(msg));
	for (;;) {
	}
}

/* Non-blocking: collect console characters into a line; returns 1 when a line is complete. */
static int uart_poll_line(char *buf, size_t max, size_t *n)
{
	USART_TypeDef *u = COM_INSTANCE;

	if (u->ISR & (USART_ISR_ORE | USART_ISR_FE | USART_ISR_NE)) {
		u->ICR = USART_ICR_ORECF | USART_ICR_FECF | USART_ICR_NECF;
	}
	while (u->ISR & USART_ISR_RXNE_RXFNE) {
		char c = (char)(u->RDR & 0xFFu);

		if (c == '\r' || c == '\n') {
			if (*n) {
				buf[*n] = '\0';
				*n = 0;
				return 1;
			}
			continue;
		}
		if (*n + 1 < max) {
			buf[(*n)++] = c;
		}
	}
	return 0;
}

static int hex_nibble(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static int parse_hex(const char *s, uint8_t *out, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		int hi = hex_nibble(s[2 * i]), lo = hex_nibble(s[2 * i + 1]);

		if (hi < 0 || lo < 0) {
			return -1;
		}
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return s[2 * len] == '\0' ? 0 : -1;
}

/* Builds "TOKEN <len> <hex> END\r\n" (or "ERR ...\r\n") for a request line into out. */
#define PQ_PK_LEN  1952u
#define PQ_SIG_LEN 3309u
#define AEGIS_PQ_GET_PUBKEY 1
#define AEGIS_PQ_QUOTE      2

static uint8_t pq_buf[PQ_PK_LEN > PQ_SIG_LEN ? PQ_PK_LEN : PQ_SIG_LEN];

static size_t put_hex_into(char *out, const uint8_t *p, size_t n)
{
	static const char d[] = "0123456789abcdef";

	for (size_t i = 0; i < n; i++) {
		out[2 * i] = d[p[i] >> 4];
		out[2 * i + 1] = d[p[i] & 0xF];
	}
	return 2 * n;
}

static size_t handle_pq(const char *line, char *out, size_t max)
{
	uint8_t challenge[CHALLENGE_LEN];
	psa_status_t st;
	size_t k;

	if (strcmp(line, "PQKEY") == 0) {
		psa_outvec o[1] = {{pq_buf, PQ_PK_LEN}};

		st = psa_call(AEGIS_PQ_SERVICE_HANDLE, AEGIS_PQ_GET_PUBKEY, NULL, 0, o, 1);
		if (st != PSA_SUCCESS || o[0].len != PQ_PK_LEN) {
			return (size_t)snprintf(out, max, "ERR pq %ld\r\n", (long)st);
		}
		k = (size_t)snprintf(out, max, "PQKEY %u ", (unsigned int)PQ_PK_LEN);
		k += put_hex_into(out + k, pq_buf, PQ_PK_LEN);
		memcpy(out + k, " END\r\n", 6);
		return k + 6;
	}
	if (parse_hex(line + 7, challenge, CHALLENGE_LEN) != 0) {
		return (size_t)snprintf(out, max, "ERR bad-request\r\n");
	}
	{
		psa_invec i[1] = {{challenge, CHALLENGE_LEN}};
		psa_outvec o[2] = {{token, sizeof(token)}, {pq_buf, PQ_SIG_LEN}};

		st = psa_call(AEGIS_PQ_SERVICE_HANDLE, AEGIS_PQ_QUOTE, i, 1, o, 2);
		if (st != PSA_SUCCESS) {
			return (size_t)snprintf(out, max, "ERR pq %ld\r\n", (long)st);
		}
		k = (size_t)snprintf(out, max, "PQTOKEN %u ", (unsigned int)o[0].len);
		k += put_hex_into(out + k, token, o[0].len);
		k += (size_t)snprintf(out + k, max - k, " %u ", (unsigned int)o[1].len);
		k += put_hex_into(out + k, pq_buf, o[1].len);
		memcpy(out + k, " END\r\n", 6);
		return k + 6;
	}
}

static size_t handle_request(const char *line, char *out, size_t max)
{
	static const char d[] = "0123456789abcdef";
	uint8_t challenge[CHALLENGE_LEN];
	size_t token_len = 0, k;
	psa_status_t st;

	if (strcmp(line, "PQKEY") == 0 || strncmp(line, "PQCHAL ", 7) == 0) {
		return handle_pq(line, out, max);
	}

	if (strncmp(line, "CHAL ", 5) != 0 || parse_hex(line + 5, challenge, CHALLENGE_LEN) != 0) {
		return (size_t)snprintf(out, max, "ERR bad-request\r\n");
	}
	st = psa_initial_attest_get_token(challenge, CHALLENGE_LEN, token, sizeof(token), &token_len);
	if (st != PSA_SUCCESS) {
		return (size_t)snprintf(out, max, "ERR psa %ld\r\n", (long)st);
	}
	k = (size_t)snprintf(out, max, "TOKEN %u ", (unsigned int)token_len);
	if (k + 2 * token_len + 8 > max) {
		return (size_t)snprintf(out, max, "ERR too-long\r\n");
	}
	for (size_t i = 0; i < token_len; i++) {
		out[k++] = d[token[i] >> 4];
		out[k++] = d[token[i] & 0xF];
	}
	memcpy(out + k, " END\r\n", 6);
	return k + 6;
}

static char reply[2 * (PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE + PQ_SIG_LEN) + 96];

/* Console output: one blocking UART transmit per 128-byte piece. */
static void put_n(const char *s, size_t n)
{
	while (n) {
		size_t c = n > 128 ? 128 : n;

		(void)stdio_output_string(s, c);
		s += c;
		n -= c;
	}
}

static void put(const char *s)
{
	put_n(s, strlen(s));
}

/* ---- TCP server: one request line per connection ---------------------------------------- */

struct conn {
	char line[REQ_LINE_MAX];
	size_t n;
	int busy;
};

static struct conn conn_slot;

static err_t on_sent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
	struct conn *c = arg;

	(void)len;
	if (tcp_sndbuf(pcb) == TCP_SND_BUF) {
		tcp_arg(pcb, NULL);
		tcp_recv(pcb, NULL);
		tcp_sent(pcb, NULL);
		if (c) {
			c->busy = 0;
		}
		tcp_close(pcb);
	}
	return ERR_OK;
}

static err_t on_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
	struct conn *c = arg;

	if (p == NULL || err != ERR_OK) {
		if (p) {
			pbuf_free(p);
		}
		tcp_arg(pcb, NULL);
		if (c) {
			c->busy = 0;
		}
		tcp_close(pcb);
		return ERR_OK;
	}
	for (struct pbuf *q = p; q; q = q->next) {
		const char *b = q->payload;

		for (u16_t i = 0; i < q->len; i++) {
			if (b[i] == '\n' || b[i] == '\r') {
				if (c->n) {
					size_t len;

					c->line[c->n] = '\0';
					c->n = 0;
					len = handle_request(c->line, reply, sizeof(reply));
					tcp_sent(pcb, on_sent);
					tcp_write(pcb, reply, (u16_t)len, TCP_WRITE_FLAG_COPY);
					tcp_output(pcb);
				}
			} else if (c->n + 1 < sizeof(c->line)) {
				c->line[c->n++] = b[i];
			}
		}
	}
	tcp_recved(pcb, p->tot_len);
	pbuf_free(p);
	return ERR_OK;
}

static err_t on_accept(void *arg, struct tcp_pcb *pcb, err_t err)
{
	(void)arg;
	if (err != ERR_OK || pcb == NULL) {
		return ERR_VAL;
	}
	if (conn_slot.busy) {
		tcp_abort(pcb);
		return ERR_ABRT;
	}
	conn_slot.busy = 1;
	conn_slot.n = 0;
	tcp_arg(pcb, &conn_slot);
	tcp_recv(pcb, on_recv);
	return ERR_OK;
}

static void on_netif_status(struct netif *n)
{
	char b[64];

	if (!ip4_addr_isany_val(*netif_ip4_addr(n))) {
		snprintf(b, sizeof(b), "AEGIS-NET ip=%s port=%u\r\n", ip4addr_ntoa(netif_ip4_addr(n)),
			 (unsigned int)PROVER_PORT);
		put(b);
	}
}

/* Fixed locally administered unicast MAC. Reading the device UID (0x08FFF800) from the
 * Non-Secure world stopped the image on this board (2026-11-16), so the UID is not used. */
static void on_link(struct netif *n)
{
	put(netif_is_link_up(n) ? "AEGIS-NET link=up\r\n" : "AEGIS-NET link=down\r\n");
}

static void mac_default(uint8_t mac[6])
{
	static const uint8_t m[6] = {0x02, 0xAE, 0x9E, 0x15, 0x73, 0x01};

	memcpy(mac, m, 6);
}

int main(void)
{
	static struct netif netif;
	char line[REQ_LINE_MAX];
	size_t n = 0;
	uint8_t mac[6];
	struct tcp_pcb *srv;
	char b[128];

	stdio_init();
	(void)tfm_ns_interface_init();
	(void)psa_crypto_init();
	SystemCoreClockUpdate();
	SysTick_Config(SystemCoreClock / 1000u);

	put("\r\nAEGIS-PROVER " AEGIS_PROVER_VERSION " ready\r\n");

	lwip_init();
	mac_default(mac);
	snprintf(b, sizeof(b), "AEGIS-NET mac=%02x:%02x:%02x:%02x:%02x:%02x\r\n",
		 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	put(b);
	if (aegis_eth_init(&netif, mac) != 0) {
		put("AEGIS-NET eth-init-failed\r\n");
	} else {
		netif_set_hostname(&netif, "aegis-stm32h573");
		netif_set_status_callback(&netif, on_netif_status);
		netif_set_link_callback(&netif, on_link);
		dhcp_start(&netif);
		srv = tcp_new();
		if (srv && tcp_bind(srv, IP_ADDR_ANY, PROVER_PORT) == ERR_OK) {
			srv = tcp_listen(srv);
			tcp_accept(srv, on_accept);
		}
	}

	put("AEGIS-NET eth-init-ok\r\n");
	for (uint32_t last = 0;;) {
		if (ticks_ms - last >= 5000u) {
			last = ticks_ms;
			uint32_t r[5];

			aegis_eth_phy_regs(r);
			snprintf(b, sizeof(b), "AEGIS-NET t=%lus link=%d phy=%04lx:%04lx bcr=%04lx bsr=%04lx scsr=%04lx\r\n",
				 (unsigned long)(ticks_ms / 1000u), aegis_eth_link_up(), (unsigned long)r[0],
				 (unsigned long)r[1], (unsigned long)r[2], (unsigned long)r[3], (unsigned long)r[4]);
			put(b);
		}
		aegis_eth_poll(&netif);
		sys_check_timeouts();
		if (uart_poll_line(line, sizeof(line), &n)) {
			size_t len = handle_request(line, reply, sizeof(reply));

			put_n(reply, len);
		}
	}
	return 0;
}

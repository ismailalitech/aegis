/* SPDX-License-Identifier: Apache-2.0
 *
 * Aegis non-secure network prover for the FRDM-RW612 (TF-M). It holds no key and computes no proof: every request
 * line that arrives on TCP port 7444 goes to the Aegis secure partition with psa_call, and the reply goes back,
 * one request per connection, as with the other Aegis endpoints. The MAC address is 02:ae plus the first four bytes
 * of the partition's ML-DSA-65 public key.
 */
#include <stdio.h>
#include <string.h>

#include "app.h"
#include "board.h"
#include "ethernetif.h"
#include "fsl_debug_console.h"
#include "fsl_phy.h"
#include "lwip/dhcp.h"
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/tcp.h"
#include "lwip/timeouts.h"
#include "netif/ethernet.h"
#include "psa/client.h"
#include "psa/crypto.h"
#include "aegis_pq_defs.h"

#define PORT        7444
#define AEGIS_NS_LINE_MAX    14600u /* AEGIS_LINE_MAX: PQKEMFIN with a 6 KB credential, in hex */
#define AEGIS_NS_REPLY_MAX   9600u  /* AEGIS_REPLY_MAX */
#define IDLE_POLLS  20     /* x 500 ms: a client that sends nothing for 10 s is dropped */

static char line[AEGIS_NS_LINE_MAX + 1];
static char reply[AEGIS_NS_REPLY_MAX + 2];
static size_t line_len, reply_len, reply_sent;
static struct tcp_pcb *client;
static int idle;
static uint32_t served;

unsigned int aegis_rand32(void)
{
	uint32_t r = 0;

	(void)psa_generate_random((uint8_t *)&r, sizeof(r));
	return r;
}

/* Replaces the device's weak SystemInit for the non-secure image. TF-M has already set clocks, the flash cache and
 * the FPU access rights; the device version would also read the flash-cache registers, which the Aegis target_cfg.c
 * makes secure-only (a non-secure access there is a SecureFault). Only the FPU access needs setting here. */
void SystemInit(void)
{
#if ((__FPU_PRESENT == 1) && (__FPU_USED == 1))
	SCB->CPACR |= ((3UL << 10 * 2) | (3UL << 11 * 2));
#endif
}

void SysTick_Handler(void)
{
	time_isr();
}

/* one line to the secure partition; the reply (without line end) into reply[] */
static void secure_request(const char *l, size_t n)
{
	psa_invec in = {l, n};
	psa_outvec out = {reply, AEGIS_NS_REPLY_MAX};
	psa_status_t st = psa_call(AEGIS_PQ_SERVICE_HANDLE, AEGIS_PQ_LINE, &in, 1, &out, 1);

	if (st == PSA_SUCCESS) {
		reply_len = out.len;
	} else {
		reply_len = (size_t)snprintf(reply, AEGIS_NS_REPLY_MAX, "ERR secure %d", (int)st);
	}
}

static void finish(struct tcp_pcb *pcb, int abort)
{
	tcp_arg(pcb, NULL);
	tcp_recv(pcb, NULL);
	tcp_sent(pcb, NULL);
	tcp_err(pcb, NULL);
	tcp_poll(pcb, NULL, 0);
	if (abort || tcp_close(pcb) != ERR_OK) {
		tcp_abort(pcb);
	}
	client = NULL;
}

static void send_more(struct tcp_pcb *pcb)
{
	while (reply_sent < reply_len) {
		size_t room = tcp_sndbuf(pcb), n = reply_len - reply_sent;

		if (room == 0) {
			break;
		}
		if (n > room) {
			n = room;
		}
		if (tcp_write(pcb, reply + reply_sent, (u16_t)n, TCP_WRITE_FLAG_COPY) != ERR_OK) {
			break;
		}
		reply_sent += n;
	}
	tcp_output(pcb);
}

static err_t on_sent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
	(void)arg;
	(void)len;
	idle = 0;
	if (reply_sent < reply_len) {
		send_more(pcb);
	} else if (tcp_sndqueuelen(pcb) == 0) {
		finish(pcb, 0);
	}
	return ERR_OK;
}

static err_t on_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
	char *nl;

	(void)arg;
	if (p == NULL || err != ERR_OK) {
		if (p) {
			pbuf_free(p);
		}
		finish(pcb, 0);
		return ERR_OK;
	}
	idle = 0;
	if (reply_len) { /* one request per connection: ignore anything after it */
		tcp_recved(pcb, p->tot_len);
		pbuf_free(p);
		return ERR_OK;
	}
	if (line_len + p->tot_len <= AEGIS_NS_LINE_MAX) {
		pbuf_copy_partial(p, line + line_len, p->tot_len, 0);
		line_len += p->tot_len;
	} else {
		line_len = AEGIS_NS_LINE_MAX + 1; /* too long: answered below */
	}
	tcp_recved(pcb, p->tot_len);
	pbuf_free(p);
	if (line_len > AEGIS_NS_LINE_MAX) {
		reply_len = (size_t)snprintf(reply, AEGIS_NS_REPLY_MAX, "ERR too-long");
	} else {
		line[line_len] = '\0';
		nl = memchr(line, '\n', line_len);
		if (nl == NULL) {
			return ERR_OK; /* wait for the rest of the line */
		}
		*nl = '\0';
		if (nl > line && nl[-1] == '\r') {
			nl[-1] = '\0';
		}
		secure_request(line, strlen(line));
		served++;
	}
	reply[reply_len++] = '\r';
	reply[reply_len++] = '\n';
	reply_sent = 0;
	send_more(pcb);
	return ERR_OK;
}

static void on_err(void *arg, err_t err)
{
	(void)arg;
	(void)err;
	client = NULL; /* the pcb is already freed by lwIP */
}

static err_t on_poll(void *arg, struct tcp_pcb *pcb)
{
	(void)arg;
	if (++idle >= IDLE_POLLS) {
		finish(pcb, 1);
		return ERR_ABRT;
	}
	return ERR_OK;
}

static err_t on_accept(void *arg, struct tcp_pcb *pcb, err_t err)
{
	(void)arg;
	if (err != ERR_OK || pcb == NULL) {
		return ERR_VAL;
	}
	if (client != NULL) { /* one request at a time: a second client is refused */
		tcp_abort(pcb);
		return ERR_ABRT;
	}
	client = pcb;
	line_len = reply_len = reply_sent = 0;
	idle = 0;
	tcp_recv(pcb, on_recv);
	tcp_sent(pcb, on_sent);
	tcp_err(pcb, on_err);
	tcp_poll(pcb, on_poll, 1);
	return ERR_OK;
}

static int hexval(char c)
{
	return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

/* MAC = 02:ae + the first 4 bytes of the ML-DSA public key, from the partition's PQKEY reply "PQKEY 1952 <hex> END" */
static int mac_from_key(uint8_t mac[6])
{
	const char *h;

	secure_request("PQKEY", 5);
	reply[reply_len < AEGIS_NS_REPLY_MAX ? reply_len : AEGIS_NS_REPLY_MAX - 1] = '\0';
	if (strncmp(reply, "PQKEY 1952 ", 11) != 0) {
		return -1;
	}
	h = reply + 11;
	mac[0] = 0x02;
	mac[1] = 0xae;
	for (int i = 0; i < 4; i++) {
		int a = hexval(h[2 * i]), b = hexval(h[2 * i + 1]);

		if (a < 0 || b < 0) {
			return -1;
		}
		mac[2 + i] = (uint8_t)(a << 4 | b);
	}
	return 0;
}

int main(void)
{
	static phy_handle_t phy;
	static struct netif netif;
	ethernetif_config_t cfg = {.phyHandle = &phy, .phyAddr = EXAMPLE_PHY_ADDRESS, .phyOps = EXAMPLE_PHY_OPS,
				   .phyResource = EXAMPLE_PHY_RESOURCE};
	struct tcp_pcb *listener;
	int bound = 0;

	BOARD_InitHardware();
	time_init();
#if defined(AEGIS_NS_PROBE_ADDR)
	/* TEST BUILD ONLY (tools: endpoints/rw612/tfm/probe.sh): read one peripheral register from the non-secure side.
	 * For a peripheral the Aegis target_cfg.c makes secure-only, the read must fault and never print "read ok". */
	PRINTF("aegis-probe: non-secure read of %s at 0x%08x ...\r\n", AEGIS_NS_PROBE_NAME, (unsigned)AEGIS_NS_PROBE_ADDR);
	{
		volatile uint32_t v = *(volatile uint32_t *)(uintptr_t)AEGIS_NS_PROBE_ADDR;

		PRINTF("aegis-probe: read ok, value 0x%08x\r\n", (unsigned)v);
	}
#endif
	PRINTF("AEGIS-RW612-TFM-PROVER %s (non-secure network side; the key and the proofs are in the secure partition)\r\n",
	       "0.2.0");
	if (mac_from_key(cfg.macAddress) != 0) {
		static const uint8_t fallback[6] = {0x02, 0xae, 0x00, 0x00, 0x00, 0x01};

		memcpy(cfg.macAddress, fallback, 6);
		PRINTF("aegis: no key from the secure partition (%.40s); fixed MAC\r\n", reply);
	}
	{
		/* the lite debug console ignores the 0 flag of %02x, so format the address by hand */
		static const char hx[] = "0123456789abcdef";
		char m[18];

		for (int i = 0; i < 6; i++) {
			m[3 * i] = hx[cfg.macAddress[i] >> 4];
			m[3 * i + 1] = hx[cfg.macAddress[i] & 15];
			m[3 * i + 2] = i < 5 ? ':' : '\0';
		}
		PRINTF("aegis: mac %s\r\n", m);
	}
	cfg.srcClockHz = EXAMPLE_CLOCK_FREQ;
	lwip_init();
	netif_add(&netif, NULL, NULL, NULL, &cfg, ethernetif0_init, ethernet_input);
	netif_set_default(&netif);
	netif_set_up(&netif);
	while (ethernetif_wait_linkup(&netif, 5000) != ERR_OK) {
		PRINTF("aegis: no Ethernet link yet\r\n");
	}
	dhcp_start(&netif);
	listener = tcp_new();
	tcp_bind(listener, IP_ADDR_ANY, PORT);
	listener = tcp_listen(listener);
	tcp_accept(listener, on_accept);
	for (;;) {
		ethernetif_input(&netif);
		sys_check_timeouts();
		if (!bound && dhcp_supplied_address(&netif)) {
			bound = 1;
			PRINTF("aegis: address %s, listening on %d\r\n", ipaddr_ntoa(&netif.ip_addr), PORT);
		}
	}
}

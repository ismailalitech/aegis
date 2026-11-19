/* SPDX-License-Identifier: Apache-2.0
 *
 * Aegis prover for the NXP FRDM-RW612 (RW612: Cortex-M33 at 260 MHz, ELS, Ethernet with a KSZ8081 PHY), Zephyr.
 *
 * At start:
 *   seed      = ELS: HMAC-SHA256(CKDF(die master key), "aegis-rw612-mldsa65-seed-v1")   (aegis_els.c)
 *   prov_root = ELS: HMAC-SHA256(CKDF(die master key), "aegis-rw612-provision-root-v1")
 *   (pk, sk)  = ML-DSA-65.KeyGen_internal(seed); the seed is wiped
 * Then DHCP on the Ethernet port, and the Aegis line protocol on TCP 7444 (aegis_proto.c), one request per
 * connection. The quote reports one measurement, APP: SHA-256 of this firmware image as it sits in flash.
 * The MAC address is 02:ae + the first 4 bytes of the ML-DSA public key, as on the STM32 endpoints.
 */
#include <string.h>
#include <zephyr/drivers/entropy.h>
#include <zephyr/kernel.h>
#include <zephyr/net/ethernet.h>
#include <zephyr/net/ethernet_mgmt.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/dhcpv4.h>
#include <zephyr/net/socket.h>
#include <zephyr/sys/printk.h>

#include "aegis_els.h"
#include "aegis_proto.h"
#include "gateway_pk.h"
#include "aegis_sha256.h"

#define PORT 7444

extern char __rom_region_start[];
extern char _flash_used[];

static const struct device *const trng = DEVICE_DT_GET(DT_CHOSEN(zephyr_entropy));
static const uint8_t gateway_pk[1952] = AEGIS_GATEWAY_PK;
static char line[AEGIS_LINE_MAX + 2];
static char reply[AEGIS_REPLY_MAX];

static int dev_random(uint8_t *out, size_t n)
{
	return entropy_get_entropy(trng, out, (uint16_t)n);
}

static void dev_measure(uint8_t out[32], size_t *len)
{
	*len = (size_t)_flash_used;
	sha256((const uint8_t *)__rom_region_start, *len, out);
}

static uint32_t dev_uptime(void)
{
	return (uint32_t)(k_uptime_get() / 1000);
}

/* The session clock: Zephyr's uptime, 64 bits of milliseconds counted by the kernel from the RW612's OS timer. This
 * prover is one image with no secure side, so the clock is as trusted as the rest of the firmware ("device-key"). */
static int dev_monotonic(uint64_t *now)
{
	int64_t ms = k_uptime_get();

	if (ms < 0) {
		return -1;
	}
	*now = (uint64_t)ms / 1000u;
	return 0;
}

static const struct aegis_proto_platform platform = {
	.random = dev_random, .measure = dev_measure, .uptime_s = dev_uptime, .monotonic_s = dev_monotonic};

static K_SEM_DEFINE(got_ip, 0, 1);
static struct net_mgmt_event_callback mgmt_cb;

static void on_ipv4(struct net_mgmt_event_callback *cb, uint64_t ev, struct net_if *iface)
{
	ARG_UNUSED(cb);
	ARG_UNUSED(iface);
	if (ev == NET_EVENT_IPV4_ADDR_ADD) {
		k_sem_give(&got_ip);
	}
}

static void serve(void)
{
	struct sockaddr_in a = {0};
	struct timeval tv = {.tv_sec = 10};
	int s = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), one = 1;

	zsock_setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	a.sin_family = AF_INET;
	a.sin_port = htons(PORT);
	if (zsock_bind(s, (struct sockaddr *)&a, sizeof(a)) != 0 || zsock_listen(s, 4) != 0) {
		printk("aegis: cannot listen on %d\n", PORT);
		return;
	}
	for (;;) {
		int c = zsock_accept(s, NULL, NULL);
		size_t got = 0;
		ssize_t r;
		int n;
		char *nl = NULL;

		if (c < 0) {
			continue;
		}
		zsock_setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		while (got < AEGIS_LINE_MAX && (r = zsock_recv(c, line + got, AEGIS_LINE_MAX - got, 0)) > 0) {
			got += (size_t)r;
			nl = memchr(line, '\n', got);
			if (nl) {
				break;
			}
		}
		line[got] = 0;
		if (nl) {
			*nl = 0;
		}
		if (!nl && got >= AEGIS_LINE_MAX) {
			n = snprintf(reply, sizeof(reply), "ERR too-long");
		} else {
			n = aegis_proto_handle(line, reply, sizeof(reply));
		}
		memcpy(reply + n, "\r\n", 2);
		for (size_t off = 0; off < (size_t)n + 2;) {
			r = zsock_send(c, reply + off, (size_t)n + 2 - off, 0);
			if (r <= 0) {
				break;
			}
			off += (size_t)r;
		}
		zsock_close(c);
	}
}

static void prover(void *a, void *b, void *c)
{
	uint8_t seed[32], root[32], fp[32], meas[32];
	struct net_if *iface = net_if_get_default();
	size_t img;
	int rc;

	printk("AEGIS-RW612-PROVER %s\n", AEGIS_DEVICE_VERSION);
	rc = aegis_els_init();
	aegis_els_dump_slots();
	if (rc == 0) {
		rc = aegis_els_derive("aegis-rw612-mldsa65-seed-v1", seed);
	}
	if (rc == 0) {
		rc = aegis_els_derive("aegis-rw612-provision-root-v1", root);
	}
	if (rc != 0) {
		printk("aegis: ELS key derivation failed (%d); no prover\n", rc);
		return;
	}
	rc = aegis_proto_init(&platform, seed, root, gateway_pk);
	memset(seed, 0, sizeof(seed));
	memset(root, 0, sizeof(root));
	if (rc != 0) {
		printk("aegis: ML-DSA key generation failed\n");
		return;
	}
	sha256(aegis_proto_pk(), 1952, fp);
	dev_measure(meas, &img);
	printk("aegis: key sha256 %02x%02x%02x%02x%02x%02x%02x%02x..., image %u bytes, sha256 "
	       "%02x%02x%02x%02x%02x%02x%02x%02x...\n",
	       fp[0], fp[1], fp[2], fp[3], fp[4], fp[5], fp[6], fp[7], (unsigned)img, meas[0], meas[1], meas[2],
	       meas[3], meas[4], meas[5], meas[6], meas[7]);

	/* a stable, per-chip MAC address (locally administered), set while the interface is down */
	{
		struct ethernet_req_params p = {0};
		uint8_t *mac = p.mac_address.addr;

		mac[0] = 0x02; mac[1] = 0xae;
		memcpy(mac + 2, aegis_proto_pk(), 4);
		net_if_down(iface);
		rc = net_mgmt(NET_REQUEST_ETHERNET_SET_MAC_ADDRESS, iface, &p, sizeof(p));
		net_if_up(iface);
		printk("aegis: mac %02x:%02x:%02x:%02x:%02x:%02x%s\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
		       rc ? " (not set: the board's default stays)" : "");
	}
	net_mgmt_init_event_callback(&mgmt_cb, on_ipv4, NET_EVENT_IPV4_ADDR_ADD);
	net_mgmt_add_event_callback(&mgmt_cb);
	net_dhcpv4_start(iface);
	k_sem_take(&got_ip, K_FOREVER);
	{
		char buf[NET_IPV4_ADDR_LEN];
		struct net_if_ipv4 *ip = iface->config.ip.ipv4;

		printk("aegis: address %s, listening on %d\n",
		       net_addr_ntop(AF_INET, &ip->unicast[0].ipv4.address.in_addr, buf, sizeof(buf)), PORT);
	}
	serve();
}

/* ML-DSA-65 signing and key generation need tens of KB of stack: the prover runs in its own thread */
K_THREAD_DEFINE(aegis_prover, 65536, prover, NULL, NULL, NULL, 7, 0, 0);

int main(void)
{
	return 0;
}

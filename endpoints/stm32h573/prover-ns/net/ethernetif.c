/* SPDX-License-Identifier: Apache-2.0
 *
 * lwIP network interface for the STM32H573I-DK Ethernet MAC (RMII, PHY at MDIO address 0),
 * running in the TF-M Non-Secure world, polled (no interrupts).
 *
 * Pins (from the board's Zephyr device tree, AF11): RXD0 PC4, RXD1 PC5, REF_CLK PA1,
 * CRS_DV PA7, TX_EN PG11, TXD0 PG13, TXD1 PG12, MDIO PA2, MDC PC1.
 * Uses the ST HAL ETH driver (HAL v2 API). The Cortex-M33 has no data cache, so no
 * cache maintenance is needed around DMA buffers.
 */
#include <stddef.h>
#include <string.h>

#include "ethernetif.h"
#include "lwip/etharp.h"
#include "lwip/pbuf.h"
#include "netif/ethernet.h"
#include "stm32h5xx_hal.h"

#define PHY_ADDR      0u
#define PHY_BCR       0u
#define PHY_BSR       1u
#define PHY_SCSR      31u /* LAN8742 special control/status: bits 4:2 speed indication */
#define RX_BUF_CNT    12u
#define RX_BUF_SIZE   1536u

typedef struct {
	struct pbuf_custom pc;
	uint8_t buf[RX_BUF_SIZE] __attribute__((aligned(32)));
} rx_buf_t;

static ETH_DMADescTypeDef rx_desc[ETH_RX_DESC_CNT] __attribute__((aligned(32)));
static ETH_DMADescTypeDef tx_desc[ETH_TX_DESC_CNT] __attribute__((aligned(32)));
static rx_buf_t rx_pool[RX_BUF_CNT];
static volatile uint8_t rx_used[RX_BUF_CNT];
static uint8_t tx_buf[1536] __attribute__((aligned(32)));
static ETH_HandleTypeDef heth;
static ETH_TxPacketConfigTypeDef tx_cfg;
static uint8_t mac_addr[6];
static int link_was_up;

/* ---- HAL hooks -------------------------------------------------------------------------- */

void HAL_ETH_MspInit(ETH_HandleTypeDef *h)
{
	GPIO_InitTypeDef g = {0};

	(void)h;
	__HAL_RCC_GPIOA_CLK_ENABLE();
	__HAL_RCC_GPIOC_CLK_ENABLE();
	__HAL_RCC_GPIOG_CLK_ENABLE();
	__HAL_RCC_SBS_CLK_ENABLE();
	HAL_SBS_ETHInterfaceSelect(SBS_ETH_RMII);
	__HAL_RCC_ETH_CLK_ENABLE();
	__HAL_RCC_ETHTX_CLK_ENABLE();
	__HAL_RCC_ETHRX_CLK_ENABLE();

	g.Mode = GPIO_MODE_AF_PP;
	g.Pull = GPIO_NOPULL;
	g.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
	g.Alternate = GPIO_AF11_ETH;
	g.Pin = GPIO_PIN_1 | GPIO_PIN_2 | GPIO_PIN_7;
	HAL_GPIO_Init(GPIOA, &g);
	g.Pin = GPIO_PIN_1 | GPIO_PIN_4 | GPIO_PIN_5;
	HAL_GPIO_Init(GPIOC, &g);
	g.Pin = GPIO_PIN_11 | GPIO_PIN_12 | GPIO_PIN_13;
	HAL_GPIO_Init(GPIOG, &g);
}

static void rx_free(struct pbuf *p)
{
	rx_buf_t *b = (rx_buf_t *)p;

	rx_used[b - rx_pool] = 0;
}

void HAL_ETH_RxAllocateCallback(uint8_t **buff)
{
	for (uint32_t i = 0; i < RX_BUF_CNT; i++) {
		if (!rx_used[i]) {
			rx_used[i] = 1;
			rx_pool[i].pc.custom_free_function = rx_free;
			*buff = rx_pool[i].buf;
			return;
		}
	}
	*buff = NULL;
}

void HAL_ETH_RxLinkCallback(void **pStart, void **pEnd, uint8_t *buff, uint16_t Length)
{
	rx_buf_t *b = (rx_buf_t *)(void *)(buff - offsetof(rx_buf_t, buf));
	struct pbuf *p = pbuf_alloced_custom(PBUF_RAW, Length, PBUF_REF, &b->pc, buff, RX_BUF_SIZE);
	struct pbuf **start = (struct pbuf **)pStart, **end = (struct pbuf **)pEnd;

	p->next = NULL;
	p->tot_len = 0;
	if (*start == NULL) {
		*start = p;
	} else {
		(*end)->next = p;
	}
	*end = p;
	for (struct pbuf *q = *start; q != NULL; q = q->next) {
		q->tot_len += Length;
	}
}

void HAL_ETH_TxFreeCallback(uint32_t *buff)
{
	(void)buff; /* frames are copied into tx_buf; nothing to free */
}

/* ---- lwIP glue -------------------------------------------------------------------------- */

static err_t low_level_output(struct netif *netif, struct pbuf *p)
{
	ETH_BufferTypeDef tb = {0};

	(void)netif;
	if (p->tot_len > sizeof(tx_buf)) {
		return ERR_BUF;
	}
	pbuf_copy_partial(p, tx_buf, p->tot_len, 0);
	tb.buffer = tx_buf;
	tb.len = p->tot_len;
	tb.next = NULL;
	tx_cfg.Length = p->tot_len;
	tx_cfg.TxBuffer = &tb;
	tx_cfg.pData = (void *)tx_buf;
	if (HAL_ETH_Transmit(&heth, &tx_cfg, 20) != HAL_OK) {
		HAL_ETH_ReleaseTxPacket(&heth);
		return ERR_IF;
	}
	HAL_ETH_ReleaseTxPacket(&heth);
	return ERR_OK;
}

static err_t aegis_netif_init(struct netif *netif)
{
	netif->name[0] = 'e';
	netif->name[1] = '0';
	netif->output = etharp_output;
	netif->linkoutput = low_level_output;
	netif->mtu = 1500;
	netif->hwaddr_len = ETH_HWADDR_LEN;
	memcpy(netif->hwaddr, mac_addr, 6);
	netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET;
	return ERR_OK;
}

static int phy_read(uint32_t reg, uint32_t *val)
{
	return HAL_ETH_ReadPHYRegister(&heth, PHY_ADDR, reg, val) == HAL_OK ? 0 : -1;
}

/* Returns 1 when the PHY reports link up, and configures the MAC speed/duplex. */
static int phy_link_update(void)
{
	uint32_t bsr = 0, scsr = 0;
	ETH_MACConfigTypeDef mc;

	if (phy_read(PHY_BSR, &bsr) || phy_read(PHY_BSR, &bsr) || !(bsr & (1u << 2))) {
		return 0; /* BSR link bit is latched low: read twice */
	}
	if (!(bsr & (1u << 5)) || phy_read(PHY_SCSR, &scsr)) {
		return 0; /* auto-negotiation not complete yet */
	}
	HAL_ETH_GetMACConfig(&heth, &mc);
	switch ((scsr >> 2) & 7u) {
	case 1: mc.Speed = ETH_SPEED_10M;  mc.DuplexMode = ETH_HALFDUPLEX_MODE; break;
	case 5: mc.Speed = ETH_SPEED_10M;  mc.DuplexMode = ETH_FULLDUPLEX_MODE; break;
	case 2: mc.Speed = ETH_SPEED_100M; mc.DuplexMode = ETH_HALFDUPLEX_MODE; break;
	default: mc.Speed = ETH_SPEED_100M; mc.DuplexMode = ETH_FULLDUPLEX_MODE; break;
	}
	HAL_ETH_SetMACConfig(&heth, &mc);
	return 1;
}

int aegis_eth_init(struct netif *netif, const uint8_t mac[6])
{
	memcpy(mac_addr, mac, 6);
	heth.Instance = ETH;
	heth.Init.MACAddr = mac_addr;
	heth.Init.MediaInterface = HAL_ETH_RMII_MODE;
	heth.Init.RxDesc = rx_desc;
	heth.Init.TxDesc = tx_desc;
	heth.Init.RxBuffLen = RX_BUF_SIZE;
	if (HAL_ETH_Init(&heth) != HAL_OK) {
		return -1;
	}
	memset(&tx_cfg, 0, sizeof(tx_cfg));
	tx_cfg.Attributes = ETH_TX_PACKETS_FEATURES_CSUM | ETH_TX_PACKETS_FEATURES_CRCPAD;
	tx_cfg.ChecksumCtrl = ETH_CHECKSUM_IPHDR_PAYLOAD_INSERT_PHDR_CALC;
	tx_cfg.CRCPadCtrl = ETH_CRC_PAD_INSERT;

	if (netif_add(netif, NULL, NULL, NULL, NULL, aegis_netif_init, ethernet_input) == NULL) {
		return -2;
	}
	netif_set_default(netif);
	netif_set_up(netif);
	/* Restart auto-negotiation on the PHY. */
	(void)HAL_ETH_WritePHYRegister(&heth, PHY_ADDR, PHY_BCR, (1u << 12) | (1u << 9));
	return 0;
}

/* Call often from the main loop: link state, then received frames. */
void aegis_eth_poll(struct netif *netif)
{
	static uint32_t last_link_check;
	struct pbuf *p = NULL;

	if (HAL_GetTick() - last_link_check > 250u) {
		int up;

		last_link_check = HAL_GetTick();
		up = link_was_up ? 1 : phy_link_update();
		if (link_was_up) {
			uint32_t bsr = 0;

			up = !(phy_read(PHY_BSR, &bsr) || phy_read(PHY_BSR, &bsr)) && (bsr & (1u << 2));
		}
		if (up && !link_was_up) {
			HAL_ETH_Start(&heth);
			netif_set_link_up(netif);
		} else if (!up && link_was_up) {
			netif_set_link_down(netif);
			HAL_ETH_Stop(&heth);
		}
		link_was_up = up;
	}
	if (!link_was_up) {
		return;
	}
	while (HAL_ETH_ReadData(&heth, (void **)&p) == HAL_OK && p != NULL) {
		if (netif->input(p, netif) != ERR_OK) {
			pbuf_free(p);
		}
		p = NULL;
	}
}

int aegis_eth_link_up(void)
{
	return link_was_up;
}

/* Diagnostics: PHY identifier and basic status/control registers. */
void aegis_eth_phy_regs(uint32_t out[5])
{
	static const uint32_t regs[5] = {2, 3, PHY_BCR, PHY_BSR, PHY_SCSR};

	for (int i = 0; i < 5; i++) {
		out[i] = 0xFFFFFFFFu;
		(void)phy_read(regs[i], &out[i]);
	}
}

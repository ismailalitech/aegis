/* SPDX-License-Identifier: Apache-2.0 */
#ifndef AEGIS_ETHERNETIF_H
#define AEGIS_ETHERNETIF_H

#include <stdint.h>
#include "lwip/netif.h"

int aegis_eth_init(struct netif *netif, const uint8_t mac[6]);
void aegis_eth_poll(struct netif *netif);
int aegis_eth_link_up(void);
void aegis_eth_phy_regs(uint32_t out[5]);

#endif

/* SPDX-License-Identifier: Apache-2.0 */
#ifndef APP_H
#define APP_H
#include "fsl_phyksz8081.h"

extern phy_ksz8081_resource_t g_phy_resource;
#define EXAMPLE_ENET         ENET
#define EXAMPLE_PHY_ADDRESS  0x02U
#define EXAMPLE_PHY_OPS      &phyksz8081_ops
#define EXAMPLE_PHY_RESOURCE &g_phy_resource
#define EXAMPLE_CLOCK_FREQ   SystemCoreClock /* main clock 260 MHz, set by the secure side; CLKCTL0 is secure-only */
#define AEGIS_DEBUG_UART_CLK_HZ 20000000U /* FLEXCOMM3 via FRG3 from frg_pll, as the secure side sets it */

void BOARD_InitHardware(void);
#endif

/* SPDX-License-Identifier: Apache-2.0
 * Non-secure board set-up for the Aegis network prover. TF-M's secure image has already set the clocks (PLLs, FlexSPI,
 * the debug UART); calling BOARD_InitBootClocks here would touch ELS, which is secure-only, and reprogram clocks the
 * code is running from. This only does what Ethernet needs, as NXP's lwip_dhcp example for this board does. */
#include "app.h"
#include "board.h"
#include "fsl_enet.h"
#include "fsl_gpio.h"
#include "fsl_reset.h"
#include "pin_mux.h"

phy_ksz8081_resource_t g_phy_resource;

static status_t mdio_write(uint8_t phy, uint8_t reg, uint16_t data)
{
	return ENET_MDIOWrite(EXAMPLE_ENET, phy, reg, data);
}

static status_t mdio_read(uint8_t phy, uint8_t reg, uint16_t *data)
{
	return ENET_MDIORead(EXAMPLE_ENET, phy, reg, data);
}

void BOARD_InitHardware(void)
{
	gpio_pin_config_t out = {kGPIO_DigitalOutput, 1U}, in = {kGPIO_DigitalInput, 0U};
	uint32_t i = ENET_GetInstance(EXAMPLE_ENET);

	BOARD_InitNETPins();
	BOARD_InitDebugConsole();
	CLOCK_EnableClock(kCLOCK_TddrMciEnetClk); /* 50 MHz reference clock for the PHY (RMII) */
	ENET_ResetHardware();
	GPIO_PortInit(GPIO, 0U);
	GPIO_PortInit(GPIO, 1U);
	GPIO_PinInit(GPIO, 0U, 21U, &out); /* PHY reset */
	GPIO_PinInit(GPIO, 1U, 23U, &in);  /* PHY interrupt (unused) */
	GPIO_PinWrite(GPIO, 0U, 21U, 0U);
	SDK_DelayAtLeastUs(100000, CLOCK_GetCoreSysClkFreq());
	GPIO_PinWrite(GPIO, 0U, 21U, 1U);
	(void)CLOCK_EnableClock(s_enetClock[i]);
	(void)CLOCK_EnableClock(s_enetExtraClock[i]);
	ENET_SetSMI(EXAMPLE_ENET, EXAMPLE_CLOCK_FREQ, false);
	g_phy_resource.read = mdio_read;
	g_phy_resource.write = mdio_write;
}

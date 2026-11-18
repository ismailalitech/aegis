/* SPDX-License-Identifier: Apache-2.0
 * Non-secure board set-up for the Aegis network prover. TF-M's secure image has already set the clocks (PLLs, FlexSPI,
 * the debug UART); calling BOARD_InitBootClocks here would touch ELS, which is secure-only, and reprogram clocks the
 * code is running from. The Aegis target_cfg.c also makes RSTCTL0, CLKCTL0 and SYSCTL0 secure-only, so nothing here may
 * touch them: the clock frequencies are constants (SystemCoreClock 260 MHz, the console's 20 MHz), and the secure
 * partition switches the Ethernet controller's clocks on before this image runs. */
#include "app.h"
#include "board.h"
#include "fsl_enet.h"
#include "fsl_gpio.h"
#include "fsl_reset.h"
#include "pin_mux.h"
#include "fsl_debug_console.h"

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

	BOARD_InitNETPins();
	/* the secure side set up FLEXCOMM3 and its FRG (20 MHz, measured on this board): only the driver state here */
	DbgConsole_Init(3U, 115200U, kSerialPort_Uart, AEGIS_DEBUG_UART_CLK_HZ);
	/* the ENET clocks and reset are done by the secure partition (RSTCTL0/CLKCTL0 are secure-only); GPIO is in
	 * CLKCTL1/RSTCTL1, still non-secure, and the drivers are built without clock control */
	CLOCK_EnableClock(kCLOCK_HsGpio0);
	CLOCK_EnableClock(kCLOCK_HsGpio1);
	GPIO_PortInit(GPIO, 0U);
	GPIO_PortInit(GPIO, 1U);
	GPIO_PinInit(GPIO, 0U, 21U, &out); /* PHY reset */
	GPIO_PinInit(GPIO, 1U, 23U, &in);  /* PHY interrupt (unused) */
	GPIO_PinWrite(GPIO, 0U, 21U, 0U);
	SDK_DelayAtLeastUs(100000, SystemCoreClock);
	GPIO_PinWrite(GPIO, 0U, 21U, 1U);
	ENET_SetSMI(EXAMPLE_ENET, EXAMPLE_CLOCK_FREQ, false);
	g_phy_resource.read = mdio_read;
	g_phy_resource.write = mdio_write;
}

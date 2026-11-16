/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * TEMPORARY Non-Secure test image: runs kat_core (mldsa-native / mlkem-native with the Aegis
 * secure partition's configuration) on the STM32H573's Cortex-M33, one request per console line.
 * Flashed only to run the NIST ACVP vectors, then replaced by the prover image again.
 */
#include <stdint.h>
#include <string.h>

#include "board.h"
#include "kat_core.h"
#include "stm32h5xx.h"
#include "tfm_ns_interface.h"
#include "uart_stdout.h"

extern uint32_t tfm_ns_interface_init(void);

static void out(const char *s)
{
	(void)stdio_output_string(s, strlen(s));
}

static char line[32768];

int main(void)
{
	size_t n = 0;
	USART_TypeDef *u = COM_INSTANCE;

	stdio_init();
	(void)tfm_ns_interface_init();
	out("\r\nAEGIS-KAT ready\r\n");
	for (;;) {
		if (u->ISR & (USART_ISR_ORE | USART_ISR_FE | USART_ISR_NE)) {
			u->ICR = USART_ICR_ORECF | USART_ICR_FECF | USART_ICR_NECF;
			out("ERR uart-overrun\r\n");
			n = 0;
		}
		if (!(u->ISR & USART_ISR_RXNE_RXFNE)) {
			continue;
		}
		char c = (char)(u->RDR & 0xFFu);
		if (c == '\r' || c == '\n') {
			if (n) {
				line[n] = '\0';
				kat_handle(line, out);
				n = 0;
			}
		} else if (n + 1 < sizeof(line)) {
			line[n++] = c;
		}
	}
	return 0;
}

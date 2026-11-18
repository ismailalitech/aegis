/* SPDX-License-Identifier: Apache-2.0
 * Non-secure test client for the Aegis partition on the FRDM-RW612: sends protocol lines with psa_call and prints
 * the replies, so the secure side can be checked on the chip before the network prover exists. */
#include <string.h>

#include "app.h"
#include "board.h"
#include "fsl_debug_console.h"
#include "psa/client.h"
#include "tfm_ns_interface.h"
#include "aegis_pq_defs.h"

static char reply[9600];

static void request(const char *line)
{
	psa_invec in = {line, strlen(line)};
	psa_outvec out = {reply, sizeof(reply) - 1};
	psa_status_t st = psa_call(AEGIS_PQ_SERVICE_HANDLE, AEGIS_PQ_LINE, &in, 1, &out, 1);

	if (st != PSA_SUCCESS) {
		PRINTF("> %.40s\r\n< status %d\r\n", line, (int)st);
		return;
	}
	reply[out.len] = '\0';
	PRINTF("> %.40s\r\n< %u bytes: %.150s%s\r\n", line, (unsigned)out.len, reply, out.len > 150 ? " ..." : "");
}

int main(void)
{
	BOARD_InitHardware();
	PRINTF("AEGIS-RW612-TFM-TEST: non-secure client of the Aegis partition (SID 0x%x)\r\n",
	       (unsigned)AEGIS_PQ_SERVICE_SID);
	request("PQKEY");
	request("PQCHAL 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	request("PQSESSION");
	request("HELLO");
	PRINTF("AEGIS-RW612-TFM-TEST done\r\n");
	for (;;) {
	}
}

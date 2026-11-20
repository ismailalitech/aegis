/* SPDX-License-Identifier: Apache-2.0
 * The Aegis trusted application on the Zynq UltraScale+ (OP-TEE): identity and command, shared with the bridge. */
#ifndef AEGIS_TA_H
#define AEGIS_TA_H

#define AEGIS_TA_UUID \
	{ 0xb56a99ca, 0x1c3c, 0x40c8, { 0xaf, 0x55, 0xb8, 0xdd, 0x5e, 0xe0, 0x32, 0x13 } }

/* One request line of the Aegis line protocol in, the reply line out (the Prover SDK's core, sdk/src/aegis_proto.c):
 *   params[0] memref input   the request, without its line end
 *   params[1] memref output  the reply, without a line end; its size is set to the reply's length */
#define AEGIS_TA_CMD_LINE 0

#define AEGIS_TA_LINE_MAX  14600u /* AEGIS_LINE_MAX: PQKEMFIN with a 6 KB credential, in hex */
#define AEGIS_TA_REPLY_MAX 9600u  /* AEGIS_REPLY_MAX */

#endif

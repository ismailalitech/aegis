/* SPDX-License-Identifier: Apache-2.0
 * PC stand-in for the part of the GlobalPlatform TEE Client API that the bridge uses
 * (../../bridge/aegis_tee_bridge.c); ../ta_board.c implements it by calling the TA's entry points. */
#ifndef TEE_CLIENT_API_H
#define TEE_CLIENT_API_H

#include <stddef.h>
#include <stdint.h>

typedef uint32_t TEEC_Result;
typedef struct {
	uint32_t timeLow;
	uint16_t timeMid;
	uint16_t timeHiAndVersion;
	uint8_t clockSeqAndNode[8];
} TEEC_UUID;
typedef struct {
	int unused;
} TEEC_Context;
typedef struct {
	void *ta;
} TEEC_Session;
typedef union {
	struct {
		void *buffer;
		size_t size;
	} tmpref;
	struct {
		uint32_t a;
		uint32_t b;
	} value;
} TEEC_Parameter;
typedef struct {
	uint32_t started;
	uint32_t paramTypes;
	TEEC_Parameter params[4];
} TEEC_Operation;

#define TEEC_SUCCESS              0x00000000u
#define TEEC_ERROR_GENERIC        0xffff0000u
#define TEEC_ERROR_BAD_PARAMETERS 0xffff0006u
#define TEEC_ERROR_ITEM_NOT_FOUND 0xffff0008u
#define TEEC_ERROR_SHORT_BUFFER   0xffff0010u
#define TEEC_ERROR_TARGET_DEAD    0xffff3024u

#define TEEC_LOGIN_PUBLIC 0

#define TEEC_NONE               0
#define TEEC_MEMREF_TEMP_INPUT  5
#define TEEC_MEMREF_TEMP_OUTPUT 6
#define TEEC_PARAM_TYPES(p0, p1, p2, p3) ((uint32_t)((p0) | ((p1) << 4) | ((p2) << 8) | ((p3) << 12)))

TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *ctx);
TEEC_Result TEEC_OpenSession(TEEC_Context *ctx, TEEC_Session *sess, const TEEC_UUID *dest, uint32_t method,
			     const void *data, TEEC_Operation *op, uint32_t *origin);
TEEC_Result TEEC_InvokeCommand(TEEC_Session *sess, uint32_t cmd, TEEC_Operation *op, uint32_t *origin);

#endif

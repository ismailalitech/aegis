/* SPDX-License-Identifier: Apache-2.0
 * PC stand-in for the part of the GlobalPlatform TEE Internal Core API that aegis_ta.c uses (test_ta.c). */
#ifndef TEE_INTERNAL_API_H
#define TEE_INTERNAL_API_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef uint32_t TEE_Result;
typedef struct {
	uint32_t timeLow;
	uint16_t timeMid;
	uint16_t timeHiAndVersion;
	uint8_t clockSeqAndNode[8];
} TEE_UUID;
typedef union {
	struct {
		void *buffer;
		size_t size;
	} memref;
	struct {
		uint32_t a;
		uint32_t b;
	} value;
} TEE_Param;
typedef struct {
	uint32_t seconds;
	uint32_t millis;
} TEE_Time;
typedef struct stub_session *TEE_TASessionHandle;

#define TEE_HANDLE_NULL NULL
#define TEE_NUM_PARAMS 4
#define TEE_TIMEOUT_INFINITE 0xffffffffu

#define TEE_SUCCESS               0x00000000u
#define TEE_ERROR_GENERIC         0xffff0000u
#define TEE_ERROR_ACCESS_DENIED   0xffff0001u
#define TEE_ERROR_BAD_PARAMETERS  0xffff0006u
#define TEE_ERROR_BAD_STATE       0xffff0007u
#define TEE_ERROR_ITEM_NOT_FOUND  0xffff0008u
#define TEE_ERROR_SHORT_BUFFER    0xffff0010u

#define TEE_PARAM_TYPE_NONE          0
#define TEE_PARAM_TYPE_VALUE_OUTPUT  2
#define TEE_PARAM_TYPE_MEMREF_INPUT  5
#define TEE_PARAM_TYPE_MEMREF_OUTPUT 6
#define TEE_PARAM_TYPES(t0, t1, t2, t3) ((uint32_t)((t0) | ((t1) << 4) | ((t2) << 8) | ((t3) << 12)))

void TEE_GenerateRandom(void *buf, size_t n);
void TEE_GetSystemTime(TEE_Time *t);
void TEE_MemFill(void *buf, uint32_t x, size_t n);
TEE_Result TEE_OpenTASession(const TEE_UUID *dest, uint32_t timeout, uint32_t pt, TEE_Param params[TEE_NUM_PARAMS],
			     TEE_TASessionHandle *sess, uint32_t *origin);
TEE_Result TEE_InvokeTACommand(TEE_TASessionHandle sess, uint32_t timeout, uint32_t cmd, uint32_t pt,
			       TEE_Param params[TEE_NUM_PARAMS], uint32_t *origin);
void TEE_CloseTASession(TEE_TASessionHandle sess);

extern char stub_log[2048];
void stub_msg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
#define IMSG(...) stub_msg(__VA_ARGS__)
#define EMSG(...) stub_msg(__VA_ARGS__)

/* the TA's entry points (OP-TEE declares them in its own header) */
TEE_Result TA_CreateEntryPoint(void);
void TA_DestroyEntryPoint(void);
TEE_Result TA_OpenSessionEntryPoint(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS], void **sess);
void TA_CloseSessionEntryPoint(void *sess);
TEE_Result TA_InvokeCommandEntryPoint(void *sess, uint32_t cmd, uint32_t pt, TEE_Param params[TEE_NUM_PARAMS]);

#endif

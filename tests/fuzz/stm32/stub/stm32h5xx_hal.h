/* SPDX-License-Identifier: Apache-2.0 */
/* PC stand-in for the STM32H5 HAL parts aegis_pq_attest.c uses to derive from the DHUK in SAES (tests/fuzz/stm32).
 * HAL_CRYP_Encrypt gives a fixed function of the label: a stand-in device key. */
#ifndef FZ_STM32H5XX_HAL_H
#define FZ_STM32H5XX_HAL_H
#include <stdint.h>
typedef enum { HAL_OK = 0, HAL_ERROR = 1 } HAL_StatusTypeDef;
typedef struct {
	uint32_t DataType, KeySize, Algorithm, DataWidthUnit, KeyIVConfigSkip, KeyMode, KeySelect, KeyProtection;
	uint32_t *pKey;
} CRYP_InitTypeDef;
typedef struct { void *Instance; CRYP_InitTypeDef Init; } CRYP_HandleTypeDef;
#define SAES ((void *)0x1)
#define CRYP_NO_SWAP 0u
#define CRYP_KEYSIZE_256B 1u
#define CRYP_AES_ECB 0u
#define CRYP_DATAWIDTHUNIT_BYTE 1u
#define CRYP_KEYIVCONFIG_ALWAYS 0u
#define CRYP_KEYMODE_NORMAL 0u
#define CRYP_KEYSEL_HW 1u
#define CRYP_KEYPROT_DISABLE 0u
#define __HAL_RCC_RNG_CLK_ENABLE() do { } while (0)
#define __HAL_RCC_SAES_CLK_ENABLE() do { } while (0)
HAL_StatusTypeDef HAL_CRYP_Init(CRYP_HandleTypeDef *h);
HAL_StatusTypeDef HAL_CRYP_Encrypt(CRYP_HandleTypeDef *h, uint32_t *in, uint16_t size, uint32_t *out, uint32_t t);
HAL_StatusTypeDef HAL_CRYP_DeInit(CRYP_HandleTypeDef *h);
#endif

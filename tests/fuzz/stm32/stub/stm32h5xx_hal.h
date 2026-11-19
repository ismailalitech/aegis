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
/* The registers of the session clock (the RTC on the LSI), with the device header's bit values: plain memory here.
 * The harness plays the hardware between two reads (AEGIS_TEST_HW_STEP in aegis_pq_attest.c). */
typedef struct {
	volatile uint32_t TR, DR, SSR, ICSR, PRER, WUTR, CR, PRIVCFGR, SECCFGR, WPR, SR, SCR;
} RTC_TypeDef;
typedef struct {
	volatile uint32_t BDCR, SECCFGR, APB3ENR;
} RCC_TypeDef;
typedef struct {
	volatile uint32_t DBPCR;
} PWR_TypeDef;
extern RTC_TypeDef fz_rtc;
extern RCC_TypeDef fz_rcc;
extern PWR_TypeDef fz_pwr;
#define RTC (&fz_rtc)
#define RCC (&fz_rcc)
#define PWR (&fz_pwr)
#define PWR_DBPCR_DBP          0x00000001u
#define RCC_APB3ENR_RTCAPBEN   0x00200000u
#define RCC_BDCR_RTCSEL        0x00000300u
#define RCC_BDCR_RTCSEL_0      0x00000100u
#define RCC_BDCR_RTCSEL_1      0x00000200u
#define RCC_BDCR_RTCEN         0x00008000u
#define RCC_BDCR_LSION         0x04000000u
#define RCC_BDCR_LSIRDY        0x08000000u
#define RCC_SECCFGR_LSISEC     0x00000008u
#define RTC_ICSR_RSF           0x00000020u
#define RTC_ICSR_INITF         0x00000040u
#define RTC_ICSR_INIT          0x00000080u
#define RTC_ICSR_BIN           0x00000300u
#define RTC_ICSR_BIN_0         0x00000100u
#define RTC_ICSR_BCDU          0x00001C00u
#define RTC_PRER_PREDIV_A_Pos  16u
#define RTC_PRER_PREDIV_A      0x007F0000u
#define RTC_PRIVCFGR_PRIV      0x00008000u
#define RTC_SECCFGR_SEC        0x00008000u
#define RTC_SR_SSRUF           0x00000040u
#define RTC_SCR_CSSRUF         0x00000040u
HAL_StatusTypeDef HAL_CRYP_Init(CRYP_HandleTypeDef *h);
HAL_StatusTypeDef HAL_CRYP_Encrypt(CRYP_HandleTypeDef *h, uint32_t *in, uint16_t size, uint32_t *out, uint32_t t);
HAL_StatusTypeDef HAL_CRYP_DeInit(CRYP_HandleTypeDef *h);
#endif

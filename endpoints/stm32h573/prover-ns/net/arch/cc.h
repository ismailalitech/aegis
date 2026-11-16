/* SPDX-License-Identifier: Apache-2.0
 * lwIP compiler/platform glue for arm-none-eabi-gcc, bare metal. */
#ifndef LWIP_ARCH_CC_H
#define LWIP_ARCH_CC_H

#include <stdint.h>
#include <stdlib.h>

#define BYTE_ORDER LITTLE_ENDIAN
#define LWIP_RAND() ((u32_t)aegis_rand32())
#define LWIP_PLATFORM_DIAG(x) do { } while (0)
#define LWIP_PLATFORM_ASSERT(x) do { aegis_lwip_assert(x); } while (0)

uint32_t aegis_rand32(void);
void aegis_lwip_assert(const char *msg);

#endif

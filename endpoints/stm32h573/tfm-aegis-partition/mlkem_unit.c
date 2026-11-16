/* SPDX-License-Identifier: Apache-2.0
 * Compile mlkem-native (monolithic build) with the Aegis configuration in its own unit, so its
 * MLK_CONFIG_FILE does not mix with mldsa-native's configuration. */
#define MLK_CONFIG_FILE "aegis_mlkem_config.h"
#include "mlkem_native.c"

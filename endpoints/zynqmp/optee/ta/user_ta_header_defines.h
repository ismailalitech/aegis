/* SPDX-License-Identifier: Apache-2.0 */
#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include "aegis_ta.h"

#define TA_UUID AEGIS_TA_UUID
/* one instance for the whole boot: the session key, the heartbeat counter and the pending ML-KEM exchange live in
 * it from one bridge connection to the next */
#define TA_FLAGS (TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION | TA_FLAG_INSTANCE_KEEP_ALIVE)
#define TA_STACK_SIZE (64 * 1024)
#define TA_DATA_SIZE  (512 * 1024)
#define TA_VERSION "0.1.1"
#define TA_DESCRIPTION "Aegis post-quantum attestation (ML-DSA-65, ML-KEM-768, KMAC heartbeats)"

#endif

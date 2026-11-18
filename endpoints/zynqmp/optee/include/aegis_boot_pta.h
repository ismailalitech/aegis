/* SPDX-License-Identifier: Apache-2.0
 *
 * OP-TEE pseudo trusted application "aegis.boot" on the Zynq UltraScale+ Aegis endpoint: what OP-TEE kept of the
 * FSBL's hand-off page (aegis_zynqmp_handoff.h), for the Aegis TA only. The seed is never returned.
 *
 * Shared by OP-TEE (endpoints/zynqmp/optee/os-patches carries a copy) and the TA (endpoints/zynqmp/optee/ta).
 */
#ifndef AEGIS_BOOT_PTA_H
#define AEGIS_BOOT_PTA_H

#include "aegis_zynqmp_handoff.h"

#define PTA_AEGIS_BOOT_UUID \
	{ 0xc452052e, 0x9c90, 0x40fc, { 0xbf, 0x0f, 0x70, 0xcc, 0xca, 0xbf, 0x18, 0xdd } }
#define PTA_AEGIS_BOOT_NAME "aegis.boot"

/* The only client, the Aegis TA (AEGIS_TA_UUID in aegis_ta.h). Any other caller, and the normal world, get
 * TEE_ERROR_ACCESS_DENIED at open session. */
#define PTA_AEGIS_BOOT_CLIENT_UUID \
	{ 0xb56a99ca, 0x1c3c, 0x40c8, { 0xaf, 0x55, 0xb8, 0xdd, 0x5e, 0xe0, 0x32, 0x13 } }

/*
 * PTA_AEGIS_BOOT_CMD_GET_INFO
 *   params[0] value output   a: status (AEGIS_BOOT_HO_*), b: the hand-off's flags (AEGIS_HO_*)
 *   params[1] value output   a: bh_key_src, b: csu_status
 *   params[2] value output   a: count, b: what OP-TEE derives its keys and the TAs' keys from (AEGIS_BOOT_HUK_*)
 *   params[3] memref output  count entries of struct aegis_ho_meas, each label NUL-terminated; its size is set to
 *                            count * sizeof(struct aegis_ho_meas) (TEE_ERROR_SHORT_BUFFER if the buffer is smaller)
 * Unless the status is AEGIS_BOOT_HO_VALID, the flags, bh_key_src, csu_status and count are 0.
 */
#define PTA_AEGIS_BOOT_CMD_GET_INFO 0

#define AEGIS_BOOT_HO_ABSENT   0u /* no magic in the page: the FSBL handed nothing over */
#define AEGIS_BOOT_HO_VALID    1u
#define AEGIS_BOOT_HO_REJECTED 2u /* magic found, but version, count or digest wrong: nothing of it is used */

#define AEGIS_BOOT_HUK_DEFAULT 0u /* OP-TEE's development hardware unique key (16 zero bytes), the same on every
                                   * chip */
#define AEGIS_BOOT_HUK_SEED    1u /* 32 bytes derived from the hand-off's seed (AEGIS_HO_SEED_VALID and
                                   * AEGIS_HO_KEY_BH_BLACK were both set) */

#endif

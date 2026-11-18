/* SPDX-License-Identifier: Apache-2.0
 *
 * Hand-off from the FSBL to OP-TEE on the Zynq UltraScale+ Aegis endpoint (docs/zynqmp-key-design.md, phase B).
 *
 * The FSBL fills one 4 KiB page at AEGIS_HANDOFF_PA, inside OP-TEE's secure memory (TZDRAM 0x6000_0000-0x6FFF_FFFF;
 * its last page, which OP-TEE gives to TAs only later), just before it hands off to TF-A. OP-TEE reads it once during
 * its own initialisation, before the normal world runs, keeps a copy, and wipes the page. Nothing in the normal world
 * runs between the two.
 *
 * Shared by the FSBL hook (endpoints/zynqmp/fsbl) and OP-TEE (endpoints/zynqmp/optee). Plain C, fixed layout, no
 * pointers, little-endian, every field naturally aligned.
 */
#ifndef AEGIS_ZYNQMP_HANDOFF_H
#define AEGIS_ZYNQMP_HANDOFF_H

#include <stdint.h>

#define AEGIS_HANDOFF_PA       0x6FFFF000u
#define AEGIS_HANDOFF_SIZE     0x1000u
#define AEGIS_HANDOFF_MAGIC    0x48474541u /* "AEGH" */
#define AEGIS_HANDOFF_VERSION  1u
#define AEGIS_HANDOFF_MAX_MEAS 8u

/* flags */
#define AEGIS_HO_SEED_VALID    (1u << 0) /* seed was derived under the CSU AES device key */
#define AEGIS_HO_KEY_BH_BLACK  (1u << 1) /* that device key is the boot header's black key, decrypted by this chip's
                                          * PUF KEK (boot header key source = BH black key, and the FSBL itself was
                                          * decrypted with it). Only with this bit is the seed bound to the chip. */
#define AEGIS_HO_AES_CLEARED   (1u << 2) /* the FSBL cleared the AES key and KUP registers afterwards */

/* The seed is AES-256-GCM-encrypt(device key, IV = AEGIS_SEED_IV, plaintext = AEGIS_SEED_LABEL) (ciphertext only,
 * the tag is not used): deterministic, the same chip and boot header give the same 32 bytes every boot. */
#define AEGIS_SEED_LABEL "aegis-zynqmp-device-seed-v1-----" /* exactly 32 bytes */
#define AEGIS_SEED_IV    { 0x61, 0x65, 0x67, 0x69, 0x73, 0x2d, 0x7a, 0x79, 0x6e, 0x71, 0x6d, 0x70 } /* "aegis-zynqmp" */

struct aegis_ho_meas {
	char label[16];     /* NUL-padded, e.g. "FSBL", "PMUFW", "PL", "TFA", "TEE", "UBOOT" */
	uint8_t value[32];  /* the first 32 bytes of the CSU's SHA3-384 over the partition as stored in the boot image */
	uint32_t length;    /* bytes hashed */
	uint32_t attrib;    /* the partition header's attribute word, for the record */
};

struct aegis_zynqmp_handoff {
	uint32_t magic;     /* AEGIS_HANDOFF_MAGIC */
	uint32_t version;   /* AEGIS_HANDOFF_VERSION */
	uint32_t flags;     /* AEGIS_HO_* */
	uint32_t count;     /* entries used in meas[] */
	uint32_t bh_key_src;    /* the boot header's encryption-status word, as the FSBL read it */
	uint32_t csu_status;    /* CSU_STATUS when the hook ran (authentication and encryption bits) */
	uint32_t reserved[2];
	uint8_t seed[32];
	struct aegis_ho_meas meas[AEGIS_HANDOFF_MAX_MEAS];
	uint8_t sha3_384[48]; /* CSU SHA3-384 over everything above: a consistency check, not a security mechanism */
};

#endif

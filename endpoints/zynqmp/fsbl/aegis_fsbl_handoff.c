// SPDX-License-Identifier: Apache-2.0
/*
 * Aegis hook for the Zynq UltraScale+ FSBL (Vitis 2025.2 zynqmp_fsbl, A53 64-bit, xilsecure's ZynqMP server API):
 * measures the boot image, derives the device seed under the CSU AES device key and leaves both in the hand-off page
 * for OP-TEE (endpoints/zynqmp/handoff/aegis_zynqmp_handoff.h, docs/zynqmp-key-design.md phase B).
 *
 * Nothing here writes eFUSEs, BBRAM, the PUF or the boot device. The boot device is only read, through the FSBL's own
 * DeviceOps.DeviceCopy. The seed is never printed; its only copy outside the hand-off page is wiped.
 *
 * Nothing here can stop the boot: every failure ends in a flag that stays clear or a measurement that stays zero. The
 * xilsecure calls are made only in the states their Xil_Assert checks expect, because a failed assert hangs the FSBL.
 */
#include <stddef.h>
#include <string.h>

#include "xil_cache.h"
#include "xfsbl_hw.h"
#include "xfsbl_main.h"
#include "xcsudma.h"
#include "xsecure_aes.h"
#include "xsecure_sha.h"
#include "xsecure_utils.h"

#include "aegis_fsbl_handoff.h"

_Static_assert(sizeof(AEGIS_SEED_LABEL) - 1U == 32U, "the seed label is 32 bytes");
_Static_assert(sizeof(struct aegis_ho_meas) == 56U, "hand-off layout");
_Static_assert(offsetof(struct aegis_zynqmp_handoff, seed) == 32U, "hand-off layout");
_Static_assert(offsetof(struct aegis_zynqmp_handoff, sha3_384) == 512U, "hand-off layout");
_Static_assert(sizeof(struct aegis_zynqmp_handoff) <= AEGIS_HANDOFF_SIZE, "hand-off fits its page");
_Static_assert(sizeof(((struct aegis_zynqmp_handoff *)0)->sha3_384) == 48U, "hand-off layout");

/* Boot header (bootgen's ZynqMpBootHeaderStructure). The FSBL names 0x28, 0x38 and 0x44 itself (XIH_BH_*). */
#define AEGIS_BH_SOURCE_OFFSET     0x30U       /* where the boot ROM's images start: the PMU firmware if present */
#define AEGIS_BH_READ_LEN          0x100U
#define AEGIS_BH_KEY_SRC_BH_BLACK  0xA35C7C53U /* bootgen BH_BLACK_KEY: key in the boot header, under the PUF KEK */

/* CSU_STATUS, set by the boot ROM (PMU firmware's csu.h: CSU_STATUS_BOOT_ENC_MASK) */
#define AEGIS_CSU_STATUS           (CSU_BASEADDR + 0x0U)
#define AEGIS_CSU_STATUS_BOOT_ENC  0x2U

#define AEGIS_SHA3_384_LEN 48U

/* Partition attribute values the FSBL has no names for */
#define AEGIS_PH_EL3 0x6U
#define AEGIS_PH_EL2 0x4U
#define AEGIS_PH_EL1 0x2U

/* A multiple of xilsecure's SHA3 block (104 bytes) and of 4, so every full chunk goes to the CSU DMA in one transfer
 * instead of through the driver's 104-byte bounce buffer. */
#define AEGIS_CHUNK ((AEGIS_FSBL_SCRATCH_SIZE / XSECURE_SHA3_BLOCK_LEN) * XSECURE_SHA3_BLOCK_LEN)

extern XFsblPs FsblInstance; /* xfsbl_main.c */
extern XCsuDma CsuDma;       /* xfsbl_csu_dma.c: initialised by the FSBL in every boot mode that loads partitions */

static struct {
	u32 Measured;
	u32 BhRead;   /* the boot header was read back from the device the boot ROM booted from */
	u32 BhKeySrc;
	u32 BhAttr;
	u32 Count;
	u32 Dropped;
	struct aegis_ho_meas Meas[AEGIS_HANDOFF_MAX_MEAS];
} Aegis;

static XSecure_Sha3 AegisSha3;
static XSecure_Aes AegisAes;

/* CSU DMA buffers. The destination owns its cache line: the driver invalidates the range it writes. */
static u32 AegisIv[4] __attribute__((aligned(64)));
static u8 AegisPt[32] __attribute__((aligned(64)));
static u8 AegisCt[64] __attribute__((aligned(64))); /* 32 bytes of ciphertext, 16 of tag */

static void aegis_wipe(void *Ptr, u32 Len)
{
	volatile u8 *P = (volatile u8 *)Ptr;

	while (Len != 0U) {
		*P = 0U;
		P++;
		Len--;
	}
}

static u32 aegis_dma_ready(void)
{
	return (CsuDma.IsReady == (u32)XIL_COMPONENT_IS_READY) ? (u32)TRUE : (u32)FALSE;
}

/* TRUE if [Start, Start + Size) is DDR the FSBL can write and no partition was loaded there. */
static u32 aegis_ddr_is_free(u64 Start, u64 Size)
{
#ifdef XFSBL_PS_DDR
	const XFsblPs_ImageHeader *Ih = &FsblInstance.ImageHeader;
	u32 Count = Ih->ImageHeaderTable.NoOfPartitions;
	u32 Index;

	if ((Start + Size - 1U) > (u64)XFSBL_PS_DDR_END_ADDRESS) {
		return (u32)FALSE;
	}
	if (Count > XIH_MAX_PARTITIONS) {
		Count = XIH_MAX_PARTITIONS;
	}
	for (Index = 1U; Index < Count; Index++) {
		const XFsblPs_PartitionHeader *Ph = &Ih->PartitionHeader[Index];
		u64 Load = Ph->DestinationLoadAddress;
		u64 Words = Ph->TotalDataWordLength;

		if ((Ph->PartitionAttributes & XIH_PH_ATTRB_DEST_DEVICE_MASK) == XIH_PH_ATTRB_DEST_DEVICE_PL) {
			continue;
		}
		if (Ph->UnEncryptedDataWordLength > Words) {
			Words = Ph->UnEncryptedDataWordLength;
		}
		if ((Words != 0U) && (Load < (Start + Size)) && (Start < (Load + (Words * XIH_PARTITION_WORD_LENGTH)))) {
			return (u32)FALSE;
		}
	}
	return (u32)TRUE;
#else
	(void)Start;
	(void)Size;
	return (u32)FALSE;
#endif
}

/* CSU SHA3-384 (NIST padding, xilsecure's default) over Len bytes of the boot image at Offset, as stored: read back in
 * chunks through the FSBL's device ops. Out gets the first 32 bytes. */
static u32 aegis_hash_image(u64 Offset, u64 Len, u8 *Out)
{
	u8 *Scratch = (u8 *)(UINTPTR)AEGIS_FSBL_SCRATCH_PA;
	u32 Digest[AEGIS_SHA3_384_LEN / 4U] = {0U};
	u32 Src = (u32)Offset;
	u32 Left = (u32)Len;
	u32 Chunk;

	if ((Len == 0U) || ((Offset + Len) > 0xFFFFFFFFULL)) {
		return (u32)FALSE;
	}
	if (XSecure_Sha3Initialize(&AegisSha3, &CsuDma) != (s32)XST_SUCCESS) {
		return (u32)FALSE;
	}
	XSecure_Sha3Start(&AegisSha3);
	while (Left != 0U) {
		Chunk = (Left < AEGIS_CHUNK) ? Left : AEGIS_CHUNK;
		if (FsblInstance.DeviceOps.DeviceCopy(Src, (PTRSIZE)Scratch, Chunk) != XFSBL_SUCCESS) {
			(void)XSecure_Sha3Finish(&AegisSha3, (u8 *)Digest); /* puts the engine back in reset */
			return (u32)FALSE;
		}
		if (XSecure_Sha3Update(&AegisSha3, Scratch, Chunk) != (u32)XST_SUCCESS) {
			return (u32)FALSE; /* the driver has already reset the engine; Finish would assert */
		}
		Src += Chunk;
		Left -= Chunk;
	}
	if (XSecure_Sha3Finish(&AegisSha3, (u8 *)Digest) != (u32)XST_SUCCESS) {
		return (u32)FALSE;
	}
	(void)memcpy(Out, Digest, 32U);
	return (u32)TRUE;
}

/* Base, or Base ".<n>" when n earlier entries already carry Base. */
static void aegis_set_label(struct aegis_ho_meas *Meas, const char *Base)
{
	u32 Len = (u32)strlen(Base);
	u32 Same = 0U;
	u32 Index;

	if (Len > (sizeof(Meas->label) - 3U)) {
		Len = (u32)sizeof(Meas->label) - 3U;
	}
	for (Index = 0U; Index < Aegis.Count; Index++) {
		const char *Have = Aegis.Meas[Index].label;

		if ((strncmp(Have, Base, Len) == 0) && ((Have[Len] == '\0') || (Have[Len] == '.'))) {
			Same++;
		}
	}
	(void)memset(Meas->label, 0, sizeof(Meas->label));
	(void)memcpy(Meas->label, Base, Len);
	if (Same != 0U) {
		Meas->label[Len] = '.';
		Meas->label[Len + 1U] = (char)('0' + Same); /* Same < AEGIS_HANDOFF_MAX_MEAS: one digit */
	}
}

/* One entry. A range that cannot be read or hashed keeps a zero value and length 0. */
static void aegis_measure(const char *Base, u32 Attrib, u64 Offset, u64 Len, u32 CanRead)
{
	struct aegis_ho_meas *Meas;

	if (Aegis.Count >= AEGIS_HANDOFF_MAX_MEAS) {
		Aegis.Dropped++;
		return;
	}
	Meas = &Aegis.Meas[Aegis.Count];
	aegis_set_label(Meas, Base);
	(void)memset(Meas->value, 0, sizeof(Meas->value));
	Meas->length = 0U;
	Meas->attrib = Attrib;
	if ((CanRead == (u32)TRUE) && (aegis_hash_image(Offset, Len, Meas->value) == (u32)TRUE)) {
		Meas->length = (u32)Len;
	} else {
		(void)memset(Meas->value, 0, sizeof(Meas->value));
	}
	Aegis.Count++;
}

/* Label by destination, as the FSBL itself tells the images apart (XFsbl_GetPcrIndex, the TF-A hand-off). */
static const char *aegis_label(u32 Attrib, u32 Index, char *Other)
{
	u32 Device = Attrib & XIH_PH_ATTRB_DEST_DEVICE_MASK;
	u32 Cpu = Attrib & XIH_PH_ATTRB_DEST_CPU_MASK;
	u32 El = Attrib & XIH_PH_ATTRB_TARGET_EL_MASK;
	u32 Secure = Attrib & XIH_PH_ATTRB_TR_SECURE_MASK;

	if (Device == XIH_PH_ATTRB_DEST_DEVICE_PL) {
		return "PL";
	}
	if ((Device == XIH_PH_ATTRB_DEST_DEVICE_PMU) || (Cpu == XIH_PH_ATTRB_DEST_CPU_PMU)) {
		return "PMUFW";
	}
	if (Cpu <= XIH_PH_ATTRB_DEST_CPU_A53_3) { /* an A53 core, or none given: the FSBL's own core */
		if (El == AEGIS_PH_EL3) {
			return "TFA";
		}
		if ((El == AEGIS_PH_EL1) && (Secure != 0U)) {
			return "TEE";
		}
		if (((El == AEGIS_PH_EL2) || (El == AEGIS_PH_EL1)) && (Secure == 0U)) {
			return "UBOOT";
		}
	}
	Other[0] = 'P';
	Other[1] = (char)('0' + (Index / 10U));
	Other[2] = (char)('0' + (Index % 10U));
	Other[3] = '\0';
	if (Index < 10U) {
		Other[1] = Other[2];
		Other[2] = '\0';
	}
	return Other;
}

/*
 * Called once all partitions are loaded, while the FSBL still has the boot device as it used it for loading (data
 * cache on, SD card-detect override in place; XFsbl_Handoff changes both before the hand-off hook runs).
 *
 * Measures what is stored, not what was loaded: each range is read from the boot device a second time. Partition 0
 * is what the boot ROM loaded: the PMU firmware (BIF [pmufw_image]) followed by the FSBL; the boot header says where
 * the first ends. Partitions the FSBL does not own are not loaded by it and are left out.
 */
void AegisFsbl_Measure(void)
{
	const XFsblPs_ImageHeader *Ih = &FsblInstance.ImageHeader;
	u8 *Scratch = (u8 *)(UINTPTR)AEGIS_FSBL_SCRATCH_PA;
	u32 Count = Ih->ImageHeaderTable.NoOfPartitions;
	u64 Base = FsblInstance.ImageOffsetAddress;
	u32 SrcOffset = 0U;
	u32 PmuLen = 0U;
	u32 CanRead;
	u32 Index;
	char Other[4];

	if (Aegis.Measured == (u32)TRUE) {
		return;
	}
	Aegis.Measured = (u32)TRUE;
	if ((Count == 0U) || (Count > XIH_MAX_PARTITIONS) ||
	    (FsblInstance.PrimaryBootDevice == XFSBL_JTAG_BOOT_MODE)) {
		return;
	}
	CanRead = (u32)FALSE;
	if ((FsblInstance.DeviceOps.DeviceCopy != NULL) && (aegis_dma_ready() == (u32)TRUE) &&
	    (aegis_ddr_is_free(AEGIS_FSBL_SCRATCH_PA, AEGIS_FSBL_SCRATCH_SIZE) == (u32)TRUE)) {
		CanRead = (u32)TRUE;
	}

	/* With a secondary boot device the image the FSBL reads is not the one the boot ROM booted: its boot header and
	 * its partition 0 say nothing about this boot. */
	if (FsblInstance.SecondaryBootDevice == 0U) {
		const XFsblPs_PartitionHeader *Ph = &Ih->PartitionHeader[0];
		u64 Offset = (u64)Ph->DataWordOffset * XIH_PARTITION_WORD_LENGTH;
		u64 Len = (u64)Ph->TotalDataWordLength * XIH_PARTITION_WORD_LENGTH;

		if ((CanRead == (u32)TRUE) &&
		    (FsblInstance.DeviceOps.DeviceCopy((u32)Base, (PTRSIZE)Scratch, AEGIS_BH_READ_LEN) == XFSBL_SUCCESS)) {
			Aegis.BhKeySrc = Xil_In32((UINTPTR)Scratch + XIH_BH_ENC_STS_OFFSET);
			Aegis.BhAttr = Xil_In32((UINTPTR)Scratch + XIH_BH_IMAGE_ATTRB_OFFSET);
			SrcOffset = Xil_In32((UINTPTR)Scratch + AEGIS_BH_SOURCE_OFFSET);
			PmuLen = Xil_In32((UINTPTR)Scratch + XIH_BH_TOTAL_PFW_LENGTH_OFFSET);
			Aegis.BhRead = (u32)TRUE;
		}
		if (Len != 0U) {
			if ((PmuLen != 0U) && (PmuLen < Len) && (SrcOffset == Offset)) {
				aegis_measure("PMUFW", Ph->PartitionAttributes, Base + Offset, PmuLen, CanRead);
				aegis_measure("FSBL", Ph->PartitionAttributes, Base + Offset + PmuLen, Len - PmuLen, CanRead);
			} else {
				aegis_measure("FSBL", Ph->PartitionAttributes, Base + Offset, Len, CanRead);
			}
		}
	}

	for (Index = 1U; Index < Count; Index++) {
		const XFsblPs_PartitionHeader *Ph = &Ih->PartitionHeader[Index];

		if (((Ph->PartitionAttributes & XIH_PH_ATTRB_PART_OWNER_MASK) != XIH_PH_ATTRB_PART_OWNER_FSBL) ||
		    (Ph->UnEncryptedDataWordLength == 0U)) {
			continue; /* not loaded by the FSBL, or nothing stored (execute in place) */
		}
		aegis_measure(aegis_label(Ph->PartitionAttributes, Index, Other), Ph->PartitionAttributes,
			      Base + ((u64)Ph->DataWordOffset * XIH_PARTITION_WORD_LENGTH),
			      (u64)Ph->TotalDataWordLength * XIH_PARTITION_WORD_LENGTH, CanRead);
	}

	if (Aegis.Dropped != 0U) {
		struct aegis_ho_meas *Last = &Aegis.Meas[AEGIS_HANDOFF_MAX_MEAS - 1U];

		(void)memset(Last, 0, sizeof(*Last));
		(void)memcpy(Last->label, AEGIS_FSBL_LABEL_TRUNCATED, sizeof(AEGIS_FSBL_LABEL_TRUNCATED));
		Last->length = Aegis.Dropped + 1U;
	}

	if (CanRead == (u32)TRUE) {
		(void)memset(Scratch, 0, AEGIS_FSBL_SCRATCH_SIZE);
		Xil_DCacheFlushRange((INTPTR)AEGIS_FSBL_SCRATCH_PA, (INTPTR)AEGIS_FSBL_SCRATCH_SIZE);
	}
}

/* Seed = AES-256-GCM-encrypt(device key, AEGIS_SEED_IV, AEGIS_SEED_LABEL), ciphertext only, into AegisCt. The engine
 * takes the IV as four words, as the FSBL passes the boot header's; the fourth is zero here. XSecure_AesEncryptData
 * ends by zeroising the AES and KUP keys and resetting the engine, and reports a failure of that too. */
static u32 aegis_derive_seed(void)
{
	static const u8 Iv[12] = AEGIS_SEED_IV;

	(void)memset(AegisIv, 0, sizeof(AegisIv));
	(void)memcpy(AegisIv, Iv, sizeof(Iv));
	(void)memcpy(AegisPt, AEGIS_SEED_LABEL, sizeof(AegisPt));
	if (XSecure_AesEncryptData(&AegisAes, AegisCt, AegisPt, (u32)sizeof(AegisPt)) != (u32)XST_SUCCESS) {
		aegis_wipe(AegisCt, (u32)sizeof(AegisCt));
		return (u32)FALSE;
	}
	return (u32)TRUE;
}

/*
 * AEGIS_HO_KEY_BH_BLACK: the device key is the boot header's black key and this FSBL was decrypted with it. Three
 * things must hold:
 *   1. the boot header on the boot device names the BH black key as key source (word 0x28 == 0xA35C7C53);
 *   2. its attributes do not say "authenticate only" (bits 5:4 == 3): with that, bootgen leaves the FSBL in clear
 *      text although a key source is named (the FSBL makes the same distinction in XFsbl_ValidateHeader);
 *   3. CSU_STATUS.BOOT_ENC is set: the boot ROM's own record that it decrypted the image it booted.
 * (3) is the only indicator that does not come from the boot device, and the strongest there is: the boot ROM sets it,
 * AMD's register reference describes it as a status bit, and nothing in the 2025.2 FSBL, PMU firmware or xilsecure
 * writes it. It is not fully reliable on its own: it says "decrypted", not "with which key". (1) is read back from the
 * device by this code, after the boot ROM read it: no CSU register tells which key source the boot ROM used, so a
 * boot device swapped in between would not be noticed. That cannot leak the chip's seed (the seed comes from
 * whatever key the boot ROM really loaded), it can only make the flag wrong. And the flag is a statement by this
 * FSBL, not a defence against another FSBL: what keeps another FSBL from the seed is that the boot ROM gives the
 * black key only to an image encrypted with it (docs/zynqmp-key-design.md, test 4).
 * The flag is set only together with AEGIS_HO_SEED_VALID.
 */
static u32 aegis_key_is_bh_black(u32 CsuStatus)
{
	if ((Aegis.BhRead == (u32)TRUE) && (Aegis.BhKeySrc == AEGIS_BH_KEY_SRC_BH_BLACK) &&
	    ((Aegis.BhAttr & XIH_BH_IMAGE_ATTRB_AUTH_ONLY_MASK) != XIH_BH_IMAGE_ATTRB_AUTH_ONLY_MASK) &&
	    ((CsuStatus & AEGIS_CSU_STATUS_BOOT_ENC) != 0U)) {
		return (u32)TRUE;
	}
	return (u32)FALSE;
}

/*
 * Called from XFsbl_HookBeforeHandoff. By then XFsbl_Handoff has switched the data cache off, so the page is written
 * straight to DDR; the flush is for a caller that left the cache on.
 */
void AegisFsbl_BeforeHandoff(u32 EarlyHandoff)
{
	static u32 Done;
	struct aegis_zynqmp_handoff *Ho = (struct aegis_zynqmp_handoff *)(UINTPTR)AEGIS_HANDOFF_PA;
	u32 Digest[AEGIS_SHA3_384_LEN / 4U] = {0U};
	u32 CsuStatus = XFsbl_In32(AEGIS_CSU_STATUS);
	u32 DmaReady = aegis_dma_ready();
	u32 PageFree = aegis_ddr_is_free(AEGIS_HANDOFF_PA, AEGIS_HANDOFF_SIZE);
	u32 Flags = 0U;
	u32 AesReady;

	if ((EarlyHandoff == (u32)TRUE) || (Done == (u32)TRUE)) {
		return;
	}
	Done = (u32)TRUE;

	/* Fails only when the export-control eFUSE has disabled the crypto cores. */
	AesReady = (XSecure_AesInitialize(&AegisAes, &CsuDma, XSECURE_CSU_AES_KEY_SRC_DEV, AegisIv, NULL) ==
		    (s32)XST_SUCCESS) ? (u32)TRUE : (u32)FALSE;

	if (PageFree == (u32)TRUE) {
		(void)memset(Ho, 0, AEGIS_HANDOFF_SIZE);
		Ho->magic = AEGIS_HANDOFF_MAGIC;
		Ho->version = AEGIS_HANDOFF_VERSION;
		Ho->count = (Aegis.Count < AEGIS_HANDOFF_MAX_MEAS) ? Aegis.Count : AEGIS_HANDOFF_MAX_MEAS;
		Ho->bh_key_src = Aegis.BhKeySrc;
		Ho->csu_status = CsuStatus;
		(void)memcpy(Ho->meas, Aegis.Meas, sizeof(Ho->meas));

		if ((AesReady == (u32)TRUE) && (DmaReady == (u32)TRUE) && (aegis_derive_seed() == (u32)TRUE)) {
			(void)memcpy(Ho->seed, AegisCt, sizeof(Ho->seed));
			Flags |= AEGIS_HO_SEED_VALID;
			if (aegis_key_is_bh_black(CsuStatus) == (u32)TRUE) {
				Flags |= AEGIS_HO_KEY_BH_BLACK;
			}
		}
		aegis_wipe(AegisCt, (u32)sizeof(AegisCt));
	}

	/* Clear the AES key and the KUP key, checked on the status bits. This comes before the page's hash because the
	 * flag is under the hash; the SHA3 core does not use the AES key. xilsecure leaves the AES core in reset, and
	 * its own calls to XSecure_AesKeyZero are all made with the core running: take it out of reset for the request
	 * and put it back. No control clears the device key itself (design, point 5). */
	if (AesReady == (u32)TRUE) {
		XSecure_AesReset(&AegisAes);
		if (XSecure_AesKeyZero(&AegisAes) == (u32)XST_SUCCESS) {
			Flags |= AEGIS_HO_AES_CLEARED;
		}
		XSecure_SetReset(AegisAes.BaseAddress, XSECURE_CSU_AES_RESET_OFFSET);
	}

	if (PageFree != (u32)TRUE) {
		XFsbl_Printf(DEBUG_PRINT_ALWAYS, "AEGIS: hand-off page not written (no free DDR at 0x%x)\r\n",
			     AEGIS_HANDOFF_PA);
		return;
	}
	Ho->flags = Flags;

	/* A page whose hash does not match is one OP-TEE must not use. */
	if ((DmaReady == (u32)TRUE) && (XSecure_Sha3Initialize(&AegisSha3, &CsuDma) == (s32)XST_SUCCESS) &&
	    (XSecure_Sha3Digest(&AegisSha3, (const u8 *)Ho, (u32)offsetof(struct aegis_zynqmp_handoff, sha3_384),
				(u8 *)Digest) == (u32)XST_SUCCESS)) {
		(void)memcpy(Ho->sha3_384, Digest, sizeof(Ho->sha3_384));
	}
	Xil_DCacheFlushRange((INTPTR)AEGIS_HANDOFF_PA, (INTPTR)AEGIS_HANDOFF_SIZE);

	XFsbl_Printf(DEBUG_PRINT_ALWAYS, "AEGIS: hand-off flags=0x%x meas=%d bh_key_src=0x%08x csu_status=0x%x\r\n",
		     Flags, Ho->count, Aegis.BhKeySrc, CsuStatus);
}

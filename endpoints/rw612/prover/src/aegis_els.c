/* SPDX-License-Identifier: Apache-2.0
 *
 * Device-unique secrets from the RW612's ELS (EdgeLock Secure Subsystem), for the Aegis prover.
 *
 *   slot 0 holds NXP_DIE_MK_SK, the die master key: loaded by the boot ROM from the PUF, never readable by software.
 *   K   = CKDF-SP800-108(slot 0, 12-byte derivation data "AEGIS-RW612\1") -> a free ELS slot, HMAC use only
 *   out = HMAC-SHA256(K, label)                                   computed inside ELS, 32 bytes returned
 *   K is deleted from its slot afterwards.
 *
 * The same chip gives the same output on every boot; another chip gives another one. Software sees `out`, never the
 * die key nor K. A firmware running on this chip can call ELS the same way, so the secret is bound to the chip, not
 * to the firmware (see endpoints/rw612/README.md).
 */
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

#include <mcuxClEls.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxCsslFlowProtection.h>

#include "aegis_els.h"

#define DIE_MASTER_KEY_SLOT 0u

static const uint8_t ddata[MCUXCLELS_CKDF_DERIVATIONDATA_SIZE] __aligned(4) = {'A', 'E', 'G', 'I', 'S', '-',
									      'R', 'W', '6', '1', '2', 1};

/* Run a flow-protected ELS call, check its protection token and its result. */
#define ELS_CALL(ok, fname, call, expect)                                                                         \
	do {                                                                                                      \
		MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r_, t_, call);                                                   \
		(ok) = (MCUX_CSSL_FP_FUNCTION_CALLED(fname) == t_) && (r_ == (expect));                          \
		MCUX_CSSL_FP_FUNCTION_CALL_END();                                                                 \
	} while (0)

static int els_wait(void)
{
	int ok;

	ELS_CALL(ok, mcuxClEls_WaitForOperation, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR),
		 MCUXCLELS_STATUS_OK);
	return ok ? 0 : -1;
}

static int key_props(unsigned slot, uint32_t *word)
{
	mcuxClEls_KeyProp_t p;
	int ok;

	p.word.value = 0;
	ELS_CALL(ok, mcuxClEls_GetKeyProperties, mcuxClEls_GetKeyProperties((mcuxClEls_KeyIndex_t)slot, &p),
		 MCUXCLELS_STATUS_OK);
	*word = p.word.value;
	return ok ? 0 : -1;
}

/* ELS is already on when the application starts: the boot ROM enables it to load the die key (slots 0 to 7 hold the
 * ROM's keys). mcuxClEls_Enable_Async() is not called: it writes the whole ELS_CTRL register (ELS_CTRL = ELS_EN) and
 * would clear whatever else the ROM set there. Only wait until ELS is idle. */
int aegis_els_init(void)
{
	return els_wait();
}

void aegis_els_dump_slots(void)
{
	for (unsigned s = 0; s < MCUXCLELS_KEY_SLOTS; s++) {
		uint32_t w;

		if (key_props(s, &w) == 0 && (w & MCUXCLELS_KEYPROPERTY_VALUE_ACTIVE)) {
			printk("els slot %2u: props 0x%08x\n", s, w);
		}
	}
}

/* A 256-bit key takes two consecutive slots (a base slot and the next one; the die key is slots 0 and 1). Find an
 * even base slot whose pair is empty, from the top (the ROM's keys sit at the bottom). Asking ELS for a 256-bit key
 * in the last slot is a fault, and on this chip an ELS fault resets the chip. */
static int free_slot(void)
{
	for (int s = MCUXCLELS_KEY_SLOTS - 2; s >= 2; s -= 2) {
		uint32_t a, b;

		if (key_props((unsigned)s, &a) == 0 && key_props((unsigned)s + 1u, &b) == 0 &&
		    !(a & MCUXCLELS_KEYPROPERTY_VALUE_ACTIVE) && !(b & MCUXCLELS_KEYPROPERTY_VALUE_ACTIVE)) {
			return s;
		}
	}
	return -1;
}

int aegis_els_derive(const char *label, uint8_t out[32])
{
	static uint8_t in[64] __aligned(4);
	static uint8_t mac[MCUXCLELS_HMAC_OUTPUT_SIZE] __aligned(4);
	mcuxClEls_KeyProp_t prop;
	mcuxClEls_HmacOption_t opt;
	uint32_t master;
	size_t n = strlen(label);
	int slot, ok, rc = -1;

	if (n > sizeof(in) || key_props(DIE_MASTER_KEY_SLOT, &master) != 0 ||
	    !(master & MCUXCLELS_KEYPROPERTY_VALUE_ACTIVE) || !(master & MCUXCLELS_KEYPROPERTY_VALUE_CKDF)) {
		return -2; /* no die master key for derivation */
	}
	slot = free_slot();
	if (slot < 0) {
		return -3;
	}
	prop.word.value = 0;
	prop.bits.ksize = MCUXCLELS_KEYPROPERTY_KEY_SIZE_256;
	prop.bits.kactv = MCUXCLELS_KEYPROPERTY_ACTIVE_TRUE;
	prop.bits.uhmac = MCUXCLELS_KEYPROPERTY_HMAC_TRUE;
	prop.bits.upprot_priv = MCUXCLELS_KEYPROPERTY_PRIVILEGED_TRUE;
	prop.bits.upprot_sec = MCUXCLELS_KEYPROPERTY_SECURE_TRUE;
	ELS_CALL(ok, mcuxClEls_Ckdf_Sp800108_Async,
		 mcuxClEls_Ckdf_Sp800108_Async(DIE_MASTER_KEY_SLOT, (mcuxClEls_KeyIndex_t)slot, prop, ddata),
		 MCUXCLELS_STATUS_OK_WAIT);
	if (!ok || els_wait() != 0) {
		return -4;
	}
	memcpy(in, label, n);
	opt.word.value = 0;
	opt.bits.extkey = MCUXCLELS_HMAC_EXTERNAL_KEY_DISABLE;
	ELS_CALL(ok, mcuxClEls_Hmac_Async, mcuxClEls_Hmac_Async(opt, (mcuxClEls_KeyIndex_t)slot, NULL, in, n, mac),
		 MCUXCLELS_STATUS_OK_WAIT);
	if (ok && els_wait() == 0) {
		memcpy(out, mac, 32);
		rc = 0;
	} else {
		rc = -5;
	}
	memset(mac, 0, sizeof(mac));
	ELS_CALL(ok, mcuxClEls_KeyDelete_Async, mcuxClEls_KeyDelete_Async((mcuxClEls_KeyIndex_t)slot),
		 MCUXCLELS_STATUS_OK_WAIT);
	if (!ok || els_wait() != 0) {
		rc = rc ? rc : -6;
	}
	return rc;
}

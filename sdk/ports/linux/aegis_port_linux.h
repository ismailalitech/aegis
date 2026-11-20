/* SPDX-License-Identifier: Apache-2.0
 *
 * Aegis Prover SDK, port to Linux user space: where a maker of a Linux device starts from.
 *
 * It is the C counterpart of the Python prover (endpoints/zybo/aegis_linux_prover.py), with the same command line,
 * the same profile and the same measurements, so one policy entry of the gateway fits both. The Zybo and the ZynqMP's
 * Linux side still run the Python prover; this port is built and tested on the PC only
 * (tests/host/test_sdk_linux_port.py).
 *
 * What it is, and is not ("software trust", profile aegis-linux-software-v1): nothing here is held by hardware. The
 * identity seed and the exchange root are random bytes made at the first start and kept in files only root can
 * read; the measurements are SHA-256 hashes of files, computed by the running Linux at every quote; the clock is the
 * kernel's. A modified Linux can report false values and read the key. A product moves each of these into its
 * secure world: the seed to a key the kernel cannot read (a TPM, a secure element, a TEE: struct aegis_platform's
 * identity functions, or the whole core in a trusted application as endpoints/zynqmp/optee does), the measurements
 * to the boot chain.
 */
#ifndef AEGIS_PORT_LINUX_H
#define AEGIS_PORT_LINUX_H
#include "aegis_sdk.h"

#define AEGIS_LINUX_PROFILE "aegis-linux-software-v1"
#define AEGIS_LINUX_FW      "linux-sdk" /* the status text says fw=<fw>-<version> */
#define AEGIS_LINUX_VERSION "0.1.0"
/* The measured components: up to 7 groups of files from the command line, and the prover's own executable. Their
 * claims take at most 121 + 8 * 161 bytes, which a PQTOKEN reply of AEGIS_REPLY_MAX bytes carries. */
#define AEGIS_LINUX_MAX_GROUPS   7u
#define AEGIS_LINUX_MAX_FILES    8u
#define AEGIS_LINUX_LABEL_MAX    15u
#define AEGIS_LINUX_EVIDENCE_MAX 1440u

struct aegis_linux {
	struct aegis_prover prover; /* the core's context: this port owns the storage, the core the content */
	struct aegis_platform platform;
	uint8_t work[AEGIS_WORK_LEN(AEGIS_LINUX_EVIDENCE_MAX)];
	struct {
		char label[AEGIS_LINUX_LABEL_MAX + 1];
		const char *path[AEGIS_LINUX_MAX_FILES];
		size_t paths;
	} group[AEGIS_LINUX_MAX_GROUPS + 1];
	struct aegis_measurement meas[AEGIS_LINUX_MAX_GROUPS + 1];
	size_t groups;
	char self[512];             /* the prover's own executable: the last component, PROVER */
	uint64_t started;           /* the clock at aegis_linux_prepare, for the status text's uptime */
};

/* Fill in this port's platform functions and the PROVER component. */
int aegis_linux_prepare(struct aegis_linux *l);
/* One more measured component, "LABEL=path[,path...]": SHA-256 over the files in that order, as one stream. The
 * text is changed in place and must stay valid. */
int aegis_linux_add_measure(struct aegis_linux *l, char *spec);
/* Load the device secrets from the state directory (made at the first start: the directory 0700, the files 0600) and
 * start the core. verifier_pk must stay valid. Returns an enum aegis_result. */
int aegis_linux_start(struct aegis_linux *l, const char *state_dir, const uint8_t *verifier_pk);
#endif

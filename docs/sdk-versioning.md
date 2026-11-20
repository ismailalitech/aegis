<!-- SPDX-License-Identifier: Apache-2.0 -->
# Prover SDK: versions, API and ABI

## The numbers

| Number | Now | Where | Changes when |
|---|---|---|---|
| SDK release | **1.0.0** | `project(aegis_sdk VERSION ...)` in `sdk/CMakeLists.txt`; the CMake package's version | every release (semantic versioning, below) |
| API version | **1** | `AEGIS_SDK_API_VERSION` in `sdk/include/aegis_sdk.h` | an incompatible change of the header (below); always together with a new major release |
| Protocol | labels in the signed messages | `aegis-endpoint-quote-v1`, `aegis-credential-v1`, `aegis-hb-v2`, transcript `v2`, `eat-cose-v1` | a change of what is signed or MACed: a new label, never a changed meaning of an old one |

Release 1.0.0 is API version 1, as it runs on every device in this repository (STM32H573 with TF-M, RW612 with TF-M,
ZynqMP with OP-TEE, Linux, the PC) and as pinned byte for byte by `vectors/sdk-golden/`.

## What API version 1 promises

Everything declared in `sdk/include/aegis_sdk.h` ([`sdk-api-reference.md`](sdk-api-reference.md)) is the API. For
as long as `AEGIS_SDK_API_VERSION` is 1:

- **Functions** keep their names, parameters and contracts. New functions may be added (a minor release).
- **`struct aegis_platform`, `struct aegis_config`, `struct aegis_measurement`** keep their members, in their order
  and with their types: a port written for 1.0.0 compiles and behaves the same with every 1.x release. A new platform
  function (for example the load and store functions a stored endorsement would need, `sdk/README.md`) changes the
  layout of `struct aegis_platform` and so means API version 2.
- **`struct aegis_prover`** is opaque: its layout is in the header only so that its size is known. Its size and
  members may change in any release; that is why `AEGIS_PROVER_INIT` passes `sizeof(struct aegis_prover)` and the
  API version, and `aegis_prover_init` refuses a caller compiled against another layout or version
  (`AEGIS_ERR_VERSION`) instead of writing past its storage.
- **`enum aegis_result`** keeps the value of every name (`AEGIS_OK` is 0, the others as numbered in the reference).
  New results may be added at the end. Treat every nonzero value as a refusal, including ones you do not know.
- **Sizes** (`AEGIS_PK_LEN`, `AEGIS_SIG_LEN`, ...) are those of FIPS 203 and FIPS 204 and do not change. Limits
  (`AEGIS_LINE_MAX`, `AEGIS_REPLY_MAX`, `AEGIS_WORK_MIN`, `AEGIS_WORK_LEN()`, `AEGIS_CRED_MAX`) do not shrink; a
  buffer sized from them stays large enough.
- **The line protocol**: the commands and replies of `aegis_prover_handle_line` and their `ERR` texts stay; a new
  command may be added, and an unknown one is answered `ERR unknown`.
- **Behaviour**: for the same inputs and the same random bytes, the core's replies are the same bytes
  (`tools/sdk_golden.py check`: 0 differences is a release condition). A change of output is a protocol change and
  gets a new label (above), never a silent one.

## The ABI

The SDK ships as source and as a **static library**, `libaegis_sdk.a`. There is no shared library, no symbol
versioning and no promise that objects from two releases link together. Build the library and every file that
includes `aegis_sdk.h` from the same release, with the same compiler target and the same `AEGIS_EAT_COSE` setting.
What remains of an ABI is checked at run time: the size of `struct aegis_prover` and the API version, at
`aegis_prover_init`.

Exported symbols: the functions of the header (`aegis_prover_*`, `aegis_wipe`), `aegis_sha256` (from
`aegis_sha256.h`, installed with the header for ports that measure images), and the internal symbols of KMAC and of
mldsa-native and mlkem-native, all prefixed `aegis_` (`aegis_mldsa_*`, `aegis_mlkem_*`, `aegis_kmac*`). Do not call
the internal ones; they may change in any release.

## Build options

`AEGIS_EAT_COSE=1` adds `aegis_prover_quote_eat()`, the `AEGIS_EAT_*` macros and the `PQEAT` command, and changes
nothing else: not the layout of any structure, not a byte of any other reply. It is part of API version 1 as an
option. A library built without it and a caller built with it fail to link (`aegis_prover_quote_eat` is missing),
which is the intended failure.

## Releases

| Change | Release |
|---|---|
| a fix with the same outputs (golden vectors unchanged), documentation | patch: 1.0.x |
| a new function, a new command, a new result at the end, a new build option off by default | minor: 1.x.0 |
| anything that breaks a promise above | major, with `AEGIS_SDK_API_VERSION` increased, new golden vectors and a fuzz seed family for what is new |

A device in the field keeps working with a verifier of a newer release as long as the protocol labels it uses are
accepted by the verifier's policy (`"transcript"`, `"evidence_format"`, `"heartbeat_mac"`); the verifier, not the
device, decides which versions it still accepts.

## Dependencies

mldsa-native and mlkem-native **v2.0.0** exactly (commits `834a90d5` and `d1b2fe78`). Another version of either is a
change of the cryptography under the SDK: it needs the golden vectors, the ACVP vectors and the fuzzers again before
a release takes it.

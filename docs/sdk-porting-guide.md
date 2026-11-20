<!-- SPDX-License-Identifier: Apache-2.0 -->
# Porting the Aegis Prover SDK to a device

For a device maker who wants a device to be attested by an Aegis verifier: what to build, what to write, in which
order, and how to know it works. The SDK is version 1.0.0 and implements API version 1
([`sdk-versioning.md`](sdk-versioning.md)). Three other documents go with this one:

- [`sdk/README.md`](../sdk/README.md): what the SDK does, the full contract of each platform function and the limits;
- [`sdk-api-reference.md`](sdk-api-reference.md): every declaration of `sdk/include/aegis_sdk.h`, generated from it;
- [`sdk/examples/simulated-device/`](../sdk/examples/simulated-device/): a complete device in one C file, attested end
  to end by the repository's verifier with one command. Read it next to this guide: its sections are numbered like
  the steps below.

## What you get, what you write

```
 your transport (TCP, UART, BLE, a PSA call, a TEE command)  ->  aegis_prover_handle_line()   the SDK
                                                                 or aegis_prover_quote() ...  (libaegis_sdk.a)
                                                                          |
                                         struct aegis_platform: random, clock, measurements   you write this
                                         or evidence, optionally identity and status          (about 150 lines)
```

The SDK is plain C11: no heap, no threads, no operating system, nothing from the C library but `memcpy`, `memset`,
`memcmp`, `strlen` and `strcmp`. It never touches the network and never waits; one call is one request and one reply.
You provide memory, five or six functions, and a way to carry lines (or binary messages) to and from the verifier.

## Step 0: decide where it runs

Everything the SDK holds is secret or must not be changed by less trusted code: the context (identity key, session
key), the work buffer, the stack it runs on, the platform functions and what they read. Put all of it in the
device's secure world:

| Device | Where the SDK runs | Port in this repository |
|---|---|---|
| Arm v8-M with TF-M (STM32H573, RW612) | a TF-M secure partition | `endpoints/stm32h573/tfm-aegis-partition/`, `endpoints/rw612/tfm/aegis_pq/` |
| Arm v8-A with OP-TEE (ZynqMP) | a trusted application | `endpoints/zynqmp/optee/ta/` |
| A microcontroller without a secure world | the whole firmware (and then the whole firmware is trusted) | `endpoints/rw612/prover/` |
| Linux, a PC | a process (software trust only) | `sdk/ports/linux/`, `sdk/ports/host/`, the example |

The verifier's policy names what kind of device it is through the `profile` your platform reports, and grants a
trust level for it (`software`, `device-key`, `trustzone`). Report the profile that is true of your device; see
step 8.

## Step 1: get the sources and build the library

Dependencies: mldsa-native and mlkem-native **v2.0.0** from `pq-code-package` (Apache-2.0, ISC or MIT), unmodified;
the SDK's two configuration headers in `sdk/crypto/` select ML-DSA-65 (reduced RAM) and ML-KEM-768 with the
`aegis_` symbol prefix. The tags this repository is tested with are commit `834a90d5` (mldsa-native) and `d1b2fe78`
(mlkem-native).

```sh
git clone --depth 1 --branch v2.0.0 https://github.com/pq-code-package/mldsa-native.git ~/aegis-tools/mldsa-native
git clone --depth 1 --branch v2.0.0 https://github.com/pq-code-package/mlkem-native.git ~/aegis-tools/mlkem-native
```

Three ways to build, the same five sources each time:

| | Command | Result |
|---|---|---|
| CMake | `cmake -S sdk -B build/sdk && cmake --build build/sdk && cmake --install build/sdk --prefix /opt/aegis-sdk` | `libaegis_sdk.a`, `include/aegis/{aegis_sdk.h,aegis_sha256.h}`, a CMake package: `find_package(aegis_sdk 1.0)` then link `aegis::sdk` |
| GNU make | `make -C sdk` (`lib`, `ports`, `examples`, `install PREFIX=...`) | `sdk/build/libaegis_sdk.a` and the programs |
| Your firmware build | add `sdk/src/aegis_proto.c`, `aegis_kmac.c`, `aegis_sha256.c`, `sdk/crypto/mlkem_unit.c`, `<mldsa-native>/mldsa/mldsa_native.c` | define `MLD_CONFIG_FILE="aegis_mldsa_config.h"`; include paths `sdk/include sdk/src sdk/crypto/mldsa sdk/crypto/mlkem <mldsa-native>/mldsa <mlkem-native>/mlkem` |

Options (CMake `-D...=ON`, make `...=1`):

| Option | Default | Effect |
|---|---|---|
| `AEGIS_EAT_COSE` | off | the core also answers `PQEAT` with an EAT in COSE_Sign1 ([`evidence-format.md`](evidence-format.md)); declares `aegis_prover_quote_eat()`. Must be the same for the library and every file that includes `aegis_sdk.h` (the CMake target passes it on). Without it the core is byte for byte the default. |
| `MLDSA_NATIVE_DIR`, `MLKEM_NATIVE_DIR` | `~/aegis-tools/{mldsa,mlkem}-native/{mldsa,mlkem}` | where the two libraries are (`$AEGIS_TOOLS` moves the default) |
| `AEGIS_SDK_BUILD_PORTS` (CMake) | on | `aegis_host_prover` and `aegis_linux_prover` (POSIX) |
| `AEGIS_SDK_BUILD_EXAMPLES` (CMake) | on | `aegis_sim_device` (POSIX) |
| `AEGIS_SDK_WERROR` (CMake), `WARN=` (make) | on | warnings in the SDK's own files are errors |

A cross build of the library alone needs nothing but the compiler:

```sh
make -C sdk CC=arm-none-eabi-gcc AR=arm-none-eabi-ar \
     CFLAGS='-Os -mcpu=cortex-m33 -mthumb -ffunction-sections -fdata-sections' lib
```

## Step 2: budget the resources

Measured for a Cortex-M33 (GCC 14.2, `-Os`):

| | Size | Source |
|---|---|---|
| Code, the library's five objects | 32.8 KB (34.5 KB with `AEGIS_EAT_COSE`): core 8.0 KB, ML-DSA-65 13.0 KB, ML-KEM-768 9.7 KB, KMAC 1.3 KB, SHA-256 0.8 KB | `arm-none-eabi-size` of the cross build above, before the linker drops unused sections |
| Context, `struct aegis_prover` | 13232 bytes of RAM | `sizeof` on the STM32H573 partition |
| Work buffer | at least `AEGIS_WORK_MIN` (1234 bytes); `AEGIS_WORK_LEN(evidence_max)` for every credential the protocol allows (2854 with small evidence); at least `AEGIS_EAT_WORK_MIN` (1962) with `AEGIS_EAT_COSE` | `aegis_sdk.h` |
| Stack, quote or exchange start (ML-DSA-65 signing) | 18.7 KB | `tools/stack_estimate.py` on the TF-M build |
| Stack, exchange finish (ML-KEM-768 decapsulation) | 18.4 KB | same |
| Stack, start (ML-DSA-65 key generation) | 16.4 KB | same |
| Stack, heartbeat | 0.7 KB | same |
| Line transport buffers | request `AEGIS_LINE_MAX` (14600 bytes), reply `AEGIS_REPLY_MAX` (9600) | `aegis_sdk.h`; a binary transport needs neither |

The stack figures are estimates from GCC's `-fstack-usage` and the call graph, not proven bounds; on the STM32 the
measured high-water mark was 168 bytes above them. **Give the thread or partition that calls the core 24 KB of stack
or more, and measure the high-water mark on your device** (the TF-M ports report it in every heartbeat). Nothing is
allocated at run time and nothing is kept across a reset.

## Step 3: randomness (`random`)

Fill `n` bytes from the chip's TRNG, or a DRBG seeded from it, read inside the secure world. The bytes go into every
exchange's ML-KEM key and, hedged, into every ML-DSA signature. Return nonzero on any failure: the core then refuses
the request, it never substitutes anything.

The generator must not produce the same bytes again after a reset. The core cannot see that (it keeps no state across
a reset), and repeated exchange keys let a recorded exchange be replayed: `tests/host/test_reset_replay_check.py`
shows the attack, `tests/board/reset_replay_check.py` checks a real device for it.

Example: `sim_random` (getrandom). Chips: `psa_generate_random` in the STM32 partition; the ELS random generator in
the RW612 partition; `TEE_GenerateRandom` in the OP-TEE port.

## Step 4: time (`clock`, `clock_hz`)

A counter that only moves forward, `clock_hz` counts per second (1 or more), any origin, read at every request. It
ends sessions on the device's own clock when the verifier's credential has expired, whatever the network does
([`endpoint-expiry.md`](endpoint-expiry.md)). Nothing outside the secure world may be able to set, slow or stop it,
including by entering a power mode. Return nonzero whenever you can no longer vouch for it; the session then ends and
none starts.

This is the step that needs thought on a microcontroller, because the usual tick timers belong to the non-secure
side. The STM32 port runs the RTC as a binary counter on the internal oscillator, makes both secure and checks at
every reading that they still are (`clock_hz = 250`). The RW612 port uses the secure SysTick and checks its rate
once. The OP-TEE port asks the TEE for the time's protection level and reports no clock below the level it needs.
Example: `sim_clock`, `CLOCK_MONOTONIC` in milliseconds (`clock_hz = 1000`), which protects nothing.

## Step 5: evidence (`measurements`, or `evidence`)

Either:

- **`measurements`** with `profile` and `version`: point the core at an array of `struct aegis_measurement` (label
  such as `"SPE"`, `"NSPE"`, `"APP"`; a 32-byte digest; a description). The core encodes them as CBOR claims (or, with
  `AEGIS_EAT_COSE`, as measured components in an EAT) and signs them. The measurements must be taken by code that the
  measured code cannot change: the boot stage before it, or the secure world before the non-secure image runs.
  Example: `measure_image` and `sim_measurements` hash the image files once at start. RW612: both flash partitions
  hashed before the non-secure image starts. ZynqMP: what the first-stage loader handed over.
  For a PC or Linux device the digest is `sha256sum` of the image.
- **`evidence`**: your platform's own signed token for the challenge (TF-M's initial attestation token on the STM32),
  which the core signs as it is.

The verifier compares each label and digest with the reference values in its policy (`"allowed"`); anything not
listed is a quarantine. For TF-M images signed for MCUboot, `tools/image_measurement.py` prints the digests the
boot loader records.

## Step 6: identity (`identity_seed` and `exchange_root`, or the platform's key)

Two 32-byte, device-unique secrets, derived from a hardware key that only the secure world can use, with different
derivation labels:

- `identity_seed`: the core derives the device's ML-DSA-65 key pair from it at every start (the same pair each time);
- `exchange_root`: mixed with fresh randomness into every exchange's ML-KEM key (defence in depth for a weak
  generator, not a substitute for a good one).

Both must never be stored in the clear or visible to the non-secure side; pass them to `aegis_prover_init` and wipe
your copies with `aegis_wipe`. 32 zero bytes are refused: that is what a failed derivation leaves. Hardware keys used
by the ports here: the STM32's DHUK through SAES, the RW612's ELS die key, OP-TEE's hardware unique key. Example:
`derive()` hashes a secret file with two labels, which stands in for such a key derivation.

If the key lives in a secure element or key store instead, set `identity_public_key` and `identity_sign` (pure
ML-DSA-65, empty context, hedged) and pass `identity_seed = NULL`; the core then never sees the secret key
(`sdk/ports/host` shows the shape with `AEGIS_HOST_PLATFORM_KEY`).

## Step 7: the optional parts (`status`, `compat`)

`status` writes a short `key=value;key=value` text for heartbeats; it is MACed with the session key, not secret, and
must not contain a `ttl=` key chosen by anyone less trusted (the core appends the real one). `compat` is 0 for every
new port.

## Step 8: start the core and carry the messages

```c
static const struct aegis_platform platform = { .random = ..., .clock = ..., .clock_hz = ..., .measurements = ...,
                                                .profile = "...", .version = "...", .status = ... };
static struct aegis_prover prover;                      /* secure RAM, not retained across a reset */
static uint8_t work[AEGIS_WORK_LEN(1024)];
static const uint8_t verifier_pk[AEGIS_PK_LEN] = { ... };   /* pinned in the measured image */

const struct aegis_config cfg = { .platform = &platform, .verifier_pk = verifier_pk, .identity_seed = seed,
                                  .exchange_root = root, .work = work, .work_len = sizeof(work) };
int rc = AEGIS_PROVER_INIT(&prover, &cfg);             /* at every start, before the first request */
aegis_wipe(seed, sizeof(seed)); aegis_wipe(root, sizeof(root));
```

`AEGIS_PROVER_INIT` passes `sizeof(struct aegis_prover)` and `AEGIS_SDK_API_VERSION`, so a platform file compiled
against another header is refused with `AEGIS_ERR_VERSION` instead of corrupting memory. `platform` and
`verifier_pk` are kept by pointer: make them `const`, in memory only the secure world can write.

Then the transport: read a line (up to `AEGIS_LINE_MAX`; answer `ERR too-long` yourself beyond it), **copy it into
secure memory**, call `aegis_prover_handle_line(&prover, line, reply, AEGIS_REPLY_MAX)`, send the reply and `\r\n`.
One context serves one request at a time: serialise the calls. Call `aegis_prover_poll` from a timer if the session
key should be wiped the moment the session ends. A transport with its own framing uses the binary operations
(`aegis_prover_quote`, `_kem_init`, `_kem_finish`, `_session`, `_heartbeat`) instead; the STM32 partition's PSA
messages are those.

The verifier's key: the public key of the verifier that will issue credentials to the device, from its
`identity.json` (`tools/gen_gateway_pin.py --identity ... --out gateway_pk.h` writes it as a C header). Only
credentials signed with that key start a session.

## Step 9: the verifier's side

One policy entry per device ([`pc-verifier.md`](pc-verifier.md), [`architecture.md`](architecture.md)):

```json
{"name": "my-device-1", "kind": "aegis-device", "profile": "aegis-rw612-tfm-v1", "host": "...", "port": 7444,
 "pq_pub_file": "keys/my-device-1.mldsa65.pub", "transcript": "v2", "provision": true, "heartbeat_mac": "kmac256",
 "allowed": [{"type": "SPE", "measurement_value": "..."}, {"type": "NSPE", "measurement_value": "..."}]}
```

The verifier accepts a closed set of profiles per kind and grants each a trust level (`PLAIN_KINDS` in
`gateway/aegisd/fleet.py`): `aegis-linux-software-v1` (trust `software`), `aegis-rw612-els-v1` (`device-key`),
`aegis-rw612-tfm-v1` and `aegis-zynqmp-optee-v1` (`trustzone`). A new device family whose key and measurements are
held differently needs its own profile name, and adding it to the verifier is a reviewed change of the verifier, not
of the SDK: the profile is the verifier's statement of how far it trusts that kind of device. Until then, report the
profile that does not claim more than your device gives (the example reports `aegis-linux-software-v1`).

Enrol the device's key: endorsed at production ([`enrolment.md`](enrolment.md), `"endorsement": "required"`), or
trust on first use (`fleet.py enroll-pq`) for a bench.

## Step 10: check the port

| Check | How |
|---|---|
| It is admitted, with a session bound to its quote, heartbeats and a quarantine on a changed image | the flow of `sdk/examples/simulated-device/run.sh` against your device: `fleet.py enroll-pq`, `check`, `once`, `session`, a heartbeat |
| Each platform function failing refuses the request | make `random` and `clock` fail once each (`tests/fuzz/fuzz_sdk_core.c` does it for the PC port) |
| The clock ends the session | move your clock past the credential's lifetime (`tests/board/expiry_check.py` on a board) |
| No replay after a reset | `tests/board/reset_replay_check.py` |
| The evidence is readable without Aegis code | with `AEGIS_EAT_COSE`: `fleet.py export-evidence`, then `tools/verify_evidence.py pack` |
| The core is unchanged | `tools/sdk_golden.py check` (0 differences against `vectors/sdk-golden/`) |
| Stack | the high-water mark under the longest operation (ML-DSA signing) with your transport on top |

## Before shipping

- [ ] The context, work buffer, stack, platform structure and verifier key are in secure memory; the structure and
      the key are `const`.
- [ ] Requests are copied into secure memory before the core reads them.
- [ ] `random` is a TRNG or a DRBG seeded from one, and does not repeat after a reset.
- [ ] `clock` cannot be set, slowed or stopped from outside the secure world, and fails rather than guess.
- [ ] Measurements are taken by code the measured code cannot change.
- [ ] Seed and root come from a hardware key, are wiped after `aegis_prover_init`, and never leave the secure world.
- [ ] The context is not retained or saved across a reset.
- [ ] Debug access is closed on production devices.
- [ ] The reported profile is the one that is true of the device.
- [ ] The library and the header come from the same SDK release, with the same `AEGIS_EAT_COSE` setting.

What the SDK does not protect against (physical attacks, firmware that holds the key and lies, a device without a
secure counter) is in the "Limits" section of [`sdk/README.md`](../sdk/README.md) and in
[`threat-model.md`](threat-model.md).

# Aegis Prover SDK

The device's side of Aegis attestation, as one C source that every chip builds, and the small platform layer a
device maker writes for it. API version 1 (`AEGIS_SDK_API_VERSION` in `include/aegis_sdk.h`).

A device with the SDK can do four things for a verifier (the Aegis gateway, or the portable verifier of
`docs/pc-verifier.md`):

1. **Quote.** Sign evidence about its software for the verifier's challenge with its ML-DSA-65 identity key.
2. **Session.** Make an ML-KEM-768 key for that same quote, sign the two together (one transcript), and accept the
   verifier's signed credential for exactly that exchange. Both sides then hold a session key.
3. **Heartbeat.** Prove the session cheaply between attestations: KMAC256 over a nonce, a counter and a status text.
4. **End the session by itself.** The credential carries a lifetime; the device wipes the session key on its own
   clock when that is over, whatever the network does.

`docs/architecture.md` has the protocol and its reasons; the head of `src/aegis_proto.c` has every construction.

## What is in here

```
sdk/
  include/aegis_sdk.h        the whole public interface: platform layer, context, operations, sizes
  src/aegis_proto.c          the protocol core (state machine, claims, transcript, line transport)
  src/aegis_kmac.[ch]        KMAC256 (NIST SP 800-185), self-contained
  src/aegis_sha256.[ch]      SHA-256, one call: the key fingerprint; ports use it to measure images
  crypto/                    configurations for mldsa-native and mlkem-native v2.0.0 (not included: see Build)
  ports/host/                reference port for a PC: the worked example below, and what the tests run
  ports/linux/               a prover for Linux userspace on the same core
  tests/                     small PC checks of KMAC and of the ML-DSA configuration
```

The ports to chips live with their build systems:

| Device | Platform file | Secure world | Transport | State |
|---|---|---|---|---|
| STM32H573, TF-M | `endpoints/stm32h573/tfm-aegis-partition/aegis_pq_attest.c` | TF-M secure partition | PSA messages, one per operation | built, PC-tested against the image in the field, byte for byte |
| RW612, TF-M | `endpoints/rw612/tfm/aegis_pq/aegis_pq.c` | TF-M secure partition | lines through one PSA message | secure image built, not on a board |
| RW612, single image | `endpoints/rw612/prover/src/main.c` | none (the whole firmware) | lines over TCP | source only (no Zephyr workspace on the build PC) |
| ZynqMP, OP-TEE | `endpoints/zynqmp/optee/ta/aegis_ta.c` | trusted application | lines through one TA command | PC-tested on a stand-in for OP-TEE (`optee/tests/run.sh`); no `.ta` built on this PC |
| Linux | `sdk/ports/linux/aegis_port_linux.c` | none (a process) | lines over TCP | PC-tested; the Linux endpoints on the bench still run the Python prover, `endpoints/zybo/aegis_linux_prover.py` |
| PC | `sdk/ports/host/aegis_port_host.c` | none | lines over TCP | the tests and the fuzzers run it |

## How it fits together

```
 verifier  <--- your transport (TCP, UART, BLE, a PSA call from the non-secure side) --->  device
                                                                   |
                                         aegis_prover_handle_line()  or  aegis_prover_quote() ...
                                                                   |
                                                    the core: sdk/src/aegis_proto.c
                                                                   |
                                    struct aegis_platform: random, clock, measurements or evidence,
                                    optionally the identity key and a status text       <- you write this
```

The core never touches the network and never blocks. It is a function from one request to one reply. You carry the
bytes; that part of the device can be untrusted, because everything it carries is signed, MACed or public.

There are two ways to call it, with the same state machine behind both:

- **Text lines.** `aegis_prover_handle_line(&prover, line, reply, cap)`: the protocol as the gateway speaks it to
  `kind: aegis-device` endpoints (`PQKEY`, `PQCHAL`, `PQKEMINIT`, `PQKEMFIN`, `PQHB`, `PQSESSION`; binary fields in
  hex). Use this unless you have a reason not to: the gateway and the PC verifier work with it as they are.
- **Binary operations.** `aegis_prover_quote`, `_kem_init`, `_kem_finish`, `_session`, `_heartbeat`: the same steps
  with pointers and lengths, for a transport that has its own framing. The STM32 partition's PSA messages are these.

## Build

The core needs mldsa-native and mlkem-native v2.0.0 (`pq-code-package`, Apache-2.0 or ISC or MIT); the two
configuration headers in `crypto/` select ML-DSA-65 with reduced RAM and ML-KEM-768, with the `aegis_` name prefix.
Add to your build:

```
sdk/src/aegis_proto.c  sdk/src/aegis_kmac.c  sdk/src/aegis_sha256.c
sdk/crypto/mlkem_unit.c                     (mlkem-native, compiled in its own unit)
<mldsa-native>/mldsa/mldsa_native.c         with -DMLD_CONFIG_FILE="aegis_mldsa_config.h"
include paths: sdk/include sdk/src sdk/crypto/mldsa sdk/crypto/mlkem <mldsa-native>/mldsa <mlkem-native>/mlkem
```

and your platform file. The PC build, complete:

```sh
N=~/aegis-tools
gcc -O2 -D_GNU_SOURCE -DMLD_CONFIG_FILE='"aegis_mldsa_config.h"' \
    -Isdk/include -Isdk/src -Isdk/ports/host -Isdk/crypto/mldsa -Isdk/crypto/mlkem \
    -I$N/mldsa-native/mldsa -I$N/mlkem-native/mlkem \
    sdk/ports/host/host_main.c sdk/ports/host/aegis_port_host.c \
    sdk/src/aegis_proto.c sdk/src/aegis_sha256.c sdk/src/aegis_kmac.c sdk/crypto/mlkem_unit.c \
    $N/mldsa-native/mldsa/mldsa_native.c -o aegis_host_prover
```

`tests/host/test_rw612_proto.py` builds exactly this and runs the gateway's own code against it.

What it costs on a Cortex-M33 (GCC 14, `-Os`, the STM32H573 partition):

| | |
|---|---|
| Context (`struct aegis_prover`) | 13216 bytes of RAM: both identity keys, one signature, one ML-KEM key pair, the session |
| Work buffer | 1234 bytes at least (`AEGIS_WORK_MIN`); 2854 for every credential the protocol allows (`AEGIS_WORK_LEN`) |
| Stack, quote or exchange start (ML-DSA-65 signature) | 18.7 KB below the transport's entry; the core's own frames are 136 bytes of it |
| Stack, exchange finish (ML-KEM decapsulation) | 18.4 KB |
| Stack, start (ML-DSA-65 key generation) | 16.4 KB |
| Stack, heartbeat | 0.8 KB |

The stack is mldsa-native's and mlkem-native's; `tools/stack_estimate.py <TF-M build>` recomputes the figures from
GCC's `-fstack-usage` output and the image's call graph. Give the thread or partition that calls the core 24 KB or
more, and watch the high-water mark (the TF-M ports report it in every heartbeat).

## The platform layer

One structure of functions, `struct aegis_platform`. Each gets your `user` pointer back and returns 0 for success.
**Any other return value makes the core refuse the request that needed the function.** It never substitutes a
default: no randomness means no signature, no clock means no session, no measurement means no quote.

| Member | Required | Contract | Security requirement |
|---|---|---|---|
| `random(user, out, n)` | yes | Fill `n` bytes (the core asks for 32 at a time). | From the chip's TRNG or a DRBG seeded from it, read inside the secure world. It must not produce the same bytes again after a reset: the bytes go into each exchange's ML-KEM key, and a repeated key lets a recorded exchange be replayed (`tests/host/test_reset_replay_check.py`). A failure refuses the request; 32 zero bytes for an exchange key do too. |
| `clock(user, &now)`, `clock_hz` | yes | A count that only advances, `clock_hz` counts a second, any origin. Read at every request. | Nothing outside the secure world can set, slow or stop it: not the non-secure image, not a power mode it can enter. Return nonzero whenever you can no longer say so (the clock source changed, a wrap may have been missed); the session then ends and none starts. Without such a counter the device cannot end a session by itself. |
| `measurements(user, &list, &count)`, `profile`, `version` | one of these two | Point `*list` at your array of `struct aegis_measurement` (label, 32-byte digest, description), valid until the next call. The core encodes them as CBOR claims with `profile` and `version`. | Taken by code that the measured code cannot change: the boot stage before it, or the secure world before the non-secure image runs. A port that hashes storage when asked (the single-image prover, the PC port) reports what is stored, not what was started, and its `profile` should say so. The verifier's policy keys on `profile`. |
| `evidence(user, challenge, out, cap, &len)` | one of these two | Write your platform's own token for this challenge (at most `cap` bytes). The core signs it unchanged. | As above, for whatever produced the token (TF-M's initial attestation service on the STM32). |
| `identity_public_key`, `identity_sign` | no, both or neither | The key lives in the platform: give the public key, and sign with pure ML-DSA-65, empty context, hedged (FIPS 204 `ML-DSA.Sign`). | The secret key never leaves the element that holds it. Leave both `NULL` to let the core hold the key (next table). |
| `status(user, buf, cap)` | no | A short status text for heartbeats in the line transport (`key=value;key=value`), terminated, shorter than `cap`. | It is MACed, not secret. Never let a less trusted party choose a `ttl=` key in it: the core appends the real one. |
| `compat` | no | 0. The two `AEGIS_COMPAT_*` flags keep the STM32 image in the field byte-compatible. | |

And what you hand to `aegis_prover_init` in `struct aegis_config`:

| Member | Contract | Security requirement |
|---|---|---|
| `identity_seed` | 32 bytes; the core derives the ML-DSA-65 key pair from it at every start (the same pair each time). `NULL` when the platform holds the key. | Device-unique, derived from a hardware secret that only the secure world can use (the STM32's DHUK through SAES, the RW612's ELS die key, OP-TEE's hardware unique key from the PUF). Never stored in the clear, never visible to the non-secure side. The core does not keep it; wipe your copy (`aegis_wipe`). |
| `exchange_root` | 32 bytes, mixed into every exchange's ML-KEM key with fresh randomness. | A second secret from the same hardware key, with its own derivation label. It is defence in depth for a weak generator, not a substitute for one. |
| `verifier_pk` | The verifier's ML-DSA-65 public key, 1952 bytes. Not copied. | Part of the measured, signed image (ROM). Only credentials under this key start a session; whoever can change it owns the device's sessions. |
| `work`, `work_len` | The work buffer, in secure RAM. | |

### State and persistence

The core keeps everything in the context you provide and in the work buffer, and **needs no persistent storage**.
This is a requirement, not only a convenience:

- Put the context in secure RAM. It holds the identity secret key (unless the platform holds it), the pending
  decapsulation key and the session key.
- Call `aegis_prover_init` at every start, before the first request. It wipes the context. A session and the quote
  that an exchange may continue must not outlive a reset, so do not place the context in retention RAM and do not
  save it.
- One context serves one request at a time. There is no locking inside: serialise the calls.
- Call `aegis_prover_poll` from a timer if you want the session key wiped at the moment the session ends rather than
  at the next request.

## Porting guide, with the PC port as the example

`ports/host/aegis_port_host.c` is about 150 lines and numbered in the order below. Read it next to this list.

1. **Randomness.** `host_random` calls `getrandom`. On a chip: the TRNG driver or the secure world's DRBG service.
   The STM32 port calls TF-M's `psa_generate_random` and keeps the status to answer with.
2. **Time.** `host_clock` returns `CLOCK_MONOTONIC` seconds, `clock_hz = 1`. On a chip this is the part that needs
   thought, because the usual tick timers belong to the non-secure side. The STM32 port runs the RTC as a binary
   counter on the internal oscillator, makes both secure, and checks at every reading that they still are
   (`clock_hz = 250`). The RW612 port uses the secure SysTick and verifies its rate once against the processor
   clock. The OP-TEE port asks for the time's protection level and reports no clock below 1000.
3. **Measurements.** `host_measurements` hashes the files it was given and fills its own array. On a chip with a
   measuring boot stage you only report: the RW612 port hashes both flash partitions once, before the non-secure
   image runs; the OP-TEE port reports what the first-stage loader handed over; the STM32 port gives TF-M's token
   through `evidence` instead.
4. **Identity.** By default the PC port passes a seed to the core. With `platform_key` it keeps the key pair itself
   and gives the core `host_identity_public_key` and `host_identity_sign`: the shape of a secure-element port.
5. **Status text**, if you use the line transport.
6. **Start.** `aegis_host_start` fills `struct aegis_config` and calls `AEGIS_PROVER_INIT(&prover, &cfg)`. The macro
   passes `sizeof(struct aegis_prover)` and the API version, so a platform file built against another header is
   refused instead of corrupting memory.

Then the transport, `ports/host/host_main.c`: read a line, call `aegis_prover_handle_line`, send the reply. Answer
`ERR too-long` yourself for a line beyond `AEGIS_LINE_MAX`. That is the whole integration.

Check your port the way the repository checks its own:

- Run the gateway's code against it: `tests/host/test_rw612_proto.py` shows every step (attestation, an exchange
  bound by the transcript, heartbeats, the refusals, the session's end with a clock you can move).
- Make each platform function fail once and see the request refused. The fuzz harness does this for the PC port
  (`tests/fuzz/fuzz_sdk_core.c`: random draws that fail or give zeros, a clock that fails, runs backwards or jumps).
- Reset the device and replay a recorded exchange: `tests/board/reset_replay_check.py`.

## Results

Operations return `enum aegis_result`. `AEGIS_OK` is 0; with any other value nothing was written to the outputs. The
line transport answers `ERR <reason>` (the header lists the text for each value); a binary transport maps them to
its own codes, as the STM32 port does to PSA statuses. A refused credential ends the pending exchange and leaves an
established session alone.

## What must stay in the secure world

- The context, the work buffer, the seed and the exchange root, and the stack the core runs on.
- The platform functions and everything they read: the generator, the counter and its clock source, the stored
  measurements, the pinned verifier key.
- Debug access. A debugger can stop the clock and read the keys; ship with it closed.

What may be outside: the transport, including the buffers the request and the reply travel in (the ports copy the
request into secure memory before the core reads it).

## Limits

- **A transcript stops a swap between honest images only.** It shows that one boot of the code holding the identity
  key signed exactly this quote and then made this ML-KEM key for it. Firmware that holds the key and lies can sign a
  transcript for a quote another image made, as it could forge the quote. Preventing that needs an identity key that
  depends on the measured code (derived from the measurements, or released by the boot chain only to the measured
  image). In every port here the key depends on the chip only. That is future work, and the place for it is the
  platform's identity functions.
- **Nothing is measured again for the exchange.** A quote says what was measured when the platform took its
  measurements, not what runs now.
- **One quote at a time.** A second verifier asking for a quote between the first one's quote and its exchange makes
  that exchange unbound; the verifier asks again.
- **The credential is matched as text.** The core looks for `"key":"hex"` and `"key":digits` in the signed body and
  relies on the verifier writing canonical JSON (no spaces, each key once). It is not a JSON parser.
- **The session clock is as good as the platform's counter.** A device without a secure counter (the single-image
  prover, Linux) ends sessions on a clock its own firmware could change, and its profile says "software" or
  "device-key" trust accordingly.
- **Physical attacks.** The ML-DSA and ML-KEM code is mldsa-native and mlkem-native portable C: constant-time by
  design, with hedged signing, and with no countermeasures against power analysis or fault injection.
- **Classical parts remain where the platform has them.** The STM32's token is signed by TF-M with ES256 inside the
  ML-DSA signature; the post-quantum claim is the outer signature's.

## Where later work attaches

Nothing of these is in version 1; the seams are marked in `src/aegis_proto.c`.

- **Endorsed enrolment.** Today a device trusts one pinned verifier key and the verifier learns device keys at
  enrolment. A manufacturer's endorsement of the identity key, and a credential chain in place of the single pinned
  key, both end in `check_credential()` and `struct aegis_config.verifier_pk`. An endorsement that must be stored on
  the device would be the first persistent item: a pair of load and store functions added to
  `struct aegis_platform`, with a new `AEGIS_SDK_API_VERSION`.
- **EAT and COSE.** The claims are encoded in one function, `make_claims()`; a platform can already supply a
  finished token through `evidence`. An EAT profile replaces the first or comes in through the second, and the
  signature framing is in `sign_work()`.
- **A measurement-dependent key** (see Limits): `identity_public_key` and `identity_sign`.

## Tests

| What | Where |
|---|---|
| The gateway's code against the core on the PC | `tests/host/test_rw612_proto.py` and the tests that import it |
| The same answers as before the SDK, byte for byte, for a fixed generator | `tests/host/test_sdk_golden.py`, `tools/sdk_golden.py` (records from the commit before the SDK, and compares whole fuzz corpora) |
| One fuzz harness on the core, both transports, every configuration, with an independent model of the protocol | `tests/fuzz/fuzz_sdk_core.c`, `tests/fuzz/run.sh`; seeds of all families in `tests/fuzz/seeds` |
| The STM32 port's own code (PSA messages, the RTC, the stack mark) on PC stand-ins | `tests/fuzz/stm32`, `STM32=1 tests/fuzz/run.sh`, `tests/host/test_stm32_partition.py` |
| The OP-TEE port on a stand-in for OP-TEE | `endpoints/zynqmp/optee/tests/run.sh` |
| The Linux port | `tests/host/test_sdk_linux_port.py` |

<!-- SPDX-License-Identifier: Apache-2.0 -->
# Simulated device

A device made from the Aegis Prover SDK and nothing else, on a PC: `sim_device.c` (about 280 lines) is a complete
integration, built against the SDK's static library and its two public headers only. It serves the Aegis line
protocol on `127.0.0.1` and is attested by the repository's own verifier (`gateway/aegisd/fleet.py`) exactly as a
board is.

It is a teaching device and protects nothing: its "hardware key" is a file, its keys are in process memory, its clock
is the operating system's. It says so: it reports the profile `aegis-linux-software-v1`, and the verifier admits it
with trust `software`, never `trustzone` or `device-key`.

## Run it

From the repository root, with mldsa-native and mlkem-native v2.0.0 in `~/aegis-tools` (or `MLDSA_NATIVE_DIR` and
`MLKEM_NATIVE_DIR` set) and a Python with `cryptography` 47 or later (`tools/setup_host.sh` makes `.venv`; the
standalone checkers also need `pycose==1.1.0` and `cbor2<6`):

```sh
sdk/examples/simulated-device/run.sh
```

Expected output (keys, digests, ports and the time-to-live differ from run to run):

```
 1 Python with ML-DSA-65 (cryptography)               ok  (cryptography 50.0.2)
 2 build the SDK and the device (AEGIS_EAT_COSE=1)    ok  (116908 bytes)
 3 verifier identity (aegisd.py init)                 ok  (key sha256 1056b135bd1eda46...)
 4 device secret and firmware image                   ok  (APP sha256 5b283b26b8968513...)
 5 start the simulated device                         ok  (127.0.0.1:44565, key sha256 76b10071c49c93eb...)
 6 enrol the device key (fleet.py enroll-pq)          ok
 7 policy check (fleet.py check)                      ok
 8 attest and provision (fleet.py once)               ok  (ADMITTED, trust software, session bound to the quote, eat-cose-v1)
 9 same session on both sides (fleet.py session)      ok
10 KMAC256 heartbeat with the session key             ok  (fw=sim-1.0.0;requests=6;ttl=3825 counter 1)
11 evidence pack: tools/verify_evidence.py            ok  (EAT, result and keys verified)
12 changed image: quarantined                         ok  (component APP not allowed (measurement e597c63bfbc3...))
13 audit log: tools/verify_audit.py                   ok  (11 entries in 3 signed batches)
RESULT: PASS (work directory /tmp/aegis-sim.XXXXXX, removed)
```

It exits non-zero at the first step that fails and keeps the work directory with every command's output in `log/`.
`KEEP=1` keeps it in any case; `AEGIS_EAT_COSE=0` runs the SDK's default evidence (CBOR claims) and skips step 11,
which needs EAT. `tests/host/test_sdk_example.py` runs the script in both modes.

## What each step shows

| Step | What happens | Where to read about it |
|---|---|---|
| 2 | `make -C sdk lib examples`: `libaegis_sdk.a` (core, KMAC, SHA-256, mldsa-native, mlkem-native) and the device | `docs/sdk-porting-guide.md`, "Build" |
| 3 | A verifier identity on this PC (`aegisd.py init --platform linux --key-store software`); its public key is the one the device pins | `docs/pc-verifier.md` |
| 5 | The device derives its identity seed and exchange root from its secret, measures its image once, starts the core | `sim_device.c` |
| 6 | The verifier pins the device's ML-DSA-65 key by trust on first use (a product would use endorsed enrolment) | `docs/enrolment.md` |
| 8 | Challenge, quote (an EAT in COSE_Sign1), appraisal, then an ML-KEM-768 exchange that continues the quote (`"transcript": "v2"`) and a credential the device checks against its pinned key | `docs/architecture.md`, `docs/evidence-format.md` |
| 9-10 | Both sides name the same session; a heartbeat is MACed with the session key | `docs/endpoint-expiry.md` |
| 11 | The verifier exports the evidence and its signed attestation result; a checker that imports no Aegis code verifies them | `docs/evidence-format.md` |
| 12 | One bit of the image changed, the device restarted: refused on its measurement, and its session is withdrawn | |
| 13 | The verifier's signed audit log of all of the above, checked without Aegis code | `docs/audit-and-policy.md` |

## Run it by hand

```sh
make -C sdk AEGIS_EAT_COSE=1 lib examples                    # sdk/build-eat/aegis_sim_device
sdk/build-eat/aegis_sim_device --verifier-pk verifier.pub --secret device-secret.hex --image APP=firmware.bin
# READY 41235 <sha256 of the device's public key>
```

`verifier.pub` is the verifier's ML-DSA-65 public key in hex (the `pk` of `identity.json`), `device-secret.hex` 32
random bytes in hex. `run.sh` writes the policy entry that goes with it; copy it from there.

## From here to a real device

`sim_device.c` is numbered like the porting guide: (1) randomness, (2) time, (3) measurements, (4) identity,
(5) status text, (6) transport. `docs/sdk-porting-guide.md` says for each what it must become on a chip and which
port in this repository already does it (STM32H573 with TF-M, RW612, ZynqMP with OP-TEE).

<!-- SPDX-License-Identifier: Apache-2.0 -->
# Aegis 1.0: release notes

Aegis 1.0 is a bench prototype of a post-quantum attestation gateway, published with its source, its tests and the
records of what ran on the boards. It is not security-certified; the known limits at the end of this page are part of
the release, not footnotes to it.

## What is in it

### Components

| Component | Where | What it does |
|---|---|---|
| Gateway verifier | `gateway/aegisd/` (`fleet.py`, `aegisd.py`) | challenges each endpoint every 30 seconds, appraises its evidence against the policy, admits it with an ML-KEM-768 credential and session or quarantines it with the reason ([`architecture.md`](architecture.md)) |
| Gateway identity and quote | `gateway/aegisd/aegisd.py`, `host/aegis_verify.py` | the gateway signs its own quote (ML-DSA-65), which a PC verifier checks; also runs on an ordinary Linux host (`--platform linux`, [`pc-verifier.md`](pc-verifier.md)) |
| Fabric accelerator | `hw/` | a SHA-3 sponge/NTT block in the PolarFire fabric that speeds up liboqs's ML-KEM-768 and ML-DSA-65 ([`accelerator-v2.md`](accelerator-v2.md)) |
| Prover SDK | `sdk/` | the one protocol core every endpoint builds, with a platform layer per chip ([`../sdk/README.md`](../sdk/README.md)) |
| Endpoint firmware | `endpoints/` | the SDK's ports: a TF-M partition on the STM32H573 and on the RW612, an OP-TEE trusted application on the ZynqMP, a Linux prover |
| Endorser | `provision/aegis_provision.py` | endorses device keys at the bench instead of trust on first use ([`enrolment.md`](enrolment.md)); signs policies |
| Enforcement | `gateway/enforce/` | an nftables ruleset and a one-port VLAN design ([`vlan-enforcement.md`](vlan-enforcement.md)); tested in network namespaces only |
| Standalone checkers | `tools/verify_evidence.py`, `tools/verify_audit.py` | check evidence packs, the audit log and signed policies with third-party libraries only, without this repository's code |
| Bench tools | `tools/regression.sh`, `tools/soak.py`, `tools/bench_watch.py` | the regression, the soak runner and the watchdog ([`soak-and-watchdogs.md`](soak-and-watchdogs.md)) |

### Boards

| Role | Board | Secure environment | Image on the bench |
|---|---|---|---|
| Gateway | Microchip PolarFire SoC Discovery Kit | Linux, the fabric accelerator | `gateway/` |
| Endpoint x2 | STM32H573I-DK | TF-M v2.3.0 plus the Aegis PQ partition | the partition on the Prover SDK (SPE 9de76167) |
| Endpoint | NXP FRDM-RW612 | NXP's TF-M v2.1.4 plus the Aegis partition, key from the ELS die key | `rw612-tfm-0.3.2` ([`../endpoints/rw612/tfm/README.md`](../endpoints/rw612/tfm/README.md)) |
| Endpoint | Zynq UltraScale+ (TE0807 module) | OP-TEE trusted application | TA 0.2.0 on the Prover SDK ([`zynqmp-sdk-port.md`](zynqmp-sdk-port.md)) |
| Endpoint that cannot attest | Arduino Uno | none | quarantined on every cycle, by design |

The images are those of the endorsement records
([`../evidence/endorsed-enrolment/bench/`](../evidence/endorsed-enrolment/bench/)) and of the ZynqMP's bench result
([`zynqmp-sdk-port.md`](zynqmp-sdk-port.md), "Result on the bench").

### Standards

| What | Standard | Status |
|---|---|---|
| Signatures | ML-DSA-65, FIPS 204 | final |
| Key exchange | ML-KEM-768, FIPS 203 | final |
| Heartbeats | KMAC256, SP 800-185 | final |
| Evidence | EAT, RFC 9711, in a COSE_Sign1 | RFC |
| ML-DSA in COSE | RFC 9964 | RFC |
| Attestation results | EAR (`draft-ietf-rats-ear-06`), AR4SI (`draft-ietf-rats-ar4si-11`) | **IETF drafts** |

Details, including the exact profile strings and claim numbers: [`evidence-format.md`](evidence-format.md).

### Protocol features

- **One transcript** (`"transcript": "v2"`): the endpoint signs its ML-KEM key over the quote it issued in this boot,
  so a session goes only to the code whose quote was appraised ([`architecture.md`](architecture.md), "One
  transcript"; [`../evidence/transcript-v2/`](../evidence/transcript-v2/)). On every attesting endpoint of the bench.
- **Endorsed enrolment** (`"endorsement": "required"`): a device key is trusted only from a record signed by a listed
  endorser ([`enrolment.md`](enrolment.md)). On every attesting endpoint of the bench.
- **Session end on the device's own clock** ([`endpoint-expiry.md`](endpoint-expiry.md)).
- **Opt-in, off by default** ([`evidence-format.md`](evidence-format.md),
  [`audit-and-policy.md`](audit-and-policy.md)): EAT/COSE evidence and the verifier's signed attestation results
  (EAR), the evidence pack (`fleet.py export-evidence`); a signed, hash-chained audit log of the verifier's decisions
  (`"audit_log": true`); a policy signed by an operator key that is not on the gateway, with a version that never goes
  back.

### Prover SDK, API version 1

Release 1.0.0 of the SDK is API version 1 ([`sdk-versioning.md`](sdk-versioning.md)): functions keep their names,
parameters and contracts across 1.x, and the core's answers are held byte for byte to recorded traces
(`tools/sdk_golden.py check`). It is packaged as a static library with a CMake package and two public headers. A device
maker starts from [`sdk-porting-guide.md`](sdk-porting-guide.md); every declaration is in
[`sdk-api-reference.md`](sdk-api-reference.md), generated from the header and checked by the host tests.

### Evaluation container

[`../container/`](../container/README.md) runs, with no hardware and no network, every part of Aegis that does not
need a board: release hygiene, the SDK's golden traces and API reference, the simulated device attested end to end,
the gateway's quote service and PC verifier, the host test suite and the red-team parser fuzzer.

## Try it without hardware

```sh
docker build -f container/Dockerfile --build-arg REVISION=$(git rev-parse HEAD) -t aegis-eval .
docker run --rm --network none aegis-eval            # every stage, about 2 minutes
```

Or on the PC itself, after `tools/setup_host.sh`:

```sh
sdk/examples/simulated-device/run.sh                 # a device on the SDK: enrolled, admitted, heartbeat, quarantined
.venv/bin/python -m unittest discover -s tests/host  # the host test suite
```

The simulated device ([`../sdk/examples/simulated-device/README.md`](../sdk/examples/simulated-device/README.md)) is
attested by the same `fleet.py` the gateway runs; it reports trust `software`, never `trustzone`. Its EAT evidence pack
and the verifier's signed audit log are checked by the standalone checkers.

## How it was verified

- **Host tests**: `tests/host`, about 450 tests (EAT, transcript, endorsement, audit and policy, the SDK's ports and
  docs, the soak runner), run by CI and as the first stage of the regression.
- **Regression**: `tools/regression.sh --board --with-expiry` has 14 stages (host tests, red team, RTL simulation,
  ACVP, the boards, the endpoints' session end). It passed 14 of 14 three times during the soak, with the ZynqMP
  connected ([`../evidence/soak-20261121/NOTE.md`](../evidence/soak-20261121/NOTE.md)); the run before is
  [`../evidence/console/regression-14of14-20261119.txt`](../evidence/console/regression-14of14-20261119.txt).
- **Fuzzing**: `tests/fuzz/fuzz_sdk_core.c` (libFuzzer) runs the SDK core against a model of the protocol in the
  RW612, STM32 and EAT modes, in CI (`.github/workflows/ci.yml`); earlier records:
  [`../evidence/rw612-tfm/fuzzing.txt`](../evidence/rw612-tfm/fuzzing.txt),
  [`../evidence/stm32-kemfix/fuzzing.txt`](../evidence/stm32-kemfix/fuzzing.txt). `tests/redteam/fuzz_host.py` sends
  hostile tokens, quotes, records, logs and policies to the verifier's parsers.
- **ACVP**: the fabric accelerator passes the 265 NIST ACVP cases
  ([`../evidence/accel-v2/after-fix/summary.txt`](../evidence/accel-v2/after-fix/summary.txt)).
- **Soak**: 3 hours on three live boards (the second STM32, the RW612, the ZynqMP), credentials shortened to 600 s,
  an expiry round every hour: 40 of 40 samples answered, 37 session renewals per endpoint, no quarantine, reset or
  reboot ([`../evidence/soak-20261121/`](../evidence/soak-20261121/NOTE.md)). The report says FAIL on one item, a false
  clock-rate estimate of the runner (the note explains it; `tools/soak.py` is fixed). The first STM32 was unplugged
  for this run.

## Known limits

These hold for 1.0 as released; [`threat-model.md`](threat-model.md), section 5, is the full list.

- **The EAT option is off in every board image.** EAT/COSE evidence and signed results run on the PC and in the
  simulated device; no board on the bench runs them.
- **EAR and AR4SI are IETF drafts.** Their claim numbers and profile string can still change; a later draft's output
  is refused rather than misread ([`evidence-format.md`](evidence-format.md)).
- **Root on the gateway** can still write the audit log again (shown only by an anchor kept off the gateway), leave
  entries out as they happen, and replace or remove the policy signers file
  ([`threat-model.md`](threat-model.md), T26 and T27). The signed audit log and the signed policy have run on the PC
  only.
- **Development keys.** The STM32s run in the Open state with TF-M's public development signing keys, and the RW612
  with development keys and no secure boot (the state of the bench). Anyone with the debugger can replace a secure
  image; the transcript does not defend against an image built by an attacker
  ([`threat-model.md`](threat-model.md), limitations 1 and 10).
- **The ZynqMP's lock-down is not part of main.**
- **Soak: 3 hours only.** Trend bounds (memory, descriptors, disk) are not judged under 4 hours; counter wraps and drift
  over several days are untested.
- **No VLAN enforcement on the bench network.** The nftables ruleset and the one-port VLAN design are tested in
  network namespaces only, not on a switch ([`vlan-enforcement.md`](vlan-enforcement.md)).
- **Side channels and fault injection are not evaluated** ([`threat-model.md`](threat-model.md), limitation 5).

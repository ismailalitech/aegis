<!-- SPDX-License-Identifier: Apache-2.0 -->
# Evaluation container

Everything in Aegis that runs without hardware, in one container and from one command:

| Stage | What it shows |
|---|---|
| `release-hygiene` | every source file names its licence (SPDX), no key or secret is tracked (`tools/check_release.py`) |
| `sdk-golden` | the Prover SDK's core answers byte for byte as recorded (`tools/sdk_golden.py check`) |
| `sdk-api-reference` | the API reference is the header's (`tools/gen_sdk_api_ref.py --check`) |
| `simulated-device` | a device built on the Prover SDK, attested by the verifier (`fleet.py`, the code the gateway runs) on the portable PC-verifier flow: enrolled, admitted with an ML-KEM-768 session bound to its quote, a KMAC256 heartbeat, quarantined when its image changes; its EAT evidence pack and the verifier's signed audit log checked by the standalone checkers that import no Aegis code (`sdk/examples/simulated-device/`) |
| `gateway-quote` | the gateway's identity and quote service (`aegisd.py serve --platform linux`) and the PC verifier of the gateway (`host/aegis_verify.py`): enrolled, quote accepted |
| `host-tests` | the host test suite, `tests/host` (about 450 tests) |
| `redteam-host` | 2000 malformed tokens and quotes against the verifier's parsers (`tests/redteam/fuzz_host.py`) |

What it cannot show: anything on the boards (the PolarFire gateway's fabric accelerator, the STM32, RW612 and ZynqMP
endpoints, network enforcement on a switch). Those are in `tools/regression.sh --board` and the records under
`evidence/`. The fuzzers (`tests/fuzz/run.sh`, clang and libFuzzer) and the enforcement tests in network namespaces
(root) are not in the container either; CI runs them (`.github/workflows/ci.yml`).

## Commands

From the repository root, with Docker (or Podman: replace `docker` by `podman`):

```sh
docker build -f container/Dockerfile --build-arg REVISION=$(git rev-parse HEAD) -t aegis-eval .
docker run --rm --network none aegis-eval                 # every stage, about 2 minutes
docker run --rm --network none aegis-eval quick           # all but host-tests and redteam-host, under a minute
docker run --rm --network none aegis-eval simulated-device gateway-quote    # chosen stages
docker run --rm aegis-eval --list                         # the stage names
```

Keep the logs: `mkdir -p container/out && chmod 777 container/out`, then add
`-v "$PWD/container/out:/out" -e AEGIS_EVAL_OUT=/out`. Or with Compose, which does both:

```sh
mkdir -p container/out && chmod 777 container/out
docker compose -f container/compose.yaml build
docker compose -f container/compose.yaml run --rm eval
```

To look around inside: `docker run --rm -it --network none --entrypoint /bin/bash aegis-eval`, then for example
`KEEP=1 sdk/examples/simulated-device/run.sh` and read the work directory it names (the policy, the verdicts, the
evidence pack, the audit log).

## Expected output

`docker run --rm --network none aegis-eval` prints (times, digests, ports and counts differ):

```
Aegis evaluation, logs in /tmp/aegis-eval.XXXXXX
PASS release-hygiene       0s  640 tracked files: 0 without an SPDX line, 4 third-party with their own notice, 8 exempt; 0 secrets
PASS sdk-golden            4s  stm32: 31 recorded seeds, 0 differ line: 18 recorded seeds, 0 differ
PASS sdk-api-reference     0s  /home/aegis/aegis/docs/sdk-api-reference.md is up to date
PASS simulated-device      3s  8 attest and provision (fleet.py once) ok (ADMITTED, trust software, session bound to the quote, eat-cose-v1) 12 changed image: quarantined ok (component APP not allowed (measurement ...))
PASS gateway-quote         0s  gateway quote accepted
PASS host-tests           88s  Ran 403 tests in 87.382s OK (skipped=14)
PASS redteam-host         16s  nothing broken
passed 7, failed 0
```

The exit status is 0 only if every stage passed. A failed stage prints `FAIL` and the path of its log.

The 14 skipped host tests are those of the TPM-sealed verifier key: they need `swtpm` and `tpm2-pytss` (12) or a
real TPM (2), which the container does not have. Everything else runs.

## What is pinned

| | How | Where |
|---|---|---|
| Base image | `ubuntu:24.04` by digest | `ARG BASE_IMAGE` in the Dockerfile |
| Ubuntu packages (gcc, make, cmake, Python 3.12, OpenSSL) | the Ubuntu archive as it was at one moment, `APT::Snapshot` (snapshot.ubuntu.com) | `ARG UBUNTU_SNAPSHOT=20261115T000000Z`; `--build-arg UBUNTU_SNAPSHOT=` uses the current archive instead. The snapshot is HTTPS only, so `ca-certificates` alone comes from the current archive first; a snapshot index that fails to download fails the build |
| Python packages | every package, transitive ones too, by version and by the SHA-256 of its wheel (x86_64 and aarch64), `pip install --require-hashes` | `requirements.txt`, made from `requirements.in` |
| mldsa-native, mlkem-native v2.0.0, liboqs 0.16.0 | tag and commit; the build stops if the tag is not that commit | `ARG MLDSA_NATIVE_COMMIT`, `MLKEM_NATIVE_COMMIT`, `LIBOQS_COMMIT` |

The image runs as user `aegis` (uid 10001), with no network at run time (`--network none`; the verifier, the device
and the gateway service talk over 127.0.0.1 inside the container). It holds no keys: every key is made during the run,
in a temporary directory, and is gone with the container. Nor does it hold a machine id: the Linux-host identity of
`aegisd.py` is bound to one, so `/etc/machine-id` links to `/tmp/machine-id`, which `evaluate.sh` fills with a new
random id when each container starts; no two containers share one.

## Without Docker

`container/evaluate.sh` runs the same stages on a Linux PC that has the repository's `.venv` (`tools/setup_host.sh`,
or `python3 -m venv .venv && .venv/bin/pip install --require-hashes --no-deps -r container/requirements.txt`), gcc,
make and cmake, and mldsa-native, mlkem-native and liboqs in `~/aegis-tools` as CI puts them there.

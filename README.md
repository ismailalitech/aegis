# Aegis

A bench prototype of a **post-quantum attestation gateway**. A PolarFire SoC Discovery Kit decides
which endpoints may be trusted, from evidence their secure hardware produces, and gives admitted
endpoints a credential and an ML-KEM-768 session key. Identities and quotes are signed with
ML-DSA-65 (FIPS 204); key exchange uses ML-KEM-768 (FIPS 203).

![The Aegis system: a PC checks the gateway, the PolarFire gateway attests the endpoints, two STM32s and an NXP RW612 are admitted and the Arduino Uno is quarantined](docs/diagrams/system-overview.svg)

What has run on the bench, each with the record or test that shows it:

- The PolarFire gateway signs its own quote, which the PC verifier accepts
  ([`evidence/console/quote-accepted.json`](evidence/console/quote-accepted.json)), and attests endpoints (`gateway/`).
- A fabric SHA-3 sponge/NTT accelerator (`hw/`) passes the 265 NIST ACVP cases
  ([`evidence/accel-v2/after-fix/summary.txt`](evidence/accel-v2/after-fix/summary.txt)) and makes liboqs's
  ML-KEM-768 and ML-DSA-65 1.19 to 1.54 times faster on the board
  ([`evidence/accel-v2/after-fix/speed.md`](evidence/accel-v2/after-fix/speed.md)).
- Two STM32H573I-DK (TF-M v2.3.0 plus a PQ partition) are attested over Ethernet and held in sessions with KMAC256
  heartbeats (`endpoints/stm32h573/`;
  [`evidence/two-boards/board2-first-boot.txt`](evidence/two-boards/board2-first-boot.txt),
  [`evidence/stm32-sstack/heartbeat-sstack.txt`](evidence/stm32-sstack/heartbeat-sstack.txt)).
- An NXP FRDM-RW612 runs the prover as a TF-M secure partition: its ML-DSA-65 key comes from the die key in ELS,
  both flash partitions are measured before non-secure code runs, and the verdict says trustzone trust
  (`endpoints/rw612/tfm/`; [`evidence/rw612-tfm/trustzone-prover.txt`](evidence/rw612-tfm/trustzone-prover.txt)).
  The earlier single-image Zephyr prover is in `endpoints/rw612/prover/`.
- A Zynq UltraScale+ endpoint (TE0807 module) runs the protocol in an OP-TEE trusted application, with Linux only
  carrying the lines, and has been admitted (`endpoints/zynqmp/`;
  [`evidence/zynqmp/optee-phase-a.txt`](evidence/zynqmp/optee-phase-a.txt)). It replaces the retired Zybo board;
  the Zybo's Linux prover script (`endpoints/zybo/aegis_linux_prover.py`) is still the software-trust prover
  ([`evidence/zynqmp/software-trust.txt`](evidence/zynqmp/software-trust.txt)).
- A non-secure image signed with the trusted key but changed is quarantined on its measurement
  ([`evidence/console/demo-journal.txt`](evidence/console/demo-journal.txt)), and an Arduino Uno that cannot attest
  is quarantined on every cycle ([`evidence/console/two-endpoints-demo.txt`](evidence/console/two-endpoints-demo.txt)).
- Fuzzers for both secure partitions ([`evidence/rw612-tfm/fuzzing.txt`](evidence/rw612-tfm/fuzzing.txt),
  [`evidence/stm32-kemfix/fuzzing.txt`](evidence/stm32-kemfix/fuzzing.txt)), a red-team harness (`tests/redteam/`)
  and a regression run check it. `tools/regression.sh --board --with-expiry` has 14 stages; the last full run passed
  14 of 14 ([`evidence/console/regression-14of14-20261119.txt`](evidence/console/regression-14of14-20261119.txt)).
  Its first stage, the host suite in `tests/host/`, runs 87 tests.
- The gateway's identity and quote service also runs on an ordinary Linux host (`aegisd --platform linux`), with
  OpenSSL (3.5 or later) or liboqs as the ML-DSA/ML-KEM backend
  ([`tests/host/test_linux_host_verifier.py`](tests/host/test_linux_host_verifier.py)).
- Claims maps with non-scalar or repeated CBOR keys are refused
  ([`tests/host/test_cbor_keys.py`](tests/host/test_cbor_keys.py)).

One decision cycle, every 30 seconds per endpoint (the default `--interval` of `gateway/aegisd/fleet.py`):

![Challenge, evidence, checks, then ADMITTED with an ML-KEM credential and a session, or QUARANTINED with the reason](docs/diagrams/decision-cycle.svg)

Read `docs/architecture.md` first, then `docs/threat-model.md` for what is **not** claimed. This is
a development prototype: development signing keys and trust-on-first-use enrolment are stated limits. Network
enforcement is not in place on the bench: the nftables ruleset and the one-port VLAN design are tested in network
namespaces only ([`tests/host/test_enforcement.sh`](tests/host/test_enforcement.sh),
[`tests/host/test_enforcement_vlan.sh`](tests/host/test_enforcement_vlan.sh);
[`evidence/console/enforcement.txt`](evidence/console/enforcement.txt),
[`evidence/console/enforcement-vlan.txt`](evidence/console/enforcement-vlan.txt)), not on a VLAN switch.

## Running it

Copy `bench.env.example` to `bench.env` and set your addresses. Then:

    tools/setup_host.sh        # Python environment and liboqs
    tools/regression.sh        # host stages; add --board for the real boards
                               # and --with-expiry for the endpoints' session end (about 3 minutes more)
    tools/demo.sh              # the live demo (needs the boards and an STM32 programmer)
    sudo tests/host/test_enforcement.sh   # the enforcement rules in network namespaces
    tests/fuzz/run.sh                     # fuzz the RW612 partition's protocol code (STM32=1: the STM32 partition)
    tools/bench_watch.py --gateway <addr> # log when the gateway or an endpoint goes quiet (--once: one check)

## Layout

`gateway/` services and policy, `common/` wire formats and crypto glue, `host/` PC tools,
`endpoints/` firmware for the prover nodes, `hw/` fabric RTL, `tests/`, `vectors/` (ACVP
checksums), `evidence/` (published records of real runs), `docs/` (architecture, threat model,
whitepaper, datasheet, phase notes, `diagrams/` generated by `tools/gen_diagrams.py`, `figures/`
Libero screenshots).

Apache-2.0 licensed (see `LICENSE`); the project's own source files carry SPDX headers. Third-party files shipped in
the repository keep their own licences and are listed in `NOTICE`. Not security-certified; do not use it to protect
anything real.

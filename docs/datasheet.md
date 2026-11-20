# Aegis gateway: datasheet (prototype)

**Post-quantum attestation gateway on PolarFire SoC** · bench prototype, 2026-11-20 · not certified

| | |
|---|---|
| Platform | PolarFire SoC Discovery Kit, MPFS095T-1FCSG325E; Linux 6.18 on 3 U54 cores, FreeRTOS on the 4th |
| Signatures / key exchange | ML-DSA-65 (FIPS 204) / ML-KEM-768 (FIPS 203) |
| Endpoints | STM32H573I-DK x2, TF-M v2.3.0 plus PQ partition, key derived from the hardware-unique key; NXP FRDM-RW612, TF-M secure partition, key from the ELS die key; Zynq UltraScale+ (TE0807), OP-TEE trusted application (`evidence/zynqmp/optee-phase-a.txt`) |
| Evidence | TF-M attestation token (image measurements, signer ids) + ML-DSA-65 signature over the challenge |
| Decisions | ADMITTED or QUARANTINED with a reason; credential revoked on quarantine; ML-KEM session with heartbeats |
| Cycle | decision every 30 s per endpoint (configurable) |
| Interfaces | gateway TCP 7443 (identity, quote); endpoint TCP 7444 (line protocol); Ethernet 1 Gb/s |
| Fabric accelerator | version 2: SHA-3 sponge kept in the fabric with DMA squeeze to DDR, and the FIPS 203/204 NTT, at 50 MHz; about 18,300 LUTs, synthesis estimate 95.9 MHz (`accelerator-v2.md`) |
| Verified | NIST ACVP vectors: PC, PolarFire with the fabric sponge (`evidence/accel-v2/after-fix/summary.txt`), STM32; regression 14 of 14 stages with `--board --with-expiry` (`evidence/console/regression-14of14-20261119.txt`); host suite 87 tests (`tests/host/`) |
| Not included | network enforcement on the bench (the ruleset is tested in network namespaces only, not on a VLAN switch), hardware-held gateway key, side-channel or fault testing |

**Performance (U54 core, liboqs 0.16.0, software / with the fabric accelerator):** ML-KEM-768 keygen 1.22 / 0.94 ms,
encaps 1.44 / 1.14 ms, decaps 1.78 / 1.40 ms; ML-DSA-65 keypair 3.95 / 2.57 ms, sign 13.9 / 11.6 ms, verify 4.09 /
2.78 ms: 1.19 to 1.54 times faster (`evidence/accel-v2/after-fix/speed.md`).

**Verifier on any Linux host:** `aegisd --platform linux` serves identity and quote without the PolarFire system
controller, with OpenSSL (3.5 or later) or liboqs as the ML-DSA/ML-KEM backend (`tests/host/test_linux_host_verifier.py`).

**Licence** Apache-2.0 · https://github.com/ismailalitech/aegis

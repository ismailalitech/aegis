# Aegis gateway: datasheet (prototype)

**Post-quantum attestation gateway on PolarFire SoC** · bench prototype, 2026-11-16 · not certified

| | |
|---|---|
| Platform | PolarFire SoC Discovery Kit, MPFS095T-1FCSG325E; Linux 6.18 on 3 U54 cores, FreeRTOS on the 4th |
| Signatures / key exchange | ML-DSA-65 (FIPS 204) / ML-KEM-768 (FIPS 203) |
| Endpoint | STM32H573I-DK, TF-M v2.3.0 plus PQ partition; key derived from the hardware-unique key |
| Evidence | TF-M attestation token (image measurements, signer ids) + ML-DSA-65 signature over the challenge |
| Decisions | ADMITTED or QUARANTINED with a reason; credential revoked on quarantine; ML-KEM session with heartbeats |
| Cycle | decision every 30 s per endpoint (configurable) |
| Interfaces | gateway TCP 7443 (identity, quote); endpoint TCP 7444 (line protocol); Ethernet 1 Gb/s |
| Fabric accelerator | Keccak-f[1600] (24 cycles) and one NTT unit at 50 MHz; about 11,800 4-LUT; timing met (2.06 ns worst slack) |
| Verified | NIST ACVP vectors: PC, PolarFire with fabric Keccak, STM32; 12 of 12 regression stages |
| Not included | network enforcement (needs a managed 802.1Q switch), hardware-held gateway key, side-channel or fault testing |

**Performance (U54 core, liboqs 0.16.0):** ML-KEM-768 keygen 1.22 ms, encaps 1.42 ms, decaps 1.76 ms;
ML-DSA-65 keypair 3.99 ms, sign 14.3 ms, verify 4.12 ms. The fabric accelerator is correct but adds
8 to 12 percent end to end (bus transfer cost); it is not a speed-up in this version.

**Licence** Apache-2.0 · https://github.com/ismailalitech/aegis

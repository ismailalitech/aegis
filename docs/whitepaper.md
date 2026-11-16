# Aegis: a post-quantum attestation gateway on PolarFire SoC

Status: bench prototype, measured on real boards, 2026-11-16. Read `threat-model.md` for everything
this paper does not claim.

## 1. Problem

Industrial and embedded networks mostly trust a device because it is plugged in. Zero-trust
guidance asks for the opposite: a device earns access by proving what it is and what it runs, and
keeps proving it. Two things make that hard for small devices today: the proofs are signed with
classical public-key schemes that a large quantum computer could forge, and the devices cannot run
the heavy verification code a gateway needs.

Aegis shows a small gateway that decides admission from **evidence the endpoint's own secure
hardware produces**, signed and exchanged with the NIST post-quantum algorithms ML-DSA-65
(FIPS 204) and ML-KEM-768 (FIPS 203).

## 2. What was built

- **Gateway**: a PolarFire SoC Discovery Kit (MPFS095T). Linux on three U54 cores runs `aegisd`
  (its own signed quote) and `aegis-fleet` (attest, admit or quarantine, credentials, session
  heartbeats). A fabric block accelerates Keccak and the NTT; a FreeRTOS supervisor runs on the
  fourth core.
- **Endpoint**: an STM32H573I-DK running TF-M v2.3.0 with an added post-quantum partition. An
  ML-DSA-65 identity key is derived inside the secure world from the chip's hardware-unique key and
  signs the TF-M attestation token together with the gateway's challenge.
- **Legacy node**: an Arduino Uno with no keys and no measured boot, to show a device that cannot
  attest.
- **Verifier on a PC** that checks the gateway's own quote, a red-team harness, and a regression
  that exercises all of it on the boards.

## 3. Protocol in one page

1. The gateway sends a fresh challenge to the endpoint.
2. The endpoint returns a TF-M attestation token (image measurements, signer ids, the challenge)
   plus an ML-DSA-65 signature over it from the device key. The first time, the key is enrolled by
   trust on first use.
3. The gateway checks the signature, the nonce and the measurements against its policy. A mismatch
   in any of them means **QUARANTINED**, with the reason logged.
4. If admitted, the gateway runs an ML-KEM-768 exchange: the endpoint encapsulation key is signed by
   the device key; the gateway encapsulates and returns the ciphertext with a credential signed by
   the gateway's ML-DSA-65 key and bound to that ciphertext. The endpoint, which pins the gateway
   key in its secure image, checks both.
5. Both sides now hold a session key. Heartbeats under that key keep the admission alive between
   full re-attestations; a lost or failed session leads to re-provisioning at the next cycle.

## 4. Results

| Claim | Evidence |
|---|---|
| Correct ML-KEM-768 / ML-DSA-65 | NIST ACVP vectors pass on the PC, on the PolarFire with the fabric doing every Keccak permutation, and on the STM32 Cortex-M33 code (265 of 265) |
| Tampered but correctly signed firmware is caught | a Non-Secure image signed with the trusted key boots normally and is QUARANTINED on its measurement; its credential is revoked |
| Devices that cannot attest are refused | the Uno is QUARANTINED on every cycle |
| Attacks on the protocol | 3000 token mutations accepted: 0; 800 hostile endpoint replies admitted: 0; classic-token downgrade and KEM key replay refused; malformed frames do not stop the services |
| Whole system | the regression passes 12 of 12 stages (host and boards) |

**The fabric accelerator is not faster.** Keccak runs in 24 cycles at 50 MHz, but moving 100
uncached words over the APB bus per permutation costs 16.7 us. ML-KEM-768 keygen goes from 1.22 to
1.32 ms and ML-DSA-65 sign from 14.3 to 15.5 ms with the fabric. The accelerator is correct and is a
base for keeping data in the fabric, not a speed-up as built. The core adds about 11,800 4-LUTs
(36,373 LE, 38.9 %, for the whole design) and meets timing with 2.06 ns worst slack.

## 5. Honest limits

- **No network enforcement yet.** The gateway decides, but a single-port board cannot sit in the
  traffic path. Real separation needs a managed 802.1Q switch; the nftables hook and kernel support
  exist.
- **The gateway's own key lives in software.** The board's chip is the non-"S" part: it has no
  hardware crypto block and does not hand a PUF-protected key to software. Linux file permissions
  protect it, and enrolment is trust on first use.
- **Development keys** sign the endpoint images and TF-M's published attestation key is used;
  only the ML-DSA signature is security-relevant. The endpoint is left in its open (not closed)
  product state.
- **Not evaluated**: side channels, fault injection, power loss during provisioning.
- Not certified. Do not use it to protect anything real.

## 6. Where it goes next

A managed switch to turn decisions into blocked traffic; a gateway key held by hardware (an "S"
device or an external secure element); closing the endpoint and using production keys; moving
whole sponge and polynomial steps into the fabric to make the accelerator pay off.

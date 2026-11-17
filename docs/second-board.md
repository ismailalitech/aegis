# Two chips, two keys (17 November 2026)

Question: is the endpoint's ML-DSA-65 key really bound to the chip, or would any STM32H573 with the same firmware have
it? Answered with a second STM32H573I-DK (ST-LINK `002E0039...`) set up exactly like the endpoint (`003D002F...`).

## Setting up the second board

| Step | Result |
|---|---|
| Backup as received, under reset: both 2 MiB flash views and the option bytes (`backups/stm32h573/20261117-182207-board2-as-received`) | it held a small program in its first three sectors; TrustZone already on, all flash secure |
| Mass erase; option bytes set to the endpoint's (secure watermarks bank 1 sectors 0-0x43, none in bank 2; hide protection sectors 0-0x13) | all 34 option-byte fields equal to the endpoint's |
| Written: TF-M BL2 copied from the endpoint's backup (`0x0C010000`, 96 KiB), secure image `tfm-s-v2.3.0-aegis-pq-hb-hedged-kmac`, non-secure prover 0.4.0 | each write verified |
| Left erased: scratch, BL2 counters, TF-M's emulated OTP, NV counters, protected and internal storage | BL2 provisioned the board on its first boot (`evidence/two-boards/board2-first-boot.txt`), then booted both images; `AEGIS-PROVER 0.4.0 ready` |

## Results (`evidence/two-boards/`)

| | Board 1 (endpoint) | Board 2 |
|---|---|---|
| Aegis ML-DSA-65 key (from the chip's DHUK through SAES) | sha256 `29b953e6...` | sha256 `c9e2aa6e...` |
| PSA attestation instance ID (TF-M dummy provisioning) | `01078c18...` | `01078c18...` (same) |
| PSA implementation ID | `a0a1a2...bf` | `a0a1a2...bf` (same) |

- The two ML-DSA keys differ in 1,941 of 1,952 bytes (equal bytes by chance: about 8 expected).
- The PSA identity is the same on both: TF-M's development provisioning gives every board the same initial attestation
  key. A verifier that trusted PSA tokens alone could not tell these two boards apart.
- **Impersonation refused:** the gateway's checker, given board 2's quote under board 1's name (board 1's pinned key),
  answers `ML-DSA-65 quote signature invalid`; with board 2's own key it admits it. Same firmware, same PSA identity,
  different chip: not admitted.

This closes threat T14 on two chips. It does not show uniqueness over a population, and it relies on ST's statement
that the DHUK is unique per device.

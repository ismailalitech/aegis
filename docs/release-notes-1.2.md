<!-- SPDX-License-Identifier: Apache-2.0 -->
# Aegis 1.2: release notes

Changes since [Aegis 1.1](release-notes-1.1.md). The Prover SDK is unchanged (release 1.0.0, API version 1); every
change is in the verifier, its checkers and its documentation. A 1.1 reader accepts what 1.2 writes, and a 1.2
checker accepts 1.1 packs (as "export time not signed"); the new policy keys are opt-in.

## Verifier

- **A signed evidence pack.** `fleet.py export-evidence` adds `manifest.cose`: the verifier signs the manifest, so
  every listed file and the export time are covered (typ `application/vnd.aegis.evidence-pack+cbor`, so it cannot
  stand in for a result, an audit batch or a policy). Every 1.2 result carries `aegis.pack-signed`, and
  `tools/verify_evidence.py` refuses such a pack without a valid `manifest.cose`; `--require-signed-export` refuses
  any unsigned pack ([`evidence-format.md`](evidence-format.md)).
- **The audit head in the result.** With the audit log on, a result names the last audit batch on disk when it was
  signed (`aegis.audit-log`, `aegis.audit-batch`, `aegis.audit-head`), so a result and the log can be checked
  against each other ([`audit-and-policy.md`](audit-and-policy.md)).
- **Warnings in the result.** `aegis.warnings` carries the verdict's warning and the appraisal's details (at most 8
  texts of 300 characters).
- **Policy: `"disabled"` and `"min_trust"`.** A disabled entry is not contacted, is quarantined every cycle and its
  credential revoked. `"min_trust"` (per entry or for the fleet) sets a floor on the trust label, strongest first:
  `trustzone` > `trustzone-devkey` > `device-key` > `software` > `development-shared-key`; a verdict below it is
  quarantined, and a floor an entry can never meet is refused when the policy loads
  ([`architecture.md`](architecture.md)).

## For readers of Aegis data

- **Schemas** (JSON Schema 2020-12) for the pack manifest, the state file and its verdicts, the policy, the
  endorsement record and the signers file: [`schemas/`](schemas/).
- **[`data-formats.md`](data-formats.md):** every `aegis.*` claim with its type and digest, the closed sets of trust
  and enrolment values, the older quote format and the PSA claims Aegis reads.
- **Synthetic golden vectors** made by Aegis's own writers, with a test that keeps them valid:
  `tests/vectors/aegis-1.2/` (`tools/gen_golden_vectors.py`).

## On the bench (21 November 2026)

1.2 deployed on the gateway; regression 14 of 14. A 1.2 pack of STM32 board 2 verifies with
`--require-signed-export`. With `"min_trust": "trustzone"` on that board the gateway logged `QUARANTINED policy:
entry stm32h573-dk-2 can NEVER meet min_trust trustzone: its trust is trustzone-devkey` and did not contact it; with
`"disabled": true`, `QUARANTINED disabled by policy [credential: revoked]`; with `"min_trust": "trustzone-devkey"`,
which it meets, it was admitted again and stays so.

## Known limits

As in [1.0](release-notes-1.0.md#known-limits) and [1.1](release-notes-1.1.md#known-limits). A relying party that
does not pass `--require-signed-export` still accepts a 1.1 pack without a signed export time. The 24-hour soak has
not run yet (the boards are in use for other work).

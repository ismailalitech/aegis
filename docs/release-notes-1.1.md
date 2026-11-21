<!-- SPDX-License-Identifier: Apache-2.0 -->
# Aegis 1.1: release notes

Changes since [Aegis 1.0](release-notes-1.0.md). The Prover SDK is unchanged (release 1.0.0, API version 1).

## Verifier

- **A trust label for TF-M endpoints.** A kind `aegis-pq` endpoint (TF-M with the post-quantum partition, the
  STM32H573s) is now labelled by the attestation key its policy entry pins: `trustzone-devkey` when that is TF-M's
  published development key (`gateway/policy/keys/tfm-dev-iak.pub.pem`), `trustzone` for a key of the device's own.
  Before 1.1 such a verdict carried no label, so a reader of the signed result had to infer the trust from other
  claims. With the development key, the result's `executables` claim carries a detail that says so
  (`common/eat.py`, `gateway/aegisd/fleet.py`; [`architecture.md`](architecture.md); tests in
  `tests/host/test_fleet.py` and `tests/host/test_evidence_format.py`).
- **Anchors against a signed policy.** `tools/audit_anchors.py --policy-signers` (from 1.0's last pull request)
  lets the collector run against a gateway that runs from a signed policy.

## On the bench

The gateway runs with the audit log on, a signed policy and signed results kept for every endpoint; STM32 board 2
runs the EAT image; the costs measured there are in [`audit-and-policy.md`](audit-and-policy.md), "Measured on the
bench".

## Known limits

As in [1.0](release-notes-1.0.md#known-limits). The 24-hour soak has not run yet (the boards are in use for other
work); the 3-hour soak of 1.0 is the latest.

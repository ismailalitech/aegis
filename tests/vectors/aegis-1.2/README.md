<!-- SPDX-License-Identifier: Apache-2.0 -->
# Golden vectors, Aegis 1.2

Synthetic: written by [`tools/gen_golden_vectors.py`](../../../tools/gen_golden_vectors.py) with the repository's own
writers, in one process, with no board, no network and no bench data. Every key is derived from a published seed
(`aegis-golden-vectors-1.2/` and a name, in the generator), so **none is a secret and none is a real device's or verifier's**; the
addresses are from TEST-NET-1. The formats are specified in [`docs/data-formats.md`](../../../docs/data-formats.md)
and the JSON Schemas in [`docs/schemas/`](../../../docs/schemas/); `tests/host/test_golden_vectors.py` checks that
these files still verify and still match the schemas, and that a fresh run of the generator makes the same structure.

**What is the same in every run and what is not.** The keys, the challenges, the clock (first cycle at 1795000000), the
PSA tokens and the claims inside the device evidence are fixed. ML-DSA-65 signatures are hedged (FIPS 204), so every
COSE object, detached signature and endorsement record differs from run to run, and so does every hash over one of
them: the SHA-256 of the files in a manifest, the record names the policy pins (`endorsement_sha256`), and therefore
the policy's own hash and `ni` name, and the audit log's chain. Compare structure and verify signatures; do not
compare these bytes.

## The files

| Path | What it shows |
|---|---|
| [`policy/fleet.json`](policy/fleet.json) | the fleet policy: one entry per device, every kind and evidence format, and most keys an entry can have (Aegis 1.2: `min_trust` floors each entry meets, one `disabled` entry) ([`policy.schema.json`](../../../docs/schemas/policy.schema.json)) |
| [`policy/fleet.cose`](policy/fleet.cose) | the same policy signed (COSE_Sign1, ML-DSA-65), version 1, audience `golden-fleet`, signer `golden-policy-signer` |
| [`policy/policy-signers.json`](policy/policy-signers.json) | the verifier's signers file for it ([`policy-signers.schema.json`](../../../docs/schemas/policy-signers.schema.json)) |
| [`policy/keys/`](policy/keys/) | the devices' ML-DSA-65 public keys in hex (`pq_pub_file`) and the TF-M attestation key (`tfm-iak.pub.pem`) |
| [`policy/endorsers/`](policy/endorsers/) | the endorser's ML-DSA-65 public key in hex (`endorsers[].pk_file`) |
| [`policy/endorsements/`](policy/endorsements/) | the installed records: `pq-quote.json` (JSON form, [`endorsement.schema.json`](../../../docs/schemas/endorsement.schema.json)), `pq-eat.cbor` and `rw612-tfm-eat.cbor` (COSE form) |
| [`fleet-state.json`](fleet-state.json) | the verdicts of the second cycle as `fleet.py watch` writes them ([`fleet-state.schema.json`](../../../docs/schemas/fleet-state.schema.json)); the state directory is named `/var/lib/aegis` |
| `packs/<name>/` | the evidence pack of each entry after that cycle, as `fleet.py export-evidence` writes it: `manifest.json` ([`manifest.schema.json`](../../../docs/schemas/manifest.schema.json)) and `manifest.cose`, the verifier's signature over it and the export time. Every result names the audit log's head at that time (batch 1) |
| [`audit/audit-000001.cbor`](audit/audit-000001.cbor) | the audit log of five cycles, one segment of 4 batches |
| [`audit/anchor.cbor`](audit/anchor.cbor) | an anchor: batch 2, kept as `fleet.py audit --out` keeps one after the third cycle |
| [`audit/verifier.mldsa65.pub`](audit/verifier.mldsa65.pub) | the verifier's identity key in hex: it signs the results and the batches |
| [`audit/audit-report.json`](audit/audit-report.json) | what `fleet.py audit --entries` reports for the log at 1795003690 |

## The packs

| Pack | Evidence format | Result | What it shows |
|---|---|---|---|
| [`packs/psa-tfm/`](packs/psa-tfm/) | psa-token | warning | kind `psa`: TF-M's PSA token alone (`evidence.token`, ES256, checked with `keys/device-iak.pem`, not by the standalone checker). The key is pinned, not endorsed: `warning` (instance identity -33) |
| [`packs/pq-quote/`](packs/pq-quote/) | aegis-quote-v1 | affirming | kind `aegis-pq`, the older quote: TF-M's token and a detached ML-DSA-65 signature (`evidence.token`, `evidence.sig`); endorsed by a JSON record (`endorsement.json`): `affirming`, trust `trustzone` |
| [`packs/pq-eat/`](packs/pq-eat/) | eat-cose-v1 | affirming | kind `aegis-pq`, standard evidence: an EAT nesting TF-M's token (`evidence.cbor`); endorsed by a COSE record (`endorsement.cbor`); exported with `--with-policy` (`policy.json`): `affirming` |
| [`packs/rw612-tfm-eat/`](packs/rw612-tfm-eat/) | eat-cose-v1 | affirming | kind `aegis-device`, profile `aegis-rw612-tfm-v1`, standard evidence with measured components; endorsed (COSE record with a UEID, an expiry and notes): `affirming`, trust `trustzone` |
| [`packs/rw612-els-quote/`](packs/rw612-els-quote/) | aegis-quote-v1 | warning | kind `aegis-device`, profile `aegis-rw612-els-v1`, the older claims map; trust on first use: `warning` (-33 and executables -35), trust `device-key` |
| [`packs/zynqmp-devhuk-eat/`](packs/zynqmp-devhuk-eat/) | eat-cose-v1 | warning | kind `aegis-tee`, the development profile with `allow_dev_profile`: `warning` (-34), trust `development-shared-key`, the verdict's warning in the result's details |
| [`packs/zynqmp-optee-quote/`](packs/zynqmp-optee-quote/) | aegis-quote-v1 | contraindicated | kind `aegis-tee`, profile `aegis-zynqmp-optee-v1`, the older claims map with a component the policy does not allow: not admitted, `contraindicated` (executables 33) |
| [`packs/linux-host/`](packs/linux-host/) | aegis-quote-v1 | warning | kind `aegis-linux`, the older claims map: `warning`, trust `software` |
| [`packs/offline-eat/`](packs/offline-eat/) | eat-cose-v1 | incomplete | kind `aegis-device` that did not answer: no evidence in the pack, `incomplete` |
| [`packs/retired-device/`](packs/retired-device/) | none | incomplete | an entry with `"disabled": true`: not contacted, not admitted, `incomplete`, `aegis.disabled` in the result and no evidence format (`null` in the manifest) |

## The keys, by COSE Key Thumbprint

| Key | Thumbprint |
|---|---|
| endorser | `80662c11dc1fcb5779267ef0b31b190c93c0ff6ed9559a9074ea9bc7db42c98d` |
| policy-signer | `dcac919eb72103e6e07e4e96e8bc2706c4be8522708d7eee2d33319674d2d957` |
| verifier | `ae31ea0c573e569447b6b3d6622ed7af161a23d1a60521110ff4ed63360b563f` |
| device `linux-host` | `91010e580c8d312a7d1ed821d06637ad40676ac7f9d3b7033a39654673059cd2` |
| device `offline-eat` | `0d9d659f9b2807c933f3fab2f09addb687f45efe771c11f7a9129d0e7198abf7` |
| device `pq-eat` | `bafc7fe945abee29dec98c138848e2f66f0b98b8b9d60e7162d71fb4a538bb5e` |
| device `pq-quote` | `1e91826bc05263cfce9d65fd07d1dca72efa339aea9f870723b7ee8c9c33dcf1` |
| device `retired-device` | `1d9af0a3fc4774a9a61b3370c286e57d9a5e7a2428936d83a5111b79afcd1c20` |
| device `rw612-els-quote` | `eed650d25902e69a2f6819cef659b9ba40ff07cb493bb1cf9d9ec5820877bcf2` |
| device `rw612-tfm-eat` | `1ea7c5f5652a79fe9fe7c0d87c686b0eec30568ecadf98593061a6a9f11351e4` |
| device `zynqmp-devhuk-eat` | `df93a41e1bd6bb25d33aff287a32d2722c91380086991379b6b55e1f23a1097e` |
| device `zynqmp-optee-quote` | `6b8ee1a15a8354f3221cbe0659fefc663e4d96991c9fc8916d515a5aa597e84b` |

## Checking them

    tools/verify_evidence.py pack packs/pq-eat --verifier-key ae31ea0c573e569447b6b3d6622ed7af161a23d1a60521110ff4ed63360b563f --require-signed-export
    tools/verify_audit.py log audit --key audit/verifier.mldsa65.pub --result packs/pq-eat/attestation-result.cbor --at 1795003690
    tools/verify_audit.py log audit --key audit/verifier.mldsa65.pub --anchor audit/anchor.cbor --at 1795003690
    tools/verify_audit.py policy policy/fleet.cose --key policy/policy-signers.json --audience golden-fleet

The audit log promises its next batch: checked later than its last batch's `due` without `--at` (or with
`--no-freshness`), it is reported stale, as a log whose verifier stopped is. Its batches, by the verifier's clock:

    batch 1 at 1795000000
    batch 2 at 1795000060
    batch 3 at 1795000090
    batch 4 at 1795003690

Make them again: `tools/gen_golden_vectors.py` (it replaces this directory).

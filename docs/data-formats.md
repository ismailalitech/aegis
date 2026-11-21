<!-- SPDX-License-Identifier: Apache-2.0 -->
# Data formats: what a consumer of Aegis evidence reads

For a program that reads what an Aegis verifier writes (an inventory, a SIEM, a compliance report) without running
Aegis code. Every statement here is taken from the code of Aegis 1.1 (`gateway/aegisd/fleet.py`, `common/eat.py`,
`common/endorsement.py`, `common/psa_token.py`, `common/signed_policy.py`, `common/audit.py`,
`sdk/src/aegis_proto.c`); where the code is the specification, its function is named. The design and the reasons are
in [`evidence-format.md`](evidence-format.md), [`enrolment.md`](enrolment.md) and
[`audit-and-policy.md`](audit-and-policy.md); this page is the reference.

Synthetic examples of every format below, made by the verifier's own writers with published test keys:
[`../tests/vectors/aegis-1.2/`](../tests/vectors/aegis-1.2/README.md) (`tools/gen_golden_vectors.py`).

## The JSON files and their schemas

JSON Schema, draft 2020-12, in [`schemas/`](schemas/):

| File | Written by | Schema |
|---|---|---|
| `manifest.json` of an evidence pack | `fleet.py export-evidence POLICY NAME` | [`schemas/manifest.schema.json`](schemas/manifest.schema.json) |
| `STATE_DIR/fleet-state.json` (`/var/lib/aegis` on the gateway) | `fleet.py watch`, after every cycle | [`schemas/fleet-state.schema.json`](schemas/fleet-state.schema.json); one verdict: `#/$defs/verdict` |
| `fleet.json`, the policy (plain, or inside a signed policy) | the operator | [`schemas/policy.schema.json`](schemas/policy.schema.json); one entry: `#/$defs/endpoint` |
| an endorsement record, JSON form (`endorsements/<name>.json`, `endorsement.json` in a pack) | `provision/aegis_provision.py endorse` | [`schemas/endorsement.schema.json`](schemas/endorsement.schema.json) |
| `policy-signers.json` | the operator | [`schemas/policy-signers.schema.json`](schemas/policy-signers.schema.json) |

What the schemas say about openness follows the code. The objects Aegis writes (manifest, verdict, endorsement
record, signers file) are closed: a key that is not in the schema is not one this version writes, and the verifier
refuses a record or signers file with an unknown key. The policy is open, because the verifier ignores keys it does
not know (`"note"`, `"image"` in an `allowed` item); inside a known key it is strict, and a value it does not know is
refused rather than read as the default (`fleet.py policy_errors`, `fleet.py check`). Enumerations are closed where
the code has a closed set. The verdict's `reasons`, `warning` and `credential` are text for people, not a closed
list: do not parse them.

Hashes in JSON are lower-case hex. A "SHA-256 of a key" is always over the raw 1952-byte ML-DSA-65 public key (a
P-256 key is never hashed this way); a key's **thumbprint** is something else, the COSE Key Thumbprint (RFC 9679) over
`{1: 7, 3: -49, -1: key}` in deterministic CBOR, which is also the `kid` of everything that key signs.

## The closed lists

### `aegis.trust` (the verdict's `trust`)

What holds the key that signed the evidence and who measured the software. Set by `fleet.py attest` from the entry's
kind and the profile or key the evidence names; nothing else is ever written.

| Value | Where it comes from | What it means |
|---|---|---|
| `trustzone` | kind `aegis-pq` whose PSA token verifies with a pinned initial attestation key (IAK) other than TF-M's development key; kind `aegis-device`, profile `aegis-rw612-tfm-v1`; kind `aegis-tee`, profile `aegis-zynqmp-optee-v1` | the key and the measurements are in a TrustZone or TEE secure world that the normal world cannot reach |
| `trustzone-devkey` | kind `aegis-pq` whose PSA token is signed with TF-M's published development IAK | as `trustzone`, but anyone can sign such a token: what it says rests on the endpoint's ML-DSA-65 key alone. Admitted with a warning |
| `device-key` | kind `aegis-device`, profile `aegis-rw612-els-v1` | the key is derived in the chip's key store (NXP ELS) and proves the chip; the firmware measures itself |
| `software` | kind `aegis-linux`, profile `aegis-linux-software-v1` | key and measurements are held by Linux, not by hardware |
| `development-shared-key` | kind `aegis-tee`, profile `aegis-zynqmp-optee-devhuk-v1` (only with `"allow_dev_profile": true`); kind `psa` pinned to TF-M's development IAK | the key is the same on every chip (or public): the evidence proves the firmware, not which device sent it. Admitted with a warning |

**Absent** for kind `psa` with any other IAK, for kind `aegis-pq` without `iak_pub_pem` (only the ML-DSA-65
signature is checked), and for a verdict refused before the claims were read. `trust` is set as soon as the profile
or key is known, so a refused verdict may carry one.

### `aegis.enrolment` (the verdict's `enrolment`)

How the pinned ML-DSA-65 key came to be trusted; post-quantum kinds only (absent for kind `psa`, and for an entry the
policy rules refuse).

| Value | Meaning |
|---|---|
| `endorsed` | the entry says `"endorsement": "required"` and a record signed by an endorser the policy trusts names this device, its family and exactly the pinned key (`common/endorsement.py check`) |
| `trust-on-first-use` | no endorsement asked for: the key is whatever `fleet.py enroll-pq` was first given |
| `refused` | an endorsement is required and the record was refused (missing, another key, an untrusted or revoked endorser, expired, not the pinned record, too old). The endpoint is never admitted and is not contacted |

### Other closed values

| Field | Values |
|---|---|
| policy `kind` | `psa` (the default), `aegis-pq`, `aegis-device`, `aegis-tee`, `aegis-linux` |
| policy `profile` | `aegis-rw612-els-v1`, `aegis-rw612-tfm-v1` (kind `aegis-device`); `aegis-zynqmp-optee-devhuk-v1`, `aegis-zynqmp-optee-v1` (kind `aegis-tee`); `aegis-linux-software-v1` (kind `aegis-linux`) |
| evidence format (pack manifest, `aegis.evidence-format`) | `eat-cose-v1` (EAT in COSE_Sign1), `aegis-quote-v1` (the older `PQCHAL` quote), `psa-token` (kind `psa`), and in the result only `none` (nothing was asked) |
| result status (`ear.status`, the manifest's and the verdict's `status`) | `affirming` (2), `warning` (32), `contraindicated` (96), `incomplete` (127) |
| `session_binding`, `aegis.session-binding` | `transcript-v2`, `unbound` |
| `enforcement`, `aegis.enforcement` | `ok`, `FAILED` |
| `device_state`, `aegis.device-state` | `development`, `closed` (the operator's statement; nothing measures it) |
| policy `heartbeat_mac` | `kmac256` (default), `sha3-256` |
| policy `transcript`, `endorsement`, `evidence_format` | `v2`; `required`; `eat-cose-v1` |

## The attestation result (EAR) and its `aegis.*` claims

`attestation-result.cbor`: a COSE_Sign1 (tag 18; protected header exactly `{1: -49, 4: kid, 16:
"application/eat+cwt"}`; empty unprotected header; payload attached; ML-DSA-65 signature of 3309 bytes over the
Sig_structure, pure, empty context) by the verifier's identity key. Its payload, in deterministic CBOR
(`common/eat.py ear_payload`, draft-ietf-rats-ear-06):

| Key | Type | Value |
|---|---|---|
| 265 | tstr | `"tag:ietf.org,2026:rats/ear#05"` |
| 6 | uint | iat |
| 4 | uint | exp: iat plus the admission's lifetime; absent if the verifier had none |
| 1004 | map | `{0: "https://github.com/ismailalitech/aegis", 1: "aegis-fleet-verifier 1 (evidence eat-cose-v1, results draft-ietf-rats-ear-06)"}` |
| 1000 | uint | status, the same as the one appraisal's |
| 266 | map | exactly one appraisal, under the policy kind as label (`"aegis-pq"`, ...) |

The appraisal:

| Key | Type | Value |
|---|---|---|
| 1000 | uint | status: 2, 32, 96, 127 |
| 1001 | map uint => int | trustworthiness vector, `{0: instance-identity, 2: executables}` ([`evidence-format.md`](evidence-format.md) has the table of values) |
| 1003 | [tstr] | `["ni:///sha-256;" + base64url(SHA-256(policy JSON)), no padding]` (RFC 6920) |
| 1010 | [tstr] | only when not affirming: up to 8 of the verdict's reasons and its warning, each cut to 300 characters |
| 1011 | map uint => [tstr] | why a vector value is what it is |
| 10 | bstr .size 32 | the evidence's challenge, when the claims were read |
| 1005 | map | what the attester claimed: 256 ueid (bstr, EAT only), 273 measurements (measured components, below), -82400 the claims' profile (tstr; for a PSA token its own profile claim, e.g. `"PSA_IOT_PROFILE_1"`), 263 dbgstat (uint) |
| 1006 | map tstr => any | the verifier's claims: the `aegis.*` table below |
| 1014 | map tstr => map | endorser claims, with `enrolment` endorsed: `{"<the policy's name for the endorser>": {...}}` |

**1006** (`eat.ear_payload`; text keys):

| Claim | CBOR type | Value |
|---|---|---|
| `aegis.endpoint` | tstr | the policy entry's name. Always present |
| `aegis.kind` | tstr | the policy kind. Always present |
| `aegis.admitted` | bool | the verdict. Always present; a reader refuses a result where it disagrees with the status (admitted only with 2 or 32) |
| `aegis.evidence-format` | tstr | `eat-cose-v1`, `aegis-quote-v1`, `psa-token`, or `none`. Always present |
| `aegis.trust` | tstr | the closed list above; absent where the verdict has none |
| `aegis.enrolment` | tstr | the closed list above; absent where the verdict has none |
| `aegis.session-binding` | tstr | `transcript-v2` or `unbound`, when a session was issued or kept this cycle |
| `aegis.device-key-sha256` | **tstr**, 64 lower-case hex | SHA-256 of the device's ML-DSA-65 public key (1952 bytes) the evidence was verified with |
| `aegis.quote-sha3-256` | **bstr**, 32 bytes | SHA3-256 of the bytes the device's signature covers: for `aegis-quote-v1` the token itself (not the label), for `eat-cose-v1` the COSE Sig_structure `["Signature1", protected, h'', payload]`. The token hash of transcript v2's T1 |
| `aegis.evidence-sha256` | **bstr**, 32 bytes | SHA-256 of the evidence file as received: `evidence.cbor`, or `evidence.token` (the detached `evidence.sig` is not covered) |
| `aegis.enforcement` | tstr | `ok` or `FAILED`, when the policy's enforcement hook ran |

**1014**, per endorser:

| Key | CBOR type | Value |
|---|---|---|
| `aegis.record-sha256` | tstr, 64 hex | the record's name, as a policy's `endorsement_sha256` pins it: JSON form SHA-256 of canonical JSON `{"body": ..., "sig": ...}` (sorted keys, no spaces); COSE form SHA-256 of the file |
| `aegis.device-key-sha256` | tstr, 64 hex | SHA-256 of the endorsed ML-DSA-65 key |
| `aegis.device-state` | tstr | `development` or `closed` |
| 6 | uint | when the record was issued (endorser's clock) |

Note the mix, which is the code's: the two key and record hashes are hex text, the two evidence hashes are byte
strings. No claim is SHA3 except `aegis.quote-sha3-256`.

## The private claims (-82400 to -82408)

In the private-use range of the CWT registry; each means something only under an Aegis profile.

| Key | Type | Evidence (`.../aegis/evidence/v1`) | Endorsement (`.../aegis/endorsement/v1`) | EAR 1005 |
|---|---|---|---|---|
| -82400 | tstr, 1 to 64 | the platform profile, with 273 only | `profile` | the claims' profile |
| -82401 | tstr | | `kind` | |
| -82402 | tstr | | `serial` | |
| -82403 | tstr | | `device_state` | |
| -82404 | bstr .size 32 | | `evidence.token_sha3_256` (SHA3-256, as `aegis.quote-sha3-256`) | |
| -82405 | tstr | | `notes` | |
| -82406 | bstr, 1 to 64 | | `instance_id` when it is not a UEID | |
| -82407 | uint | | `v` (1) | |
| -82408 | bstr .size 32 | | `endorser_pk_sha256` (SHA-256 of the endorser's ML-DSA-65 key) | |

## Device evidence, standard form (`eat-cose-v1`, `evidence.cbor`)

The same COSE_Sign1 envelope, by the device's identity key; claims in deterministic CBOR, **a closed set**: a claim
that is not listed is refused (`eat.read_evidence`). 10 eat_nonce (bstr 32), 256 ueid (bstr 33: `0x01` ||
SHA-256 of the device key), 265 `"tag:github.com,2026:ismailalitech/aegis/evidence/v1"`, 275 intuse (1), optional
263 dbgstat (0 to 4), and exactly one of: 273 measurements with -82400, or 266 `{"platform": h'd83d' || token}` (the
platform's own token, tagged 61, as for kind `aegis-pq`). A measured component (RFC 10013) is
`[295, bstr .cbor {1: [name, ? [version]], 2: [1, SHA-256 digest (32 bytes)], ? 3: [signer]}]`, 1 to 16 of them,
one per name. [`evidence-format.md`](evidence-format.md) gives the rules.

## Device evidence, older form (`aegis-quote-v1`, `evidence.token` + `evidence.sig`)

The default, requested with `PQCHAL <challenge hex>` and answered `PQTOKEN <len> <token hex> <len> <sig hex> END`.

- **Signature** (`evidence.sig`): 3309 bytes, ML-DSA-65 (pure, empty context, hedged) by the device key over
  `"aegis-endpoint-quote-v1" || 0x00 || token`. Not COSE. The format's name in a pack, `aegis-quote-v1`, is not this
  label.
- **Token for kind `aegis-pq`**: TF-M's PSA token as the platform made it (below). The verifier checks the ML-DSA-65
  signature first, then the token's own ES256 signature if the entry names an `iak_pub_pem`.
- **Token for the plain-claims kinds** (`aegis-device`, `aegis-tee`, `aegis-linux`): a CBOR map with PSA profile 1
  claim numbers, written by the Prover SDK (`aegis_proto.c make_claims`) and the Linux prover in this key order,
  **not** in deterministic encoding (that would put -75006 second):

  | Key | Type | Value |
  |---|---|---|
  | -75000 | tstr | the profile (`aegis-rw612-els-v1`, ...): what the policy pins |
  | -75008 | bstr .size 32 | the challenge |
  | -75009 | bstr .size 33 | `0x02` \|\| SHA-256 of the device's ML-DSA-65 key (0x02: not a PSA IAK-based instance ID) |
  | -75006 | array of maps | one per component, keys in this order: 1 name (tstr), 2 digest (bstr 32, SHA-256: of the image in flash, of the files measured), 4 version (tstr), 5 signer (bstr 32, all zero: none), 6 description (tstr, "SHA256 of ...") |

  The verifier's set is **not closed** here: `psa_token.claims_from_map` names the keys it knows (both the PSA
  profile 1 numbers and the EAT numbers, table below), keeps any other under its number, and decides on profile,
  challenge, instance ID and components only. Key order and encoding are not checked; the signature covers the
  bytes as sent.
- **Hashes**: the transcript (`aegis.quote-sha3-256`, the verdict's `quote.token_sha3_256`) is SHA3-256 of the
  token; `aegis.evidence-sha256` is SHA-256 of the token.

Kind `psa` (`psa-token`, `evidence.token` alone): `CHAL <challenge hex>` answered `TOKEN <len> <hex> END`, TF-M's
token and nothing else.

**Not the same thing:** the gateway's own quote of itself (`aegisd.py`, request `{"type": "quote"}` over a
length-prefixed JSON connection) is signed under the label `aegis-quote-v1`: ML-DSA-65 over `"aegis-quote-v1" ||
0x00 || canonical(body)`, body `{"v": 1, "type": "quote", "nonce": hex, "identity_sha256", "measurements": {...},
"gw_monotonic_s"}`. It never appears in an evidence pack.

## The PSA token claims Aegis reads

A PSA initial attestation token is a COSE_Sign1 (tag 18 optional), protected header with `1: -7` (ES256) required,
signature 64 bytes `r || s` over `["Signature1", protected, h'', payload]` (`common/psa_token.py`).

| PSA profile 1 | EAT-based | Name | Used for |
|---|---|---|---|
| -75008 | 10 | challenge | must be this cycle's challenge |
| -75006 | 2399 | sw_components | every component must match the policy's `allowed` (and, if endorsed, exactly the endorsed set); per component: 1 measurement_type, 2 measurement_value, 5 signer_id are compared; 4 version is carried into the result (1005), 6 measurement_desc is not used |
| -75009 | 256 | instance_id | copied to the verdict (`instance_id`); not compared |
| -75000 | 265 | profile | the plain-claims kinds: must be the entry's `profile`; a PSA token's is copied to the result (1005, -82400) |
| -75001 ... -75005, -75010 | 2394 ... 2398 | client_id, lifecycle, implementation_id, boot_seed, certification_ref, verification_service | decoded, not used |

## Endorsement records

JSON form `aegis-endorsement-v1`: [`schemas/endorsement.schema.json`](schemas/endorsement.schema.json); the signature
is ML-DSA-65 over `"aegis-endorsement-v1" || 0x00 || canonical(body)`. COSE form `aegis-endorsement-cose-v1` (a file
whose first byte is `0xd2`): the same envelope, payload claims in deterministic CBOR, a closed set: 1 iss
`endorser`, 2 sub `device`, 6 iat `issued`, 4 exp `expires`, 8 cnf `{1: COSE_Key}` (the device key itself, under the
signature), 10 `evidence.challenge` (bstr 32), 256 ueid `instance_id` if it is one (`0x01` and 16, 24 or 32 bytes;
otherwise -82406), 265 `"tag:github.com,2026:ismailalitech/aegis/endorsement/v1"`, 273 measurements (measured
components: name = type, SHA-256 digest, authorities = `[signer_id]`), and the private claims above.
`endorsement.loads` reads either form into the same body.

## Signed policy and audit log

Both are COSE_Sign1 with ML-DSA-65; [`audit-and-policy.md`](audit-and-policy.md) has the claims.

- **Signed policy** (`fleet.cose`), typ `application/vnd.aegis.fleet-policy+cbor`, by a policy-signing key from
  `policy-signers.json`: `{1: "tag:github.com,2026:ismailalitech/aegis/policy/v1", 2: version, 3: issued, 4: the
  policy JSON (bstr, byte for byte), 5: signer, ? 6: audience}`. Its SHA-256 is the one results and the audit log
  name, signed or not.
- **Audit log** (`STATE_DIR/audit/audit-NNNNNN.cbor`), a CBOR sequence of batch records, typ
  `application/vnd.aegis.audit-batch+cbor`, by the verifier's identity key: `{1: format, 2: log id (bstr 16), 3: batch,
  4: SHA-256 of the previous record (32 zero bytes for batch 1), 5: time, 6: first entry, 7: [entries], ? 8: due}`,
  entry `{1: time, 2: event, ? 3: subject, ? 4: details}`. An anchor (`fleet.py audit --out`) is one batch record,
  byte for byte. Hashes inside entries' details are byte strings.

Check them without Aegis code: `tools/verify_evidence.py` (packs, results, evidence, endorsements) and
`tools/verify_audit.py` (audit log, signed policy), which import only pycose, cbor2 and cryptography.

## Aegis 1.2

Placeholders, to be filled where the change lands (branch v12-verifier):

- **Evidence pack**: a signed export time. 1.2: see docs/data-formats.md once v12-verifier lands.
- **Attestation result**: the audit log's head named in the signed result, and the verdict's warnings and details
  placed in it. 1.2: see docs/data-formats.md once v12-verifier lands.
- **Policy**: entry keys `"disabled"` and `"min_trust"`. 1.2: see docs/data-formats.md once v12-verifier lands.

Until then everything on this page is Aegis 1.1, and the schemas describe exactly what 1.1 writes: a consumer that
validates a 1.2 manifest or verdict against them will see the new keys refused, which is the signal to take the 1.2
schemas.

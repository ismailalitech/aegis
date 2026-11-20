# Evidence, attestation results and endorsements in standard formats

Design note for WP10 part A. Until now every signed object in Aegis had a format of its own: a quote was a claims
map or a PSA token with a detached ML-DSA-65 signature over `"aegis-endpoint-quote-v1" || 0x00 || token`, an
endorsement was canonical JSON, and a verdict was a line in the journal that nobody signed. Someone who wanted to
check any of it needed this repository's code. This note defines the same three statements as standard objects that
a third party reads with a COSE library and a public key:

| Statement | Who signs | Object | Profile (`eat_profile`) |
|---|---|---|---|
| evidence: "this device, this software, for this challenge" | the device's ML-DSA-65 identity key | EAT in a COSE_Sign1 | `tag:github.com,2026:ismailalitech/aegis/evidence/v1` |
| attestation result: "this verifier appraised it under this policy, with this outcome" | the verifier's ML-DSA-65 identity key | EAR in a COSE_Sign1 | `tag:ietf.org,2026:rats/ear#05` |
| endorsement: "this key belongs to this device, which reported these components" | the endorser's ML-DSA-65 key | CWT with EAT claims in a COSE_Sign1 | `tag:github.com,2026:ismailalitech/aegis/endorsement/v1` |

| Piece | Where |
|---|---|
| the envelope (COSE_Sign1, ML-DSA-65) | `common/cose.py` |
| the claims: evidence, attestation result | `common/eat.py` |
| the endorsement in this form | `common/endorsement.py` (`sign_cose`, `loads`) |
| the verifier: policy key, results, `export-evidence` | `gateway/aegisd/fleet.py` |
| the device: an option of the Prover SDK, off by default | `sdk/src/aegis_proto.c` (`AEGIS_EAT_COSE`) |
| the standalone checker (third-party libraries only) | `tools/verify_evidence.py` |

**Status.** Software only: everything here is exercised by the host tests against simulated devices and against the
SDK's core built for the PC. No board image has the option yet, and the gateway on the bench still runs `main`. The
older formats stay the default and stay accepted ("Compatibility" below).

## The standards, and the versions used

| What | Document | Used for |
|---|---|---|
| COSE_Sign1 | RFC 9052, sections 4.2 and 4.4 | the envelope and the bytes that are signed (Sig_structure) |
| ML-DSA in COSE | **RFC 9964** (May 2026), which was `draft-ietf-cose-dilithium` up to version -11 | algorithm **-49 (ML-DSA-65)**, key type **AKP = 7** with parameters `alg` (3) and `pub` (-1); pure ML-DSA with an empty context string (section 5) |
| ML-DSA | FIPS 204, `ML-DSA.Sign` / `ML-DSA.Verify`, parameter set ML-DSA-65 | public key 1952 bytes, signature 3309 bytes; signing is hedged (fresh randomness in every signature) |
| COSE Key Thumbprint | RFC 9679; for AKP keys RFC 9964 section 6 | `kid`: SHA-256 over `{1: 7, 3: -49, -1: pub}` |
| `typ` header parameter | RFC 9596 (label 16), media type `application/eat+cwt` from RFC 9782 | says what the payload is, under the signature |
| deterministic CBOR | RFC 8949 section 4.2.1 | one object, one byte string |
| CWT, `cnf` | RFC 8392, RFC 8747 | `iss`, `sub`, `iat`, `exp`; the endorsed key |
| EAT | RFC 9711 | `eat_nonce` (10), `ueid` (256), `dbgstat` (263), `eat_profile` (265), `submods` (266), `measurements` (273), `intuse` (275) |
| measured component | RFC 10013 (July 2026), CoAP Content-Format **295** (`application/measured-component+cbor`) | one entry of `measurements` |
| EAR | `draft-ietf-rats-ear-06` (20 November 2026). **Not an RFC.** | the attestation result's claims (1000 to 1014) |
| AR4SI | `draft-ietf-rats-ar4si-11` (31 October 2026). **Not an RFC.** | the tiers and the trustworthiness vector |
| `ni` URI | RFC 6920 | names the policy a result was reached under |

The two drafts can still change their claim numbers and the EAR profile string. They are used through the constants
at the top of `common/eat.py` and nowhere else; a result names the profile it was written to, so a reader built for a
later draft refuses these instead of misreading them.

Private claims use keys below -65536, which the CWT claims registry leaves to private use. This project uses -82400
to -82408; a number in that block means something only under one of the two Aegis profiles.

## The envelope

Every object is one tagged COSE_Sign1 with an attached payload:

    18([
      protected:   bstr .cbor { 1: -49,            ; alg: ML-DSA-65
                                4: kid,            ; bstr .size 32: the signer's COSE Key Thumbprint
                                16: "application/eat+cwt" },
      unprotected: {},
      payload:     bstr .cbor claims,
      signature:   bstr .size 3309               ; ML-DSA-65 over Sig_structure
    ])

    Sig_structure = [ "Signature1", protected, h'', payload ]       ; external_aad is empty
    kid           = SHA-256( a3 01 07 03 38 30 20 59 07a0 || public key )

The protected header is always the same 60 bytes but for the kid, so the object begins `d2 84 58 3c a3 01 38 30 04 58
20`. Every item is in deterministic encoding: shortest lengths, map keys in bytewise order. An object therefore has
exactly one byte string, and the SHA-256 of a file names the object.

A reader of these objects is strict about each thing a hostile sender could vary (`common/cose.py`, `verify1`):

- the algorithm is read from the protected header only and must be -49. No other algorithm is ever tried, so a
  header that names a classical one is a refusal, not a downgrade;
- the unprotected header must be empty. A `kid` or `alg` put there is not ignored: the object is refused;
- the protected header holds exactly `alg`, `kid` and `typ`. An unknown parameter or `crit` is refused, not skipped;
- `kid` must be the thumbprint of the key the reader already trusts for that role. A key is never taken from the
  object;
- the payload is attached, the signature is 3309 bytes, nothing follows the object, and re-encoding what was decoded
  gives the same bytes.

**One key, two kinds of message.** The device's and the verifier's keys also sign the older messages, as
`label || 0x00 || message` with a label that begins `aegis-`. A Sig_structure begins `84 6a "Signature1"`. No byte
string is both, so a signature obtained for one kind is never valid for the other
(`test_a_signature_for_an_older_message_is_not_one_for_a_cose_object`).

## Evidence

Profile `tag:github.com,2026:ismailalitech/aegis/evidence/v1`, signed by the device's identity key.

| Key | Claim | Value |
|---|---|---|
| 10 | `eat_nonce` | `bstr .size 32`: the verifier's challenge |
| 256 | `ueid` | `bstr .size 33`: `0x01` (type RAND) followed by the SHA-256 of the device's public key, the hash every Aegis policy and record already names the key by |
| 263 | `dbgstat` | optional, 0 to 4. Reserved for a port whose secure world reads the debug state itself; the SDK does not emit it yet, and the verifier only copies it into the result |
| 265 | `eat_profile` | the profile above |
| 273 | `measurements` | `[+ [295, bstr .cbor measured-component]]`, 1 to 16 entries, one per name |
| 266 | `submods` | `{"platform": bstr}`: the platform's own token, nested (RFC 9711 section 4.2.18): tag 61 and then the token's bytes as the platform made them |
| 275 | `intuse` | 1 (generic) |
| -82400 | platform profile | text: the Aegis profile name a policy pins (`aegis-rw612-tfm-v1`, ...); with `measurements` only |

    measured-component = { 1: [ name: tstr, ? [ version: tstr ] ],     ; component-id
                           2: [ 1, bstr .size 32 ],                    ; SHA-256 digest
                           ? 3: [ signer: bstr ] }                     ; authorities, where the platform knows one

Exactly one of `measurements` and `submods`:

- **measurements** for devices whose secure world reports its own components (policy kinds `aegis-device`,
  `aegis-tee`, `aegis-linux`): the label and digest the older claims carried, with the platform's version text. The
  older claims' free-text description and all-zero signer are not carried;
- **a nested platform token** for a platform that already has a signed token (kind `aegis-pq`, the STM32H573: TF-M's
  PSA initial attestation token, itself a COSE_Sign1 with ES256). The EAT's ML-DSA-65 signature covers the token
  whole; the verifier checks both signatures and both nonces, and reads the components from the inner token.

Rules of the profile, in the order of RFC 9711 section 6.3:

| | |
|---|---|
| encoding | CBOR, definite lengths, deterministic encoding; a receiver refuses anything else |
| envelope | COSE_Sign1, tagged (18), payload attached. No COSE_Mac0, no detached bundle, no CWT tag around the top-level object |
| algorithm | ML-DSA-65 (-49) and nothing else |
| key identification | `kid` in the protected header = the signing key's COSE Key Thumbprint. The verifier holds the key (endorsed, or pinned on first use); none is sent with the evidence |
| freshness | `eat_nonce`, 32 bytes from the verifier, one per token |
| claims | 10, 256, 265, 275 and one of 273 and 266 are required; -82400 with 273. **A claim not in the table is refused**, where RFC 9711 lets a receiver ignore what it does not know: a later version must not be able to add a restriction that this verifier would silently drop |
| submodules | only `"platform"`, only a nested token |

Sizes: 3596 bytes with one measurement (217 bytes of claims), 3877 with a nested PSA token of about 330 bytes. The
signature is 3309 of them.

## The transcript: what T1 hashes

Transcript v2 (`docs/architecture.md`, `common/transcript.py`) binds a session to the quote the verifier appraised:

    T1 = SHA3-256("aegis-transcript-v2/quote" || challenge[32] || SHA3-256(token)[32])

`token` is **the byte string the device's quote signature covers, without any label**:

| Quote | `token` |
|---|---|
| older (`PQCHAL`) | the evidence as sent: the claims map or the PSA token. (The signature is over `"aegis-endpoint-quote-v1" || 0x00 || token`; the label is not hashed.) |
| standard (`PQEAT`) | the COSE **Sig_structure** of the evidence: `84 6a "Signature1" || bstr(protected) || 40 || bstr(payload)` |

Reasons for the Sig_structure rather than something near it:

- it is what was signed. The protected header (algorithm, kid, typ) is under the signature and so belongs to the
  quote; the hash of the payload alone would leave it out;
- the signature is not part of it. ML-DSA signing is hedged, so the whole COSE_Sign1 differs from one signing to the
  next for the same quote, and the device would hash 3.3 kB more for nothing: the transcript's own signature (over
  T2) already comes from the same key;
- both sides have it anyway: the device builds it in its work buffer to sign it, a verifier rebuilds it to verify.

Nothing else in the transcript changes: T2, T3, the labels, the credential's `transcript_sha3_256`, the confirmation
tag. A device keeps one quote to continue, the last one it signed, of either kind. A verifier that appraised an EAT
and one that appraised the older quote of the same boot therefore compute different T1, and each session continues
exactly the quote its verifier saw. `tools/verify_evidence.py` prints this hash for a piece of evidence
(`quote_sha3_256`), and the attestation result carries it (`aegis.quote-sha3-256`).

## On the wire, and in the policy

    PQEAT <challenge, 64 hex digits>   ->   PQEAT <length> <COSE_Sign1 in hex> END

A policy entry asks for it:

    { "name": "frdm-rw612", "kind": "aegis-device", ..., "evidence_format": "eat-cose-v1" }

- Without the key the entry is asked as before (`PQCHAL`, or `CHAL` for kind `psa`). Nothing changes for firmware
  in the field.
- With it the verifier sends `PQEAT` and accepts only an EAT. There is **no fallback in either direction**: firmware
  without the option answers `ERR unknown` and is not admitted, and an older-format answer to `PQEAT` is refused.
- A value this verifier does not know (`"eat-cose-v2"`) is a policy error: the entry is refused without being asked.
  The key needs a post-quantum kind.
- The same rules then apply to the claims: the pinned profile, `allowed`, the endorsed components, the challenge.
  A component without `authorities` has no signer, so an `allowed` entry that names a `signer_id` does not match it.
- The endorser's reference file may carry the key too; `aegis_provision.py endorse` then appraises standard evidence.

## The attestation result

For every verdict of a cycle the verifier signs an EAR with its identity key (`fleet.py`: `attestation_result`), if
it has one (`aegisd.py init`); without an identity the loop runs as before and says so once.

    { 265: "tag:ietf.org,2026:rats/ear#05",
      6: iat,  4: exp,                                   ; exp = iat + the admission's own lifetime
      1004: { 0: "https://github.com/ismailalitech/aegis", 1: "aegis-fleet-verifier 1 (...)" },
      1000: status,                                      ; the same as the one appraisal's
      266: { "<kind>": {                                 ; one appraisal, under the entry's kind
        1000: status,                                    ; 2 affirming, 32 warning, 96 contraindicated, 127 incomplete
        1001: { 0: instance-identity, 2: executables },  ; AR4SI trustworthiness vector
        1003: [ "ni:///sha-256;<policy file's hash>" ],
        ? 1010: [ + tstr ],                              ; the verdict's reasons and warning, when not affirming
        ? 1011: { category: [ + tstr ] },
        ? 10: nonce,                                     ; the evidence's
        ? 1005: { 256: ueid, 273: measurements, -82400: platform },      ; what the attester claimed
        1006: { "aegis.endpoint", "aegis.kind", "aegis.admitted": bool, "aegis.evidence-format",
                ? "aegis.trust", ? "aegis.enrolment", ? "aegis.session-binding", ? "aegis.device-key-sha256",
                ? "aegis.quote-sha3-256": bstr,          ; T1's token hash
                ? "aegis.evidence-sha256": bstr,         ; SHA-256 of the evidence as received
                ? "aegis.enforcement" },
        ? 1014: { "<endorser>": { "aegis.record-sha256", "aegis.device-key-sha256", "aegis.device-state", 6: iat } }
      } } }

How a verdict becomes a vector (`common/eat.py`, `appraisal`):

| Category | Value | When |
|---|---|---|
| instance-identity (0) | 2 | the key is endorsed by an endorser the policy trusts |
| | -33 | the key is pinned without an endorsement (trust on first use, or a classical key the policy pins) |
| | -34 | a development profile whose key is the same on every chip |
| | 97 | the entry requires an endorsement and the record was refused |
| | 99 | the evidence's signature does not verify |
| | 0 | nothing was appraised (no answer, an entry the policy rules refuse) |
| executables (2) | 3 | every component is allowed (and, where endorsed, the endorsed one), measured by an earlier boot stage or the secure world |
| | -35 | the same, but measured by the measured software itself (trust `software` or `device-key`) |
| | 33 | a component is not allowed, or not the endorsed one |

-33 to -35 are in the range AR4SI leaves to "a non-standard reason for the warning"; their meaning is this table's.

The status is `affirming` only if the endpoint is admitted, every value in the vector is affirming and the verdict
carries no warning; `warning` if it is admitted otherwise; `contraindicated` if evidence was appraised, or the key's
endorsement refused, and the endpoint is not admitted; `incomplete` if there was nothing to appraise. **It is never
better than the verdict**: not admitted is never affirming or warning, and a reader refuses a result that says
`aegis.admitted` under any other status (`test_the_status_is_never_better_than_the_verdict`).

A relying party checks: the signature under the verifier key it trusts (by thumbprint), the profile, `exp`, the
status, and the policy's `ni` name if it knows which policy it expects. A result is about 4.4 kB.

The verifier keeps each cycle's evidence as received and its result under `STATE_DIR/attestation/<name>/`
(`evidence.cbor`, or `evidence.token` and `evidence.sig` for the older quote; `result.cbor`; `meta.json`), replaced
every cycle. The verdict names the result's status, its SHA-256 and the file. That is about 8 kB written per
endpoint and cycle, and one more signature per verdict, by a loop that until now wrote one small state file; and a
verifier that only observed now loads its identity key every cycle. Both are to be looked at on the gateway before
this runs there (flash wear, a TPM-sealed key on the PC verifier).

## The endorsement

The record of `docs/enrolment.md`, with the same claims one for one, format name `aegis-endorsement-cose-v1`:

| Key | Claim | From the JSON body |
|---|---|---|
| 1 | `iss` | `endorser` |
| 2 | `sub` | `device` |
| 6, 4 | `iat`, `exp` | `issued`, `expires` |
| 8 | `cnf` = `{1: COSE_Key}` | the device's public key itself (AKP, with its thumbprint as `kid`). The JSON record carried the key beside the signed body and its hash inside; here the key is under the signature |
| 10 | `eat_nonce` | `evidence.challenge` |
| 256 | `ueid` | `instance_id`, if it is a UEID; otherwise private claim -82406 |
| 265 | `eat_profile` | `tag:github.com,2026:ismailalitech/aegis/endorsement/v1` |
| 273 | `measurements` | `measurements`: name, SHA-256 digest, `authorities` = the signer |
| -82400 ... -82405 | | `profile`, `kind`, `serial`, `device_state`, `evidence.token_sha3_256`, `notes` |
| -82407, -82408 | | `v`, `endorser_pk_sha256` |

`endorsement.loads()` reads either form and returns the same body, so every rule of the verifier (trusted and
revoked endorsers, device, family, key, expiry, the pinned record, the endorsed components) applies to both without
a second implementation. A claim outside the table is refused. The record's name (`endorsement_sha256` in a policy)
is the SHA-256 of the file.

    provision/aegis_provision.py endorse <device> --record-format cose      # writes <device>.cbor
    gateway/aegisd/fleet.py enroll-endorsed fleet.json <device>.cbor

The verifier stores the record where the entry looks for it (by default `endorsements/<name>.json`, whatever the
form: the first byte says which it is). JSON stays the tool's default.

## The evidence pack and the standalone checker

    fleet.py export-evidence fleet.json <name> [--out DIR] [--with-policy]

writes a new directory for one endpoint from the last cycle:

    manifest.json                 format aegis-evidence-pack-v1: every file's SHA-256, the policy's hash and ni name,
                                  the result's status, the keys' thumbprints
    evidence.cbor                 the EAT (or evidence.token + evidence.sig: the older quote; evidence.token alone: a PSA token)
    attestation-result.cbor       the EAR
    endorsement.cbor | .json      the entry's record, if it has one
    keys/verifier.cosekey         COSE_Key files (AKP, ML-DSA-65); keys/device-iak.pem for a PSA token's ES256 key
    keys/device.cosekey
    keys/endorser.cosekey
    policy.json                   only with --with-policy

`tools/verify_evidence.py` checks a pack, or one object, **without any code of this repository**. It imports
pycose 1.1.0, cbor2 5.x and cryptography (with OpenSSL 3.5 or later for ML-DSA), and its claim numbers were written
from this document. pycose has no ML-DSA: the checker registers algorithm -49 with pycose's own extension point,
lets pycose decode the message and build the Sig_structure, and gives the verification to OpenSSL.

    pip install pycose==1.1.0 'cbor2<6' cryptography
    tools/verify_evidence.py pack DIR --verifier-key <thumbprint> --endorser-key <thumbprint> --device-key <thumbprint>
    tools/verify_evidence.py evidence FILE --key KEY [--nonce HEX]
    tools/verify_evidence.py result FILE --key KEY
    tools/verify_evidence.py endorsement FILE --key KEY

For a pack it checks every file against the manifest; the evidence under the device key, the result under the
verifier key and the endorsement under the endorser key; and that the three speak of the same thing: the result
names this evidence file's hash, the quote hash, the device key, the nonce and the measurements of the evidence, the
policy of the manifest, and the endorsement names this device, its key and the measurements of an admitted result.

What it does not do, and says so in its report: the keys in a pack are there for convenience, and without the
thumbprints on the command line the report marks each key `NOT CHECKED`; whoever relies on a pack compares them with
keys obtained another way. It does not check the ES256 signature of a nested PSA token (that needs the platform's
key and a PSA verifier), and it does not judge the policy: the result says what the verifier decided, not whether
the policy was a good one.

## The device's side: an option of the Prover SDK

`sdk/src/aegis_proto.c` built with `-DAEGIS_EAT_COSE=1` answers `PQEAT` and has `aegis_prover_quote_eat()`
(`sdk/include/aegis_sdk.h`). **It is off by default.** Without the flag the core compiles to the same object code as
before (compared section by section when the option was added), and `tools/sdk_golden.py check` reports no
difference.

- The Sig_structure is built in the work buffer and signed there; the platform's `identity_sign`, where the platform
  holds the key, signs it unchanged (it already signs pure ML-DSA-65 with an empty context).
- The work buffer must hold 1962 bytes (the key as a COSE_Key, hashed for the kid) and the claims plus 78; a platform
  token may be as long as the work buffer less 230 bytes. `AEGIS_WORK_LEN()` already gives more.
- The device answers whichever request it gets. Nothing in `struct aegis_prover` or `struct aegis_platform` changed,
  so `AEGIS_SDK_API_VERSION` did not.
- At most 16 measurements; a label is 1 to 64 bytes, the version text at most 64.

Not done: the STM32H573 partition has no PSA message for the new operation, and no port's build enables the flag. The
reference port (`sdk/ports/host`) serves it over its socket when built with the flag, which is what the tests use.

## Compatibility

| Format | Asked with | Status |
|---|---|---|
| PSA token, ES256 (kind `psa`) | `CHAL` | accepted, unchanged |
| older quote: claims or PSA token, detached ML-DSA-65 signature | `PQCHAL` | accepted, the default for every post-quantum kind |
| standard evidence | `PQEAT` | accepted where the entry says `"evidence_format": "eat-cose-v1"` |
| endorsement, JSON (`aegis-endorsement-v1`) | | accepted, the tool's default |
| endorsement, COSE (`aegis-endorsement-cose-v1`) | | accepted |

A result is issued for every one of them and a pack can be exported for every one of them; the checker verifies the
older quote and the JSON record too, and says in its report that they are not COSE.

## Tests

| What | Where |
|---|---|
| envelope, evidence claims, verifier, results, COSE endorsement, pack and checker (simulated devices) | `tests/host/test_evidence_format.py` |
| the SDK option: every encoding boundary with ASan/UBSan, the core behind a socket against `fleet.py`, a bound session, a pack | `sdk/tests/eat_check.c`, `tests/host/test_sdk_eat.py` |
| the default build is unchanged | `tests/host/test_sdk_golden.py` |
| hostile objects against the decoders, the verifier and the checker | `tests/redteam/fuzz_host.py` (stage `host-redteam`) |
| the SDK core with the option under libFuzzer, with the harness's model of an EAT; the shared corpus through that build | `EAT=1 tests/fuzz/run.sh`, seeds `tests/fuzz/seeds/sdk-eat-*`, `tests/host/test_sdk_eat.py` (`Corpus`) |

CI runs all of it: the host regression, two minutes of the fuzz build with the option, and a step that fails if a
test of the standalone checker was skipped for want of its libraries.

## Limits and open questions

1. **EAR and AR4SI are drafts.** Numbers and the profile string may change before publication; -33 to -35 are this
   project's own reasons and mean nothing to a generic AR4SI consumer beyond "warning".
2. **No board has run this.** The bench images answer `PQCHAL` only; enabling the option changes each image's
   measurement and needs a regression on the boards.
3. **The nested PSA token's inner signature** is checked by the verifier, not by the standalone checker.
4. **Reference values are still the policy's `allowed` list**, named in a result by the policy file's hash. A CoRIM
   would be the standard form; it is not part of this work.
5. **The device does not carry its endorsement.** A verifier that has never seen the device still needs the record
   from the endorser (`sdk/README.md`, "Where later work attaches").
6. **A result says what one verifier decided.** It is as trustworthy as that verifier's key and policy; a relying
   party that wants to check the appraisal itself has the evidence in the pack and can run its own.

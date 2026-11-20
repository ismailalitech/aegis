# A signed audit log of the verifier's decisions, and a signed policy

Design note for WP10 part B. Part A ([evidence-format.md](evidence-format.md)) made each verdict a signed object
that a third party can check. Two things around the verdicts were still unsigned: the *history* (the journal says
who was admitted when, and anyone who can write the journal can change it), and the *policy* the verdicts are
reached under (a JSON file that whoever can write the policy directory can replace or put back as it was last
month). This note defines both:

| Statement | Who signs | Object |
|---|---|---|
| audit log: "these are my decisions, in this order, and this is all of them up to here" | the verifier's ML-DSA-65 identity key | batches of entries, each a COSE_Sign1, each naming the hash of the one before |
| policy: "this is the policy the fleet shall run from, and it replaces every lower version" | the operator's ML-DSA-65 policy-signing key, which no verifier holds | the policy file inside a COSE_Sign1 |

| Piece | Where |
|---|---|
| the log: format, writer, reader | `common/audit.py` |
| what the fleet verifier logs, and when; `fleet.py audit` | `gateway/aegisd/fleet.py` (`AuditTrail`, `open_audit`) |
| the signed policy: format, signers, the version counter | `common/signed_policy.py` |
| the verifier's side of it; the key pin of an entry | `gateway/aegisd/fleet.py` (`load_policy`, `device_key`) |
| the operator's side: the policy-signing key and `policy-sign` | `provision/aegis_provision.py` |
| the standalone checker of both (third-party libraries only) | `tools/verify_audit.py` |

**Status.** Software only: everything here is exercised by the host tests against simulated endpoints. No board
was touched, and the gateway on the bench still runs `main`. **Both are off by default**: a policy without
`"audit_log"` and a verifier without policy-signing keys run exactly as before ("Compatibility" below).

Both objects use the envelope of part A unchanged (`common/cose.py`: tagged COSE_Sign1, ML-DSA-65 = algorithm -49 of
RFC 9964, `kid` = the signer's COSE Key Thumbprint, an empty unprotected header, deterministic CBOR), with a `typ`
of their own in the protected header:

| Object | `typ` (RFC 9596, label 16) | Signed by |
|---|---|---|
| evidence, attestation result, endorsement | `application/eat+cwt` | device, verifier, endorser |
| audit batch | `application/vnd.aegis.audit-batch+cbor` | verifier |
| signed policy | `application/vnd.aegis.fleet-policy+cbor` | policy signer |

`typ` is under the signature and every reader requires its own, so the verifier's signature on an attestation
result is never a batch record and the other way round
(`test_a_batch_is_not_an_attestation_result_nor_the_other_way`). Neither media type is registered; they are names
of this project.

## The audit log

### Format

The log is a directory, `STATE_DIR/audit/`, of segment files `audit-000001.cbor`, `audit-000002.cbor`, ... Each
file is a CBOR sequence (RFC 8742) of **batch records**, and every byte of a segment is inside one. A batch record
is a COSE_Sign1 whose payload is:

    { 1: "tag:github.com,2026:ismailalitech/aegis/audit/v1",
      2: log        bstr .size 16     ; made at random when the log begins
      3: batch      uint              ; 1, 2, 3, ... through every segment of the log
      4: prev       bstr .size 32     ; SHA-256 of the batch record before this one (the whole COSE_Sign1);
                                      ; 32 zero bytes for batch 1
      5: time       uint              ; the verifier's clock when it signed
      6: first      uint              ; the number of this batch's first entry: entries count 1, 2, 3, ...
      7: entries    [* entry]         ; at most 256; may be empty
      ? 8: due      uint              ; the verifier promises the next batch by this time
    }
    entry = { 1: time uint, 2: event tstr, ? 3: subject tstr, ? 4: details { * tstr => any } }

- **Append-only and chained.** A batch names its own number, the hash of the record before it and the number of
  its first entry. An entry therefore has one place in the log, and a reader that walks the segments in order finds
  any batch that was changed, removed, repeated, moved or taken from another log.
- **One signature per batch, not per entry.** A batch is what one cycle of the loop has to say; it costs 3.5 kB of
  signature and envelope whatever it holds. An entry inside it is 100 to 500 bytes.
- **The first entry of batch 1 is `log-start`** and says how the log began: the first in its directory, after a log
  signed by another key (it then names that log's last batch and its hash), or after a damaged segment.
- A record is at most 16384 bytes (`cose.MAX_SIGN1`); what does not fit goes into the next batch.

### What is logged, and when

The loop adds an entry **when something changes, not every cycle** (`fleet.py`, `AuditTrail`):

| Event | Subject | When | Details |
|---|---|---|---|
| `start` | | the loop or a `once` run began. Every endpoint's decision is then logged once | command, platform, enforcing or not, the verifier's key hash |
| `policy` | | the policy in use changed (first cycle included) | its SHA-256, the one before; for a signed policy its version, signer, signer key hash and the signed file's hash |
| `policy-refused` | | a policy file was refused or could not be read; once per reason | why; the hash of the policy that stays in use |
| `admit`, `refuse` | endpoint | the endpoint's decision is the first since `start`, or differs from its last one | kind, the address asked, how far the appraisal got (`stage`), device key hash, measurements, enrolment, trust, endorsement record and endorser, evidence format, enforcement result, the quote's hash, the attestation result's hash if one was issued; for `refuse` up to six reasons |
| `issue` | endpoint | a session credential was issued | session id, expiry, binding (`transcript-v2` or `unbound`) |
| `revoke` | endpoint | a stored session was deleted, or replaced before its time (a failed heartbeat, another key, another binding) | session id, why, whether another one replaced it |
| `expiry` | endpoint | a stored session reached the end of its life and was replaced | session id, its expiry |
| `remove` | endpoint | the endpoint is no longer in the policy | |
| `enrol` | endpoint | `enroll-pq` or `enroll-endorsed` pinned a key | how (trust on first use, endorsed), the key hash, the endorser and record, the address asked, whether `--force` |
| `stop` | | the policy no longer asks for a log; the batch carries no `due` | why |
| `log-start`, `recovered`, `gap`, `audit-error`, `unwritable` | | the log's own housekeeping (below); the last two stand for an entry that could not be made from what a verdict held | |

A decision is remembered under the entry's name and address, so two entries that a policy names alike do not take
turns in the log. **What makes a decision another decision:** admitted or not, the stage (`policy`, `endorsement`,
`no-evidence`, `evidence`, `appraised`), the device key, the measurements, how the key is trusted (enrolment, trust
label, endorsement record), the evidence format, and whether enforcement worked. The *words* of a refusal are
recorded but are not part of it: some carry a time or an errno that differs from cycle to cycle, and an endpoint
that stays refused for the same reason must not cost a batch per cycle
(`test_a_decision_that_changes_is_an_entry_and_one_that_only_words_itself_differently_is_not`).

Everything put into an entry is bounded and made encodable first (`audit.clean`): text to 300 characters, lists to
16 items, an entry to 4096 bytes (a longer one keeps its event and subject and says `truncated`). Verdict fields
come from what endpoints send; nothing in them can stop the loop or make a batch unreadable (fuzz section 7).

### What it costs

The review of part A noted that attestation results write about 8 kB per endpoint and cycle. The audit log is built
the other way round:

| Situation | Written |
|---|---|
| a cycle in which no decision, session or policy changed | **nothing**: no byte, no signature, the identity key is not opened |
| a cycle in which something changed | one batch: 3.5 kB plus the entries, one `write` and one `fsync`, one ML-DSA-65 signature; at most one per `min_interval_s` (300 s), later changes wait for it |
| nothing changed for `checkpoint_s` (default 3600 s) | one empty batch of about 3.5 kB, so that the log says "still here, nothing to report" |
| the loop starts | one batch with `start`, `policy` and every endpoint's decision: 6.1 kB for the bench's four endpoints |
| a one-hour session is renewed | `expiry` and `issue` in one batch: 3.7 kB per provisioned endpoint and hour |

For the bench (three provisioned endpoints, 30 s cycle) that is about 0.3 MB a day, where results for the same
fleet write about 90 MB. An endpoint that changes its answer every cycle would cost one batch per cycle, however
many endpoints do it: at a 30 s cycle about 2,900 batches, **about 10 MB a day**. `"min_interval_s"` (default 300)
bounds that: entries made after a batch wait in memory until 300 s after it, then go out together, so the worst is
288 batches a day, **about 1 to 1.5 MB a day** (3.5 kB each plus the entries), and a steady fleet costs the 24
checkpoints, about 85 kB a day. The first batch of a run, `stop`, `once` and the enrolment commands do not wait.
Entries keep their own times; those waiting are lost if the process dies meanwhile (limit 4). `"min_interval_s": 0`
writes every change in the cycle it happens.

Segments are kept for ever by default: at 1 to 1.5 MB a day a flapping fleet fills about 0.5 GB a year.
`"max_segments": N` (0: keep all, the default; otherwise 2 or more) bounds the directory to about N files of
`segment_bytes`: a batch that finds more deletes the oldest down to N (never the one being written), and carries a
signed **`pruned`** entry naming the segments, the log, the last batch they held and its hash, so that what an
anchor from before covered is accounted for, not silently gone. The files are deleted only after that batch is on
disk. The log then begins at a later batch: read it with `--allow-pruned`. Copy segments away first if they may be
needed.

    "audit_log": true
    "audit_log": { "checkpoint_s": 3600, "min_interval_s": 300, "segment_bytes": 1048576, "max_segments": 0 }

Only the JSON value `true`, or an object with those keys (whole numbers; `segment_bytes` 65536 or more;
`max_segments` 0 or 2 or more; `checkpoint_s` 0 for no empty batches and no promise), turns the log on
(`fleet.py`, `audit_settings`). Any other
value is an error said once at error priority, and by `fleet.py check` with exit status 1: someone meant to have a
log and must not find out later that none was kept. The same if the verifier has no identity to sign with.

The verdict and its enforcement never wait for the log. If a batch cannot be written (no key, a full disk) the loop
goes on, says so once at error priority, and keeps up to 512 entries in memory for the next cycle; what did not fit
is counted and the count becomes a `gap` entry. If the policy changes the log's settings while it cannot be
written, what the old settings' writer held goes to the new one, followed by a `gap` entry that says how many
entries were carried over and how many did not fit.

### What a reader can tell

`audit.verify()` and `tools/verify_audit.py` check the same things, in file order: every record is a batch record
signed by a key the reader trusts as this verifier's; batch 1 begins the log; every later batch continues the one
before it (number, `prev`, `first`); nothing follows the last record.

| Done to the log | Without the verifier's key | Found by |
|---|---|---|
| an entry or a batch changed | the signature fails | any reader |
| a batch removed from the middle, repeated, reordered, moved in from another log | the chain breaks (`batch`, `prev`, `first`, `log`) | any reader |
| the beginning removed (old segments deleted) | the log does not begin at batch 1 | any reader, unless `--allow-pruned` |
| **the end cut off** between two batches | **the rest is a whole, signed, shorter log** | a reader with an **anchor** or a **head** from after the cut, or reading after the last batch's **`due`** |
| the whole directory deleted | the verifier begins a new log (another `log` id) | a reader with an anchor; the gap in time |

**Without anchors kept off the gateway (or the journal's `--head` lines), cutting the log off at a record boundary is undetectable**: the writer and the reader check only that the last record is a whole, signed batch, and the batches written by `once`, the enrolment commands and `stop` carry no `due` time, so a log that ends after one of them is never stale.

And with the verifier's key (root on the gateway, limitation 3 of the threat model):

| Done to the log | Found by |
|---|---|
| the log written again from some batch on, or from the start | a reader with an anchor from before: the batch of that number is not the anchored record |
| entries left out as they happen | nothing in this design |

### Anchors, the promise, rotation

**An anchor is a batch record.** Each one is a signed statement "the log `log` had `batch` batches, and this is the
last one". Kept somewhere the gateway cannot write, it fixes the log up to that batch for good:

    fleet.py audit POLICY --out anchor.cbor          # checks the log, prints where it stands, writes the last record
    tools/verify_audit.py log DIR --key KEY --anchor anchor.cbor

(`fleet.py audit` reads the log under the writers' lock with the verifier's own code and key, so it works on the
gateway, which has none of the checker's libraries; `--entries` prints every entry, `--audit-key FILE` accepts an
identity the verifier had before. Its exit status is 1 for a log that is not whole, or stale.)

The reader then requires that the log holds exactly that record under that number. A log that ends before it was
cut off; a log with another record there was written again; a log with another id was replaced.

**The journal is a second, weaker anchor.** For every batch the loop prints
`aegis-audit: batch N of log L, entries A to B, sha256 H`, and `verify_audit.py --head N:H` checks the log against
such a line. It costs nothing more, and helps where the journal is forwarded or read by someone else.

**The promise.** A batch written by the loop says when the next one is due: `time + checkpoint_s` plus the
admission TTL as slack. A log whose last batch is past its `due` is **stale**: the verifier stopped, or the end was
cut off. The checker fails such a log by default (`--at TIME` checks as of an earlier time, for an archived copy;
`--no-freshness` turns it off). A `once` run and the enrolment commands make no promise of their own; they repeat a
standing one unchanged and drop one that has lapsed.

**Rotation.** A new segment is begun when the current one would pass `segment_bytes` (1 MiB: three to four days on
the bench). The chain runs through the segments, so a segment that was copied away and checked can be deleted: the
remaining log then begins at a later batch, which the checker accepts only with `--allow-pruned`, and says so. The
verifier itself deletes segments only with `"max_segments"`, and then says so in the log (`pruned`, above).

### The writer

- **The key is opened only to sign a batch** (`audit.Log`, `load_sk`), so a steady verifier does not unseal a
  TPM-held identity every cycle for the log.
- **A torn end.** A record is appended with one `write` and flushed before the loop goes on. If the process dies in
  the middle, the segment ends in half a record that was never signed. The next writer cuts exactly that off, under
  the lock, and its next batch begins with `recovered` and the number of bytes dropped. A reader of the torn file
  refuses it.
- **Two writers.** The loop and an enrolment command may write the same log. Every append is made under a lock on
  the directory, onto the log as it is on disk then (`test_two_writers_make_one_chain`).
- **Another identity.** A verifier whose identity was made again (`aegisd.py init`) cannot continue the old log. It
  begins a new one, in a new segment, whose `log-start` names the old log's last batch and its hash. A reader given
  both keys checks both and the join; given only the new log it says that what came before is missing. If the
  identity is made again **while the loop runs**, the loop still holds the old public key and would sign with the
  new secret key: every batch is checked against the log's key before it is appended, and one that does not verify
  is not written (`KeyMismatch`, said once at error priority; the entries wait in memory). Restart the loop.
- **Damage.** The writer checks the record it continues from (the last one), not the whole log. If that is not a
  batch record signed by its key, it leaves the segment alone and begins a new log that says so
  (`damaged_segment`). Damage further back is found by a reader.

## The signed policy

### Format

    COSE_Sign1, typ "application/vnd.aegis.fleet-policy+cbor", payload
    { 1: "tag:github.com,2026:ismailalitech/aegis/policy/v1",
      2: version    uint, 1 or more
      3: issued     uint                 ; the signer's clock
      4: policy     bstr                 ; the policy file, byte for byte
      5: signer     tstr                 ; the signer's name
      ? 6: audience tstr                 ; the fleet this policy is for
    }

The policy inside stays the JSON it was. Its SHA-256 is what an attestation result and the audit log name, signed or
not, so a result reached under `fleet.json` and one reached under the same policy in `fleet.cose` name the same
policy. A signed policy is 3.5 kB longer than its JSON. The JSON must be one object with an `"endpoints"` list and
**no name twice in any object**: two parsers must not be able to read one signed file two ways.

### On the verifier

**Off by default.** A verifier checks signatures only if it has been given the keys to check them with, in a
signers file:

    { "format": "aegis-policy-signers-v1",
      "signers": [ { "name": "ops", "pk": "<ML-DSA-65 public key, hex>" } ],
      "audience": "bench" }                                  ; optional

It is looked for in `STATE_DIR/policy-signers.json`, or where `--policy-signers FILE` says (`fleet.py`,
`policy_signers`, `load_policy`):

| | no signers file (the default) | with a signers file |
|---|---|---|
| a JSON policy | read as before | **refused**: "not signed" |
| a signed policy by a listed key | **refused**: not read unchecked | accepted, if its version is not behind and its audience fits |
| a signed policy by any other key, altered, of another `typ`, with claims outside the format | refused | refused |
| a signers file that is there and unusable, or `--policy-signers` naming a missing file | | refused: a verifier told to check does not go on unchecked |
| a signers file that lists the verifier's own identity key | | refused: the verifier holds no key that can sign a policy, and its own key is on the gateway |

- The policy file is whichever one is named on the command line: `fleet.py watch fleet.cose`. Its first byte says
  what it is (`d2`, tag 18, or `{`). Key files, endorser keys and endorsement records are still looked up beside it.
- **Every command** that reads a policy applies this (`watch`, `once`, `check`, the enrolment commands, `audit`,
  `export-evidence`); a refused policy ends the command with status 1.
- **In the loop**, which reads its policy again every cycle, a refused file leaves the last accepted policy in use
  (as an unreadable file always did), says so once at error priority and in the audit log (`policy-refused`). The
  same file is not verified again every cycle.
- **A loop that ran from an unsigned policy and is then given a signers file stops.** There is no accepted policy to
  keep; running on from the unsigned one would be the downgrade. systemd starts it again, it refuses the unsigned
  file, and the admissions lapse with their TTL.
- **`audience`**: with `"audience"` in the signers file a policy must carry exactly that name. It is for an operator
  who signs for more than one fleet with one key, so that the bench's policy is not valid at the plant.

`--policy-signers` in the service's unit is the stricter way to turn it on: a state directory that lost the file
(a restore, a mistake) then refuses to start instead of running unsigned. A verifier that finds
`policy-version.json` and no signers file says so at warning priority on every start and in `check`.

**The signers file disappearing while the loop runs fails closed.** If the loop runs from a signed policy,
`policy-version.json` is there and `STATE_DIR/policy-signers.json` is gone, the policy file is refused (an unsigned
JSON file is not read unchecked), the last verified policy stays in use, and the refusal is said at error priority
and in the audit log (`policy-refused`). Putting the file back resumes the check; running unsigned again takes a
restart, which says so at warning priority.

### The version

A verifier keeps the last version it accepted in `STATE_DIR/policy-version.json` (`signed_policy.check_version`):

| The policy offered | |
|---|---|
| a higher version | accepted; `watch` and `once` record it, written under a temporary name and flushed before the rename |
| the same version, the same policy | accepted (the loop's reload) |
| the same version, another policy | refused |
| a lower version | refused: "rollback refused" |
| any, and the record cannot be read | refused: a counter that cannot be read is not a counter at zero |

`check` looks at a policy without recording anything, so a policy can be tried before it is deployed. Versions may
skip. There is no way back to a lower version except deleting the record on the verifier.

### What the signature covers: the key pin

A policy names files: `pq_pub_file`, `iak_pub_pem`, the endorsers' keys, the endorsement records. The signature
covers their names, not their content, unless the policy also carries their hash:

| File | Pinned by |
|---|---|
| an endorser's key | `pk_sha256` in `"endorsers"` (since `docs/enrolment.md`) |
| an endorsement record | `endorsement_sha256` in the entry |
| a device key pinned on first use | **`pq_pub_sha256`** in the entry (new): `device_key()` refuses a key file that holds another key, and `export-evidence` does not put such a key into a pack |
| the ES256 key of a `psa` entry | not pinned (limit 5) |

    { "name": "frdm-rw612", "kind": "aegis-device", "pq_pub_file": "keys/frdm-rw612.mldsa65.pub",
      "pq_pub_sha256": "<SHA-256 of the public key>", ... }

`policy-sign --pin-keys` writes the pins from the key files beside the policy before it signs. Without a pin a
replaced key file is admitted under a signed policy exactly as under an unsigned one
(`test_an_entry_can_pin_the_key_its_key_file_must_hold`).

**Enrolment under a signed policy.** `enroll-endorsed` normally writes the record's pin into the policy. A verifier
cannot change a signed policy, so it installs the record and the key and prints the pin for the operator to put
into the next version. Until then the entry behaves as an unpinned one (an older record of the same endorser for
the same key would be accepted), or, if it still pins the previous record, the device is refused.

### Signing

    aegis_provision.py policy-init --name ops                   # the key: TPM-sealed where there is a TPM, else 0600
    aegis_provision.py policy-export DIR [--audience bench]     # DIR/policy-signers.json for the verifier
    aegis_provision.py policy-sign fleet.json [--pin-keys] [--audience bench] [--out fleet.cose]

The key lives on the operator's machine in its own state directory (`~/.local/state/aegis-policy-signer`), apart
from the endorser's, with a record of its own kind. `policy-sign`:

1. reads the policy, refuses what is not a policy (not JSON, a name twice, no `"endpoints"`);
2. with `--pin-keys`, adds `pq_pub_sha256` to every post-quantum entry from its key file; an entry that already
   pins another key than its file holds stops the command;
3. takes the next version from its ledger (`signed.jsonl`): one more than the last it signed. A version given with
   `--policy-version` that is not higher is refused unless `--force`;
4. prints what it is about to sign (the version and the one before, the hash, each endpoint with its address and
   how its key is pinned, the enforcement command, the endorsers, whether results and the audit log are on, and
   what a verifier would refuse or the signature does not cover) and asks the operator to type `yes`. Without a
   terminal nothing is signed; `--yes` is for a script;
5. signs, reads the signed bytes back as a verifier does, writes the ledger line, and only then the file (and, if
   pins were added, the policy with them; the one that was read is kept as `fleet.json.bak`).

### The checker

    pip install pycose==1.1.0 'cbor2<6' cryptography
    tools/verify_audit.py log DIR --key KEY [--anchor FILE] [--head N:SHA256] [--at TIME] [--allow-pruned] [--entries]
    tools/verify_audit.py policy FILE --key KEY [--audience FLEET] [--min-version N] [--extract OUT.json]

Like `verify_evidence.py` it imports nothing of this repository, and its numbers were written from this document.
`KEY` is a hex file, a COSE_Key file (as in an evidence pack), the verifier's `identity.json`, or a
`policy-signers.json`. For a policy it prints the version, the signer, the policy's hash and its `ni` name (what an
attestation result calls it), and can write out the JSON inside. It has no counter: `--min-version` is how a
relying party says which version it expects at least. The host fuzzer holds the two readers of each format to each
other.

## Threat model

Against the adversaries of [threat-model.md](threat-model.md), and one more that these two objects are about:
**someone who can write files on the verifier but does not hold a signing key** (a deployment channel, a restore
from backup, an operator's mistake, a file-write flaw in something that runs beside the verifier).

| Threat | What helps | What does not |
|---|---|---|
| the history of decisions is edited afterwards, or entries are removed | the chain and the signatures: any reader finds it | |
| the end of the log is cut off | an anchor or a journal line from after the cut; the promise once it lapses | a reader with neither, before `due` |
| a record of a decision is needed by a third party later | the log is one key's statements in order; the entry names the device key, the measurements, the quote and (if issued) the result | the log says what the verifier decided, not that the decision was right |
| the policy file is replaced by one nobody approved | with a signers file: refused, and the loop keeps the last accepted one | without a signers file: nothing (the default) |
| an older signed policy is put back (an endpoint that was removed, a measurement that was withdrawn) | the version counter | deleting the counter with the same access |
| a key file beside a signed policy is replaced | `pq_pub_sha256`, `endorsement_sha256`, `pk_sha256` | entries without the pin; `iak_pub_pem` |
| a policy signed for another fleet is copied here | `audience` | verifiers without one |
| a flapping or hostile endpoint makes the verifier write | entries only on change; at most one batch per `min_interval_s` (300 s); `max_segments` | without `max_segments` the directory grows for ever (about 1 to 1.5 MB a day at worst) |
| hostile verdict content breaks the log | everything bounded and encoded before it is queued; fuzzed | |
| **root on the gateway** | an anchor kept elsewhere shows a log written again; the policy-signing key is not on the gateway, so a new *signed* policy cannot be made there | root can replace the signers file, delete the counter, stop the log, or sign a log that leaves things out as they happen. As before, root on the gateway is outside what Aegis defends against |

## Compatibility

| | Default | Turned on by |
|---|---|---|
| audit log | off: nothing written, no key opened, verdicts unchanged | `"audit_log": true` in the policy |
| signed policy | off: the policy is the JSON file | a signers file on the verifier |
| key pin | none | `"pq_pub_sha256"` in an entry |

With all three off, `fleet.py` behaves as on `main`: the same verdicts, the same files in the state directory, the
same journal lines; the modules of this note are not even imported
(`test_without_policy_signing_keys_the_policy_is_the_json_file_as_before`,
`test_off_by_default_nothing_is_written_and_no_key_is_opened`, `test_an_unsigned_loop_reloads_as_before`).
A verdict never carries anything of the audit log, so the state file and the `once` output are the same with it on.
Nothing changes on any endpoint, in the SDK or on the wire; `tools/sdk_golden.py check` reports no difference.

## Tests

| What | Where |
|---|---|
| the log: the document's bytes, nothing written when nothing is said, every manipulation in the tables above, anchors, the promise, pruning, a torn end, two writers, another identity, damage, hostile entries, a log that cannot be written | `tests/host/test_audit_policy.py` (`Log`) |
| the trail: off by default, a steady fleet, changes, sessions, policy changes, enrolment, the `audit` command, bad settings | the same file (`Trail`) |
| the signed policy: the document's bytes, who may sign, hostile claims, audience, the version, the signers file | (`Policy`) |
| the verifier: unsigned as before, signed only, rollback, the loop (`watch` run for a few cycles), the key pin, enrolment under a signed policy | (`Verifier`, `EndorsedUnderASignedPolicy`) |
| the signer: its own key, export, sign, confirmation, `--pin-keys`, versions and the ledger | (`Signer`) |
| the standalone checker: no shared code, the same reading as the verifier's, every refusal, anchor, head, freshness, pruning; a signed policy | (`Checker`) |
| hostile logs, policy files and verdicts against both readers and the loader | `tests/redteam/fuzz_host.py` section 7 (stage `host-redteam`) |

CI runs all of it in the host regression, and a step fails if a test of the checker was skipped for want of its
libraries.

## Limits and open questions

1. **The log is as honest as the key holder.** It is tamper-evident against everyone who does not hold the
   verifier's identity key. That key is a file on the gateway (limitation 3 of the threat model). Whoever holds it
   can write a log from scratch; an anchor kept elsewhere shows that it is not the log that was anchored, and
   nothing shows an entry that was never written.
2. **Cutting off the end needs someone who looked.** Without an anchor or a journal line from after the cut, and
   before the promise lapses, a shorter log is a valid log. Without anchors kept off the gateway (or the journal's
   `--head` lines), truncation at a record boundary is undetectable: only the last record is checked, and batches
   from `once`, the enrolment commands and `stop` carry no `due` time. Nothing takes anchors off the gateway by itself yet:
   the PC verifier could fetch one with each gateway quote, and an attestation result could name the log's head.
   Neither is done.
3. **The verifier's clock** is the only one. Times in the log are what the gateway thought the time was; a reader
   is told where the clock went back, not what the right time was. The promise is judged on the reader's clock.
4. **Entries held in memory are lost with the process**: those waiting for `min_interval_s`, or for a disk that
   came back. A decision reached and enforced in a cycle the process did not survive is not in the log.
5. **A signed policy covers what it pins.** Key files of trust-on-first-use entries without `pq_pub_sha256`, and
   the ES256 key file of a `psa` entry, are outside the signature. Endorsement records are covered by their own
   signature and, where pinned, by the policy.
6. **The counter and the signers file are files in the verifier's state.** Whoever can write there can go back to
   an older signed policy by deleting the counter, or turn the check off by removing the signers file (unless the
   unit names it with `--policy-signers`) and restarting the verifier: a running loop refuses to go on unsigned.
   That is the same access that can replace the verifier's identity.
7. **One signer is enough.** Any key of the signers file can sign any version; there is no threshold, no expiry of
   a policy and no signed revocation of a signer: a signer is removed by replacing the signers file on each
   verifier.
8. **No board has run this**, and the write cost on the gateway's storage is computed, not measured. Before the
   log is turned on there: one cycle's batch on the PolarFire (one ML-DSA-65 signature in software), and the
   growth of `STATE_DIR/audit/` over a week.
9. **The log is local.** There is no transparency log, no witness and no gossip between verifiers; an anchor is a
   file someone has to keep.

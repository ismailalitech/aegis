# SPDX-License-Identifier: Apache-2.0
"""The golden vectors (tests/vectors/aegis-1.2/) and the JSON Schemas (docs/schemas/) of docs/data-formats.md.

  schemas     every schema uses only the keywords the validator below implements (draft 2020-12, a subset), its
              closed lists are the code's (fleet.py, eat.py, endorsement.py, signed_policy.py), it refuses what the
              verifier refuses, and docs/data-formats.md links it and names every trust and enrolment value
  vectors     the committed files: every pack verifies with tools/verify_evidence.py and the reader's own key
              thumbprints, the audit log and its anchor and the signed policy with tools/verify_audit.py, every
              JSON file matches its schema, every key is the one its published seed makes, and the files agree
              with one another (the audit log names the results of the packs)
  regenerate  tools/gen_golden_vectors.py run again into a temporary directory makes the same files: the same
              names, the same README, the same JSON once the hashes over signatures are masked, the same evidence
              claims; and its packs verify too. ML-DSA-65 signing is hedged, so signatures are not compared.

No JSON Schema package is a dependency of this repository: the validator here implements the subset the schemas use,
and refuses a schema with any other keyword, so a schema cannot silently ask for more than is checked.
"""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for p in ("common", "gateway/aegisd"):
    sys.path.insert(0, os.path.join(ROOT, p))

import cbor  # noqa: E402
import cose  # noqa: E402
import eat  # noqa: E402
import endorsement  # noqa: E402
import fleet  # noqa: E402
import signed_policy  # noqa: E402

VECTORS = os.path.join(ROOT, "tests", "vectors", "aegis-1.2")
SCHEMAS = os.path.join(ROOT, "docs", "schemas")
DOC = os.path.join(ROOT, "docs", "data-formats.md")
EVIDENCE_CHECKER = os.path.join(ROOT, "tools", "verify_evidence.py")
AUDIT_CHECKER = os.path.join(ROOT, "tools", "verify_audit.py")

# name -> (status, admitted, trust, enrolment): what the generator's fleet is meant to show
EXPECTED = {
    "psa-tfm": ("warning", True, None, None),
    "pq-quote": ("affirming", True, "trustzone", "endorsed"),
    "pq-eat": ("affirming", True, "trustzone", "endorsed"),
    "rw612-tfm-eat": ("affirming", True, "trustzone", "endorsed"),
    "rw612-els-quote": ("warning", True, "device-key", "trust-on-first-use"),
    "zynqmp-devhuk-eat": ("warning", True, "development-shared-key", "trust-on-first-use"),
    "zynqmp-optee-quote": ("contraindicated", False, "trustzone", "trust-on-first-use"),
    "linux-host": ("warning", True, "software", "trust-on-first-use"),
    "offline-eat": ("incomplete", False, None, "trust-on-first-use"),
}


def have_libs():
    try:
        import cbor2  # noqa: F401
        import pycose  # noqa: F401
        from cryptography.hazmat.primitives.asymmetric import mldsa
        mldsa.MLDSA65PrivateKey.from_seed_bytes(bytes(32))
    except Exception:  # noqa: BLE001
        return False
    return True


NEEDS_LIBS = unittest.skipUnless(have_libs(), "needs pycose, cbor2 and cryptography with ML-DSA")


def generator():
    spec = importlib.util.spec_from_file_location("gen_golden_vectors", os.path.join(ROOT, "tools",
                                                                                     "gen_golden_vectors.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load(*path):
    with open(os.path.join(*path)) as f:
        return json.load(f)


def schema(name):
    return load(SCHEMAS, name + ".schema.json")


def checker(tool, *args):
    """A standalone checker as a program of its own (-I: nothing of this repository on its path)."""
    r = subprocess.run([sys.executable, "-I", tool, *args], capture_output=True, text=True, cwd=tempfile.gettempdir())
    try:
        return r.returncode, json.loads(r.stdout)
    except ValueError:
        return r.returncode, {"verified": False, "reason": r.stdout + r.stderr}


# ---- a JSON Schema validator: the subset of draft 2020-12 the schemas use ----------------------------------------------

class SchemaError(Exception):
    """The schema uses something this validator does not implement."""


ANNOTATIONS = {"$schema", "$id", "$comment", "$defs", "title", "description", "default", "examples"}
KEYWORDS = {"type", "enum", "const", "pattern", "minLength", "maxLength", "minimum", "maximum", "exclusiveMinimum",
            "minItems", "maxItems", "items", "properties", "required", "additionalProperties", "propertyNames",
            "dependentRequired", "allOf", "anyOf", "oneOf", "not", "if", "then", "else", "$ref"}
TYPES = {"object": lambda v: isinstance(v, dict), "array": lambda v: isinstance(v, list),
         "string": lambda v: isinstance(v, str), "boolean": lambda v: isinstance(v, bool), "null": lambda v: v is None,
         "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
         "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool)}


def same(a, b):
    """JSON equality: true is not 1."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(same(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b))
    return type(a) in (int, float) and type(b) in (int, float) and a == b or (type(a) is type(b) and a == b)


def check_schema(s, path="#"):
    """SchemaError unless every keyword of s, at any depth, is one validate() implements."""
    if isinstance(s, bool):
        return
    if not isinstance(s, dict):
        raise SchemaError("%s: a schema is an object or a boolean" % path)
    unknown = set(s) - KEYWORDS - ANNOTATIONS
    if unknown:
        raise SchemaError("%s: keywords this validator does not implement: %s" % (path, sorted(unknown)))
    for k in ("items", "additionalProperties", "propertyNames", "not", "if", "then", "else"):
        if k in s:
            check_schema(s[k], "%s/%s" % (path, k))
    for k in ("properties", "$defs"):
        for name, sub in s.get(k, {}).items():
            check_schema(sub, "%s/%s/%s" % (path, k, name))
    for k in ("allOf", "anyOf", "oneOf"):
        for i, sub in enumerate(s.get(k, [])):
            check_schema(sub, "%s/%s/%d" % (path, k, i))
    if "$ref" in s and not s["$ref"].startswith("#/$defs/"):
        raise SchemaError("%s: only local references (#/$defs/...) are implemented" % path)


def validate(s, v, root=None, where="$"):
    """The errors of instance v against schema s, as ["where: why"]; empty if it is valid."""
    root = s if root is None else root
    if s is True:
        return []
    if s is False:
        return ["%s: nothing is allowed here" % where]
    errs = []
    if "$ref" in s:
        target = root
        for part in s["$ref"][2:].split("/"):
            target = target[part]
        errs += validate(target, v, root, where)
    if "type" in s:
        types = s["type"] if isinstance(s["type"], list) else [s["type"]]
        if not any(TYPES[t](v) for t in types):
            return errs + ["%s: %r is not of type %s" % (where, v, "/".join(types))]
    if "enum" in s and not any(same(v, x) for x in s["enum"]):
        errs.append("%s: %r is not one of %r" % (where, v, s["enum"]))
    if "const" in s and not same(v, s["const"]):
        errs.append("%s: %r is not %r" % (where, v, s["const"]))
    if isinstance(v, str):
        if "pattern" in s:
            pat = s["pattern"][:-1] + r"\Z" if s["pattern"].endswith("$") else s["pattern"]     # ECMA-262 $
            if not re.search(pat, v):
                errs.append("%s: %r does not match %s" % (where, v[:80], s["pattern"]))
        if len(v) < s.get("minLength", 0) or len(v) > s.get("maxLength", len(v)):
            errs.append("%s: length %d is out of range" % (where, len(v)))
    if TYPES["number"](v):
        if ("minimum" in s and v < s["minimum"]) or ("maximum" in s and v > s["maximum"]) \
                or ("exclusiveMinimum" in s and v <= s["exclusiveMinimum"]):
            errs.append("%s: %r is out of range" % (where, v))
    if isinstance(v, list):
        if len(v) < s.get("minItems", 0) or len(v) > s.get("maxItems", len(v)):
            errs.append("%s: %d items is out of range" % (where, len(v)))
        if "items" in s:
            for i, x in enumerate(v):
                errs += validate(s["items"], x, root, "%s[%d]" % (where, i))
    if isinstance(v, dict):
        for k in s.get("required", []):
            if k not in v:
                errs.append("%s: %r is required" % (where, k))
        props = s.get("properties", {})
        for k, x in v.items():
            if k in props:
                errs += validate(props[k], x, root, "%s.%s" % (where, k))
            elif "additionalProperties" in s:
                errs += validate(s["additionalProperties"], x, root, "%s.%s" % (where, k))
            if "propertyNames" in s:
                errs += validate(s["propertyNames"], k, root, "%s (name %r)" % (where, k))
        for k, needs in s.get("dependentRequired", {}).items():
            if k in v:
                errs += ["%s: %r needs %r" % (where, k, n) for n in needs if n not in v]
    for sub in s.get("allOf", []):
        errs += validate(sub, v, root, where)
    if "anyOf" in s and all(validate(sub, v, root, where) for sub in s["anyOf"]):
        errs.append("%s: matches none of anyOf" % where)
    if "oneOf" in s:
        n = sum(not validate(sub, v, root, where) for sub in s["oneOf"])
        if n != 1:
            errs.append("%s: matches %d of oneOf, not one" % (where, n))
    if "not" in s and not validate(s["not"], v, root, where):
        errs.append("%s: matches what is not allowed" % where)
    if "if" in s:
        branch = s.get("then") if not validate(s["if"], v, root, where) else s.get("else")
        if branch is not None:
            errs += validate(branch, v, root, where)
    return errs


# ---- the schemas -------------------------------------------------------------------------------------------------------

def find(s, *path):
    for p in path:
        s = s[p]
    return s


def conditional(entry, kind):
    """The profile enum an endpoint's if/then gives kind."""
    for c in entry["allOf"]:
        cond = c["if"].get("properties", {}).get("kind", {})
        if cond.get("const") == kind and set(c["if"]["required"]) == {"kind"}:
            prof = c["then"]["properties"]["profile"]
            return set(prof["enum"]) if "enum" in prof else {prof["const"]}
    return None


class Schemas(unittest.TestCase):
    NAMES = ("manifest", "fleet-state", "policy", "endorsement", "policy-signers")

    def test_every_schema_is_draft_2020_12_and_in_the_implemented_subset(self):
        self.assertEqual(sorted(n[:-len(".schema.json")] for n in os.listdir(SCHEMAS)), sorted(self.NAMES))
        for name in self.NAMES:
            s = schema(name)
            self.assertEqual(s["$schema"], "https://json-schema.org/draft/2020-12/schema", name)
            check_schema(s)
            # every reference resolves
            refs = re.findall(r'"\$ref": "#/\$defs/([^"]+)"', json.dumps(s))
            self.assertTrue(set(refs) <= set(s.get("$defs", {})), name)
        with self.assertRaises(SchemaError):
            check_schema({"type": "object", "unevaluatedProperties": False})

    def test_the_closed_lists_are_the_codes(self):
        pol, state, man, rec = schema("policy"), schema("fleet-state"), schema("manifest"), schema("endorsement")
        ep = pol["$defs"]["endpoint"]
        kinds = set(fleet.KNOWN_KINDS)
        self.assertEqual(set(ep["properties"]["kind"]["enum"]), kinds)
        self.assertEqual(set(state["$defs"]["kind"]["enum"]), kinds)
        self.assertEqual(set(man["$defs"]["kind"]["enum"]), kinds)
        self.assertEqual(set(rec["$defs"]["body"]["properties"]["kind"]["enum"]), set(fleet.PQ_KINDS))
        profiles = {p for d in fleet.PLAIN_KINDS.values() for p in d}
        self.assertEqual(set(ep["properties"]["profile"]["enum"]), profiles)
        for kind, accepted in fleet.PLAIN_KINDS.items():
            self.assertEqual(conditional(ep, kind), set(accepted), kind)
        self.assertEqual(set(rec["$defs"]["body"]["properties"]["profile"]["enum"]), profiles - fleet.DEV_PROFILES)
        self.assertEqual(set(ep["properties"]["heartbeat_mac"]["enum"]), set(fleet.HEARTBEAT_MACS))
        self.assertEqual({ep["properties"]["transcript"]["const"]}, set(fleet.TRANSCRIPTS))
        self.assertEqual({ep["properties"]["endorsement"]["const"]}, set(fleet.ENDORSEMENTS))
        self.assertEqual({ep["properties"]["evidence_format"]["const"]}, set(fleet.EVIDENCE_FORMATS))
        self.assertEqual(set(find(pol, "properties", "audit_log", "oneOf", 1, "properties")), set(fleet.AUDIT_SETTINGS))
        # every value attest() can write into "trust", read from its source
        with open(os.path.join(ROOT, "gateway", "aegisd", "fleet.py")) as f:
            src = f.read()
        written = set()
        for rhs in re.findall(r'verdict\["trust"\] = (.+)', src):
            written |= set(re.findall(r'"([a-z-]+)"', rhs))
        written |= {label for d in fleet.PLAIN_KINDS.values() for label in d.values()}
        self.assertIn("accepted[profile]", src)
        self.assertEqual(set(state["$defs"]["trust"]["enum"]), written)
        self.assertEqual(set(state["$defs"]["enrolment"]["enum"]), {fleet.ENDORSED, fleet.TOFU, fleet.NOT_ENDORSED})
        self.assertEqual(set(state["$defs"]["status"]["enum"]), set(eat.TIER_NAMES.values()))
        self.assertEqual(set(man["$defs"]["status"]["enum"]), set(eat.TIER_NAMES.values()))
        v = state["$defs"]["verdict"]["properties"]
        self.assertEqual(set(v["session_binding"]["enum"]), {fleet._binding("v2"), fleet._binding(None)})
        self.assertEqual(v["endorsement"], {"$ref": "#/$defs/endorsement"})
        self.assertEqual(set(state["$defs"]["endorsement"]["properties"]["device_state"]["enum"]),
                         set(endorsement.DEVICE_STATES))
        self.assertEqual(man["properties"]["format"]["const"], fleet.PACK_FORMAT)
        self.assertEqual(set(man["properties"]["evidence_format"]["enum"]),
                         {fleet.EAT_COSE, fleet.LEGACY_QUOTE, fleet.PSA_TOKEN, None})
        # the endorsement record: every key the code knows, the ones it requires
        body = rec["$defs"]["body"]
        self.assertEqual(set(body["properties"]), endorsement._BODY_KEYS)
        self.assertEqual(set(body["required"]), endorsement._REQUIRED)
        self.assertEqual(set(rec["properties"]), endorsement._RECORD_KEYS)
        self.assertEqual(rec["properties"]["format"]["const"], endorsement.FORMAT)
        self.assertEqual(body["properties"]["device_state"]["enum"], list(endorsement.DEVICE_STATES))
        self.assertEqual(schema("policy-signers")["properties"]["format"]["const"], signed_policy.SIGNERS_FORMAT)

    def test_the_document_names_every_value_and_links_every_schema(self):
        with open(DOC) as f:
            doc = f.read()
        for name in self.NAMES:
            self.assertIn("(schemas/%s.schema.json)" % name, doc)
        state = schema("fleet-state")["$defs"]
        for value in state["trust"]["enum"] + state["enrolment"]["enum"]:
            self.assertIn("| `%s` |" % value, doc)
        for claim in ("aegis.endpoint", "aegis.kind", "aegis.admitted", "aegis.evidence-format", "aegis.trust",
                      "aegis.enrolment", "aegis.session-binding", "aegis.device-key-sha256", "aegis.quote-sha3-256",
                      "aegis.evidence-sha256", "aegis.enforcement", "aegis.record-sha256", "aegis.device-state"):
            self.assertIn("`%s`" % claim, doc)
        # and every aegis.* claim the code writes is one of those
        with open(os.path.join(ROOT, "common", "eat.py")) as f:
            for claim in set(re.findall(r'"(aegis\.[a-z0-9-]+)"', f.read())):
                self.assertIn("`%s`" % claim, doc)

    def test_the_policy_schema_refuses_what_the_verifier_refuses(self):
        """For entries that differ in one key: the schema and fleet.policy_errors() agree."""
        good = {"name": "d", "kind": "aegis-tee", "host": "192.0.2.1", "port": 7444, "pq_pub_file": "k.pub",
                "profile": "aegis-zynqmp-optee-v1"}
        cases = [
            ({}, True),
            ({"kind": "aegis-device"}, False),                              # a profile of another kind
            ({"profile": "aegis-zynqmp-optee-devhuk-v1"}, False),           # development profile, not allowed
            ({"profile": "aegis-zynqmp-optee-devhuk-v1", "allow_dev_profile": True}, True),
            ({"profile": "aegis-zynqmp-optee-devhuk-v1", "allow_dev_profile": True, "endorsement": "required"}, False),
            ({"profile": None}, False),
            ({"kind": "aegis-gpu"}, False),
            ({"name": "../x"}, False),
            ({"name": ".hidden"}, False),
            ({"heartbeat_mac": "hmac"}, False),
            ({"transcript": "v3"}, False),
            ({"transcript": "v2", "endorsement": "required", "evidence_format": "eat-cose-v1"}, True),
            ({"endorsement": "optional"}, False),
            ({"evidence_format": "eat-cose-v2"}, False),
            ({"endorsement_sha256": "AB" * 32}, False),
            ({"pq_pub_sha256": "ab" * 31}, False),
            ({"verifier_pin_sha256": "AB" * 32}, True),
            ({"verifier_pin_sha256": "zz" * 32}, False),
            ({"max_endorsement_age_s": 0}, False),
            ({"max_endorsement_age_s": True}, False),
            ({"pq_pub_file": None}, False),
            ({"kind": "psa", "pq_pub_file": None, "profile": None}, False),     # psa without its ES256 key
            ({"kind": "psa", "pq_pub_file": None, "profile": None, "iak_pub_pem": "iak.pem"}, True),
            ({"kind": "psa", "iak_pub_pem": "iak.pem", "transcript": "v2"}, False),
            ({"kind": "psa", "iak_pub_pem": "iak.pem", "evidence_format": "eat-cose-v1"}, False),
            ({"kind": "aegis-pq", "profile": None}, True),
            ({"kind": "aegis-linux", "profile": "aegis-linux-software-v1"}, True),
        ]
        entry = {"$defs": schema("policy")["$defs"], "$ref": "#/$defs/endpoint"}
        for change, ok in cases:
            e = {k: v for k, v in dict(good, **change).items() if v is not None}
            self.assertEqual(fleet.policy_errors(e) == [], ok, (change, fleet.policy_errors(e)))
            self.assertEqual(validate(entry, e) == [], ok, (change, validate(entry, e)))
        top = schema("policy")
        for audit_log, ok in ((True, True), (None, True), ({"checkpoint_s": 60}, True), ({"max_segments": 1}, False),
                              ({"segment_bytes": 4096}, False), ({"every": 1}, False), ("yes", False)):
            p = {"endpoints": [], "audit_log": audit_log}
            try:
                runs = fleet.audit_settings(p) is not None or audit_log in (None, False)
            except ValueError:
                runs = False
            self.assertEqual(runs, ok, audit_log)
            self.assertEqual(validate(top, p) == [], ok, (audit_log, validate(top, p)))

    def test_the_written_objects_are_closed_and_their_values_checked(self):
        state = schema("fleet-state")
        v = {"endpoint": "d", "kind": "aegis-device", "time": 1, "admitted": True, "reasons": [], "enforce_rc": None,
             "trust": "trustzone", "enrolment": "endorsed"}
        self.assertEqual(validate(state, {"updated": 1, "verdicts": [v]}), [])
        for bad in ({"trust": "hardware"}, {"enrolment": "pinned"}, {"admitted": True, "reasons": ["x"]},
                    {"admitted": False}, {"enrolment": "refused"}, {"enforcement": "FAILED"}, {"colour": "red"},
                    {"quote": {"challenge": "00" * 32}}, {"attestation_result": {"status": "fine"}}):
            self.assertNotEqual(validate(state, {"updated": 1, "verdicts": [dict(v, **bad)]}), [], bad)
        man = load(VECTORS, "packs", "pq-quote", "manifest.json")
        for edit in (lambda m: m["files"].update({"../x": "00" * 32}), lambda m: m.pop("policy_id"),
                     lambda m: m["files"].pop("evidence.token"), lambda m: m.update(signed=True),
                     lambda m: m["result"].update(status="good"), lambda m: m["key_thumbprints"].update(other="00" * 32)):
            m = copy.deepcopy(man)
            edit(m)
            self.assertNotEqual(validate(schema("manifest"), m), [])
        rec = load(VECTORS, "policy", "endorsements", "pq-quote.json")
        for edit in (lambda r: r["body"].update(colour="red"), lambda r: r["body"].pop("issued"),
                     lambda r: r["body"].update(device_state="production"), lambda r: r.update(sig=r["sig"][:-2]),
                     lambda r: r["body"]["measurements"].append({"type": "X", "measurement_value": "AB"})):
            r = copy.deepcopy(rec)
            edit(r)
            self.assertNotEqual(validate(schema("endorsement"), r), [])
            with self.assertRaises(endorsement.Refused):
                endorsement.loads(json.dumps(r).encode())


# ---- the committed vectors ---------------------------------------------------------------------------------------------

@NEEDS_LIBS
class Vectors(unittest.TestCase):
    d = VECTORS

    @classmethod
    def setUpClass(cls):
        cls.gen = generator()

    def thumb(self, role):
        return cose.key_thumbprint(self.gen.mldsa_keys(role)[0]).hex()

    def test_every_pack_verifies_with_the_readers_own_keys_and_matches_its_schema(self):
        packs = sorted(os.listdir(os.path.join(self.d, "packs")))
        self.assertEqual(packs, sorted(EXPECTED))
        state = {v["endpoint"]: v for v in load(self.d, "fleet-state.json")["verdicts"]}
        for name in packs:
            pack = os.path.join(self.d, "packs", name)
            man = load(pack, "manifest.json")
            self.assertEqual(validate(schema("manifest"), man), [], name)
            trust = ["--verifier-key", self.thumb("verifier")]
            if "keys/device.cosekey" in man["files"]:
                trust += ["--device-key", self.thumb("device/" + name)]
            if "keys/endorser.cosekey" in man["files"]:
                trust += ["--endorser-key", self.thumb("endorser")]
            rc, rep = checker(EVIDENCE_CHECKER, "pack", pack, *trust)
            self.assertEqual((rc, rep["verified"]), (0, True), (name, rep))
            status, admitted, label, enrolment = EXPECTED[name]
            res = rep["attestation_result"]
            self.assertEqual((res["status"], res["admitted"]), (status, admitted), name)
            self.assertEqual(res["verifier_claims"].get("aegis.trust"), label, name)
            self.assertEqual(res["verifier_claims"].get("aegis.enrolment"), enrolment, name)
            self.assertEqual((man["result"]["status"], state[name]["attestation_result"]["status"]), (status, status))
            self.assertEqual(state[name].get("trust"), label, name)
            self.assertEqual(state[name]["attestation_result"]["sha256"], man["files"]["attestation-result.cbor"])

    def test_the_state_file_policy_records_and_signers_match_their_schemas(self):
        self.assertEqual(validate(schema("fleet-state"), load(self.d, "fleet-state.json")), [])
        policy = load(self.d, "policy", "fleet.json")
        self.assertEqual(validate(schema("policy"), policy), [])
        self.assertEqual([fleet.policy_errors(fleet.effective_entry(policy, e)) for e in policy["endpoints"]],
                         [[]] * len(policy["endpoints"]))
        self.assertEqual({e.get("kind", "psa") for e in policy["endpoints"]}, set(fleet.KNOWN_KINDS))
        for path in (("policy", "endorsements", "pq-quote.json"), ("packs", "pq-quote", "endorsement.json")):
            self.assertEqual(validate(schema("endorsement"), load(self.d, *path)), [], path)
        self.assertEqual(validate(schema("policy-signers"), load(self.d, "policy", "policy-signers.json")), [])
        for p in ("fleet.example.json", "fleet.pc.example.json"):
            self.assertEqual(validate(schema("policy"), load(ROOT, "gateway", "policy", p)), [], p)

    def test_every_endorsement_is_accepted_for_its_entry_at_the_vectors_time(self):
        base = os.path.join(self.d, "policy")
        policy = load(base, "fleet.json")
        endorsed = [e for e in policy["endpoints"] if e.get("endorsement")]
        self.assertEqual(len(endorsed), 3)
        forms = set()
        for e in endorsed:
            _, body = fleet.device_key(fleet.effective_entry(policy, e), base, policy["endorsers"], now=self.gen.T0)
            self.assertEqual(body["record_sha256"], e["endorsement_sha256"])
            with open(fleet.endorsement_file(e, base), "rb") as f:
                forms.add(endorsement.loads(f.read())["format"])
        self.assertEqual(forms, {endorsement.FORMAT, endorsement.FORMAT_COSE})

    def test_the_keys_are_the_ones_their_published_seeds_make(self):
        from cryptography.hazmat.primitives import serialization
        base = os.path.join(self.d, "policy")
        for e in load(base, "fleet.json")["endpoints"]:
            if "pq_pub_file" in e:
                with open(os.path.join(base, e["pq_pub_file"])) as f:
                    self.assertEqual(f.read().strip(), self.gen.mldsa_keys("device/" + e["name"])[0].hex())
        with open(os.path.join(base, "keys", "tfm-iak.pub.pem"), "rb") as f:
            self.assertEqual(f.read(), self.gen.p256_key("iak/tfm").public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        with open(os.path.join(self.d, "audit", "verifier.mldsa65.pub")) as f:
            self.assertEqual(f.read().strip(), self.gen.mldsa_keys("verifier")[0].hex())
        signers = load(base, "policy-signers.json")["signers"]
        self.assertEqual([s["pk"] for s in signers], [self.gen.mldsa_keys("policy-signer")[0].hex()])
        with open(os.path.join(self.d, "README.md")) as f:
            readme = f.read()
        for role in ("verifier", "endorser", "policy-signer"):
            self.assertIn(self.thumb(role), readme)

    def test_the_audit_log_and_its_anchor_verify(self):
        a = os.path.join(self.d, "audit")
        rep = load(a, "audit-report.json")
        at = str(rep["logs"][-1]["to"])
        rc, out = checker(AUDIT_CHECKER, "log", a, "--key", os.path.join(a, "verifier.mldsa65.pub"),
                          "--anchor", os.path.join(a, "anchor.cbor"), "--at", at, "--entries")
        self.assertEqual((rc, out["verified"]), (0, True), out)
        self.assertEqual(out["logs"][0]["last_batch"], 4)
        self.assertEqual(out["anchors"][0]["batch"], 2)
        # a time after the promised next batch: stale, as a log whose verifier stopped
        rc, out = checker(AUDIT_CHECKER, "log", a, "--key", os.path.join(a, "verifier.mldsa65.pub"),
                          "--at", str(rep["logs"][-1]["due"] + 1))
        self.assertEqual(rc, 1, out)
        # the log names what the packs hold: each first decision names its result's hash
        events = [e for e in rep["entries"] if e["event"] in ("admit", "refuse")]
        self.assertEqual([e["event"] for e in events][-2:], ["refuse", "admit"])        # the Linux host went away
        self.assertEqual(events[-2]["subject"], "linux-host")
        first = {e["subject"]: e for e in reversed(events[:len(EXPECTED)])}
        for name in EXPECTED:
            man = load(self.d, "packs", name, "manifest.json")
            self.assertEqual(first[name]["details"]["result_sha256"], man["files"]["attestation-result.cbor"], name)
            self.assertEqual(first[name]["event"], "admit" if EXPECTED[name][1] else "refuse")

    def test_the_signed_policy_verifies_and_holds_the_policy(self):
        base = os.path.join(self.d, "policy")
        out = os.path.join(tempfile.mkdtemp(), "policy.json")
        rc, rep = checker(AUDIT_CHECKER, "policy", os.path.join(base, "fleet.cose"), "--key",
                          os.path.join(base, "policy-signers.json"), "--audience", self.gen.FLEET, "--extract", out)
        self.assertEqual((rc, rep["verified"]), (0, True), rep)
        with open(out, "rb") as f, open(os.path.join(base, "fleet.json"), "rb") as g:
            self.assertEqual(f.read(), g.read())
        with open(os.path.join(self.d, "packs", self.gen.WITH_POLICY, "policy.json"), "rb") as f, \
                open(os.path.join(base, "fleet.json"), "rb") as g:
            self.assertEqual(f.read(), g.read())
        self.assertEqual(rep["policy_id"], load(self.d, "packs", "pq-eat", "manifest.json")["policy_id"])
        rc, rep = checker(AUDIT_CHECKER, "policy", os.path.join(base, "fleet.cose"), "--key",
                          os.path.join(base, "policy-signers.json"), "--audience", "another-fleet")
        self.assertEqual(rc, 1, rep)


# ---- a fresh run -------------------------------------------------------------------------------------------------------

HEX = re.compile(r"\A[0-9a-f]{64,}\Z")


def masked(v):
    """JSON with the values a signature changes put aside: long hex strings and ni names."""
    if isinstance(v, str):
        return "<hex>" if HEX.match(v) else "<ni>" if v.startswith("ni:///") else v
    if isinstance(v, dict):
        return {k: masked(x) for k, x in v.items()}
    if isinstance(v, list):
        return [masked(x) for x in v]
    return v


def tree(d):
    return sorted(os.path.relpath(os.path.join(p, n), d) for p, _, names in os.walk(d) for n in names)


@NEEDS_LIBS
class Regenerate(Vectors):
    """Everything Vectors checks, on a fresh run of the generator; and that the run makes the committed files."""

    @classmethod
    def setUpClass(cls):
        cls.gen = generator()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.d = os.path.join(cls.tmp.name, "aegis-1.2")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            cls.gen.main([cls.d])

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_the_same_files_and_structure_as_the_committed_ones(self):
        self.assertEqual(tree(self.d), tree(VECTORS))
        for rel in tree(VECTORS):
            a, b = os.path.join(VECTORS, rel), os.path.join(self.d, rel)
            with open(a, "rb") as f, open(b, "rb") as g:
                old, new = f.read(), g.read()
            if rel.endswith(".json"):
                self.assertEqual(masked(json.loads(new)), masked(json.loads(old)), rel)
            elif rel.endswith(("README.md", ".pub", ".pem", ".generated-by-gen_golden_vectors")) or \
                    rel.endswith("evidence.token"):
                self.assertEqual(new, old, rel)         # no signature in them, or a deterministic one (ES256)
            elif rel.endswith("evidence.cbor"):
                self.assertEqual(cose.parse(new).payload, cose.parse(old).payload, rel)
            elif rel.endswith(".cosekey"):
                self.assertEqual(new, old, rel)
            elif rel.endswith(".sig"):
                self.assertEqual(len(new), len(old), rel)       # a detached ML-DSA-65 signature: 3309 bytes
            else:
                # a signature of its own, made again: the same kind of object, not the same bytes
                self.assertEqual(new[:1], old[:1], rel)
        self.assertNotEqual(open(os.path.join(self.d, "audit", "anchor.cbor"), "rb").read(),
                            open(os.path.join(VECTORS, "audit", "anchor.cbor"), "rb").read())

    def test_the_committed_audit_log_is_one_run_of_the_generator(self):
        a, b = (load(d, "audit", "audit-report.json") for d in (VECTORS, self.d))
        self.assertEqual([(e["event"], e["subject"], e["batch"], e["time"]) for e in a["entries"]],
                         [(e["event"], e["subject"], e["batch"], e["time"]) for e in b["entries"]])
        self.assertEqual(cbor.loads(cose.parse(open(os.path.join(VECTORS, "audit", "anchor.cbor"), "rb").read())
                                    .payload)[3], 2)


if __name__ == "__main__":
    unittest.main()

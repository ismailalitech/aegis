# SPDX-License-Identifier: Apache-2.0
"""Standard evidence (docs/evidence-format.md): EAT in COSE_Sign1 with ML-DSA-65, the verifier's signed attestation
result, the COSE form of the endorsement record, and the evidence pack.

Simulated endpoints (no hardware). The claim numbers and byte strings in this file are written out as the document
gives them, not taken from common/eat.py, so that a changed constant there fails here.

  envelope      one object, one byte string; what a hostile sender would vary is refused (another algorithm, a header
                outside the signature, an unknown or critical header, another key, a detached payload, a second
                encoding of the same object); a signature made for an older Aegis message is not one for a COSE object
  evidence      the profile's claims and nothing else; the device, the nonce, the measurements
  verifier      "evidence_format": "eat-cose-v1" in a policy entry: admitted, the same policy rules, no fallback to
                the older format in either direction; the older formats still accepted where the entry does not ask
  results       every verdict gets a signed result whose status is never better than the verdict
  endorsement   the same record as an EAT in a COSE_Sign1: same body, same rules, enrolment and attestation with it
  pack          `fleet.py export-evidence` and tools/verify_evidence.py, which shares no code with the repository
"""
import ast
import contextlib
import hashlib
import io
import json
import os
import random
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

os.environ.setdefault("TSS2_LOG", "all+NONE")
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for p in ("common", "gateway/aegisd", "provision", "tests/host"):
    sys.path.insert(0, os.path.join(ROOT, p))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

import aegis_provision as prov  # noqa: E402
import cbor  # noqa: E402
import cose  # noqa: E402
import eat  # noqa: E402
import endorsement  # noqa: E402
import fleet  # noqa: E402
import mldsa  # noqa: E402
import psa_token  # noqa: E402
import test_fleet as tf  # noqa: E402

CHECKER = os.path.join(ROOT, "tools", "verify_evidence.py")
VERIFY = psa_token.verify_with_cryptography
PK, SK = tf.PQ_KEYS[0]
PK2, SK2 = tf.PQ_KEYS[1]
MEAS = "ab" * 32
PROFILE = "tag:github.com,2026:ismailalitech/aegis/evidence/v1"
PLATFORM = "aegis-rw612-tfm-v1"
TYP = "application/eat+cwt"
# deterministic CBOR of {1: 7 (AKP), 3: -49 (ML-DSA-65), -1: bstr of 1952}: the COSE Key Thumbprint's input
THUMB_HEAD = bytes.fromhex("a30107033830205907a0")


def thumb(pk):
    return hashlib.sha256(THUMB_HEAD + pk).digest()


def protected(pk, alg=-49, typ=TYP, **more):
    hdr = {1: alg, 4: thumb(pk), 16: typ}
    hdr.update({int(k[1:]): v for k, v in more.items()})
    return cbor.dumps(hdr, sort=True)


def sign1(sk, prot, payload, unprotected=None, tag=18, sig=None):
    """A COSE_Sign1 built by hand, so that each part can be wrong on purpose."""
    tbs = cbor.dumps(["Signature1", prot, b"", payload])
    sig = mldsa.sign_raw(sk, tbs) if sig is None else sig
    body = [prot, unprotected or {}, payload, sig]
    return cbor.dumps(cbor.Tag(tag, body) if tag is not None else body)


def component(name, digest_hex, version=None, signer=None):
    mc = {1: [name, [version]] if version else [name], 2: [1, bytes.fromhex(digest_hex)]}
    if signer:
        mc[3] = [bytes.fromhex(signer)]
    return [295, cbor.dumps(mc, sort=True)]


def evidence_claims(challenge, pk=PK, platform=PLATFORM, comps=None):
    return {10: challenge, 256: b"\x01" + hashlib.sha256(pk).digest(), 265: PROFILE, 275: 1, -82400: platform,
            273: [component("SPE", MEAS, "1.0")] if comps is None else comps}


class EatDevice:
    """A device with standard evidence: PQKEY, PQEAT (an EAT in a COSE_Sign1) and, as firmware with the option does,
    PQCHAL (the older claims and a detached signature). edit(claims) changes the EAT's claims before they are signed;
    answer(line) replaces a whole reply. kind aegis-pq: nest(challenge) gives the platform's token to nest."""

    def __init__(self, pk=PK, sk=SK, platform=PLATFORM, edit=None, answer=None, nest=None):
        self.pk, self.sk, self.platform, self.edit, self.answer, self.nest = pk, sk, platform, edit, answer, nest
        self.asked, self.last = [], None
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self.loop, daemon=True).start()

    def evidence(self, challenge):
        claims = evidence_claims(challenge, self.pk, self.platform)
        if self.nest:
            del claims[273], claims[-82400]
            claims[266] = {"platform": b"\xd8\x3d" + self.nest(challenge)}
        if self.edit:
            self.edit(claims)
        return sign1(self.sk, protected(self.pk), cbor.dumps(claims, sort=True))

    def reply(self, line):
        if self.answer:
            r = self.answer(line)
            if r is not None:
                return r
        if line == "PQKEY":
            return b"PQKEY %d %s END" % (len(self.pk), self.pk.hex().encode())
        word, ch = line.split()
        if word == "PQEAT":
            self.last = ev = self.evidence(bytes.fromhex(ch))
            return b"PQEAT %d %s END" % (len(ev), ev.hex().encode())
        if word == "PQCHAL":
            tok = cbor.dumps({265: self.platform, 10: bytes.fromhex(ch), 256: b"\x02" + hashlib.sha256(self.pk).digest(),
                              2399: [{1: "SPE", 2: bytes.fromhex(MEAS)}]})
            sig = mldsa.sign(self.sk, b"aegis-endpoint-quote-v1", tok)
            return b"PQTOKEN %d %s %d %s END" % (len(tok), tok.hex().encode(), len(sig), sig.hex().encode())
        return b"ERR unknown"

    def loop(self):
        while True:
            c, _ = self.srv.accept()
            with c:
                try:
                    buf = b""
                    while b"\n" not in buf:
                        chunk = c.recv(65536)
                        if not chunk:
                            break
                        buf += chunk
                    line = buf.split(b"\n")[0].decode().strip()
                    self.asked.append(line.split()[0] if line else "")
                    c.sendall(self.reply(line) + b"\r\n")
                except Exception:  # noqa: BLE001 - a test's hostile answer function; the verifier sees a closed socket
                    pass


def run(main, argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        rc = main(argv)
    return rc, out.getvalue()


def checker(*args):
    """tools/verify_evidence.py as a program of its own (-I: nothing of this repository on its path)."""
    r = subprocess.run([sys.executable, "-I", CHECKER, *args], capture_output=True, text=True, cwd=tempfile.gettempdir())
    try:
        return r.returncode, json.loads(r.stdout)
    except ValueError:
        return r.returncode, {"verified": False, "reason": r.stdout + r.stderr}


def have_checker_libs():
    try:
        import cbor2  # noqa: F401
        import pycose  # noqa: F401
        from cryptography.hazmat.primitives.asymmetric import mldsa as _  # noqa: F401
    except Exception:  # noqa: BLE001
        return False
    return True


NEEDS_LIBS = unittest.skipUnless(have_checker_libs(), "needs pycose, cbor2 and cryptography with ML-DSA")


class Envelope(unittest.TestCase):
    def setUp(self):
        self.payload = cbor.dumps(evidence_claims(b"\x07" * 32), sort=True)

    def refused(self, data, text, pk=PK, **kw):
        with self.assertRaises(cose.Refused) as c:
            cose.verify1(data, pk, **kw)
        self.assertIn(text, str(c.exception))

    def test_the_object_is_the_documented_bytes(self):
        data = cose.sign1(SK, PK, self.payload)
        prot = bytes.fromhex("a3013830045820") + thumb(PK) + bytes.fromhex("1073") + TYP.encode()
        self.assertEqual(len(prot), 60)
        self.assertLess(len(self.payload), 256)
        head = bytes.fromhex("d284583c") + prot + bytes.fromhex("a058") + bytes([len(self.payload)]) \
            + self.payload + bytes.fromhex("590ced")
        self.assertEqual(data[:len(head)], head)
        self.assertEqual(len(data), len(head) + 3309)
        s = cose.verify1(data, PK)
        self.assertEqual((s.payload, s.kid, s.typ), (self.payload, thumb(PK), TYP))
        self.assertEqual(s.tbs, bytes.fromhex("846a") + b"Signature1" + bytes.fromhex("583c") + prot + b"\x40"
                         + data[len(prot) + 5:len(head) - 3])
        self.assertTrue(mldsa.verify_raw(PK, s.tbs, data[-3309:]))
        self.assertEqual(cose.key_thumbprint(PK), thumb(PK))
        # the same object made by hand, and both backends of the signature where there are two
        self.assertEqual(cose.verify1(sign1(SK, protected(PK), self.payload), PK).payload, self.payload)

    def test_a_cose_key_round_trips_and_names_itself(self):
        key = cose.cose_key(PK)
        self.assertEqual(key, {1: 7, 2: thumb(PK), 3: -49, -1: PK})
        self.assertEqual(cose.key_from_cose(key), PK)
        for bad in (dict(key, **{"x": 1}), {**key, 1: 2}, {**key, 3: -48}, {**key, 2: thumb(PK2)}, {**key, -1: PK[:-1]},
                    {k: v for k, v in key.items() if k != 2}, [key], None):
            with self.assertRaises(cose.Refused):
                cose.key_from_cose(bad)

    def test_another_key_or_an_altered_object_is_refused(self):
        data = cose.sign1(SK, PK, self.payload)
        self.refused(data, "is not the expected key", pk=PK2)
        # the other key's name on this key's signature
        self.refused(sign1(SK, protected(PK2), self.payload), "signature does not verify", pk=PK2)
        for at in (70, len(data) - 3400, len(data) - 1):        # payload, payload, signature
            bad = bytearray(data)
            bad[at] ^= 1
            self.refused(bytes(bad), "signature does not verify")
        bad = bytearray(data)
        bad[12] ^= 1                                            # the kid
        self.refused(bytes(bad), "is not the expected key")
        self.refused(data, "typ is", typ="application/cwt")

    def test_no_other_algorithm_is_ever_tried(self):
        for alg in (-48, -50, -7, -8, -35, 0, "ML-DSA-65", None, True):
            self.refused(sign1(SK, protected(PK, alg=alg), self.payload), "algorithm is not ML-DSA-65")
        hdr = cbor.dumps({4: thumb(PK), 16: TYP}, sort=True)
        self.refused(sign1(SK, hdr, self.payload), "algorithm is not ML-DSA-65")
        # the right algorithm outside the signature does not make up for it, and is itself refused
        self.refused(sign1(SK, hdr, self.payload, unprotected={1: -49}), "unprotected header is not empty")

    def test_nothing_outside_the_signature_is_read(self):
        for extra in ({4: thumb(PK2)}, {1: -7}, {"x": 1}, {16: TYP}):
            self.refused(sign1(SK, protected(PK), self.payload, unprotected=extra), "unprotected header is not empty")

    def test_unknown_and_critical_headers_are_refused(self):
        self.refused(sign1(SK, protected(PK, _2=[99], _99=1), self.payload), "critical header")
        self.refused(sign1(SK, protected(PK, _33=[b"x"]), self.payload), "does not know")
        self.refused(sign1(SK, protected(PK, _3=61), self.payload), "does not know")
        self.refused(sign1(SK, cbor.dumps({1: -49, 16: TYP}, sort=True), self.payload), "no kid")
        self.refused(sign1(SK, cbor.dumps({1: -49, 4: thumb(PK)[:8], 16: TYP}, sort=True), self.payload), "no kid")
        self.refused(sign1(SK, cbor.dumps({1: -49, 4: thumb(PK)}, sort=True), self.payload), "no typ")
        self.refused(sign1(SK, cbor.dumps([1, -49]), self.payload), "not a map")

    def test_one_object_has_one_encoding(self):
        prot = protected(PK)
        good = sign1(SK, prot, self.payload)
        sig = good[-3309:]
        # the header's map in another order: a valid signature over it, and still refused
        swapped = cbor.dumps({16: TYP, 4: thumb(PK), 1: -49})
        self.assertNotEqual(swapped, prot)
        self.refused(sign1(SK, swapped, self.payload), "protected header is not in deterministic encoding")
        # a length written longer than it needs to be: the same items, other bytes
        self.assertEqual(good[:4], bytes.fromhex("d284583c"))
        longer = good[:2] + bytes.fromhex("59003c") + good[4:]
        self.assertEqual(cbor.loads(longer).value, cbor.loads(good).value)
        self.refused(longer, "not in deterministic encoding")
        self.refused(good + b"\x00", "not a COSE_Sign1")
        self.refused(good[:-1], "not a COSE_Sign1")
        self.refused(sign1(SK, prot, self.payload, tag=None), "not a tagged COSE_Sign1")
        self.refused(sign1(SK, prot, self.payload, tag=98), "not a tagged COSE_Sign1")
        self.refused(cbor.dumps(cbor.Tag(18, [prot, {}, None, sig])), "no attached payload")
        self.refused(cbor.dumps(cbor.Tag(18, [prot, {}, self.payload, sig, b""])), "not an array of 4")
        self.refused(cbor.dumps(cbor.Tag(18, [prot, {}, self.payload, sig[:-1]])), "not an ML-DSA-65 signature")
        self.refused(cbor.dumps(cbor.Tag(18, [b"", {}, self.payload, sig])), "protected header")
        self.refused(b"", "no COSE object")
        self.refused(sign1(SK, prot, b"\x00" * 20000), "larger than")
        for junk in (b"\xd2", b"\xd2\x84", b"{}", b"\xff" * 40, b"\xd2" + b"\x9b" + b"\xff" * 8):
            self.refused(junk, "")

    def test_a_signature_for_an_older_message_is_not_one_for_a_cose_object(self):
        """The same key signs label || 0x00 || message elsewhere (quotes, KEM keys, credentials, endorsements). Every
        label begins "aegis-"; a Sig_structure begins 84 6a "Signature1"."""
        prot = protected(PK)
        tbs = cbor.dumps(["Signature1", prot, b"", self.payload])
        self.assertEqual(tbs[:12], bytes.fromhex("846a") + b"Signature1")
        for label in (b"aegis-endpoint-quote-v1", b"aegis-kem-init-v2", b"aegis-credential-v1", b"aegis-endorsement-v1"):
            self.assertNotEqual(tbs[:len(label) + 1], label + b"\x00")
            old = mldsa.sign(SK, label, self.payload)
            self.refused(sign1(SK, prot, self.payload, sig=old), "signature does not verify")
            self.refused(sign1(SK, prot, label + b"\x00" + self.payload, sig=old), "signature does not verify")
            # and the other way round: a COSE signature is not a labelled one over anything a verifier would build
            new = mldsa.sign_raw(SK, tbs)
            self.assertFalse(mldsa.verify(PK, label, self.payload, new))
            self.assertFalse(mldsa.verify(PK, label, tbs, new))

    def test_parse_reads_without_a_key_and_says_so(self):
        s = cose.parse(cose.sign1(SK, PK, self.payload))
        self.assertEqual((s.kid, s.typ), (thumb(PK), TYP))
        with self.assertRaises(cose.Refused):
            cose.parse(b"\x00")


class Evidence(unittest.TestCase):
    CH = b"\x21" * 32

    def read(self, claims, pk=PK):
        return eat.read_evidence(cbor.dumps(claims, sort=True), pk)

    def refused(self, claims, text, pk=PK):
        with self.assertRaises(eat.Refused) as c:
            self.read(claims, pk)
        self.assertIn(text, str(c.exception))

    def test_the_documented_claims_are_read(self):
        c = evidence_claims(self.CH, comps=[component("SPE", MEAS, "1.2.3", "cd" * 32), component("NSPE", "ef" * 32)])
        ev = self.read(c)
        self.assertEqual(ev["nonce"], self.CH)
        self.assertEqual(ev["ueid"], b"\x01" + hashlib.sha256(PK).digest())
        self.assertEqual(ev["platform"], PLATFORM)
        self.assertEqual(ev["components"], [
            {"measurement_type": "SPE", "version": "1.2.3", "measurement_value": bytes.fromhex(MEAS),
             "signer_id": bytes.fromhex("cd" * 32)},
            {"measurement_type": "NSPE", "measurement_value": bytes.fromhex("ef" * 32)}])
        self.assertIsNone(ev["platform_token"])
        # what the module's own encoder makes is the same bytes
        self.assertEqual(eat.evidence_payload(self.CH, PK, [("SPE", bytes.fromhex(MEAS), "1.0")], PLATFORM),
                         cbor.dumps(evidence_claims(self.CH), sort=True))
        self.assertEqual(self.read({**c, 263: 2})["dbgstat"], 2)

    def test_a_nested_platform_token_is_handed_on_as_it_is(self):
        tok = tf.make_token(ec.generate_private_key(ec.SECP256R1()), self.CH)
        c = evidence_claims(self.CH)
        del c[273], c[-82400]
        c[266] = {"platform": b"\xd8\x3d" + tok}
        ev = self.read(c)
        self.assertEqual((ev["platform_token"], ev["components"]), (tok, None))
        self.assertEqual(eat.evidence_payload(self.CH, PK, platform_token=tok), cbor.dumps(c, sort=True))
        self.refused({**c, 266: {"platform": tok}}, "not tagged as a CWT")
        self.refused({**c, 266: {"other": b"\xd8\x3d" + tok}}, "submods is not")
        self.refused({**c, 266: {"platform": b"\xd8\x3d" + tok, "more": b""}}, "submods is not")
        self.refused({**c, 273: [component("SPE", MEAS)]}, "not both")
        self.refused({**c, -82400: PLATFORM}, "goes with measurements")

    def test_claims_outside_the_profile_are_refused(self):
        c = evidence_claims(self.CH)
        self.refused({**c, 1: "issuer"}, "does not know")
        self.refused({**c, -82401: "x"}, "does not know")
        self.refused({**c, "note": 1}, "does not know")
        for k in (10, 256, 265, 275):
            self.refused({a: b for a, b in c.items() if a != k}, "lacks claim %d" % k)
        self.refused({a: b for a, b in c.items() if a != 273}, "measurements or a platform token")
        self.refused({a: b for a, b in c.items() if a != -82400}, "goes with measurements")
        self.refused({**c, 265: "tag:github.com,2026:ismailalitech/aegis/evidence/v2"}, "eat_profile")
        self.refused({**c, 265: "tag:psacertified.org,2023:psa#tfm"}, "eat_profile")
        self.refused({**c, 10: self.CH[:31]}, "eat_nonce")
        self.refused({**c, 10: self.CH.hex()}, "eat_nonce")
        self.refused({**c, 275: 2}, "intuse")
        self.refused({**c, 275: True}, "intuse")
        self.refused({**c, 263: 5}, "dbgstat")
        self.refused({**c, -82400: ""}, "platform profile")
        self.refused({**c, -82400: 7}, "platform profile")

    def test_the_ueid_is_the_signing_keys(self):
        c = evidence_claims(self.CH)
        self.refused(c, "ueid", pk=PK2)
        self.refused({**c, 256: b"\x02" + hashlib.sha256(PK).digest()}, "ueid")
        self.refused({**c, 256: hashlib.sha256(PK).digest()}, "ueid")

    def test_measured_components_have_one_form(self):
        c = evidence_claims(self.CH)

        def comps(*entries):
            return {**c, 273: list(entries)}
        mc = {1: ["SPE"], 2: [1, bytes.fromhex(MEAS)]}
        enc = lambda m: [295, cbor.dumps(m, sort=True)]   # noqa: E731
        self.assertEqual(self.read(comps(enc(mc)))["components"][0]["measurement_type"], "SPE")
        self.refused(comps(), "1 to 16")
        self.refused({**c, 273: {}}, "1 to 16")
        self.refused(comps(*[component("C%d" % i, MEAS) for i in range(17)]), "1 to 16")
        self.assertEqual(len(self.read(comps(*[component("C%d" % i, MEAS) for i in range(16)]))["components"]), 16)
        self.refused(comps(component("SPE", MEAS), component("SPE", "00" * 32)), "two measured components of one name")
        self.refused(comps([294, cbor.dumps(mc, sort=True)]), "[295, bstr]")
        self.refused(comps([295, mc]), "[295, bstr]")
        self.refused(comps([295, cbor.dumps(mc, sort=True), 1]), "[295, bstr]")
        self.refused(comps([295, cbor.dumps({2: mc[2], 1: mc[1]})]), "deterministic")
        self.refused(comps(enc({**mc, 4: b"\x00" * 8})), "not {id")
        self.refused(comps(enc({**mc, 5: [1, b"raw"]})), "not {id")
        self.refused(comps(enc({1: mc[1]})), "not {id")
        self.refused(comps(enc({**mc, 1: "SPE"})), "id is not")
        self.refused(comps(enc({**mc, 1: ["SPE", "1.0"]})), "version is not")
        self.refused(comps(enc({**mc, 1: ["SPE", ["1.0", 1]]})), "version is not")
        self.refused(comps(enc({**mc, 1: [""]})), "id is not")
        self.refused(comps(enc({**mc, 2: [2, bytes(48)]})), "digest is not")
        self.refused(comps(enc({**mc, 2: [1, bytes(31)]})), "digest is not")
        self.refused(comps(enc({**mc, 2: ["sha-256", bytes(32)]})), "digest is not")
        self.refused(comps(enc({**mc, 3: []})), "authorities")
        self.refused(comps(enc({**mc, 3: [b"a", b"b"]})), "authorities")
        self.refused(comps(enc({**mc, 3: ["text"]})), "authorities")

    def test_claims_have_one_encoding_and_hostile_ones_only_refuse(self):
        c = evidence_claims(self.CH)
        with self.assertRaises(eat.Refused):
            eat.read_evidence(cbor.dumps(dict(reversed(list(c.items())))), PK)
        for junk in (b"", b"\xa0", b"\x80", b"\xff", cbor.dumps([c]), cbor.dumps(c, sort=True) + b"\x00",
                     cbor.dumps({10: [[[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]]]})):
            with self.assertRaises(eat.Refused):
                eat.read_evidence(junk, PK)


class Bench(unittest.TestCase):
    """A verifier's policy directory and state (with an identity, so results are signed), one endorser."""

    @classmethod
    def setUpClass(cls):
        cls.iak = ec.generate_private_key(ec.SECP256R1())
        cls.estate = tempfile.mkdtemp()
        prov.init(cls.estate, "bench", key_store="software")
        cls.endorser = prov.Endorser(cls.estate)
        cls.vpk, cls.vsk = mldsa.keypair()

    def setUp(self):
        self.d, self.out, self.state = tempfile.mkdtemp(), tempfile.mkdtemp(), tempfile.mkdtemp()
        with open(os.path.join(self.state, "identity.json"), "w") as f:
            json.dump({"body": {"v": 1, "type": "identity", "pk": self.vpk.hex()}}, f)
        with open(os.path.join(self.state, "identity.sk"), "wb") as f:
            f.write(self.vsk)
        with open(os.path.join(self.d, "iak.pem"), "wb") as f:
            f.write(self.iak.public_key().public_bytes(serialization.Encoding.PEM,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo))
        os.mkdir(os.path.join(self.d, "keys"))
        run(prov.main, ["export", os.path.join(self.d, "endorsers"), "--state", self.estate])
        self.policy = {"timeout_s": 5, "endorsers": [self.endorser.policy_entry()], "endpoints": [],
                       "attestation_results": True}

    def add(self, name, dev, pin=True, **kw):
        e = {"name": name, "kind": "aegis-device", "host": "127.0.0.1", "port": dev.port,
             "profile": getattr(dev, "platform", None),
             "pq_pub_file": "keys/%s.pub" % name, "allowed": [{"type": "SPE", "measurement_value": MEAS}],
             "evidence_format": "eat-cose-v1"}
        e.update(kw)
        e = {k: v for k, v in e.items() if v is not None}
        if pin:
            with open(os.path.join(self.d, e["pq_pub_file"]), "w") as f:
                f.write(dev.pk.hex() + "\n")
        self.policy["endpoints"].append(e)
        self.save()
        return e

    def add_pq(self, name, dev, **kw):
        return self.add(name, dev, kind="aegis-pq", profile=None, iak_pub_pem="iak.pem",
                        allowed=[{"type": "SPE", "measurement_value": tf.GOOD_S, "signer_id": tf.SIGNER},
                                 {"type": "NSPE", "measurement_value": tf.GOOD_NS, "signer_id": tf.SIGNER}], **kw)

    def save(self):
        self.pol = os.path.join(self.d, "fleet.json")
        with open(self.pol, "w") as f:
            json.dump(self.policy, f, indent=1)
        with open(self.pol, "rb") as f:
            self.policy_bytes = f.read()

    def attest(self, e, facts=None):
        return fleet.attest(e, VERIFY, self.d, 5, self.policy.get("endorsers"), facts)

    def cycle(self):
        return fleet.run_once(self.policy, self.d, VERIFY, credentials=False, state=self.state,
                              policy_bytes=self.policy_bytes)

    def result(self, name):
        with open(os.path.join(self.state, "attestation", name, "result.cbor"), "rb") as f:
            return f.read()

    def enrol(self, e, **kw):
        res = prov.endorse(self.endorser, e, self.d, self.out, ecdsa_verify=VERIFY, **kw)
        self.assertTrue(res["endorsed"], res)
        e["endorsement"] = "required"
        self.save()
        fleet.install_endorsement(self.policy, self.d, res["record"], policy_path=self.pol)
        self.save()
        return res

    def assertRefused(self, v, text):
        self.assertFalse(v["admitted"], v)
        self.assertTrue(any(text in r for r in v["reasons"]), v["reasons"])


class Verifier(Bench):
    def test_standard_evidence_is_admitted_under_the_same_rules(self):
        dev = EatDevice()
        e = self.add("dev", dev)
        facts = {}
        v = self.attest(e, facts)
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertEqual(dev.asked, ["PQEAT"])
        self.assertEqual((v["evidence_format"], v["trust"], v["pq_signature"]), ("eat-cose-v1", "trustzone", "ML-DSA-65 valid"))
        self.assertEqual(v["measurements"], {"SPE": MEAS})
        self.assertEqual(v["instance_id"], "01" + hashlib.sha256(PK).hexdigest())
        self.assertEqual(v["device_pk_sha256"], hashlib.sha256(PK).hexdigest())
        # T1's token hash: SHA3-256 of the COSE Sig_structure of the evidence
        parts = cbor.loads(dev.last).value
        tbs = cbor.dumps(["Signature1", parts[0], b"", parts[2]])
        self.assertEqual(v["quote"]["token_sha3_256"], hashlib.sha3_256(tbs).hexdigest())
        self.assertEqual(facts["evidence"], dev.last)
        self.assertEqual((facts["stage"], facts["signature"], facts["components_ok"]), ("appraised", True, True))
        # the policy's rules are the older format's: another measurement, another platform profile
        self.assertRefused(self.attest(dict(e, allowed=[{"type": "SPE", "measurement_value": "00" * 32}])), "not allowed")
        self.assertRefused(self.attest(dict(e, profile="aegis-rw612-els-v1")), "policy requires")
        self.assertRefused(self.attest(dict(e, allowed=[{"type": "SPE", "measurement_value": MEAS,
                                                         "signer_id": "cd" * 32}])), "not allowed")

    def test_the_older_format_is_still_accepted_where_the_entry_does_not_ask(self):
        dev = EatDevice()
        e = self.add("dev", dev, evidence_format=None)
        v = self.attest(e)
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertEqual(dev.asked, ["PQCHAL"])
        self.assertNotIn("evidence_format", v)
        # and a classical PSA token (kind psa), as before
        v = fleet.attest({"name": "psa", "host": "127.0.0.1", "port": tf.FakeEndpoint(self.iak).port,
                          "iak_pub_pem": "iak.pem",
                          "allowed": [{"type": "SPE", "measurement_value": tf.GOOD_S, "signer_id": tf.SIGNER},
                                      {"type": "NSPE", "measurement_value": tf.GOOD_NS, "signer_id": tf.SIGNER}]},
                         VERIFY, self.d, 5)
        self.assertTrue(v["admitted"], v["reasons"])

    def test_there_is_no_fallback_between_the_formats(self):
        # firmware without the option: the entry asks for standard evidence and gets none
        old = EatDevice(answer=lambda line: b"ERR unknown" if line.startswith("PQEAT") else None)
        v = self.attest(self.add("old", old))
        self.assertRefused(v, "no EAT evidence")
        self.assertEqual(old.asked, ["PQEAT"])                  # PQCHAL is not tried instead
        # a device that answers the new request with the older reply
        mixed = EatDevice()
        mixed.answer = lambda line: EatDevice.reply(EatDevice(), line.replace("PQEAT", "PQCHAL")) \
            if line.startswith("PQEAT") else None
        self.assertRefused(self.attest(self.add("mixed", mixed)), "no EAT evidence")
        # the older claims inside the new reply: not a COSE_Sign1
        def claims_as_eat(line):
            if line.startswith("PQEAT"):
                tok = cbor.dumps({265: PLATFORM, 10: bytes.fromhex(line.split()[1])})
                return b"PQEAT %d %s END" % (len(tok), tok.hex().encode())
        self.assertRefused(self.attest(self.add("claims", EatDevice(answer=claims_as_eat))), "EAT evidence refused")
        # a length that is not the evidence's
        def short(line):
            if line.startswith("PQEAT"):
                return b"PQEAT 5 %s END" % (b"00" * 6)
        self.assertRefused(self.attest(self.add("short", EatDevice(answer=short))), "length mismatch")

    def test_a_policy_value_the_verifier_does_not_know_is_refused_without_asking(self):
        dev = EatDevice()
        for fmt in ("eat-cose-v2", "EAT-COSE-V1", "", 1, True, ["eat-cose-v1"]):
            v = self.attest(dict(self.add("dev", dev), evidence_format=fmt))
            self.assertRefused(v, "unknown evidence_format")
        self.assertEqual(dev.asked, [])
        v = fleet.attest({"name": "psa", "host": "127.0.0.1", "port": dev.port, "iak_pub_pem": "iak.pem",
                          "allowed": [], "evidence_format": "eat-cose-v1"}, VERIFY, self.d, 5)
        self.assertRefused(v, "needs a post-quantum kind")
        self.assertEqual(dev.asked, [])
        rc, out = run(fleet.main, ["check", self.pol])
        self.assertEqual(rc, 0, out)

    def test_evidence_that_is_not_this_devices_or_this_cycles_is_refused(self):
        e = self.add("a", EatDevice(pk=PK2, sk=SK2), pin=False)
        with open(os.path.join(self.d, e["pq_pub_file"]), "w") as f:
            f.write(PK.hex())
        self.assertRefused(self.attest(e), "is not the expected key")
        # the pinned key's name on another key's signature
        forged = EatDevice()
        forged.sk = SK2
        facts = {}
        self.assertRefused(self.attest(self.add("forged", forged), facts), "signature does not verify")
        self.assertEqual((facts["stage"], facts["signature"]), ("evidence", False))
        # an answer recorded in an earlier cycle
        replay = EatDevice()
        old = replay.evidence(b"\x00" * 32)
        replay.answer = lambda line: b"PQEAT %d %s END" % (len(old), old.hex().encode()) if line.startswith("PQEAT") else None
        self.assertRefused(self.attest(self.add("replay", replay)), "challenge mismatch")

    def test_signed_claims_outside_the_profile_are_refused(self):
        cases = [(lambda c: c.update({1: "x"}), "does not know"),
                 (lambda c: c.pop(-82400), "goes with measurements"),
                 (lambda c: c.update({-82400: "aegis-rw612-els-v1"}), "policy requires"),
                 (lambda c: c.update({273: [component("SPE", "99" * 32)]}), "not allowed"),
                 (lambda c: c.update({273: [component("SPE", MEAS), component("EXTRA", MEAS)]}), "EXTRA not allowed"),
                 (lambda c: c.update({265: "tag:example.com,2026:other"}), "eat_profile"),
                 (lambda c: c.update({256: b"\x01" + bytes(32)}), "ueid"),
                 (lambda c: c.update({266: {"platform": b"\xd8\x3d" + tf.make_token(self.iak, c[10])}}), "not both"),
                 (lambda c: (c.pop(273), c.update({266: {"platform": b"\xd8\x3d" + tf.make_token(self.iak, c[10])}})),
                  "goes with measurements"),
                 (lambda c: (c.pop(273), c.pop(-82400),
                             c.update({266: {"platform": b"\xd8\x3d" + tf.make_token(self.iak, c[10])}})),
                  "the platform's token, not measurements")]
        for i, (edit, text) in enumerate(cases):
            facts = {}
            v = self.attest(self.add("c%d" % i, EatDevice(edit=edit)), facts)
            self.assertRefused(v, text)
            self.assertTrue(facts["signature"])

    def test_a_platform_token_nested_in_the_evidence(self):
        """kind aegis-pq (the STM32H573): TF-M's PSA token inside the EAT, both signatures and both nonces checked."""
        dev = EatDevice(nest=lambda ch: tf.make_token(self.iak, ch))
        e = self.add_pq("stm", dev)
        v = self.attest(e)
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertEqual(v["measurements"], {"SPE": tf.GOOD_S, "NSPE": tf.GOOD_NS})
        self.assertEqual(dev.asked, ["PQEAT"])
        other = ec.generate_private_key(ec.SECP256R1())
        for name, nest, text in (("tampered", lambda ch: tf.make_token(self.iak, ch, ns_meas="99" * 32), "not allowed"),
                                 ("other-iak", lambda ch: tf.make_token(other, ch), "signature invalid"),
                                 ("stale-inner", lambda ch: tf.make_token(self.iak, b"\x00" * 32), "challenge mismatch"),
                                 ("junk", lambda ch: b"\x00" * 40, "")):
            self.assertRefused(self.attest(self.add_pq(name, EatDevice(nest=nest))), text)
        # the outer nonce stale, the inner one fresh
        stale = EatDevice(nest=lambda ch: tf.make_token(self.iak, ch), edit=lambda c: c.update({10: b"\x00" * 32}))
        self.assertRefused(self.attest(self.add_pq("stale-outer", stale)), "challenge mismatch")
        # measurements where the kind has a platform token
        plain = EatDevice()
        self.assertRefused(self.attest(self.add_pq("plain", plain)), "measurements, not the platform's token")


class Results(Bench):
    def read(self, name, **kw):
        return eat.read_ear(self.result(name), self.vpk, **kw)

    def test_every_verdict_gets_a_signed_result(self):
        good, silent = EatDevice(), socket.socket()
        silent.bind(("127.0.0.1", 0))                            # bound, not listening: nothing answers
        self.add("good", good)
        self.add("legacy", EatDevice(), evidence_format=None)
        self.add("tampered", EatDevice(edit=lambda c: c.update({273: [component("SPE", "99" * 32)]})))
        forged = EatDevice()
        forged.sk = SK2
        self.add("forged", forged)
        self.add("silent", good, port=silent.getsockname()[1])
        self.add("unknown-format", good, evidence_format="eat-cose-v9")
        vs = {v["endpoint"]: v for v in self.cycle()}
        self.assertEqual({n: v["admitted"] for n, v in vs.items()},
                         {"good": True, "legacy": True, "tampered": False, "forged": False, "silent": False,
                          "unknown-format": False})
        want = {"good": "warning", "legacy": "warning", "tampered": "contraindicated", "forged": "contraindicated",
                "silent": "incomplete", "unknown-format": "incomplete"}
        for name, status in want.items():
            ar = vs[name]["attestation_result"]
            self.assertNotIn("error", ar)
            r = self.read(name)
            self.assertEqual((ar["status"], r["status"], r["endpoint"], r["admitted"]),
                             (status, status, name, vs[name]["admitted"]), name)
            self.assertEqual(ar["sha256"], hashlib.sha256(self.result(name)).hexdigest())
            self.assertEqual(r["policy_ids"], [eat.policy_id(self.policy_bytes)])
            self.assertEqual(r["verifier_claims"]["aegis.evidence-format"],
                             {"legacy": "aegis-quote-v1"}.get(name, "eat-cose-v1" if name != "unknown-format" else "none"))
            self.assertGreater(r["exp"], r["iat"])
        # trust on first use is a warning about the identity, not about the executables
        r = self.read("good")
        self.assertEqual(r["vector"], {0: -33, 2: 3})
        self.assertEqual(r["nonce"], cbor.loads(cbor.loads(good.last).value[2])[10])
        self.assertEqual(r["verifier_claims"]["aegis.evidence-sha256"], hashlib.sha256(good.last).digest())
        self.assertEqual(r["verifier_claims"]["aegis.quote-sha3-256"].hex(), vs["good"]["quote"]["token_sha3_256"])
        self.assertEqual(r["attester_claims"][256], b"\x01" + hashlib.sha256(PK).digest())
        self.assertEqual(r["attester_claims"][273], [component("SPE", MEAS, "1.0")])
        self.assertEqual(self.read("tampered")["vector"], {0: -33, 2: 33})
        self.assertEqual(self.read("forged")["vector"], {0: 99})
        self.assertEqual(self.read("silent")["vector"], {0: 0})
        self.assertIn("not allowed", " ".join(self.read("tampered")["details"]))
        # the evidence is kept as it was received, and named by the result
        d = os.path.join(self.state, "attestation")
        self.assertEqual(sorted(os.listdir(os.path.join(d, "good"))), ["evidence.cbor", "meta.json", "result.cbor"])
        self.assertEqual(sorted(os.listdir(os.path.join(d, "legacy"))),
                         ["evidence.sig", "evidence.token", "meta.json", "result.cbor"])
        self.assertEqual(sorted(os.listdir(os.path.join(d, "silent"))), ["meta.json", "result.cbor"])
        # the next cycle's files replace these: an endpoint that stops answering keeps no old evidence
        self.policy["endpoints"][0]["port"] = silent.getsockname()[1]
        self.save()
        self.cycle()
        self.assertEqual(sorted(os.listdir(os.path.join(d, "good"))), ["meta.json", "result.cbor"])
        self.assertEqual(self.read("good")["status"], "incomplete")
        silent.close()

    def test_an_endorsed_key_with_measurements_from_the_secure_world_is_affirming(self):
        dev = EatDevice()
        e = self.add("dev", dev)
        self.enrol(e)
        v, = self.cycle()
        self.assertTrue(v["admitted"], v["reasons"])
        r = self.read("dev")
        self.assertEqual((r["status"], r["vector"], r["details"]), ("affirming", {0: 2, 2: 3}, None))
        who = r["endorser_claims"]["bench"]
        self.assertEqual(who["aegis.record-sha256"], v["endorsement"]["record_sha256"])
        self.assertEqual(who["aegis.device-key-sha256"], hashlib.sha256(PK).hexdigest())
        # the record refused: the device is not asked, and the result says the identity is not recognised
        self.policy["endpoints"][0]["endorsement_sha256"] = "00" * 32
        self.save()
        asked = len(dev.asked)
        v, = self.cycle()
        self.assertRefused(v, "endorsement required")
        self.assertEqual(len(dev.asked), asked)
        r = self.read("dev")
        self.assertEqual((r["status"], r["vector"]), ("contraindicated", {0: 97}))

    def test_a_result_is_only_this_verifiers_and_only_for_its_lifetime(self):
        self.add("dev", EatDevice())
        self.cycle()
        data = self.result("dev")
        r = self.read("dev", now=None)
        self.assertEqual(eat.read_ear(data, self.vpk, now=r["exp"] - 1)["status"], "warning")
        with self.assertRaises(eat.Refused):
            eat.read_ear(data, self.vpk, now=r["exp"])
        with self.assertRaises(cose.Refused):
            eat.read_ear(data, PK)
        bad = bytearray(data)
        bad[100] ^= 1
        with self.assertRaises(cose.Refused):
            eat.read_ear(bytes(bad), self.vpk)
        # evidence is not a result, a result is not evidence, even under the right key
        with self.assertRaises(eat.Refused):
            eat.read_ear(cose.sign1(self.vsk, self.vpk, cbor.dumps(evidence_claims(b"\x01" * 32, self.vpk), sort=True)),
                         self.vpk)
        with self.assertRaises(eat.Refused):
            eat.read_evidence(cose.verify1(data, self.vpk).payload, self.vpk)

    def test_the_status_is_never_better_than_the_verdict(self):
        r = random.Random(10)
        tiers = {eat.AFFIRMING, eat.WARNING, eat.CONTRAINDICATED, eat.INCOMPLETE}
        for _ in range(4000):
            verdict = {"endpoint": "x", "admitted": r.random() < 0.5, "reasons": ["r"] if r.random() < 0.5 else []}
            for k, values in (("enrolment", ["endorsed", "trust-on-first-use", "refused"]),
                              ("trust", ["software", "device-key", "trustzone", "development-shared-key"]),
                              ("warning", ["w"])):
                if r.random() < 0.6:
                    verdict[k] = r.choice(values)
            facts = {"stage": r.choice(["policy", "endorsement", "no-evidence", "evidence", "appraised", "error", None])}
            for k, values in (("signature", [True, False]), ("components_ok", [True, False])):
                if r.random() < 0.7:
                    facts[k] = r.choice(values)
            status, vector, details = eat.appraisal(verdict, facts)
            self.assertIn(status, tiers)
            self.assertTrue(vector)
            self.assertLessEqual(set(details), set(vector))
            if not verdict["admitted"]:
                self.assertIn(status, (eat.CONTRAINDICATED, eat.INCOMPLETE), (verdict, facts))
            if status == eat.AFFIRMING:
                self.assertTrue(verdict["admitted"] and not verdict.get("warning"))
                self.assertTrue(all(2 <= v <= 31 for v in vector.values()), (verdict, facts, vector))
            # a result that says "admitted" under a failing status cannot be made into bytes a reader accepts
            data = cose.sign1(self.vsk, self.vpk, eat.ear_payload(verdict, facts, "ni:///sha-256;x", 1000, 1060))
            got = eat.read_ear(data, self.vpk)
            self.assertEqual((got["admitted"], got["status"]), (verdict["admitted"], eat.TIER_NAMES[status]))

    def test_a_status_that_contradicts_the_verdict_is_refused(self):
        """Signed by the right key, but "admitted" under a failing status, or not admitted under affirming or warning:
        neither reader takes it."""
        facts = {"stage": "appraised", "signature": True, "components_ok": True}
        for admitted, status in ((True, eat.CONTRAINDICATED), (True, eat.INCOMPLETE),
                                 (False, eat.AFFIRMING), (False, eat.WARNING)):
            c = cbor.loads(eat.ear_payload({"endpoint": "x", "admitted": not admitted, "reasons": []}, facts,
                                           "ni:///sha-256;x", 1000, 1060))
            a = next(iter(c[266].values()))
            c[1000] = a[1000] = status
            a[1006]["aegis.admitted"] = admitted
            data = cose.sign1(self.vsk, self.vpk, cbor.dumps(c, sort=True))
            with self.assertRaises(eat.Refused):
                eat.read_ear(data, self.vpk)
            if have_checker_libs():
                path = os.path.join(self.d, "r.cbor")
                with open(path, "wb") as f:
                    f.write(data)
                with open(os.path.join(self.d, "v.pub"), "w") as f:
                    f.write(self.vpk.hex())
                rc, rep = checker("result", path, "--key", os.path.join(self.d, "v.pub"))
                self.assertEqual((rc, rep["verified"]), (1, False), rep)
                self.assertIn("admitted with status", rep["reason"])

    def test_without_an_identity_the_loop_runs_and_signs_nothing(self):
        self.add("dev", EatDevice())
        v, = fleet.run_once(self.policy, self.d, VERIFY, credentials=False, state=tempfile.mkdtemp(),
                            policy_bytes=self.policy_bytes)
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertNotIn("attestation_result", v)
        v, = fleet.run_once(self.policy, self.d, VERIFY, credentials=False, state=self.state)
        self.assertNotIn("attestation_result", v)


    def test_results_are_off_unless_the_policy_asks(self):
        """Without "attestation_results": true only an entry with standard evidence gets a result; a policy of the
        older formats alone runs as before: no key loaded, no file written, no "attestation_result" in a verdict."""
        del self.policy["attestation_results"]
        self.add("legacy", EatDevice(), evidence_format=None)
        loads = []
        real = fleet.verifier_keys
        self.addCleanup(setattr, fleet, "verifier_keys", real)
        fleet.verifier_keys = lambda state: loads.append(state) or real(state)
        v, = self.cycle()
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertNotIn("attestation_result", v)
        self.assertEqual(loads, [])
        self.assertFalse(os.path.exists(os.path.join(self.state, "attestation")))
        rc, out = run(fleet.main, ["once", self.pol, "--state-dir", self.state, "--platform", "linux",
                                   "--no-credentials", "--verifier", "cryptography"])
        self.assertEqual(rc, 0, out)
        self.assertNotIn("attestation_result", out)
        self.assertNotIn("no verifier identity", out)
        self.assertEqual(loads, [])
        # an entry with standard evidence asks for its own result, and only for its own
        self.add("eat", EatDevice())
        vs = {v["endpoint"]: v for v in self.cycle()}
        self.assertNotIn("attestation_result", vs["legacy"])
        self.assertEqual(vs["eat"]["attestation_result"]["status"], "warning")
        self.assertEqual(os.listdir(os.path.join(self.state, "attestation")), ["eat"])
        # and the policy's switch asks for every entry's
        self.policy["attestation_results"] = True
        self.save()
        vs = {v["endpoint"]: v for v in self.cycle()}
        self.assertEqual(vs["legacy"]["attestation_result"]["status"], "warning")
        for off in (False, "yes", 1):
            self.policy["attestation_results"] = off
            self.policy["endpoints"] = self.policy["endpoints"][:1]
            self.save()
            v, = self.cycle()
            self.assertNotIn("attestation_result", v, off)


class EndorsementCose(Bench):
    def test_the_standard_record_enrols_and_admits_like_the_json_one(self):
        dev = EatDevice()
        e = self.add("dev", dev)
        res = prov.endorse(self.endorser, e, self.d, self.out, ecdsa_verify=VERIFY, record_format="cose",
                           serial="SN 7", notes="bench", valid_days=30)
        self.assertTrue(res["endorsed"], res)
        self.assertEqual(os.listdir(self.out), ["dev.cbor"])
        with open(res["record"], "rb") as f:
            data = f.read()
        self.assertEqual(data[:2], b"\xd2\x84")
        self.assertEqual(res["record_sha256"], hashlib.sha256(data).hexdigest())
        rec = endorsement.loads(data)
        body = rec["body"]
        self.assertEqual((rec["format"], rec["device_pk"]), ("aegis-endorsement-cose-v1", PK.hex()))
        self.assertEqual((body["device"], body["kind"], body["profile"], body["serial"], body["notes"]),
                         ("dev", "aegis-device", PLATFORM, "SN 7", "bench"))
        self.assertEqual(body["measurements"], [{"type": "SPE", "measurement_value": MEAS}])
        self.assertEqual(body["instance_id"], "01" + hashlib.sha256(PK).hexdigest())
        # the claims, as the document numbers them
        c = cbor.loads(cbor.loads(data).value[2])
        self.assertEqual((c[1], c[2], c[265], c[-82401], c[-82400], c[-82402], c[-82403], c[-82405], c[-82407]),
                         ("bench", "dev", "tag:github.com,2026:ismailalitech/aegis/endorsement/v1", "aegis-device",
                          PLATFORM, "SN 7", "development", "bench", 1))
        self.assertEqual(c[8], {1: {1: 7, 2: thumb(PK), 3: -49, -1: PK}})
        self.assertEqual(c[256], b"\x01" + hashlib.sha256(PK).digest())
        self.assertEqual(c[-82408], bytes.fromhex(self.endorser.pk_sha256))
        self.assertEqual(c[4] - c[6], 30 * 86400)
        self.assertEqual(c[273], [component("SPE", MEAS)])
        # the same body signed in the older form is the same body
        self.assertEqual(endorsement.loads(endorsement.dumps(endorsement.sign(body, self.endorser.sk, PK)))["body"], body)
        e["endorsement"] = "required"
        self.save()
        rc, out = run(fleet.main, ["enroll-endorsed", self.pol, res["record"]])
        self.assertEqual(rc, 0, out)
        with open(self.pol) as f:
            self.policy = json.load(f)
        e = self.policy["endpoints"][0]
        self.assertEqual(e["endorsement_sha256"], res["record_sha256"])
        v = self.attest(e)
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertEqual((v["enrolment"], v["endorsement"]["record_sha256"]), ("endorsed", res["record_sha256"]))
        # endorsed measurements bind as before
        other = EatDevice(edit=lambda c: c.update({273: [component("SPE", MEAS), component("NSPE", MEAS)]}))
        self.assertRefused(self.attest(dict(e, port=other.port, allowed=e["allowed"] + [
            {"type": "NSPE", "measurement_value": MEAS}])), "not in the endorsement")

    def test_an_altered_or_foreign_standard_record_is_refused(self):
        dev = EatDevice()
        e = self.add("dev", dev)
        res = self.enrol(e, record_format="cose")
        e = self.policy["endpoints"][0]
        path = fleet.endorsement_file(e, self.d)
        with open(path, "rb") as f:
            data = f.read()
        self.assertTrue(self.attest(e)["admitted"])
        asked = dev.asked.count("PQEAT")

        def put(b):
            with open(path, "wb") as f:
                f.write(b)
        for at in (8, 80, 300, 2100, len(data) - 5):
            bad = bytearray(data)
            bad[at] ^= 1
            put(bytes(bad))
            self.assertRefused(self.attest(dict(e, endorsement_sha256=None)), "endorsement required")
        # the same claims signed by a key the policy does not list, under either name
        claims = cbor.loads(data).value[2]
        put(cose.sign1(SK2, PK2, claims))
        self.assertRefused(self.attest(dict(e, endorsement_sha256=None)), "does not verify")
        c = cbor.loads(claims)
        c[-82408] = hashlib.sha256(PK2).digest()
        put(cose.sign1(SK2, PK2, cbor.dumps(c, sort=True)))
        self.assertRefused(self.attest(dict(e, endorsement_sha256=None)), "not a trusted endorser")
        # a claim the verifier does not know, properly signed by the endorser
        for edit in (lambda c: c.update({-82450: 1}), lambda c: c.update({265: PROFILE}), lambda c: c.pop(8),
                     lambda c: c.update({8: {1: cose.cose_key(PK2)}}), lambda c: c.update({2: "other"}),
                     lambda c: c.update({-82407: 2}), lambda c: c.update({-82401: "aegis-tee"})):
            c = cbor.loads(claims)
            edit(c)
            put(cose.sign1(self.endorser.sk, self.endorser.pk, cbor.dumps(c, sort=True)))
            self.assertRefused(self.attest(dict(e, endorsement_sha256=None)), "endorsement required")
        # a valid record that is not the pinned one
        again = prov.endorse(self.endorser, dict(e, endorsement=None, endorsement_sha256=None), self.d,
                             tempfile.mkdtemp(), ecdsa_verify=VERIFY, record_format="cose")
        with open(again["record"], "rb") as f:
            put(f.read())
        self.assertRefused(self.attest(e), "not the one the policy pins")
        self.assertNotEqual(again["record_sha256"], res["record_sha256"])
        put(data)
        self.assertTrue(self.attest(e)["admitted"])
        # none of the refused records had the device asked: only the second endorsement (before it signs, and with
        # the record it made) and the last attestation
        self.assertEqual(dev.asked.count("PQEAT"), asked + 3)

    def test_the_tool_writes_either_form(self):
        dev = EatDevice()
        self.add("dev", dev)
        ref = prov.draft_reference(self.policy, ["dev"], self.d)
        ref["devices"][0].update(host="127.0.0.1", port=dev.port)
        path = os.path.join(tempfile.mkdtemp(), "reference.json")
        with open(path, "w") as f:
            json.dump(ref, f)
        for fmt, name in (("cose", "dev.cbor"), ("json", "dev.json")):
            out = tempfile.mkdtemp()
            rc, text = run(prov.main, ["endorse", "dev", "--reference", path, "--yes", "--state", self.estate,
                                       "--out", out, "--record-format", fmt])
            self.assertEqual((rc, os.listdir(out)), (0, [name]), text)
        self.assertEqual(ref["devices"][0]["evidence_format"], "eat-cose-v1")
        # the endorser appraised standard evidence: twice a record, before it signs and with the record it made
        self.assertEqual(dev.asked.count("PQEAT"), 4)
        self.assertNotIn("PQCHAL", dev.asked)


@NEEDS_LIBS
class Pack(Bench):
    def export(self, name, *more):
        out = os.path.join(tempfile.mkdtemp(), "pack")
        rc, text = run(fleet.main, ["export-evidence", self.pol, name, "--out", out, "--state-dir", self.state,
                                    "--platform", "linux", *more])
        self.assertEqual(rc, 0, text)
        with open(os.path.join(out, "manifest.json")) as f:
            return out, json.load(f), text

    def trust(self, endorser=True):
        t = ["--verifier-key", thumb(self.vpk).hex(), "--device-key", thumb(PK).hex()]
        return t + (["--endorser-key", thumb(self.endorser.pk).hex()] if endorser else [])

    def test_the_checker_shares_no_code_with_the_repository(self):
        with open(CHECKER) as f:
            tree = ast.parse(f.read())
        mods = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                mods.add(node.module.split(".")[0])
        third = mods - set(sys.stdlib_module_names)
        self.assertEqual(third, {"cbor2", "cryptography", "pycose"})
        ours = {os.path.splitext(n)[0] for d in ("common", "gateway/aegisd", "provision", "tools")
                for n in os.listdir(os.path.join(ROOT, d))}
        self.assertEqual(mods & ours, set())

    def test_a_pack_of_standard_evidence_verifies_with_third_party_libraries_only(self):
        dev = EatDevice()
        e = self.add("dev", dev)
        self.enrol(e, record_format="cose")
        v, = self.cycle()
        self.assertTrue(v["admitted"], v["reasons"])
        out, man, text = self.export("dev", "--with-policy")
        self.assertIn("result affirming (admitted)", text)
        self.assertEqual(sorted(man["files"]), ["attestation-result.cbor", "endorsement.cbor", "evidence.cbor",
                                                "keys/device.cosekey", "keys/endorser.cosekey", "keys/verifier.cosekey",
                                                "policy.json"])
        self.assertEqual(man["key_thumbprints"], {"device": thumb(PK).hex(), "endorser": thumb(self.endorser.pk).hex(),
                                                  "verifier": thumb(self.vpk).hex()})
        self.assertEqual((man["evidence_format"], man["policy_sha256"]),
                         ("eat-cose-v1", hashlib.sha256(self.policy_bytes).hexdigest()))
        rc, rep = checker("pack", out, *self.trust())
        self.assertEqual((rc, rep["verified"]), (0, True), rep)
        self.assertEqual((rep["attestation_result"]["status"], rep["attestation_result"]["admitted"]), ("affirming", True))
        self.assertEqual(rep["attestation_result"]["trustworthiness_vector"], {"0": 2, "2": 3})
        self.assertEqual(rep["evidence"]["measurements"], [{"name": "SPE", "sha256": MEAS, "version": "1.0"}])
        self.assertEqual(rep["evidence"]["quote_sha3_256"], v["quote"]["token_sha3_256"])
        self.assertEqual((rep["endorsement"]["device"], rep["endorsement"]["device_key_sha256"]),
                         ("dev", hashlib.sha256(PK).hexdigest()))
        self.assertTrue(all("command line" in k["trusted"] for k in rep["keys"].values()))
        for agreed in ("the quote hash (transcript v2) in evidence and result", "the nonce in evidence and result",
                       "the measurements in evidence and result", "the endorsed key and the device key",
                       "the endorsed measurements and the result's", "the evidence file and the result's evidence hash"):
            self.assertIn(agreed + " agree", rep["checks"])
        # without the reader's own keys it says that the keys are the pack's
        rc, rep = checker("pack", out)
        self.assertEqual(rc, 0, rep)
        self.assertTrue(all(k["trusted"].startswith("NOT CHECKED") for k in rep["keys"].values()))
        # each object on its own
        key = os.path.join(out, "keys")
        for what, name, k in (("evidence", "evidence.cbor", "device"), ("result", "attestation-result.cbor", "verifier"),
                              ("endorsement", "endorsement.cbor", "endorser")):
            rc, rep = checker(what, os.path.join(out, name), "--key", os.path.join(key, k + ".cosekey"))
            self.assertEqual((rc, rep["verified"]), (0, True), rep)
            for other in {"device", "verifier", "endorser"} - {k}:
                rc, rep = checker(what, os.path.join(out, name), "--key", os.path.join(key, other + ".cosekey"))
                self.assertEqual((rc, rep["verified"]), (1, False), rep)
        nonce = cbor.loads(cbor.loads(dev.last).value[2])[10]
        ev = os.path.join(out, "evidence.cbor")
        self.assertEqual(checker("evidence", ev, "--key", os.path.join(key, "device.cosekey"), "--nonce", nonce.hex())[0], 0)
        self.assertEqual(checker("evidence", ev, "--key", os.path.join(key, "device.cosekey"), "--nonce", "00" * 32)[0], 1)
        with open(os.path.join(self.d, "hex.pub"), "w") as f:
            f.write(PK.hex())
        self.assertEqual(checker("evidence", ev, "--key", os.path.join(self.d, "hex.pub"))[0], 0)
        # an existing directory is never mixed with a new pack
        rc, text = run(fleet.main, ["export-evidence", self.pol, "dev", "--out", out, "--state-dir", self.state,
                                    "--platform", "linux"])
        self.assertEqual(rc, 1, text)

    def test_a_changed_or_mixed_pack_does_not_verify(self):
        self.add("dev", EatDevice())
        self.add("other", EatDevice(pk=PK2, sk=SK2))
        self.enrol(self.policy["endpoints"][0], record_format="cose")
        self.cycle()
        out, man, _ = self.export("dev")
        other, _, _ = self.export("other")
        self.assertEqual(checker("pack", out, *self.trust())[0], 0)
        self.assertEqual(checker("pack", other, "--verifier-key", thumb(self.vpk).hex(), "--device-key", thumb(PK2).hex())[0], 0)

        def changed(edit, *trust):
            import shutil
            d = os.path.join(tempfile.mkdtemp(), "pack")
            shutil.copytree(out, d)
            edit(d)
            rc, rep = checker("pack", d, *(trust or self.trust()))
            self.assertEqual((rc, rep["verified"]), (1, False), rep)
            return rep["reason"]

        def flip(name, at):
            def edit(d):
                with open(os.path.join(d, name), "r+b") as f:
                    f.seek(at)
                    b = f.read(1)
                    f.seek(at)
                    f.write(bytes([b[0] ^ 1]))
            return edit

        def remanifest(d):
            with open(os.path.join(d, "manifest.json")) as f:
                m = json.load(f)
            for name in m["files"]:
                with open(os.path.join(d, name), "rb") as f:
                    m["files"][name] = hashlib.sha256(f.read()).hexdigest()
            with open(os.path.join(d, "manifest.json"), "w") as f:
                json.dump(m, f)

        def swap(name, src=other):
            def edit(d):
                import shutil
                shutil.copy(os.path.join(src, name), os.path.join(d, name))
                remanifest(d)
            return edit
        for name in ("evidence.cbor", "attestation-result.cbor", "endorsement.cbor", "keys/device.cosekey"):
            self.assertIn("not the file the manifest names", changed(flip(name, 90)))
            # and with the manifest made to fit: the signatures, the kids, the thumbprints
            changed(lambda d, name=name: (flip(name, 90)(d), remanifest(d)))
        # another device's evidence or result in this pack, every file properly signed
        self.assertIn("kid is not the thumbprint", changed(swap("evidence.cbor")))
        self.assertIn("another endpoint", changed(swap("attestation-result.cbor")))
        changed(lambda d: (swap("evidence.cbor")(d), swap("keys/device.cosekey")(d)),
                "--verifier-key", thumb(self.vpk).hex(), "--device-key", thumb(PK2).hex())
        # a pack whose keys are not the reader's
        self.assertIn("not the one you trust", changed(lambda d: None, "--verifier-key", thumb(PK).hex()))
        self.assertIn("not the one you trust", changed(lambda d: None, "--device-key", thumb(PK2).hex()))
        # a result re-signed by someone else, with that key put into the pack
        def resign(d):
            with open(os.path.join(d, "attestation-result.cbor"), "rb") as f:
                payload = cbor.loads(f.read()).value[2]
            with open(os.path.join(d, "attestation-result.cbor"), "wb") as f:
                f.write(cose.sign1(SK2, PK2, payload))
            with open(os.path.join(d, "keys", "verifier.cosekey"), "wb") as f:
                f.write(fleet.cbor_key(PK2))
            remanifest(d)
        self.assertIn("not the one you trust", changed(resign))
        # the manifest is not signed: a file left out of the pack (and the manifest) is caught by what the result names
        def drop(*names):
            def edit(d):
                with open(os.path.join(d, "manifest.json")) as f:
                    m = json.load(f)
                for name in names:
                    os.remove(os.path.join(d, name))
                    del m["files"][name]
                with open(os.path.join(d, "manifest.json"), "w") as f:
                    json.dump(m, f)
            return edit
        self.assertIn("the pack has none", changed(drop("evidence.cbor")))
        self.assertIn("the pack has none", changed(drop("evidence.cbor", "keys/device.cosekey"),
                                                   "--verifier-key", thumb(self.vpk).hex()))
        self.assertIn("has no endorsement", changed(drop("endorsement.cbor")))
        self.assertIn("has no endorsement", changed(drop("endorsement.cbor", "keys/endorser.cosekey"),
                                                    "--verifier-key", thumb(self.vpk).hex()))
        # a result without endorser claims, checked by someone who expects an endorsement
        rc, rep = checker("pack", other, "--verifier-key", thumb(self.vpk).hex(), "--device-key", thumb(PK2).hex(),
                          "--endorser-key", thumb(self.endorser.pk).hex())
        self.assertEqual((rc, rep["verified"]), (1, False), rep)
        self.assertIn("has no endorsement", rep["reason"])
        # a file the manifest names outside the pack
        def escape(d):
            with open(os.path.join(d, "manifest.json")) as f:
                m = json.load(f)
            m["files"]["../x"] = "00" * 32
            with open(os.path.join(d, "manifest.json"), "w") as f:
                json.dump(m, f)
        self.assertIn("leaves the pack", changed(escape))

    def test_packs_of_the_older_formats_verify_too(self):
        """Legacy formats stay accepted: the older quote (a token and a detached signature) and the JSON record."""
        dev = EatDevice()
        e = self.add("dev", dev, evidence_format=None)
        self.enrol(e)
        self.add("psa", tf.FakeEndpoint(self.iak), pin=False, kind=None, profile=None, pq_pub_file=None,
                 evidence_format=None, iak_pub_pem="iak.pem",
                 allowed=[{"type": "SPE", "measurement_value": tf.GOOD_S, "signer_id": tf.SIGNER},
                          {"type": "NSPE", "measurement_value": tf.GOOD_NS, "signer_id": tf.SIGNER}])
        vs = self.cycle()
        self.assertEqual([v["admitted"] for v in vs], [True, True], vs)
        out, man, _ = self.export("dev")
        self.assertEqual(sorted(man["files"]), ["attestation-result.cbor", "endorsement.json", "evidence.sig",
                                                "evidence.token", "keys/device.cosekey", "keys/endorser.cosekey",
                                                "keys/verifier.cosekey"])
        self.assertEqual(man["evidence_format"], "aegis-quote-v1")
        rc, rep = checker("pack", out, *self.trust())
        self.assertEqual((rc, rep["verified"]), (0, True), rep)
        self.assertIn("aegis-quote-v1", rep["evidence"]["format"])
        self.assertIn("aegis-endorsement-v1", rep["endorsement"]["format"])
        self.assertEqual(rep["attestation_result"]["status"], "affirming")
        rc, rep = checker("endorsement", os.path.join(out, "endorsement.json"), "--key",
                          os.path.join(out, "keys", "endorser.cosekey"))
        self.assertEqual((rc, rep["verified"]), (0, True), rep)
        # the older quote's detached signature cannot be left out of the pack either
        import shutil
        nosig = os.path.join(tempfile.mkdtemp(), "pack")
        shutil.copytree(out, nosig)
        os.remove(os.path.join(nosig, "evidence.sig"))
        with open(os.path.join(nosig, "manifest.json")) as f:
            m = json.load(f)
        del m["files"]["evidence.sig"]
        with open(os.path.join(nosig, "manifest.json"), "w") as f:
            json.dump(m, f)
        rc, rep = checker("pack", nosig, *self.trust())
        self.assertEqual((rc, rep["verified"]), (1, False), rep)
        self.assertIn("no evidence.sig", rep["reason"])
        # the detached signature belongs to this token
        with open(os.path.join(out, "evidence.token"), "r+b") as f:
            f.write(b"\xa5")
        self.assertEqual(checker("pack", out, *self.trust())[0], 1)
        out, man, _ = self.export("psa")
        self.assertEqual(sorted(man["files"]), ["attestation-result.cbor", "evidence.token", "keys/device-iak.pem",
                                                "keys/verifier.cosekey"])
        rc, rep = checker("pack", out, "--verifier-key", thumb(self.vpk).hex())
        self.assertEqual((rc, rep["verified"]), (0, True), rep)
        self.assertEqual(rep["attestation_result"]["verifier_claims"]["aegis.evidence-format"], "psa-token")

    def test_a_second_quote_not_admitted_makes_one_consistent_pack(self):
        """The bound exchange is refused and the second quote of the cycle is not admitted: the verdict, the signed
        result and the evidence kept with it are all the second quote's, and the pack verifies."""
        n = []

        def second_bad(c):
            n.append(1)
            if len(n) > 1:
                c[273] = [component("SPE", "99" * 32)]
        dev = EatDevice(edit=second_bad)
        self.add("dev", dev, provision=True, transcript="v2")
        self.addCleanup(setattr, fleet, "BUSY_BACKOFF_S", fleet.BUSY_BACKOFF_S)
        self.addCleanup(setattr, fleet, "provision", fleet.provision)
        fleet.BUSY_BACKOFF_S = (0, 0)

        def refused(*a, **kw):
            raise fleet.TranscriptRefused("another verifier's quote in between")
        fleet.provision = refused
        v, = fleet.run_once(self.policy, self.d, VERIFY, credentials=True, state=self.state,
                            policy_bytes=self.policy_bytes, enforce_hooks=False)
        self.assertEqual(len(n), 2)
        self.assertFalse(v["admitted"])
        self.assertIn("second quote of the cycle not admitted", v["reasons"][-1])
        parts = cbor.loads(dev.last).value
        self.assertEqual(v["quote"]["token_sha3_256"],
                         hashlib.sha3_256(cbor.dumps(["Signature1", parts[0], b"", parts[2]])).hexdigest())
        self.assertEqual(v["measurements"], {"SPE": "99" * 32})
        r = eat.read_ear(self.result("dev"), self.vpk)
        self.assertEqual((r["status"], r["admitted"]), ("contraindicated", False))
        self.assertEqual(r["verifier_claims"]["aegis.evidence-sha256"], hashlib.sha256(dev.last).digest())
        self.assertEqual(r["verifier_claims"]["aegis.quote-sha3-256"].hex(), v["quote"]["token_sha3_256"])
        out, man, _ = self.export("dev")
        rc, rep = checker("pack", out, *self.trust(endorser=False))
        self.assertEqual((rc, rep["verified"]), (0, True), rep)
        self.assertEqual(rep["evidence"]["measurements"], [{"name": "SPE", "sha256": "99" * 32}])

    def test_a_key_file_that_is_not_the_pinned_key_is_not_exported(self):
        e = self.add("dev", EatDevice(), pq_pub_sha256=hashlib.sha256(PK).hexdigest())
        self.assertTrue(self.cycle()[0]["admitted"])
        out, man, _ = self.export("dev")
        self.assertEqual(man["key_thumbprints"]["device"], thumb(PK).hex())
        with open(os.path.join(self.d, e["pq_pub_file"]), "w") as f:     # replaced after the cycle
            f.write(PK2.hex() + "\n")
        rc, text = run(fleet.main, ["export-evidence", self.pol, "dev", "--out", os.path.join(tempfile.mkdtemp(), "p"),
                                    "--state-dir", self.state, "--platform", "linux"])
        self.assertEqual(rc, 1, text)
        self.assertIn("is not the key the policy pins (pq_pub_sha256", text)

    def test_export_says_why_there_is_nothing_to_export(self):
        self.add("dev", EatDevice())
        for name, text in (("dev", "no attestation of dev is kept"), ("nobody", "no entry named"), ("../x", "no entry")):
            rc, out = run(fleet.main, ["export-evidence", self.pol, name, "--out", os.path.join(tempfile.mkdtemp(), "p"),
                                       "--state-dir", self.state, "--platform", "linux"])
            self.assertEqual(rc, 1)
            self.assertIn(text, out)


if __name__ == "__main__":
    unittest.main()

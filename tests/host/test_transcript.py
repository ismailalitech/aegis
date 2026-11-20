# SPDX-License-Identifier: Apache-2.0
"""One transcript (audit finding 2): the verifier finishes a session only with the code whose quote it appraised.

The device here has one ML-DSA-65 key and several firmware images that all hold it, as after an upgrade or with a debug
image signed for the same key. Its endpoint side is written out again in this file from docs/architecture.md, with
hashlib only, so that it is a second reading of the layout and not common/transcript.py checking itself. The tests
run the gateway's own code (fleet.attest, fleet.credential_step, fleet.main on both platforms) against it:

  - the transcript as intended is accepted, and both sides hold the same session;
  - the swap: the quote comes from firmware A, the ML-KEM exchange is answered after the device restarted into
    firmware B. Refused whether B knows the transcript or not, and whether or not B first signed a quote of its own
    for the same challenge;
  - reordered and replayed pieces are refused: an exchange without a quote, a quote of another cycle, a recorded KEM
    key, a recorded confirmation, a confirmation made the old way;
  - with "transcript": "v2" in the policy the old exchange is refused and a stored session made that way is replaced;
    without it the old exchange still works, and is marked as the weaker one;
  - what it cannot do: a firmware that holds the key and signs a transcript for a quote it did not make is accepted
    (test_limit_...). The key would have to depend on the measured code to prevent that.
"""
import contextlib
import hashlib
import io
import json
import os
import socket
import sys
import tempfile
import threading
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
for p in ("common", "gateway/aegisd"):
    sys.path.insert(0, os.path.abspath(os.path.join(ROOT, p)))

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

import fleet  # noqa: E402
import kmac  # noqa: E402
import mldsa  # noqa: E402
import mlkem  # noqa: E402
import transcript  # noqa: E402
import wire  # noqa: E402
from test_fleet import GOOD_NS, GOOD_S, SIGNER, make_token  # noqa: E402

BAD_NS = "bb" * 32


def H(*parts):
    return hashlib.sha3_256(b"".join(parts)).digest()


# firmware images that hold the same device key
FW_A = {"nspe": GOOD_NS, "transcript": True}               # the appraised image
FW_B = {"nspe": BAD_NS, "transcript": True}                # another image that knows the transcript
FW_B_OLD = {"nspe": BAD_NS, "transcript": False}           # another image from before the transcript
FW_A_OLD = {"nspe": GOOD_NS, "transcript": False}          # an allowed image from before the transcript
FW_OLD_CONFIRM = {"nspe": GOOD_NS, "transcript": True, "confirm": "v1"}


class Device:
    """One request per connection, as the provers. RAM (the quote, the pending exchange, the session) is lost at
    boot(); the key is not."""

    def __init__(self, gw_pk):
        self.iak = ec.generate_private_key(ec.SECP256R1())
        self.pk, self.sk = mldsa.keypair()
        self.gw_pk = gw_pk
        self.lines, self.replies = [], []
        self.after_quote = None      # called once when the next PQCHAL has been answered (what happens "in between")
        self.rewrite = None          # someone on the path: (request, reply) -> reply
        self.lie = None              # (challenge, token hash) a lying firmware signs a transcript for
        self.boot(FW_A)
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self.loop, daemon=True).start()

    def boot(self, fw):
        self.fw, self.quote, self.kem, self.session, self.hb = fw, None, None, None, 0

    def loop(self):
        while True:
            c, _ = self.srv.accept()
            try:
                buf = b""
                while b"\n" not in buf:
                    chunk = c.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                line = buf.split(b"\n")[0].decode().strip()
                reply = self.handle(line)
                if self.rewrite:
                    reply = self.rewrite(line, reply)
                self.lines.append(line.split()[0])
                self.replies.append((line, reply))
                # what happens "in between" happens once the answer is made and before it is sent, so that it is
                # over when the gateway reads the answer (run after sending, it raced with the test's next step)
                if line.startswith("PQCHAL") and self.after_quote:
                    hook, self.after_quote = self.after_quote, None
                    hook()
                c.sendall(reply.encode() + b"\r\n")
            finally:
                c.close()

    def ask(self, line):
        """A request from someone else on the network."""
        return fleet._exchange("127.0.0.1", self.port, line, 5)

    def handle(self, line):
        p = line.split()
        if p[0] == "PQKEY":
            return "PQKEY %d %s END" % (len(self.pk), self.pk.hex())
        if p[0] == "PQCHAL":
            ch = bytes.fromhex(p[1])
            self.quote = None
            tok = make_token(self.iak, ch, ns_meas=self.fw["nspe"])
            sig = mldsa.sign(self.sk, b"aegis-endpoint-quote-v1", tok)
            if self.fw["transcript"]:
                self.quote = (ch, H(b"aegis-transcript-v2/quote", ch, H(tok)))
            return "PQTOKEN %d %s %d %s END" % (len(tok), tok.hex(), len(sig), sig.hex())
        if p[0] == "PQKEMINIT":
            nonce = bytes.fromhex(p[1])
            self.kem, t1 = None, None
            if self.quote and self.quote[0] == nonce:
                t1, self.quote = self.quote[1], None
            if self.lie and self.lie[0] == nonce:          # not an honest image: a transcript for a quote it never made
                t1 = H(b"aegis-transcript-v2/quote", self.lie[0], self.lie[1])
            ek, dk = mlkem.keypair()
            if t1:
                t2 = H(b"aegis-transcript-v2/kem-init", t1, ek)
                sig = mldsa.sign(self.sk, b"aegis-kem-init-v2", t2)
            else:
                t2, sig = None, mldsa.sign(self.sk, b"aegis-kem-init-v1", nonce + ek)
            self.kem = (nonce, dk, ek, t2)
            return "PQKEMEK %d %s %d %s END" % (len(ek), ek.hex(), len(sig), sig.hex())
        if p[0] == "PQKEMFIN":
            if not self.kem:
                return "ERR cred no-exchange"
            (nonce, dk, ek, t2), self.kem = self.kem, None
            ct, cred = bytes.fromhex(p[1]), bytes.fromhex(p[2])
            body, _, sig = cred.partition(b"\n")
            if not mldsa.verify(self.gw_pk, b"aegis-credential-v1", body, sig):
                return "ERR cred signature"
            b = json.loads(body)
            if b.get("kem_ct_sha3_256") != H(ct).hex() or b.get("kem_ek_sha3_256") != H(ek).hex():
                return "ERR cred other-exchange"
            if t2 and b.get("transcript_sha3_256") != t2.hex():
                return "ERR cred other-transcript"
            k = mlkem.decaps(ct, dk)
            if t2 and self.fw.get("confirm") != "v1":
                t3 = H(b"aegis-transcript-v2/kem-fin", t2, H(ct), H(cred))
                tag, self.session = H(b"aegis-confirm-v2", k, t3), H(b"aegis-session-v2", k, t3)
            else:
                tag, self.session = H(b"aegis-confirm-v1", k, nonce, H(ct), H(cred)), H(b"aegis-session-v1", k, nonce, H(ct))
            self.cred, self.hb = cred, 0
            return "PQKEMOK %s END" % tag.hex()
        if p[0] == "PQHB":
            if not self.session:
                return "ERR pq no-session"
            self.hb += 1
            ctr, status = self.hb.to_bytes(8, "little"), b"uptime_s=1;link=1;fw=test"
            tag = kmac.kmac256(self.session, bytes.fromhex(p[1]) + ctr + status, 32, b"aegis-hb-v2")
            return "PQHB %s %s %s END" % (status.hex(), ctr.hex(), tag.hex())
        if p[0] == "PQSESSION":
            if not self.session:
                return "ERR pq no-session"
            return "PQSESSION %s %s END" % (H(b"aegis-session-id-v1", self.session).hex(), H(self.cred).hex())
        return "ERR unknown"


class Transcript(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.state = tempfile.mkdtemp()
        self.gw_pk, self.gw_sk = mldsa.keypair()
        with open(os.path.join(self.state, "identity.json"), "w") as f:
            json.dump({"body": {"v": 1, "type": "identity", "pk": self.gw_pk.hex()}}, f)
        with open(os.path.join(self.state, "identity.sk"), "wb") as f:
            f.write(self.gw_sk)
        self.dev = Device(self.gw_pk)
        with open(os.path.join(self.d, "dev.pub"), "w") as f:
            f.write(self.dev.pk.hex())
        self.conf = {"name": "dev", "kind": "aegis-pq", "host": "127.0.0.1", "port": self.dev.port,
                     "pq_pub_file": "dev.pub", "provision": True, "transcript": "v2",
                     "allowed": [{"type": "SPE", "measurement_value": GOOD_S, "signer_id": SIGNER},
                                 {"type": "NSPE", "measurement_value": GOOD_NS, "signer_id": SIGNER}]}

    def attest(self):
        v = fleet.attest(self.conf, None, self.d, timeout=5)
        self.assertTrue(v["admitted"], v["reasons"])
        return v

    def step(self, v):
        return fleet.credential_step(self.conf, v, self.d, state=self.state)

    def cycle(self):
        v = self.attest()
        return v, self.step(v)

    def stored(self):
        return [f for f in ("dev.json", "dev.session") if os.path.exists(os.path.join(self.state, "credentials", f))]

    def assert_refused(self, cs, why):
        self.assertTrue(cs.startswith("provisioning REFUSED: "), cs)
        self.assertIn(why, cs)
        self.assertEqual(self.stored(), [])
        self.assertIsNone(self.dev.session)
        self.assertNotIn("PQKEMFIN", self.dev.lines)       # refused before the gateway sent anything to finish with

    # ---- the layout ----

    def test_layout_known_answers(self):
        """Fixed inputs, with the values this file's own reading (H above) gives, and three of them pinned as
        constants: a change of a label, an order or a length in common/transcript.py shows here."""
        ch, tok, ek, ct, cred, k = bytes(range(32)), b"token", bytes(1184), b"ct", b"cred", bytes(range(32, 64))
        t1 = transcript.quote(ch, transcript.token_hash(tok))
        t2 = transcript.kem_init(t1, ek)
        t3 = transcript.kem_fin(t2, ct, cred)
        self.assertEqual(t1, H(b"aegis-transcript-v2/quote", ch, H(tok)))
        self.assertEqual(t2, H(b"aegis-transcript-v2/kem-init", t1, ek))
        self.assertEqual(t3, H(b"aegis-transcript-v2/kem-fin", t2, H(ct), H(cred)))
        self.assertEqual(transcript.confirm_tag(k, t3), H(b"aegis-confirm-v2", k, t3))
        self.assertEqual(transcript.session_key(k, t3), H(b"aegis-session-v2", k, t3))
        self.assertEqual(transcript.KEM_INIT_LABEL, b"aegis-kem-init-v2")
        self.assertEqual((t1.hex(), t2.hex(), t3.hex()), KAT)
        self.assertEqual(len({t1, t2, t3, transcript.confirm_tag(k, t3), transcript.session_key(k, t3)}), 5)

    def test_layout_fixed_lengths(self):
        for call in (lambda: transcript.quote(bytes(31), bytes(32)), lambda: transcript.quote(bytes(32), bytes(33)),
                     lambda: transcript.kem_init(bytes(32), bytes(1183)), lambda: transcript.kem_init(bytes(31), bytes(1184)),
                     lambda: transcript.kem_fin(bytes(33), b"ct", b"cred"), lambda: transcript.confirm_tag(bytes(31), bytes(32)),
                     lambda: transcript.session_key(bytes(32), bytes(31)), lambda: transcript.token_hash(b"")):
            with self.assertRaises(ValueError):
                call()

    # ---- accepted ----

    def test_good_transcript_accepted(self):
        v, cs = self.cycle()
        self.assertTrue(cs.startswith("issued session "), cs)
        self.assertIn("bound to quote %s... (transcript v2)" % v["quote"]["token_sha3_256"][:12], cs)
        self.assertNotIn("unbound", cs)
        self.assertEqual(v["session_binding"], "transcript-v2")
        self.assertNotIn("warning", v)
        self.assertEqual(self.dev.lines, ["PQCHAL", "PQKEMINIT", "PQKEMFIN"])
        # PQKEMINIT carried the challenge of the quote, and nothing else names the quote to the endpoint
        self.assertEqual(self.dev.replies[1][0], "PQKEMINIT " + v["quote"]["challenge"])
        with open(os.path.join(self.state, "credentials", "dev.json")) as f:
            m = json.load(f)
        with open(os.path.join(self.state, "credentials", "dev.session"), "rb") as f:
            self.assertEqual(f.read(), self.dev.session)   # the device made it from its own reading of the layout
        self.assertEqual(m["transcript"], "v2")
        self.assertEqual(m["body"]["transcript"], "v2")
        self.assertEqual(m["quote"], v["quote"])
        # the signed body stays well inside what the STM32 partition can verify (1214 bytes)
        self.assertLess(len(wire.canonical(m["body"])), 1214 - 256)
        self.assertEqual(m["body"]["measurements"], {"SPE": GOOD_S, "NSPE": GOOD_NS})
        self.assertEqual(fleet.query_session(self.conf), (m["session_id"], m["credential_sha3_256"]))
        for n in (1, 2):
            v, cs = self.cycle()
            self.assertEqual(cs, "valid, heartbeat %d (uptime_s=1;link=1;fw=test)" % n)
            self.assertEqual(v["session_binding"], "transcript-v2")

    # ---- the swap ----

    def test_swap_to_a_firmware_from_before_the_transcript_refused(self):
        v = self.attest()                                   # firmware A, appraised
        self.dev.boot(FW_B_OLD)                             # the same key now answers from another image
        self.assert_refused(self.step(v), "the endpoint answered the unbound exchange")

    def test_swap_to_a_firmware_that_knows_the_transcript_refused(self):
        v = self.attest()
        self.dev.boot(FW_B)                                 # no quote in its RAM: nothing to continue
        self.assert_refused(self.step(v), "the endpoint answered the unbound exchange")

    def test_swap_with_its_own_quote_for_the_same_challenge_refused(self):
        v = self.attest()
        self.dev.boot(FW_B)
        # someone has firmware B sign a quote for the gateway's challenge first: B's quote reports B's measurements,
        # so B's transcript is another one
        self.assertTrue(self.dev.ask("PQCHAL " + v["quote"]["challenge"]).startswith("PQTOKEN "))
        self.assert_refused(self.step(v), "not signed over the transcript of the quote just appraised")

    def test_same_firmware_restarted_in_between_refused_then_works(self):
        v = self.attest()
        self.dev.boot(FW_A)                                 # even the appraised image: it must be the same boot
        self.assert_refused(self.step(v), "the endpoint answered the unbound exchange")
        _, cs = self.cycle()
        self.assertTrue(cs.startswith("issued session "), cs)

    def test_restart_into_an_allowed_firmware_from_before_the_transcript_gets_no_session(self):
        _, cs = self.cycle()
        self.assertTrue(cs.startswith("issued session "), cs)
        self.dev.boot(FW_B_OLD)                             # the session was in RAM
        self.conf["allowed"].append({"type": "NSPE", "measurement_value": BAD_NS, "signer_id": SIGNER})  # even if allowed
        v, cs = self.cycle()
        self.assertTrue(cs.startswith("provisioning REFUSED: "), cs)
        self.assertIn("no-session", cs)                     # the heartbeat failed first
        self.assertEqual(self.stored(), [])

    # ---- reordered and replayed pieces ----

    def test_quote_of_another_cycle_refused(self):
        old = self.attest()
        self.attest()                                       # the endpoint has signed a newer quote since
        self.assert_refused(self.step(old), "the endpoint answered the unbound exchange")

    def test_another_verifiers_quote_in_between_refused_then_works(self):
        v = self.attest()
        self.dev.ask("PQCHAL " + os.urandom(32).hex())      # a second verifier attests in between
        self.assert_refused(self.step(v), "the endpoint answered the unbound exchange")
        _, cs = self.cycle()
        self.assertTrue(cs.startswith("issued session "), cs)

    def test_another_verifiers_quote_in_between_second_quote_of_the_cycle(self):
        """What the fleet loop does about it: one more quote, appraised like the first, and the exchange for that
        one. Only if it says the same as the verdict being reported."""
        self.dev.after_quote = lambda: self.dev.handle("PQCHAL " + os.urandom(32).hex())   # the other verifier's
        self.addCleanup(setattr, fleet, "BUSY_BACKOFF_S", fleet.BUSY_BACKOFF_S)
        fleet.BUSY_BACKOFF_S = (0, 0)
        pol = {"endpoints": [self.conf]}
        v = fleet.run_once(pol, self.d, None, state=self.state)[0]
        self.assertTrue(v["credential"].startswith("issued session "), v["credential"])
        self.assertIn("(transcript v2, second quote of the cycle)", v["credential"])
        self.assertEqual(self.dev.lines, ["PQCHAL", "PQKEMINIT", "PQCHAL", "PQKEMINIT", "PQKEMFIN"])
        self.assertEqual(self.dev.replies[3][0], "PQKEMINIT " + v["quote"]["challenge"])   # the second quote's
        self.assertIn(v["quote"]["token_sha3_256"][:12], v["credential"])
        with open(os.path.join(self.state, "credentials", "dev.session"), "rb") as f:
            self.assertEqual(f.read(), self.dev.session)
        # a restart into the same image in between: the second quote is of the new boot, and so is the session
        self.dev.boot(FW_A)
        self.dev.after_quote = lambda: self.dev.boot(FW_A)
        v = fleet.run_once(pol, self.d, None, state=self.state)[0]
        self.assertIn("second quote of the cycle", v["credential"])
        # a restart into other code in between: its quote does not say what the verdict says, so no second try with
        # it, even when the policy would admit that code too
        self.conf["allowed"].append({"type": "NSPE", "measurement_value": BAD_NS, "signer_id": SIGNER})
        for other in (FW_B, FW_B_OLD):
            self.dev.boot(FW_A)
            self.dev.lines.clear()
            self.dev.after_quote = lambda: self.dev.boot(other)
            v = fleet.run_once(pol, self.d, None, state=self.state)[0]
            self.assertEqual(v["measurements"]["NSPE"], GOOD_NS)
            self.assertTrue(v["credential"].startswith("provisioning REFUSED: "), v["credential"])
            self.assertNotIn("PQKEMFIN", self.dev.lines)
            self.assertIsNone(self.dev.session)
            self.assertEqual(self.stored(), [])

    def other_verifier_every_quote(self):
        """Another verifier's PQCHAL after each of this gateway's quotes, so the first exchange and its retry fail."""
        def hook():
            self.dev.handle("PQCHAL " + os.urandom(32).hex())
            self.dev.after_quote = hook
        self.dev.after_quote = hook
        self.addCleanup(setattr, self.dev, "after_quote", None)
        self.addCleanup(setattr, fleet, "BUSY_BACKOFF_S", fleet.BUSY_BACKOFF_S)
        fleet.BUSY_BACKOFF_S = (0, 0)

    def into_renewal_window(self):
        path = os.path.join(self.state, "credentials", "dev.json")
        with open(path) as f:
            m = json.load(f)
        m["body"]["expires"] = int(__import__("time").time()) + 200     # renewed five minutes before the end
        with open(path, "w") as f:
            json.dump(m, f)

    def test_refused_renewal_keeps_a_working_session(self):
        """A renewal displaced twice by another verifier's quotes: the session made from an earlier admitted quote still
        works and is kept until it expires (pc-verifier.md: an established session is not touched)."""
        _, cs = self.cycle()
        self.assertTrue(cs.startswith("issued session "), cs)
        session = self.dev.session
        self.into_renewal_window()
        self.other_verifier_every_quote()
        v = fleet.run_once({"endpoints": [self.conf]}, self.d, None, state=self.state)[0]
        self.assertTrue(v["admitted"])
        self.assertTrue(v["credential"].startswith("provisioning REFUSED: "), v["credential"])
        self.assertIn("stored session kept until it expires", v["credential"])
        self.assertEqual(self.dev.lines[-4:], ["PQCHAL", "PQKEMINIT", "PQCHAL", "PQKEMINIT"])
        self.assertEqual(self.stored(), ["dev.json", "dev.session"])
        self.assertEqual(self.dev.session, session)
        with open(os.path.join(self.state, "credentials", "dev.session"), "rb") as f:
            self.assertEqual(fleet.heartbeat(self.conf, f.read())[1], 1)     # and it still works
        # the next cycle renews it once nobody is in between
        self.dev.after_quote = None
        _, cs = self.cycle()
        self.assertTrue(cs.startswith("issued session "), cs)

    def test_refused_renewal_deletes_an_unusable_session(self):
        _, cs = self.cycle()
        self.assertTrue(cs.startswith("issued session "), cs)
        self.dev.boot(FW_A)                                 # the session was in RAM: the heartbeat fails
        self.other_verifier_every_quote()
        v = fleet.run_once({"endpoints": [self.conf]}, self.d, None, state=self.state)[0]
        self.assertTrue(v["credential"].startswith("provisioning REFUSED: "), v["credential"])
        self.assertIn("no-session", v["credential"])
        self.assertEqual(self.stored(), [])

    def test_malformed_kem_key_reply_refused_in_bound_mode(self):
        """Any answer to PQKEMINIT that is not the signed continuation of the quote is refused the same way, and
        follows the same rule for the stored session."""
        ek_hex = "00" * 1184
        for bad in ("ERR sign", "PQKEMEK 1184 %s 3309 zz END" % ek_hex, "PQKEMEK 1183 %s 3309 %s END" % (
                ek_hex[2:], "00" * 3309), "PQKEMEK 1184 %s END" % ek_hex):
            with self.subTest(bad=bad[:20]):
                self.dev.rewrite = lambda line, reply, bad=bad: bad if line.startswith("PQKEMINIT") else reply
                v = self.attest()
                self.dev.lines.clear()
                self.assert_refused(self.step(v), "")
        # with a working session in its renewal window: kept
        self.dev.rewrite = None
        _, cs = self.cycle()
        self.assertTrue(cs.startswith("issued session "), cs)
        self.into_renewal_window()
        self.dev.rewrite = lambda line, reply: "PQKEMEK 1184 zz 1 00 END" if line.startswith("PQKEMINIT") else reply
        _, cs = self.cycle()
        self.assertEqual(cs, "provisioning REFUSED: KEM key or signature is not hex (stored session kept until it "
                             "expires)")
        self.assertEqual(self.stored(), ["dev.json", "dev.session"])
        # without the policy key a malformed reply is an ordinary failure, as before
        del self.conf["transcript"]
        os.remove(os.path.join(self.state, "credentials", "dev.json"))
        _, cs = self.cycle()
        self.assertEqual(cs, "provisioning failed: KEM key or signature is not hex")

    def test_second_quote_not_admitted_quarantines_the_cycle(self):
        """The endpoint restarts into code the policy does not admit between the two quotes of a cycle: the cycle's
        verdict is the later one, enforced again, with its reasons in the journal line, and no session is kept."""
        _, cs = self.cycle()
        self.assertTrue(cs.startswith("issued session "), cs)
        self.into_renewal_window()
        log = os.path.join(self.d, "enforced")
        pol = {"endpoints": [self.conf], "enforce_cmd": [
            sys.executable, "-c", "import sys; open(%r, 'a').write(' '.join(sys.argv[1:]) + '\\n')" % log]}
        self.dev.after_quote = lambda: self.dev.boot(FW_B)     # BAD_NS is not allowed
        self.addCleanup(setattr, fleet, "BUSY_BACKOFF_S", fleet.BUSY_BACKOFF_S)
        fleet.BUSY_BACKOFF_S = (0, 0)
        v = fleet.run_once(pol, self.d, None, state=self.state)[0]
        self.assertFalse(v["admitted"])
        self.assertTrue(any(r.startswith("second quote of the cycle not admitted: ") and "NSPE" in r
                            for r in v["reasons"]), v["reasons"])
        self.assertTrue(v["credential"].startswith("revoked: provisioning REFUSED"), v["credential"])
        self.assertEqual(self.stored(), [])
        self.assertNotIn("PQKEMFIN", self.dev.lines[-3:])
        with open(log) as f:
            self.assertEqual(f.read().split("\n"), ["dev admit", "dev quarantine", ""])
        self.assertEqual(v["enforcement"], "ok")
        line, _ = fleet.journal_line(v)
        self.assertIn(" QUARANTINED ", line)
        self.assertIn("second quote of the cycle not admitted", line)

    def test_second_quote_not_admitted_is_never_continued(self):
        """credential_step on its own: a second verdict that is not admitted, though it carries a valid quote with the
        same measurements (here: refused for a reason outside the measurements), gets no exchange."""
        v = self.attest()
        self.dev.ask("PQCHAL " + os.urandom(32).hex())      # the first exchange will fail

        def requote():
            again = self.attest()
            again["admitted"], again["reasons"] = False, ["profile is not what the policy pins"]
            return again
        self.dev.lines.clear()
        cs = fleet.credential_step(self.conf, v, self.d, state=self.state, requote=requote)
        self.assertTrue(cs.startswith("revoked: "), cs)
        self.assertEqual(self.dev.lines, ["PQKEMINIT", "PQCHAL"])
        self.assertIsNone(self.dev.session)
        self.assertFalse(v["admitted"])
        self.assertIn("second quote of the cycle not admitted: profile is not what the policy pins", v["reasons"])

    def test_exchange_before_the_quote_refused(self):
        """The pieces in the wrong order: someone gets the KEM key signed for the gateway's challenge before the quote
        exists, and plays it to the gateway afterwards."""
        challenge = os.urandom(32)
        early = self.dev.ask("PQKEMINIT " + challenge.hex())
        real = fleet.secrets.token_bytes
        fleet.secrets.token_bytes = lambda n: challenge
        try:
            v = self.attest()
        finally:
            fleet.secrets.token_bytes = real
        self.assertEqual(v["quote"]["challenge"], challenge.hex())
        self.dev.rewrite = lambda line, reply: early if line.startswith("PQKEMINIT") else reply
        self.assert_refused(self.step(v), "the endpoint answered the unbound exchange")

    def test_replayed_kem_key_refused(self):
        _, cs = self.cycle()
        self.assertTrue(cs.startswith("issued session "), cs)
        recorded = self.dev.replies[1][1]                   # a KEM key signed over the first cycle's transcript
        self.assertTrue(recorded.startswith("PQKEMEK "))
        self.dev.boot(FW_A)
        self.dev.lines.clear()
        v = self.attest()
        self.dev.rewrite = lambda line, reply: recorded if line.startswith("PQKEMINIT") else reply
        self.assert_refused(self.step(v), "not signed over the transcript of the quote just appraised")

    def test_replayed_confirmation_refused(self):
        _, cs = self.cycle()
        recorded = self.dev.replies[2][1]
        self.assertTrue(recorded.startswith("PQKEMOK "))
        self.dev.boot(FW_A)
        v = self.attest()
        self.dev.rewrite = lambda line, reply: recorded if line.startswith("PQKEMFIN") else reply
        cs = self.step(v)
        self.assertEqual(cs, "provisioning failed: key confirmation failed (after heartbeat failure: no heartbeat: "
                             "'ERR pq no-session')")
        v, cs = self.cycle()                                # and the gateway did not keep that session
        self.assertEqual(cs.split(" (")[0], "provisioning failed: key confirmation failed")

    def test_confirmation_made_the_old_way_refused(self):
        self.dev.boot(FW_OLD_CONFIRM)                       # signs the transcript, then confirms without it
        _, cs = self.cycle()
        self.assertEqual(cs, "provisioning failed: key confirmation failed")
        self.assertEqual(self.stored(), [])

    def test_no_quote_no_bound_exchange(self):
        for quote in (None, {}, {"challenge": "zz", "token_sha3_256": "00" * 32}, {"challenge": "00" * 32}):
            with self.assertRaises(fleet.TranscriptRefused):
                fleet.provision(self.conf, self.d, self.gw_sk, "gid", {}, timeout=5, quote=quote)
        self.assertEqual(self.dev.lines, [])                # nothing was sent

    # ---- the policy ----

    def test_policy_v2_refuses_the_old_flow(self):
        self.dev.boot(FW_A_OLD)                             # an allowed image that only knows the old exchange
        v, cs = self.cycle()
        self.assert_refused(cs, "transcript v2 required")
        self.assertNotIn("session_binding", v)

    def test_without_the_policy_key_the_old_flow_works_and_is_marked_weaker(self):
        del self.conf["transcript"]
        self.dev.boot(FW_A_OLD)
        v, cs = self.cycle()
        self.assertTrue(cs.startswith("issued session "), cs)
        self.assertIn("[unbound: the session is not tied to the attestation", cs)
        self.assertIn("weaker", cs)
        self.assertEqual(v["session_binding"], "unbound")
        v["credential"] = cs
        line, prio = fleet.journal_line(v)
        self.assertEqual(prio, fleet.LOG_WARNING)
        self.assertIn("WARNING: session issued unbound", line)
        # the nonce of the old exchange is random, not the challenge
        self.assertNotEqual(self.dev.replies[1][0], "PQKEMINIT " + v["quote"]["challenge"])
        v, cs = self.cycle()
        self.assertTrue(cs.startswith("valid, heartbeat 1 (uptime_s=1;link=1;fw=test) [unbound"), cs)
        self.assertEqual(v["session_binding"], "unbound")
        self.assertIsNone(fleet.journal_line(dict(v, credential=cs))[1])   # the warning priority once per session

    def test_without_the_policy_key_an_upgraded_endpoint_is_still_unbound(self):
        """The policy decides, not the endpoint: no key, no bound exchange, even where the firmware could."""
        del self.conf["transcript"]
        v, cs = self.cycle()
        self.assertIn("[unbound", cs)
        self.assertNotEqual(self.dev.replies[1][0], "PQKEMINIT " + v["quote"]["challenge"])
        with open(os.path.join(self.state, "credentials", "dev.json")) as f:
            m = json.load(f)
        self.assertIsNone(m["transcript"])
        self.assertNotIn("transcript_sha3_256", m["body"])
        with open(os.path.join(self.state, "credentials", "dev.session"), "rb") as f:
            self.assertEqual(f.read(), self.dev.session)

    def test_stored_unbound_session_is_replaced_when_the_policy_asks_for_the_transcript(self):
        del self.conf["transcript"]
        _, cs = self.cycle()
        self.assertIn("[unbound", cs)
        unbound_key = self.dev.session
        self.conf["transcript"] = "v2"
        v, cs = self.cycle()
        self.assertTrue(cs.startswith("issued session "), cs)
        self.assertIn("(transcript v2)", cs)
        self.assertNotIn("PQHB", self.dev.lines)            # the old session was not asked for a heartbeat
        self.assertNotEqual(self.dev.session, unbound_key)
        self.assertEqual(v["session_binding"], "transcript-v2")

    def test_stored_unbound_session_is_dropped_when_the_endpoint_cannot_bind(self):
        del self.conf["transcript"]
        self.dev.boot(FW_A_OLD)
        _, cs = self.cycle()
        self.assertEqual(sorted(self.stored()), ["dev.json", "dev.session"])
        self.conf["transcript"] = "v2"
        _, cs = self.cycle()
        self.assertTrue(cs.startswith("provisioning REFUSED: transcript v2 required"), cs)
        self.assertIn("stored session is unbound, the policy asks for transcript-v2", cs)
        self.assertEqual(self.stored(), [])

    def test_policy_value_checked_before_the_endpoint_is_asked(self):
        self.conf["transcript"] = "v3"
        v = fleet.attest(self.conf, None, self.d, timeout=5)
        self.assertFalse(v["admitted"])
        self.assertEqual(v["reasons"], ["policy: unknown transcript 'v3' (known: v2)"])
        self.assertEqual(self.dev.lines, [])
        self.assertEqual(fleet.policy_errors({"name": "x", "iak_pub_pem": "k.pem", "transcript": "v2"}),
                         ["policy: transcript v2 needs a post-quantum kind (aegis-pq, aegis-linux, aegis-device, aegis-tee)"])
        with self.assertRaises(ValueError):
            fleet.provision(self.conf, self.d, self.gw_sk, "gid", {}, timeout=5, quote={})

    def test_check_names_the_binding(self):
        other = dict(self.conf, name="old")
        del other["transcript"]
        pol = os.path.join(self.d, "fleet.json")
        with open(pol, "w") as f:
            json.dump({"endpoints": [self.conf, other]}, f)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(fleet.main(["check", pol, "--platform", "polarfire", "--state-dir", self.state]), 0)
        text = out.getvalue()
        self.assertIn("  session bound to the attestation (transcript v2 required; the unbound exchange is refused)", text)
        self.assertIn("  session unbound: the session is not tied to the attestation", text)

    # ---- both platforms, through the command line ----

    def run_main(self, platform):
        entry = dict(self.conf)
        if platform == "linux":         # a host issues credentials only where the policy names its key as the pinned one
            entry["verifier_pin_sha256"] = hashlib.sha256(self.gw_pk).hexdigest()
        pol = os.path.join(self.d, "fleet.json")
        with open(pol, "w") as f:
            json.dump({"endpoints": [entry]}, f)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = fleet.main(["once", pol, "--platform", platform, "--state-dir", self.state])
        self.assertEqual(rc, 0)
        return json.loads(out.getvalue())[0]

    def test_both_platforms_accept_the_transcript_and_refuse_the_swap(self):
        for platform in ("polarfire", "linux"):
            with self.subTest(platform=platform):
                self.setUp()
                v = self.run_main(platform)
                self.assertTrue(v["admitted"], v)
                self.assertTrue(v["credential"].startswith("issued session "), v["credential"])
                self.assertEqual(v["session_binding"], "transcript-v2")
                self.assertTrue(self.run_main(platform)["credential"].startswith("valid, heartbeat 1"))
                # the swap, between the quote and the exchange of one cycle
                self.dev.boot(FW_A)
                self.dev.after_quote = lambda: self.dev.boot(FW_B_OLD)
                v = self.run_main(platform)
                # the first quote was firmware A's, and good; the second quote of the cycle, taken when the exchange
                # was refused, is firmware B's, which the policy does not admit: that is the cycle's verdict
                self.assertFalse(v["admitted"], v)
                self.assertIn("second quote of the cycle not admitted", v["reasons"][-1])
                self.assertTrue(v["credential"].startswith("revoked: provisioning REFUSED (transcript v2 required"),
                                v["credential"])
                self.assertNotIn("session_binding", v)
                self.assertEqual(self.stored(), [])
                self.assertIsNone(self.dev.session)
                # and without the policy key the same swap goes through: the reason for the key
                del self.conf["transcript"]
                self.dev.boot(FW_A)
                self.dev.after_quote = lambda: self.dev.boot(FW_B_OLD)
                v = self.run_main(platform)
                self.assertTrue(v["credential"].startswith("issued session "), v["credential"])
                self.assertEqual(v["session_binding"], "unbound")
                self.assertEqual(self.dev.fw, FW_B_OLD)     # the session is with firmware B, the verdict was about A
                self.assertIsNotNone(self.dev.session)

    # ---- what it does not do ----

    def test_limit_a_firmware_that_holds_the_key_and_lies_is_accepted(self):
        """Not a defence, a boundary, kept as a test so that nobody reads more into the transcript than it says: an
        image that holds the device key can sign a transcript for a quote another image made (the quote went over the
        network in the clear). Every honest image, old or new, refuses to; a hostile one that has the key could forge
        the quote itself just as well. Closing this needs a key that depends on the measured code."""
        v = self.attest()
        self.dev.boot(FW_B)
        self.dev.lie = (bytes.fromhex(v["quote"]["challenge"]), bytes.fromhex(v["quote"]["token_sha3_256"]))
        cs = self.step(v)
        self.assertTrue(cs.startswith("issued session "), cs)


KAT = ("cf21233c122f704a1c13f51026168c2bc4abdf4b57961cf7ece79769f18d4d3c",
       "1faf9dfa6b352ada926f6449ddf8eed88166f565ec108bd7edd1295f5052c529",
       "69a5835395676b27b7a4162e4d507d59ee10784f769fb804b6a5974315ab71c4")

if __name__ == "__main__":
    unittest.main()

# SPDX-License-Identifier: Apache-2.0
"""The PC verifier's identity key sealed to a TPM 2.0 (common/keystore.py, aegisd --key-store).

Against swtpm (the libtpms simulator; apt install swtpm, pip install tpm2-pytss), skipped cleanly without them:
the key is never on disk in the clear, the state directory copied to another TPM is useless, an altered file is
refused, a PCR-bound seal stops working when the PCR changes, a TPM with an owner password is refused, and the quote
says where the key lives. Without a TPM the key falls back to a 0600 file and says so.

Against this machine's TPM (/dev/tpmrm0, when this user can open it): the same round trip, no persistent handle left
behind, and a blob sealed by the real TPM cannot be unsealed on the simulator."""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

os.environ.setdefault("TSS2_LOG", "all+NONE")   # the TPM refusals below are expected; keep ESYS quiet
ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
for p in ("common", "host", "gateway/aegisd", "gateway/sysserv"):
    sys.path.insert(0, os.path.abspath(os.path.join(ROOT, p)))

import aegisd  # noqa: E402
import aegis_verify as av  # noqa: E402
import keystore  # noqa: E402
import mldsa  # noqa: E402
import test_linux_host_verifier as tl  # noqa: E402

try:
    import tpm2_pytss  # noqa: F401
    HAVE_PYTSS = True
except ImportError:
    HAVE_PYTSS = False
HAVE_SWTPM = HAVE_PYTSS and shutil.which("swtpm") is not None


def _free_port_pair():
    for _ in range(50):
        with socket.socket() as a:
            a.bind(("127.0.0.1", 0))
            p = a.getsockname()[1]
        if p >= 65535:
            continue
        try:
            with socket.socket() as b:
                b.bind(("127.0.0.1", p + 1))
            return p
        except OSError:
            continue
    raise RuntimeError("no free port pair")


class Swtpm:
    """A fresh simulated TPM (its own seeds, so its own SRK) for the life of the object."""

    def __init__(self):
        self.dir = tempfile.mkdtemp()
        self.port = _free_port_pair()
        self.proc = subprocess.Popen(
            ["swtpm", "socket", "--tpm2", "--tpmstate", "dir=" + self.dir,
             "--server", "type=tcp,port=%d,bindaddr=127.0.0.1" % self.port,
             "--ctrl", "type=tcp,port=%d,bindaddr=127.0.0.1" % (self.port + 1),
             "--flags", "not-need-init,startup-clear"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.tcti = "swtpm:host=127.0.0.1,port=%d" % self.port
        deadline = time.monotonic() + 10
        while True:
            try:
                socket.create_connection(("127.0.0.1", self.port), 0.2).close()
                break
            except OSError:
                if time.monotonic() > deadline or self.proc.poll() is not None:
                    self.close()
                    raise RuntimeError("swtpm did not start")
                time.sleep(0.05)

    def esapi(self):
        return tpm2_pytss.ESAPI(self.tcti)

    def close(self):
        self.proc.kill()
        self.proc.wait()
        shutil.rmtree(self.dir, ignore_errors=True)


def state_files(state):
    out = {}
    for root, _, files in os.walk(state):
        for n in files:
            with open(os.path.join(root, n), "rb") as f:
                out[os.path.relpath(os.path.join(root, n), state)] = f.read()
    return out


def serve(state, hw, tcti):
    ready, port = threading.Event(), []
    threading.Thread(target=aegisd.serve, args=(state, 0, hw),
                     kwargs={"ready": lambda p: (port.append(p), ready.set()), "tcti": tcti}, daemon=True).start()
    ready.wait(10)
    return port[0]


@unittest.skipUnless(HAVE_SWTPM, "needs swtpm and tpm2-pytss")
class SealedToSimulator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tpm, cls.other = Swtpm(), Swtpm()
        cls.hw = tl.host()
        cls.state = tempfile.mkdtemp()
        cls.rec = aegisd.init_identity(cls.state, cls.hw, key_store="auto", tcti=cls.tpm.tcti)
        cls.pk = bytes.fromhex(cls.rec["body"]["pk"])

    @classmethod
    def tearDownClass(cls):
        cls.tpm.close()
        cls.other.close()

    def copy_state(self):
        d = tempfile.mkdtemp()
        for n, data in state_files(self.state).items():
            with open(os.path.join(d, n), "wb") as f:
                f.write(data)
        return d

    def test_identity_names_the_tpm(self):
        body = self.rec["body"]
        self.assertEqual(body["key_store"], "tpm2-sealed")
        self.assertIn("TPM 2.0 (IBM", body["key_storage"])          # swtpm reports manufacturer IBM
        self.assertEqual(body["key_store_tpm"]["pcrs"], "")
        self.assertTrue(aegisd.mldsa.verify(self.pk, aegisd.wire.LABEL_IDENTITY, aegisd.wire.canonical(body),
                                            bytes.fromhex(self.rec["sig"])))

    def test_key_never_on_disk_in_the_clear(self):
        _, sk = aegisd.load_identity(self.state, self.tpm.tcti)
        self.assertTrue(mldsa.verify(self.pk, b"l", b"m", mldsa.sign(sk, b"l", b"m")))
        files = state_files(self.state)
        self.assertEqual(sorted(files), ["identity.json", "identity.tpm.json"])
        self.assertEqual(os.stat(os.path.join(self.state, "identity.tpm.json")).st_mode & 0o777, 0o600)
        for name, data in files.items():
            self.assertNotIn(sk, data, name)
            self.assertNotIn(sk.hex().encode(), data, name)

    def test_quote_says_where_the_key_lives(self):
        port = serve(self.state, self.hw, self.tpm.tcti)
        enrolled = av.enroll("127.0.0.1", port, store=tempfile.mkdtemp())[1]
        resp, nonce, elapsed = av.fresh_quote("127.0.0.1", port)
        ok, reasons = av.check_quote(enrolled, resp, nonce, elapsed)
        self.assertTrue(ok, reasons)
        m = resp["body"]["measurements"]
        self.assertEqual(m["key_store"], "tpm2-sealed")
        self.assertEqual(m["key_store_tpm_srk_name"], self.rec["body"]["key_store_tpm"]["srk_name"])

    def test_state_on_another_tpm_is_useless(self):
        """Disk theft, or a copy to another machine: the other TPM has another owner seed, so another SRK."""
        d = self.copy_state()
        with self.assertRaisesRegex(keystore.TpmError, "sealed to another TPM"):
            aegisd.load_identity(d, self.other.tcti)
        with open(os.path.join(d, "identity.tpm.json")) as f:
            sealed = json.load(f)
        with self.assertRaisesRegex(keystore.TpmError, "integrity check failed"):   # the TPM itself refuses it
            keystore.unseal(sealed, self.other.tcti, check_srk=False)

    def test_altered_files_refused(self):
        d = self.copy_state()
        path = os.path.join(d, "identity.tpm.json")
        with open(path) as f:
            good = json.load(f)
        for field, fn in (("ciphertext", lambda h: h[:-2] + ("00" if h[-2:] != "00" else "01")),
                          ("private", lambda h: h[:-2] + ("00" if h[-2:] != "00" else "01")),
                          ("pk_sha256", lambda h: "00" * 32)):
            bad = dict(good, **{field: fn(good[field])})
            with open(path, "w") as f:
                json.dump(bad, f)
            with self.assertRaises(keystore.TpmError, msg=field):
                aegisd.load_identity(d, self.tpm.tcti)

    def test_fleet_loads_the_sealed_key(self):
        import fleet
        old = os.environ.get("AEGIS_TPM_TCTI")
        os.environ["AEGIS_TPM_TCTI"] = self.tpm.tcti
        try:
            sk, gid = fleet.load_gateway_identity(self.state)
        finally:
            if old is None:
                del os.environ["AEGIS_TPM_TCTI"]
            else:
                os.environ["AEGIS_TPM_TCTI"] = old
        self.assertEqual(gid, aegisd.wire.digest(self.rec["body"]))
        self.assertTrue(mldsa.verify(self.pk, b"l", b"m", mldsa.sign(sk, b"l", b"m")))

    def test_existing_identity_kept_without_force(self):
        with self.assertRaises(SystemExit):
            aegisd.init_identity(self.state, self.hw, key_store="tpm", tcti=self.tpm.tcti)

    def test_pcr_bound_seal_stops_working_when_the_pcr_changes(self):
        sealed = keystore.seal(b"k" * 32, pcrs=[16], tcti=self.tpm.tcti)
        self.assertEqual(sealed["pcrs"], "sha256:16")
        self.assertEqual(keystore.unseal(sealed, self.tpm.tcti), b"k" * 32)
        with self.tpm.esapi() as e:        # the simulator only: PCR 16 is the debug PCR
            e.pcr_event(tpm2_pytss.ESYS_TR.PCR16, b"changed")
        with self.assertRaisesRegex(keystore.TpmError, "policy"):
            keystore.unseal(sealed, self.tpm.tcti)

    def test_pcr_bound_identity(self):
        state = tempfile.mkdtemp()
        rec = aegisd.init_identity(state, self.hw, key_store="tpm", pcrs=[23], tcti=self.tpm.tcti)
        self.assertEqual(rec["body"]["key_store_tpm"]["pcrs"], "sha256:23")
        _, _, claims = aegisd.load_identity_claims(state, self.tpm.tcti)
        self.assertEqual(claims["key_store_tpm_pcrs"], "sha256:23")

    def test_too_much_to_seal(self):
        with self.assertRaises(ValueError):
            keystore.seal(b"x" * 129, tcti=self.tpm.tcti)
        with self.assertRaises(ValueError):
            keystore.seal(b"x", pcrs=[24], tcti=self.tpm.tcti)


@unittest.skipUnless(HAVE_SWTPM, "needs swtpm and tpm2-pytss")
class OwnerPasswordRefused(unittest.TestCase):
    def test_owner_password_means_no_tpm(self):
        tpm = Swtpm()
        try:
            with tpm.esapi() as e:     # the simulator only: never done to a real TPM
                e.hierarchy_change_auth(tpm2_pytss.ESYS_TR.OWNER, b"set-by-someone-else")
            ok, why, _ = keystore.tpm_status(tpm.tcti)
            self.assertFalse(ok)
            self.assertIn("owner hierarchy has a password", why)
            with self.assertRaises(SystemExit):
                aegisd.init_identity(tempfile.mkdtemp(), tl.host(), key_store="tpm", tcti=tpm.tcti)
            rec = aegisd.init_identity(tempfile.mkdtemp(), tl.host(), key_store="auto", tcti=tpm.tcti)
            self.assertEqual(rec["body"]["key_store"], "software-file")
            self.assertIn("owner hierarchy has a password", rec["body"]["key_storage"])
        finally:
            tpm.close()


class SoftwareFallback(unittest.TestCase):
    """No TPM: the key is a 0600 file and the identity and quote say so."""

    def test_no_tpm_falls_back_and_says_so(self):
        state, hw = tempfile.mkdtemp(), tl.host()
        rec = aegisd.init_identity(state, hw, key_store="auto", tcti="device:/nonexistent/tpmrm0")
        body = rec["body"]
        self.assertEqual(body["key_store"], "software-file")
        self.assertIn("no TPM", body["key_storage"])
        self.assertIn("weaker", body["key_storage"])
        self.assertNotIn("key_store_tpm", body)
        self.assertEqual(os.stat(os.path.join(state, "identity.sk")).st_mode & 0o777, 0o600)
        port = serve(state, hw, None)
        resp, _, _ = av.fresh_quote("127.0.0.1", port)
        self.assertEqual(resp["body"]["measurements"]["key_store"], "software-file")

    def test_tpm_demanded_but_absent(self):
        with self.assertRaises(SystemExit):
            aegisd.init_identity(tempfile.mkdtemp(), tl.host(), key_store="tpm", tcti="device:/nonexistent/tpmrm0")


def _real_tpm():
    if not HAVE_PYTSS or os.environ.get("AEGIS_TPM_TCTI"):
        return False
    return keystore.tpm_status("device:/dev/tpmrm0")[0]


def _persistent_handles(tcti):
    with tpm2_pytss.ESAPI(tcti) as e:
        _, data = e.get_capability(tpm2_pytss.TPM2_CAP.HANDLES, 0x81000000, 256)
        return sorted(int(h) for h in data.data.handles)


@unittest.skipUnless(_real_tpm(), "needs this user to open /dev/tpmrm0 (group tss) and a TPM without owner password")
class SealedToThisMachinesTpm(unittest.TestCase):
    """Creates only transient objects under the owner hierarchy; nothing is left in the TPM."""

    TCTI = "device:/dev/tpmrm0"

    def test_round_trip_and_nothing_left_behind(self):
        before = _persistent_handles(self.TCTI)
        state, hw = tempfile.mkdtemp(), tl.host()
        rec = aegisd.init_identity(state, hw, key_store="tpm", tcti=self.TCTI)
        self.assertEqual(rec["body"]["key_store"], "tpm2-sealed")
        _, sk, claims = aegisd.load_identity_claims(state, self.TCTI)
        pk = bytes.fromhex(rec["body"]["pk"])
        self.assertTrue(mldsa.verify(pk, b"l", b"m", mldsa.sign(sk, b"l", b"m")))
        self.assertEqual(claims["key_store"], "tpm2-sealed")
        for name, data in state_files(state).items():
            self.assertNotIn(sk, data, name)
        self.assertEqual(_persistent_handles(self.TCTI), before)

    @unittest.skipUnless(HAVE_SWTPM, "needs swtpm")
    def test_real_tpm_seal_useless_on_the_simulator(self):
        sealed = keystore.seal(b"r" * 32, tcti=self.TCTI)
        self.assertEqual(keystore.unseal(sealed, self.TCTI), b"r" * 32)
        sim = Swtpm()
        try:
            with self.assertRaisesRegex(keystore.TpmError, "sealed to another TPM"):
                keystore.unseal(sealed, sim.tcti)
            with self.assertRaisesRegex(keystore.TpmError, "integrity check failed"):
                keystore.unseal(sealed, sim.tcti, check_srk=False)
        finally:
            sim.close()


if __name__ == "__main__":
    unittest.main()

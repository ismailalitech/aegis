#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Aegis gateway identity and quote service (Phase 1).

  aegisd.py init   [--state DIR]          create the gateway identity (once)
  aegisd.py show   [--state DIR]          print the identity record
  aegisd.py serve  [--state DIR] [--port 7443]

  --platform polarfire | linux | auto (default: polarfire on the board, linux anywhere else)
  --key-store auto | tpm | software    (init, linux only; default auto: the TPM when one is usable)
  --tpm-pcrs 7                         (init with the TPM: also bind the seal to these PCR values)

On an ordinary Linux server or VM (--platform linux) there is no system controller: the identity names the host by
a hash of /etc/machine-id, and the quote carries what the running system reports about itself (this code's hash,
the kernel, the OS release). That is software trust: the key is a file and the measurements come from the system
being measured. With a usable TPM 2.0 (/dev/tpmrm0) the identity key is sealed to it (common/keystore.py): the files
in DIR are useless on another machine, but the key is in this process's memory while it runs, and root on this machine
can unseal it. TPMs do not implement ML-DSA, so the TPM cannot hold the signing key itself. Without a TPM the key is a
0600 file, and the identity and every quote say which ("key_store": "tpm2-sealed" or "software-file").

On the PolarFire, hardware facts come from the PolarFire system controller through the
read-only tool aegis_sysserv.py (serial number, Microchip device certificate,
design info, design digests, security locks). The identity key is ML-DSA-65,
generated in software from the kernel random pool and stored in DIR with mode
0600. On this chip (MPFS095T, non-S) no hardware service can hold or use the
key, so it is protected only by Linux file permissions.

The mpfs-generic-service module is loaded if missing and NEVER unloaded:
its driver has no remove path and an rmmod corrupts the kernel's misc list.
"""
import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
for p in (HERE, os.path.join(HERE, "..", "sysserv"), os.path.join(HERE, "..", "..", "common")):
    sys.path.insert(0, os.path.abspath(p))

import keystore  # noqa: E402
import mldsa  # noqa: E402
import wire  # noqa: E402

DEFAULT_STATE = "/var/lib/aegis"


class HardwareSource:
    """Live system-controller reads on the board."""

    def __init__(self):
        import threading
        import aegis_sysserv
        self.ss = aegis_sysserv
        self.lock = threading.Lock()  # the device allows one opener at a time
        if not os.path.exists(aegis_sysserv.DEVICE):
            subprocess.run(["modprobe", "mpfs-generic-service"], check=True)

    def read(self, name):
        with self.lock:
            return self.ss.call(name)


class LinuxHostSource:
    """An ordinary Linux server or VM: no system controller. Everything here is reported by the running system
    about itself, and the identity and quote say so ("platform": "linux-host")."""

    platform = "linux-host"

    def __init__(self, machine_id_path="/etc/machine-id", os_release_path="/etc/os-release"):
        self.machine_id_path, self.os_release_path = machine_id_path, os_release_path

    def host_id(self):
        """SHA-256 of the machine ID, so the ID itself (which systemd asks to keep private) is not published."""
        with open(self.machine_id_path, "rb") as f:
            mid = f.read().strip()
        if not mid:
            raise ValueError("%s is empty" % self.machine_id_path)
        return hashlib.sha256(b"aegis-host-id-v1\0" + mid).hexdigest()

    def identity_facts(self):
        return {"platform": self.platform, "dsn": self.host_id()[:32]}

    def measurements(self):
        m = {"platform": self.platform, "host_id_sha256": self.host_id(), "machine": os.uname().machine}
        try:
            m["os_release_sha256"] = file_sha256(self.os_release_path)
        except OSError:
            pass
        return m


def pick_platform(name="auto"):
    """polarfire: the system controller's device exists, or this is a RISC-V machine (the module is loaded on
    demand). Anything else is an ordinary Linux host."""
    if name == "auto":
        import aegis_sysserv
        name = "polarfire" if (os.path.exists(aegis_sysserv.DEVICE) or os.uname().machine == "riscv64") else "linux"
    if name == "polarfire":
        return HardwareSource()
    if name == "linux":
        return LinuxHostSource()
    raise ValueError("unknown platform %r" % name)


def device_cert_der(raw):
    n = int.from_bytes(raw[2:4], "big") + 4
    if raw[0] != 0x30 or raw[1] != 0x82 or n > len(raw):
        raise ValueError("device certificate is not a DER SEQUENCE")
    return raw[:n]


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def own_code_sha256():
    files = [os.path.join(HERE, "aegisd.py"),
             os.path.join(HERE, "..", "sysserv", "aegis_sysserv.py"),
             os.path.join(HERE, "..", "..", "common", "mldsa.py"),
             os.path.join(HERE, "..", "..", "common", "keystore.py"),
             os.path.join(HERE, "..", "..", "common", "wire.py")]
    h = hashlib.sha256()
    for f in files:
        h.update(file_sha256(f).encode())
    return h.hexdigest()


def pick_key_store(name="software", tcti=None):
    """(store, why): "tpm" demands a usable TPM; "auto" falls back to the file and says why."""
    if name == "software":
        return keystore.SOFTWARE, "--key-store software"
    ok, why, _ = keystore.tpm_status(tcti)
    if ok:
        return keystore.TPM, ""
    if name == "tpm":
        raise SystemExit("no usable TPM: %s" % why)
    if name != "auto":
        raise ValueError("unknown key store %r" % name)
    return keystore.SOFTWARE, why


def key_storage_text(where, why=""):
    if where["key_store"] == keystore.TPM:
        tpm = where["tpm"]
        return ("TPM 2.0 (%s, firmware %s): ML-DSA-65 key encrypted under a key sealed to this TPM (fixedTPM, owner "
                "SRK %s...%s); unsealed into aegisd's memory at start. Not usable off this machine; root on it can "
                "unseal it" % (tpm["manufacturer"], tpm["firmware"], tpm["srk_name"][:16],
                               ", PCR policy " + tpm["pcrs"] if tpm["pcrs"] else ""))
    return "software, Linux file mode 0600 (no TPM: %s), weaker than a TPM-sealed key" % (why or "none")


def init_identity(state, hw, force=False, key_store="software", pcrs=None, tcti=None):
    os.makedirs(state, mode=0o700, exist_ok=True)
    if keystore.stored_where(state) and not force:
        raise SystemExit("identity exists in %s (use --force to replace)" % state)
    pk, sk = mldsa.keypair()
    if hasattr(hw, "identity_facts"):       # a host without a system controller (LinuxHostSource)
        store, why = pick_key_store(key_store, tcti)
        where = keystore.save(state, sk, pk, store, pcrs, tcti)
        body = {"v": 1, "type": "identity", **hw.identity_facts(), "pk_alg": "ML-DSA-65", "pk": pk.hex(),
                "key_store": where["key_store"], "key_storage": key_storage_text(where, why)}
        if where["key_store"] == keystore.TPM:
            body["key_store_tpm"] = where["tpm"]
        rec = {"body": body, "sig": mldsa.sign(sk, wire.LABEL_IDENTITY, wire.canonical(body)).hex()}
    else:
        if key_store == "tpm":
            raise SystemExit("--key-store tpm: the PolarFire gateway has no TPM")
        cert = device_cert_der(hw.read("device_cert"))
        body = {
            "v": 1,
            "type": "identity",
            "dsn": hw.read("serial").hex(),
            "device_cert_sha256": hashlib.sha256(cert).hexdigest(),
            "design_info": hw.read("design_info").hex(),
            "pk_alg": "ML-DSA-65",
            "pk": pk.hex(),
            "key_storage": "software, Linux file mode 0600 (no hardware key service on MPFS095T non-S)",
        }
        rec = {"body": body, "sig": mldsa.sign(sk, wire.LABEL_IDENTITY, wire.canonical(body)).hex(),
               "device_cert": cert.hex()}
        keystore.save(state, sk, pk, keystore.SOFTWARE)
    with open(os.path.join(state, "identity.json"), "w") as f:
        json.dump(rec, f, indent=1)
    return rec


def load_identity(state, tcti=None):
    rec, sk, _ = load_identity_claims(state, tcti)
    return rec, sk


def load_identity_claims(state, tcti=None):
    """(record, secret key, claims about where the key was loaded from, for the quote)."""
    with open(os.path.join(state, "identity.json")) as f:
        rec = json.load(f)
    pk = bytes.fromhex(rec["body"]["pk"]) if "pk" in rec.get("body", {}) else None
    sk, claims = keystore.load(state, pk, tcti)
    return rec, sk, claims


def measurements(hw, key_claims=None):
    if hasattr(hw, "measurements"):
        m = dict(hw.measurements(), aegisd_code_sha256=own_code_sha256(), **(key_claims or {}))
    else:
        m = {
            "design_info": hw.read("design_info").hex(),
            "usercode": hw.read("usercode").hex(),
            "security_locks": hw.read("security").hex(),
            "design_digests_sha256": hashlib.sha256(hw.read("digest")).hexdigest(),
            "aegisd_code_sha256": own_code_sha256(),
        }
    try:
        m["kernel"] = os.uname().release
        with open("/proc/sys/kernel/random/boot_id") as f:
            m["boot_id"] = f.read().strip()
    except OSError:
        pass
    return m


def make_quote(rec, sk, hw, nonce_hex, key_claims=None):
    nonce = bytes.fromhex(nonce_hex)
    if len(nonce) != 32:
        raise ValueError("nonce must be 32 bytes")
    body = {
        "v": 1,
        "type": "quote",
        "nonce": nonce.hex(),
        "identity_sha256": wire.digest(rec["body"]),
        "measurements": measurements(hw, key_claims),
        "gw_monotonic_s": round(time.monotonic(), 3),
    }
    return {"body": body, "sig": mldsa.sign(sk, wire.LABEL_QUOTE, wire.canonical(body)).hex()}


def handle(conn, rec, sk, hw, key_claims=None):
    req = wire.recv(conn)
    kind = req.get("type")
    if kind == "identity":
        wire.send(conn, rec)
    elif kind == "quote":
        wire.send(conn, make_quote(rec, sk, hw, str(req.get("nonce", "")), key_claims))
    else:
        wire.send(conn, {"error": "unknown request"})


MAX_CLIENTS = 8
CLIENT_TIMEOUT_S = 3


def _serve_one(conn, rec, sk, hw, slots, key_claims=None):
    try:
        conn.settimeout(CLIENT_TIMEOUT_S)
        handle(conn, rec, sk, hw, key_claims)
    except Exception as e:  # one bad client must not stop the service
        try:
            wire.send(conn, {"error": str(e)})
        except OSError:
            pass
    finally:
        conn.close()
        slots.release()


def serve(state, port, hw, once=False, ready=None, tcti=None):
    """One thread per connection, at most MAX_CLIENTS at a time, each with a short timeout, so
    a slow or half-open client cannot block quotes for others (found by tests/redteam)."""
    import threading
    rec, sk, claims = load_identity_claims(state, tcti)
    if not hasattr(hw, "measurements"):
        claims = None     # the PolarFire gateway's quote stays as its verifiers enrolled it (its key_storage says)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(16)
    if ready:
        ready(srv.getsockname()[1])
    slots = threading.BoundedSemaphore(MAX_CLIENTS)
    while True:
        conn, peer = srv.accept()
        if not slots.acquire(blocking=False):
            conn.close()  # too many clients at once: refuse instead of queueing
            continue
        th = threading.Thread(target=_serve_one, args=(conn, rec, sk, hw, slots, claims), daemon=True)
        th.start()
        if once:
            th.join()
            break
    srv.close()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Aegis gateway identity and quote service")
    ap.add_argument("cmd", choices=["init", "show", "serve"])
    ap.add_argument("--state", default=DEFAULT_STATE)
    ap.add_argument("--port", type=int, default=7443)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--platform", choices=["auto", "polarfire", "linux"], default="auto")
    ap.add_argument("--key-store", choices=["auto", "tpm", "software"], default="auto",
                    help="init on linux: where the identity key lives (auto: the TPM if usable, else a 0600 file)")
    ap.add_argument("--tpm-pcrs", default="", help="init with the TPM: comma-separated sha256 PCRs the seal requires "
                    "(their values now); a firmware or boot change then makes the key unusable until a new init")
    a = ap.parse_args(argv)
    if a.cmd == "show":
        with open(os.path.join(a.state, "identity.json")) as f:
            rec = json.load(f)
        body = dict(rec["body"], pk=rec["body"]["pk"][:32] + "...")
        print(json.dumps(body, indent=1))
        return 0
    hw = pick_platform(a.platform)
    if a.cmd == "init":
        pcrs = [int(p) for p in a.tpm_pcrs.split(",") if p.strip()]
        rec = init_identity(a.state, hw, a.force, a.key_store, pcrs)
        print("identity created, sha256", wire.digest(rec["body"]))
        print("key store:", rec["body"]["key_storage"])
        return 0
    serve(a.state, a.port, hw)
    return 0


if __name__ == "__main__":
    sys.exit(main())

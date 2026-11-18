#!/usr/bin/env python3
"""Aegis prover for a Linux endpoint (first: a Digilent Zybo Z7-10, Zynq-7010), kind "aegis-linux".

The same line protocol as the STM32 prover, TCP 7444, one request per connection:
  PQKEY                    -> PQKEY <len> <hex> END                       this endpoint's ML-DSA-65 public key
  PQCHAL <32-byte hex>     -> PQTOKEN <len> <claims> <len> <sig> END     claims signed with ML-DSA-65
  PQKEMINIT <nonce>        -> PQKEMEK <len> <ek> <len> <sig> END          fresh ML-KEM-768 key, signed
  PQKEMFIN <ct> <cred>     -> PQKEMOK <tag> END | ERR cred <reason>       credential checked, session kept
  PQHB <nonce>             -> PQHB <status> <counter> <tag> END           KMAC256 over the session
  PQSESSION                -> PQSESSION <session id> <credential hash> END

What this endpoint is, and is not: the Zynq-7000 has no PUF, and its hardware keys are in eFUSEs that can be written
once, which this project does not touch. So the ML-DSA-65 key is generated at first start and kept in a file
(readable by root), and the measurements are SHA-256 hashes of the boot files and of this program, computed by the
running Linux. A modified Linux could report false values. The claims say so (profile aegis-linux-software-v1), and the
gateway labels the verdict "software trust". It is a weaker endpoint than the STM32, on purpose and on record.

  aegis_linux_prover.py --state /var/lib/aegis-prover --gateway-pk gateway.mldsa65.pub \
      --measure BOOT=/boot/boot.bin,/boot/u-boot.img --measure KERNEL=/boot/zImage,/boot/zynq-zybo-z7.dtb \
      [--port 7444] [--heartbeat-mac kmac256]
"""
import argparse
import hashlib
import hmac
import json
import os
import socket
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
for d in (os.path.join(HERE, "common"), os.path.join(HERE, "..", "..", "common")):
    if os.path.isdir(d):
        sys.path.insert(0, d)
import cbor  # noqa: E402
import kmac  # noqa: E402
import mldsa  # noqa: E402
import mlkem  # noqa: E402

VERSION = "0.1.0"
PROFILE = "aegis-linux-software-v1"
QUOTE_LABEL = b"aegis-endpoint-quote-v1"
KEM_INIT_LABEL = b"aegis-kem-init-v1"
CRED_LABEL = b"aegis-credential-v1"
# PSA claim numbers (common/psa_token.py), so the gateway's measurement check applies unchanged
C_PROFILE, C_SWC, C_CHALLENGE, C_INSTANCE = -75000, -75006, -75008, -75009
SWC_TYPE, SWC_VALUE, SWC_VERSION, SWC_SIGNER, SWC_DESC = 1, 2, 4, 5, 6
T0 = time.monotonic()


def sha3(*parts):
    return hashlib.sha3_256(b"".join(parts)).digest()


def load_or_create_key(state):
    """The ML-DSA-65 key pair, created at first start (software key: see the module text)."""
    os.makedirs(state, mode=0o700, exist_ok=True)
    skf, pkf = os.path.join(state, "mldsa65.sk"), os.path.join(state, "mldsa65.pub")
    if not os.path.exists(skf):
        pk, sk = mldsa.keypair()
        fd = os.open(skf + ".new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(sk)
        with open(pkf, "w") as f:
            f.write(pk.hex() + "\n")
        os.replace(skf + ".new", skf)
    with open(skf, "rb") as f:
        sk = f.read()
    with open(pkf) as f:
        pk = bytes.fromhex(f.read().strip())
    return pk, sk


def measure(groups):
    """[(label, [paths])] -> PSA software components: SHA-256 over the files of each group, in order."""
    comps = []
    for label, paths in groups:
        h = hashlib.sha256()
        for p in paths:
            with open(p, "rb") as f:
                for blk in iter(lambda: f.read(1 << 20), b""):
                    h.update(blk)
        comps.append({SWC_TYPE: label, SWC_VALUE: h.digest(), SWC_VERSION: VERSION,
                      SWC_SIGNER: b"\x00" * 32, SWC_DESC: "SHA256 of " + ", ".join(os.path.basename(p) for p in paths)})
    return comps


class Prover:
    def __init__(self, a):
        self.pk, self.sk = load_or_create_key(a.state)
        with open(a.gateway_pk) as f:
            self.gw_pk = bytes.fromhex(f.read().strip())
        self.groups = a.measure
        self.hb_mac = a.heartbeat_mac
        self.instance = b"\x02" + hashlib.sha256(self.pk).digest()   # 0x02: not a PSA IAK-based instance ID
        self.kem = None            # (nonce, decapsulation key) between PQKEMINIT and PQKEMFIN
        self.session = None        # (session key, credential)
        self.hb = 0

    def handle(self, line):
        p = line.split()
        if not p:
            return "ERR empty"
        cmd = p[0]
        try:
            if cmd == "PQKEY" and len(p) == 1:
                return "PQKEY %d %s END" % (len(self.pk), self.pk.hex())
            if cmd == "PQCHAL" and len(p) == 2:
                ch = bytes.fromhex(p[1])
                if len(ch) != 32:
                    return "ERR bad-request"
                claims = {C_PROFILE: PROFILE, C_CHALLENGE: ch, C_INSTANCE: self.instance,
                          C_SWC: measure(self.groups + [("PROVER", [os.path.abspath(__file__)])])}
                tok = cbor.dumps(claims)
                sig = mldsa.sign(self.sk, QUOTE_LABEL, tok)
                return "PQTOKEN %d %s %d %s END" % (len(tok), tok.hex(), len(sig), sig.hex())
            if cmd == "PQKEMINIT" and len(p) == 2:
                nonce = bytes.fromhex(p[1])
                if len(nonce) != 32:
                    return "ERR bad-request"
                ek, dk = mlkem.keypair()
                self.kem = (nonce, dk)
                sig = mldsa.sign(self.sk, KEM_INIT_LABEL, nonce + ek)
                return "PQKEMEK %d %s %d %s END" % (len(ek), ek.hex(), len(sig), sig.hex())
            if cmd == "PQKEMFIN" and len(p) == 3:
                return self.kem_finish(bytes.fromhex(p[1]), bytes.fromhex(p[2]))
            if cmd == "PQHB" and len(p) == 2:
                if not self.session:
                    return "ERR pq no-session"
                nonce = bytes.fromhex(p[1])
                if len(nonce) != 32:
                    return "ERR bad-request"
                self.hb += 1
                ctr = self.hb.to_bytes(8, "little")
                status = ("uptime_s=%d;link=1;fw=linux-%s" % (time.monotonic() - T0, VERSION)).encode()
                key = self.session[0]
                if self.hb_mac == "kmac256":
                    tag = kmac.kmac256(key, nonce + ctr + status, 32, b"aegis-hb-v2")
                else:
                    tag = sha3(b"aegis-hb-v1", key, nonce, ctr, status)
                return "PQHB %s %s %s END" % (status.hex(), ctr.hex(), tag.hex())
            if cmd == "PQSESSION" and len(p) == 1:
                if not self.session:
                    return "ERR pq no-session"
                key, cred = self.session
                return "PQSESSION %s %s END" % (sha3(b"aegis-session-id-v1", key).hex(), sha3(cred).hex())
        except ValueError:
            return "ERR bad-request"
        return "ERR unknown"

    def kem_finish(self, ct, cred):
        """Accept the gateway's credential only if it is signed by the pinned gateway key, names this endpoint's key and
        this exchange's ciphertext, and has not expired; only then replace the session (an aborted or forged exchange
        leaves an established session alone)."""
        if not self.kem:
            return "ERR cred no-exchange"
        nonce, dk = self.kem
        self.kem = None
        body, sep, sig = cred.partition(b"\n")
        if not sep or not mldsa.verify(self.gw_pk, CRED_LABEL, body, sig):
            return "ERR cred signature"
        try:
            b = json.loads(body)
        except ValueError:
            return "ERR cred format"
        if b.get("kem_ct_sha3_256") != sha3(ct).hex():
            return "ERR cred other-exchange"
        if b.get("endpoint_pq_pk_sha256") != hashlib.sha256(self.pk).hexdigest():
            return "ERR cred other-endpoint"
        if time.time() > 1.7e9 and b.get("expires", 0) < time.time():    # only with a set clock (no RTC battery)
            return "ERR cred expired"
        k = mlkem.decaps(ct, dk)
        tag = sha3(b"aegis-confirm-v1", k, nonce, sha3(ct), sha3(cred))
        self.session = (sha3(b"aegis-session-v1", k, nonce, sha3(ct)), cred)
        self.hb = 0
        return "PQKEMOK %s END" % tag.hex()


def serve(prover, port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(8)
    print("AEGIS-LINUX-PROVER %s ready on %d, key sha256 %s" % (VERSION, port, hashlib.sha256(prover.pk).hexdigest()[:16]),
          flush=True)
    while True:
        c, _ = srv.accept()
        c.settimeout(10)
        try:
            buf = b""
            while b"\n" not in buf and len(buf) < 65536:
                chunk = c.recv(65536)
                if not chunk:
                    break
                buf += chunk
            line = buf.split(b"\n")[0].decode("ascii", "replace").strip()
            c.sendall((prover.handle(line) + "\r\n").encode())
        except (OSError, UnicodeError):
            pass
        finally:
            c.close()


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", default="/var/lib/aegis-prover")
    ap.add_argument("--gateway-pk", required=True, help="the gateway's ML-DSA-65 identity public key (hex)")
    ap.add_argument("--measure", action="append", default=[], metavar="LABEL=PATH[,PATH...]")
    ap.add_argument("--port", type=int, default=7444)
    ap.add_argument("--heartbeat-mac", choices=["kmac256", "sha3-256"], default="kmac256")
    a = ap.parse_args(argv)
    a.measure = [(m.split("=", 1)[0], m.split("=", 1)[1].split(",")) for m in a.measure]
    serve(Prover(a), a.port)


if __name__ == "__main__":
    main()

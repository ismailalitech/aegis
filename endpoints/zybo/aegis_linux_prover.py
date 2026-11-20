#!/usr/bin/env python3
"""Aegis prover for a Linux endpoint (first: a Digilent Zybo Z7-10, Zynq-7010), kind "aegis-linux".

The same line protocol as the STM32 prover, TCP 7444, one request per connection:
  PQKEY                    -> PQKEY <len> <hex> END                       this endpoint's ML-DSA-65 public key
  PQCHAL <32-byte hex>     -> PQTOKEN <len> <claims> <len> <sig> END     claims signed with ML-DSA-65
  PQKEMINIT <nonce>        -> PQKEMEK <len> <ek> <len> <sig> END          fresh ML-KEM-768 key, signed
  PQKEMFIN <ct> <cred>     -> PQKEMOK <tag> END | ERR cred <reason>       credential checked, session kept
  PQHB <nonce>             -> PQHB <status> <counter> <tag> END           KMAC256 over the session
  PQSESSION                -> PQSESSION <session id> <credential hash> END

One transcript (common/transcript.py, from 0.3.0): the prover remembers the last quote it signed since it started
(its challenge and T1 = H(quote || challenge || SHA3(claims))). A PQKEMINIT whose nonce is that challenge continues
that quote: the signature is then over T2 = H(kem-init || T1 || ek) with the label "aegis-kem-init-v2", the credential
must name T2 ("transcript_sha3_256"), and the confirmation tag and the session key are made from
T3 = H(kem-fin || T2 || SHA3(ct) || SHA3(credential)). A quote continues at most one exchange. Any other nonce gets the
first version's exchange (signature over nonce || ek), which a verifier whose policy says "transcript": "v2" refuses.
The measurements in a quote are taken when it is asked for (measure() below: the files as they are on disk then), not
again at PQKEMINIT: the transcript says that this process, since its start, signed exactly that quote and then made
this key for it.

A session ends on this endpoint's own clock (docs/endpoint-expiry.md): the credential's lifetime ("expires" minus
"issued", as signed by the gateway) plus a sixteenth after the accepted PQKEMFIN, the session key is dropped; PQHB and
PQSESSION then answer "ERR pq expired" until the gateway provisions again. The clock is the kernel's CLOCK_BOOTTIME
(monotonic, counting suspended time; CLOCK_MONOTONIC where it is missing): software trust, like the key.

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
import transcript  # noqa: E402

VERSION = "0.3.0"
PROFILE = "aegis-linux-software-v1"
QUOTE_LABEL = b"aegis-endpoint-quote-v1"
KEM_INIT_LABEL = b"aegis-kem-init-v1"
CRED_LABEL = b"aegis-credential-v1"
# PSA claim numbers (common/psa_token.py), so the gateway's measurement check applies unchanged
C_PROFILE, C_SWC, C_CHALLENGE, C_INSTANCE = -75000, -75006, -75008, -75009
SWC_TYPE, SWC_VALUE, SWC_VERSION, SWC_SIGNER, SWC_DESC = 1, 2, 4, 5, 6
T0 = time.monotonic()
CRED_LIFETIME_MAX = 86400     # seconds; as the device provers (aegis_proto.h)


def monotonic_s():
    """Whole seconds from a clock that only advances and that setting the date does not move."""
    return int(time.clock_gettime(getattr(time, "CLOCK_BOOTTIME", time.CLOCK_MONOTONIC)))


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
        self.kem = None            # (nonce, decapsulation key, key, T2 or None) between PQKEMINIT and PQKEMFIN
        self.quote = None          # (challenge, T1) of the last quote signed since the start, until an exchange uses it
        self.session = None        # (session key, credential, clock at PQKEMFIN, seconds it may live)
        self.expired = False       # the last session ended by the clock: "ERR pq expired" until the next one
        self.clock = monotonic_s   # the tests replace it
        self.now = None            # this request's clock reading; None: the clock failed
        self.hb = 0

    def sweep(self):
        """Read the clock once per request and end a session that has outlived its credential, or whose age the clock
        cannot give (it failed, or shows less than at the session's start)."""
        try:
            self.now = int(self.clock())
        except Exception:  # noqa: BLE001
            self.now = None
        if self.session:
            _, _, start, limit = self.session
            if self.now is None or self.now < start or self.now - start >= limit:
                self.session = None
                self.expired = True

    def no_session(self):
        return "ERR pq expired" if self.expired else "ERR pq no-session"

    def handle(self, line):
        self.sweep()               # before anything else, whatever the request
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
                self.quote = None          # only a quote that was signed and sent can be continued
                claims = {C_PROFILE: PROFILE, C_CHALLENGE: ch, C_INSTANCE: self.instance,
                          C_SWC: measure(self.groups + [("PROVER", [os.path.abspath(__file__)])])}
                tok = cbor.dumps(claims)
                sig = mldsa.sign(self.sk, QUOTE_LABEL, tok)
                self.quote = (ch, transcript.quote(ch, transcript.token_hash(tok)))
                return "PQTOKEN %d %s %d %s END" % (len(tok), tok.hex(), len(sig), sig.hex())
            if cmd == "PQKEMINIT" and len(p) == 2:
                nonce = bytes.fromhex(p[1])
                if len(nonce) != 32:
                    return "ERR bad-request"
                # a new exchange replaces a pending one whether or not it completes, and it is kept only once signed
                # (as on the RW612 and STM32 partitions, 2026-11-18)
                self.kem = None
                # the nonce names the quote this exchange continues: the challenge of the last one signed. That
                # quote is used up, whether or not the exchange completes. Any other nonce: the unbound exchange.
                t1 = None
                if self.quote and hmac.compare_digest(nonce, self.quote[0]):
                    t1, self.quote = self.quote[1], None
                try:
                    ek, dk = mlkem.keypair()
                    t2 = transcript.kem_init(t1, ek) if t1 else None
                    sig = (mldsa.sign(self.sk, transcript.KEM_INIT_LABEL, t2) if t2 else
                           mldsa.sign(self.sk, KEM_INIT_LABEL, nonce + ek))
                except Exception:  # noqa: BLE001 (any failure of the crypto library refuses this exchange only)
                    return "ERR sign"
                self.kem = (nonce, dk, ek, t2)
                return "PQKEMEK %d %s %d %s END" % (len(ek), ek.hex(), len(sig), sig.hex())
            if cmd == "PQKEMFIN" and len(p) == 3:
                return self.kem_finish(bytes.fromhex(p[1]), bytes.fromhex(p[2]))
            if cmd == "PQHB" and len(p) == 2:
                if not self.session:
                    return self.no_session()
                nonce = bytes.fromhex(p[1])
                if len(nonce) != 32:
                    return "ERR bad-request"
                self.hb += 1
                ctr = self.hb.to_bytes(8, "little")
                key, _, start, limit = self.session
                status = ("uptime_s=%d;link=1;fw=linux-%s;ttl=%d" % (time.monotonic() - T0, VERSION,
                                                                    limit - (self.now - start))).encode()
                if self.hb_mac == "kmac256":
                    tag = kmac.kmac256(key, nonce + ctr + status, 32, b"aegis-hb-v2")
                else:
                    tag = sha3(b"aegis-hb-v1", key, nonce, ctr, status)
                return "PQHB %s %s %s END" % (status.hex(), ctr.hex(), tag.hex())
            if cmd == "PQSESSION" and len(p) == 1:
                if not self.session:
                    return self.no_session()
                key, cred = self.session[:2]
                return "PQSESSION %s %s END" % (sha3(b"aegis-session-id-v1", key).hex(), sha3(cred).hex())
        except ValueError:
            return "ERR bad-request"
        return "ERR unknown"

    def kem_finish(self, ct, cred):
        """Accept the gateway's credential only if it is signed by the pinned gateway key, names this endpoint's key and
        this exchange's ciphertext (and, for an exchange that continues a quote, its transcript T2), carries a
        lifetime, and has not expired; only then replace the session (an aborted or forged exchange leaves an
        established session alone)."""
        if not self.kem:
            return "ERR cred no-exchange"
        if self.now is None:
            return "ERR clock"      # a session's end could not be measured: none starts
        nonce, dk, ek, t2 = self.kem
        self.kem = None
        body, sep, sig = cred.partition(b"\n")
        if not sep or not mldsa.verify(self.gw_pk, CRED_LABEL, body, sig):
            return "ERR cred signature"
        try:
            b = json.loads(body)
        except ValueError:
            return "ERR cred format"
        if not isinstance(b, dict):
            return "ERR cred format"
        if b.get("kem_ct_sha3_256") != sha3(ct).hex():
            return "ERR cred other-exchange"
        if b.get("endpoint_pq_pk_sha256") != hashlib.sha256(self.pk).hexdigest():
            return "ERR cred other-endpoint"
        if b.get("kem_ek_sha3_256") != sha3(ek).hex():      # this exchange's key, not an earlier one
            return "ERR cred other-key"
        if t2 and b.get("transcript_sha3_256") != t2.hex():  # the verifier signed for this quote and this key
            return "ERR cred other-transcript"
        issued, expires = b.get("issued"), b.get("expires")
        if type(issued) is not int or type(expires) is not int or not 0 < expires - issued <= CRED_LIFETIME_MAX \
                or issued < 0:
            return "ERR cred validity"
        if time.time() > 1.7e9 and expires < time.time():    # only with a set clock (no RTC battery)
            return "ERR cred expired"
        k = mlkem.decaps(ct, dk)
        if t2:
            t3 = transcript.kem_fin(t2, ct, cred)
            tag, key = transcript.confirm_tag(k, t3), transcript.session_key(k, t3)
        else:
            tag, key = sha3(b"aegis-confirm-v1", k, nonce, sha3(ct), sha3(cred)), sha3(b"aegis-session-v1", k, nonce, sha3(ct))
        lifetime = expires - issued
        self.session = (key, cred, self.now, lifetime + lifetime // 16)
        self.expired = False
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
            try:
                reply = prover.handle(line)
            except Exception as e:  # noqa: BLE001 (one bad request must not stop the prover)
                print("request failed: %s" % type(e).__name__, flush=True)
                reply = "ERR internal"
            c.sendall((reply + "\r\n").encode())
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

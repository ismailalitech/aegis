#!/usr/bin/env python3
"""Ask the STM32 for two quotes on the same challenge and check both with the pinned ML-DSA-65 key, as the gateway does.

What this can and cannot show: the PSA token inside each quote carries TF-M's own ECDSA signature, which is randomized,
so the token, and with it the message ML-DSA signs, differs on every request even for the same challenge. Different
ML-DSA signatures here therefore do NOT show hedged signing: deterministic signing would differ too. Hedged signing is
shown on the PC with the partition's code signing one message twice (tests/host/test_hedged_signing.py), and the board
runs that build (its secure-image measurement is the hedged build's).
  hedged_quotes.py HOST PORT PINNED_KEY_HEX_FILE
"""
import hashlib, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "gateway", "aegisd"))
sys.path.insert(0, os.path.join(HERE, "..", "..", "common"))
import cbor, fleet, mldsa  # noqa: E402

host, port, keyfile = sys.argv[1], int(sys.argv[2]), sys.argv[3]
pk = bytes.fromhex(open(keyfile).read().strip())
ch = os.urandom(32)
print("challenge %s... (the same for both requests)" % ch.hex()[:24])
q = []
for i in (1, 2):
    tok, sig = fleet.request_pq(host, port, ch, 20)
    q.append((tok, sig))
    print("quote %d: ML-DSA-65 signature %d bytes sha256 %s, verifies with the pinned key: %s"
          % (i, len(sig), hashlib.sha256(sig).hexdigest()[:16], mldsa.verify(pk, fleet.PQ_LABEL, tok, sig)))
a, b = (cbor.loads(t).value for t, _ in q)
print("PSA token payload (the claims) equal: %s; TF-M's ECDSA signature equal: %s" % (a[2] == b[2], a[3] == b[3]))
print("so the signed message differs per request, and different ML-DSA signatures do not by themselves show hedging")

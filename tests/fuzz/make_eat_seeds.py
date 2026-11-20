#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Writes the standard-evidence seeds of the shared fuzz corpus (tests/fuzz/seeds/sdk-eat-*): the sequences a
reviewer would try against the Prover SDK's option AEGIS_EAT_COSE (docs/evidence-format.md), as inputs the harness's
model checks (tests/fuzz/fuzz_sdk_core.c says how).

  tests/fuzz/make_eat_seeds.py        (re)writes the files

Every file has the prefix "AEG\\x01" and a configuration byte (bit 0 the binary front, bit 4 the platform's token,
bit 5 the key held by the platform, bit 6 the smallest work buffer). Operation 4 with selector bit 0 is the EAT
request in a harness built with -DAEGIS_EAT_COSE=1 (EAT=1 tests/fuzz/run.sh, tests/host/test_sdk_eat.py) and the
older quote in one built without, so the same files are inputs of both builds: of the default one too, where
tests/host/test_sdk_golden.py runs the whole corpus.
"""
import os

from make_transcript_seeds import C1, C2, HB, INIT, QUOTE, SESSION, fin, op

HERE = os.path.dirname(os.path.abspath(__file__))
EAT = lambda c, sel=1: op(4, c, sel=sel)                        # noqa: E731
NO_EVIDENCE = lambda n, mode=0: op(6, bytes([n | mode << 2]), sel=6)   # noqa: E731 - the next n times; a token: mode
RNG_FAILS = op(6, bytes([0, 1]))
LINE, BINARY, TOKEN, PLATKEY, SMALL = 0x00, 0x01, 0x10, 0x20, 0x40
EXCHANGE = lambda c: INIT(c) + fin() + SESSION + HB             # noqa: E731

SEEDS = {
    # the transcript as a verifier runs it on standard evidence, twice
    "sdk-eat-bound-exchange-line": (LINE, EAT(C1) + EXCHANGE(C1) + EAT(C2) + EXCHANGE(C2)),
    "sdk-eat-bound-exchange-binary": (BINARY, EAT(C1) + EXCHANGE(C1) + EAT(C2) + EXCHANGE(C2)),
    # one quote to continue, the last of either kind
    "sdk-eat-and-older-quote-line": (LINE, EAT(C1) + QUOTE(C2) + INIT(C1) + fin() + INIT(C2) + fin() + SESSION
                                     + QUOTE(C1) + EAT(C2) + INIT(C1) + fin() + INIT(C2) + fin() + SESSION + HB),
    "sdk-eat-and-older-quote-binary": (BINARY | PLATKEY, QUOTE(C1) + EAT(C2) + INIT(C1) + fin() + INIT(C2) + fin()
                                       + SESSION + EAT(C1) + QUOTE(C2) + INIT(C1) + fin() + SESSION),
    # the platform's token nested: an honest one, none, one byte more than its room, the room filled, no length
    "sdk-eat-token-line": (TOKEN, EAT(C1) + EXCHANGE(C1) + NO_EVIDENCE(1, 0) + EAT(C2) + NO_EVIDENCE(1, 1) + EAT(C2)
                           + NO_EVIDENCE(1, 2) + EAT(C2) + EXCHANGE(C2) + NO_EVIDENCE(1, 3) + EAT(C1) + INIT(C1)),
    "sdk-eat-token-binary": (BINARY | TOKEN | PLATKEY, EAT(C1) + EXCHANGE(C1) + NO_EVIDENCE(1, 2) + EAT(C2)
                             + EXCHANGE(C2) + NO_EVIDENCE(2, 1) + EAT(C1) + EAT(C1) + EAT(C1) + INIT(C1) + fin()),
    # no measurements, no randomness for the signature: nothing signed, nothing to continue, the next one works
    "sdk-eat-refused-line": (LINE, EAT(C1) + NO_EVIDENCE(1) + EAT(C2) + INIT(C1) + fin() + RNG_FAILS + EAT(C1)
                             + INIT(C1) + fin() + EAT(C2) + EXCHANGE(C2)),
    "sdk-eat-refused-binary": (BINARY, EAT(C1) + RNG_FAILS + EAT(C2) + INIT(C1) + EAT(C1, sel=3) + EAT(C2)
                               + EAT(C1, sel=3) + EXCHANGE(C2)),
    # a work buffer too small for it: refused, the older quote still served
    "sdk-eat-small-work-line": (SMALL, QUOTE(C1) + EAT(C2) + INIT(C1) + fin() + QUOTE(C2) + EXCHANGE(C2)),
    "sdk-eat-small-work-token-binary": (BINARY | TOKEN | SMALL, EAT(C1) + QUOTE(C1) + EXCHANGE(C1) + NO_EVIDENCE(1, 2)
                                        + EAT(C2)),
    # the same as raw lines: upper-case hex, extra spaces, a malformed request that changes nothing
    "sdk-eat-raw-lines": (LINE, op(0, b"PQEAT " + C1.hex().upper().encode()) + op(0, b"PQKEMINIT  " + C1.hex().encode())
                          + fin() + SESSION + EAT(C2) + op(0, b"PQEAT " + C1.hex().encode()[:-1])
                          + op(0, b"PQEAT " + C1.hex().encode() + b" 00") + EXCHANGE(C2)
                          + op(0, b"PQEAT\t" + C2.hex().encode() + b"\r\n") + EXCHANGE(C2)),
}

if __name__ == "__main__":
    for name, (cfg, data) in SEEDS.items():
        with open(os.path.join(HERE, "seeds", name), "wb") as f:
            f.write(b"AEG\x01" + bytes([cfg]) + data)
        print("seeds/%s: %d bytes" % (name, 5 + len(data)))

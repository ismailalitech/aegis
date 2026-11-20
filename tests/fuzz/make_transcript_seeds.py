#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Writes the transcript seeds of both fuzz harnesses (tests/fuzz/seeds for the Prover SDK's core, in the line
transport's first input format; tests/fuzz/stm32/seeds for the STM32H573 partition): the sequences a reviewer would
try by hand against "one transcript" (docs/architecture.md), as inputs the harnesses' models check.

  tests/fuzz/make_transcript_seeds.py        (re)writes the files named transcript-*
  tests/fuzz/merge_seeds.py                  then copies the STM32 ones into the shared corpus (seeds/stm32-*)

An input is a list of operations "op | selector << 3, length (2 bytes, little-endian), payload" (the harnesses' own
text explains each). The ones used here, the same in both harnesses unless noted:
  1  PQKEMINIT / KEM_INIT, nonce = payload
  2  PQKEMFIN / KEM_FINISH as the gateway builds it; payload byte 0: mutation flags, bytes 1-32: encapsulation coins,
     of which byte 32, bit 0: turn the transcript's name round (leave it out of a credential that needs it, add it to
     one that does not), bit 1: name another transcript
  3  PQHB / HEARTBEAT, nonce = payload
  4  PQCHAL / QUOTE, challenge = payload
  5  PQSESSION / SESSION
  6  the next random draws fail (payload: good draws before, failing draws); STM32 only, selector 5: a reset
  0  a raw request: a line (the core's line transport), or a PSA message with its type and sizes (STM32)
"""
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
C1, C2 = bytes(range(0x10, 0x30)), bytes(range(0x60, 0x80))


def op(code, payload=b"", sel=0):
    return bytes([code | sel << 3]) + struct.pack("<H", len(payload)) + payload


def fin(tr=0, flags=0):
    """A credential as the gateway signs it; tr goes into the last coin byte's two low bits."""
    return op(2, bytes([flags]) + bytes(range(0x80, 0x9f)) + bytes([0xa0 | tr]))


QUOTE, INIT, SESSION = (lambda c: op(4, c)), (lambda c: op(1, c)), op(5)
HB = op(3, bytes(range(32)) + b"up=1")
COMMON = {
    # the transcript as the gateway runs it, twice: quote, the exchange that continues it, session, heartbeat
    "transcript-bound-exchange": QUOTE(C1) + INIT(C1) + fin() + SESSION + HB + QUOTE(C2) + INIT(C2) + fin() + SESSION + HB,
    # a credential that does not name the transcript, or names another, is refused; the next exchange works
    "transcript-credential-without-it": QUOTE(C1) + INIT(C1) + fin(tr=1) + SESSION + QUOTE(C1) + INIT(C1) + fin(tr=3)
                                        + SESSION + QUOTE(C2) + INIT(C2) + fin() + SESSION,
    # a quote continues one exchange: the same nonce again gets the unbound exchange (and its credential may name
    # anything about a transcript: the tag is the first version's)
    "transcript-quote-used-once": QUOTE(C1) + INIT(C1) + INIT(C1) + fin(tr=1) + SESSION + HB,
    # only the last quote: a second PQCHAL replaces the first
    "transcript-other-quote-in-between": QUOTE(C1) + QUOTE(C2) + INIT(C1) + fin() + INIT(C2) + fin() + SESSION,
    # an exchange that continues no quote, between a quote and its exchange, leaves the quote usable
    "transcript-unbound-in-between": QUOTE(C1) + INIT(C2) + fin() + SESSION + INIT(C1) + fin() + SESSION + HB,
    # a quote whose signature fails (no randomness) is not one to continue; a KEM_INIT that fails uses the quote up
    "transcript-refused-steps": QUOTE(C1) + op(6, bytes([0, 1])) + QUOTE(C1) + INIT(C1) + fin() + SESSION
                                + QUOTE(C2) + op(6, bytes([0, 1])) + INIT(C2) + INIT(C2) + fin() + SESSION,
}


def stm32_raw(mtype, in0, o0, o1):
    return op(0, bytes([mtype]) + struct.pack("<HHHH", len(in0), 0, o0, o1) + in0)


STM32 = dict(COMMON)
RESET = op(6, bytes([0, 2, 0, 0, 0xff, 0xff]), sel=5)
STM32.update({
    # the swap: the quote is of one boot, the exchange of the next (another image could be running by then). The
    # partition has no quote to continue after the reset, so it answers the unbound exchange, which a verifier that
    # requires the transcript refuses; nothing here can make it sign a transcript for the first boot's quote
    "transcript-swap-after-reset": QUOTE(C1) + RESET + INIT(C1) + fin(tr=1) + SESSION + RESET + QUOTE(C1) + RESET
                                   + QUOTE(C2) + INIT(C1) + fin() + INIT(C2) + fin() + SESSION + HB,
    # the same steps as raw PSA messages (types 2 and 3), then a QUOTE with a short output buffer: refused before
    # anything changes, so the quote before it can still be continued
    "transcript-raw-messages": stm32_raw(2, C1, 0x250, 3309) + stm32_raw(3, C1, 1184, 3309) + fin() + SESSION
                               + QUOTE(C2) + stm32_raw(2, C1, 0x24f, 3309) + INIT(C2) + fin() + SESSION + HB,
})
RW612 = dict(COMMON)
RW612.update({
    # the same steps as raw lines, upper-case hex and extra spaces included; a malformed PQCHAL changes nothing
    "transcript-raw-lines": op(0, b"PQCHAL " + C1.hex().upper().encode()) + op(0, b"PQKEMINIT  " + C1.hex().encode() + b"\r\n")
                            + fin() + SESSION + QUOTE(C2) + op(0, b"PQCHAL " + C1.hex().encode()[:-1]) + INIT(C2) + fin()
                            + SESSION + HB,
})

if __name__ == "__main__":
    for folder, seeds in (("seeds", RW612), (os.path.join("stm32", "seeds"), STM32)):
        for name, data in seeds.items():
            with open(os.path.join(HERE, folder, name), "wb") as f:
                f.write(data)
            print("%s/%s: %d bytes" % (folder, name, len(data)))

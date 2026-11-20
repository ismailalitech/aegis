#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Writes the part of the shared corpus (tests/fuzz/seeds) that is not the RW612 family's own files:

  stm32-<name>   every seed of the STM32H573 family (tests/fuzz/stm32/seeds/<name>, which stay where they are for
                 that family's own harness), for the shared harness: the bytes "AEG\\x01", the configuration byte
                 0x5F (the binary operations, a clock of 250 counts a second, both compatibility flags, the
                 platform's token as evidence, the smallest work buffer: that partition's configuration of the core),
                 then the seed unchanged. fuzz_sdk_core.c reads that family's operations as far as they are the
                 core's: a PSA message the partition refuses for its sizes only reads the clock; the session clock's
                 hardware becomes a clock that fails (a fault), jumps beyond any lifetime (a wrap) or starts or does
                 not start (a reset); the stack scenario of operation 6 is not the core's and is ignored.
  sdk-<name>     what neither family's seeds had: the identity key held by the platform, the line transport on a
                 250 Hz clock, zero bytes from the generator on the line transport, the work buffer's limit, a reset
                 and a recorded credential on the line transport, a platform without evidence, heartbeat status
                 buffers, raw credentials of every length, the compatibility flags on the line transport.

  tests/fuzz/merge_seeds.py        (re)writes the files named stm32-* and sdk-*

An input is a list of operations "op | selector << 3, length (2 bytes, little-endian), payload"; fuzz_sdk_core.c
explains each. Every file here must pass that harness's checks (tests/host/test_sdk_golden.py runs them)."""
import glob
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
SEEDS = os.path.join(HERE, "seeds")
MAGIC = b"AEG\x01"
BINARY, HZ250, HB_FROM_BOOT, NO_ENDPOINT, TOKEN, PLATFORM_KEY, SMALL_WORK = 1, 2, 4, 8, 16, 32, 64
STM32 = BINARY | HZ250 | HB_FROM_BOOT | NO_ENDPOINT | TOKEN | SMALL_WORK   # 0x5F
C1, C2, C3 = bytes(range(0x10, 0x30)), bytes(range(0x60, 0x80)), bytes(range(0xb0, 0xd0))
DROP_PK, BAD_SIG = 0x04, 0x08


def op(code, payload=b"", sel=0):
    return bytes([code | sel << 3]) + struct.pack("<H", len(payload)) + payload


def fin(tr=0, flags=0, extra=b"", life=0, variant=0):
    """A credential as the gateway signs it; life picks 3600, 1, 86400 or 40 seconds."""
    return op(2, bytes([flags]) + bytes(range(0x80, 0x9f)) + bytes([0xa0 | tr]) + extra, sel=variant | life << 3)


def u32(v):
    return struct.pack("<I", v)


QUOTE, INIT, SESSION, REPLAY = (lambda c: op(4, c)), (lambda c: op(1, c)), op(5), op(5, sel=1)
HB = op(3, bytes(range(32)) + b"up=1")
RNG = lambda good, bad, zeros=False: op(6, bytes([good, bad | (4 if zeros else 0)]))   # noqa: E731
EXCHANGE = QUOTE(C1) + INIT(C1) + fin() + SESSION + HB


def raw(mtype, in0, in1=b"", o0=0, o1=0):
    """A raw message of the binary front: type, the two input sizes, the two output sizes, the inputs."""
    return op(0, bytes([mtype]) + struct.pack("<HHHH", len(in0), len(in1), o0, o1) + in0 + in1)


def sdk_seeds():
    line_reset, line_ticks, line_no_evidence = op(6, sel=4), (lambda n: op(6, u32(n), sel=5)), op(6, b"\x01", sel=6)
    line_seconds = lambda n: op(6, u32(n), sel=1)   # noqa: E731
    bin_no_evidence = op(6, b"\x01", sel=6)
    # the next n quotes get a token of the given kind: 1 one byte beyond the room, 2 exactly the room, 3 no length
    bin_evidence = line_evidence = lambda n, mode: op(6, bytes([n | mode << 2]), sel=6)   # noqa: E731
    ct = bytes(1088)
    return {
        # the identity key held by the platform: the same exchange, and a signature the platform cannot make
        "sdk-platform-key-line": (PLATFORM_KEY, EXCHANGE + RNG(0, 1) + QUOTE(C2) + RNG(1, 1) + INIT(C2) + INIT(C2) + fin()
                                  + SESSION + HB),
        "sdk-platform-key-binary": (BINARY | PLATFORM_KEY, EXCHANGE + RNG(0, 1) + QUOTE(C2) + RNG(1, 1) + INIT(C2)
                                    + INIT(C2) + fin() + SESSION + HB + op(7)),
        "sdk-platform-key-stm32-like": (STM32 | PLATFORM_KEY, EXCHANGE + QUOTE(C2) + INIT(C2) + fin(tr=1) + SESSION),
        # lines on a clock of 250 counts a second: a session of 40 s lives 42 s (10500 counts); the seconds left
        # are rounded up, and the session ends at the count, not at the second
        "sdk-line-250hz": (HZ250, QUOTE(C1) + INIT(C1) + fin(life=3) + HB + line_ticks(100) + HB + line_seconds(41)
                           + HB + line_ticks(149) + HB + line_ticks(1) + HB + SESSION + EXCHANGE),
        # zero bytes from a generator that reports success: no key from them, but a signature (it is then the
        # deterministic one)
        "sdk-rng-zero-line": (0, RNG(0, 1, True) + INIT(C1) + QUOTE(C1) + RNG(1, 1, True) + INIT(C1) + fin() + SESSION
                              + RNG(0, 1, True) + QUOTE(C2) + INIT(C2) + fin() + SESSION + HB),
        "sdk-rng-zero-binary": (BINARY, RNG(0, 2, True) + INIT(C1) + INIT(C1) + QUOTE(C1) + INIT(C1) + fin() + SESSION),
        # the smallest work buffer: a body of more than 1214 bytes does not fit and is refused as not signed
        "sdk-work-buffer-limit-line": (SMALL_WORK, INIT(C1) + fin(extra=b"x" * 1000) + SESSION + INIT(C1)
                                       + fin(extra=b"x" * 300) + SESSION + HB),
        "sdk-work-buffer-limit-binary": (BINARY | SMALL_WORK, QUOTE(C1) + INIT(C1) + fin(extra=b"y" * 1000) + SESSION
                                         + QUOTE(C1) + INIT(C1) + fin(extra=b"y" * 300) + SESSION + HB),
        # with the whole buffer the same long body is accepted
        "sdk-long-credential": (0, INIT(C1) + fin(extra=b"x" * 1000) + SESSION + HB),
        # a reset on the line transport, and the recorded PQKEMFIN sent again, before and after a new PQKEMINIT
        "sdk-reset-replay-line": (0, EXCHANGE + REPLAY + line_reset + SESSION + REPLAY + INIT(C1) + REPLAY + SESSION
                                  + QUOTE(C1) + line_reset + INIT(C1) + fin(tr=1) + SESSION),
        # a platform that gives no evidence: no quote, and none to continue
        "sdk-no-evidence-line": (0, QUOTE(C1) + line_no_evidence + QUOTE(C2) + INIT(C1) + INIT(C2) + fin() + SESSION
                                 + QUOTE(C3) + INIT(C3) + fin() + SESSION),
        "sdk-no-evidence-token": (BINARY | TOKEN, QUOTE(C1) + bin_no_evidence + QUOTE(C2) + INIT(C1) + INIT(C2) + fin()
                                  + SESSION + QUOTE(C3) + INIT(C3) + fin() + SESSION),
        # a token whose length the platform reports wrongly or at the limit: one byte beyond the room (refused, and
        # the quote before it is gone), exactly the room (accepted and continued), nothing (refused)
        "sdk-evidence-length-binary": (BINARY | TOKEN, QUOTE(C1) + bin_evidence(1, 1) + QUOTE(C2) + INIT(C1) + INIT(C2)
                                       + bin_evidence(1, 2) + QUOTE(C3) + INIT(C3) + fin() + SESSION
                                       + bin_evidence(1, 3) + QUOTE(C1) + INIT(C1) + QUOTE(C2) + INIT(C2) + fin()),
        "sdk-evidence-length-small-work": (BINARY | TOKEN | SMALL_WORK, bin_evidence(1, 2) + QUOTE(C1) + INIT(C1) + fin()
                                           + SESSION + bin_evidence(2, 1) + QUOTE(C2) + QUOTE(C3) + QUOTE(C1)
                                           + INIT(C1) + fin() + SESSION),
        "sdk-evidence-length-line": (TOKEN, line_evidence(1, 1) + QUOTE(C1) + INIT(C1) + line_evidence(1, 2) + QUOTE(C2)
                                     + INIT(C2) + fin() + SESSION + line_evidence(1, 3) + QUOTE(C3) + INIT(C3)),
        # heartbeat status buffers: room, none (the status as given), exactly enough, too small (one byte short of
        # the text with its ";ttl=3825", and by more); then raw ones
        "sdk-heartbeat-one-short": (BINARY, EXCHANGE + op(3, bytes(32) + b"g" * 7, sel=3) + op(3, bytes(32) + b"g" * 6, sel=3)
                                    + op(3, bytes(32) + b"h" * 10, sel=3) + op(3, bytes(32) + b"g" * 7, sel=2) + SESSION),
        "sdk-heartbeat-buffers": (BINARY, HB + EXCHANGE + op(3, bytes(32) + b"a=1", sel=1) + op(3, bytes(32) + b"a=1", sel=2)
                                  + op(3, bytes(32) + b"a=1", sel=3) + op(3, bytes(32) + b"b" * 40, sel=3)
                                  + op(3, bytes(32) + b"c" * 30, sel=18) + raw(6, bytes(32), b"ttl=9;x", 40, 0)
                                  + raw(6, bytes(32), b"d" * 200, 40, 150) + raw(6, bytes(32), b"e" * 9, 39, 0)
                                  + raw(6, bytes(32), b"e" * 9, 8, 0) + SESSION),
        # raw credentials of every length: none, too long (the exchange stays pending for both), not signed
        "sdk-raw-credentials": (BINARY, raw(4, ct, b"z" * 10) + INIT(C1) + raw(4, ct) + raw(4, ct, b"z" * 6145)
                                + raw(4, ct, b"z" * 6144) + INIT(C1) + raw(4, ct, b"{}\n" + bytes(3309)) + INIT(C1)
                                + fin() + SESSION + raw(0, b"") + raw(1, b"") + raw(5, b"")),
        # the compatibility flags on the line transport: a credential without the device's key, and a heartbeat
        # counter that goes on from one session to the next
        "sdk-compat-flags-line": (HB_FROM_BOOT | NO_ENDPOINT, QUOTE(C1) + INIT(C1) + fin(flags=DROP_PK) + HB + HB
                                  + QUOTE(C2) + INIT(C2) + fin(flags=DROP_PK) + HB + SESSION),
        # without them the same credential is for another endpoint; and what a credential is refused for comes in
        # one order (signature before any name)
        "sdk-refusal-order": (0, INIT(C1) + fin(flags=DROP_PK) + INIT(C1) + fin(flags=DROP_PK | BAD_SIG) + QUOTE(C2)
                              + INIT(C2) + fin(tr=1, flags=0x02) + QUOTE(C2) + INIT(C2) + fin(tr=1, variant=3)
                              + INIT(C1) + fin(flags=0x01 | DROP_PK) + SESSION),
        # the token as evidence on the line transport, the claims on the binary operations
        "sdk-token-line": (TOKEN, EXCHANGE + op(0, b"PQKEY")),
        "sdk-claims-binary-250hz": (BINARY | HZ250, EXCHANGE + op(6, u32(3824), sel=1) + HB + op(6, u32(249), sel=2) + HB
                                    + op(6, u32(1), sel=2) + HB + SESSION),
    }


def main():
    for old in glob.glob(os.path.join(SEEDS, "stm32-*")) + glob.glob(os.path.join(SEEDS, "sdk-*")):
        os.remove(old)
    n = 0
    for path in sorted(glob.glob(os.path.join(HERE, "stm32", "seeds", "*"))):
        with open(path, "rb") as f, open(os.path.join(SEEDS, "stm32-" + os.path.basename(path)), "wb") as out:
            out.write(MAGIC + bytes([STM32]) + f.read())
        n += 1
    made = sdk_seeds()
    for name, (config, body) in made.items():
        with open(os.path.join(SEEDS, name), "wb") as out:
            out.write(MAGIC + bytes([config]) + body)
    print("%d stm32-* and %d sdk-* seeds in %s" % (n, len(made), SEEDS))


if __name__ == "__main__":
    main()

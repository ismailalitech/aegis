#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Red-team checks against the real devices (no physical action needed).

  STM32 prover (via the TCP port that serves its line protocol, today the PC relay):
    malformed commands, bad hex, wrong lengths, overlong lines, KEM steps out of order, random
    bytes. Property: the device answers ERR (or nothing harmful) and a genuine post-quantum quote
    still verifies afterwards; PQKEMFIN without PQKEMINIT is refused by the secure side.
  Gateway quote service (aegisd, TCP 7443): malformed frames and a half-open client.
    Property: the service keeps answering and its quote still verifies (PC verifier).

  fuzz_devices.py --stm32 HOST:PORT --gateway HOST [--n 60]
"""
import argparse
import json
import os
import random
import secrets
import socket
import struct
import sys
import time

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
for p in ("common", "host", "gateway/aegisd"):
    sys.path.insert(0, os.path.abspath(os.path.join(ROOT, p)))
import aegis_verify as av  # noqa: E402
import fleet  # noqa: E402
import mldsa  # noqa: E402

R = random.Random(99)


def line_req(host, port, line, timeout=40):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(line + b"\n")
            buf = b""
            while b"\n" not in buf:
                c = s.recv(65536)
                if not c:
                    break
                buf += c
            return buf.split(b"\n")[0].strip().decode(errors="replace")
    except OSError as e:
        return "SOCKET-ERROR %s" % e


def stm32_cases(n):
    hexs = lambda k: secrets.token_hex(k).encode()  # noqa: E731
    cases = [b"CHAL", b"CHAL " + hexs(31), b"CHAL " + hexs(33), b"CHAL zz" + hexs(31)[2:], b"PQCHAL",
             b"PQCHAL " + hexs(16), b"PQKEY extra", b"PQKEMFIN " + hexs(1088) + b" " + hexs(100),
             b"PQKEMFIN " + hexs(10) + b" " + hexs(10), b"PQKEMINIT " + hexs(31), b"PQKEMFIN", b"PQSESSIONX",
             b"A" * 20000, b"PQKEMFIN " + b"0" * 30000, b"\x00\x01\x02\xff" * 10, b"TOKEN 1 00 END"]
    for _ in range(n):
        cases.append(bytes(R.choice(b"0123456789abcdefPQCHALKEMINT ") for _ in range(R.randrange(1, 300))))
    return cases


def stm32_quote_ok(host, port, pk):
    ch = secrets.token_bytes(32)
    r = line_req(host, port, b"PQCHAL " + ch.hex().encode()).split()
    if len(r) != 6 or r[0] != "PQTOKEN":
        return False
    tok, sig = bytes.fromhex(r[2]), bytes.fromhex(r[4])
    return mldsa.verify(pk, b"aegis-endpoint-quote-v1", tok, sig) and ch.hex() in tok.hex()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stm32", default=os.environ.get("STM32"), required="STM32" not in os.environ)
    ap.add_argument("--gateway", default=os.environ.get("GATEWAY"), required="GATEWAY" not in os.environ)
    ap.add_argument("--n", type=int, default=60)
    a = ap.parse_args()
    out, broken = {}, []

    host, port = a.stm32.split(":")
    port = int(port)
    pk = fleet.request_pq_key(host, port, timeout=40)
    replies = {"ERR": 0, "other": 0, "socket-error": 0}
    first_other = []
    t0 = time.time()
    for c in stm32_cases(a.n):
        r = line_req(host, port, c)
        k = "ERR" if r.startswith("ERR") else ("socket-error" if r.startswith("SOCKET") else "other")
        replies[k] += 1
        if k == "other" and len(first_other) < 3:
            first_other.append([c[:30].decode(errors="replace"), r[:40]])
    fin_without_init = line_req(host, port, b"PQKEMFIN " + secrets.token_hex(1088).encode() + b" 00")
    alive = stm32_quote_ok(host, port, pk)
    out["stm32"] = {"malformed_requests": sum(replies.values()), "replies": replies, "non_err_examples": first_other,
                    "kemfin_without_init": fin_without_init[:30], "genuine_quote_verifies_after": alive,
                    "elapsed_s": round(time.time() - t0, 1)}
    if not alive:
        broken.append("STM32 stopped producing valid quotes after malformed input")
    if not fin_without_init.startswith("ERR"):
        broken.append("PQKEMFIN without PQKEMINIT was not refused")

    g = a.gateway
    enrolled = av.load_enrolled()
    sent = 0
    for _ in range(a.n * 4):
        frame = struct.pack(">I", R.randrange(0, 4000)) + bytes(R.randrange(256) for _ in range(R.randrange(0, 300)))
        try:
            with socket.create_connection((g, 7443), timeout=3) as s:
                s.sendall(frame)
                s.shutdown(socket.SHUT_WR)
                s.settimeout(3)
                s.recv(4096)
        except OSError:
            pass
        sent += 1
    slow = socket.create_connection((g, 7443), timeout=5)
    slow.sendall(struct.pack(">I", 2000) + b"{")
    t1 = time.monotonic()
    resp, nonce, el = av.fresh_quote(g, 7443)
    ok, reasons = av.check_quote(enrolled, resp, nonce, el)
    slow_s = round(time.monotonic() - t1, 3)
    slow.close()
    out["gateway_aegisd"] = {"malformed_frames": sent, "quote_ok_with_half_open_client": ok, "reasons": reasons,
                             "quote_time_s": slow_s}
    if not ok:
        broken.append("gateway quote failed after malformed input: %s" % reasons)
    out["broken"] = broken
    print(json.dumps(out, indent=1))
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())

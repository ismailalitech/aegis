#!/usr/bin/env python3
"""TEMPORARY transport: expose the STM32 prover's serial line protocol on TCP.

Used only while the STM32's Ethernet port has no link. The gateway connects to
<PC>:7444 exactly as it would to the STM32 itself; this relay forwards one
request line to the ST-LINK virtual COM port and returns the device's reply.
It adds no trust: the token is signed inside the STM32's secure world, and the
relay could only drop or delay it (which the verifier then treats as failure).
"""
import argparse
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stm32_console as sc  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=7444)
    a = ap.parse_args()
    con = sc.Console()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", a.port))
    srv.listen(2)
    print("serial bridge on port %d -> %s" % (a.port, sc.port_path()), flush=True)
    while True:
        c, peer = srv.accept()
        c.settimeout(10)
        try:
            req = b""
            while b"\n" not in req and len(req) < 200:
                chunk = c.recv(256)
                if not chunk:
                    break
                req += chunk
            line = req.split(b"\n")[0].strip().decode(errors="replace")
            con.read_for(0.05)
            con.buf = b""
            con.send(line)
            reply = con.wait_for(b"TOKEN ", 10) or con.wait_for(b"ERR", 1) or "ERR bridge-timeout"
            c.sendall(reply.encode() + b"\r\n")
            print("%s %s -> %s..." % (peer[0], line[:20], reply[:24]), flush=True)
        except OSError as e:
            print("client error:", e, flush=True)
        finally:
            c.close()


if __name__ == "__main__":
    main()

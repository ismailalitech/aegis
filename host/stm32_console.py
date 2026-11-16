#!/usr/bin/env python3
"""Talk to the Aegis prover over the ST-LINK virtual COM port.

  stm32_console.py boot  [--wait 20]        reset the board, print the console
  stm32_console.py token [--out FILE]       send a fresh 32-byte challenge, save the token
"""
import argparse
import glob
import json
import os
import secrets
import subprocess
import sys
import termios
import time
import tty

CLI = os.path.expanduser("~/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin/STM32_Programmer_CLI")


def port_path():
    c = sorted(glob.glob("/dev/serial/by-id/usb-STMicroelectronics_STLINK*"))
    if len(c) != 1:
        raise SystemExit("expected one ST-LINK VCP, found %r" % c)
    return c[0]


class Console:
    def __init__(self, path=None):
        self.fd = os.open(path or port_path(), os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        tty.setraw(self.fd)
        a = termios.tcgetattr(self.fd)
        a[4] = a[5] = termios.B115200
        termios.tcsetattr(self.fd, termios.TCSANOW, a)
        self.buf = b""

    def read_for(self, seconds):
        end = time.time() + seconds
        while time.time() < end:
            try:
                self.buf += os.read(self.fd, 4096)
            except BlockingIOError:
                time.sleep(0.02)
        return self.buf

    def wait_for(self, marker, seconds):
        end = time.time() + seconds
        while time.time() < end:
            i = self.buf.find(marker)
            if i >= 0:
                j = self.buf.find(b"\n", i)
                if j >= 0:
                    line, self.buf = self.buf[i:j], self.buf[j + 1:]
                    return line.strip().decode(errors="replace")
            try:
                self.buf += os.read(self.fd, 4096)
            except BlockingIOError:
                time.sleep(0.02)
        return None

    def send(self, line):
        os.write(self.fd, line.encode() + b"\r\n")


def reset():
    subprocess.run([CLI, "-c", "port=SWD", "mode=HOTPLUG", "-hardRst"], capture_output=True, check=True)


def get_token(con, challenge, timeout=10):
    con.buf = b""
    con.send("CHAL " + challenge.hex())
    t0 = time.monotonic()
    line = con.wait_for(b"TOKEN ", timeout)
    el = time.monotonic() - t0
    if not line:
        raise RuntimeError("no token (console: %r)" % con.buf[-200:])
    parts = line.split()
    if len(parts) != 4 or parts[3] != "END":
        raise RuntimeError("malformed token line")
    tok = bytes.fromhex(parts[2])
    if len(tok) != int(parts[1]):
        raise RuntimeError("token length %d, device said %s" % (len(tok), parts[1]))
    return tok, el


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["boot", "token"])
    ap.add_argument("--wait", type=float, default=20)
    ap.add_argument("--out")
    a = ap.parse_args()
    con = Console()
    if a.cmd == "boot":
        reset()
        sys.stdout.write(con.read_for(a.wait).decode(errors="replace").replace("\r", ""))
        return 0
    ch = secrets.token_bytes(32)
    tok, el = get_token(con, ch)
    rec = {"challenge": ch.hex(), "token": tok.hex(), "elapsed_s": round(el, 3)}
    if a.out:
        with open(a.out, "w") as f:
            json.dump(rec, f, indent=1)
    print(json.dumps({"challenge": ch.hex()[:16] + "...", "token_bytes": len(tok), "elapsed_s": rec["elapsed_s"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())

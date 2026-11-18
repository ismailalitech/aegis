#!/usr/bin/env python3
"""The FRDM-RW612 console for the recorded demo (tools/rw612/record_demo.sh): the board's USB serial port, line by
line, without Zephyr's shell prompt and colour codes, with IPv4 addresses masked (the bench network is not published).
  demo_console.py <serial device>"""
import re
import sys

import serial

GREEN, CYAN, RESET = "\x1b[32m", "\x1b[36m", "\x1b[0m"
s = serial.Serial(sys.argv[1], 115200, timeout=0.2)
buf = b""
while True:
    buf += s.read(4096)
    while b"\n" in buf:
        raw, buf = buf.split(b"\n", 1)
        t = re.sub(r"\x1b\[[0-9;]*[A-Za-z]|\x1b\[\d*D|\r", "", raw.decode(errors="replace"))
        t = re.sub(r"^(uart:~\$ ?)+", "", t)
        t = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "<lan address>", t)
        t = re.sub(r"^\[\d\d:\d\d:\d\d\.\d{3},\d{3}\] ", "", t)
        t = t.replace("<inf> ", "")
        if not t.strip():
            continue
        if t.startswith("aegis: key") or t.startswith("AEGIS-RW612"):
            t = CYAN + t + RESET
        elif "listening" in t:
            t = GREEN + t + RESET
        print(t, flush=True)

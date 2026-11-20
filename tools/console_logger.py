#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Record a serial console to timestamped files, for the gateway's kernel console (ttyS1 on the PolarFire SoC
Discovery Kit, the embedded FlashPro5's second UART on the PC). Each line gets the PC's time; a new file starts
every day and when one reaches 20 MB; NUL bytes and escape sequences are dropped. Runs until killed; if the port
disappears (board unplugged) it waits and reopens it.
  tools/console_logger.py /dev/ttyUSB2 <out dir> [baud]
"""
import os
import re
import sys
import time

import serial

PORT, OUT = sys.argv[1], sys.argv[2]
BAUD = int(sys.argv[3]) if len(sys.argv) > 3 else 115200
MAX = 20 * 1024 * 1024
ESC = re.compile(rb"\x1b\[[0-9;]*[A-Za-z]")
os.makedirs(OUT, exist_ok=True)


def out_file():
    day = time.strftime("%Y%m%d")
    n = 0
    while True:
        p = os.path.join(OUT, "console-%s-%d.log" % (day, n))
        if not os.path.exists(p) or os.path.getsize(p) < MAX:
            return p
        n += 1


def main():
    buf = b""
    while True:
        try:
            s = serial.Serial(PORT, BAUD, timeout=1)
        except (serial.SerialException, OSError):
            time.sleep(5)
            continue
        try:
            while True:
                buf += s.read(4096)
                *lines, buf = buf.split(b"\n")
                if lines:
                    with open(out_file(), "ab") as f:
                        for ln in lines:
                            ln = ESC.sub(b"", ln.replace(b"\x00", b"").rstrip(b"\r"))
                            f.write(time.strftime("%Y-%m-%d %H:%M:%S ").encode() + ln + b"\n")
        except (serial.SerialException, OSError):
            s.close()
            time.sleep(5)


if __name__ == "__main__":
    main()

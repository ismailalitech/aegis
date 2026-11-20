#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Print the measurement MCUboot (TF-M BL2) records for a signed image: the SHA-256 image
hash TLV (type 0x10) and the signer ID (SHA-256 of the public key TLV, type 0x02 with
MCUBOOT_HW_KEY). These are the values that appear in the PSA token's sw_components.

  image_measurement.py tfm_ns_signed.bin [more.bin ...]
"""
import hashlib
import json
import struct
import sys


def measurement(img):
    magic, = struct.unpack("<I", img[:4])
    if magic != 0x96F3B83D:
        raise ValueError("not an MCUboot image")
    hdr, = struct.unpack("<H", img[8:10])
    isz, = struct.unpack("<I", img[12:16])
    ver = img[20:28]
    off = hdr + isz
    tl = {}
    for _ in range(2):
        m, tot = struct.unpack("<HH", img[off:off + 4])
        if m not in (0x6907, 0x6908):
            break
        p = off + 4
        while p < off + tot:
            t, ln = struct.unpack("<HH", img[p:p + 4])
            tl.setdefault(t, img[p + 4:p + 4 + ln])
            p += 4 + ln
        off += tot
    return {
        "version": "%d.%d.%d" % (ver[0], ver[1], struct.unpack("<H", ver[2:4])[0]),
        "measurement_value": tl[0x10].hex(),
        "signer_id": hashlib.sha256(tl[0x02]).hexdigest() if 0x02 in tl else None,
    }


if __name__ == "__main__":
    print(json.dumps({p: measurement(open(p, "rb").read()) for p in sys.argv[1:]}, indent=1))

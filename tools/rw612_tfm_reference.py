#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reference measurements for the RW612 TF-M prover (endpoints/rw612/tfm): what the Aegis secure partition reports
as SPE and NSPE after endpoints/rw612/tfm/flash.sh has written these two images.

The partition hashes whole partitions, not image lengths:
  SPE  = SHA-256(flash 0x08001000 .. 0x0809FFFF)   (0x9F000 bytes; the secure .bin is written at 0x08000400, so its
                                                   first 0xC00 bytes, the flash config block, are not in it)
  NSPE = SHA-256(flash 0x080A0000 .. 0x0839FFFF)   (0x300000 bytes)
flash.sh erases both partitions first, so every byte the images do not cover is 0xFF.

  tools/rw612_tfm_reference.py <secure .bin> <non-secure .bin> [--json]
"""
import hashlib
import json
import sys

S_BIN_BASE, S_PART, S_SIZE = 0x400, 0x1000, 0x9F000
NS_PART, NS_SIZE = 0xA0000, 0x300000


def partition(image, image_offset, part_offset, size):
    """The partition's bytes: 0xFF, with the image laid over it at its flash offset."""
    buf = bytearray(b"\xff" * size)
    start = image_offset - part_offset
    if start < 0:
        image = image[-start:]
        start = 0
    if start + len(image) > size:
        raise SystemExit("image does not fit in its partition")
    buf[start:start + len(image)] = image
    return bytes(buf)


def reference(s_bin, ns_bin):
    s = partition(s_bin, S_BIN_BASE, S_PART, S_SIZE)
    ns = partition(ns_bin, NS_PART, NS_PART, NS_SIZE)
    return {"SPE": hashlib.sha256(s).hexdigest(), "NSPE": hashlib.sha256(ns).hexdigest()}


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    with open(argv[0], "rb") as f:
        s_bin = f.read()
    with open(argv[1], "rb") as f:
        ns_bin = f.read()
    ref = reference(s_bin, ns_bin)
    if "--json" in argv:
        print(json.dumps([{"type": k, "measurement_value": v} for k, v in ref.items()]))
    else:
        for k, v in ref.items():
            print("%-5s %s" % (k, v))


if __name__ == "__main__":
    main(sys.argv[1:])

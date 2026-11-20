#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Turn the COM11 log of the xilskey PUF registration example into the files bootgen reads.

Input: the console log of one run of the (Aegis-patched) xilskey_puf_registration_example, Vitis 2025.2.
The example prints (xilskey_puf_registration_example.c, lines 153-168, 821-826, 889-894):

  App:PUF Syndrome data Start!!!
  <386 words x 4 bytes, each word printed byte by byte from memory, i.e. little-endian: 3088 hex chars>
  App:PUF Syndrome data End!!!
  App: AUX-<8 hex>          App: CHASH -<8 hex>          App: ShutterValue -<8 hex>
  App: Black key IV - <24 hex>
  App: Black key - <64 hex>

Output files (written to --out-dir, never overwritten), in the form bootgen's FileImport::LoadHexData reads
(fscanf "%2X" pairs, whitespace ignored, exact byte count required: bootgen xilinx_v2025.2,
zynqmp/src/bootheader-zynqmp.cpp SetPufData / SetGreyOrBlackKey / SetGreyOrBlackKekIV):

  helperdata.txt   [puf_file]    1544 bytes = 3088 hex chars (PUF_DATA_LENGTH, common/include/bootheader.h)
  black_key.txt    [bh_keyfile]    32 bytes =   64 hex chars
  black_iv.txt     [bh_key_iv]     12 bytes =   24 hex chars
  puf_info.txt     CHASH, AUX, shutter value (for [fsbl_config] shutter=...), SHA-256 of each file

These are the same three extracts AMD's tutorial makes by hand (UG1209 2025.2, "PUF Registration in Boot
Header Mode": helperdata.txt between the syndrome markers, black_iv.txt, black_key.txt).

Self-checks: every value present exactly once; hex and lengths; registration status 0; the closing
"Successfully ran" line; no eFUSE-programming message anywhere; CHASH and AUX equal syndrome words 384/385
(the library copies them there, xilskey_eps_zynqmp_puf.c lines 709-712); black key non-zero and different
from the red key; IV equal to black_key_iv.hex; the red key does not appear in the log.
"""
import argparse
import hashlib
import os
import re
import sys

SYN_WORDS = 386
HELPER_BYTES = SYN_WORDS * 4          # 1544, bootgen PUF_DATA_LENGTH
EXPECTED_SHUTTER = 0x0100005E         # XSK_ZYNQMP_PUF_SHUTTER_VALUE in xilskey 2025.2

EFUSE_MESSAGES = [
    "Programming eFUSE", "Syndrome write successful", "Helper data writing failed", "Aux write",
    "CHASH write", "Black key writing", "Writing eFUSE PUF secure bits", "Writing eFUSE secure bits",
    "Black key CRC", "Formatted syndrome data start",
]


def fail(msg):
    print("PARSE FAILED: " + msg, file=sys.stderr)
    sys.exit(2)


def one(pattern, text, what):
    hits = re.findall(pattern, text)
    if len(hits) != 1:
        fail("%s: expected exactly one match, found %d (one log per registration run)" % (what, len(hits)))
    return hits[0]


def read_key_file(path, nbytes):
    t = open(path, encoding="ascii").read().strip().upper()
    if not re.fullmatch(r"[0-9A-F]{%d}" % (2 * nbytes), t):
        fail("%s must hold %d hex characters" % (path, 2 * nbytes))
    return t


def bootgen_byte_count(path):
    """Count bytes the way bootgen's LoadHexData does for a file made only of hex digits and whitespace."""
    text = open(path, encoding="ascii").read()
    if re.search(r"[^0-9A-Fa-f\s]", text):
        return -1
    n = 0
    for tok in text.split():
        n += (len(tok) + 1) // 2
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--red-key", required=True, help="red_key.hex: only used to check it is NOT in the log")
    ap.add_argument("--iv", required=True, help="black_key_iv.hex used at build time")
    a = ap.parse_args()

    raw = open(a.log, "rb").read()
    text = raw.decode("utf-8", "replace").replace("\ufeff", "").replace("\r", "")
    red = read_key_file(a.red_key, 32)
    iv_expected = read_key_file(a.iv, 12)

    if red in re.sub(r"\s", "", text).upper():
        fail("the red key appears in the log; move the log into C:\\tz\\aegis-keys only and do not use this build")
    for m in EFUSE_MESSAGES:
        if m in text:
            fail("eFUSE message %r in the log: STOP, report it, do not continue" % m)
    status = one(r"App:PUF Registration Completed:0x([0-9a-fA-F]{1,8})", text, "registration status line")
    if int(status, 16) != 0:
        fail("registration status 0x%s" % status)
    if "Successfully ran xilskey puf registration example" not in text:
        fail("the closing 'Successfully ran ...' line is missing (run incomplete or failed)")
    if "failed with" in text:
        fail("the example reported a failure")

    syn_block = one(r"App:PUF Syndrome data Start!!!\n(.*?)\nApp:PUF Syndrome data End!!!", text + "",
                    "syndrome block")
    syn = re.sub(r"\s", "", syn_block)
    if not re.fullmatch(r"[0-9a-fA-F]+", syn):
        fail("syndrome block holds non-hex characters (UART noise?)")
    if len(syn) != 2 * HELPER_BYTES:
        fail("syndrome block is %d hex chars, expected %d" % (len(syn), 2 * HELPER_BYTES))
    aux = int(one(r"App: AUX-([0-9a-fA-F]{1,8})\b", text, "AUX"), 16)
    chash = int(one(r"App: CHASH -([0-9a-fA-F]{1,8})\b", text, "CHASH"), 16)
    shutter = int(one(r"App: ShutterValue -([0-9a-fA-F]{1,8})\b", text, "ShutterValue"), 16)
    iv = one(r"App: Black key IV - ([0-9a-fA-F]{24})\b", text, "black key IV").upper()
    bkey = one(r"App: Black key - ([0-9a-fA-F]{64})\b", text, "black key").upper()

    words = [int.from_bytes(bytes.fromhex(syn[8 * i:8 * i + 8]), "little") for i in range(SYN_WORDS)]
    if words[SYN_WORDS - 2] != chash:
        fail("syndrome word 384 (0x%08x) != CHASH (0x%08x)" % (words[SYN_WORDS - 2], chash))
    if words[SYN_WORDS - 1] != aux:
        fail("syndrome word 385 (0x%08x) != AUX (0x%08x)" % (words[SYN_WORDS - 1], aux))
    if chash == 0 or aux == 0 or aux >> 24:
        fail("implausible CHASH/AUX 0x%08x/0x%08x" % (chash, aux))
    if all(w == 0 for w in words[:140]):
        fail("syndrome data all zero")
    if int(bkey, 16) == 0:
        fail("black key is zero")
    if bkey == red:
        fail("black key equals the red key (encryption did not happen)")
    if iv != iv_expected:
        fail("black key IV in the log %s != black_key_iv.hex %s" % (iv, iv_expected))
    warnings = []
    if shutter != EXPECTED_SHUTTER:
        warnings.append("shutter 0x%08x differs from the 2025.2 default 0x%08x; the printed value is used"
                        % (shutter, EXPECTED_SHUTTER))
    if any(w != 0 for w in words[141:SYN_WORDS - 2]):
        warnings.append("syndrome words 141..383 are not all zero (unexpected, but the full 1544 bytes are kept)")

    os.makedirs(a.out_dir, exist_ok=True)
    files = {
        "helperdata.txt": syn.lower() + "\n",
        "black_key.txt": bkey + "\n",
        "black_iv.txt": iv + "\n",
    }
    expect = {"helperdata.txt": HELPER_BYTES, "black_key.txt": 32, "black_iv.txt": 12}
    for name in list(files) + ["puf_info.txt"]:
        if os.path.exists(os.path.join(a.out_dir, name)):
            fail("%s already exists in %s; use a fresh directory per run" % (name, a.out_dir))
    info = ["# PUF registration in boot-header mode (xilskey 2025.2 example, Aegis build)",
            "log_sha256 %s" % hashlib.sha256(raw).hexdigest(),
            "chash 0x%08x" % chash, "aux 0x%08x" % aux, "shutter 0x%08x" % shutter]
    for name, content in files.items():
        p = os.path.join(a.out_dir, name)
        with open(p, "w", encoding="ascii", newline="\n") as f:
            f.write(content)
        n = bootgen_byte_count(p)
        if n != expect[name]:
            fail("%s: bootgen would read %d bytes, expected %d" % (name, n, expect[name]))
        info.append("%s sha256 %s bytes %d" % (name, hashlib.sha256(content.encode()).hexdigest(), n))
    with open(os.path.join(a.out_dir, "puf_info.txt"), "w", encoding="ascii", newline="\n") as f:
        f.write("\n".join(info) + "\n")
    for w in warnings:
        print("WARNING " + w)
    print("CHASH 0x%08x AUX 0x%08x SHUTTER 0x%08x" % (chash, aux, shutter))
    print("PARSE_OK " + a.out_dir)


if __name__ == "__main__":
    main()

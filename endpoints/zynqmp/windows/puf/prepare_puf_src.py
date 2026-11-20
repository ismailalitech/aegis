#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare AMD's xilskey PUF registration example for a boot-header-mode run (Aegis, ZynqMP phase B).

Copies xilskey_puf_registration_example.c and xilskey_puf_registration.h (Vitis 2025.2 / embeddedsw
xilinx_v2025.2) into a build directory and patches the copies:

  * every user switch in the header is set: XSK_PUF_INFO_ON_UART TRUE, all eFUSE and secure-bit switches FALSE;
  * the red key and the black-key IV are written into XSK_PUF_AES_KEY / XSK_PUF_BLACK_KEY_IV (the copy holding
    the key lives only in the build directory, inside C:\\tz\\aegis-keys, and is deleted after the run);
  * a guard block after the includes makes the compiler stop (#error) unless the switches are exactly as
    required, and turns every eFUSE/BBRAM write API into a macro that cannot compile if it is called;
  * the line that prints the red key on the UART is replaced, so the console log never holds the red key.

The two input files must match the SHA-256 values below (computed with CRLF normalised to LF). Those are the
files whose eFUSE paths were reviewed (README.md, "eFUSE safety"). Any other version stops the script.

Usage:
  prepare_puf_src.py --src-dir <dir with the two example files> --red-key <red_key.hex> --iv <black_key_iv.hex>
                     --out-dir <empty dir>
  prepare_puf_src.py --verify <out-dir> --red-key <red_key.hex> --iv <black_key_iv.hex>
"""
import argparse
import hashlib
import os
import re
import sys

C_NAME = "xilskey_puf_registration_example.c"
H_NAME = "xilskey_puf_registration.h"

# embeddedsw tag xilinx_v2025.2, lib/sw_services/xilskey/examples/ (LF line endings)
PINNED_SHA256 = {
    C_NAME: "77c8b87993ca80d7006009840b9ca8a787cca80e235530bb4a5b729577db13ee",
    H_NAME: "6db0dc3b9ee5a8eb36f731b229f276c480f55d7b28ef0a063f9630a49f5112fd",
}

# The only values this run accepts. The four secure-bit values sit inside "#if (XSK_PUF_PROGRAM_SECUREBITS == TRUE)"
# in AMD's header, so with PROGRAM_SECUREBITS FALSE they are not even defined; they are pinned to FALSE anyway.
REQUIRED_SWITCHES = [
    ("XSK_PUF_INFO_ON_UART", "TRUE"),
    ("XSK_PUF_PROGRAM_EFUSE", "FALSE"),
    ("XSK_PUF_IF_CONTRACT_MANUFACTURER", "FALSE"),
    ("XSK_PUF_READ_SECUREBITS", "FALSE"),
    ("XSK_PUF_PROGRAM_SECUREBITS", "FALSE"),
    ("XSK_PUF_SYN_INVALID", "FALSE"),
    ("XSK_PUF_SYN_WRLK", "FALSE"),
    ("XSK_PUF_REGISTER_DISABLE", "FALSE"),
    ("XSK_PUF_RESERVED", "FALSE"),
    ("XSK_PUF_REG_MODE", "XSK_PUF_MODE4K"),
]

# Every xilskey API that programs an eFUSE (or the BBRAM, or reloads the eFUSE cache after programming).
# Inside the example's translation unit each becomes a macro that expands to an undeclared identifier,
# so any call that survives the preprocessor is a compile error. Declarations come from the header,
# which is included before these macros, so they are not affected.
FORBIDDEN_CALLS = [
    "XilSKey_ZynqMp_EfusePs_Write",
    "XilSKey_ZynqMp_EfusePs_WritePufHelprData",
    "XilSKey_ZynqMp_EfusePs_WritePufChash",
    "XilSKey_ZynqMp_EfusePs_WritePufAux",
    "XilSKey_Write_Puf_EfusePs_SecureBits",
    "XilSKey_ZynqMp_EfusePs_WriteAndVerifyBit",
    "XilSKey_ZynqMp_EfusePs_ProgramPufAsUserFuses",
    "XilSKey_ZynqMp_EfusePs_SetWriteConditions",
    "XilSKey_ZynqMp_EfusePs_CacheLoad",
    "XilSKey_EfusePs_Write",
    "XilSKey_EfusePs_WriteEfuseBit",
    "XilSKey_ZynqMp_Bbram_Program",
    "XilSKey_ZynqMp_Bbram_Zeroise",
]

GUARD_MARK = "AEGIS_BOOT_HEADER_MODE_GUARD"

RED_KEY_PRINT = (
    '\txPuf_printf(XPUF_DEBUG_GENERAL, "App: Red key - ");\n'
    "\tfor (Index = 0; Index < 32; Index++)\n"
    "\t\txPuf_printf(XPUF_DEBUG_GENERAL,\n"
    '\t\t\t"%02x", PufInstance.RedKey[Index]);\n'
    '\txPuf_printf(XPUF_DEBUG_GENERAL, "\\r\\n");\n'
)
RED_KEY_PRINT_REPLACEMENT = (
    '\txPuf_printf(XPUF_DEBUG_GENERAL, "App: Red key - (not printed, Aegis build)\\r\\n");\n'
    "\t(void)Index;\n"
)

INCLUDE_ANCHOR = '#include "xilskey_puf_registration.h"\n#include "xplatform_info.h"\n'


def fail(msg):
    print("PREPARE FAILED: " + msg, file=sys.stderr)
    sys.exit(2)


def read_lf(path):
    with open(path, "rb") as f:
        data = f.read()
    return data.replace(b"\r\n", b"\n").decode("ascii")


def read_hex_file(path, nbytes, what):
    with open(path, "r", encoding="ascii") as f:
        text = f.read().strip()
    if not re.fullmatch(r"[0-9A-Fa-f]{%d}" % (2 * nbytes), text):
        fail("%s (%s) must hold exactly %d hex characters and nothing else" % (what, path, 2 * nbytes))
    if int(text, 16) == 0:
        fail("%s is all zero" % what)
    return text.upper()


def guard_block():
    lines = [
        "",
        "/* ---- %s: inserted by Aegis prepare_puf_src.py. Boot-header mode only: ---- */" % GUARD_MARK,
        "/* ---- the build stops unless every eFUSE switch is FALSE and no write API is called. ---- */",
        "#if !defined(TRUE) || !defined(FALSE)",
        '#error "Aegis guard: TRUE/FALSE are not macros, the switch checks below would be meaningless"',
        "#endif",
        "#if (TRUE != 1) || (FALSE != 0)",
        '#error "Aegis guard: unexpected TRUE/FALSE values"',
        "#endif",
        "#if !defined(XSK_PUF_INFO_ON_UART) || (XSK_PUF_INFO_ON_UART != TRUE) || !defined(XPUF_INFO_ON_UART)",
        '#error "Aegis guard: XSK_PUF_INFO_ON_UART must be TRUE (helper data and black key go to the UART)"',
        "#endif",
        "#if !defined(XSK_PUF_PROGRAM_EFUSE) || (XSK_PUF_PROGRAM_EFUSE != FALSE) || defined(XPUF_FUSE_SYN_DATA)",
        '#error "Aegis guard: XSK_PUF_PROGRAM_EFUSE must be FALSE"',
        "#endif",
        "#if !defined(XSK_PUF_PROGRAM_SECUREBITS) || (XSK_PUF_PROGRAM_SECUREBITS != FALSE)",
        '#error "Aegis guard: XSK_PUF_PROGRAM_SECUREBITS must be FALSE"',
        "#endif",
        "#if !defined(XSK_PUF_READ_SECUREBITS) || (XSK_PUF_READ_SECUREBITS != FALSE)",
        '#error "Aegis guard: XSK_PUF_READ_SECUREBITS must be FALSE"',
        "#endif",
        "#if !defined(XSK_PUF_IF_CONTRACT_MANUFACTURER) || (XSK_PUF_IF_CONTRACT_MANUFACTURER != FALSE) || defined(XPUF_CONTRACT_MANUFACTURER)",
        '#error "Aegis guard: XSK_PUF_IF_CONTRACT_MANUFACTURER must be FALSE"',
        "#endif",
    ]
    for name in ("XSK_PUF_SYN_INVALID", "XSK_PUF_SYN_WRLK", "XSK_PUF_REGISTER_DISABLE", "XSK_PUF_RESERVED"):
        lines += [
            "#if defined(%s) && (%s != FALSE)" % (name, name),
            '#error "Aegis guard: %s must be FALSE"' % name,
            "#endif",
        ]
    lines += [
        "#if (XSK_PUF_REG_MODE != XSK_PUF_MODE4K)",
        '#error "Aegis guard: registration must be in 4K mode"',
        "#endif",
        "/* Any call to an eFUSE/BBRAM write API below this line expands to an undeclared identifier. */",
    ]
    for fn in FORBIDDEN_CALLS:
        lines.append("#define %s(...) AEGIS_EFUSE_WRITE_FORBIDDEN_%s" % (fn, fn))
    lines += ["/* ---- end of %s ---- */" % GUARD_MARK, ""]
    return "\n".join(lines) + "\n"


def set_define(text, name, value, quoted=False):
    """Set '#define NAME value' (exactly one occurrence, any whitespace)."""
    pat = re.compile(r"^(#define[ \t]+%s[ \t]+)(\S+)[ \t]*$" % re.escape(name), re.M)
    hits = pat.findall(text)
    if len(hits) != 1:
        fail("header: expected exactly one '#define %s', found %d" % (name, len(hits)))
    new = '"%s"' % value if quoted else value
    return pat.sub(lambda m: m.group(1) + new, text)


def get_define(text, name):
    pat = re.compile(r"^#define[ \t]+%s[ \t]+(\S+)[ \t]*$" % re.escape(name), re.M)
    hits = pat.findall(text)
    if len(hits) != 1:
        fail("header: expected exactly one '#define %s', found %d" % (name, len(hits)))
    return hits[0]


def verify(out_dir, red, iv):
    """Re-check a prepared build directory (used by the run script right before the board run)."""
    h = read_lf(os.path.join(out_dir, H_NAME))
    c = read_lf(os.path.join(out_dir, C_NAME))
    for name, want in REQUIRED_SWITCHES:
        got = get_define(h, name)
        if got != want:
            fail("header: %s is %s, must be %s" % (name, got, want))
        print("SWITCH %-34s %s" % (name, got))
    if get_define(h, "XSK_PUF_AES_KEY").strip('"').upper() != red:
        fail("header: XSK_PUF_AES_KEY does not match red_key.hex")
    if get_define(h, "XSK_PUF_BLACK_KEY_IV").strip('"').upper() != iv:
        fail("header: XSK_PUF_BLACK_KEY_IV does not match black_key_iv.hex")
    # the secure-bit block must still be the only place the four secure bits are defined
    if "#if (XSK_PUF_PROGRAM_SECUREBITS == TRUE)" not in h:
        fail("header: the PROGRAM_SECUREBITS block is missing")
    if c.count(GUARD_MARK) != 2:
        fail("source: guard block missing or duplicated")
    if c.find(GUARD_MARK) < c.find(INCLUDE_ANCHOR):
        fail("source: guard block is not after the includes")
    if "App: Red key - (not printed, Aegis build)" not in c or '"%02x", PufInstance.RedKey[Index]' in c:
        fail("source: red-key print not removed")
    if red in c.upper() or red in re.sub(r"\s", "", c).upper():
        fail("source: the red key must only be in the header")
    print("VERIFY_OK")


def prepare(src_dir, out_dir, red, iv):
    if os.path.exists(out_dir) and os.listdir(out_dir):
        fail("output directory is not empty: " + out_dir)
    os.makedirs(out_dir, exist_ok=True)
    texts = {}
    for name in (C_NAME, H_NAME):
        text = read_lf(os.path.join(src_dir, name))
        digest = hashlib.sha256(text.encode("ascii")).hexdigest()
        if digest != PINNED_SHA256[name]:
            fail("%s sha256 %s differs from the reviewed xilinx_v2025.2 file %s. The eFUSE review does not "
                 "cover this version: stop and get it re-reviewed." % (name, digest, PINNED_SHA256[name]))
        print("SOURCE_OK %s sha256 %s" % (name, digest))
        texts[name] = text

    h = texts[H_NAME]
    for name, want in REQUIRED_SWITCHES:
        h = set_define(h, name, want)
    h = set_define(h, "XSK_PUF_AES_KEY", red, quoted=True)
    h = set_define(h, "XSK_PUF_BLACK_KEY_IV", iv, quoted=True)

    c = texts[C_NAME]
    if c.count(INCLUDE_ANCHOR) != 1:
        fail("source: include anchor not found exactly once")
    c = c.replace(INCLUDE_ANCHOR, INCLUDE_ANCHOR + guard_block())
    if c.count(RED_KEY_PRINT) != 1:
        fail("source: red-key print block not found exactly once")
    c = c.replace(RED_KEY_PRINT, RED_KEY_PRINT_REPLACEMENT)

    # Windows line endings for the Vitis copy; the pinned hashes above are on the LF form.
    for name, text in ((H_NAME, h), (C_NAME, c)):
        with open(os.path.join(out_dir, name), "w", encoding="ascii", newline="\r\n") as f:
            f.write(text)
    verify(out_dir, red, iv)
    print("PREPARE_OK " + out_dir)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src-dir")
    ap.add_argument("--out-dir")
    ap.add_argument("--verify", metavar="OUT_DIR")
    ap.add_argument("--red-key", required=True)
    ap.add_argument("--iv", required=True)
    a = ap.parse_args()
    red = read_hex_file(a.red_key, 32, "red key")
    iv = read_hex_file(a.iv, 12, "black-key IV")
    if a.verify:
        verify(a.verify, red, iv)
    elif a.src_dir and a.out_dir:
        prepare(a.src_dir, a.out_dir, red, iv)
    else:
        ap.error("give --src-dir and --out-dir, or --verify")


if __name__ == "__main__":
    main()

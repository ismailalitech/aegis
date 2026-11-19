#!/usr/bin/env python3
"""Build the encrypted BOOT.BIN (ZynqMP, PUF black key in the boot header) and check the result.

Runs on the Windows PC only: it needs the red key. Everything that holds the red key (the .nky file) lives in a
temporary directory next to the key file (C:\\tz\\aegis-keys\\bootgen-<time>) and is deleted at the end, also on
failure. The output directory gets BOOT.BIN, the BIF (file names only, no key), the bootgen log, a report and
SHA256SUMS; none of them contains the red key (checked).

The .nky file bootgen wants (UG1283 "aeskeyfile"; format as bootgen's own WriteEncryptionKeyFile writes it):
    Device       xczu4eg;
    Key 0        <red key, 64 hex>;
    IV 0         <12 random bytes, 24 hex>;
Key 0 is the key the device holds at boot (here: the red key that the boot ROM recovers from the black key).
IV 0 is fresh for every build: AES-GCM must never see the same key and IV twice.

Usage (Windows, from make_boot_encrypted.ps1):
  make_boot_encrypted.py --red-key C:\\tz\\aegis-keys\\red_key.hex --reg-dir C:\\tz\\aegis-keys\\reg-<time>
      --fsbl ... --pmufw ... --bit ... --bl31 ... --tee ... --uboot ... --out-dir C:\\tz\\stage\\boot-enc-<time>
      --bootgen C:\\AMDDesignTools\\2025.2\\Vitis\\bin\\bootgen.bat [--auth none|bh --auth-dir ...]
      [--expect-sums SHA256SUMS]
"""
import argparse
import datetime
import hashlib
import os
import re
import secrets
import shutil
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(HERE, "boot-encrypted.bif.template")
BH_BLACK_KEY = 0xA35C7C53       # bootgen common/include/bootheader.h
PUF_HD_OFFSET = 0x8B8          # boot header (0xB8) + register init table (0x800); helper data follows
HELPER_BYTES = 1544

PARTS = [  # (argument, name inside the BIF and in SHA256SUMS)
    ("fsbl", "fsbl.elf"), ("pmufw", "pmufw.elf"), ("bit", "system.bit"),
    ("bl31", "bl31.elf"), ("tee", "tee-raw.bin"), ("uboot", "u-boot.elf"),
]


def fail(msg):
    raise SystemExit("MAKE_BOOT FAILED: " + msg)


def read_hex(path, nbytes, what):
    t = open(path, encoding="ascii").read()
    t = re.sub(r"\s", "", t).upper()
    if not re.fullmatch(r"[0-9A-F]{%d}" % (2 * nbytes), t):
        fail("%s (%s): expected %d bytes as hex" % (what, path, nbytes))
    return t


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd, cwd, log):
    if cmd[0].lower().endswith((".bat", ".cmd")):
        cmd = ["cmd", "/c"] + cmd
    p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = p.stdout.decode("utf-8", "replace")
    log.write("$ " + " ".join(cmd) + "\n" + out + "\n")
    return p.returncode, out


def make_bif(shutter, auth):
    t = open(TEMPLATE, encoding="ascii").read()
    if auth == "bh":
        lines = ("\t[pskfile] psk.pem\n\t[sskfile] ssk.pem\n"
                 "\t[auth_params] ppk_select=0; spk_id=0x00000000\n")
        t = t.replace("@BH_AUTH@", "bh_auth_enable, ").replace("@AUTH_LINES@", lines)
        t = t.replace("@FSBL_AUTH@", "authentication=rsa, ")
    else:
        t = t.replace("@BH_AUTH@", "").replace("@AUTH_LINES@", "").replace("@FSBL_AUTH@", "")
    t = t.replace("@SHUTTER@", "0x%08X" % shutter)
    if "@" in t.split("the_ROM_image:")[1]:
        fail("unfilled placeholder in the BIF")
    return t


def check_boot_bin(path, black_key, black_iv, helper, shutter, auth, red):
    d = open(path, "rb").read()
    rep = []
    u32 = lambda off: struct.unpack_from("<I", d, off)[0]
    checks = [
        ("width detection 0x20", u32(0x20) == 0xAA995566),
        ("image id 0x24 'XNLX'", u32(0x24) == 0x584C4E58),
        ("key source 0x28 = BH black key 0xA35C7C53", u32(0x28) == BH_BLACK_KEY),
        ("attributes: PUF helper data in boot header (bits 7:6 = 3)", (u32(0x44) >> 6) & 3 == 3),
        ("attributes: PUF 4K mode (bits 17:16 = 3)", (u32(0x44) >> 16) & 3 == 3),
        ("attributes: boot-header RSA (bits 15:14) = %s" % ("3" if auth == "bh" else "0"),
         (u32(0x44) >> 14) & 3 == (3 if auth == "bh" else 0)),
        ("attributes: no auth_only (bits 5:4 = 0)", (u32(0x44) >> 4) & 3 == 0),
        ("black key at 0x4C = black_key.txt", d[0x4C:0x6C] == bytes.fromhex(black_key)),
        ("PUF shutter at 0x6C = 0x%08X" % shutter, u32(0x6C) == shutter),
        ("black key IV at 0xAC = black_iv.txt", d[0xAC:0xB8] == bytes.fromhex(black_iv)),
        ("helper data at 0x%X = helperdata.txt" % PUF_HD_OFFSET,
         d[PUF_HD_OFFSET:PUF_HD_OFFSET + HELPER_BYTES] == bytes.fromhex(helper)),
        ("red key bytes absent", bytes.fromhex(red) not in d),
        ("red key hex absent", red.encode() not in d.upper()),
    ]
    ok = True
    for name, good in checks:
        rep.append(("OK   " if good else "FAIL ") + name)
        ok &= good
    rep.append("attributes 0x%08X, fsbl_sec_hdr_iv (IV 0) %s" % (u32(0x44), d[0xA0:0xAC].hex()))
    return ok, rep


def check_partitions(read_out):
    """Parse `bootgen -read BOOT.BIN pht`: only the boot-loader partition may be encrypted."""
    rep, ok = [], True
    for name, body in re.findall(r"PARTITION HEADER TABLE \(([^)]*)\)(.*?)(?=PARTITION HEADER TABLE|\Z)", read_out, re.S):
        m = re.search(r"encryption \[(yes|no)\]", body)
        enc = m.group(1) if m else "?"
        want = "yes" if name.startswith("fsbl.elf") else "no"
        good = enc == want
        ok &= good
        rep.append("%s partition %-18s encryption %s (want %s)" % ("OK  " if good else "FAIL", name, enc, want))
    if not rep:
        ok = False
        rep.append("FAIL could not parse bootgen -read pht output")
    return ok, rep


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--red-key", required=True)
    ap.add_argument("--reg-dir", required=True)
    for arg, _ in PARTS:
        ap.add_argument("--" + arg, required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--bootgen", required=True)
    ap.add_argument("--auth", choices=["none", "bh"], default="none")
    ap.add_argument("--auth-dir", help="holds psk.pem/ssk.pem for --auth bh (created with bootgen if missing)")
    ap.add_argument("--expect-sums", help="SHA256SUMS of the current plain BOOT.BIN inputs")
    ap.add_argument("--keep-temp", action="store_true", help=argparse.SUPPRESS)  # for tests with dummy keys only
    a = ap.parse_args()

    red = read_hex(a.red_key, 32, "red key")
    black_key = read_hex(os.path.join(a.reg_dir, "black_key.txt"), 32, "black key")
    black_iv = read_hex(os.path.join(a.reg_dir, "black_iv.txt"), 12, "black key IV")
    helper = read_hex(os.path.join(a.reg_dir, "helperdata.txt"), HELPER_BYTES, "helper data")
    info = open(os.path.join(a.reg_dir, "puf_info.txt"), encoding="ascii").read()
    m = re.search(r"^shutter 0x([0-9a-fA-F]{8})$", info, re.M)
    if not m:
        fail("no shutter value in puf_info.txt")
    shutter = int(m.group(1), 16)
    if os.path.exists(os.path.join(a.out_dir, "BOOT.BIN")):
        fail("%s already holds a BOOT.BIN; use a new output directory" % a.out_dir)

    sums = {}
    if a.expect_sums:
        for line in open(a.expect_sums, encoding="ascii"):
            parts = line.split()
            if len(parts) == 2:
                sums[parts[1].lstrip("*")] = parts[0].lower()
    inputs = []
    for arg, name in PARTS:
        src = getattr(a, arg)
        if not os.path.isfile(src):
            fail("missing input %s" % src)
        h = sha256(src)
        note = ""
        if a.expect_sums and name not in sums:
            fail("%s has no line for %s" % (a.expect_sums, name))
        if name in sums:
            if sums[name] != h:
                fail("%s (%s) sha256 %s does not match %s from %s" % (name, src, h, sums[name], a.expect_sums))
            note = " (matches %s)" % os.path.basename(a.expect_sums)
        inputs.append((src, name, h))
        print("INPUT %-12s %s %s%s" % (name, h, src, note))

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    tmp = os.path.join(os.path.dirname(os.path.abspath(a.red_key)), "bootgen-" + stamp)
    os.makedirs(tmp)
    os.makedirs(a.out_dir, exist_ok=True)
    log = open(os.path.join(a.out_dir, "bootgen.log"), "w", encoding="utf-8")
    report = ["# make_boot_encrypted.py %s, auth=%s" % (stamp, a.auth)]
    try:
        for src, name, _ in inputs:
            shutil.copyfile(src, os.path.join(tmp, name))
        for name in ("black_key.txt", "black_iv.txt", "helperdata.txt"):
            shutil.copyfile(os.path.join(a.reg_dir, name), os.path.join(tmp, name))
        iv0 = secrets.token_bytes(12).hex().upper()
        with open(os.path.join(tmp, "red.nky"), "w", encoding="ascii", newline="\n") as f:
            f.write("Device       xczu4eg;\n\nKey 0        %s;\nIV 0         %s;\n" % (red, iv0))
        if a.auth == "bh":
            if not a.auth_dir:
                fail("--auth bh needs --auth-dir")
            os.makedirs(a.auth_dir, exist_ok=True)
            if not all(os.path.isfile(os.path.join(a.auth_dir, k)) for k in ("psk.pem", "ssk.pem")):
                with open(os.path.join(a.auth_dir, "generate_keys.bif"), "w", encoding="ascii") as f:
                    f.write("gen:\n{\n\t[ppkfile] ppk.pem\n\t[pskfile] psk.pem\n\t[spkfile] spk.pem\n"
                            "\t[sskfile] ssk.pem\n}\n")
                rc, out = run([a.bootgen, "-arch", "zynqmp", "-generate_keys", "auth", "pem",
                               "-image", "generate_keys.bif"], a.auth_dir, log)
                if rc != 0 or not os.path.isfile(os.path.join(a.auth_dir, "psk.pem")):
                    fail("bootgen -generate_keys failed, see bootgen.log")
                print("AUTH_KEYS_GENERATED " + a.auth_dir)
            for k in ("psk.pem", "ssk.pem"):
                shutil.copyfile(os.path.join(a.auth_dir, k), os.path.join(tmp, k))
        bif = make_bif(shutter, a.auth)
        with open(os.path.join(tmp, "boot-encrypted.bif"), "w", encoding="ascii", newline="\n") as f:
            f.write(bif)
        rc, out = run([a.bootgen, "-arch", "zynqmp", "-image", "boot-encrypted.bif", "-o", "BOOT.BIN", "-w", "on"],
                      tmp, log)
        if rc != 0 or "Bootimage generated successfully" not in out or "[ERROR]" in out:
            fail("bootgen failed (exit %d), see %s" % (rc, os.path.join(a.out_dir, "bootgen.log")))
        ok1, rep1 = check_boot_bin(os.path.join(tmp, "BOOT.BIN"), black_key, black_iv, helper, shutter, a.auth, red)
        rc, out = run([a.bootgen, "-arch", "zynqmp", "-read", "BOOT.BIN", "pht"], tmp, log)
        ok2, rep2 = check_partitions(out)
        report += rep1 + rep2
        for line in rep1 + rep2:
            print(line)
        if not (ok1 and ok2):
            fail("BOOT.BIN checks failed")
        shutil.copyfile(os.path.join(tmp, "BOOT.BIN"), os.path.join(a.out_dir, "BOOT.BIN"))
        shutil.copyfile(os.path.join(tmp, "boot-encrypted.bif"), os.path.join(a.out_dir, "boot-encrypted.bif"))
        with open(os.path.join(a.out_dir, "SHA256SUMS"), "w", encoding="ascii", newline="\n") as f:
            f.write("%s  BOOT.BIN\n" % sha256(os.path.join(a.out_dir, "BOOT.BIN")))
            for _, name, h in inputs:
                f.write("%s  %s\n" % (h, name))
            for name in ("black_key.txt", "black_iv.txt", "helperdata.txt"):
                f.write("%s  %s\n" % (sha256(os.path.join(a.reg_dir, name)), name))
        with open(os.path.join(a.out_dir, "report.txt"), "w", encoding="ascii", newline="\n") as f:
            f.write("\n".join(report) + "\n")
        print("BOOT_BIN_OK %s sha256 %s" % (os.path.join(a.out_dir, "BOOT.BIN"),
                                           sha256(os.path.join(a.out_dir, "BOOT.BIN"))))
    finally:
        log.close()
        if a.keep_temp:
            print("TEMP KEPT (test only): " + tmp)
        else:
            shutil.rmtree(tmp, ignore_errors=True)
            if os.path.exists(tmp):
                print("WARNING: could not delete %s (it holds red.nky): delete it by hand" % tmp, file=sys.stderr)
    for f in os.listdir(a.out_dir):
        p = os.path.join(a.out_dir, f)
        data = open(p, "rb").read()
        if bytes.fromhex(red) in data or red.encode() in data.upper():
            fail("the red key ended up in %s: delete the output directory" % p)


if __name__ == "__main__":
    main()

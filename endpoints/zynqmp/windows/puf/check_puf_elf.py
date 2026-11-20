#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Static check of the built PUF registration ELF (AArch64, Vitis 2025.2 standalone) before it goes to the board.

No toolchain needed: the script reads the ELF itself and decodes the AArch64 direct branches.

PASS needs all of:
  1. the example's eFUSE helpers (XilSkey_Program_Black_Key, XilSKey_Generate_FuseFormat) are not in the binary
     at all, i.e. the "#if defined XPUF_FUSE_SYN_DATA" blocks were compiled out;
  2. no eFUSE/BBRAM write function of libxilskey is reachable from the entry point or from main(): the script
     builds a call graph from BL/B/B.cond/CBZ/TBZ targets, and treats every function whose address is taken
     (ADR, ADRP+ADD, or a 64-bit pointer word in any loaded section) as an extra root, so indirect calls are
     covered conservatively;
  3. the strings that only exist when an eFUSE block is compiled are absent, the UART-print strings are present,
     and the red-key print was removed;
  4. optionally (--red-key/--iv): the key and IV strings from the key files are in the binary exactly once.

Exit status 0 = PASS, 1 = FAIL, 2 = cannot analyse (treated as FAIL by the run script).
"""
import argparse
import bisect
import re
import struct
import sys
from collections import deque

# Functions that program eFUSEs/BBRAM, prepare the controller for programming, or reload the cache after it.
FORBIDDEN = {
    "XilSKey_ZynqMp_EfusePs_Write",
    "XilSKey_ZynqMp_EfusePs_WritePufHelprData",
    "XilSKey_ZynqMp_EfusePs_WritePufChash",
    "XilSKey_ZynqMp_EfusePs_WritePufAux",
    "XilSKey_Write_Puf_EfusePs_SecureBits",
    "XilSKey_ZynqMp_EfusePs_WriteAndVerifyBit",
    "XilSKey_ZynqMp_EfusePs_WriteBit",
    "XilSKey_ZynqMp_EfusePs_PufRowWrite",
    "XilSKey_ZynqMp_EfusePs_WriteAndVerify_RowRange",
    "XilSKey_ZynqMp_EfusePs_WriteAndVerify_RowData",
    "XilSKey_ZynqMp_EfusePs_Write_SecCtrl",
    "XilSKey_ZynqMp_EfusePs_Write_SecCtrlBits",
    "XilSKey_ZynqMp_EfusePs_Write_UsrCtrlBits",
    "XilSKey_ZynqMp_EfusePs_ProgramPufAsUserFuses",
    "XilSKey_ZynqMp_EfusePs_ProgramPufUserFuse",
    "XilSKey_ZynqMp_EfusePs_SetWriteConditions",
    "XilSKey_ZynqMp_EfusePs_CacheLoad",
    "XilSKey_EfusePs_Write",
    "XilSKey_EfusePs_WriteEfuseBit",
    "XilSKey_EfusePs_WriteWithXadcCheckAndVerify",
    "XilSKey_ZynqMp_Bbram_Program",
    "XilSKey_ZynqMp_Bbram_Zeroise",
    "XilSkey_Program_Black_Key",
    "XilSKey_Generate_FuseFormat",
}
# Any other symbol that looks like an eFUSE/BBRAM writer is treated the same way.
FORBIDDEN_RE = re.compile(r"(?i)(efuse.*(write|program|pgm|burn))|((write|program|burn).*efuse)|(bbram.*(program|zeroise))")
MUST_BE_ABSENT = {"XilSkey_Program_Black_Key", "XilSKey_Generate_FuseFormat"}
MUST_BE_PRESENT = {"main", "XilSKey_Puf_Registration", "XSecure_AesEncryptData"}

STRINGS_ABSENT = [
    b"App: Programming eFUSE",
    b"Syndrome write successful",
    b"Aux write successful",
    b"CHASH write successful",
    b"Black key writing is",
    b"Writing eFUSE PUF secure bits",
    b"Registration at Contract Manufacturer",
    b"is not disabled \n\r",  # READ_SECUREBITS block
]
STRINGS_PRESENT = [
    b"App:PUF Syndrome data Start!!!",
    b"App:PUF Syndrome data End!!!",
    b"App: Black key - ",
    b"App: Black key IV - ",
    b"App: ShutterValue -",
    b"App: Red key - (not printed, Aegis build)",
]

SHF_ALLOC, SHF_EXECINSTR = 0x2, 0x4
STT_NOTYPE, STT_FUNC = 0, 2


class Elf:
    def __init__(self, data):
        self.d = data
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise ValueError("not a little-endian ELF64 file")
        (self.e_type, self.e_machine, _, self.e_entry, _, e_shoff, _, _, _, _, e_shentsize, e_shnum,
         e_shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
        if self.e_machine != 183:
            raise ValueError("not an AArch64 ELF (e_machine %d)" % self.e_machine)
        self.sections = []
        for i in range(e_shnum):
            name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from(
                "<IIQQQQIIQQ", data, e_shoff + i * e_shentsize)
            self.sections.append(dict(name_off=name, type=typ, flags=flags, addr=addr, off=off, size=size,
                                      link=link, entsize=entsize))
        shstr = self.sections[e_shstrndx]
        for s in self.sections:
            s["name"] = self._cstr(shstr["off"] + s["name_off"])

    def _cstr(self, off):
        end = self.d.index(b"\0", off)
        return self.d[off:end].decode("ascii", "replace")

    def symbols(self):
        out = []
        for s in self.sections:
            if s["type"] != 2:  # SHT_SYMTAB
                continue
            strtab = self.sections[s["link"]]
            for i in range(s["size"] // 24):
                st_name, st_info, _, st_shndx, st_value, st_size = struct.unpack_from(
                    "<IBBHQQ", self.d, s["off"] + i * 24)
                out.append((self._cstr(strtab["off"] + st_name), st_info & 0xF, st_shndx, st_value, st_size))
        return out

    def section_bytes(self, s):
        if s["type"] == 8:  # SHT_NOBITS
            return b""
        return self.d[s["off"]:s["off"] + s["size"]]


def sext(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def branch_target(word, pc):
    """Direct branch target of an AArch64 instruction, or None. Returns (target, kind)."""
    if (word & 0xFC000000) == 0x94000000:            # BL
        return pc + (sext(word & 0x3FFFFFF, 26) << 2), "bl"
    if (word & 0xFC000000) == 0x14000000:            # B
        return pc + (sext(word & 0x3FFFFFF, 26) << 2), "b"
    if (word & 0xFF000010) == 0x54000000:            # B.cond
        return pc + (sext((word >> 5) & 0x7FFFF, 19) << 2), "bcond"
    if (word & 0x7E000000) == 0x34000000:            # CBZ/CBNZ
        return pc + (sext((word >> 5) & 0x7FFFF, 19) << 2), "cbz"
    if (word & 0x7E000000) == 0x36000000:            # TBZ/TBNZ
        return pc + (sext((word >> 5) & 0x3FFF, 14) << 2), "tbz"
    return None


def ends_flow(word):
    """Unconditional end of straight-line flow: B, BR, RET, ERET."""
    return ((word & 0xFC000000) == 0x14000000 or (word & 0xFFFFFC1F) == 0xD61F0000
            or (word & 0xFFFFFC1F) == 0xD65F0000 or word == 0xD69F03E0)


def analyse(path, red_hex=None, iv_hex=None):
    data = open(path, "rb").read()
    elf = Elf(data)
    syms = elf.symbols()
    names_all = {n for n, *_ in syms if n}
    problems, notes = [], []

    exec_secs = [s for s in elf.sections if s["flags"] & SHF_EXECINSTR and s["flags"] & SHF_ALLOC and s["size"]]
    alloc_secs = [s for s in elf.sections if s["flags"] & SHF_ALLOC and s["type"] != 8 and s["size"]]

    def in_exec(addr):
        return any(s["addr"] <= addr < s["addr"] + s["size"] for s in exec_secs)

    # code regions: FUNC symbols plus NOTYPE labels in code (assembly startup), mapping symbols excluded
    starts = {}
    sized = {}
    for name, typ, shndx, value, size in syms:
        if not name or name.startswith("$") or name.startswith(".L") or typ not in (STT_FUNC, STT_NOTYPE):
            continue
        if shndx == 0 or shndx >= 0xFF00 or not in_exec(value):
            continue
        starts.setdefault(value, []).append(name)
        if typ == STT_FUNC and size:
            sized[value] = max(sized.get(value, 0), size)
    if not starts:
        raise ValueError("no code symbols (stripped ELF?)")
    order = sorted(starts)
    region_end = {}
    for i, a in enumerate(order):
        nxt = order[i + 1] if i + 1 < len(order) else None
        sec = next(s for s in exec_secs if s["addr"] <= a < s["addr"] + s["size"])
        end = sec["addr"] + sec["size"]
        if nxt is not None and nxt < end:
            end = nxt
        region_end[a] = end

    def region_of(addr):
        i = bisect.bisect_right(order, addr) - 1
        if i < 0:
            return None
        a = order[i]
        return a if addr < region_end[a] else None

    def label(a):
        return "/".join(sorted(starts[a]))

    edges = {a: set() for a in order}
    address_taken = set()
    for s in exec_secs:
        code = elf.section_bytes(s)
        base = s["addr"]
        regs = {}
        cur = None
        for off in range(0, len(code) - 3, 4):
            pc = base + off
            r = region_of(pc)
            if r != cur:
                regs = {}
                cur = r
            if r is None:
                continue
            word = struct.unpack_from("<I", code, off)[0]
            bt = branch_target(word, pc)
            if bt:
                tr = region_of(bt[0])
                if tr is not None and tr != r:
                    edges[r].add(tr)
            # address computations: ADR / ADRP (+ ADD)
            if (word & 0x1F000000) == 0x10000000:
                imm = sext((((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 3), 21)
                rd = word & 0x1F
                val = ((pc & ~0xFFF) + (imm << 12)) if word & 0x80000000 else (pc + imm)
                regs[rd] = val
                if val in starts:
                    address_taken.add(val)
            elif (word & 0xFF800000) == 0x91000000:  # ADD Xd, Xn, #imm{, lsl 12}
                rn, rd = (word >> 5) & 0x1F, word & 0x1F
                if rn in regs:
                    val = regs[rn] + (((word >> 10) & 0xFFF) << (12 if word & 0x400000 else 0))
                    if val in starts:
                        address_taken.add(val)
                    regs[rd] = val
                else:
                    regs.pop(rd, None)
        # fall-through between assembly labels (regions without an ELF size)
        for a in order:
            if not (s["addr"] <= a < s["addr"] + s["size"]) or a in sized:
                continue
            last = region_end[a] - 4
            if last >= a:
                w = struct.unpack_from("<I", code, last - base)[0]
                nxt = region_end[a]
                if not ends_flow(w) and nxt in starts:
                    edges[a].add(nxt)
    # 64-bit pointers stored in any loaded section (vector/handler tables, literal pools, .data)
    for s in alloc_secs:
        b = elf.section_bytes(s)
        start = (8 - s["addr"] % 8) % 8
        for off in range(start, len(b) - 7, 8):
            v = struct.unpack_from("<Q", b, off)[0]
            if v in starts:
                address_taken.add(v)

    by_name = {}
    for a in order:
        for n in starts[a]:
            by_name[n] = a
    roots = set(address_taken)
    entry_region = region_of(elf.e_entry)
    if entry_region is not None:
        roots.add(entry_region)
    else:
        problems.append("entry point 0x%x is not inside a known code symbol" % elf.e_entry)
    if "main" in by_name:
        roots.add(by_name["main"])

    parent = {r: None for r in roots}
    q = deque(roots)
    while q:
        a = q.popleft()
        for b in edges[a]:
            if b not in parent:
                parent[b] = a
                q.append(b)

    def chain(a):
        out = []
        while a is not None:
            out.append(label(a) + ("(addr-taken)" if a in address_taken and parent[a] is None else ""))
            a = parent[a]
        return " <- ".join(out)

    for n in sorted(MUST_BE_ABSENT):
        if n in names_all:
            problems.append("%s is in the binary: an eFUSE block of the example was compiled" % n)
    for n in sorted(MUST_BE_PRESENT):
        if n not in names_all:
            problems.append("%s missing: not the expected PUF registration build" % n)

    forbidden_present = sorted(a for a in order if any(n in FORBIDDEN or FORBIDDEN_RE.search(n) for n in starts[a]))
    for a in forbidden_present:
        if a in parent:
            problems.append("REACHABLE eFUSE/BBRAM writer %s: %s" % (label(a), chain(a)))
        else:
            notes.append("present but unreachable (linked library code): %s" % label(a))
    # forbidden names that exist as symbols but not as code regions (should not happen)
    for n in sorted(names_all):
        if (n in FORBIDDEN or FORBIDDEN_RE.search(n)) and n not in by_name:
            notes.append("non-code symbol with a writer-like name: %s" % n)

    blob = b"".join(elf.section_bytes(s) for s in alloc_secs)
    for st in STRINGS_ABSENT:
        if st in blob:
            problems.append("string %r present: an eFUSE block was compiled" % st.decode())
    for st in STRINGS_PRESENT:
        if st not in blob:
            problems.append("string %r missing" % st.decode())
    if red_hex:
        n = blob.upper().count(red_hex.encode())
        if n != 1:
            problems.append("red key string found %d times in loaded sections (expected 1)" % n)
    if iv_hex:
        n = blob.upper().count(iv_hex.encode())
        if n != 1:
            problems.append("IV string found %d times in loaded sections (expected 1)" % n)

    print("ELF %s entry 0x%x, %d code regions, %d reachable, %d address-taken roots"
          % (path, elf.e_entry, len(order), len(parent), len(address_taken)))
    for n in notes:
        print("NOTE " + n)
    for p in problems:
        print("FAIL " + p)
    if problems:
        print("ELF_CHECK_FAIL")
        return 1
    print("ELF_CHECK_PASS: no eFUSE/BBRAM writer reachable, eFUSE blocks compiled out")
    return 0


def read_hex(path, n):
    t = open(path, encoding="ascii").read().strip().upper()
    if not re.fullmatch(r"[0-9A-F]{%d}" % (2 * n), t):
        raise ValueError("%s: expected %d hex characters" % (path, 2 * n))
    return t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("elf")
    ap.add_argument("--red-key")
    ap.add_argument("--iv")
    a = ap.parse_args()
    try:
        rc = analyse(a.elf, read_hex(a.red_key, 32) if a.red_key else None, read_hex(a.iv, 12) if a.iv else None)
    except (ValueError, OSError, struct.error) as e:
        print("ELF_CHECK_ERROR " + str(e))
        rc = 2
    sys.exit(rc)


if __name__ == "__main__":
    main()

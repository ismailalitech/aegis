#!/usr/bin/env python3
"""Operation script for tb_aegis_pqc2: APB writes, reads with expected values, DMA waits and memory checks, generated
from a Python model of aegis_sponge (state, slots, XOR mode, squeeze into memory). Every hash the script computes is
also checked here against hashlib, so the expected values are not just the model agreeing with itself.

Script lines (hex fields), read by the testbench with $fscanf:
    W off data          APB write
    R off expect mask   APB read, (value & mask) must equal expect
    D status mask       poll STATUS until bit 16 (DMA busy) is 0, then (STATUS & mask) must equal status
    M addr expect       64-bit word at byte address addr in the AXI memory model must equal expect
    N count             the memory model must have accepted exactly count write beats so far
    E 0                 end
"""
import hashlib
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "model"))
from keccak import keccak_f1600 as _keccak_f  # noqa: E402  (hw/model: 25 lanes, index x + 5y; self-tested vs hashlib)

ID, CTRL, STATUS, KCOUNT, SCMD, SCFG, DMALO, DMAHI, LANE = 0x00, 0x04, 0x08, 0x0C, 0x1C, 0x20, 0x24, 0x28, 0x38
PERMUTE, CLEAR, SELECT, SQUEEZE = 1, 2, 3, 4
ERR_BASE = 0x80F000          # the testbench's memory model answers SLVERR in [ERR_BASE, ERR_BASE + 0x1000)
M64 = (1 << 64) - 1


class Model:
    def __init__(self, out):
        self.out = out
        self.st = [0] * 25
        self.slots = {}
        self.cur = 0
        self.xor = 0
        self.rate = 0
        self.nblk = 0
        self.addr = 0
        self.mem = {}
        self.beats = 0
        self.perms = 0
        self.err = 0
        self.done_blk = 0

    def w(self, off, data):
        self.out.append("W %x %x" % (off, data))
        if off == SCFG:
            self.xor, self.rate, self.nblk = data & 1, (data >> 8) & 0x1F, (data >> 16) & 0xFF
        elif off == DMALO:
            self.addr = (self.addr & ~0xFFFFFFFF) | data
        elif off == DMAHI:
            self.addr = (self.addr & 0xFFFFFFFF) | ((data & 0x3F) << 32)
        elif off >= LANE:
            wd = (off - LANE) // 4
            lane, half = wd // 2, wd % 2
            old = (self.st[lane] >> (32 * half)) & 0xFFFFFFFF
            new = (old ^ data) if self.xor else data
            self.st[lane] = (self.st[lane] & ~(0xFFFFFFFF << (32 * half)) & M64) | (new << (32 * half))
        elif off == CTRL and data & 1:
            self.permute()
        elif off == SCMD:
            self.cmd(data & 7, (data >> 4) & 7)

    def permute(self):
        self.st = _keccak_f(self.st)
        self.perms += 1

    def cmd(self, c, slot):
        if c == PERMUTE:
            self.permute()
        elif c == CLEAR:
            self.st = [0] * 25
        elif c == SELECT and slot != self.cur:
            self.slots[self.cur] = list(self.st)
            self.st = list(self.slots.get(slot, [0] * 25))   # the testbench always CLEARs a fresh slot first
            self.cur = slot
        elif c == SQUEEZE:
            self.done_blk = 0
            ok = (self.addr % 8 == 0 and 1 <= self.rate <= 21 and self.nblk >= 1 and
                  (self.addr & 0xFFF) + self.nblk * self.rate * 8 <= 4096)
            if not ok:
                self.err = 1
                return
            self.err = 0
            a = self.addr
            for _ in range(self.nblk):
                self.permute()
                if ERR_BASE <= a < ERR_BASE + 0x1000:
                    self.beats += self.rate          # the beats are accepted, the response is an error
                    self.err = 1
                    return
                for i in range(self.rate):
                    self.mem[a + 8 * i] = self.st[i]
                self.beats += self.rate
                self.done_blk += 1
                a += self.rate * 8

    def r(self, off, mask=0xFFFFFFFF):
        if off >= LANE:
            wd = (off - LANE) // 4
            v = (self.st[wd // 2] >> (32 * (wd % 2))) & 0xFFFFFFFF
        elif off == KCOUNT:
            v = self.perms
        elif off == ID:
            v = 0xAE150002
        else:
            raise ValueError(off)
        self.out.append("R %x %x %x" % (off, v & mask, mask))
        return v

    def dma_wait(self):
        st = (self.done_blk << 24) | (self.cur << 18) | (self.err << 17) | (1 << 4)   # idle, not DMA-busy
        self.out.append("D %x %x" % (st, 0xFF1F0011))

    def check_mem(self):
        for a in sorted(self.mem):
            self.out.append("M %x %x" % (a, self.mem[a]))
        self.out.append("N %x" % self.beats)

    # ---------------------------------------------------------------- host-side sponge, as a driver would do it
    def select(self, slot):
        self.w(SCMD, SELECT | (slot << 4))

    def absorb_bytes(self, data, rate, pad):
        """XOR-absorb data with padding (pad = 0x1F SHAKE, 0x06 SHA3) and leave the sponge ready to squeeze."""
        self.w(SCFG, 1)
        buf = bytearray(data) + bytes([pad])
        buf += bytes((-len(buf)) % rate)
        buf[-1] |= 0x80
        for off in range(0, len(buf), rate):
            blk = buf[off:off + rate]
            for i in range(rate // 4):
                word = int.from_bytes(blk[4 * i:4 * i + 4], "little")
                if word:
                    self.w(LANE + 4 * i, word)
            if off + rate < len(buf):
                self.w(SCMD, PERMUTE)

    def squeeze_apb(self, rate, nbytes):
        out = bytearray()
        while len(out) < nbytes:
            self.w(SCMD, PERMUTE)                    # no poll: the next read waits on PREADY
            for i in range(rate // 4):
                out += self.r(LANE + 4 * i).to_bytes(4, "little")
        return bytes(out[:nbytes])

    def squeeze_dma(self, rate, nblk, addr):
        self.w(DMALO, addr & 0xFFFFFFFF)
        self.w(DMAHI, addr >> 32)
        self.w(SCFG, 1 | ((rate // 8) << 8) | (nblk << 16))
        self.w(SCMD, SQUEEZE)
        self.dma_wait()
        return b"".join(self.mem.get(addr + 8 * i, 0).to_bytes(8, "little") for i in range(nblk * rate // 8))


def main():
    rnd = random.Random(0xAE15)
    out = []
    m = Model(out)
    m.r(ID)

    # 1. the first driver's path: plain writes of all 50 words, CTRL bit 0, read back
    m.w(SCFG, 0)
    for t in range(3):
        for wd in range(50):
            m.w(LANE + 4 * wd, rnd.getrandbits(32))
        m.w(CTRL, 1)
        for wd in range(50):
            m.r(LANE + 4 * wd)
    m.r(KCOUNT)

    # 2. hashes over APB, checked against hashlib
    cases = [("shake128", 168, 0x1F), ("shake256", 136, 0x1F), ("sha3_256", 136, 0x06), ("sha3_512", 72, 0x06)]
    for name, rate, pad in cases:
        for n in (0, 1, rate - 1, rate, rate + 1, 3 * rate + 7):
            msg = bytes(rnd.getrandbits(8) for _ in range(n))
            m.w(SCMD, CLEAR)
            m.absorb_bytes(msg, rate, pad)
            outlen = {"sha3_256": 32, "sha3_512": 64}.get(name, rate * 2 + 5)
            got = m.squeeze_apb(rate, outlen)
            h = hashlib.new(name, msg)
            ref = h.digest(outlen) if name.startswith("shake") else h.digest()
            assert got == ref, (name, n)

    # 3. four sponges interleaved across slots (as a four-way SHAKE128 squeeze does), slot 0 left alone
    seeds = [bytes(rnd.getrandbits(8) for _ in range(34)) for _ in range(4)]
    outs = [bytearray() for _ in range(4)]
    for k, s in enumerate(seeds):
        m.select(k + 1)
        m.w(SCMD, CLEAR)
        m.absorb_bytes(s, 168, 0x1F)
    for blk in range(3):
        for k in (2, 0, 3, 1):
            m.select(k + 1)
            outs[k] += m.squeeze_apb(168, 168)
    for k, s in enumerate(seeds):
        assert bytes(outs[k]) == hashlib.shake_128(s).digest(3 * 168)
    m.select(1)
    m.select(1)                                      # SELECT of the current slot does nothing

    # 4. squeeze by DMA: ExpandA-like (5 blocks of SHAKE128), ExpandMask-like (5 blocks of SHAKE256), SHA3-512 rate
    base = 0x800000
    for k, (rate, nblk, pad) in enumerate(((168, 5, 0x1F), (136, 5, 0x1F), (136, 1, 0x1F), (72, 3, 0x1F))):
        msg = bytes(rnd.getrandbits(8) for _ in range(40 + k))
        m.select(5 + (k % 3))
        m.w(SCMD, CLEAR)
        m.absorb_bytes(msg, rate, pad)
        got = m.squeeze_dma(rate, nblk, base + 0x1000 * k + 8 * k)
        f = hashlib.shake_128 if rate == 168 else hashlib.shake_256
        if rate != 72:
            assert got == f(msg).digest(rate * nblk)
    # a DMA squeeze continues the sponge: APB squeeze after DMA gives the next block
    m.select(4)
    m.w(SCMD, CLEAR)
    msg = b"continue after dma"
    m.absorb_bytes(msg, 168, 0x1F)
    a = m.squeeze_dma(168, 2, base + 0x6000)
    b = m.squeeze_apb(168, 168)
    assert a + b == hashlib.shake_128(msg).digest(3 * 168)
    # the largest command that fits: 24 blocks of 168 bytes = 4032 bytes from the start of a 4 KiB page
    m.w(SCMD, CLEAR)
    m.absorb_bytes(b"long", 168, 0x1F)
    assert m.squeeze_dma(168, 24, base + 0x7000) == hashlib.shake_128(b"long").digest(24 * 168)

    # 5. refused commands: misaligned, crossing 4 KiB, rate 0, rate 22, zero blocks; nothing is written
    for addr, rate_l, nblk in ((base + 0x8004, 21, 1), (base + 0x8F80, 21, 1), (base + 0x8000, 0, 1),
                               (base + 0x8000, 22, 1), (base + 0x8000, 21, 0)):
        m.w(DMALO, addr)
        m.w(DMAHI, 0)
        m.w(SCFG, 1 | (rate_l << 8) | (nblk << 16))
        m.w(SCMD, SQUEEZE)
        m.dma_wait()
    # 6. an error response stops the command after the first block
    m.w(DMALO, ERR_BASE)
    m.w(DMAHI, 0)
    m.w(SCFG, 1 | (21 << 8) | (3 << 16))
    m.w(SCMD, SQUEEZE)
    m.dma_wait()
    # and the next good command clears the error
    m.squeeze_dma(136, 1, base + 0x9000)
    # 7. a high address (above 4 GiB) reaches the AXI address bits 37:32
    m.squeeze_dma(136, 1, (0x14 << 32) | 0x800000)

    m.r(KCOUNT)
    m.check_mem()
    out.append("E 0")
    path = os.path.join(HERE, "vectors", "sponge_ops.txt")
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")
    print("sponge vectors: %d operations, %d permutations, %d memory words -> %s"
          % (len(out), m.perms, len(m.mem), os.path.relpath(path)))


if __name__ == "__main__":
    main()

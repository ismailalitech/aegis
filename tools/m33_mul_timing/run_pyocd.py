#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""RAM-only run of the timing harness over SWD (pyocd, generic cortex_m target: no flash algorithm is loaded,
nothing but SRAM and core/debug registers is written).
  run_pyocd.py <probe uid> <elf> <bin> <out.json> [--secure] [--mpu-off]"""
import os
import json, subprocess, sys, time
from pyocd.core.helpers import ConnectHelper
from pyocd.core.target import Target

uid, elf, binf, outf = sys.argv[1:5]
secure = "--secure" in sys.argv
mpu_off = "--mpu-off" in sys.argv
NM = os.environ.get("NM", "arm-none-eabi-nm")  # the GNU Arm toolchain's nm
syms = {}
for line in subprocess.check_output([NM, elf], text=True).splitlines():
    p = line.split()
    if len(p) == 3:
        syms[p[2]] = int(p[0], 16)
data = open(binf, "rb").read()
base = syms["_start"] & ~1
rep = {"uid": uid, "elf": elf, "base": hex(base)}
DHCSR, DSCSR, DEMCR, MPU_CTRL, CPUID, DAUTH = 0xE000EDF0, 0xE000EE08, 0xE000EDFC, 0xE000ED94, 0xE000ED00, 0xE000EFB8

with ConnectHelper.session_with_chosen_probe(unique_id=uid, target_override="cortex_m", connect_mode="attach",
                                            options={"resume_on_disconnect": False, "frequency": 4000000}) as s:
    t = s.board.target
    t.halt()
    time.sleep(0.05)
    st = {}
    for r in ("pc", "xpsr", "control", "primask"):
        try:
            st[r] = hex(t.read_core_register(r))
        except Exception as e:
            st[r] = f"err {e}"
    for n, a in (("DHCSR", DHCSR), ("DSCSR", DSCSR), ("DEMCR", DEMCR), ("MPU_CTRL_S", MPU_CTRL),
                 ("MPU_CTRL_NS", 0xE002ED94), ("CPUID", CPUID), ("DAUTHSTATUS", DAUTH), ("SAU_CTRL", 0xE000EDD0)):
        try:
            st[n] = hex(t.read32(a))
        except Exception as e:
            st[n] = f"err {e}"
    rep["halt_state"] = st
    print("halted:", st, flush=True)
    dhcsr = t.read32(DHCSR)
    rep["secure_debug_enabled_S_SDE"] = bool(dhcsr & (1 << 20))
    rep["halted_in_secure_CDS"] = bool(t.read32(DSCSR) & (1 << 16))
    # load
    t.write_memory_block8(base, list(data))
    back = bytes(t.read_memory_block8(base, len(data)))
    assert back == data, "RAM readback mismatch"
    t.write32(syms["status"], 0)
    if secure:
        t.write32(DSCSR, (t.read32(DSCSR) & ~(1 << 17)) | (1 << 16))  # CDSKEY must be 0 for CDS to take the write
    if mpu_off:
        t.write32(MPU_CTRL if secure else 0xE002ED94, 0)
    rep["run_DSCSR"] = hex(t.read32(DSCSR))
    rep["run_MPU_CTRL_cur"] = hex(t.read32(MPU_CTRL)); rep["run_SAU_CTRL_cur"] = hex(t.read32(0xE000EDD0))
    rep["run_MPU_CTRL"] = hex(t.read32(MPU_CTRL if secure else 0xE002ED94))
    xpsr = t.read_core_register("xpsr")
    t.write_core_register("xpsr", (xpsr & 0x1FF) | 0x01000000)
    t.write_core_register("pc", base)
    print("running", rep["run_DSCSR"], rep["run_MPU_CTRL"], flush=True)
    t.resume()
    time.sleep(1.0)
    for _ in range(100):
        if t.get_state() == Target.State.HALTED:
            break
        time.sleep(0.1)
    else:
        t.halt()
    rep["end_pc"] = hex(t.read_core_register("pc"))
    rep["end_xpsr"] = hex(t.read_core_register("xpsr"))
    rep["end_DSCSR"] = hex(t.read32(DSCSR))
    rep["status"] = hex(t.read32(syms["status"]))
    rep["demcr_seen"] = hex(t.read32(syms["demcr_seen"]))
    rep["dwt_ctrl_seen"] = hex(t.read32(syms["dwt_ctrl_seen"]))
    rep["cpuid_seen"] = hex(t.read32(syms["cpuid_seen"]))
    for n, a in (("CFSR", 0xE000ED28), ("HFSR", 0xE000ED2C), ("SFSR", 0xE000EDE4), ("SFAR", 0xE000EDE8)):
        rep["end_" + n] = hex(t.read32(a))
    print("end:", {k: v for k, v in rep.items() if k.startswith("end_") or k == "status"}, flush=True)
    if rep["status"] != "0x600d":
        json.dump(rep, open(outf, "w"), indent=1); sys.exit("harness did not finish")
    nb = t.read32(syms["block_count"])
    names = bytes(t.read_memory_block8(syms["block_names"], 200)).split(b"\0")[0].decode().split(",")
    NC, R, MAXB, NMC, MPER = 26, 8, 18, 8, 64
    res = t.read_memory_block32(syms["results"], MAXB * NC * R)
    rep["blocks"] = {names[b]: [res[(b * NC + c) * R:(b * NC + c + 1) * R] for c in range(NC)] for b in range(nb)}
    mc = t.read_memory_block32(syms["mont_cyc"], NMC * MPER)
    mo = t.read_memory_block32(syms["mont_out"], NMC * MPER)
    rep["mont_cyc"] = [mc[c * MPER:(c + 1) * MPER] for c in range(NMC)]
    rep["mont_out"] = [[v - (1 << 32) if v >> 31 else v for v in mo[c * MPER:(c + 1) * MPER]] for c in range(NMC)]
    rep["mont_empty"] = t.read_memory_block32(syms["mont_empty"], MPER)
    rep["mont_a"] = t.read_memory_block32(syms["mont_a"], NMC * MPER)
    rep["mont_b"] = t.read_memory_block32(syms["mont_b"], NMC * MPER)
    pc = t.read_memory_block32(syms["pw_cyc"], 5 * 4)
    rep["pw_cyc"] = [pc[c * 4:(c + 1) * 4] for c in range(5)]
    # leave the core halted; the board is reset separately afterwards
json.dump(rep, open(outf, "w"), indent=1)
print("saved", outf)

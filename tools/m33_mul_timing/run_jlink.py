#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""RAM-only run of the timing harness on the FRDM-RW612 through JLinkExe (command file; no reset, no flash access:
loadbin targets SRAM only). Writes the same JSON layout as run_pyocd.py.
  run_jlink.py <elf> <bin> <out.json> [--mpu-off] [--probe-only]"""
import json, os, re, subprocess, sys, tempfile
elf, binf, outf = sys.argv[1:4]
mpu_off = "--mpu-off" in sys.argv
probe_only = "--probe-only" in sys.argv
J = os.path.expanduser("~/aegis-tools/jlink/JLinkExe")
NM = "arm-none-eabi-nm"
syms = {}
for line in subprocess.check_output([NM, elf], text=True).splitlines():
    p = line.split()
    if len(p) == 3:
        syms[p[2]] = int(p[0], 16)
base = syms["_start"] & ~1
end = syms["__end"]
dump = os.path.abspath(outf + ".ram.bin")
regs = [("DHCSR", 0xE000EDF0), ("DSCSR", 0xE000EE08), ("DEMCR", 0xE000EDFC), ("CPUID", 0xE000ED00),
        ("DAUTHSTATUS", 0xE000EFB8), ("MPU_CTRL", 0xE000ED94), ("SAU_CTRL", 0xE000EDD0), ("DWT_CTRL", 0xE0001000)]
cmds = ["h"] + [f"mem32 0x{a:08X} 1" for _, a in regs]
cmds += ["w4 0xE000EE08 0x00010000"]                      # DSCSR.CDS=1 (CDSKEY=0): run in Secure state
cmds += [f"mem32 0x{a:08X} 1" for _, a in regs]
if probe_only:
    cmds += ["g", "exit"]
else:
    cmds += [f"loadbin {os.path.abspath(binf)} 0x{base:08X}", f"verifybin {os.path.abspath(binf)} 0x{base:08X}",
             f"w4 0x{syms['status']:08X} 0"]
    if mpu_off:
        cmds += ["w4 0xE000ED94 0"]
    cmds += ["mem32 0xE000EE08 1", "wreg XPSR 0x01000000", f"SetPC 0x{base:08X}", "g", "Sleep 3000", "h",
             "mem32 0xE000EE08 1", "mem32 0xE000ED28 1", "mem32 0xE000ED2C 1", "mem32 0xE000EDE4 1",
             f"mem32 0x{syms['status']:08X} 1", f"savebin {dump} 0x{base:08X} 0x{end - base:X}", "exit"]
cf = tempfile.NamedTemporaryFile("w", suffix=".jlink", delete=False)
cf.write("\n".join(cmds) + "\n"); cf.close()
env = dict(os.environ); env.pop("DISPLAY", None)
log = subprocess.run([J, "-NoGui", "1", "-device", "RW612", "-if", "SWD", "-speed", "4000", "-autoconnect", "1",
                      "-CommandFile", cf.name], capture_output=True, text=True, env=env, timeout=120).stdout
open(outf + ".jlink.log", "w").write(log)
print("\n".join(l for l in log.splitlines() if re.match(r"^(PC|R15|XPSR|[0-9A-F]{8} = |Downloading|Verify|O\.K\.|Error|ERROR|Cortex|Security|Found SW)", l.strip()) or "Cortex-M33" in l)[-6000:])
if probe_only:
    sys.exit(0)
ram = open(dump, "rb").read()
def w(a, n=1):
    o = a - base
    return [int.from_bytes(ram[o + 4 * i:o + 4 * i + 4], "little") for i in range(n)]
rep = {"tool": "JLinkExe", "base": hex(base), "status": hex(w(syms["status"])[0]),
       "cpuid_seen": hex(w(syms["cpuid_seen"])[0]), "dwt_ctrl_seen": hex(w(syms["dwt_ctrl_seen"])[0]),
       "demcr_seen": hex(w(syms["demcr_seen"])[0])}
print("status", rep["status"])
if rep["status"] != "0x600d":
    json.dump(rep, open(outf, "w"), indent=1); sys.exit("harness did not finish")
nb = w(syms["block_count"])[0]
o = syms["block_names"] - base
names = ram[o:o + 200].split(b"\0")[0].decode().split(",")
NC, R, MAXB, NMC, MPER = 26, 8, 18, 8, 64
res = w(syms["results"], MAXB * NC * R)
rep["blocks"] = {names[b]: [res[(b * NC + c) * R:(b * NC + c + 1) * R] for c in range(NC)] for b in range(nb)}
mc = w(syms["mont_cyc"], NMC * MPER); mo = w(syms["mont_out"], NMC * MPER)
rep["mont_cyc"] = [mc[c * MPER:(c + 1) * MPER] for c in range(NMC)]
rep["mont_out"] = [[v - (1 << 32) if v >> 31 else v for v in mo[c * MPER:(c + 1) * MPER]] for c in range(NMC)]
rep["mont_empty"] = w(syms["mont_empty"], MPER)
rep["mont_a"] = w(syms["mont_a"], NMC * MPER); rep["mont_b"] = w(syms["mont_b"], NMC * MPER)
pc = w(syms["pw_cyc"], 20); rep["pw_cyc"] = [pc[c * 4:(c + 1) * 4] for c in range(5)]
json.dump(rep, open(outf, "w"), indent=1)
print("saved", outf)

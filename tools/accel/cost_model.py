#!/usr/bin/env python3
"""Predict ML-KEM-768 / ML-DSA-65 times on the gateway (one U54 core, liboqs 0.16.0) for several ways of attaching a
Keccak core to the fabric, from measured costs and the permutation profile of tools/accel/profile_keccak.sh.

    tools/accel/cost_model.py [build/accel/keccak-profile.json]

Every constant says where it comes from. MEASURED values are from the board (docs/phase2-notes.md and the pfdaq
repository); ASSUMED values have not been measured yet and are the first thing to measure on the board.
The model is checked by predicting the existing core (architecture A), whose times were measured.
"""
import json
import os
import sys

# MEASURED on the board
APB_READ_US = 0.222        # one 32-bit read from Linux user space to the core over FIC3 APB (gateway/pqc/mmio_cost.c)
APB_WRITE_US = 0.141       # one 32-bit write, same path
A_CALL_US = 16.7           # existing core, one permutation as Linux sees it (50 words in, 50 out, poll)
SW_PERM_US = 16.7 - (19.0 - 17.3)  # software permutation: liboqs speed_common, one-block SHA3-256 17.3 us software vs
                                   # 19.0 us with the fabric core -> the core costs 1.7 us more than software per call
NC_READ_US_PER_8B = 8 / 70.5       # non-cached DDR, 64-bit loads: pfdaq_cap copies its non-cached DMA buffer at 70.5 MB/s
CORE_PERM_US = 24 / 50.0   # 24 rounds at 50 MHz (one round per clock)

# ASSUMED (to measure first)
DMA_LATENCY_US = 1.0       # from the start command to the first block landing in DDR (FIC0 AXI write, clock crossing)
POLLS = 2                  # status reads per command

MEASURED_TIMES_MS = {      # docs/phase2-notes.md, liboqs speed_kem / speed_sig, one U54 core: (software, existing core)
    "ML-KEM-768 keygen": (1.219, 1.315), "ML-KEM-768 encaps": (1.417, 1.508), "ML-KEM-768 decaps": (1.755, 1.870),
    "ML-DSA-65 keygen": (3.99, 4.48), "ML-DSA-65 sign": (14.3, 15.5), "ML-DSA-65 verify": (4.12, 4.57),
}


def cost_us(arch, phase, rate, x4, perms, calls):
    """Time spent in Keccak for one profile category under one architecture."""
    words32 = rate // 4
    if arch == "software":
        return perms * SW_PERM_US
    if arch == "A: per-permutation over APB (built)":
        return perms * A_CALL_US
    if arch == "B: state kept in the fabric, APB":
        # absorb: the block is written; squeeze: the block is read; one command and the polls per block
        per = (words32 * (APB_WRITE_US if phase == "absorb" else APB_READ_US) + APB_WRITE_US + POLLS * APB_READ_US)
        return perms * per
    if arch == "C: state kept in the fabric, squeeze by DMA into DDR":
        if phase == "absorb":   # absorbing stays on APB writes (posted)
            return perms * (words32 * APB_WRITE_US + APB_WRITE_US + POLLS * APB_READ_US)
        # one command per call; the core runs ahead (0.48 us per block); the CPU reads each block from non-cached DDR
        per_call = 3 * APB_WRITE_US + DMA_LATENCY_US + POLLS * NC_READ_US_PER_8B
        per_perm = max(rate / 8 * NC_READ_US_PER_8B, CORE_PERM_US)
        return calls * per_call + perms * per_perm
    raise ValueError(arch)


ARCHS = ["software", "A: per-permutation over APB (built)", "B: state kept in the fabric, APB",
         "C: state kept in the fabric, squeeze by DMA into DDR"]


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "..", "build", "accel",
                                                               "keccak-profile.json")
    prof = json.load(open(path))
    print("Software permutation: %.1f us (derived from speed_common); core compute %.2f us; existing call %.1f us"
          % (SW_PERM_US, CORE_PERM_US, A_CALL_US))
    print()
    head = "| Operation | perms | software (measured) | A predicted / measured | B | C |"
    print(head)
    print("|---|---|---|---|---|---|")
    worst = 0.0
    for op, cats in prof.items():
        sw_ms, a_ms = MEASURED_TIMES_MS[op]
        perms = sum(v[0] for v in cats.values())
        rest_ms = sw_ms - perms * SW_PERM_US / 1000       # time outside Keccak, unchanged by the accelerator
        pred = {}
        for arch in ARCHS[1:]:
            k = sum(cost_us(arch, *c.split("/")[:1], int(c.split("/")[1]), c.split("/")[2] == "x4", v[0], v[1])
                    for c, v in cats.items())
            pred[arch] = rest_ms + k / 1000
        err = (pred[ARCHS[1]] - a_ms) / a_ms * 100
        worst = max(worst, abs(err))
        cells = ["%.2f ms" % sw_ms, "%.2f / %.2f ms (%+.0f %%)" % (pred[ARCHS[1]], a_ms, err)]
        for arch in ARCHS[2:]:
            cells.append("%.2f ms (x%.2f)" % (pred[arch], sw_ms / pred[arch]))
        print("| %s | %.0f | %s |" % (op, perms, " | ".join(cells)))
    print()
    print("Model check: the built core (A) is predicted within %.0f %% of its measured times." % worst)
    print("x = speed-up against software. C assumes DMA latency %.1f us (not yet measured)." % DMA_LATENCY_US)


if __name__ == "__main__":
    main()

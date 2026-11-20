#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Turn a window of the aegis_pqc testbench trace (VCD) into a `type: wave` diagram for tools/gen_diagrams.py.

  extract_wave.py TRACE.vcd OUT.yaml

The window starts 160 ns before the first Keccak permutation starts and ends 100 ns after it finishes, so the figure
is the simulation and not a drawing of it. Repeated values are collapsed; only changes are drawn.
"""
import sys, yaml

BUS = {'PSEL', 'PENABLE', 'PWRITE', 'PADDR', 'PCLK'}
want = {('tb_aegis_pqc', n) for n in BUS} | {('dut', 'k_busy'), ('dut', 'k_done')}
ids, scope, tr = {}, [], {}
with open(sys.argv[1]) as f:
    for line in f:
        if line.startswith('$scope'): scope.append(line.split()[2])
        elif line.startswith('$upscope'): scope.pop()
        elif line.startswith('$var'):
            p = line.split()
            if (scope[-1], p[4]) in want:
                ids.setdefault(p[3], []).append(p[4]); tr[p[4]] = []
        elif line.startswith('$enddefinitions'): break
    t = 0
    for line in f:
        c = line[0]
        if c == '#': t = int(line[1:])
        elif c in '01' and len(line) > 1:
            for k in ids.get(line[1:].strip(), []): tr[k].append((t, int(c)))
        elif c == 'b':
            v, i = line[1:].split()
            for k in ids.get(i, []): tr[k].append((t, int(v, 2) if 'x' not in v and 'z' not in v else None))

start = next(t for t, v in tr['k_busy'] if v == 1)
end = next(t for t, v in tr['k_done'] if t > start and v == 1)
w0, w1 = start - 160_000, end + 100_000          # picoseconds

def series(name, label=None):
    cur = None
    for t, v in tr[name]:
        if t <= w0: cur = v
    out, last = [[0, label(cur) if label else cur]], cur
    for t, v in tr[name]:
        if w0 < t <= w1 and v != last:
            out.append([round((t - w0) / 1000), label(v) if label else v]); last = v
    return out

def addr(v):
    if v is None: return '-'
    o = v & 0xFFF
    return {0xE04: 'CTRL', 0xE08: 'STATUS'}.get(o, '0x%03X' % o)

length = round((w1 - w0) / 1000)
busy_t = round((start - w0) / 1000); done_t = round((end - w0) / 1000)
ctrl_t = next(round((t - w0) / 1000) for t, v in tr['PADDR'] if v == 0x40000E04 and t > w0)
spec = [{
    'id': 'sim-keccak-permutation', 'type': 'wave', 'width': 900, 'height': 430, 'length': length, 'step': 3.4,
    'alt': 'Waveform from the RTL simulation of the aegis_pqc block on its APB slot. The CPU writes the last state words, '
           'writes 1 to the control register, and the busy signal then stays high for 480 nanoseconds, 24 clocks, while '
           'the status register is polled. Done goes high as it ends and the result is read back.',
    'ticks': [[x, '%d ns' % x] for x in range(0, length + 1, 100)],
    'signals': [
        {'name': 'PCLK', 'kind': 'plain', 'values': series('PCLK')},
        {'name': 'PSEL', 'kind': 'hart', 'values': series('PSEL')},
        {'name': 'PENABLE', 'kind': 'hart', 'values': series('PENABLE')},
        {'name': 'PWRITE', 'kind': 'hart', 'values': series('PWRITE')},
        {'name': 'PADDR', 'bus': True, 'kind': 'hart', 'values': series('PADDR', addr)},
        {'name': 'k_busy', 'kind': 'fabric', 'values': series('k_busy')},
        {'name': 'k_done', 'kind': 'fabric', 'values': series('k_done')},
    ],
    'callouts': [
        {'t0': 0, 't1': ctrl_t, 'title': 'State words in',
         'text': 'The CPU writes the state into the block one 32-bit word per APB transfer.'},
        {'t0': ctrl_t, 't1': busy_t, 'title': 'Start',
         'text': 'A write of 1 to CTRL starts one Keccak-f[1600] permutation.'},
        {'t0': busy_t, 't1': done_t, 'title': '24 clocks',
         'text': 'k_busy is high for %d ns, 24 rounds at one per clock. STATUS is polled meanwhile.' % (done_t - busy_t)},
        {'t0': done_t, 't1': length, 'title': 'Done',
         'text': 'k_done goes high as the permutation ends; the next transfer reads the result.'},
    ],
}]
yaml.safe_dump(spec, open(sys.argv[2], 'w'), sort_keys=False, width=120)
print('window %d ns, busy %d ns' % (length, done_t - busy_t))

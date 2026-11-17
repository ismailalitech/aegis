#!/usr/bin/env python3
"""Turn the first SQUEEZE_DMA of the tb_aegis_pqc2 trace (VCD) into a `type: wave` diagram for tools/gen_diagrams.py.

  extract_wave_dma.py TRACE.vcd OUT.yaml

Window: from 100 ns before the CPU writes the SQUEEZE command until 100 ns after the first block's write response.
The AXI slave model's ready signals are random, so the waits in the figure are the simulation's, not drawn.
"""
import sys, yaml

TOP = ['clk', 'psel', 'penable', 'pwrite', 'paddr', 'pwdata', 'pready', 'awvalid', 'awready', 'wvalid', 'wready',
       'wlast', 'bvalid', 'bready']
want = {('tb_aegis_pqc2', n) for n in TOP} | {('dut', 's_busy')}
ids, scope, tr = {}, [], {}
with open(sys.argv[1]) as f:
    for line in f:
        if line.startswith('$scope'): scope.append(line.split()[2])
        elif line.startswith('$upscope'): scope.pop()
        elif line.startswith('$var'):
            p = line.split()
            if scope and (scope[-1], p[4]) in want and p[4] not in tr:
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

def at(name, t):
    cur = None
    for tt, v in tr[name]:
        if tt <= t: cur = v
        else: break
    return cur

# the SQUEEZE command: an APB access to SCMD (0x1C) with data 4, completing (penable and pready high)
cmd = next(t for t, v in tr['penable'] if v == 1 and at('paddr', t) is not None and at('paddr', t) & 0xFF == 0x1C
           and at('pwdata', t) == 4 and at('pwrite', t) == 1)
bresp = next(t for t, v in tr['bvalid'] if t > cmd and v == 1 and at('bready', t) == 1)
bend = next(t for t, v in tr['bvalid'] if t > bresp and v == 0)
w0, w1 = cmd - 100_000, bend + 100_000

def series(name, label=None):
    cur = at(name, w0)
    out, last = [[0, label(cur) if label else cur]], cur
    for t, v in tr[name]:
        if w0 < t <= w1 and v != last:
            out.append([round((t - w0) / 1000), label(v) if label else v]); last = v
    return out

def addr(v):
    if v is None: return '-'
    return {0x1C: 'SCMD', 0x08: 'STATUS', 0x20: 'SCFG', 0x24: 'DMA_LO', 0x28: 'DMA_HI'}.get(v & 0xFF, '0x%02X' % (v & 0xFF))

ns = lambda t: round((t - w0) / 1000)
busy_on = next(t for t, v in tr['s_busy'] if t >= cmd and v == 1)
aw = next(t for t, v in tr['awvalid'] if t > cmd and v == 1)
aw_ok = next(t for t, v in tr['awready'] if t >= aw and v == 1)
w_first = next(t for t, v in tr['wvalid'] if t > aw and v == 1)
beats = sum(1 for t, v in tr['wready'] if w_first <= t <= bresp and v == 1)
length = ns(w1)
spec = [{
    'id': 'sim-sponge-dma', 'type': 'wave', 'width': 900, 'height': 560, 'length': length,
    'step': round(3.4 * 740 / length, 2),
    'alt': 'Waveform from the RTL simulation of aegis_pqc2 squeezing one block by DMA. The CPU writes the SQUEEZE '
           'command; the sponge is busy for 24 clocks computing the permutation, then raises AWVALID for one burst and '
           'sends the 21 lanes of the block as 64-bit beats while the memory model holds WREADY low at random; WLAST marks '
           'the 21st beat and the write response follows.',
    'ticks': [[x, '%d ns' % x] for x in range(0, length + 1, 200)],
    'signals': [
        {'name': 'PCLK', 'kind': 'plain', 'values': series('clk')},
        {'name': 'PADDR', 'bus': True, 'kind': 'hart', 'values': series('paddr', addr)},
        {'name': 'PENABLE', 'kind': 'hart', 'values': series('penable')},
        {'name': 'busy', 'kind': 'fabric', 'values': series('s_busy')},
        {'name': 'AWVALID', 'kind': 'fabric', 'values': series('awvalid')},
        {'name': 'AWREADY', 'kind': 'plain', 'values': series('awready')},
        {'name': 'WVALID', 'kind': 'fabric', 'values': series('wvalid')},
        {'name': 'WREADY', 'kind': 'plain', 'values': series('wready')},
        {'name': 'WLAST', 'kind': 'fabric', 'values': series('wlast')},
        {'name': 'BVALID', 'kind': 'plain', 'values': series('bvalid')},
    ],
    'callouts': [
        {'t0': 0, 't1': ns(busy_on), 'title': 'Command',
         'text': 'One APB write of SQUEEZE to SCMD starts the whole transfer.'},
        {'t0': ns(busy_on), 't1': ns(aw), 'title': 'Permutation',
         'text': '24 clocks, %d ns: the state never leaves the fabric.' % (ns(aw) - ns(busy_on))},
        {'t0': ns(aw), 't1': ns(bresp), 'title': 'One burst',
         'text': 'Address once, then %d beats of 64 bits (168 bytes); WREADY low = the memory waits.' % 21},
        {'t0': ns(bresp), 't1': length, 'title': 'Response',
         'text': 'The write response counts the block; the CPU can copy it while the next one is computed.'},
    ],
}]
with open(sys.argv[2], 'w') as f:
    f.write('# Generated by hw/tb/make_wave_dma.sh from a simulation run of hw/tb/tb_aegis_pqc2.sv. Do not edit.\n')
    yaml.safe_dump(spec, f, sort_keys=False, width=120)
print('wave-sponge-dma: window %d ns, permutation %d ns, AW accepted after %d ns, %d WREADY-high cycles in the burst'
      % (length, ns(aw) - ns(busy_on), ns(aw_ok) - ns(aw), beats))

#!/usr/bin/env python3
"""Build docs/diagrams/console.yaml (console figures with numbered callouts) from the records in evidence/console/.

Every line drawn comes from a file a real run wrote; this script only adds the command line and the callouts.
Run it, then tools/gen_diagrams.py.
"""
import os, re, yaml
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def clean(line):
    """A log line as drawn: without control characters (a board can emit a NUL on its UART; XML cannot carry it)."""
    return ''.join(c for c in line.rstrip('\n') if c == '\t' or ord(c) >= 32)


def rec(name): return [clean(l) for l in open(os.path.join(ROOT, 'evidence', 'console', name)) if l.strip()]
def fig(id, title, alt, cmd, lines, callouts, step=3.4, width=900):
    n = 1 + len(lines)
    return {'id': id, 'type': 'terminal', 'title': title, 'alt': alt, 'width': width, 'step': step,
            'height': 58 + 20 * n + 16 + 70 + 16 * max(0, len(callouts) // 8),
            'lines': [cmd] + lines, 'callouts': callouts}

demo = rec('demo-journal.txt')
quote = rec('quote-accepted.json')
disc = rec('disconnected-journal.txt')
reg = rec('regression-12of12.txt')
lat = rec('latency-runs.txt')
meas = rec('image-measurements.json')
hard = rec('hardening-journal.txt')
qvar = rec('quote-variation.txt')
two = rec('two-boards.txt')
duo = rec('two-endpoints-demo.txt')
rw = rec('rw612-endpoint.txt')
tz = [clean(l) for l in open(os.path.join(ROOT, 'evidence', 'rw612-tfm', 'trustzone-prover.txt')) if l.strip()]
ev = lambda n: [clean(l) for l in open(os.path.join(ROOT, 'evidence', 'console', n)) if l.strip() and not l.startswith('#')]
enf_old = [l for l in ev('enforcement-before-reply-fix.txt') if 'gateway' in l and ('PASS' in l or 'FAIL' in l) or l.startswith('passed')]
enf_new = [l for l in ev('enforcement.txt') if 'gateway' in l and ('PASS' in l or 'FAIL' in l) or l.startswith('passed')]
vlan = [l for l in ev('enforcement-vlan.txt') if not l.startswith('endpoint VLAN')]
fz = [clean(l) for l in open(os.path.join(ROOT, 'evidence', 'rw612-tfm', 'fuzzing.txt')) if l.strip()]
prb = [clean(l) for l in open(os.path.join(ROOT, 'evidence', 'rw612-tfm', 'hardening-probes.txt')) if l.strip()]


def section(lines, head):
    """The lines under one '# ...' heading of a record."""
    out, on = [], False
    for l in lines:
        if l.startswith('# '):
            on = l.startswith(head)
        elif on:
            out.append(l)
    return out


rw_boot = [re.sub(r'^\[\d\d:\d\d:\d\d\.\d{3},\d{3}\] <inf> ', '', l) for l in section(rw, '# Board console')]  # Zephyr's timestamps
rw_pc = section(rw, '# From the PC')
rw_gw = section(rw, '# Gateway')
tz_boot = section(tz, '# Boot')
tz_gw = section(tz, '# Gateway journal')
# the probe table: NXP's rules, then every Aegis-rules probe line (not the gateway sections); the ENET control once
prb_h = [x.replace('## ', '# ', 1) if x.startswith('## ') else x for x in prb]
PROBED = ('OCOTP', 'FLEXSPI', 'CACHE64_CTRL0', 'TRNG', 'RSTCTL0', 'CLKCTL0', 'SYSCTL0', 'MCI_IO_MUX', 'SOCCTRL',
          'SOC_OTP_CTRL', 'PMU', 'SYSCTL2')
tz_probe = ['NXP rules:   ' + l for l in section(prb_h, "# NXP") if l.split()[0] in ('OCOTP', 'FLEXSPI')]
for head in ('# Aegis target_cfg.c', '# Stage B', '# After the security review'):
    tz_probe += ['Aegis rules: ' + l for l in section(prb_h, head) if l.split()[0] in PROBED]
tz_probe += ['Aegis rules: ' + [l for l in section(prb_h, '# After the security review') if l.startswith('ENET_EIR')][0]]

figs = [
 fig('console-demo-journal', 'gateway journal during the demo',
     'The gateway journal during the scripted demo: an endpoint that did not answer is quarantined, then admitted with a new '
     'session and heartbeats, then quarantined when a modified image runs because its measurement is not allowed, and admitted '
     'again with a new session when the good image is back.',
     '$ ssh <gateway> journalctl -u aegis-fleet -o cat      # recorded during tools/demo.sh', demo,
     [{'lines': [1, 1], 'title': 'No quote', 'text': 'No post-quantum quote in the reply: quarantined, credential revoked.'},
      {'lines': [2, 2], 'title': 'Admitted, with a session', 'text': 'The checks pass; an ML-KEM credential and a session are issued.'},
      {'lines': [3, 5], 'title': 'Heartbeats', 'text': 'Each cycle the endpoint proves it still holds the session; the counter rises.'},
      {'lines': [6, 6], 'title': 'Modified firmware', 'text': 'Signed and booting, but its measurement is not in the policy: quarantined, credential revoked.'},
      {'lines': [7, 8], 'title': 'Good image back', 'text': 'Admitted again with a different session; the heartbeat counter starts over.'}]),
 fig('console-quote', 'PC verifier checks the gateway quote',
     'The PC verifier asks the gateway for a quote and prints that it was accepted, with the 3,309-byte ML-DSA-65 signature '
     'that was checked.',
     '$ .venv/bin/python host/aegis_verify.py quote <gateway>', quote,
     [{'lines': [0, 0], 'title': 'The check', 'text': 'A fresh nonce goes to the gateway; it signs it with its ML-DSA-65 identity key.'},
      {'lines': [2, 3], 'title': 'Accepted', 'text': 'Signature, nonce, identity and every measurement matched the enrolled reference.'},
      {'lines': [4, 5], 'title': 'Time and signature', 'text': '0.039 s in all; 3,309 bytes is the size of an ML-DSA-65 signature.'}]),
 fig('console-disconnected', 'what the gateway does when a device disappears',
     'With the bench unplugged, the gateway journal shows the STM32 quarantined because it cannot be reached and its credential '
     'revoked, and the Arduino quarantined because it returned no token.',
     '$ ssh <gateway> journalctl -u aegis-fleet -o cat -n 6', disc,
     [{'lines': [1, 1], 'title': 'No route to host', 'text': 'A device that cannot be reached cannot prove anything: quarantined, credential revoked.'},
      {'lines': [2, 2], 'title': 'Empty reply', 'text': 'The Uno answers with nothing while its relay is off: the same verdict, a different reason.'},
      {'lines': [3, 6], 'title': 'Every cycle', 'text': 'The verdict is repeated about every 33 seconds until the device answers again.'}]),
 fig('console-regression', 'the full board regression',
     'The regression prints twelve stages, five that need no hardware and seven that use the boards, all passing.',
     '$ tools/regression.sh --board', reg,
     [{'lines': [1, 5], 'title': 'Host stages', 'text': 'Unit tests, red-team parsers, RTL simulation and the NIST vectors. These run in CI on every push.'},
      {'lines': [6, 12], 'title': 'Board stages', 'text': 'Gateway checks, fabric self-test and ACVP with fabric hashing, admission, session, heartbeat, red team.'},
      {'lines': [13, 13], 'title': 'Result', 'text': 'Twelve of twelve. The run takes about 90 seconds.'}]),
 fig('console-latency', 'Linux interrupt latency: five setups',
     'Five setups of the Linux interrupt-latency measurement: the default, a pinned process at normal priority, a pinned '
     'real-time process on two cores, and the real-time process under full CPU load. Only the real-time rows have no overruns.',
     '$ tools/board/latency_ab.sh ; tools/board/latency_load.sh', lat,
     [{'lines': [1, 2], 'title': 'Default', 'text': 'Maximum 3.6 to 4.9 ms and dozens of overruns: scheduling, one tick at 250 Hz is 4 ms.'},
      {'lines': [3, 4], 'title': 'Pinned, normal priority', 'text': 'Moving the interrupt and task to another core does not help.'},
      {'lines': [5, 8], 'title': 'Pinned, SCHED_FIFO 80', 'text': 'No overruns and a maximum under half a millisecond, on CPU2 and on CPU1.'},
      {'lines': [9, 10], 'title': 'Under load', 'text': 'A busy loop on every core: 0 and 3 overruns; one run reached 1.47 ms. Not a hard bound.'}], step=3.6),
 fig('console-measurements', 'the two values per image that the policy allows',
     'The measurement tool prints, for the secure and the non-secure image running on the STM32, the image hash and the signer '
     'id. These are the exact values in the gateway policy; the two images are signed by two different keys.',
     '$ tools/image_measurement.py tfm-s-v2.3.0-aegis-pq-hb.bin prover-ns-0.4.0-hb.bin', meas,
     [{'lines': [2, 5], 'title': 'Secure image', 'text': 'TF-M v2.3.0 with the Aegis partition: its hash, and the id of the key that signed it.'},
      {'lines': [7, 10], 'title': 'Non-secure image', 'text': 'The prover: a different hash and a different signing key.'},
      {'lines': [4, 4], 'title': 'Same as the token', 'text': 'The boot loader records this hash at boot; the gateway compares the two.'}]),
 fig('console-hardening-journal', 'the gateway journal while the endpoint was hardened',
     'The gateway journal during the deployment of hedged signing and KMAC heartbeats: the old image stays admitted under the '
     'new gateway code; the new image is quarantined because its measurement is not yet in the policy; after the policy is '
     'updated it is admitted with a new session and its KMAC256 heartbeats verify. Copied from the terminal output of the '
     'session; the gateway journal itself is not kept across reboots.',
     '$ ssh <gateway> journalctl -u aegis-fleet -o cat      # during the deployment, 17 November 2026', hard,
     [{'lines': [1, 2], 'title': 'New gateway code, old image', 'text': 'Still admitted: without a policy change the gateway keeps the first heartbeat.'},
      {'lines': [3, 3], 'title': 'New image, old policy', 'text': 'An image the policy does not know is refused at once and its credential revoked.'},
      {'lines': [4, 4], 'title': 'Policy updated', 'text': 'The new measurement is allowed: admitted with a new session.'},
      {'lines': [5, 6], 'title': 'KMAC256 heartbeats', 'text': 'The heartbeat tag is now KMAC256, and it verifies every cycle.'}], width=940),
 fig('console-quote-variation', 'two quotes for the same challenge',
     'Two quotes requested with the same challenge: both ML-DSA-65 signatures verify with the pinned key and they differ, but '
     'the PSA token inside also differs, because TF-M signs it with randomized ECDSA, so this does not show hedged signing.',
     '$ tools/board/hedged_quotes.py <stm32> 7444 stm32h573-dk.mldsa65.pub', qvar,
     [{'lines': [2, 3], 'title': 'Both valid, both different', 'text': 'Two ML-DSA-65 signatures for one challenge, each checked as the gateway does.'},
      {'lines': [4, 4], 'title': 'The token changed too', 'text': "Same claims, but TF-M's own ECDSA signature differs: the signed message is not the same."},
      {'lines': [5, 5], 'title': 'What it shows', 'text': 'Not hedging. That is shown on the PC with the partition code signing one message twice.'}]),
 fig('console-two-boards', 'two chips with the same firmware',
     'Two STM32H573 boards with identical firmware, option bytes and boot loader: their ML-DSA-65 keys differ, their PSA '
     'identity is the same, and the second board is refused when it presents itself under the first board\'s name.',
     '$ PQKEY and CHAL on both boards; fleet.py once with each pinned key', two,
     [{'lines': [1, 4], 'title': 'Board 1', 'text': 'Its ML-DSA key, and the PSA identity from TF-M\'s development provisioning.'},
      {'lines': [5, 8], 'title': 'Board 2', 'text': 'A different ML-DSA key; exactly the same PSA instance and implementation IDs.'},
      {'lines': [9, 9], 'title': 'Keys', 'text': '1,941 of 1,952 bytes differ: the key comes from the chip.'},
      {'lines': [10, 11], 'title': 'Impersonation', 'text': "Under board 1's name board 2 is refused; under its own key it is admitted."}]),
 fig('console-two-endpoints-demo', 'two STM32 endpoints and the Arduino, during the demo',
     'The gateway journal during the demo with both STM32 boards on the network: board 1 is quarantined when its tampered '
     'image runs and admitted again with a new session when the good image is back, while board 2 stays admitted with its '
     'heartbeat counter rising and the Arduino is quarantined every cycle because it cannot attest.',
     '$ tools/demo.sh      # gateway journal for the run', duo,
     [{'lines': [1, 3], 'title': 'Before', 'text': 'Both STM32s admitted with their own sessions; the Arduino says it cannot attest.'},
      {'lines': [4, 4], 'title': 'Board 1 tampered', 'text': 'Its non-secure image is not in the policy: quarantined, credential revoked.'},
      {'lines': [5, 5], 'title': 'Board 2 unaffected', 'text': 'Same cycle: still admitted, heartbeat 8. Each device is judged on its own evidence.'},
      {'lines': [7, 7], 'title': 'Board 1 back', 'text': 'The good image: admitted with a new session.'},
      {'lines': [10, 12], 'title': 'Steady again', 'text': 'Board 1 heartbeat 1, board 2 heartbeat 10, the Arduino quarantined.'}], width=940),
 fig('console-rw612-boot', 'the FRDM-RW612 starting the Aegis prover',
     'The FRDM-RW612 console after a reset: Zephyr starts the prover, which lists the keys the boot ROM left in ELS (the die '
     'master key in slots 0 and 1, other ROM keys in 2, 3, 6 and 7), derives its ML-DSA-65 key from the die key, hashes '
     'its own image, sets a MAC address from the key, brings the Ethernet link up, gets an address and listens on port 7444.',
     '$ board console (USB serial), after a reset', rw_boot,
     [{'lines': [1, 2], 'title': 'Zephyr and the prover', 'text': 'Zephyr v4.5.0 starts the Aegis prover 0.1.0.'},
      {'lines': [3, 8], 'title': 'ELS key slots', 'text': 'Slots 0-1: the die master key (CKDF only). 2, 3, 6, 7: other ROM keys.'},
      {'lines': [9, 9], 'title': 'Key and image', 'text': 'The key is the same on every boot; the image hash is the APP measurement.'},
      {'lines': [10, 10], 'title': 'MAC', 'text': '02:ae and the first four bytes of the public key.'},
      {'lines': [11, 15], 'title': 'On the network', 'text': '100 Mb/s link, an address by DHCP, port 7444 open.'}]),
 fig('console-rw612-pc', 'the gateway\'s checks run from the PC',
     'Run from the PC with the gateway\'s own verifier code: the board\'s key fingerprint, twenty attestations in a row all '
     'admitted in 73 to 302 ms, the reported image hash equal to the hash of the built image, and a wrong reference refused.',
     '$ python3 fleet.attest() against the board, from the PC', rw_pc,
     [{'lines': [1, 1], 'title': 'The key', 'text': 'Fetched with PQKEY; the same across resets and images.'},
      {'lines': [2, 2], 'title': 'Twenty quotes', 'text': 'Each a fresh ML-DSA-65 signature on the Cortex-M33, plus the network.'},
      {'lines': [3, 3], 'title': 'The measurement', 'text': 'Equal to sha256sum of the zephyr.bin that was flashed.'},
      {'lines': [4, 4], 'title': 'Wrong reference', 'text': 'A policy that allows another hash quarantines the board.'}]),
 fig('console-rw612-gateway', 'the gateway journal: good image, modified image, good image',
     'The gateway journal for the FRDM-RW612: admitted with device-key trust, a credential issued over ML-KEM-768 and '
     'KMAC heartbeats; then, with a modified image (one configuration value changed), quarantined with the credential '
     'revoked because the APP measurement is not allowed; then, with the good image back, admitted with a new session.',
     '$ ssh <gateway> journalctl -u aegis-fleet -o cat | grep frdm-rw612', rw_gw,
     [{'lines': [1, 1], 'title': 'Admitted', 'text': 'Device-key trust; a credential and an ML-KEM-768 session are issued.'},
      {'lines': [2, 3], 'title': 'Heartbeats', 'text': 'KMAC256 over the session, one per cycle.'},
      {'lines': [4, 6], 'title': 'Modified image', 'text': 'The key still signs, but APP is not allowed: quarantined, credential revoked.'},
      {'lines': [7, 7], 'title': 'Good image back', 'text': 'Admitted again with a new session.'},
      {'lines': [8, 10], 'title': 'Steady', 'text': 'Heartbeats 1, 2, 3 of the new session.'}], width=1100),
 fig('console-rw612-tz-boot', 'the FRDM-RW612 starting TF-M and the Aegis partition',
     'The board console after a reset with TrustZone: TF-M boots, the Aegis partition measures both flash partitions '
     'before any non-secure code runs, the non-secure prover starts, the partition derives its key in ELS at the first '
     'request, and the network comes up with the MAC address taken from that key.',
     '$ board console (USB serial), after a reset', tz_boot,
     [{'lines': [1, 1], 'title': 'TF-M', 'text': "NXP's TF-M v2.1.4 boots the secure image."},
      {'lines': [2, 2], 'title': 'Measured first', 'text': 'SPE and NSPE are hashed before the non-secure image runs.'},
      {'lines': [5, 6], 'title': 'Non-secure prover, key', 'text': 'The network side starts; its first request makes the partition derive the key in ELS.'},
      {'lines': [7, 9], 'title': 'On the network', 'text': 'MAC from the key (the console drops the leading 0), PHY up, DHCP, port 7444.'}], width=980),
 fig('console-rw612-tz-probes', 'non-secure reads of protected peripherals',
     'A test build of the non-secure prover reads one register of a peripheral at start-up. Under NXP rules the fuse '
     'controller and FlexSPI read fine. Under the Aegis rules every protected block faults: the chip restarts and the '
     'read never returns. The ENET register the prover needs still reads.',
     '$ endpoints/rw612/tfm/probe.sh <out> NAME=0xADDR ...   # summarised from the console of each run', tz_probe,
     [{'lines': [1, 2], 'title': 'NXP rules', 'text': 'Non-secure code reads the fuse controller and the flash controller.'},
      {'lines': [3, 6], 'title': 'Aegis rules', 'text': 'Fuses, flash controller, flash cache and TRNG: a fault on every attempt.'},
      {'lines': [7, 9], 'title': 'Reset, clock, system', 'text': 'They hold the ELS reset and clock: secure only.'},
      {'lines': [10, 14], 'title': 'After the review', 'text': 'The pin mux, SOC_TOP (with the SoC OTP controller), PMU and SYSCTL2 too.'},
      {'lines': [15, 15], 'title': 'Control', 'text': 'The ENET register the prover needs still reads.'}], width=900),
 fig('console-rw612-tz-gateway', 'the gateway journal: TrustZone, a modified non-secure image, and back',
     'The gateway journal for the RW612 with TrustZone: admitted with trustzone trust, a credential issued through the '
     'secure partition and KMAC heartbeats; with a non-secure image changed by one byte, quarantined because the NSPE '
     'measurement is not allowed, credential revoked; with the good image back, admitted with a new session.',
     '$ ssh <gateway> journalctl -u aegis-fleet -o cat | grep frdm-rw612', tz_gw,
     [{'lines': [1, 3], 'title': 'TrustZone admitted', 'text': 'A credential through the secure partition, then heartbeats.'},
      {'lines': [4, 6], 'title': 'Modified non-secure image', 'text': 'Unreachable while it is flashed, then NSPE not allowed: credential revoked.'},
      {'lines': [7, 10], 'title': 'Good image back', 'text': 'Flashed again, then admitted with a new session and heartbeats.'}], width=1100),
 fig('console-rw612-fuzz', 'fuzzing the partition\'s protocol code',
     'The fuzz runs on the PC. On the reviewed code, every worker stopped within seconds: a refused PQKEMINIT had left '
     'the older exchange pending with the wrong key in it. After the fix, eight workers ran for 30 minutes each: about '
     'a million executions with the sanitizers on, and no crash, sanitizer report or disagreement with the model.',
     '$ tests/fuzz/run.sh 60 4        # aegis_proto.c as reviewed (0.2.0)',
     [l.strip() for l in fz if l.strip().startswith('ORACLE: PQKEMFIN')][:1] +
     ['$ tests/fuzz/run.sh 1800 8      # 0.2.1, the fix'] +
     [l.split(': ', 1)[1].split(' lim:')[0] for l in fz if ' DONE ' in l] +
     [l for l in fz if l.startswith('total executions')] +
     ['$ tests/fuzz/coverage.sh <corpus>'] +
     ['aegis_proto.c: functions 100.00 %, lines 94.68 %, branches 89.76 %' for l in fz if 'aegis_proto.c' in l and '94.68%' in l][:1],
     [{'lines': [1, 1], 'title': 'Before the fix', 'text': 'The model expected no pending exchange; the device still had one.'},
      {'lines': [3, 10], 'title': '8 workers, 30 min', 'text': 'Executions per worker, coverage and corpus size.'},
      {'lines': [11, 11], 'title': 'Result', 'text': 'About a million executions, nothing found.'},
      {'lines': [13, 13], 'title': 'Reached', 'text': 'The 20 missed lines are listed in the evidence, each with its reason.'}], width=980),
 fig('console-enforcement-reply-bug', 'the ruleset that let no endpoint in',
     'tests/host/test_enforcement.sh with two new checks: can the gateway reach the endpoint it must attest? With the '
     'ruleset as it was, no: the input chain dropped the replies to the gateway\'s own connections. With the reply rule, '
     'yes, and the endpoint still cannot open other gateway ports.',
     '$ sudo tests/host/test_enforcement.sh      # the ruleset of 17 November', enf_old +
     ['$ sudo tests/host/test_enforcement.sh      # with "ct direction reply accept"'] + enf_new,
     [{'lines': [1, 5], 'title': 'Before', 'text': 'The gateway cannot attest an endpoint that is not admitted: nobody is ever let in.'},
      {'lines': [6, 6], 'title': 'Before', 'text': '11 passed, 2 failed.'},
      {'lines': [8, 13], 'title': 'After', 'text': 'Attestation works both ways; other gateway ports stay closed.'}], width=1000),
 fig('console-enforcement-vlan', 'one gateway port and a VLAN switch, in network namespaces',
     'tests/host/test_enforcement_vlan.sh: a VLAN-filtering bridge plays the switch, vlan-setup.sh and the ruleset run '
     'unchanged in the gateway namespace. It checks admission and quarantine, the ways around a VLAN, and two known '
     'limits, which behave as stated.',
     '$ sudo tests/host/test_enforcement_vlan.sh', vlan,
     [{'lines': [1, 5], 'title': 'Not attested', 'text': 'Only the quote port; the gateway can attest it.'},
      {'lines': [6, 9], 'title': 'Admitted', 'text': 'To the LAN through the gateway; a second, unattested endpoint still cannot.'},
      {'lines': [10, 12], 'title': 'Quarantined', 'text': 'Cut off; still attested.'},
      {'lines': [13, 16], 'title': 'Ways around', 'text': 'A LAN address, self-tagged frames, LAN to endpoint: all blocked.'},
      {'lines': [17, 22], 'title': 'Known limits', 'text': 'Same-VLAN endpoints see each other; a taken address passes until the next cycle.'},
      {'lines': [23, 25], 'title': 'Undo', 'text': 'Nothing is left behind.'}], width=1000),
]
yaml.safe_dump(figs, open(os.path.join(ROOT, 'docs', 'diagrams', 'console.yaml'), 'w'), sort_keys=False, width=140, allow_unicode=True)
print(len(figs), 'console figures')

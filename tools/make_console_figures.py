#!/usr/bin/env python3
"""Build docs/diagrams/console.yaml (console figures with numbered callouts) from the records in evidence/console/.

Every line drawn comes from a file a real run wrote; this script only adds the command line and the callouts.
Run it, then tools/gen_diagrams.py.
"""
import os, re, yaml
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def rec(name): return [l.rstrip('\n') for l in open(os.path.join(ROOT, 'evidence', 'console', name)) if l.strip()]
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
]
yaml.safe_dump(figs, open(os.path.join(ROOT, 'docs', 'diagrams', 'console.yaml'), 'w'), sort_keys=False, width=140, allow_unicode=True)
print(len(figs), 'console figures')

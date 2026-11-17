#!/usr/bin/env python3
"""Build docs/diagrams/console.yaml (console figures with numbered callouts) from the records in evidence/console/.

Every line drawn comes from a file a real run wrote; this script only adds the command line and the callouts.
Run it, then tools/gen_diagrams.py.
"""
import os, yaml
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
]
yaml.safe_dump(figs, open(os.path.join(ROOT, 'docs', 'diagrams', 'console.yaml'), 'w'), sort_keys=False, width=140, allow_unicode=True)
print(len(figs), 'console figures')

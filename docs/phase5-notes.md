# Phase 5 notes: red-team checks and regression (working log)

## What the harness tries to break (2026-11-16)

`tests/redteam/fuzz_host.py` (PC, no hardware):
- token parser: 3000 mutated/truncated/random PSA tokens; property: nothing whose signed parts
  (protected header, payload, signature) changed is accepted; only the expected error types.
- aegisd quote service: 310 malformed frames (garbage, wrong JSON, huge length prefix, bad nonce)
  and a half-open "slow" client; property: the service keeps answering, quotes still verify,
  a slow client does not delay others.
- fleet verifier vs a hostile endpoint: 800 random reply lines; a post-quantum endpoint answering
  with a valid classic-only token (downgrade); a validly signed ML-KEM key from an earlier nonce
  (replay); property: never admitted, never provisioned.

`tests/redteam/fuzz_devices.py` (real devices): 76 malformed commands to the STM32 prover
(bad hex, wrong lengths, 20-30 KB lines, KEM steps out of order, random bytes) and 240 malformed
frames plus a half-open client to the gateway's quote service.

## Findings and fixes

1. **Accepted token with a changed unprotected header** (mutation a0 -> 80: empty map -> empty
   array). The signed parts were identical, so no forgery, but COSE requires a map there. The
   parser now rejects wrong field types (unprotected not a map, protected header or claims not a map).
2. **Quote service could be stalled by one client**: it served connections one at a time, so a
   client that sent half a frame held it for the read timeout (about 2 s per malformed frame in the
   first run; the first fuzz run took 9 min 45 s because of it). Now one thread per connection,
   at most 8, 3 s timeout, and the hardware lock covers only the system-controller read. A quote
   with a half-open client connected: 1 ms on the PC, 72 ms on the board.
   Deploying the fix changed the gateway's code hash: the PC verifier flagged
   "measurement changed: aegisd_code_sha256" until re-enrolment (intended).

## Results after the fixes

| Check | Result |
|---|---|
| token mutations accepted / unexpected exceptions | 0 / 0 (3000) |
| aegisd after 310 malformed frames; with a slow client | valid quote; 0.001 s |
| hostile endpoint replies admitted | 0 of 800 |
| classic-token downgrade; KEM key replay | refused; refused |
| STM32: 76 malformed commands | 76 x ERR, genuine PQ quote still verifies |
| STM32: PQKEMFIN without PQKEMINIT | ERR pq -137 (PSA_ERROR_BAD_STATE from the secure side) |
| gateway: 240 malformed frames + half-open client | quote valid in 0.072 s |

## Regression

`tools/regression.sh [--board]`: host unit tests (34), host red-team, RTL simulation, ACVP on the PC,
vector checksums; with --board: gateway Phase 1 checks, fabric self-test, ACVP with fabric Keccak,
fleet admission, ML-KEM session agreement, device red-team. 2026-11-16: 11/11 PASS in 90 s
(logs/regression/20261116-160803).

Not covered yet: side-channel and fault-injection checks (need lab equipment), power loss during
provisioning, network-level attacks once the gateway is in the traffic path.

## Demo script (2026-11-16)

`tools/demo.sh` (PC, about 1 min 45 s, logs in logs/demo/<time>/): (1) the PC verifies the
gateway's own ML-DSA-65 quote; (2) the gateway attests the STM32 (ML-DSA-65 over the TF-M token),
the fleet service shows the ML-KEM credential and session heartbeats; (3) a tampered Non-Secure
image (validly signed, boots normally) is flashed -> QUARANTINED, credential revoked, 0 credential
files left; (4) the good image is flashed back -> ADMITTED with a new session, heartbeat 1,
gateway and STM32 report the same session. Two clean runs on the boards (logs/demo/20261116-165457
and the following run). The script reads verdicts from the gateway service's journal; one-off checks
use `fleet.py once --no-credentials` so they never start a second key exchange next to the service.

Observed in passing: after the STM32 reboots (session lost from secure RAM) its heartbeat fails and
the gateway issues a new session at the next cycle (journal 15:57:11).

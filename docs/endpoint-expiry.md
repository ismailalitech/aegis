# The session's end on the endpoint (state of 2026-11-19: built and tested on the PC, not yet on the boards)

A credential lasts an hour and the gateway renews it five minutes before it expires (`architecture.md`). Until now
only the gateway checked that: an endpoint kept answering heartbeats under a session for as long as it had power. If
the gateway was gone, or the endpoint's non-secure side was taken over, the session never ended from the endpoint's
side.

Now every endpoint ends its session itself, on a clock of its own secure side.

## What the endpoint does

1. **The lifetime comes from the signed credential.** The gateway's credential already carries `"issued"` and
   `"expires"` (seconds), under its ML-DSA-65 signature. The endpoint takes `expires - issued`. Nothing was added to
   the credential and the gateway is unchanged.
   - The signed text must hold `"issued":` and `"expires":` exactly once each, followed by 1 to 10 decimal digits and
     then `,` or `}`; the difference must be between 1 second and one day (86400 s). Anything else is refused
     (`ERR cred validity`), like a credential for another exchange, and the session in place stays. (The Linux
     prover parses the JSON and wants the two fields as integers, with the same limits.)
   - The two times are only subtracted. The endpoint has no wall clock and never compares them with one.
2. **The start is the endpoint's own clock** at the accepted `PQKEMFIN`.
3. **Every request first reads that clock**, whatever the request is. A session older than the lifetime plus a
   margin is wiped (session key and credential hash). So is a session whose age the clock can no longer give: the
   clock fails, shows less than at the start, or its settings were changed.
4. **After that** `PQHB` and `PQSESSION` answer an error, and the gateway, which treats any failed heartbeat the same
   way, provisions again in the same cycle (`test_session_ended_by_the_endpoint_is_provisioned_again`). Attestation
   (`PQCHAL`) needs no session and keeps working.
5. **Without a trusted clock no session starts** (`ERR clock`): the endpoint is still attested and admitted, but gets
   no credential, which shows on the gateway as "provisioning failed".

| Reply | Meaning |
|---|---|
| `ERR pq no-session` | no session since the last reset |
| `ERR pq expired` | the last session was ended by the endpoint's clock; stays until the next session starts |
| `ERR cred validity` | signed and bound credential without a usable lifetime; the exchange is refused |
| `ERR clock` | no trusted clock now; the pending exchange stays |

The STM32's non-secure prover prints the partition's status codes instead: `ERR pq -137` (no session), `ERR pq -140`
(expired), `ERR pq -133` (validity), `ERR pq -147` (no clock).

**The margin is one sixteenth of the lifetime** (225 s for an hour: the session ends 3825 s after the `PQKEMFIN`).
It covers an endpoint clock up to 6 % fast: such an endpoint still does not end a session before the gateway's own
expiry. The least exact clock among the endpoints is the STM32's internal 32 kHz oscillator (LSI), an RC oscillator
good to a few per cent; the others count a crystal's clock. A slow clock lengthens the session by its error (5 % slow:
about 67 minutes of real time for an hour's credential). The actual rate of each board's clock is still to be read on
the bench, from `ttl`. In normal operation none of this is reached: the gateway replaces the session after 55 minutes.

Every heartbeat status ends with `;ttl=<seconds left>`, under the MAC. On the bench that shows the endpoint's clock
running, and its rate against the gateway's clock, without waiting an hour.

## The clock on each endpoint

A counter that only advances is enough. It must be one the non-secure side (or the normal world) cannot set, slow or
stop.

| Endpoint | Clock | Why the other side cannot move it | What can |
|---|---|---|---|
| STM32H573, TF-M v2.3.0 | the RTC on the LSI, run as a 32-bit binary counter at 250 Hz (a wrap every 198 days) | it has its own oscillator and counts in every power mode. At each start the partition sets `RTC_SECCFGR.SEC` and `RTC_PRIVCFGR.PRIV` (RTC registers, and with them the RTC's clock selection, enable and the backup-domain reset in `RCC_BDCR`, secure) and `RCC_SECCFGR.LSISEC` (the LSI's enable bit secure). Every reading checks all settings again. Still to be probed on the board from the non-secure side, as the other TrustZone rules were (`evidence/stm32-tz/`) | a debugger (it can freeze the RTC while the core is halted); temperature and voltage (the LSI's rate) |
| RW612, NXP TF-M v2.1.4 | the secure SysTick, counting the SysTick function clock (main clock / 256, about 1 MHz); the partition counts the wraps (one every 16.5 s) | ARMv8-M banks the SysTick registers per security state, and TF-M sets `AIRCR.PRIS`, so no non-secure exception or mask holds back its interrupt. The clock's mux and divider, the main clock and the PLL are in `CLKCTL0`, `SYSCTL2` and the PMU, which the Aegis `target_cfg.c` already makes secure-only. The partition also makes deep sleep a secure decision (`SCR.SLEEPDEEPS`). Every reading checks the settings | a debugger; see the fallback below |
| ZynqMP, OP-TEE 4.7.0 | `TEE_GetSystemTime`, which this build takes from the physical counter (`CNTPCT_EL0` / `CNTFRQ_EL0`) | the normal world cannot write the physical counter or its frequency register (`CNTVOFF_EL2` moves only the virtual counter it sees itself). The TA asks OP-TEE for the time's protection level and starts no session below 1000 (a time taken from Linux) | the counter's clock is set in `CRL_APB` (`TIMESTAMP_REF_CTRL`), which the normal world reaches until phase C restricts it (`zynqmp-key-design.md`): a hostile kernel could slow or stop it there |
| RW612, Zephyr prover (one image) | Zephyr's uptime | nothing: one image, no secure side ("device-key trust") | the firmware itself |
| Linux prover | `CLOCK_BOOTTIME` (monotonic, counts suspended time) | setting the date does not move it | root; software trust, like its key |

Rejected on the STM32: SysTick and timers on the system clock (TF-M's platform code leaves the clock tree and the power
controller to the non-secure image, and locks the peripheral security settings before a partition runs; Stop mode
stops them), and the cycle counter (`DWT_CYCCNT`: writable from the non-secure side, wraps in 17 s).

Rejected on the RW612: the OS timer, the CTIMERs and the RTC. Their clock gates, clock selection and resets are in
`CLKCTL1` and `RSTCTL1`, which the non-secure image can write.

**The RW612's fallback.** If the function clock does not count at the expected rate when the partition starts (it is
measured against the processor clock, with the non-secure SysTick as a second counter, before the non-secure image
runs), the secure SysTick counts the processor clock instead (a wrap every 64.5 ms at 260 MHz). TF-M's flash driver
masks interrupts for a whole erase, and an erase longer than a wrap then loses time: a non-secure image that keeps
TF-M's storage erasing could stretch a session. The heartbeat status says which clock runs: `clk=ref` or `clk=cpu`.

## What this gives, and what it does not

- **It ends a session after its lifetime** when the gateway does not renew it: the gateway is gone or unreachable, or
  someone holds the endpoint's non-secure side and keeps asking for heartbeat proofs. After 3825 s of the endpoint's
  clock the secure side gives no more proofs for that session and has wiped its key.
- **The key is wiped at the first request after the end**, not at the end itself: nothing runs in between. Without a
  request nothing can use the key either.
- **It is not a wall clock.** The endpoint cannot tell whether a credential is current, only how long it may be used
  once accepted. A credential cannot be replayed anyway: it names the ciphertext and the key of one exchange.
- **It does not detect an endpoint that is off or restarted.** A reset loses the session (it is in RAM), which is
  the safe direction; the gateway's attestation cycle sees the rest.
- **A clock that the other side can slow lengthens the session.** That is the ZynqMP's timestamp clock until phase C,
  the RW612's fallback clock, and any debugger (out of scope on this bench: `threat-model.md`, limitation 1).
- **The clocks are not yet verified on the boards.** The protocol logic is tested on the PC and fuzzed against a
  model; the STM32's RTC code runs there against a stand-in for the registers. First on each board: `ttl` must fall by
  the gateway's cycle time from one heartbeat to the next.

## Checking it on a board

1. In normal operation: the gateway's journal shows the status of every heartbeat. `ttl` starts near 3825 and must fall
   by the cycle time (a little over 30 s) from one heartbeat to the next, back to 3825 when the gateway renews the
   credential after 55 minutes. On the RW612 the status must say `clk=ref`.
2. The end itself, in about a minute: `tests/board/expiry_check.py`, on the gateway with the `aegis-fleet` service
   stopped. It provisions with a lifetime of 32 s, checks a heartbeat at once and one half-way (with the rate of the
   endpoint's clock from the two `ttl` values), and after the end expects `ERR pq expired` (STM32: `ERR pq -140`) for
   `PQHB` and `PQSESSION`, and an answer to `PQCHAL`. A longer `--lifetime` gives a better figure for the rate.
3. The gateway's side of it: with the service running again, the first cycle reads "issued session ...".

## Old and new together

The credential format did not change, so no combination needs a flag day.

| Gateway | Endpoint | Result |
|---|---|---|
| any (the credential has carried `issued` and `expires` since the first version) | new | sessions end on the endpoint after 3825 s; the status gains `;ttl=` |
| any | old | as before: the endpoint never ends a session |
| a gateway with a lifetime over one day, or without the two fields | new | every exchange refused with `ERR cred validity`: admitted, "provisioning failed" (`test_fleet.py` checks the gateway's lifetime against the endpoints' limit) |

On the STM32 the non-secure prover is unchanged (0.6.0): it passes the partition's status text and codes through.
Provers up to 0.5.0, which do not ask for the status text, get no `ttl` in it; the session ends all the same.

## Where it is

| | |
|---|---|
| `endpoints/rw612/prover/src/aegis_proto.c` | the rule, for the RW612 partition, the Zephyr prover and the ZynqMP TA; the platform gives `monotonic_s` |
| `endpoints/rw612/tfm/aegis_pq/aegis_pq.c` | the secure SysTick |
| `endpoints/zynqmp/optee/ta/aegis_ta.c` | OP-TEE's system time and its protection level |
| `endpoints/stm32h573/tfm-aegis-partition/aegis_pq_attest.c` | the rule again (this partition has its own code) and the RTC |
| `endpoints/zybo/aegis_linux_prover.py` | the rule in Python |
| `tests/host/test_rw612_proto.py`, `test_linux_prover.py`, `test_fleet.py` | before the end accepted, at the end refused and the session gone, no clock, a clock running backwards, credentials without a lifetime, the gateway provisioning again |
| `tests/fuzz` | both partitions against a model that holds the clock: every answer after any sequence of requests, clock moves and clock faults |
| `endpoints/zynqmp/optee/tests` | the TA with a trusted and an untrusted system time |
| `tests/board/expiry_check.py` | the check on a real endpoint, from the gateway (above); tried on the PC against the RW612 code built for the PC |

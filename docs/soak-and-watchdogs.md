<!-- SPDX-License-Identifier: Apache-2.0 -->
# Step 6: watchdogs and the soak

The soak runs the bench as it is for a day and checks that nothing drifts, grows, hangs or restarts without a reason.
The default is **24 hours** (`--hours` changes it). A 14-day soak is not run. Instead, the credential lifetime is
shortened and extra expiry rounds are added, so the day goes through about as many session renewals as 14 days at
the normal lifetime. Slow growth is measured as a rate and projected over 14 days.

| | |
|---|---|
| Gateway | PolarFire SoC Discovery Kit, service `aegis-fleet` (30 s cycle), state `/var/lib/aegis`, journal kept on the SD card |
| Endpoints in the soak | `stm32h573-dk-2` (STM32H573, TF-M), `frdm-rw612` (NXP RW612, TF-M), `zynqmp-te0808` (ZynqMP, OP-TEE) |
| Absent, tolerated | `stm32h573-dk` (board 1, unplugged: QUARANTINED "No route to host" every cycle), `arduino-uno` (quarantined by design) |
| PC tools | `tools/soak.py` (the runner), `tools/bench_watch.py` (the liveness watchdog), `tools/console_logger.py` (the gateway's kernel console) |

Both lists can be changed: `--endpoints` and `--absent`. Quarantine of an endpoint on the absent list is counted
and reported but never fails the soak. An endpoint on neither list is ignored.

## What the soak must catch

| Risk | How it is seen | Where it is checked |
|---|---|---|
| Gateway hang (the unexplained ~7 h hang of 18-19 November) | no SSH answer for 2 samples in a row; `fleet-state.json` not rewritten for 300 s while the service says active; aegis-fleet silent in the journal; a new `boot_id` (the hardware watchdog reset it) | soak.py, bench_watch.py, the console log |
| Gateway or service restart | `boot_id` changes; aegis-fleet `NRestarts` grows or its `MainPID` changes; the same for `aegisd` | soak.py |
| Slow memory growth on the gateway | `VmRSS` of aegis-fleet and aegisd, `MemAvailable`, the fleet's open file descriptors: a slope per hour, projected over 14 days | soak.py (live after 6 h, and in the report) |
| Flash and storage growth on the gateway | `du /var/lib/aegis` (credentials, audit log), root file system use, `journalctl --disk-usage` (journald keeps 50 MB) | soak.py |
| Slow growth on the devices | the secure stack high-water mark in the heartbeat status (`sstack=` on the STM32, `stack=` on the RW612) | soak.py |
| Device reset | `uptime_s` (STM32) or `requests` (RW612, ZynqMP) going down in the heartbeat status | soak.py |
| Counter and clock drift | the heartbeat counter must grow within a session. `ttl` against the gateway's clock gives each endpoint's clock rate. The gateway's clock against the PC's must not step. NTP state | soak.py |
| Credential renewal and expiry | every session change must come when the renewal is due: less than 300 s left (`RENEWAL_WINDOW_S`). A change before that means the session was revoked. A credential past its renewal or its end fails. The lifetime in use is compared with the one expected. The expiry check (`tests/board/expiry_check.py`) runs in each regression and in each extra round | soak.py, the regression's `endpoint-expiry` stage |
| Heartbeat `ttl` behaviour | `ttl` never above the lifetime plus a sixteenth, never below 60 s (that would mean the renewal is late and the endpoint is about to end the session) | soak.py |
| Link loss and recovery | an endpoint without a verdict line in a sample, a QUARANTINED line, `link=0` in the status. For a deliberate cable pull, see "Planned events" | soak.py, bench_watch.py |
| Kernel trouble | `journalctl -k -p err`: panic, soft or hard lock-up, oops, BUG, hung task, OOM, RCU stall. Also the same patterns in the kernel console log, which survives a hang | soak.py (`--console-dir`) |
| Fleet errors | journal lines with `Traceback`, `enforcement FAILED`, `enforcement hook failed`, `policy REFUSED`, `NO AUDIT LOG`, `could NOT be written`, `MemoryError` | soak.py |

## Pass and fail

The soak **passes** only if all of the following hold:

1. it ran to its end;
2. the regression (`tools/regression.sh --board --with-expiry`) passed at the start, at the middle (12 h) and at the
   end, and every extra expiry round passed. A regression still running after 45 min (an expiry round after 20 min;
   `--regression-timeout-min`, `--expiry-timeout-min`) is stopped and fails;
3. no failure below happened outside a planned window.

**Fail** (any one is enough):

- Any QUARANTINED line for an endpoint in the soak, a sample without a verdict line for one of them, or a session
  missing on the gateway.
- Any reboot of the gateway, or any reset of an endpoint. Planned windows never excuse these, the regression's
  windows included. The soak itself never causes a reboot or a reset.
- aegis-fleet or aegisd inactive, restarted by systemd (`NRestarts`), or with a new process outside a planned window.
- A gateway hang: no SSH answer for 2 samples (10 min), `fleet-state.json` older than 300 s, or no aegis-fleet journal
  line between two samples.
- A heartbeat counter that stops within a session; a session replaced before its renewal was due; a renewal overdue by
  more than 180 s; a stored credential past its end.
- `ttl` above the lifetime plus a sixteenth, or below 60 s. An endpoint's clock rate outside 0.90 to 1.06 endpoint
  seconds per gateway second. The endpoints' margin covers a clock up to 6 % fast. The STM32's LSI was measured at
  0.941. The rate comes from heartbeat pairs: two lines in a row of one session, up to 600 s apart, giving the `ttl`
  fallen against the gateway time between their journal stamps. A new session starts a new run of pairs, because its
  `ttl` starts again. The journal sometimes stamps one line about 10 s late and the next about 10 s early, so a single
  pair can read 0.74 or 1.29. The soak therefore leaves out each pair more than 0.25 from the median pair rate, pools
  the rest (total `ttl` fallen over total gateway time), and judges only once at least 30 min and 6 pairs are left.
  The report shows the rate, its span and how many pairs were left out. A 3 h soak on 2026-11-20 reported 1.535 for
  the STM32, which actually ran at 1:1: one pair spanned the regression's new, shorter session (`ttl` 1790 to 604 in
  184 s).
- A secure stack high-water mark at 90 % of its size or more.
- The gateway's clock stepping by more than 120 s against the PC's.
- A kernel line or console line from the fatal list, or a fleet error line. A fleet error line that names an endpoint
  is that endpoint's: on an absent endpoint it is INFO, and a planned window for that endpoint excuses it.
- Projected growth over 14 days, over one-process runs of at least an hour that add up to at least 6 h, above these
  bounds:

  | Metric | Bound over 14 days |
  |---|---|
  | aegis-fleet `VmRSS` | 16 MB |
  | aegisd `VmRSS` | 8 MB |
  | aegis-fleet file descriptors | 32 |
  | `MemAvailable`, fall | 64 MB |
  | `/var/lib/aegis` | 64 MB |
  | root file system | 256 MB |

  Absolute limits: the journal on disk at most 64 MB, at least 10 % free on `/`, `MemAvailable` at least 64 MB,
  at most 256 descriptors.

The bounds are starting values; `--bound NAME=VALUE` changes one, and the report prints the bound used next to each
figure.

**Known and expected** (logged as INFO or EXPECTED, not a failure):

- A renewal of each session when it has less than 300 s left: every 55 min at the normal lifetime, about every 5 min
  at 600 s. Each renewal also writes an `issue` and an `expiry` entry to the audit log, if the policy keeps one.
- The QUARANTINED lines of the absent endpoints (`stm32h573-dk`, `arduino-uno`).
- During a regression run, and for 5 min after it, only what its stages do: aegis-fleet stopped and started by the
  `endpoint-expiry` stage (a new process), sessions of the soak's endpoints replaced, and their quarantine and
  readmission by the expiry check. The gaps the stop leaves (aegis-fleet inactive, its journal quiet, its state file
  stale, an endpoint silent, without a session, with its counter stopped or its renewal overdue) are excused for at
  most 600 s each (`--bound regression_gap_s=...`: the stage's 3 min stop and its 240 s readmission). Longer, they
  fail. An SSH hang, aegisd, systemd restarting aegis-fleet and fleet error lines are never excused by a regression.
  The red-team stage sends malformed requests to `stm32h573-dk-2`.
- Under the soak (`AEGIS_SOAK=1`, set by the runner) the regression's `fleet-session` and `fleet-heartbeat` stages
  run once more, 20 s later, after a failure: at the 600 s lifetime a renewal can rewrite the session key while the
  check reads it. Outside the soak they run once, as before.
- The kernel message `mpfs_rtc: timed out uploading time to rtc` (seen before the November hang and at other times; on
  its own it is not a failure).
- Single SSH failures (WARN). A second one in a row is a failure.
- `clk=cpu` on the RW612 (the fallback clock, `docs/endpoint-expiry.md`) and `link=0` give a WARN.

### Planned events

A deliberate disturbance, such as pulling the RW612's cable for five minutes to watch link-loss recovery, is announced
first:

    tools/soak.py plan --out logs/soak/<run> --minutes 10 --item frdm-rw612 --reason "cable pulled for link-loss recovery"

During the window, that item's failures are logged as EXPECTED. A failure is judged when a sample sees it, up to one
sampling interval after it happened, so every window (a regression's included) lasts one `--interval-min` longer than
announced. A condition that is still there when the window ends,
for example an endpoint not ADMITTED again, is logged again as FAIL. The window is in `<run>/planned.txt`, one line
per window: `<epoch from> <epoch to> <item or *> <reason>`.

## The watchdogs

| Layer | What | State |
|---|---|---|
| Gateway hardware | `mpfs_wdt` (28 s, nowayout) driven by systemd: `RuntimeWatchdogSec=20s`, `RebootWatchdogSec=25s` | in place since 19 November (`board-changes.md`) |
| Gateway kernel | `softlockup_panic=1`, `panic_on_oops=1`, `panic=10`: a lock-up becomes a panic with its reason on ttyS1, then a reboot | in place |
| Gateway console | `tools/console_logger.py` on the FlashPro5's second UART: the last kernel lines survive a hang | runs on the PC. `--console-dir` makes the soak read it |
| Gateway service | `aegis-fleet`: `Restart=on-failure`. The soak counts every restart | in place |
| PC: liveness | `tools/bench_watch.py`, read-only SSH every 2 min. It reports DOWN for the gateway, aegis-fleet, the journal (no aegis-fleet line in the window) and each endpoint (no ADMITTED line in the window, or **heartbeat counter stopped**: at least 3 heartbeat lines, all with the same counter and no new session). On each DOWN it saves a snapshot of the gateway (journal tail, `fleet-state.json`, unit status, kernel tail) in `<out>/evidence/` and runs `--alert-cmd` | extended in this step |
| PC: soak | `tools/soak.py`: every criterion above, live, every 5 min; the gateway's raw answer saved in `raw/` for every sample that fails | new in this step |

The two PC tools overlap on purpose. bench_watch keeps running when no soak is running, and it is quicker (2 min)
and simpler. The soak keeps the numbers.

## Compressing 14 days into 24 hours

**What is compressed: renewals and expiries.** At the normal lifetime (3600 s, renewed 300 s before its end) an
endpoint goes through about 26 sessions a day, about 367 in 14 days. Two existing mechanisms raise that in one day:

1. **A shorter credential lifetime.** This step adds `fleet.py watch --credential-lifetime S` (600 s to one day; the
   default and the code path are unchanged). At 600 s a session is renewed when 300 s are left, about every 5 to
   5.5 minutes: about 270 renewals per endpoint in 24 h, about three quarters of what 14 days make. Each one is a full
   KEM exchange, a credential signature, a new heartbeat key, an audit entry and the endpoint parsing a new lifetime.
   - Safe for the live endpoints: they accept a lifetime from 1 s to one day (`docs/endpoint-expiry.md`) and end a
     session after the lifetime plus a sixteenth (637 s). The gateway renews at 300 s left, so an endpoint still has
     about 337 s of its own clock at the renewal, enough even for a clock 6 % fast. `test_fleet.py` checks the bounds.
   - Not changed: the endpoints' firmware, the policy (a signed policy stays valid), the enforcement TTL (that is
     `admit_ttl`, set by the cycle, not by the credential).
   - More audit entries: the audit log writes at most one batch per 300 s (`AUDIT_SETTINGS`), about 1 MB a day. The
     soak's `/var/lib/aegis` trend shows it.
2. **Extra expiry rounds.** `--expiry-every-h 4` runs `tools/regression.sh --expiry-only` every 4 hours, in addition
   to the expiry stage of the three regressions. In 24 h the rounds fall at 4, 8, 16 and 20 h (the one at 12 h is left
out: the middle regression runs then), so 4 rounds and 3 regressions make 7 expiry checks on each endpoint. Each round stops
   aegis-fleet for about 3 minutes, under the stage's restart trap and the 15-minute guard timer on the gateway. On
   each endpoint it checks a 32 s credential end to end: accepted, `ttl` falling at the right rate, `ERR pq expired`
   after the end, attestation still answering.

**What is projected rather than compressed: growth.** Memory, descriptors, disk and journal are sampled and fitted.
The report gives the rate per hour and the growth it would reach in 14 days, against the bounds above. Linear
projection catches a steady leak. It does not catch a leak that only starts after days, or one that grows faster
over time.

**What a day does not reach:** counter wraps (the STM32's RTC wraps after 198 days; the RW612 counts SysTick wraps
every 16.5 s and that count does not wrap in 14 days either); clock drift with temperature over several days and
nights; journald's 50 MB rotation, unless the journal is already near it. The report says so; none of it is
claimed.

### Applying the short lifetime, and restoring it

All of this runs on the gateway, done by the main session (the soak tool does none of it). It is recorded in
`board-changes.md` like any other change.

Apply:

    # 1. the fleet.py of this branch; keep the running one (compare first: the gateway's copy may carry local changes)
    ts=$(date +%Y%m%d-%H%M%S); cp /root/aegis/gateway/aegisd/fleet.py /root/aegis-backup-fleet-$ts.py
    #    (copy gateway/aegisd/fleet.py from the PC to /root/aegis/gateway/aegisd/fleet.py)
    # 2. a drop-in that adds the option
    mkdir -p /etc/systemd/system/aegis-fleet.service.d
    printf '[Service]\nExecStart=\nExecStart=/usr/bin/python3 /root/aegis/gateway/aegisd/fleet.py watch /root/aegis/gateway/policy/fleet.json --interval 30 --state /var/lib/aegis/fleet-state.json --credential-lifetime 600\n' \
        > /etc/systemd/system/aegis-fleet.service.d/soak-lifetime.conf
    systemctl daemon-reload && systemctl restart aegis-fleet
    journalctl -u aegis-fleet -n 20 -o cat | grep 'credential lifetime 600 s'

Do this **before** the soak starts, or announce it with `soak.py plan` (the restart is a new process). Sessions
issued before the restart keep their hour and are replaced by 600 s ones as they come up for renewal, within 55
minutes. Then start the soak with `--cred-lifetime 600`, so that it expects that lifetime. A different lifetime in a
credential gives a WARN, and the report reminds you to restore.

Restore (after the soak):

    rm /etc/systemd/system/aegis-fleet.service.d/soak-lifetime.conf
    rmdir /etc/systemd/system/aegis-fleet.service.d 2>/dev/null
    systemctl daemon-reload && systemctl restart aegis-fleet
    # within about 5 minutes every session is renewed at 3600 s:
    for f in /var/lib/aegis/credentials/*.json; do python3 -c 'import json,sys; b=json.load(open(sys.argv[1]))["body"]; print(sys.argv[1], b["expires"]-b["issued"])' $f; done

The new `fleet.py` can stay: without the option it behaves exactly as before. To undo that as well, copy
`/root/aegis-backup-fleet-<ts>.py` back and restart aegis-fleet.

## Running it

Run from a checkout that has `.venv`, `build/acvp/commands.jsonl` and `bench.env` (the regression's host stages need
them), for example the main checkout after this branch is merged. In this order:

1. **Watchdogs on.** Check that `tools/console_logger.py` is recording the gateway console. Restart
   `tools/bench_watch.py` detached with the soak's endpoints. It defaults to them now; with
   `--alert-cmd 'notify-send aegis'` it also alerts:

       setsid nohup python3 $PWD/tools/bench_watch.py --gateway 192.0.2.10 \
           --expect stm32h573-dk-2,frdm-rw612,zynqmp-te0808 >/dev/null 2>&1 &

2. **Dry run.** `tools/soak.py selftest` (ten simulated days on a canned gateway, healthy and with faults, about 10 s), then
   `tools/soak.py run --dry-run --gateway 192.0.2.10 --stm32 <stm32h573-dk-2's host:port>`. It prints the sampling
   script, the regression command and its environment, and parses one canned sample.
3. **One read-only sample by hand** (optional): pipe the printed script to `ssh root@192.0.2.10 sh -s` and look at
   the answer.
4. **Short lifetime** (recommended): apply it as above, wait for `credential lifetime 600 s` in the journal.
5. **Start the soak**, detached:

       setsid nohup .venv/bin/python tools/soak.py run --gateway 192.0.2.10 --stm32 <host:port> \
           --cred-lifetime 600 --expiry-every-h 4 --console-dir <console_logger dir> \
           > logs/soak-runner.out 2>&1 &

   The regression's STM32 stages use `--stm32` (default `$STM32_2`), passed as `AEGIS_STM32_OVERRIDE`, which wins over
   `bench.env`'s `STM32` (board 1). `EXPIRY_ENDPOINTS` is set to the soak's endpoints.
6. **While it runs:** `tail -f logs/soak/<run>/events.log`. Announce any deliberate disturbance with `soak.py plan`. If the
   PC or the runner stops, `tools/soak.py run --resume logs/soak/<run>` continues: the stored settings are kept, the
   journal since the last sample is read (at most 6 h back), and a regression that was interrupted runs again. The
   regression runs in a process group of its own; stopping the runner (SIGTERM, SIGHUP, Ctrl-C) sends SIGTERM to the
   whole group, so the expiry stage's restart trap runs, and SIGKILL after 180 s. If the runner was killed and its
   regression is still running, the resumed runner waits for that process group to end (at most the timeout) before
   it runs the stage again, so two regressions never overlap.
7. **At the end:** `logs/soak/<run>/report.md` gives the verdict, every failure with its first time and count, the
   regressions, a table per endpoint (renewals, last counter, clock rate, resets, stack) and the gateway trends.
   Restore the lifetime. Copy `report.md`, `samples.csv` and `events.log` (and any `raw/` and bench_watch `evidence/`
   files) into `evidence/soak-<date>/`.

`tools/soak.py report logs/soak/<run>` writes the report again at any time, for example halfway through. A report from
an unfinished run says INCOMPLETE.

## Files

| | |
|---|---|
| `tools/soak.py` | the runner. Sampling commands (`COMMANDS`, checked read-only by `check_commands`), parsers, criteria, report, canned gateway (`FakeGateway`), `selftest` |
| `tools/bench_watch.py` | the liveness watchdog, with the heartbeat-stopped and journal items, evidence snapshots and `--alert-cmd` |
| `tools/regression.sh` | `--expiry-only` (one stage) and `AEGIS_STM32_OVERRIDE` |
| `gateway/aegisd/fleet.py` | `--credential-lifetime` |
| `tests/host/test_soak.py` | parsers against real, garbled and hostile output; each criterion; trends across restarts; planned windows; stop and resume; bench_watch's items |
| `logs/soak/<run>/` | `samples.csv` (one row per sample, gateway and per-endpoint columns), `events.log`, `state.json`, `planned.txt`, `raw/`, `regression-*.log`, `report.md` |

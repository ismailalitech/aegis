# Soak, 2026-11-23 01:18 to 2026-11-24 01:28 (CET)

The 24-hour soak of [`docs/soak-and-watchdogs.md`](../../docs/soak-and-watchdogs.md) on stm32h573-dk-2, frdm-rw612
and zynqmp-te0808 (STM32 board 1 unplugged, the Arduino quarantined by design), credential lifetime shortened to
600 s, a sample every 5 minutes, an expiry round every 4 hours. Result: **PASS** (`report.md`).

| file | what it is |
|---|---|
| `report.md` | the runner's verdict and tables, unedited apart from the masked gateway address |
| `samples.csv` | one row per sample (292): gateway clock, services, memory, disk, journal, and per endpoint the verdict count, session id prefix, heartbeat, ttl, uptime, requests and secure-stack use |
| `events.log` | every finding as it was raised or cleared, with the PC's local time (CET; the gateway journal is UTC) |
| `state.json` | the runner's state at the end: configuration and bounds, schedule, regression results, per-endpoint tracking, warnings. `report.md` is made from this file and `samples.csv` |
| `raw/` | the gateway's whole answer for the samples in which a check raised a finding (here: expected ones only, at each regression and at the end) |
| `regression-start.log`, `-middle.log`, `-end.log` | output of `tools/regression.sh --board --with-expiry` (14 stages each) |
| `regression-expiry-N.log` | output of `tools/regression.sh --expiry-only` at 4, 8, 16 and 20 h (the round at 12 h is the middle regression's) |

## How it was produced

    tools/soak.py run --gateway <addr> --stm32 <stm32h573-dk-2's host:port> --hours 24 --interval-min 5 \
        --cred-lifetime 600 --expiry-every-h 4 --console-dir <tools/console_logger.py's directory>

The runner writes `report.md` itself when the run ends. It can be written again from the files here, and gives the
same text:

    tools/soak.py report evidence/soak-20261123

## Changed for publication

- the gateway's LAN address is masked as `192.168.x.x` (`report.md`, `state.json`), as in the other records;
- the console directory in `state.json` is given relative to the home directory.

Nothing else is edited. The 16-digit session values are prefixes of the session identifier (a hash of the session
key, the one the gateway prints in its journal), not key material. The regression logs name `logs/regression/...`
directories with the per-stage output; those stay on the bench PC.

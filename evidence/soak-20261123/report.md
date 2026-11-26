# Soak report

**Result: PASS**

| | |
|---|---|
| started | 2026-11-23T01:18:25+01:00 |
| planned end | 2026-11-24T01:18:25+01:00 (24 h) |
| finished | yes |
| gateway | 192.168.x.x |
| endpoints | stm32h573-dk-2, frdm-rw612, zynqmp-te0808 |
| absent / quarantined by design (ignored) | stm32h573-dk (2512 verdict lines), arduino-uno (0 verdict lines) |
| credential lifetime expected | 600 s |
| samples | 292 (292 answered), every 5 min |
| longest time without an SSH answer | 0 s |
| gateway clock minus PC | +1 s first, +0 s last |

## Failures

None.

## Regression runs

| stage | result | start | minutes |
|---|---|---|---|
| start | PASS | 2026-11-23T01:18:28+01:00 | 6.5 |
| expiry-1 | PASS | 2026-11-23T05:18:28+01:00 | 2.5 |
| expiry-2 | PASS | 2026-11-23T09:18:28+01:00 | 2.5 |
| middle | PASS | 2026-11-23T13:18:28+01:00 | 6.5 |
| expiry-4 | PASS | 2026-11-23T17:18:28+01:00 | 2.5 |
| expiry-5 | PASS | 2026-11-23T21:18:28+01:00 | 2.5 |
| end | PASS | 2026-11-24T01:18:28+01:00 | 6.5 |

## Endpoints

| endpoint | verdict lines | quarantined | renewals | last heartbeat | clock rate (s/s) | resets | secure stack max | lifetime seen |
|---|---|---|---|---|---|---|---|---|
| stm32h573-dk-2 | 2512 | 0 | 282 | 7105 | 0.9876 over 67105 s (1946 pairs, 1 left out) | 0 | 18872/26624 (first 18872) | 600 |
| frdm-rw612 | 2512 | 0 | 281 | 6 | 1.0002 over 67175 s (1948 pairs, 1 left out) | 0 | 19176/32768 (first 19176) | 600 |
| zynqmp-te0808 | 2512 | 0 | 281 | 6 | 1.0000 over 67214 s (1949 pairs, 0 left out) | 0 | - | 600 |

## Gateway trends (runs of one fleet process of an hour or more; projected over 14 days)

| metric | first | last | min | max | per hour | 14 days | bound | judged | ok |
|---|---|---|---|---|---|---|---|---|---|
| fleet_rss_kb | 24624.0 | 24888.0 | 24244.0 | 25000.0 | 14.395 | 4836.7 | 16384 | yes (23.33 h) | yes |
| aegisd_rss_kb | 17744.0 | 17744.0 | 17744.0 | 17744.0 | 0.0 | 0.0 | 8192 | yes (23.33 h) | yes |
| fleet_fds | 3.0 | 3.0 | 0.0 | 5.0 | 0.016 | 5.3 | 32 | yes (23.33 h) | yes |
| mem_avail_kb | 454068.0 | 447856.0 | 447856.0 | 460192.0 | 10.618 | -3567.6 | 65536 | yes (23.33 h) | yes |
| aegis_du_kb | 848.0 | 2078.0 | 848.0 | 2078.0 | 49.256 | 16550.1 | 65536 | yes (23.33 h) | yes |
| root_used_kb | 340733.0 | 338937.0 | 338638.0 | 340939.0 | -83.448 | -28038.4 | 262144 | yes (23.33 h) | yes |

Journal on disk: 49.0 MB first, 46.0 MB last (journald keeps 50 MB).

## Warnings and expected events

- WARN gateway x1 (first 2026-11-23T03:08:25+01:00): kernel error: mpfs_rtc 20124000.rtc: timed out uploading time to rtc
- WARN gateway x1 (first 2026-11-23T09:43:25+01:00): kernel error: mpfs_rtc 20124000.rtc: timed out uploading time to rtc
- WARN gateway x1 (first 2026-11-23T13:33:25+01:00): kernel error: mpfs_rtc 20124000.rtc: timed out uploading time to rtc
- WARN gateway x1 (first 2026-11-23T18:08:25+01:00): kernel error: mpfs_rtc 20124000.rtc: timed out uploading time to rtc
- WARN gateway x1 (first 2026-11-23T18:43:25+01:00): kernel error: mpfs_rtc 20124000.rtc: timed out uploading time to rtc
- WARN gateway x1 (first 2026-11-23T20:08:25+01:00): kernel error: mpfs_rtc 20124000.rtc: timed out uploading time to rtc
- WARN gateway x1 (first 2026-11-23T20:28:25+01:00): kernel error: mpfs_rtc 20124000.rtc: timed out uploading time to rtc
- EXPECTED aegis-fleet x3 (first 2026-11-23T01:23:25+01:00): aegis-fleet is inactive
- INFO stm32h573-dk-2 x280 (first 2026-11-23T01:23:25+01:00): session renewed
- INFO frdm-rw612 x279 (first 2026-11-23T01:23:25+01:00): session renewed
- INFO zynqmp-te0808 x279 (first 2026-11-23T01:23:25+01:00): session renewed
- EXPECTED aegis-fleet x4 (first 2026-11-23T05:23:25+01:00): aegis-fleet has a new process (59778 -> 64414)
- EXPECTED stm32h573-dk-2 x1 (first 2026-11-24T01:28:28+01:00): heartbeat counter stopped at 7105
- EXPECTED frdm-rw612 x1 (first 2026-11-24T01:28:28+01:00): heartbeat counter stopped at 6
- EXPECTED zynqmp-te0808 x1 (first 2026-11-24T01:28:28+01:00): heartbeat counter stopped at 6

**Restore the normal credential lifetime** (docs/soak-and-watchdogs.md, "Restore"): seen 600 s.

Files: samples.csv, events.log, state.json, raw/ (gateway answers of failing samples), regression-*.log.

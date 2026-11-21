# Soak report

**Result: FAIL**

| | |
|---|---|
| started | 2026-11-20T21:55:38+01:00 |
| planned end | 2026-11-21T00:55:38+01:00 (3 h) |
| finished | yes |
| gateway | 192.168.x.x |
| endpoints | stm32h573-dk-2, frdm-rw612, zynqmp-te0808 |
| absent / quarantined by design (ignored) | stm32h573-dk (342 verdict lines), arduino-uno (0 verdict lines) |
| credential lifetime expected | 600 s |
| samples | 40 (40 answered), every 5 min |
| longest time without an SSH answer | 0 s |
| gateway clock minus PC | +1 s first, +1 s last |

## Failures

| item | first | count | what |
|---|---|---|---|
| stm32h573-dk-2 | 2026-11-20T22:20:38+01:00 | 1 | endpoint clock at 1.535 s per gateway second (bounds 0.90 to 1.06) |

## Regression runs

| stage | result | start | minutes |
|---|---|---|---|
| start | PASS | 2026-11-20T21:55:41+01:00 | 6.0 |
| middle | PASS | 2026-11-20T23:25:41+01:00 | 6.0 |
| end | PASS | 2026-11-21T00:55:41+01:00 | 6.0 |

## Endpoints

| endpoint | verdict lines | quarantined | renewals | last heartbeat | clock rate (s/s) | resets | secure stack max | lifetime seen |
|---|---|---|---|---|---|---|---|---|
| stm32h573-dk-2 | 342 | 0 | 37 | 1268 | 1.0557 over 9630 s | 0 | 18872/26624 (first 18872) | 600 |
| frdm-rw612 | 342 | 0 | 37 | 7 | 1.0002 over 9073 s | 0 | 19176/32768 (first 19176) | 600 |
| zynqmp-te0808 | 342 | 0 | 37 | 7 | 1.0002 over 9083 s | 0 | - | 600 |

## Gateway trends (runs of one fleet process of an hour or more; projected over 14 days)

| metric | first | last | min | max | per hour | 14 days | bound | judged | ok |
|---|---|---|---|---|---|---|---|---|---|
| fleet_rss_kb | 23172.0 | 23280.0 | 23172.0 | 23532.0 | 76.294 | 25634.8 | 16384 | no (2.67 h) | yes |
| aegisd_rss_kb | 17696.0 | 17704.0 | 17696.0 | 17704.0 | 0.0 | 0.0 | 8192 | no (2.67 h) | yes |
| fleet_fds | 3.0 | 3.0 | 0.0 | 4.0 | -0.029 | -9.9 | 32 | no (2.67 h) | yes |
| mem_avail_kb | 471212.0 | 467312.0 | 467312.0 | 475332.0 | -289.176 | 97163.3 | 65536 | no (2.67 h) | yes |
| aegis_du_kb | 34.0 | 34.0 | 34.0 | 34.0 | 0.0 | 0.0 | 65536 | no (2.67 h) | yes |
| root_used_kb | 332345.0 | 332346.0 | 332345.0 | 332346.0 | 0.0 | 0.0 | 262144 | no (2.67 h) | yes |

Journal on disk: 42.0 MB first, 42.0 MB last (journald keeps 50 MB).

## Warnings and expected events

- WARN stm32h573-dk-2 x1 (first 2026-11-20T21:55:38+01:00): credential lifetime 3600 s, the soak expects 600 s
- WARN frdm-rw612 x1 (first 2026-11-20T21:55:38+01:00): credential lifetime 3600 s, the soak expects 600 s
- WARN zynqmp-te0808 x1 (first 2026-11-20T21:55:38+01:00): credential lifetime 3600 s, the soak expects 600 s
- EXPECTED aegis-fleet x3 (first 2026-11-20T22:00:38+01:00): aegis-fleet is inactive
- EXPECTED stm32h573-dk-2 x1 (first 2026-11-20T22:05:38+01:00): session 28c18c2cab0a77fe replaced by 8df6d9b478a6a1ac before its renewal was due (revoked)
- EXPECTED frdm-rw612 x1 (first 2026-11-20T22:05:38+01:00): session 00349764d9304d0a replaced by ff43aa493a93d0b6 before its renewal was due (revoked)
- EXPECTED zynqmp-te0808 x1 (first 2026-11-20T22:05:38+01:00): session f14188cab9595a13 replaced by d3720436a3061944 before its renewal was due (revoked)
- INFO stm32h573-dk-2 x36 (first 2026-11-20T22:10:38+01:00): session renewed
- INFO frdm-rw612 x35 (first 2026-11-20T22:10:38+01:00): session renewed
- INFO zynqmp-te0808 x36 (first 2026-11-20T22:10:38+01:00): session renewed
- EXPECTED stm32h573-dk-2 x1 (first 2026-11-21T01:05:41+01:00): heartbeat counter stopped at 1268
- EXPECTED frdm-rw612 x1 (first 2026-11-21T01:05:41+01:00): heartbeat counter stopped at 7
- EXPECTED zynqmp-te0808 x1 (first 2026-11-21T01:05:41+01:00): heartbeat counter stopped at 7

**Restore the normal credential lifetime** (docs/soak-and-watchdogs.md, "Restore"): seen 600 s.

Files: samples.csv, events.log, state.json, raw/ (gateway answers of failing samples), regression-*.log.

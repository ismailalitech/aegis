# Soak, 2026-11-20 21:55 to 2026-11-21 01:01 (CET)

3 hours on stm32h573-dk-2, frdm-rw612 and zynqmp-te0808 (STM32 board 1 unplugged, the Arduino quarantined by
design), credential lifetime shortened to 600 s, an expiry round every hour, `tools/regression.sh --board
--with-expiry` at the start, the middle and the end: all three PASS (14 stages each). 40 of 40 samples answered;
37 session renewals per endpoint; no quarantine, no reset, no reboot; secure-stack peak unchanged (STM32 18872/26624,
RW612 19176/32768); gateway services never restarted by themselves; journal and disk flat. The ZynqMP console
(watched from the second PC) stayed silent and its boot_id unchanged for the whole run.

`report.md` says FAIL because of one item: at 22:20 the runner estimated the STM32's clock at 1.535 s per gateway
second (bounds 0.90 to 1.06), and the run-wide figure for that board is 1.0557 (the other two: 1.0002). This is a
false positive of the runner's rate estimate, not a board fault: the heartbeat counter (`uptime_s`) tracks the
gateway's clock to within a second (0.9985 over 100 minutes from the gateway journal), and in the journal a heartbeat
line stamped about 10 s late is followed by one 10 s early (44 s apart against 34 s of device time, then 34 against
44), which a short window misreads. The runner is to be fixed to use longer windows or the device's own interval;
the unedited report is kept as the record.

Not covered by 3 hours: counter wraps and drift over several days; trend bounds are not judged under 4 h
(gateway memory, descriptors and disk were flat at 2.7 h). The credential lifetime was restored to 3600 s afterwards.
Times in the gateway's own journal are UTC, one hour behind this log.

# SPDX-License-Identifier: Apache-2.0
"""tools/soak.py and the endpoint-liveness additions of tools/bench_watch.py (docs/soak-and-watchdogs.md), without
hardware: the parsers against real, garbled and hostile gateway output, each failure criterion on its own, the
sampling commands' read-only check, a stopped and resumed run, and whole simulated soaks on the canned gateway."""
import csv
import json
import os
import random
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import bench_watch  # noqa: E402
import soak  # noqa: E402

T0 = 1_800_000_000


def read(d, name):
    with open(os.path.join(d, name)) as fh:
        return fh.read()

# lines as the gateway's journal shows them (evidence/ and docs/endpoint-expiry.md), in short-unix form
REAL = [
    "1800000000.123456 polarfire python3[812]: 10:28:22 frdm-rw612 ADMITTED (trustzone trust)  [credential: valid, "
    "heartbeat 1 (requests=19;stack=19384/32768;clk=ref;fw=rw612-tfm-0.2.2;ttl=3791)]",
    "1800000000.223456 polarfire python3[812]: 10:28:22 stm32h573-dk-2 ADMITTED  [credential: valid, heartbeat 33 "
    "(uptime_s=1217;link=1;fw=0.6.0;sstack=19088/26624;ttl=2771)] [endorsed by bench-pc]",
    "1800000000.323456 polarfire python3[812]: 10:28:22 zynqmp-te0808 ADMITTED (trustzone trust)  [credential: issued "
    "session bcfee3cea812... bound to quote 0123456789ab... (transcript v2)]",
    "1800000000.423456 polarfire python3[812]: 10:28:22 stm32h573-dk QUARANTINED no attestation: [Errno 113] No route "
    "to host [credential: revoked]",
    "1800000000.523456 polarfire python3[812]: <4>10:28:22 frdm-rw612 ADMITTED (trustzone trust) [credential: valid, "
    "heartbeat 2 (requests=22;stack=19384/32768;clk=ref;fw=rw612-tfm-0.2.2;ttl=3761)] WARNING: development profile",
    "1800000001.0 polarfire python3[812]: aegis-fleet: enforcement hook failed for frdm-rw612 (quarantine), rc=1:",
]


def answer(**over):
    """A complete, healthy gateway answer; over replaces sections ({name: [lines]})."""
    secs = {
        "now": [str(T0 + 300), "yes"],
        "boot": ["86400.12 170000.00", "0f0f0f0f-0f0f-0f0f-0f0f-0f0f0f0f0f0f"],
        "units": ["unit aegis-fleet ActiveState=active MainPID=812 NRestarts=0 ",
                  "unit aegisd ActiveState=active MainPID=311 NRestarts=0 "],
        "procs": ["proc aegis-fleet 812 VmRSS: 41000 kB VmHWM: 42000 kB Threads: 1 fds 9",
                  "proc aegisd 311 VmRSS: 20000 kB VmHWM: 20100 kB Threads: 2 fds 7"],
        "mem": ["MemTotal:        1015808 kB", "MemAvailable:     700000 kB", "0.31 0.25 0.20 1/97 4242"],
        "disk": ["/dev/mmcblk0p3 7000000 2500000 4200000 38% /", "2048\t/var/lib/aegis", "24000\t/var/lib/journal",
                 "Archived and active journals take up 23.4M in the file system."],
        "state": ["%d 2048" % (T0 + 290)],
        "creds": ['cred frdm-rw612 d7af479030f3 %d %d 21 "requests=22;ttl=3761"' % (T0, T0 + 3600)],
        "journal": REAL[:5],
        "journal_all": ["120"],
        "kernel": [],
    }
    secs.update(over)
    out = []
    for k, v in secs.items():
        out.append("@@ " + k)
        out += v
    return "\n".join(out + ["@@ end"]) + "\n"


class Parsing(unittest.TestCase):
    def test_real_answer(self):
        s = soak.parse_answer(answer())
        self.assertTrue(s["complete"])
        self.assertEqual(s["gw_now"], T0 + 300)
        self.assertEqual(s["units"]["aegis-fleet"], {"active": "active", "pid": 812, "nrestarts": 0})
        self.assertEqual(s["procs"]["aegis-fleet"]["rss_kb"], 41000)
        self.assertEqual(s["procs"]["aegis-fleet"]["fds"], 9)
        self.assertEqual((s["mem_total_kb"], s["mem_avail_kb"], s["load1"]), (1015808, 700000, 0.31))
        self.assertEqual((s["root_used_kb"], s["root_avail_kb"], s["aegis_du_kb"]), (2500000, 4200000, 2048))
        self.assertEqual(s["journal_du_mb"], 23.4)
        self.assertEqual(s["state_mtime"], T0 + 290)
        self.assertEqual(s["creds"]["frdm-rw612"]["hb"], 21)
        self.assertEqual(s["creds"]["frdm-rw612"]["status"]["ttl"], 3761)

    def test_journal_records(self):
        recs = soak.parse_journal(REAL)
        self.assertEqual([r["kind"] for r in recs], ["verdict"] * 5 + ["bad"])
        rw = recs[0]
        self.assertEqual((rw["ep"], rw["admitted"], rw["hb"]), ("frdm-rw612", True, 1))
        self.assertEqual(rw["status"], {"requests": 19, "stack_used": 19384, "stack_size": 32768, "clk": "ref",
                                        "fw": "rw612-tfm-0.2.2", "ttl": 3791})
        self.assertEqual(recs[1]["status"]["uptime_s"], 1217)
        self.assertEqual(recs[1]["status"]["stack_used"], 19088)
        self.assertEqual(recs[2]["issued"], "bcfee3cea812")
        self.assertFalse(recs[3]["admitted"])
        self.assertIn("No route to host", recs[3]["reasons"])
        self.assertEqual(recs[4]["hb"], 2)           # with a syslog priority prefix

    def test_status_hostile(self):
        for text in ("", ";;;", "=", "ttl=", "ttl=-5", "ttl=1e9", "ttl=99999999999999999999999", "sstack=5/3",
                     "sstack=/", "stack=na", "sstack=1/0", "a" * 5000, "\x00ttl=3\xff", None, 7,
                     "uptime_s=12;uptime_s=x", "TTL=3", "ttl=3;ttl=2"):
            d = soak.parse_status(text)
            self.assertIsInstance(d, dict)
            for k in ("ttl", "uptime_s", "requests"):
                if k in d:
                    self.assertIsInstance(d[k], int)
                    self.assertGreaterEqual(d[k], 0)
            if "stack_used" in d:
                self.assertLessEqual(d["stack_used"], d["stack_size"])
        self.assertEqual(soak.parse_status("ttl=3;ttl=2")["ttl"], 2)
        self.assertNotIn("stack_used", soak.parse_status("sstack=5/3"))

    def test_garbled_answers(self):
        good = answer()
        cases = [None, "", "garbage", good[: len(good) // 2], good.replace("@@ end", ""),
                 good.replace(str(T0 + 300), "notanumber"), "@@ end\n", "@@ now\n@@ end\n",
                 good.replace("@@ units", "@@ UNITS; rm -rf /"), "\x00" * 100 + good, good * 3]
        for c in cases:
            s = soak.parse_answer(c)
            self.assertIn("complete", s)
        self.assertFalse(soak.parse_answer(good[: len(good) // 2])["complete"])
        self.assertFalse(soak.parse_answer(good.replace(str(T0 + 300), "notanumber"))["complete"])
        self.assertFalse(soak.parse_answer("@@ now\n@@ end\n")["complete"])

    def test_random_bytes_never_raise(self):
        rnd = random.Random(7)
        good = answer()
        for _ in range(400):
            b = bytearray(good.encode())
            for _ in range(rnd.randrange(1, 40)):
                b[rnd.randrange(len(b))] = rnd.randrange(256)
            s = soak.parse_answer(b.decode(errors="replace"))
            prev = soak.parse_answer(good)
            prev["offset"] = s["offset"] = 0
            if s["gw_now"] is not None:
                soak.check_gateway(s, prev, soak.BOUNDS, 0)
                soak.check_endpoint("frdm-rw612", soak.new_ep_track(), s, prev, soak.BOUNDS, 3600, 300)
        for _ in range(100):
            junk = "".join(chr(rnd.randrange(1, 0x2FF)) for _ in range(rnd.randrange(0, 3000)))
            soak.parse_answer("@@ journal\n" + junk + "\n@@ creds\n" + junk + "\n@@ end")

    def test_hostile_names_and_sizes(self):
        lines = ["1800000000 gw python3[1]: 10:00:00 ../../etc/passwd ADMITTED [credential: valid, heartbeat 1 (ttl=3)]",
                 "1800000000 gw python3[1]: 10:00:00 %s ADMITTED" % ("x" * 100),
                 "1800000000 gw python3[1]: 10:00:00 ok-name ADMITTED [credential: valid, heartbeat %s (ttl=3)]"
                 % ("9" * 40),
                 "99 gw python3[1]: 10:00:00 ok-name ADMITTED", "x" * 100000]
        recs = soak.parse_journal(lines)
        self.assertEqual([r.get("ep") for r in recs if r["kind"] == "verdict"], ["ok-name"])
        self.assertNotIn("hb", recs[0])
        s = soak.parse_answer(answer(creds=['cred ../x 1 2 3 4 ""', "cred a b", 'cred ok zz 1 2 3 "x"',
                                            "cred-error /var/lib/aegis/credentials/x.json ValueError"]))
        self.assertEqual(list(s["creds"]), ["ok"])
        self.assertIsNone(s["creds"]["ok"]["session"])
        self.assertEqual(len(s["cred_errors"]), 1)


class Commands(unittest.TestCase):
    def test_defaults_are_read_only(self):
        self.assertEqual(soak.check_commands(soak.COMMANDS), [])

    def test_refused(self):
        for t in ("systemctl restart aegis-fleet", "systemctl --no-block stop aegis-fleet", "reboot", "rm -f /x",
                  "echo x > /etc/passwd", "journalctl --vacuum-size=1M", "kill 1", "dd if=/dev/zero of=/dev/mmcblk0",
                  "date; systemctl daemon-reload", "sysctl -w kernel.panic=0", "python3 -c 'open(\"/x\",\"w\")'",
                  "tee /x", "sed -i s/a/b/ /root/aegis/gateway/policy/fleet.json", "systemd-run reboot"):
            self.assertTrue(soak.check_commands({"x": t}), t)
        self.assertTrue(soak.check_commands({"Bad Name": "date"}))
        self.assertTrue(soak.check_commands({"x": 5}))
        self.assertEqual(soak.check_commands({"x": "ls /proc/1/fd 2>/dev/null | wc -l"}), [])

    def test_script(self):
        s = soak.build_script(soak.COMMANDS, T0)
        self.assertIn("--since @%d" % T0, s)
        self.assertNotIn("@SINCE@", s)
        self.assertNotIn("@STATE@", s)
        self.assertTrue(s.rstrip().endswith('echo "@@ end"'))


def cur_prev(**over):
    prev = soak.parse_answer(answer(now=[str(T0), "yes"], journal=[]))
    cur = soak.parse_answer(answer(**over))
    prev["offset"] = cur["offset"] = 3
    return cur, prev


def keys(fs, level="FAIL"):
    return {f["key"].split(":")[1] if ":" in f["key"] else f["key"] for f in fs if f["level"] == level}


class Criteria(unittest.TestCase):
    def test_healthy_gateway(self):
        cur, prev = cur_prev()
        self.assertEqual(keys(soak.check_gateway(cur, prev, soak.BOUNDS, 3)), set())

    def test_gateway_failures(self):
        cases = [
            (dict(boot=["10.0 1.0", "1e1e1e1e-1e1e-1e1e-1e1e-1e1e1e1e1e1e"]), "reboot"),
            (dict(units=["unit aegis-fleet ActiveState=failed MainPID=0 NRestarts=0 ",
                         "unit aegisd ActiveState=active MainPID=311 NRestarts=0 "]), "inactive"),
            (dict(units=["unit aegis-fleet ActiveState=active MainPID=900 NRestarts=1 ",
                         "unit aegisd ActiveState=active MainPID=311 NRestarts=0 "]), "nrestarts"),
            (dict(units=["unit aegis-fleet ActiveState=active MainPID=900 NRestarts=0 ",
                         "unit aegisd ActiveState=active MainPID=311 NRestarts=0 "]), "pid"),
            (dict(state=["%d 2048" % (T0 - 100)]), "stale"),
            (dict(state=["missing"]), "missing"),
            (dict(journal=[]), "quiet"),
            (dict(journal=REAL), "bad"),
            (dict(disk=["/dev/mmcblk0p3 7000000 6900000 100000 99% /",
                        "Archived and active journals take up 80.0M in the file system."]), "low"),
            (dict(mem=["MemTotal: 1015808 kB", "MemAvailable: 1000 kB"]), "low"),
            (dict(procs=["proc aegis-fleet 812 VmRSS: 41000 kB VmHWM: 42000 kB Threads: 1 fds 900"]), "high"),
        ]
        for over, want in cases:
            cur, prev = cur_prev(**over)
            got = keys(soak.check_gateway(cur, prev, soak.BOUNDS, 3))
            self.assertIn(want, got, (over, got))
        cur, prev = cur_prev(kernel=["%d gw kernel: watchdog: BUG: soft lockup - CPU#1 stuck for 22s!" % T0])
        fs = soak.check_gateway(cur, prev, soak.BOUNDS, 3)
        self.assertTrue(any(f["key"].startswith("kernel:") and f["level"] == "FAIL" and f["always"] for f in fs))
        cur, prev = cur_prev(disk=["Archived and active journals take up 80.0M in the file system."])
        self.assertIn("size", keys(soak.check_gateway(cur, prev, soak.BOUNDS, 3)))

    def test_bad_lines_attributed_to_their_endpoint(self):
        eps, absent = ["stm32h573-dk-2", "frdm-rw612"], ["stm32h573-dk", "arduino-uno"]
        lines = [
            "1800000001 gw python3[812]: aegis-fleet: enforcement hook failed for frdm-rw612 (quarantine), rc=1:",
            "1800000002 gw python3[812]: aegis-fleet: enforcement hook failed for stm32h573-dk (quarantine), rc=1:",
            "1800000003 gw python3[812]: aegis-fleet: enforcement FAILED for stm32h573-dk-2: nft exited 1",
            "1800000004 gw python3[812]: aegis-fleet: policy REFUSED arduino-uno: no route",
            "1800000005 gw python3[812]: Traceback (most recent call last):",
        ]
        cur, prev = cur_prev(journal=lines)
        fs = [f for f in soak.check_gateway(cur, prev, soak.BOUNDS, 3, eps, absent)
              if f["key"].startswith("journal:bad")]
        self.assertEqual([(f["item"], f["level"]) for f in fs], [
            ("frdm-rw612", "FAIL"), ("stm32h573-dk", "INFO"), ("stm32h573-dk-2", "FAIL"), ("arduino-uno", "INFO"),
            ("aegis-fleet", "FAIL")])
        self.assertIsNone(soak.bad_line_endpoint("failed for frdm-rw612x", eps))
        self.assertEqual(soak.bad_line_endpoint("failed for frdm-rw612.", eps), "frdm-rw612")

    def test_known_kernel_message_and_clock(self):
        cur, prev = cur_prev(kernel=["%d gw kernel: mpfs_rtc: timed out uploading time to rtc" % T0])
        fs = soak.check_gateway(cur, prev, soak.BOUNDS, 3)
        self.assertEqual(keys(fs), set())
        self.assertEqual([f["level"] for f in fs], ["INFO"])
        cur["offset"] = 500
        self.assertIn("step", keys(soak.check_gateway(cur, prev, soak.BOUNDS, 3)))
        cur, prev = cur_prev(now=[str(T0 + 300), "no"])
        self.assertIn("ntp", keys(soak.check_gateway(cur, prev, soak.BOUNDS, 3), "WARN"))

    def ep(self, name, tr, **over):
        cur, prev = cur_prev(**over)
        return soak.check_endpoint(name, tr, cur, prev, soak.BOUNDS, 3600, 300)

    def test_endpoint_healthy_then_stopped(self):
        tr = soak.new_ep_track()
        self.assertEqual(keys(self.ep("frdm-rw612", tr)), set())
        self.assertEqual(tr["hb"], 21)
        self.assertEqual(tr["stack_used_max"], 19384)
        # the same session, the same counter: stopped
        fs = self.ep("frdm-rw612", tr, journal=[REAL[0].replace("1800000000.123456", "1800000200")])
        self.assertIn("hbstop", keys(fs))

    def test_endpoint_quarantine_and_silence(self):
        tr = soak.new_ep_track()
        fs = self.ep("stm32h573-dk", tr)
        self.assertIn("quarantined", keys(fs))
        self.assertEqual(tr["quarantined"], 1)
        fs = self.ep("zynqmp-te0808", soak.new_ep_track(), journal=[])
        self.assertIn("silent", keys(fs))

    def test_renewal_expected_or_not(self):
        tr = soak.new_ep_track()
        self.ep("frdm-rw612", tr)
        # a new session when the old one had 3300 s left: revoked
        fs = self.ep("frdm-rw612", dict(tr), journal=[REAL[4]],
                     creds=['cred frdm-rw612 aaaaaaaaaaaa %d %d 1 ""' % (T0 + 300, T0 + 3900)])
        self.assertIn("replaced", keys(fs))
        # due: the old one is inside the renewal window
        tr2 = dict(tr, expires=T0 + 500)
        fs = self.ep("frdm-rw612", tr2, journal=[REAL[4]],
                     creds=['cred frdm-rw612 aaaaaaaaaaaa %d %d 1 ""' % (T0 + 300, T0 + 3900)])
        self.assertEqual(keys(fs), set())
        self.assertIn("renewed", keys(fs, "INFO"))

    def test_overdue_expired_and_lifetime(self):
        tr = soak.new_ep_track()
        fs = self.ep("frdm-rw612", tr, creds=['cred frdm-rw612 d7af479030f3 %d %d 21 ""' % (T0 - 3250, T0 + 350)])
        self.assertIn("overdue", keys(fs))
        fs = self.ep("frdm-rw612", soak.new_ep_track(), creds=['cred frdm-rw612 d7af479030f3 %d %d 21 ""' % (
            T0 - 3600, T0)])
        self.assertIn("expired", keys(fs))
        fs = self.ep("frdm-rw612", soak.new_ep_track(), creds=['cred frdm-rw612 d7af479030f3 %d %d 21 ""' % (
            T0, T0 + 600)])
        self.assertIn("lifetime", keys(fs, "WARN"))

    def test_status_criteria(self):
        def st(status, tr=None):
            tr = tr or soak.new_ep_track()
            line = REAL[1].replace("uptime_s=1217;link=1;fw=0.6.0;sstack=19088/26624;ttl=2771", status)
            return keys(self.ep("stm32h573-dk-2", tr, journal=[line], creds=[]), "FAIL"), tr
        self.assertEqual(st("uptime_s=10;sstack=19088/26624;ttl=2771")[0], set())
        self.assertIn("stack", st("sstack=25000/26624")[0])
        self.assertIn("ttlhigh", st("ttl=5000")[0])
        self.assertIn("ttllow", st("ttl=30")[0])
        tr = soak.new_ep_track()
        tr["uptime_s"] = 5000
        self.assertIn("reset", st("uptime_s=10", tr)[0])
        tr = soak.new_ep_track()
        tr["requests"] = 5000
        self.assertIn("reset", st("requests=10", tr)[0])
        warn = keys(self.ep("stm32h573-dk-2", soak.new_ep_track(),
                            journal=[REAL[1].replace("link=1", "link=0").replace("fw=0.6.0", "clk=cpu")], creds=[]),
                    "WARN")
        self.assertEqual(warn, {"link", "clk"})

    def test_clock_rate(self):
        def run(rate):
            tr = soak.new_ep_track()
            lines = []
            for i in range(80):
                lines.append("%d gw python3[1]: 10:00:00 frdm-rw612 ADMITTED [credential: valid, heartbeat %d "
                             "(requests=%d;ttl=%d)]" % (T0 + 30 * i, i + 1, i, 3800 - int(30 * i * rate)))
            cur, prev = cur_prev(journal=lines, creds=[])
            return keys(soak.check_endpoint("frdm-rw612", tr, cur, prev, soak.BOUNDS, 3600, 300)), tr
        self.assertNotIn("rate", run(1.0)[0])
        self.assertNotIn("rate", run(0.941)[0])      # the STM32's LSI, measured on the bench
        self.assertIn("rate", run(1.09)[0])
        self.assertIn("rate", run(0.85)[0])
        self.assertAlmostEqual(run(1.0)[1]["rate_dttl"] / run(1.0)[1]["rate_dt"], 1.0, places=3)

    def test_console(self):
        fs = soak.console_findings("2026-11-20 03:00:00 [ 1.0] ok\n2026-11-20 03:00:01 Kernel panic - not syncing\n")
        self.assertEqual(len(fs), 1)
        self.assertTrue(fs[0]["always"])


class Trends(unittest.TestCase):
    def rows(self, leak_kb_h, restart_every_h=None, hours=24):
        out = []
        for i in range(int(hours * 12)):
            t = T0 + i * 300
            seg = int(i * 300 / 3600 / restart_every_h) if restart_every_h else 0
            age_h = (t - (T0 + seg * restart_every_h * 3600 if restart_every_h else T0)) / 3600
            out.append({"pc_time": t, "ok": 1, "fleet_pid": 100 + seg, "fleet_rss_kb": 41000 + leak_kb_h * age_h,
                        "aegisd_rss_kb": 20000, "fleet_fds": 9, "mem_avail_kb": 700000, "aegis_du_kb": 2048 + i * 0.1,
                        "root_used_kb": 2500000})
        return out

    def test_flat_passes_leak_fails(self):
        fs, table = soak.trend_findings(self.rows(0), soak.BOUNDS)
        self.assertEqual(fs, [])
        self.assertTrue(all(r["judged"] for r in table))
        fs, _ = soak.trend_findings(self.rows(100), soak.BOUNDS)
        self.assertEqual([f["key"] for f in fs], ["trend:fleet_rss_kb"])

    def test_leak_seen_across_restarts(self):
        # the fleet restarted every 4 h (expiry rounds): RSS falls back each time; the slope inside each run counts
        fs, table = soak.trend_findings(self.rows(100, restart_every_h=4), soak.BOUNDS)
        self.assertEqual([f["key"] for f in fs], ["trend:fleet_rss_kb"])
        r = next(x for x in table if x["metric"] == "fleet_rss_kb")
        self.assertAlmostEqual(r["slope_per_h"], 100, delta=1)
        fs, _ = soak.trend_findings(self.rows(0, restart_every_h=4), soak.BOUNDS)
        self.assertEqual(fs, [])

    def test_too_short_not_judged(self):
        fs, table = soak.trend_findings(self.rows(1000, hours=3), soak.BOUNDS)
        self.assertEqual(fs, [])
        self.assertFalse(any(r["judged"] for r in table))
        self.assertEqual(soak.trend_findings([], soak.BOUNDS)[0], [])
        self.assertIsNone(soak.pooled_slope_per_h([[(1, 1)], []]))


class Runs(unittest.TestCase):
    def test_healthy_day(self):
        with tempfile.TemporaryDirectory() as d:
            passed, s = soak.simulate(d, hours=24)
            self.assertTrue(passed, s.st["failures"])
            self.assertEqual(sorted(s.st["done"]), ["end", "middle", "start"])
            report = read(d, "report.md")
            self.assertIn("**Result: PASS**", report)
            with open(os.path.join(d, "samples.csv")) as fh:
                rows = list(csv.DictReader(fh))
            self.assertGreater(len(rows), 280)
            self.assertIn("frdm-rw612:hb", rows[0])
            self.assertGreater(s.st["eps"]["frdm-rw612"]["renewals"], 20)
            self.assertGreater(s.st["absent"]["stm32h573-dk"], 1000)    # its quarantine counted, never a failure

    def test_short_credentials_and_expiry_rounds(self):
        with tempfile.TemporaryDirectory() as d:
            passed, s = soak.simulate(d, hours=24, lifetime=600, expiry_every_h=4)
            self.assertTrue(passed, s.st["failures"])
            self.assertIn("expiry-1", s.st["done"])
            self.assertGreater(s.st["eps"]["zynqmp-te0808"]["renewals"], 200)
            self.assertIn("Restore the normal credential lifetime", read(d, "report.md"))

    def test_failures_found(self):
        with tempfile.TemporaryDirectory() as d:
            passed, s = soak.simulate(d, hours=8, faults={"hb_stop": {"frdm-rw612": T0 + 3 * 3600}})
            self.assertFalse(passed)
            self.assertIn("frdm-rw612:hbstop", s.st["failures"])
            self.assertIn("**Result: FAIL**", read(d, "report.md"))
            self.assertTrue(os.listdir(os.path.join(d, "raw")))
        with tempfile.TemporaryDirectory() as d:
            passed, s = soak.simulate(d, hours=8, fail_stages=("middle",))
            self.assertFalse(passed)
            self.assertIn("regression:middle", s.st["failures"])

    def test_planned_window_excuses(self):
        with tempfile.TemporaryDirectory() as d:
            faults = {"quarantine": {"zynqmp-te0808": T0 + 2 * 3600 + 60}}
            with open(os.path.join(d, "planned.txt"), "w") as fh:
                fh.write("%d %d zynqmp-te0808 link pulled on purpose\n" % (T0 + 2 * 3600, T0 + 2 * 3600 + 1800))
            passed, s = soak.simulate(d, hours=8, faults=faults)
            self.assertTrue(passed, s.st["failures"])
            self.assertIn("EXPECTED", read(d, "events.log"))

    def test_absent_endpoint_tolerated_only_when_listed(self):
        with tempfile.TemporaryDirectory() as d:
            clock = soak.FakeClock(T0)
            cfg = soak.make_cfg(hours=1, endpoints=["stm32h573-dk-2", "stm32h573-dk"], absent=[], regression=False)
            gw = soak.FakeGateway(clock, ["stm32h573-dk-2"], absent=["stm32h573-dk"])
            s = soak.Soak(d, cfg, gw, clock, soak.FakeRegression(clock, gw))
            self.assertFalse(s.loop())
            self.assertIn("stm32h573-dk:quarantined", s.st["failures"])

    def test_stop_and_resume(self):
        with tempfile.TemporaryDirectory() as d:
            clock = soak.FakeClock(T0)
            cfg = soak.make_cfg(hours=8, absent=["stm32h573-dk"])
            gw = soak.FakeGateway(clock, cfg["endpoints"])
            reg = soak.FakeRegression(clock, gw)
            # stopped in the middle of the middle regression (4 h + 5 min)
            s = soak.Soak(d, cfg, gw, clock, reg)
            self.assertIsNone(s.loop(stop=lambda: clock.now() > T0 + 4 * 3600 + 300))
            self.assertIsNotNone(s.st["running"])
            s.save()
            clock.sleep(1200)               # the runner was away 20 min
            s2 = soak.Soak(d, soak.make_cfg(hours=1), gw, clock, reg)
            self.assertEqual(s2.cfg["hours"], 8)        # the stored settings win
            self.assertTrue(s2.loop(), s2.st["failures"])
            self.assertEqual(reg.runs.count("middle"), 2)
            log = read(d, "events.log")
            self.assertIn("resumed", log)
            self.assertIn("interrupted", log)
            with open(os.path.join(d, "samples.csv")) as fh:
                self.assertEqual(fh.read().count("pc_time"), 1)

    def test_resume_waits_for_a_regression_still_running(self):
        with tempfile.TemporaryDirectory() as d:
            clock = soak.FakeClock(T0)
            cfg = soak.make_cfg(hours=8, absent=["stm32h573-dk"])
            gw = soak.FakeGateway(clock, cfg["endpoints"])
            reg = soak.FakeRegression(clock, gw)
            s = soak.Soak(d, cfg, gw, clock, reg)
            self.assertIsNone(s.loop(stop=lambda: clock.now() > T0 + 4 * 3600 + 300))
            run = s.st["running"]
            self.assertEqual(run["stage"], "middle")
            s.save()
            # the runner was killed; its regression (process group) goes on for another 10 min
            reg2 = soak.FakeRegression(clock, gw)
            reg2.groups[run["pgid"]] = clock.now() + 600
            s2 = soak.Soak(d, cfg, gw, clock, reg2)
            self.assertTrue(s2.st["running"]["orphan"])
            self.assertIn("still running", read(d, "events.log"))
            s2.loop(stop=lambda: clock.now() > T0 + 4 * 3600 + 300 + 500)
            self.assertEqual(reg2.runs, [])                 # not started again while the old one runs
            self.assertTrue(s2.loop(), s2.st["failures"])
            self.assertEqual(reg2.runs[0], "middle")        # then it runs again
            self.assertIn("from before the restart ended", read(d, "events.log"))

    def test_hung_regression_times_out(self):
        with tempfile.TemporaryDirectory() as d:
            clock = soak.FakeClock(T0)
            cfg = soak.make_cfg(hours=8, absent=["stm32h573-dk"])
            gw = soak.FakeGateway(clock, cfg["endpoints"])
            reg = soak.FakeRegression(clock, gw, hang=("middle",))
            s = soak.Soak(d, cfg, gw, clock, reg)
            self.assertFalse(s.loop())                      # ends: the soak does not wait for it forever
            self.assertEqual(s.st["done"]["middle"]["rc"], "timeout")
            self.assertLessEqual(s.st["done"]["middle"]["min"], 46)
            self.assertIn("regression:middle", s.st["failures"])
            self.assertEqual(len(reg.killed), 1)
            self.assertEqual(sorted(s.st["done"]), ["end", "middle", "start"])
        with tempfile.TemporaryDirectory() as d:
            clock = soak.FakeClock(T0)
            cfg = soak.make_cfg(hours=8, absent=["stm32h573-dk"], expiry_every_h=2, expiry_timeout_min=10)
            gw = soak.FakeGateway(clock, cfg["endpoints"])
            reg = soak.FakeRegression(clock, gw, hang=("expiry-1",))
            s = soak.Soak(d, cfg, gw, clock, reg)
            self.assertFalse(s.loop())
            self.assertLessEqual(s.st["done"]["expiry-1"]["min"], 11)

    def excuse_soak(self, d):
        clock = soak.FakeClock(T0)
        cfg = soak.make_cfg(hours=8, absent=["stm32h573-dk"], interval_min=5)
        gw = soak.FakeGateway(clock, cfg["endpoints"])
        s = soak.Soak(d, cfg, gw, clock, soak.FakeRegression(clock, gw))
        s.st["planned"].append([T0, T0 + 3600, "regression", "regression middle"])
        return s

    def test_regression_window_excuses_only_its_events(self):
        F = soak.finding
        with tempfile.TemporaryDirectory() as d:
            s = self.excuse_soak(d)
            s.apply([F("FAIL", "aegis-fleet", "aegis-fleet:pid:900", "new process", once=True),
                     F("FAIL", "frdm-rw612", "frdm-rw612:replaced:abc", "replaced", once=True),
                     F("FAIL", "zynqmp-te0808", "zynqmp-te0808:quarantined:1", "q", once=True),
                     F("FAIL", "aegis-fleet", "aegis-fleet:inactive", "inactive"),
                     F("FAIL", "frdm-rw612", "frdm-rw612:silent", "silent")], T0 + 300)
            self.assertEqual(s.st["failures"], {})
            # never excused: an SSH hang, aegisd, systemd restarting the fleet, a bad journal line
            s.apply([F("FAIL", "gateway", "ssh:hang", "hang"),
                     F("FAIL", "aegisd", "aegisd:inactive", "inactive"),
                     F("FAIL", "aegis-fleet", "aegis-fleet:nrestarts:1", "restarted itself", once=True),
                     F("FAIL", "aegis-fleet", "journal:bad:5", "Traceback", once=True)], T0 + 600)
            self.assertEqual(sorted(s.st["failures"]), ["aegis-fleet:nrestarts", "aegisd:inactive",
                                                        "journal:bad", "ssh:hang"])

    def test_regression_gap_budget(self):
        F = soak.finding
        with tempfile.TemporaryDirectory() as d:
            s = self.excuse_soak(d)
            fs = [F("FAIL", "aegis-fleet", "aegis-fleet:inactive", "inactive"),
                  F("FAIL", "frdm-rw612", "frdm-rw612:silent", "silent")]
            for k in range(3):                              # 0, 5, 10 min: within the 600 s budget
                s.apply(fs, T0 + 300 + k * 300)
            self.assertEqual(s.st["failures"], {})
            s.apply(fs, T0 + 300 + 3 * 300)                 # 15 min: longer than the expiry stage's stop
            self.assertEqual(sorted(s.st["failures"]), ["aegis-fleet:inactive", "frdm-rw612:silent"])
            s.apply([], T0 + 1800)                          # cleared, then a new short gap is excused again
            s.apply(fs[:1], T0 + 2100)
            self.assertEqual(s.st["open"]["aegis-fleet:inactive"], "EXPECTED")

    def test_garbled_answer_and_short_outage_do_not_fail(self):
        with tempfile.TemporaryDirectory() as d:
            passed, s = soak.simulate(d, hours=8, faults={"garble_at": T0 + 3600,
                                                          "ssh_down": (T0 + 7200, T0 + 7200 + 200)})
            self.assertTrue(passed, s.st["failures"])
            self.assertIn("ssh:fail", s.st["warnings"])

    def test_dry_run_and_cli(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(soak.main(["run", "--dry-run", "--gateway", "192.0.2.10", "--stm32", "192.0.2.21:7444",
                                        "--expiry-every-h", "4"]), 0)
        out = buf.getvalue()
        self.assertIn("AEGIS_STM32_OVERRIDE=192.0.2.21:7444", out)
        self.assertIn("EXPIRY_ENDPOINTS=stm32h573-dk-2 frdm-rw612 zynqmp-te0808", out)
        self.assertIn("AEGIS_SOAK=1", out)
        self.assertIn("gateway complete", out)
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.json")
            with open(p, "w") as fh:
                json.dump({"evil": "systemctl restart aegis-fleet"}, fh)
            with self.assertRaises(SystemExit) as e, contextlib.redirect_stderr(io.StringIO()):
                soak.main(["run", "--dry-run", "--gateway", "x", "--stm32", "y:1", "--commands", p])
            self.assertIn("refused", str(e.exception.code))


class Runner(unittest.TestCase):
    """RegressionRunner on real processes: stop() reaches the script behind Popen's shell, its trap runs, and the
    whole process group is gone afterwards."""

    def test_stop_reaches_the_script_and_its_trap(self):
        with tempfile.TemporaryDirectory() as d:
            marker = os.path.join(d, "trapped")
            script = os.path.join(d, "child.sh")
            with open(script, "w") as fh:
                fh.write("trap 'echo trapped > %s; exit 130' TERM\nsleep 60 &\nwait\n" % marker)
            # "; true" keeps Popen's sh -c in between, as with the real command line
            reg = soak.RegressionRunner("sh %s; true" % script, "true", {}, d, grace_s=10)
            pgid = reg.start("start")
            time.sleep(0.5)
            self.assertTrue(reg.alive(pgid))
            t = time.monotonic()
            reg.stop()
            self.assertLess(time.monotonic() - t, 9)       # ended on SIGTERM, not on the SIGKILL after the grace
            self.assertFalse(reg.alive(pgid))
            self.assertTrue(os.path.exists(marker))
            self.assertIsNotNone(reg.poll())

    def test_kill_after_grace(self):
        with tempfile.TemporaryDirectory() as d:
            reg = soak.RegressionRunner("trap '' TERM; sleep 60; true", "true", {}, d, grace_s=1)
            pgid = reg.start("start")
            time.sleep(0.3)
            self.assertFalse(reg.kill_group(pgid))         # ignored SIGTERM: killed after the grace
            self.assertFalse(reg.alive(pgid))
            self.assertFalse(soak.RegressionRunner.alive(0))


FAKE_SSH = r"""#!/bin/sh
# records its arguments; answers like the gateway would, enough for tools/regression.sh
printf '%s\n' "$*" | tr '\n' ' ' >> "$FAKE_SSH_LOG"; echo >> "$FAKE_SSH_LOG"
cat > /dev/null
case "$*" in
    *"date +%s"*) date +%s ;;
    *"fleet.py session"*)
        n=$(cat "$FAKE_SSH_LOG.session" 2>/dev/null || echo 0); echo $((n+1)) > "$FAKE_SSH_LOG.session"
        [ "$n" -ge "${FAKE_SESSION_FAILS:-0}" ] ;;
    *) exit 0 ;;
esac
"""


def run_regression(d, args, **env):
    """tools/regression.sh copied into a tree of its own (no bench.env, no .venv) with a fake ssh first on PATH."""
    import shutil
    import subprocess
    tree = os.path.join(d, "repo")
    os.makedirs(os.path.join(tree, "tools"))
    os.makedirs(os.path.join(tree, "tests", "board"))
    shutil.copy(os.path.join(ROOT, "tools", "regression.sh"), os.path.join(tree, "tools"))
    open(os.path.join(tree, "tests", "board", "expiry_check.py"), "w").close()
    bindir = os.path.join(d, "bin")
    os.makedirs(bindir)
    with open(os.path.join(bindir, "ssh"), "w") as fh:
        fh.write(FAKE_SSH)
    os.chmod(os.path.join(bindir, "ssh"), 0o755)
    log = os.path.join(d, "ssh.log")
    e = dict(os.environ, PATH=bindir + os.pathsep + os.environ["PATH"], FAKE_SSH_LOG=log, GATEWAY="192.0.2.10",
             STM32="192.0.2.21:7444")
    for k in ("AEGIS_SOAK", "AEGIS_STM32_OVERRIDE", "EXPIRY_ENDPOINTS", "AEGIS_REGRESSION_EXPIRY"):
        e.pop(k, None)
    e.update(env)
    p = subprocess.run(["sh", os.path.join(tree, "tools", "regression.sh")] + args, env=e, capture_output=True,
                       stdin=subprocess.DEVNULL, text=True, timeout=120)
    calls = read(d, "ssh.log").splitlines() if os.path.exists(log) else []
    return p, calls


class RegressionScript(unittest.TestCase):
    def test_expiry_ssh_calls_give_up_on_a_dead_link(self):
        with tempfile.TemporaryDirectory() as d:
            p, calls = run_regression(d, ["--expiry-only"], EXPIRY_ENDPOINTS="frdm-rw612 zynqmp-te0808")
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertIn("PASS endpoint-expiry", p.stdout)
            self.assertGreaterEqual(len(calls), 6)
            for c in calls:
                for opt in ("BatchMode=yes", "ConnectTimeout=10", "ServerAliveInterval=15", "ServerAliveCountMax=3"):
                    self.assertIn(opt, c)

    def test_fleet_session_retried_only_under_the_soak(self):
        # the first fleet.py session fails (a renewal raced it); the second would pass
        with tempfile.TemporaryDirectory() as d:
            p, calls = run_regression(d, ["--board"], FAKE_SESSION_FAILS="1", AEGIS_SOAK="1", AEGIS_SOAK_RETRY_S="0")
            self.assertIn("PASS fleet-session", p.stdout)
            self.assertIn("PASS fleet-heartbeat", p.stdout)
            self.assertEqual(sum("fleet.py session" in c for c in calls), 2)
        with tempfile.TemporaryDirectory() as d:
            p, calls = run_regression(d, ["--board"], FAKE_SESSION_FAILS="1", AEGIS_SOAK_RETRY_S="0")
            self.assertIn("FAIL fleet-session", p.stdout)
            self.assertEqual(sum("fleet.py session" in c for c in calls), 1)
        with tempfile.TemporaryDirectory() as d:     # a real mismatch fails under the soak as well
            p, calls = run_regression(d, ["--board"], FAKE_SESSION_FAILS="2", AEGIS_SOAK="1", AEGIS_SOAK_RETRY_S="0")
            self.assertIn("FAIL fleet-session", p.stdout)
            self.assertEqual(sum("fleet.py session" in c for c in calls), 2)


class BenchWatch(unittest.TestCase):
    def reply(self, lines):
        return bench_watch.parse_reply(T0, lines)

    def test_heartbeat_stopped(self):
        stuck = [REAL[0].replace("heartbeat 1 ", "heartbeat 7 ")] * 5
        r = self.reply(stuck + ["lines 40"])
        self.assertTrue(bench_watch.hb_stopped(r, "frdm-rw612"))
        self.assertEqual(r["lines"], 40)
        moving = [REAL[0].replace("heartbeat 1 ", "heartbeat %d " % i) for i in range(5)]
        self.assertFalse(bench_watch.hb_stopped(self.reply(moving), "frdm-rw612"))
        self.assertFalse(bench_watch.hb_stopped(self.reply(stuck + [REAL[2].replace("zynqmp-te0808", "frdm-rw612")]),
                                                "frdm-rw612"))
        self.assertFalse(bench_watch.hb_stopped(self.reply(stuck[:2]), "frdm-rw612"))

    def test_check_items(self):
        real = bench_watch.query_gateway
        try:
            bench_watch.query_gateway = lambda g, q: (self.reply(
                [REAL[0].replace("heartbeat 1 ", "heartbeat 7 ")] * 4 + [REAL[1], "fleet active", "lines 0"]), None)
            res, _ = bench_watch.check("gw", ["frdm-rw612", "stm32h573-dk-2", "zynqmp-te0808"], 600)
            self.assertFalse(res["frdm-rw612"][0])
            self.assertIn("stopped at 7", res["frdm-rw612"][1])
            self.assertTrue(res["stm32h573-dk-2"][0])
            self.assertFalse(res["zynqmp-te0808"][0])
            self.assertFalse(res["journal"][0])
            bench_watch.query_gateway = lambda g, q: (None, "ssh timed out")
            res, _ = bench_watch.check("gw", ["frdm-rw612"], 600)
            self.assertIsNone(res["journal"])
            self.assertIsNone(res["frdm-rw612"])
        finally:
            bench_watch.query_gateway = real

    def test_garbled(self):
        for lines in (["lines x", "fleet", "\x00" * 50, "1 2 3: 4 5 ADMITTED [credential: valid, heartbeat 99999999999999 "],
                      ["x" * 100000]):
            r = self.reply(lines)
            self.assertIn("last", r)


if __name__ == "__main__":
    unittest.main()

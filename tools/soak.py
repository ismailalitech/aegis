#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The soak (docs/soak-and-watchdogs.md): watch the gateway and the live endpoints for a day, sample every few
minutes over read-only SSH, detect the failure criteria as they happen, run the regression at the start, the middle
and the end, and write a report.

  tools/soak.py run --gateway ADDR [--hours 24] [--interval-min 5] [--endpoints a,b,c] [--absent x,y]
                    [--cred-lifetime 3600] [--expiry-every-h 0] [--console-dir DIR] [--out DIR]
  tools/soak.py run --resume logs/soak/<time>       # continue a run that was stopped (same settings)
  tools/soak.py run --dry-run ...                   # print what would run and parse one canned sample; no SSH
  tools/soak.py plan --out DIR --minutes 10 [--item NAME] --reason "unplug frdm-rw612's cable"
  tools/soak.py report DIR                          # write report.md again from DIR
  tools/soak.py selftest                            # a simulated day on a canned gateway, healthy and with faults

Writes DIR/samples.csv, DIR/events.log, DIR/state.json, DIR/raw/ (the gateway's answer when a check fails) and, at
the end, DIR/report.md. Exit 0 only if the soak passed.

Safety: the sampling commands are read-only and are checked for that before anything runs (check_commands). The only
thing that stops and starts aegis-fleet is the regression's endpoint-expiry stage (tools/regression.sh), with its
own restart trap and the gateway-side 15-minute guard timer. This tool never reboots or restarts anything itself.
"""
import argparse
import csv
import datetime
import fcntl
import json
import math
import os
import re
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

ENDPOINTS = "stm32h573-dk-2,frdm-rw612,zynqmp-te0808"
ABSENT = "stm32h573-dk,arduino-uno"          # quarantined by design or not connected: never a failure
RENEWAL_WINDOW_S = 300                        # gateway/aegisd/fleet.py RENEWAL_WINDOW_S
CYCLE_S = 30                                  # aegis-fleet --interval
DAY14_H = 14 * 24

# ---- what is sampled ----------------------------------------------------------------------------------------------
# One SSH call per sample: these sections, each introduced by "@@ <name>", sent to `sh -s` on stdin. The tokens
# @SINCE@ (gateway epoch of the previous sample), @STATE@ (/var/lib/aegis), @UNIT@ (aegis-fleet) and @MAXLINES@
# are replaced. --commands FILE (JSON {name: template}) replaces or adds sections; check_commands refuses any that
# could change the gateway.
COMMANDS = {
    "now": "date +%s; timedatectl show -p NTPSynchronized --value 2>/dev/null || echo unknown",
    "boot": "cat /proc/uptime; cat /proc/sys/kernel/random/boot_id",
    "units": "for u in @UNIT@ aegisd; do echo \"unit $u $(systemctl show $u -p ActiveState -p MainPID -p NRestarts "
             "| tr '\\n' ' ')\"; done",
    "procs": "for u in @UNIT@ aegisd; do p=$(systemctl show -p MainPID --value $u); echo \"proc $u $p "
             "$(grep -E '^(VmRSS|VmHWM|Threads):' /proc/$p/status 2>/dev/null | tr -s ' \\t\\n' '   ') "
             "fds $(ls /proc/$p/fd 2>/dev/null | wc -l)\"; done",
    "mem": "grep -E '^(MemTotal|MemAvailable):' /proc/meminfo; cat /proc/loadavg",
    "disk": "df -Pk / | tail -n 1; du -sk @STATE@ /var/lib/journal 2>/dev/null; journalctl --disk-usage 2>/dev/null",
    "state": "stat -c '%Y %s' @STATE@/fleet-state.json 2>/dev/null || echo missing",
    "creds": "python3 -c 'import json,glob,os\n"
             "for f in sorted(glob.glob(\"@STATE@/credentials/*.json\")):\n"
             "  try:\n"
             "    m=json.load(open(f)); b=m.get(\"body\") or dict()\n"
             "    print(\"cred\", os.path.basename(f)[:-5], str(m.get(\"session_id\"))[:16], b.get(\"issued\"), "
             "b.get(\"expires\"), m.get(\"hb_counter\", 0), json.dumps(str(m.get(\"last_status\", \"\"))))\n"
             "  except Exception as e:\n"
             "    print(\"cred-error\", os.path.basename(f), type(e).__name__)'",
    "journal": "journalctl -u @UNIT@ --since @@SINCE@ -o short-unix --no-pager | tail -n @MAXLINES@",
    "journal_all": "journalctl --since @@SINCE@ -o cat --no-pager | wc -l",
    "kernel": "journalctl -k --since @@SINCE@ -p err -o short-unix --no-pager | tail -n 200",
}

FORBIDDEN = re.compile(
    r"\bsystemctl\s+(?:--\S+\s+)*(start|stop|restart|reload|try-restart|kill|enable|disable|mask|daemon-reload|"
    r"daemon-reexec|reboot|poweroff|halt|isolate|reset-failed|set-property|edit)\b|"
    r"\b(reboot|poweroff|halt|shutdown|rm|rmdir|mv|cp|dd|mkfs\S*|kill|pkill|killall|truncate|tee|chmod|chown|"
    r"systemd-run|rmmod|modprobe|insmod|sysctl|mount|umount|sed\s+-i|ln|touch|install|wget|curl|scp)\b|"
    r"journalctl\s.*--(vacuum|rotate|flush|relinquish)|\bopen\([^)]*[\"'][wax+]")


def check_commands(cmds):
    """Refuse any template that could change the gateway; returns the list of problems (empty if all are safe)."""
    bad = []
    for name, t in cmds.items():
        if not isinstance(name, str) or not re.fullmatch(r"[a-z_]{1,32}", name):
            bad.append("section name %r" % (name,))
            continue
        if not isinstance(t, str):
            bad.append("%s: not a string" % name)
            continue
        stripped = re.sub(r"\d?>\s*/dev/null|2>&1", "", t)
        if ">" in stripped.replace("->", ""):
            bad.append("%s: redirects output into a file" % name)
        m = FORBIDDEN.search(t)
        if m:
            bad.append("%s: %r is not read-only" % (name, m.group(0)))
    return bad


def build_script(cmds, since, state="/var/lib/aegis", unit="aegis-fleet", max_lines=20000):
    out = []
    for name, t in cmds.items():
        t = (t.replace("@SINCE@", str(int(since))).replace("@STATE@", state).replace("@UNIT@", unit)
             .replace("@MAXLINES@", str(int(max_lines))))
        out.append('echo "@@ %s"\n%s' % (name, t))
    out.append('echo "@@ end"')
    return "\n".join(out) + "\n"


# ---- parsing (every input may be garbled; nothing here raises on bad text) ----------------------------------------

NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
MAX_LINE = 4096
MAX_SECTION_LINES = 50000


def to_int(s):
    try:
        v = int(str(s).strip())
    except (TypeError, ValueError):
        return None
    return v if -(1 << 62) < v < (1 << 62) else None


def to_float(s):
    try:
        v = float(str(s).strip())
    except (TypeError, ValueError):
        return None
    return v if math.isfinite(v) else None


def split_sections(text):
    """'@@ name' blocks -> ({name: [lines]}, complete). complete: the answer ended with '@@ end'."""
    secs, cur, complete = {}, None, False
    if not isinstance(text, str):
        return secs, False
    for ln in text.splitlines():
        ln = ln[:MAX_LINE]
        if ln.startswith("@@ "):
            name = ln[3:].strip()
            if name == "end":
                complete, cur = True, None
                continue
            cur = name if re.fullmatch(r"[a-z_]{1,32}", name) else None
            if cur is not None:
                secs[cur] = []
            continue
        if cur is not None and len(secs[cur]) < MAX_SECTION_LINES:
            secs[cur].append(ln)
    return secs, complete


def parse_status(text):
    """'uptime_s=992;link=1;fw=0.6.0;sstack=19088/26624;ttl=3005' -> dict of what is understood."""
    d = {}
    if not isinstance(text, str):
        return d
    for part in text[:1024].split(";"):
        k, sep, v = part.partition("=")
        k = k.strip()
        if not sep or not re.fullmatch(r"[a-z_]{1,16}", k):
            continue
        v = v.strip()[:64]
        if k in ("sstack", "stack"):
            used, _, size = v.partition("/")
            u, s = to_int(used), to_int(size)
            if u is not None and s and 0 <= u <= s:
                d["stack_used"], d["stack_size"] = u, s
        elif k in ("uptime_s", "ttl", "requests", "link"):
            n = to_int(v)
            if n is not None and n >= 0:
                d[k] = n
        else:
            d[k] = v
    return d


JOURNAL = re.compile(r"^(\d{9,11}(?:\.\d{1,9})?) \S+ [^:]{1,64}: (.*)$")
VERDICT = re.compile(r"^\d\d:\d\d:\d\d (\S{1,64}) (ADMITTED|QUARANTINED)\b(.*)$")
HEARTBEAT = re.compile(r"\[credential: valid, heartbeat (\d{1,12}) \(([^()]{0,512})\)")
ISSUED = re.compile(r"\[credential: issued session ([0-9a-f]{6,64})\.\.\.")
BAD_FLEET = re.compile(r"Traceback|enforcement FAILED|enforcement hook failed|policy REFUSED|NO AUDIT LOG|"
                       r"could NOT be written|MemoryError")


def parse_journal(lines):
    """aegis-fleet lines (journalctl -o short-unix) -> list of records in order:
    {"t", "kind": verdict|bad|other, "ep", "admitted", "reasons", "hb", "status", "issued", "text"}."""
    out = []
    for ln in lines or []:
        m = JOURNAL.match(ln[:MAX_LINE])
        if not m:
            continue
        t, msg = to_float(m.group(1)), m.group(2)
        if t is None:
            continue
        msg = re.sub(r"^<\d>", "", msg)
        v = VERDICT.match(msg)
        if v and NAME.match(v.group(1)):
            rec = {"t": t, "kind": "verdict", "ep": v.group(1), "admitted": v.group(2) == "ADMITTED",
                   "text": msg[:400]}
            rest = v.group(3)
            h = HEARTBEAT.search(rest)
            if h:
                rec["hb"] = to_int(h.group(1))
                rec["status"] = parse_status(h.group(2))
            i = ISSUED.search(rest)
            if i:
                rec["issued"] = i.group(1)
            if not rec["admitted"]:
                rec["reasons"] = re.sub(r"^\s*\([^)]*trust\)\s*", "", rest).strip()[:300]
            out.append(rec)
        elif BAD_FLEET.search(msg):
            out.append({"t": t, "kind": "bad", "text": msg[:400]})
        else:
            out.append({"t": t, "kind": "other", "text": msg[:200]})
    return out


KERNEL_FATAL = re.compile(r"Kernel panic|soft lockup|hard LOCKUP|\bOops\b|\bBUG:|hung_task|blocked for more than|"
                          r"Out of memory|oom-kill|rcu.{0,20}stall|Unable to handle kernel|watchdog: BUG",
                          re.I)
KERNEL_KNOWN = re.compile(r"mpfs_rtc: timed out uploading time to rtc")


def parse_sample(secs):
    """Sections -> one sample dict. Fields that could not be read are None."""
    g = lambda name: secs.get(name) or []  # noqa: E731
    s = {"gw_now": None, "ntp": None, "uptime_s": None, "boot_id": None, "units": {}, "procs": {},
         "mem_total_kb": None, "mem_avail_kb": None, "load1": None, "root_used_kb": None, "root_avail_kb": None,
         "aegis_du_kb": None, "journal_dir_kb": None, "journal_du_mb": None, "state_mtime": None, "creds": {},
         "cred_errors": [], "journal": [], "journal_all": None, "kernel": []}
    now = g("now")
    if now:
        s["gw_now"] = to_int(now[0])
        if len(now) > 1:
            s["ntp"] = now[1].strip()[:16]
    b = g("boot")
    if b:
        s["uptime_s"] = to_float(b[0].split()[0]) if b[0].split() else None
        if len(b) > 1 and re.fullmatch(r"[0-9a-f-]{32,36}", b[1].strip()):
            s["boot_id"] = b[1].strip()
    for ln in g("units"):
        p = ln.split()
        if len(p) >= 2 and p[0] == "unit" and NAME.match(p[1]):
            kv = dict(x.split("=", 1) for x in p[2:] if "=" in x)
            s["units"][p[1]] = {"active": kv.get("ActiveState", "")[:16], "pid": to_int(kv.get("MainPID")),
                                "nrestarts": to_int(kv.get("NRestarts"))}
    for ln in g("procs"):
        p = ln.split()
        if len(p) >= 3 and p[0] == "proc" and NAME.match(p[1]):
            d = {"pid": to_int(p[2])}
            for key, field in (("VmRSS:", "rss_kb"), ("VmHWM:", "hwm_kb"), ("Threads:", "threads"), ("fds", "fds")):
                if key in p[3:]:
                    i = p.index(key, 3)
                    d[field] = to_int(p[i + 1]) if i + 1 < len(p) else None
            s["procs"][p[1]] = d
    for ln in g("mem"):
        p = ln.split()
        if len(p) >= 2 and p[0] == "MemTotal:":
            s["mem_total_kb"] = to_int(p[1])
        elif len(p) >= 2 and p[0] == "MemAvailable:":
            s["mem_avail_kb"] = to_int(p[1])
        elif len(p) >= 5 and "/" in p[3]:
            s["load1"] = to_float(p[0])
    for ln in g("disk"):
        p = ln.split()
        if len(p) >= 6 and p[-1] == "/":
            s["root_used_kb"], s["root_avail_kb"] = to_int(p[2]), to_int(p[3])
        elif len(p) == 2 and p[1].startswith("/var/lib/aegis"):
            s["aegis_du_kb"] = to_int(p[0])
        elif len(p) == 2 and p[1] == "/var/lib/journal":
            s["journal_dir_kb"] = to_int(p[0])
        else:
            m = re.search(r"take up ([0-9.]+)([BKMGT])", ln)
            if m and to_float(m.group(1)) is not None:
                mult = {"B": 1 / 1048576, "K": 1 / 1024, "M": 1, "G": 1024, "T": 1048576}[m.group(2)]
                s["journal_du_mb"] = round(to_float(m.group(1)) * mult, 3)
    st = g("state")
    if st and st[0].split():
        s["state_mtime"] = to_int(st[0].split()[0])
    for ln in g("creds"):
        p = ln.split(" ", 6)
        if len(p) == 7 and p[0] == "cred" and NAME.match(p[1]):
            try:
                status = json.loads(p[6])
            except ValueError:
                status = ""
            s["creds"][p[1]] = {"session": p[2] if re.fullmatch(r"[0-9a-f]{6,16}", p[2]) else None,
                                "issued": to_int(p[3]), "expires": to_int(p[4]), "hb": to_int(p[5]),
                                "status": parse_status(status if isinstance(status, str) else "")}
        elif ln.startswith("cred-error"):
            s["cred_errors"].append(ln[:200])
    s["journal"] = parse_journal(g("journal"))
    ja = g("journal_all")
    if ja:
        s["journal_all"] = to_int(ja[0])
    for ln in g("kernel"):
        m = JOURNAL.match(ln)
        if m:
            s["kernel"].append((to_float(m.group(1)), m.group(2)[:300]))
    return s


def parse_answer(text):
    secs, complete = split_sections(text)
    s = parse_sample(secs)
    s["complete"] = complete and s["gw_now"] is not None
    return s


# ---- the criteria ---------------------------------------------------------------------------------------------------

BOUNDS = {
    "hang_samples": 2,            # samples in a row without an SSH answer: a gateway hang (or the link)
    "state_stale_s": 300,         # fleet-state.json older than this: the fleet loop is stuck
    "clock_step_s": 120,          # gateway clock minus PC clock moved by more than this
    "ttl_rate_min": 0.90,         # endpoint seconds per gateway second, from the heartbeat ttl
    "ttl_rate_max": 1.06,         # the endpoints' margin covers a clock up to 6 % fast (docs/endpoint-expiry.md)
    "ttl_rate_min_span_s": 1800,  # gateway seconds of heartbeat pairs before the rate is judged
    "ttl_low_s": 60,              # a ttl below this: the renewal is late, the endpoint is about to end the session
    "stack_frac_max": 0.90,       # secure stack high-water mark against its size
    "trend_min_h": 6.0,           # hours of samples (one fleet process) before a trend is judged
    "fleet_rss_14d_kb": 16384,    # projected growth over 14 days
    "aegisd_rss_14d_kb": 8192,
    "fds_14d": 32,
    "mem_avail_drop_14d_kb": 65536,
    "aegis_du_14d_kb": 65536,
    "root_used_14d_kb": 262144,
    "journal_du_max_mb": 64,      # journald keeps 50 MB (docs/board-changes.md)
    "root_avail_min_frac": 0.10,
    "mem_avail_min_kb": 65536,
    "fds_max": 256,
    "regression_gap_s": 600,      # longest gap a regression's expiry stage excuses: its ~3 min stop + 240 s readmission
}

# What a regression's window excuses (Soak.excused): events of its stages, and gaps for at most regression_gap_s.
REG_FLEET_EVENTS = {"pid"}                                    # the expiry stage stops and starts aegis-fleet
REG_EP_EVENTS = {"replaced", "quarantined"}                   # sessions ended and issued again, the expiry check
REG_FLEET_GAPS = {"inactive", "quiet", "stale"}
REG_EP_GAPS = {"silent", "nosession", "hbstop", "overdue", "expired", "ttllow"}
DEFAULT_TIMEOUT_MIN = {"regression_timeout_min": 45.0, "expiry_timeout_min": 20.0}

TRENDS = [  # (column, bound key, sign: +1 growth is bad, -1 decline is bad)
    ("fleet_rss_kb", "fleet_rss_14d_kb", 1),
    ("aegisd_rss_kb", "aegisd_rss_14d_kb", 1),
    ("fleet_fds", "fds_14d", 1),
    ("mem_avail_kb", "mem_avail_drop_14d_kb", -1),
    ("aegis_du_kb", "aegis_du_14d_kb", 1),
    ("root_used_kb", "root_used_14d_kb", 1),
]


def finding(level, item, key, msg, always=False, once=False):
    """level FAIL / WARN / INFO. always: never excused by a planned window (a reboot, a reset, a panic).
    once: an event, logged every time it happens; else a condition, logged when it starts and when it clears."""
    return {"level": level, "item": item, "key": key, "msg": msg, "always": always, "once": once}


def segments(rows, pid_col="fleet_pid", min_s=3600):
    """Runs of answered rows with one fleet process (RSS and fds start again with a new process, and the regression's
    expiry stage restarts it); runs shorter than min_s are left out."""
    segs, seg = [], []
    for r in rows:
        if r.get("ok") != 1:
            continue
        if seg and r.get(pid_col) != seg[-1].get(pid_col):
            segs.append(seg)
            seg = []
        seg.append(r)
    segs.append(seg)
    return [g for g in segs if len(g) > 1 and g[-1]["pc_time"] - g[0]["pc_time"] >= min_s]


def pooled_slope_per_h(groups):
    """One slope for several runs, each with its own starting level (least squares with an intercept per run)."""
    num = den = 0.0
    n = 0
    for pts in groups:
        pts = [(t, v) for t, v in pts if t is not None and v is not None]
        if len(pts) < 2:
            continue
        mt = sum(t for t, _ in pts) / len(pts)
        mv = sum(v for _, v in pts) / len(pts)
        num += sum((t - mt) * (v - mv) for t, v in pts)
        den += sum((t - mt) ** 2 for t, _ in pts)
        n += len(pts)
    if n < 3 or den <= 0:
        return None
    return num / den * 3600.0


def trend_findings(rows, bounds, final=False):
    """Projected growth over 14 days for each TRENDS column: one slope over the runs of one fleet process each, at
    least an hour long. Returns (findings, table) where table rows are dicts for the report."""
    out, table = [], []
    segs = segments(rows)
    span_h = sum(g[-1]["pc_time"] - g[0]["pc_time"] for g in segs) / 3600.0
    every = [r for r in rows if r.get("ok") == 1]
    for col, bkey, sign in TRENDS:
        vals = [r.get(col) for r in every if r.get(col) is not None]
        sl = pooled_slope_per_h([[(r["pc_time"], r.get(col)) for r in g] for g in segs])
        proj = None if sl is None else sl * DAY14_H * sign
        judged = sl is not None and span_h >= bounds["trend_min_h"]
        ok = (not judged) or proj <= bounds[bkey]
        table.append({"metric": col, "first": vals[0] if vals else None, "last": vals[-1] if vals else None,
                      "min": min(vals) if vals else None, "max": max(vals) if vals else None,
                      "slope_per_h": None if sl is None else round(sl, 3),
                      "projected_14d": None if proj is None else round(proj, 1), "bound_14d": bounds[bkey],
                      "span_h": round(span_h, 2), "judged": judged, "ok": ok})
        if judged and not ok:
            out.append(finding("FAIL", "gateway", "trend:" + col,
                               "%s would %s by %.0f in 14 days (%.2f per hour over %.1f h; bound %d)" % (
                                   col, "grow" if sign > 0 else "fall", proj, sl, span_h, bounds[bkey])))
    return out, table


def new_ep_track():
    return {"session": None, "expires": None, "hb": None, "uptime_s": None, "requests": None, "last_hb": None,
            "rate_dt": 0.0, "rate_dttl": 0.0, "stack_used_max": None, "stack_size": None, "stack_first": None,
            "verdicts": 0, "quarantined": 0, "renewals": 0, "resets": 0, "lifetime": None}


def check_endpoint(name, tr, cur, prev, bounds, cred_lifetime, sample_span_s):
    """Findings for one endpoint from one sample, updating its track tr."""
    f = []
    recs = [r for r in cur["journal"] if r["kind"] == "verdict" and r.get("ep") == name]
    tr["verdicts"] += len(recs)
    q = [r for r in recs if not r["admitted"]]
    tr["quarantined"] += len(q)
    if q:
        f.append(finding("FAIL", name, name + ":quarantined:%d" % int(q[0]["t"]),
                         "QUARANTINED %d time(s), first: %s" % (len(q), q[0].get("reasons") or q[0]["text"]),
                         once=True))
    if not recs and sample_span_s >= 3 * CYCLE_S:
        f.append(finding("FAIL", name, name + ":silent", "no verdict line in the last %d s" % sample_span_s))
    for r in recs:
        if r.get("issued"):
            tr["renewals"] += 1
        st = r.get("status") or {}
        if r.get("hb") is not None and "ttl" in st:
            last = tr["last_hb"]
            if last and r["hb"] > last[1] and st["ttl"] <= last[2] and 0 < r["t"] - last[0] <= 600:
                tr["rate_dt"] += r["t"] - last[0]
                tr["rate_dttl"] += last[2] - st["ttl"]
            tr["last_hb"] = [r["t"], r["hb"], st["ttl"]]
        f += check_status(name, tr, st, bounds, cred_lifetime)
    c = cur["creds"].get(name)
    gw = cur["gw_now"]
    if c is None:
        if tr["session"] is not None:
            f.append(finding("FAIL", name, name + ":nosession", "no session on the gateway"))
    else:
        if c["issued"] is not None and c["expires"] is not None:
            tr["lifetime"] = c["expires"] - c["issued"]
            if tr["lifetime"] != cred_lifetime:
                f.append(finding("WARN", name, name + ":lifetime", "credential lifetime %d s, the soak expects %d s"
                                 % (tr["lifetime"], cred_lifetime)))
        if tr["session"] is not None and c["session"] != tr["session"]:
            due = tr["expires"] is not None and gw is not None and gw >= tr["expires"] - RENEWAL_WINDOW_S - 60
            if due:
                f.append(finding("INFO", name, name + ":renewed:%s" % c["session"], "session renewed", once=True))
            else:
                f.append(finding("FAIL", name, name + ":replaced:%s" % c["session"],
                                 "session %s replaced by %s before its renewal was due (revoked)" % (
                                     tr["session"], c["session"]), once=True))
        elif tr["session"] is not None and c["hb"] is not None and tr["hb"] is not None and c["hb"] <= tr["hb"]:
            f.append(finding("FAIL", name, name + ":hbstop", "heartbeat counter stopped at %d" % c["hb"]))
        if gw is not None and c["expires"] is not None:
            if gw > c["expires"]:
                f.append(finding("FAIL", name, name + ":expired", "the stored credential expired %d s ago and was "
                                 "not renewed" % (gw - c["expires"])))
            elif gw > c["expires"] - RENEWAL_WINDOW_S + 180:
                f.append(finding("FAIL", name, name + ":overdue", "renewal overdue: %d s left" % (c["expires"] - gw)))
        # its last_status is only as new as the last counted heartbeat: not checked (stale after a stop)
        tr["session"], tr["expires"], tr["hb"] = c["session"], c["expires"], c["hb"]
    if tr["rate_dt"] >= bounds["ttl_rate_min_span_s"]:
        rate = tr["rate_dttl"] / tr["rate_dt"]
        if not bounds["ttl_rate_min"] <= rate <= bounds["ttl_rate_max"]:
            f.append(finding("FAIL", name, name + ":rate", "endpoint clock at %.3f s per gateway second (bounds "
                             "%.2f to %.2f)" % (rate, bounds["ttl_rate_min"], bounds["ttl_rate_max"])))
    return f


def check_status(name, tr, st, bounds, cred_lifetime):
    f = []
    for k in ("uptime_s", "requests"):
        if k in st:
            if tr[k] is not None and st[k] < tr[k]:
                tr["resets"] += 1
                f.append(finding("FAIL", name, name + ":reset:%s:%d" % (k, st[k]),
                                 "endpoint reset: %s went from %d to %d" % (k, tr[k], st[k]), always=True, once=True))
            tr[k] = st[k]
    if "stack_used" in st:
        if tr["stack_first"] is None:
            tr["stack_first"] = st["stack_used"]
        tr["stack_used_max"] = max(tr["stack_used_max"] or 0, st["stack_used"])
        tr["stack_size"] = st["stack_size"]
        if st["stack_used"] >= bounds["stack_frac_max"] * st["stack_size"]:
            f.append(finding("FAIL", name, name + ":stack", "secure stack %d/%d used" % (
                st["stack_used"], st["stack_size"])))
    if "ttl" in st:
        top = cred_lifetime + cred_lifetime // 16 + 5
        if st["ttl"] > max(top, 3825 + 5):
            f.append(finding("FAIL", name, name + ":ttlhigh", "ttl %d above the lifetime" % st["ttl"]))
        elif st["ttl"] < bounds["ttl_low_s"]:
            f.append(finding("FAIL", name, name + ":ttllow", "ttl %d: the session is about to end on the endpoint"
                             % st["ttl"]))
    if st.get("link") == 0:
        f.append(finding("WARN", name, name + ":link", "the endpoint reports link=0"))
    if st.get("clk") == "cpu":
        f.append(finding("WARN", name, name + ":clk", "the endpoint counts on its fallback clock (clk=cpu)"))
    return f


def bad_line_endpoint(text, names):
    """The endpoint a bad aegis-fleet line names ("enforcement hook failed for frdm-rw612 ..."), or None. The longest
    name that appears as a whole word wins (stm32h573-dk-2 over stm32h573-dk)."""
    for n in sorted(set(names), key=len, reverse=True):
        if re.search(r"(?<![A-Za-z0-9._-])%s(?![A-Za-z0-9_-]|\.[A-Za-z0-9])" % re.escape(n), text):
            return n
    return None


def check_gateway(cur, prev, bounds, base_offset, endpoints=(), absent=()):
    """Findings for the gateway. A bad aegis-fleet line that names an endpoint is that endpoint's finding; on an
    absent endpoint it is INFO, as its quarantine is."""
    f = []
    gw = cur["gw_now"]
    if prev and prev.get("boot_id") and cur["boot_id"] and cur["boot_id"] != prev["boot_id"]:
        f.append(finding("FAIL", "gateway", "gateway:reboot:" + cur["boot_id"],
                         "gateway rebooted (up %s s)" % (int(cur["uptime_s"]) if cur["uptime_s"] else "?"),
                         always=True, once=True))
    for unit in ("aegis-fleet", "aegisd"):
        u = cur["units"].get(unit)
        pu = (prev or {}).get("units", {}).get(unit) if prev else None
        if u is None:
            f.append(finding("WARN", unit, unit + ":unknown", "%s: state not readable" % unit))
            continue
        if u["active"] != "active":
            f.append(finding("FAIL", unit, unit + ":inactive", "%s is %s" % (unit, u["active"] or "unknown")))
        if pu and u["nrestarts"] is not None and pu.get("nrestarts") is not None and u["nrestarts"] > pu["nrestarts"]:
            f.append(finding("FAIL", unit, unit + ":nrestarts:%d" % u["nrestarts"], "%s restarted itself "
                             "(NRestarts %d -> %d)" % (unit, pu["nrestarts"], u["nrestarts"]), once=True))
        elif pu and u["pid"] and pu.get("pid") and u["pid"] != pu["pid"]:
            f.append(finding("FAIL", unit, unit + ":pid:%d" % u["pid"], "%s has a new process (%d -> %d)" % (
                unit, pu["pid"], u["pid"]), once=True))
    if cur["state_mtime"] is None:
        f.append(finding("FAIL", "aegis-fleet", "state:missing", "fleet-state.json not readable"))
    elif gw is not None and gw - cur["state_mtime"] > bounds["state_stale_s"]:
        f.append(finding("FAIL", "aegis-fleet", "state:stale", "fleet-state.json not written for %d s (the loop is "
                         "stuck)" % (gw - cur["state_mtime"])))
    span = gw - prev["gw_now"] if prev and prev.get("gw_now") and gw else 0
    if span >= 3 * CYCLE_S and not cur["journal"]:
        f.append(finding("FAIL", "aegis-fleet", "journal:quiet", "aegis-fleet wrote nothing to the journal in %d s"
                         % span))
    for r in cur["journal"]:
        if r["kind"] == "bad":
            ep = bad_line_endpoint(r["text"], list(endpoints) + list(absent))
            if ep in absent:
                f.append(finding("INFO", ep, "journal:bad:%d" % int(r["t"]), "on an absent endpoint: " + r["text"],
                                 once=True))
            else:
                f.append(finding("FAIL", ep or "aegis-fleet", "journal:bad:%d" % int(r["t"]), r["text"], once=True))
    for t, msg in cur["kernel"]:
        if KERNEL_FATAL.search(msg):
            f.append(finding("FAIL", "gateway", "kernel:%s" % t, "kernel: " + msg, always=True, once=True))
        elif KERNEL_KNOWN.search(msg):
            f.append(finding("INFO", "gateway", "kernel-known:%s" % t, "known kernel message: " + msg, once=True))
        else:
            f.append(finding("WARN", "gateway", "kernel-err:%s" % t, "kernel error: " + msg, once=True))
    if cur.get("offset") is not None and base_offset is not None and \
            abs(cur["offset"] - base_offset) > bounds["clock_step_s"]:
        f.append(finding("FAIL", "gateway", "clock:step", "gateway clock moved %+d s against the PC since the start"
                         % (cur["offset"] - base_offset)))
    if cur["ntp"] == "no":
        f.append(finding("WARN", "gateway", "clock:ntp", "gateway clock not synchronised (NTP)"))
    if cur["journal_du_mb"] is not None and cur["journal_du_mb"] > bounds["journal_du_max_mb"]:
        f.append(finding("FAIL", "gateway", "journal:size", "journal uses %.1f MB" % cur["journal_du_mb"]))
    if cur["root_avail_kb"] is not None and cur["root_used_kb"] is not None:
        tot = cur["root_avail_kb"] + cur["root_used_kb"]
        if tot and cur["root_avail_kb"] < bounds["root_avail_min_frac"] * tot:
            f.append(finding("FAIL", "gateway", "disk:low", "root file system %d kB free" % cur["root_avail_kb"]))
    if cur["mem_avail_kb"] is not None and cur["mem_avail_kb"] < bounds["mem_avail_min_kb"]:
        f.append(finding("FAIL", "gateway", "mem:low", "MemAvailable %d kB" % cur["mem_avail_kb"]))
    fds = cur["procs"].get("aegis-fleet", {}).get("fds")
    if fds is not None and fds > bounds["fds_max"]:
        f.append(finding("FAIL", "aegis-fleet", "fds:high", "aegis-fleet holds %d file descriptors" % fds))
    for e in cur["cred_errors"]:
        f.append(finding("WARN", "gateway", "cred-error:" + e[:60], e))
    return f


def console_findings(text):
    """Lines of the gateway's kernel console (tools/console_logger.py) that end the soak."""
    return [finding("FAIL", "gateway", "console:%d:%s" % (i, ln[:40]), "console: " + ln[:300], always=True, once=True)
            for i, ln in enumerate(text.splitlines()) if KERNEL_FATAL.search(ln)]


# ---- the run --------------------------------------------------------------------------------------------------------

CSV_GW = ["pc_time", "gw_time", "ok", "offset_s", "gw_uptime_s", "fleet_active", "fleet_pid", "fleet_nrestarts",
          "fleet_rss_kb", "fleet_hwm_kb", "fleet_fds", "fleet_threads", "aegisd_rss_kb", "mem_avail_kb", "load1",
          "root_used_kb", "root_avail_kb", "aegis_du_kb", "journal_du_mb", "journal_lines", "journal_all_lines",
          "kernel_err_lines", "state_age_s", "planned"]
CSV_EP = ["verdicts", "quarantined", "session", "hb", "ttl", "uptime_s", "requests", "stack_used", "renewals"]


def iso(t):
    return datetime.datetime.fromtimestamp(t).astimezone().isoformat(timespec="seconds")


class RealClock:
    def now(self):
        return time.time()

    def sleep(self, s):
        time.sleep(max(0.0, s))


class SSHGateway:
    def __init__(self, addr):
        self.addr = addr

    def ask(self, script):
        cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=5",
               "-o", "ServerAliveCountMax=3", "root@" + self.addr, "sh -s"]
        try:
            p = subprocess.run(cmd, input=script, capture_output=True, text=True, timeout=120, errors="replace")
        except subprocess.TimeoutExpired:
            return None, "ssh timed out"
        if p.returncode == 255:
            return None, (p.stderr.strip().splitlines() or ["ssh exit 255"])[-1][:200]
        return p.stdout, None


class RegressionRunner:
    """Runs tools/regression.sh in the background, in a process group of its own (start_new_session): the shell that
    Popen puts in between is not the only process signalled. stop() sends SIGTERM to the whole group, so
    regression.sh's restart trap runs, waits for the group to end (the trap starts aegis-fleet again) and sends
    SIGKILL to what is left after the grace time. The group id is the pid returned by start(): a resumed runner uses
    it to see whether a regression from before its restart is still running (alive)."""

    def __init__(self, cmd, expiry_cmd, env, out, grace_s=180):
        self.cmd, self.expiry_cmd, self.env, self.out, self.grace_s = cmd, expiry_cmd, env, out, grace_s
        self.p = None

    def start(self, stage):
        log = open(os.path.join(self.out, "regression-%s.log" % stage), "w")
        cmd = self.expiry_cmd if stage.startswith("expiry") else self.cmd
        self.p = subprocess.Popen(cmd, shell=True, cwd=REPO, env=dict(os.environ, **self.env), stdout=log,
                                  stderr=subprocess.STDOUT, start_new_session=True)
        log.close()
        return self.p.pid

    def poll(self):
        return None if self.p is None else self.p.poll()

    @staticmethod
    def alive(pgid):
        """True while any process of the group pgid exists."""
        if not pgid or pgid <= 1:
            return False
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def _reap(self, pgid):
        if self.p is not None and self.p.pid == pgid:
            self.p.poll()              # our own group leader: a zombie would still count as alive

    def kill_group(self, pgid, grace_s=None):
        """SIGTERM to the group, wait up to grace_s for all of it to end, then SIGKILL. True if it had ended."""
        grace_s = self.grace_s if grace_s is None else grace_s
        self._reap(pgid)
        if not self.alive(pgid):
            return True
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            return True
        deadline = time.monotonic() + grace_s
        while time.monotonic() < deadline:
            self._reap(pgid)
            if not self.alive(pgid):
                return True
            time.sleep(0.2)
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if self.p is not None and self.p.pid == pgid:
            try:
                self.p.wait(10)
            except subprocess.TimeoutExpired:
                pass
        return False

    def stop(self):
        if self.p is not None:
            self.kill_group(self.p.pid)


class Soak:
    def __init__(self, out, cfg, gateway, clock, regression, cmds=COMMANDS):
        self.out, self.gw, self.clock, self.reg = out, gateway, clock, regression
        self.cmds = cmds
        self.state_path = os.path.join(out, "state.json")
        if os.path.exists(self.state_path):
            with open(self.state_path) as fh:
                self.st = json.load(fh)
            self.cfg = self.st["cfg"]
            for w in self.st["planned"]:          # a state from before regression windows had their own item
                if w[2] == "*" and w[3].startswith("regression "):
                    w[2] = "regression"
            self.event(None, "INFO", "runner", "soak runner resumed (%d s after the last sample)" % (
                clock.now() - (self.st.get("last_pc") or clock.now())))
            run = self.st.get("running")
            if run:
                pgid = run.get("pgid", run.get("pid"))
                if pgid and regression.alive(pgid):
                    # the runner stopped without stopping it: running the stage again now would overlap two
                    # regressions (two expiry stages stopping and starting aegis-fleet). Wait for it to end.
                    run["orphan"] = True
                    self.event(None, "WARN", "runner", "regression %s from before the restart is still running "
                               "(process group %d): waiting for it to end, then it runs again" % (run["stage"], pgid))
                else:
                    self.event(None, "WARN", "runner", "regression %s was interrupted by the restart; it runs again"
                               % run["stage"])
                    self.st["running"] = None
        else:
            self.cfg = cfg
            t0 = clock.now()
            dur = cfg["hours"] * 3600
            sched = [["start", t0], ["middle", t0 + dur / 2]]
            if cfg["expiry_every_h"] > 0:
                k = 1
                while k * cfg["expiry_every_h"] * 3600 < dur - 1800:
                    tk = t0 + k * cfg["expiry_every_h"] * 3600
                    if abs(tk - (t0 + dur / 2)) > 1800:
                        sched.append(["expiry-%d" % k, tk])
                    k += 1
            sched.sort(key=lambda x: x[1])
            if not cfg["regression"]:
                sched = []
            self.st = {"cfg": cfg, "t0": t0, "t_end": t0 + dur, "schedule": sched, "done": {}, "running": None,
                       "planned": [], "prev": None, "base_offset": None, "eps": {e: new_ep_track()
                                                                              for e in cfg["endpoints"]},
                       "open": {}, "failures": {}, "warnings": {}, "infos": {}, "ssh_fail": 0, "ssh_fail_since": None,
                       "max_gap_s": 0, "samples": 0, "last_pc": None, "console": {}, "next_sample": t0,
                       "absent": {e: 0 for e in cfg["absent"]}, "finished": False}
            self.event(None, "INFO", "runner", "soak started: %g h, endpoints %s, absent %s, credential lifetime %d s"
                       % (cfg["hours"], ",".join(cfg["endpoints"]), ",".join(cfg["absent"]), cfg["cred_lifetime"]))
        self.rows = read_csv(os.path.join(out, "samples.csv"))

    # -- records --

    def event(self, t, level, item, msg):
        t = self.clock.now() if t is None else t
        with open(os.path.join(self.out, "events.log"), "a") as fh:
            fh.write("%s %-8s %s: %s\n" % (iso(t), level, item, msg.replace("\n", " ")[:600]))

    def save(self):
        fd, tmp = tempfile.mkstemp(dir=self.out, prefix=".state")
        with os.fdopen(fd, "w") as fh:
            json.dump(self.st, fh, indent=1)
        os.replace(tmp, self.state_path)

    def windows(self, t):
        """The planned windows open at t (a regression's included). Findings are judged when a sample sees them, up
        to one interval after they happened, so each window lasts one interval longer than announced: an event near
        its end is excused whatever --interval-min is."""
        slack = self.cfg["interval_min"] * 60
        return [w for w in self.st["planned"] if w[0] <= t <= w[1] + slack]

    def excused(self, f, t):
        """Whether a planned window excuses the finding f seen at t. A window announced with `plan` excuses every
        failure of its item (or of all, for *). A regression's window excuses only what its stages do: the
        expiry stage's new aegis-fleet process, sessions replaced and quarantines of the endpoints under test,
        and, for at most bounds regression_gap_s (the stage's 3 min stop and the 240 s readmission), the gaps
        that stop leaves: aegis-fleet inactive, its journal quiet, its state file stale, an endpoint silent,
        without a session, with its counter stopped or its credential overdue. Never an SSH hang, aegisd, or a
        gap that lasts longer."""
        for _, _, it, _ in self.windows(t):
            if it == "regression":
                if self.regression_excuses(f, t):
                    return True
            elif it in ("*", f["item"]):
                return True
        return False

    def regression_excuses(self, f, t):
        parts = f["key"].split(":")
        kind = parts[1] if len(parts) > 1 else ""
        eps = self.cfg["endpoints"]
        if (f["item"] == "aegis-fleet" and kind in REG_FLEET_EVENTS) or (f["item"] in eps and kind in REG_EP_EVENTS):
            return True
        if (f["item"] == "aegis-fleet" and kind in REG_FLEET_GAPS) or (f["item"] in eps and kind in REG_EP_GAPS):
            since = self.st.setdefault("since", {}).get(f["key"], t)
            return t - since <= self.cfg["bounds"].get("regression_gap_s", BOUNDS["regression_gap_s"])
        return False

    def load_plans(self):
        p = os.path.join(self.out, "planned.txt")
        if not os.path.exists(p):
            return
        keep = [x for x in self.st["planned"] if x[3].startswith("regression ")]
        with open(p) as fh:
            for ln in fh:
                parts = ln.split(None, 3)
                if len(parts) == 4 and to_float(parts[0]) is not None and to_float(parts[1]) is not None:
                    keep.append([to_float(parts[0]), to_float(parts[1]), parts[2][:64], parts[3].strip()[:200]])
        self.st["planned"] = keep

    def apply(self, findings, t):
        """Log findings: conditions when they start and clear, events every time; planned windows excuse."""
        seen = set()
        since = self.st.setdefault("since", {})
        for f in findings:
            key = f["key"]
            if not f["once"]:
                since.setdefault(key, t)       # when the condition was first seen (a regression's gap budget)
            level = f["level"]
            if level in ("FAIL", "WARN") and not f["always"] and self.excused(f, t):
                level = "EXPECTED"
            if not f["once"]:
                seen.add(key)
                if self.st["open"].get(key) == level:
                    continue
                self.st["open"][key] = level
            self.event(t, level, f["item"], f["msg"])
            bucket = {"FAIL": "failures", "WARN": "warnings"}.get(level, "infos")
            summ = key.rsplit(":", 1)[0] if f["once"] and f["item"] != "regression" and key.count(":") > 1 else key
            b = self.st[bucket].setdefault(summ, {"first": iso(t), "count": 0, "msg": f["msg"][:300],
                                                  "item": f["item"], "level": level})
            b["count"] += 1
            b["last"] = iso(t)
        for key in [k for k in self.st["open"] if k not in seen]:
            if self.st["open"][key] in ("FAIL", "WARN", "EXPECTED"):
                self.event(t, "CLEARED", key.split(":")[0], key)
            del self.st["open"][key]
        for key in [k for k in since if k not in seen]:
            del since[key]

    # -- one sample --

    def sample(self):
        t = self.clock.now()
        prev = self.st["prev"]
        since = (prev or {}).get("gw_now") or 0
        if prev is None or not since:
            since = int(t) - 600
        gw_guess = int(t + (self.st["base_offset"] or 0))
        since = max(since, gw_guess - 6 * 3600)
        text, err = self.gw.ask(build_script(self.cmds, since, max_lines=20000))
        cur = parse_answer(text) if err is None else None
        self.st["samples"] += 1
        self.load_plans()
        row = {"pc_time": round(t), "ok": 0, "planned": int(bool(self.windows(t)))}
        if cur is None or not cur["complete"]:
            self.st["ssh_fail"] += 1
            self.st["ssh_fail_since"] = self.st["ssh_fail_since"] or t
            why = err or "incomplete answer"
            findings = [finding("WARN", "gateway", "ssh:fail", "no complete answer: %s" % why)]
            if self.st["ssh_fail"] >= self.cfg["bounds"]["hang_samples"]:
                findings = [finding("FAIL", "gateway", "ssh:hang", "no answer for %d samples since %s (%s): gateway "
                                    "hang or link loss" % (self.st["ssh_fail"], iso(self.st["ssh_fail_since"]), why))]
            if text:
                self.raw(t, text)
            self.apply(findings, t)
            self.append_row(row)
            return
        if self.st["ssh_fail"]:
            gap = t - self.st["ssh_fail_since"]
            self.st["max_gap_s"] = max(self.st["max_gap_s"], gap)
            self.event(t, "INFO", "gateway", "answers again after %d s" % gap)
        self.st["ssh_fail"], self.st["ssh_fail_since"] = 0, None
        cur["offset"] = cur["gw_now"] - t
        if self.st["base_offset"] is None:
            self.st["base_offset"] = cur["offset"]
        last_t = (prev or {}).get("last_journal_t") or 0
        cur["journal"] = [r for r in cur["journal"] if r["t"] > last_t]
        cur["last_journal_t"] = max([r["t"] for r in cur["journal"]] + [last_t])
        bounds = self.cfg["bounds"]
        findings = check_gateway(cur, prev, bounds, self.st["base_offset"], self.cfg["endpoints"], self.cfg["absent"])
        span = cur["gw_now"] - prev["gw_now"] if prev and prev.get("gw_now") else 0
        for name in self.cfg["endpoints"]:
            findings += check_endpoint(name, self.st["eps"][name], cur, prev, bounds, self.cfg["cred_lifetime"],
                                       span)
        for name in self.cfg["absent"]:
            self.st["absent"][name] = self.st["absent"].get(name, 0) + sum(
                1 for r in cur["journal"] if r["kind"] == "verdict" and r.get("ep") == name)
        findings += self.console()
        rows = self.rows + [self.row(row, cur)]
        if (t - self.st["t0"]) / 3600.0 >= bounds["trend_min_h"]:
            findings += trend_findings(rows, bounds)[0]
        if any(f["level"] == "FAIL" for f in findings):
            self.raw(t, text)
        self.apply(findings, t)
        self.append_row(rows[-1])
        keep = {k: cur[k] for k in ("gw_now", "boot_id", "units", "last_journal_t", "uptime_s")}
        self.st["prev"] = keep

    def row(self, row, cur):
        fl = cur["units"].get("aegis-fleet", {})
        pf = cur["procs"].get("aegis-fleet", {})
        pa = cur["procs"].get("aegisd", {})
        row.update({"gw_time": cur["gw_now"], "ok": 1, "offset_s": round(cur["offset"], 1),
                    "gw_uptime_s": cur["uptime_s"], "fleet_active": fl.get("active"), "fleet_pid": fl.get("pid"),
                    "fleet_nrestarts": fl.get("nrestarts"), "fleet_rss_kb": pf.get("rss_kb"),
                    "fleet_hwm_kb": pf.get("hwm_kb"), "fleet_fds": pf.get("fds"), "fleet_threads": pf.get("threads"),
                    "aegisd_rss_kb": pa.get("rss_kb"), "mem_avail_kb": cur["mem_avail_kb"], "load1": cur["load1"],
                    "root_used_kb": cur["root_used_kb"], "root_avail_kb": cur["root_avail_kb"],
                    "aegis_du_kb": cur["aegis_du_kb"], "journal_du_mb": cur["journal_du_mb"],
                    "journal_lines": len(cur["journal"]), "journal_all_lines": cur["journal_all"],
                    "kernel_err_lines": len(cur["kernel"]),
                    "state_age_s": None if cur["state_mtime"] is None else cur["gw_now"] - cur["state_mtime"]})
        for name in self.cfg["endpoints"]:
            tr, c = self.st["eps"][name], cur["creds"].get(name) or {}
            recs = [r for r in cur["journal"] if r["kind"] == "verdict" and r.get("ep") == name]
            st = next((r["status"] for r in reversed(recs) if r.get("status")), None) or c.get("status") or {}
            row.update({name + ":verdicts": len(recs), name + ":quarantined": sum(not r["admitted"] for r in recs),
                        name + ":session": c.get("session"), name + ":hb": c.get("hb"), name + ":ttl": st.get("ttl"),
                        name + ":uptime_s": st.get("uptime_s"), name + ":requests": st.get("requests"),
                        name + ":stack_used": st.get("stack_used"), name + ":renewals": tr["renewals"]})
        return row

    def columns(self):
        return CSV_GW + ["%s:%s" % (n, c) for n in self.cfg["endpoints"] for c in CSV_EP]

    def append_row(self, row):
        p = os.path.join(self.out, "samples.csv")
        new = not os.path.exists(p)
        with open(p, "a", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=self.columns(), extrasaction="ignore")
            if new:
                w.writeheader()
            w.writerow(row)
        self.rows.append({k: (to_float(v) if isinstance(v, (int, float)) else v) for k, v in row.items()})

    def raw(self, t, text):
        d = os.path.join(self.out, "raw")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, time.strftime("%Y%m%d-%H%M%S", time.localtime(t)) + ".txt"), "w") as fh:
            fh.write(text or "")

    def console(self):
        d = self.cfg.get("console_dir")
        if not d or not os.path.isdir(d):
            return []
        out = []
        for fn in sorted(os.listdir(d)):
            if not re.fullmatch(r"console-\d{8}-\d+\.log", fn):
                continue
            p = os.path.join(d, fn)
            off = self.st["console"].get(fn)
            size = os.path.getsize(p)
            if off is None:
                off = size if self.st["samples"] <= 1 else 0     # older days: only what is new since the start
            if size > off:
                with open(p, "rb") as fh:
                    fh.seek(off)
                    out += console_findings(fh.read(size - off).decode(errors="replace"))
            self.st["console"][fn] = size
        return out

    # -- the regression --

    def timeout_s(self, stage):
        key = "expiry_timeout_min" if stage.startswith("expiry") else "regression_timeout_min"
        return int(self.cfg.get(key, DEFAULT_TIMEOUT_MIN[key]) * 60)

    def regression_step(self):
        t = self.clock.now()
        run = self.st["running"]
        limit = self.timeout_s(run["stage"]) if run else None
        if run and run.get("orphan"):
            if self.reg.alive(run["pgid"]):
                if t - run["t"] <= limit:
                    return
                self.reg.kill_group(run["pgid"])
            else:
                self.event(t, "INFO", "regression", "%s from before the restart ended; it runs again" % run["stage"])
                self.st["running"] = None
                self.save()
                return
        if run:
            rc = None if run.get("orphan") else self.reg.poll()
            if rc is None and t - run["t"] <= limit:
                return
            stage = run["stage"]
            if rc is None:
                # hung (an SSH call that never returns, a stage that never ends): its process group is stopped
                # (SIGTERM: the restart trap starts aegis-fleet again; SIGKILL after the grace) and it fails
                if not run.get("orphan"):
                    self.reg.stop()
                rc = "timeout"
                self.event(t, "WARN", "regression", "%s still running after %d min: stopped" % (stage, limit // 60))
            self.st["done"][stage] = {"rc": rc, "start": iso(run["t"]), "end": iso(t), "min": round((t - run["t"]) / 60, 1)}
            for w in self.st["planned"]:
                if w[3] == "regression " + stage:
                    w[1] = t + 300          # the fleet's first cycles after its restart
            self.st["running"] = None
            if rc == 0:
                self.event(t, "INFO", "regression", "%s passed (%.1f min)" % (stage, (t - run["t"]) / 60))
            else:
                self.apply([finding("FAIL", "regression", "regression:%s" % stage, "regression %s failed (rc %s, see "
                                    "regression-%s.log)" % (stage, rc, stage), always=True, once=True)], t)
            self.save()
            return
        for stage, when in self.st["schedule"]:
            if stage not in self.st["done"] and t >= when:
                pid = self.reg.start(stage)
                self.st["running"] = {"stage": stage, "t": t, "pid": pid, "pgid": pid}
                self.st["planned"].append([t, t + self.timeout_s(stage) + 300, "regression", "regression " + stage])
                self.event(t, "INFO", "regression", "%s started (pid %s)" % (stage, pid))
                self.save()
                return

    def loop(self, stop=lambda: False):
        cfg = self.cfg
        while not self.st["finished"] and not stop():
            t = self.clock.now()
            if t >= self.st["next_sample"]:
                self.sample()
                self.st["last_pc"] = t
                self.st["next_sample"] = t + cfg["interval_min"] * 60
                self.save()
            if t >= self.st["t_end"] and not self.st["running"]:
                if cfg["regression"] and "end" not in self.st["done"]:
                    self.st["schedule"].append(["end", t])
                    self.regression_step()
                    continue
                self.sample()
                self.st["finished"] = True
                self.save()
                break
            self.regression_step()
            now = self.clock.now()
            wait = self.st["next_sample"] - now
            if self.st["running"]:
                wait = min(wait, 30)
            if now < self.st["t_end"]:
                wait = min(wait, self.st["t_end"] - now + 1)
            self.clock.sleep(max(1.0, wait))
        if self.st["finished"]:
            return write_report(self.out)
        return None


def read_csv(p):
    if not os.path.exists(p):
        return []
    rows = []
    with open(p, newline="") as fh:
        for r in csv.DictReader(fh):
            rows.append({k: (to_float(v) if to_float(v) is not None else (v or None)) for k, v in r.items()})
    return rows


def write_report(out):
    """report.md from state.json and samples.csv. Returns True if the soak passed."""
    with open(os.path.join(out, "state.json")) as fh:
        st = json.load(fh)
    cfg, rows = st["cfg"], read_csv(os.path.join(out, "samples.csv"))
    _, table = trend_findings(rows, cfg["bounds"], final=True)
    trend_fail = [r for r in table if r["judged"] and not r["ok"]]
    complete = st.get("finished") and (not cfg["regression"] or all(
        s in st["done"] for s in ("start", "middle", "end")))
    passed = not st["failures"] and complete
    ok_rows = [r for r in rows if r.get("ok") == 1]
    L = []
    L.append("# Soak report\n")
    L.append("**Result: %s**\n" % ("PASS" if passed else "FAIL" if st["failures"] else "INCOMPLETE"))
    L.append("| | |\n|---|---|")
    L.append("| started | %s |" % iso(st["t0"]))
    L.append("| planned end | %s (%g h) |" % (iso(st["t_end"]), cfg["hours"]))
    L.append("| finished | %s |" % ("yes" if st.get("finished") else "no"))
    L.append("| gateway | %s |" % cfg["gateway"])
    L.append("| endpoints | %s |" % ", ".join(cfg["endpoints"]))
    L.append("| absent / quarantined by design (ignored) | %s |" % ", ".join(
        "%s (%d verdict lines)" % (k, v) for k, v in st["absent"].items()))
    L.append("| credential lifetime expected | %d s |" % cfg["cred_lifetime"])
    L.append("| samples | %d (%d answered), every %g min |" % (st["samples"], len(ok_rows), cfg["interval_min"]))
    L.append("| longest time without an SSH answer | %d s |" % st["max_gap_s"])
    if ok_rows:
        offs = [r["offset_s"] for r in ok_rows if r.get("offset_s") is not None]
        if offs:
            L.append("| gateway clock minus PC | %+.0f s first, %+.0f s last |" % (offs[0], offs[-1]))
    L.append("")
    L.append("## Failures\n")
    if st["failures"]:
        L.append("| item | first | count | what |\n|---|---|---|---|")
        for k, b in sorted(st["failures"].items(), key=lambda x: x[1]["first"]):
            L.append("| %s | %s | %d | %s |" % (b["item"], b["first"], b["count"], b["msg"].replace("|", "/")))
    else:
        L.append("None.")
    if not complete:
        L.append("\nThe run is not complete (finished: %s; regressions done: %s)." % (
            bool(st.get("finished")), ", ".join(sorted(st["done"])) or "none"))
    L.append("\n## Regression runs\n")
    L.append("| stage | result | start | minutes |\n|---|---|---|---|")
    for stage, d in st["done"].items():
        L.append("| %s | %s | %s | %s |" % (stage, "PASS" if d["rc"] == 0 else "FAIL rc %s" % d["rc"], d["start"],
                                           d["min"]))
    L.append("\n## Endpoints\n")
    L.append("| endpoint | verdict lines | quarantined | renewals | last heartbeat | clock rate (s/s) | resets | "
             "secure stack max | lifetime seen |\n|---|---|---|---|---|---|---|---|---|")
    for n in cfg["endpoints"]:
        tr = st["eps"][n]
        rate = "%.4f over %d s" % (tr["rate_dttl"] / tr["rate_dt"], tr["rate_dt"]) if tr["rate_dt"] else "-"
        stack = "%s/%s (first %s)" % (tr["stack_used_max"], tr["stack_size"], tr["stack_first"]) \
            if tr["stack_used_max"] is not None else "-"
        L.append("| %s | %d | %d | %d | %s | %s | %d | %s | %s |" % (
            n, tr["verdicts"], tr["quarantined"], tr["renewals"], tr["hb"], rate, tr["resets"], stack,
            tr["lifetime"]))
    L.append("\n## Gateway trends (runs of one fleet process of an hour or more; projected over 14 days)\n")
    L.append("| metric | first | last | min | max | per hour | 14 days | bound | judged | ok |\n"
             "|---|---|---|---|---|---|---|---|---|---|")
    for r in table:
        L.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s (%s h) | %s |" % (
            r["metric"], r["first"], r["last"], r["min"], r["max"], r["slope_per_h"], r["projected_14d"],
            r["bound_14d"], "yes" if r["judged"] else "no", r["span_h"], "yes" if r["ok"] else "**no**"))
    if trend_fail and not any(k.startswith("trend:") for k in st["failures"]):
        L.append("\n(The final trend check above fails although no live trend failure was logged.)")
        passed = False
        L[1] = "**Result: FAIL**\n"
    jl = [r.get("journal_du_mb") for r in ok_rows if r.get("journal_du_mb") is not None]
    if jl:
        L.append("\nJournal on disk: %.1f MB first, %.1f MB last (journald keeps 50 MB)." % (jl[0], jl[-1]))
    L.append("\n## Warnings and expected events\n")
    for bucket in ("warnings", "infos"):
        for k, b in sorted(st[bucket].items(), key=lambda x: x[1]["first"]):
            L.append("- %s %s x%d (first %s): %s" % (b["level"], b["item"], b["count"], b["first"], b["msg"]))
    lifetimes = {st["eps"][n]["lifetime"] for n in cfg["endpoints"]} - {None}
    if cfg["cred_lifetime"] != 3600 or lifetimes - {3600}:
        L.append("\n**Restore the normal credential lifetime** (docs/soak-and-watchdogs.md, \"Restore\"): seen %s s."
                 % ", ".join(str(x) for x in sorted(lifetimes)))
    L.append("\nFiles: samples.csv, events.log, state.json, raw/ (gateway answers of failing samples), "
             "regression-*.log.")
    with open(os.path.join(out, "report.md"), "w") as fh:
        fh.write("\n".join(L) + "\n")
    return passed


# ---- the canned gateway (selftest, --dry-run, tests) --------------------------------------------------------------

class FakeClock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += max(0.0, s)


class FakeGateway:
    """A gateway, its fleet loop and the endpoints, simulated cycle by cycle. faults:
    hb_stop {ep: t}, quarantine {ep: t}, reboot_at t, ssh_down (t0, t1), rss_leak_kb_h, ep_reset {ep: t},
    clock_rate {ep: rate}, garble_at t (one garbled answer)."""

    def __init__(self, clock, endpoints, absent=("stm32h573-dk",), lifetime=3600, faults=None):
        self.clock, self.lifetime, self.f = clock, lifetime, faults or {}
        self.offset = 3.0
        self.t_boot = clock.now() - 86400
        self.boot_id = "0f" * 16
        self.pid, self.nrestarts = 4242, 0
        self.rss0, self.t_pid = 41000, clock.now()
        self.last_cycle = clock.now() - 60
        self.lines = []
        self.absent = list(absent)
        self.eps = {}
        for i, e in enumerate(endpoints):
            self.eps[e] = {"boot": clock.now() - 5000 - i * 100, "requests": 100 + i, "sid": None, "issued": 0,
                           "expires": 0, "hb": 0, "start": 0, "stack": 19088, "status": ""}
        self.state_mtime = clock.now()
        self.du = 2048.0

    def gwt(self, t):
        return t + self.offset

    def restart_fleet(self):
        """What the regression's expiry stage does: the service stops and starts; sessions end and are issued."""
        self.pid += 101
        self.t_pid = self.clock.now()
        for e in self.eps.values():
            e["sid"] = None

    def _issue(self, name, e, t):
        e["sid"] = "%012x" % (abs(hash((name, t))) & 0xFFFFFFFFFFFF)
        e["issued"], e["expires"], e["hb"], e["start"] = int(self.gwt(t)), int(self.gwt(t)) + self.lifetime, 0, t

    def _cycles(self, until):
        while self.last_cycle + CYCLE_S <= until:
            t = self.last_cycle = self.last_cycle + CYCLE_S
            if self.f.get("reboot_at") and t >= self.f["reboot_at"] and self.t_boot < self.f["reboot_at"]:
                self.t_boot, self.boot_id, self.pid = t, "1e" * 16, 999
                self.t_pid = t
                for e in self.eps.values():
                    e["sid"] = None
            gt = self.gwt(t)
            hms = time.strftime("%H:%M:%S", time.gmtime(gt))
            for name in self.absent:
                self.lines.append("%d gw python3[%d]: %s %s QUARANTINED no attestation: [Errno 113] No route to host "
                                  "[credential: revoked]" % (gt, self.pid, hms, name))
            for name, e in self.eps.items():
                if t >= self.f.get("ep_reset", {}).get(name, 1e18):
                    e["boot"], e["requests"], e["sid"] = t, 0, None
                    self.f["ep_reset"][name] = 1e18
                if t >= self.f.get("quarantine", {}).get(name, 1e18):
                    self.f["quarantine"][name] = 1e18
                    e["sid"] = None
                    self.lines.append("%d gw python3[%d]: %s %s QUARANTINED (trustzone trust) component APP not "
                                      "allowed (measurement 06da0d22095c...) [credential: revoked]" % (
                                          gt, self.pid, hms, name))
                    continue
                e["requests"] += 3
                if e["sid"] is None or e["expires"] - gt < RENEWAL_WINDOW_S:
                    self._issue(name, e, t)
                    cred = "issued session %s... bound to quote abcdef012345... (transcript v2)" % e["sid"]
                elif t >= self.f.get("hb_stop", {}).get(name, 1e18):
                    cred = "valid, heartbeat %d (requests=%d;fw=x)" % (e["hb"], e["requests"])
                else:
                    e["hb"] += 1
                    rate = self.f.get("clock_rate", {}).get(name, 1.0)
                    ttl = int(self.lifetime + self.lifetime // 16 - (t - e["start"]) * rate)
                    e["status"] = "uptime_s=%d;link=1;fw=0.6.0;sstack=%d/26624;requests=%d;ttl=%d" % (
                        t - e["boot"], e["stack"], e["requests"], ttl)
                    cred = "valid, heartbeat %d (%s)" % (e["hb"], e["status"])
                self.lines.append("%d gw python3[%d]: %s %s ADMITTED (trustzone trust) [credential: %s]" % (
                    gt, self.pid, hms, name, cred))
            self.state_mtime = gt
            self.du += 0.05
        self.lines = self.lines[-5000:]

    def ask(self, script):
        now = self.clock.now()
        down = self.f.get("ssh_down")
        if down and down[0] <= now <= down[1]:
            return None, "ssh: connect to host gw port 22: No route to host"
        self._cycles(now)
        if check_commands(COMMANDS):
            raise AssertionError("unsafe commands")
        m = re.search(r"--since @(\d+)", script)
        since = int(m.group(1)) if m else 0
        gt = int(self.gwt(now))
        rss = int(self.rss0 + self.f.get("rss_leak_kb_h", 0) * (now - self.t_pid) / 3600)
        o = ["@@ now", str(gt), "yes", "@@ boot", "%.2f 1000.00" % (now - self.t_boot),
             self.boot_id[:8] + "-" + self.boot_id[8:12] + "-" + self.boot_id[12:16] + "-" + self.boot_id[16:20] + "-"
             + self.boot_id[20:32],
             "@@ units", "unit aegis-fleet ActiveState=active MainPID=%d NRestarts=%d " % (self.pid, self.nrestarts),
             "unit aegisd ActiveState=active MainPID=311 NRestarts=0 ",
             "@@ procs", "proc aegis-fleet %d VmRSS: %d kB VmHWM: %d kB Threads: 1 fds 9" % (self.pid, rss, rss + 500),
             "proc aegisd 311 VmRSS: 20000 kB VmHWM: 20100 kB Threads: 2 fds 7",
             "@@ mem", "MemTotal:        1015808 kB", "MemAvailable:     700000 kB", "0.31 0.25 0.20 1/97 4242",
             "@@ disk", "/dev/mmcblk0p3 7000000 2500000 4200000 38% /", "%d\t/var/lib/aegis" % self.du,
             "24000\t/var/lib/journal", "Archived and active journals take up 23.4M in the file system.",
             "@@ state", "%d 2048" % self.state_mtime, "@@ creds"]
        for name, e in self.eps.items():
            if e["sid"]:
                o.append("cred %s %s %d %d %d %s" % (name, e["sid"], e["issued"], e["expires"], e["hb"],
                                                     json.dumps(e["status"])))
        o.append("@@ journal")
        o += [ln for ln in self.lines if int(ln.split()[0]) >= since]
        o += ["@@ journal_all", str(len(self.lines)), "@@ kernel"]
        if since <= int(self.gwt(self.t_boot)) + 5 <= gt and self.boot_id != "0f" * 16:
            o.append("%d gw kernel: mpfs_rtc: timed out uploading time to rtc" % (self.gwt(self.t_boot) + 5))
        o.append("@@ end")
        text = "\n".join(o) + "\n"
        g = self.f.get("garble_at")
        if g and g <= now:
            self.f["garble_at"] = None
            return text[: len(text) // 3] + "\x00\xff garbage", None
        return text, None


class FakeRegression:
    def __init__(self, clock, gw, fail=(), hang=()):
        self.clock, self.gw, self.fail, self.hang = clock, gw, set(fail), set(hang)
        self.until, self.stage, self.runs, self.killed = None, None, [], []
        self.groups = {}               # pgid -> the time it ends (a group left over from a stopped runner)

    def start(self, stage):
        self.stage, self.until = stage, self.clock.now() + (180 if stage.startswith("expiry") else 900)
        if stage in self.hang:
            self.until = float("inf")
        self.runs.append(stage)
        self.gw.restart_fleet()
        return 1000 + len(self.runs)

    def poll(self):
        if self.until is None or self.clock.now() < self.until:
            return None
        self.until = None
        return 1 if self.stage in self.fail else 0

    def alive(self, pgid):
        return self.clock.now() < self.groups.get(pgid, 0)

    def kill_group(self, pgid, grace_s=None):
        self.killed.append(pgid)
        self.groups.pop(pgid, None)
        return True

    def stop(self):
        if self.until is not None:
            self.killed.append(1000 + len(self.runs))
            self.until = None


def make_cfg(a=None, **kw):
    cfg = {"gateway": "192.0.2.10", "hours": 24.0, "interval_min": 5.0, "endpoints": ENDPOINTS.split(","),
           "absent": ABSENT.split(","), "cred_lifetime": 3600, "expiry_every_h": 0.0, "regression": True,
           "console_dir": None, "bounds": dict(BOUNDS)}
    cfg.update(DEFAULT_TIMEOUT_MIN)
    if a is not None:
        cfg.update({"gateway": a.gateway, "hours": a.hours, "interval_min": a.interval_min,
                    "endpoints": [e for e in a.endpoints.split(",") if e],
                    "absent": [e for e in a.absent.split(",") if e], "cred_lifetime": a.cred_lifetime,
                    "expiry_every_h": a.expiry_every_h, "regression": not a.no_regression,
                    "console_dir": a.console_dir, "regression_timeout_min": a.regression_timeout_min,
                    "expiry_timeout_min": a.expiry_timeout_min})
        for kv in a.bound or []:
            k, _, v = kv.partition("=")
            if k not in BOUNDS or to_float(v) is None:
                sys.exit("unknown bound or value: %s" % kv)
            cfg["bounds"][k] = to_float(v)
    cfg.update(kw)
    return cfg


def simulate(out, hours=24.0, faults=None, lifetime=3600, fail_stages=(), expiry_every_h=0.0, interval_min=5.0):
    """A whole soak on the canned gateway. Returns (passed, Soak)."""
    clock = FakeClock()
    cfg = make_cfg(hours=hours, cred_lifetime=lifetime, expiry_every_h=expiry_every_h, interval_min=interval_min,
                   absent=["stm32h573-dk"])
    gw = FakeGateway(clock, cfg["endpoints"], lifetime=lifetime, faults=faults)
    s = Soak(out, cfg, gw, clock, FakeRegression(clock, gw, fail_stages))
    return s.loop(), s


def selftest():
    cases = [
        ("healthy day, 1 h credentials", {}, 3600, True, None),
        ("healthy day, 10 min credentials, expiry rounds every 4 h", {}, 600, True, None),
        ("heartbeat counter stops", {"hb_stop": {"frdm-rw612": 1_800_000_000 + 5 * 3600}}, 3600, False, "hbstop"),
        ("gateway reboots", {"reboot_at": 1_800_000_000 + 7 * 3600}, 3600, False, "reboot"),
        ("gateway silent 20 min", {"ssh_down": (1_800_000_000 + 3 * 3600, 1_800_000_000 + 3 * 3600 + 1200)}, 3600,
         False, "ssh:hang"),
        ("fleet memory leak 300 kB/h", {"rss_leak_kb_h": 300}, 3600, False, "trend:fleet_rss_kb"),
        ("endpoint quarantined", {"quarantine": {"zynqmp-te0808": 1_800_000_000 + 9 * 3600}}, 3600, False,
         "quarantined"),
        ("endpoint resets", {"ep_reset": {"stm32h573-dk-2": 1_800_000_000 + 2 * 3600}}, 3600, False, "reset"),
        ("endpoint clock 9 % fast", {"clock_rate": {"frdm-rw612": 1.09}}, 3600, False, "rate"),
        ("one garbled answer", {"garble_at": 1_800_000_000 + 4 * 3600}, 3600, True, None),
    ]
    bad = 0
    with tempfile.TemporaryDirectory() as d:
        for i, (what, faults, life, want, key) in enumerate(cases):
            out = os.path.join(d, str(i))
            os.makedirs(out)
            passed, s = simulate(out, faults=faults, lifetime=life, expiry_every_h=4.0 if life == 600 else 0.0)
            keys = " ".join(s.st["failures"])
            ok = passed is want and (key is None or key in keys)
            bad += not ok
            print("%-4s %-58s %s%s" % ("ok" if ok else "BAD", what, "PASS" if passed else "FAIL",
                                       "" if passed else " (" + ", ".join(sorted(s.st["failures"]))[:120] + ")"))
    print("selftest: %s" % ("all cases as expected" if not bad else "%d case(s) wrong" % bad))
    return 0 if not bad else 1


# ---- command line ---------------------------------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description="Soak the gateway and the live endpoints (docs/soak-and-watchdogs.md).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--gateway", default=os.environ.get("AEGIS_GATEWAY") or os.environ.get("GATEWAY"))
    r.add_argument("--hours", type=float, default=24.0)
    r.add_argument("--interval-min", type=float, default=5.0)
    r.add_argument("--endpoints", default=ENDPOINTS)
    r.add_argument("--absent", default=ABSENT, help="endpoints whose quarantine is expected (not connected, or by "
                                                    "design)")
    r.add_argument("--cred-lifetime", type=int, default=3600,
                   help="the lifetime the gateway was started with (fleet.py --credential-lifetime)")
    r.add_argument("--expiry-every-h", type=float, default=0.0, help="extra endpoint-expiry rounds (0: none)")
    r.add_argument("--stm32", default=os.environ.get("STM32_2") or os.environ.get("STM32"),
                   help="the STM32 the regression's device stages use (default $STM32_2, else $STM32)")
    r.add_argument("--regression-cmd", default="tools/regression.sh --board --with-expiry")
    r.add_argument("--expiry-cmd", default="tools/regression.sh --expiry-only")
    r.add_argument("--regression-timeout-min", type=float, default=DEFAULT_TIMEOUT_MIN["regression_timeout_min"],
                   help="a full regression still running after this is stopped and fails")
    r.add_argument("--expiry-timeout-min", type=float, default=DEFAULT_TIMEOUT_MIN["expiry_timeout_min"],
                   help="the same for an extra expiry round")
    r.add_argument("--no-regression", action="store_true")
    r.add_argument("--console-dir", help="tools/console_logger.py's directory: panics there fail the soak")
    r.add_argument("--commands", help="JSON {section: template} replacing or adding sampling commands")
    r.add_argument("--bound", action="append", help="NAME=VALUE, to change one of the failure bounds")
    r.add_argument("--out")
    r.add_argument("--resume", help="a run directory to continue")
    r.add_argument("--dry-run", action="store_true")
    p = sub.add_parser("plan")
    p.add_argument("--out", required=True)
    p.add_argument("--minutes", type=float, required=True)
    p.add_argument("--item", default="*")
    p.add_argument("--reason", required=True)
    p.add_argument("--start-in-min", type=float, default=0.0)
    rp = sub.add_parser("report")
    rp.add_argument("dir")
    sub.add_parser("selftest")
    a = ap.parse_args(argv)
    if a.cmd == "selftest":
        return selftest()
    if a.cmd == "report":
        return 0 if write_report(a.dir) else 1
    if a.cmd == "plan":
        t0 = time.time() + a.start_in_min * 60
        if not (a.item == "*" or NAME.match(a.item)):
            ap.error("bad item")
        with open(os.path.join(a.out, "planned.txt"), "a") as fh:
            fh.write("%d %d %s %s\n" % (t0, t0 + a.minutes * 60, a.item, a.reason.replace("\n", " ")[:200]))
        print("planned %s for %g min from %s" % (a.item, a.minutes, iso(t0)))
        return 0
    cmds = dict(COMMANDS)
    if a.commands:
        with open(a.commands) as fh:
            cmds.update(json.load(fh))
    bad = check_commands(cmds)
    if bad:
        sys.exit("refused: " + "; ".join(bad))
    cfg = make_cfg(a)
    if cfg["regression"] and not a.stm32:
        sys.exit("no STM32 for the regression: --stm32 or STM32_2 / STM32 in the environment (bench.env)")
    # bench.env, which regression.sh reads, would set STM32 back to board 1: AEGIS_STM32_OVERRIDE wins over it
    env = {"GATEWAY": a.gateway or "", "AEGIS_STM32_OVERRIDE": a.stm32 or "",
           "EXPIRY_ENDPOINTS": " ".join(cfg["endpoints"]), "AEGIS_SOAK": "1"}
    if a.dry_run:
        print("# sampling script (ssh root@%s sh -s), every %g min for %g h\n" % (a.gateway, a.interval_min, a.hours))
        print(build_script(cmds, int(time.time()) - 600))
        print("# regression at start, middle, end: %s %s" % (" ".join("%s=%s" % kv for kv in env.items()),
                                                          a.regression_cmd if cfg["regression"] else "(off)"))
        if a.expiry_every_h:
            print("# extra expiry rounds every %g h: %s" % (a.expiry_every_h, a.expiry_cmd))
        clock = FakeClock()
        gw = FakeGateway(clock, cfg["endpoints"], lifetime=cfg["cred_lifetime"])
        clock.sleep(600)
        s = parse_answer(gw.ask(build_script(cmds, gw.gwt(clock.now()) - 600))[0])
        print("# one canned sample parsed: gateway %s, fleet %s, endpoints %s" % (
            "complete" if s["complete"] else "INCOMPLETE", s["units"].get("aegis-fleet"),
            {k: (v["session"], v["hb"]) for k, v in s["creds"].items()}))
        return 0
    if not a.gateway:
        ap.error("no gateway: --gateway, or AEGIS_GATEWAY / GATEWAY")
    out = a.resume or a.out or os.path.join(REPO, "logs", "soak", time.strftime("%Y%m%d-%H%M%S"))
    if a.resume and not os.path.exists(os.path.join(out, "state.json")):
        sys.exit("nothing to resume in " + out)
    os.makedirs(out, exist_ok=True)
    lock = open(os.path.join(out, ".lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        sys.exit("another soak is writing to " + out)
    reg = RegressionRunner(a.regression_cmd, a.expiry_cmd, env, out)
    soak = Soak(out, cfg, SSHGateway(a.gateway), RealClock(), reg, cmds)
    if a.resume:
        reg.env["EXPIRY_ENDPOINTS"] = " ".join(soak.cfg["endpoints"])
    stopping = []

    def on_signal(signum, _frame):
        stopping.append(signum)
        reg.stop()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGHUP, on_signal)
    print("soak in %s until %s (tools/soak.py run --resume %s to continue after a stop)" % (
        out, iso(soak.st["t_end"]), out), flush=True)
    try:
        passed = soak.loop(stop=lambda: bool(stopping))
    except KeyboardInterrupt:
        reg.stop()
        passed = None
    soak.save()
    if passed is None:
        print("stopped; resume with: tools/soak.py run --resume %s" % out)
        return 3
    print("%s: %s" % ("PASS" if passed else "FAIL", os.path.join(out, "report.md")))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())

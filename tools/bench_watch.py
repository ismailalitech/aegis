#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Notice when the gateway or an endpoint goes quiet. Every interval the PC asks the gateway over SSH (read-only:
date, systemctl is-active, journalctl) whether it answers, whether aegis-fleet is active, and whether each expected
endpoint has an ADMITTED line in the last --quiet minutes. The window is computed on the gateway's own clock, so a
wrong gateway or PC clock does not matter. An item goes DOWN after 2 failed checks in a row and OK again after one
good check; only these changes are appended to <out>/events.log. <out>/status.json is rewritten every cycle. While
the gateway or the fleet unit is down, the items below it are not checked (one line, not one per endpoint).
Also an endpoint whose heartbeat counter stands still over the window (admitted, but the same "heartbeat N" in every
line and no new session) is DOWN, and so is the item "journal" when aegis-fleet wrote nothing in the window. When an
item goes DOWN, a read-only snapshot of the gateway (journal tail, fleet-state.json, unit status) is saved in
<out>/evidence/, and --alert-cmd (if given) runs with the event line as its argument
(docs/soak-and-watchdogs.md).
  tools/bench_watch.py --gateway <addr> [--expect a,b,c] [--interval 120] [--quiet 10] [--out <dir>]
                       [--alert-cmd 'notify-send aegis']
  tools/bench_watch.py --gateway <addr> --once      # one check, print it, exit 0 only if all OK; writes nothing
  setsid nohup python3 <abs path>/bench_watch.py --gateway <addr> >/dev/null 2>&1 &    # detached
The gateway address can also come from AEGIS_GATEWAY. Default out dir ~/aegis-tools/bench-watch.
"""
import argparse
import datetime
import fcntl
import json
import os
import re
import subprocess
import sys
import time

EXPECT = "stm32h573-dk-2,frdm-rw612,zynqmp-te0808"    # the live endpoints of the soak (board 1 unplugged)
FAILS_FOR_DOWN = 2
# Short-unix journal line: "<epoch> <host> <ident>[pid]: 13:01:50 <name> ADMITTED ..."
ADMITTED = re.compile(r"^(\d+(?:\.\d+)?) \S+ [^:]+: \S+ (\S+) ADMITTED\b")
HB = re.compile(r"\[credential: valid, heartbeat (\d{1,12}) ")
ISSUED = re.compile(r"\[credential: issued session ")
SNAPSHOT = ("date; systemctl status aegis-fleet --no-pager -l 2>&1 | head -n 20; echo; cat /var/lib/aegis/fleet-state.json"
            " 2>&1 | head -c 20000; echo; journalctl -u aegis-fleet -n 200 -o short-unix --no-pager; echo; "
            "journalctl -k -n 50 -o short-unix --no-pager; uptime; free 2>/dev/null")


def now_iso():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def query_gateway(gateway, quiet_s):
    """One SSH call. Returns (reply, None) or (None, reason)."""
    remote = ("now=$(date +%%s); echo \"now $now\"; echo \"fleet $(systemctl is-active aegis-fleet)\"; "
              "journalctl -u aegis-fleet --since @$((now-%d)) -o short-unix --no-pager | "
              "awk '{n++} / ADMITTED/ {print} END {print \"lines \" n+0}'; "
              "echo end" % quiet_s)
    cmd = ["ssh", "-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=5",
           "-o", "ServerAliveCountMax=2", "root@" + gateway, remote]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
    except subprocess.TimeoutExpired:
        return None, "ssh timed out"
    lines = p.stdout.splitlines()
    if p.returncode == 255 or not lines or lines[-1] != "end" or not lines[0].startswith("now "):
        err = (p.stderr.strip().splitlines() or ["exit %d" % p.returncode])[-1]
        return None, err
    try:
        gw_now = int(lines[0].split()[1])
    except (IndexError, ValueError):
        return None, "garbled answer"
    return parse_reply(gw_now, lines[1:-1]), None


def parse_reply(gw_now, lines):
    """The lines between "now" and "end": the fleet state, the ADMITTED lines, the line count."""
    reply = {"gw_now": gw_now, "fleet": "unknown", "last": {}, "hb": {}, "issued": set(), "lines": None}
    for ln in lines:
        if ln.startswith("fleet "):
            reply["fleet"] = ln.split(None, 1)[1][:32] if " " in ln else "unknown"
            continue
        if ln.startswith("lines ") and ln[6:].strip().isdigit():
            reply["lines"] = int(ln[6:].strip())
            continue
        m = ADMITTED.match(ln[:4096])
        if m:
            name = m.group(2)
            reply["last"][name] = float(m.group(1))
            h = HB.search(ln)
            if h:
                reply["hb"].setdefault(name, []).append(int(h.group(1)))
            if ISSUED.search(ln):
                reply["issued"].add(name)
    return reply


def hb_stopped(reply, name):
    """True when every heartbeat line of the window for name shows the same counter (at least 3 lines) and no new
    session was issued in it."""
    hbs = reply["hb"].get(name, [])
    return len(hbs) >= 3 and name not in reply["issued"] and max(hbs) == min(hbs)


def check(gateway, expect, quiet_s):
    """Return {item: (ok, detail)}; None for items not checked because a parent is down."""
    reply, err = query_gateway(gateway, quiet_s)
    result = {"gateway": (False, err) if err else (True, "answers")}
    if err:
        result["fleet"] = None
        result["journal"] = None
        result.update({e: None for e in expect})
        return result, None
    fleet_ok = reply["fleet"] == "active"
    result["fleet"] = (fleet_ok, "aegis-fleet is " + reply["fleet"])
    if not fleet_ok:
        result["journal"] = None
    elif reply["lines"] is not None:
        result["journal"] = (reply["lines"] > 0, "%d aegis-fleet lines in %d min" % (reply["lines"], quiet_s // 60))
    for e in expect:
        if not fleet_ok:
            result[e] = None
        elif e in reply["last"] and hb_stopped(reply, e):
            result[e] = (False, "heartbeat counter stopped at %d" % reply["hb"][e][-1])
        elif e in reply["last"]:
            result[e] = (True, "admitted %d s ago" % (reply["gw_now"] - reply["last"][e]))
        else:
            result[e] = (False, "no ADMITTED line in %d min" % (quiet_s // 60))
    return result, reply["gw_now"]


def down_line(item, detail):
    if item == "gateway":
        return "DOWN gateway: no ssh answer for %d checks (%s)" % (FAILS_FOR_DOWN, detail)
    return "DOWN %s: %s for %d checks" % (item, detail, FAILS_FOR_DOWN)


def update(state, result):
    """Apply one check to the per-item state; return the event lines for items that changed."""
    events = []
    for item, r in result.items():
        s = state.setdefault(item, {"state": "OK", "fails": 0, "detail": "", "since": now_iso()})
        if r is None:
            s["detail"] = "not checked (parent down)"
            continue
        ok, detail = r
        s["detail"] = detail
        if ok:
            s["fails"] = 0
            if s["state"] == "DOWN":
                s["state"], s["since"] = "OK", now_iso()
                events.append("OK %s: back (%s)" % (item, detail))
        else:
            s["fails"] += 1
            if s["state"] == "OK" and s["fails"] >= FAILS_FOR_DOWN:
                s["state"], s["since"] = "DOWN", now_iso()
                events.append(down_line(item, detail))
    return events


def snapshot(gateway, out, item):
    """A read-only copy of what the gateway shows now, for the evidence of a DOWN event. Returns the file or None."""
    d = os.path.join(out, "evidence")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "%s-%s.txt" % (time.strftime("%Y%m%d-%H%M%S"), re.sub(r"[^A-Za-z0-9._-]", "_", item)))
    cmd = ["ssh", "-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "root@" + gateway, SNAPSHOT]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60, errors="replace")
        text = p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        text = "ssh timed out\n"
    with open(path, "w") as f:
        f.write(text)
    return path


def alert(cmd, line):
    """--alert-cmd: run with the event line as its one argument; never waits more than 30 s, never raises."""
    if not cmd:
        return
    try:
        subprocess.run(["sh", "-c", cmd + ' "$1"', "alert", line], timeout=30, capture_output=True)
    except (OSError, subprocess.TimeoutExpired):
        pass


def write_status(out, state, gw_now, started):
    pc_now = time.time()
    status = {"last_check": now_iso(), "started": started, "pid": os.getpid(),
              "gateway_clock_minus_pc_s": None if gw_now is None else round(gw_now - pc_now), "items": state}
    tmp = os.path.join(out, "status.json.tmp")
    with open(tmp, "w") as f:
        json.dump(status, f, indent=1)
        f.write("\n")
    os.replace(tmp, os.path.join(out, "status.json"))


def run_once(args, expect):
    result, _ = check(args.gateway, expect, args.quiet * 60)
    all_ok = True
    for item, r in result.items():
        if r is None:
            all_ok = False
            print("%-16s UNKNOWN  not checked (parent down)" % item)
        else:
            all_ok &= r[0]
            print("%-16s %-8s %s" % (item, "OK" if r[0] else "DOWN", r[1]))
    return 0 if all_ok else 1


def run_loop(args, expect):
    os.makedirs(args.out, exist_ok=True)
    lock = open(os.path.join(args.out, ".lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        sys.exit("another bench_watch is already writing to " + args.out)
    started, state = now_iso(), {}
    while True:
        t0 = time.monotonic()
        result, gw_now = check(args.gateway, expect, args.quiet * 60)
        events = update(state, result)
        if events:
            with open(os.path.join(args.out, "events.log"), "a") as f:
                for e in events:
                    f.write("%s %s\n" % (now_iso(), e))
            for e in events:
                if e.startswith("DOWN "):
                    item = e.split()[1].rstrip(":")
                    path = snapshot(args.gateway, args.out, item) if item != "gateway" else None
                    if path:
                        with open(os.path.join(args.out, "events.log"), "a") as f:
                            f.write("%s EVIDENCE %s: %s\n" % (now_iso(), item, path))
                alert(args.alert_cmd, e)
        write_status(args.out, state, gw_now, started)
        time.sleep(max(1.0, args.interval - (time.monotonic() - t0)))


def main():
    ap = argparse.ArgumentParser(description="Watch the gateway and the expected endpoints.")
    ap.add_argument("--gateway", default=os.environ.get("AEGIS_GATEWAY"), help="address (or env AEGIS_GATEWAY)")
    ap.add_argument("--expect", default=EXPECT, help="comma-separated endpoint names (default %(default)s)")
    ap.add_argument("--interval", type=int, default=120, help="seconds between checks")
    ap.add_argument("--quiet", type=int, default=10, help="minutes without ADMITTED before an endpoint fails")
    ap.add_argument("--out", default=os.path.expanduser("~/aegis-tools/bench-watch"))
    ap.add_argument("--once", action="store_true", help="one check, print, exit 0 if all OK else 1")
    ap.add_argument("--alert-cmd", help="shell command run with each DOWN/OK line as its argument, e.g. notify-send")
    args = ap.parse_args()
    if not args.gateway:
        ap.error("no gateway: give --gateway or set AEGIS_GATEWAY")
    expect = [e for e in args.expect.split(",") if e]
    sys.exit(run_once(args, expect) if args.once else run_loop(args, expect))


if __name__ == "__main__":
    main()

#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Evaluate Aegis without hardware: the container's entry point (container/README.md), and runnable on any PC with
# the repository's .venv and ~/aegis-tools as well.
#   container/evaluate.sh [all | quick | STAGE...]      default: all
#   container/evaluate.sh --list
# Stages, in this order:
#   release-hygiene     tools/check_release.py: SPDX lines on every source file, no secrets tracked
#   sdk-golden          tools/sdk_golden.py check: the Prover SDK's core answers byte for byte as recorded
#   sdk-api-reference   tools/gen_sdk_api_ref.py --check: docs/sdk-api-reference.md is the header's
#   simulated-device    sdk/examples/simulated-device/run.sh: a device on the SDK attested by the verifier (fleet.py)
#                       on this machine, with a session, a heartbeat, a quarantine, the evidence pack and the audit
#                       log checked by the standalone checkers (tools/verify_evidence.py, tools/verify_audit.py)
#   gateway-quote       the gateway's identity and quote service (aegisd.py serve --platform linux) and the PC
#                       verifier of the gateway (host/aegis_verify.py enroll, then quote): the quote is accepted
#   host-tests          the host test suite, tests/host (python -m unittest discover)
#   redteam-host        tests/redteam/fuzz_host.py 2000: malformed tokens and quotes against the verifier's parsers
# quick: every stage but host-tests and redteam-host (about a minute).
# Logs go to $AEGIS_EVAL_OUT (default: a new directory under ${TMPDIR:-/tmp}). Prints PASS or FAIL per stage and
# exits non-zero if any failed. Needs no network: everything it runs is local, on 127.0.0.1.
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO" || exit 2
ALL="release-hygiene sdk-golden sdk-api-reference simulated-device gateway-quote host-tests redteam-host"
QUICK="release-hygiene sdk-golden sdk-api-reference simulated-device gateway-quote"
usage() { sed -n '4,22p' "$0" | cut -c3-; }

case "${1:-all}" in
    --list) for s in $ALL; do echo "$s"; done; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    all) STAGES=$ALL ;;
    quick) STAGES=$QUICK ;;
    *) STAGES="$*"
       for s in $STAGES; do
           case " $ALL " in *" $s "*) ;; *) echo "unknown stage: $s (--list shows them)" >&2; exit 2 ;; esac
       done ;;
esac

if [ -n "${PYTHON:-}" ]; then PY=$PYTHON
elif [ -x .venv/bin/python ]; then PY=$REPO/.venv/bin/python
else PY=python3; fi
export PYTHON="$PY"
OUT=${AEGIS_EVAL_OUT:-$(mktemp -d "${TMPDIR:-/tmp}/aegis-eval.XXXXXX")}
if ! mkdir -p "$OUT" 2>/dev/null || ! [ -w "$OUT" ]; then
    echo "cannot write to $OUT (a mounted directory must be writable by uid $(id -u)); logs go to a temporary directory" >&2
    OUT=$(mktemp -d "${TMPDIR:-/tmp}/aegis-eval.XXXXXX")
fi

# what this evaluation runs on, for the record
{
    echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "commit: $(cat container/REVISION 2>/dev/null || git rev-parse HEAD 2>/dev/null || echo unknown)"
    # shellcheck disable=SC1091
    echo "os: $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") $(uname -m)"
    echo "python: $("$PY" --version 2>&1)"
    echo "python packages: $("$PY" -m pip freeze 2>/dev/null | tr '\n' ' ')"
    echo "gcc: $(gcc -dumpfullversion 2>/dev/null)  cmake: $(cmake --version 2>/dev/null | sed -n 1p)"
    tools=${AEGIS_TOOLS:-$HOME/aegis-tools}
    for r in mldsa-native mlkem-native liboqs-src; do
        [ -f "$tools/$r.commit" ] && echo "$r: $(cat "$tools/$r.commit")"
    done
} > "$OUT/environment.txt" 2>&1

gateway_quote() {
    d=$(mktemp -d "${TMPDIR:-/tmp}/aegis-gw.XXXXXX")
    port=$("$PY" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
    rc=1
    "$PY" gateway/aegisd/aegisd.py init --platform linux --key-store software --state "$d/state" || { rm -rf "$d"; return 1; }
    "$PY" gateway/aegisd/aegisd.py serve --platform linux --state "$d/state" --port "$port" &
    pid=$!
    i=0
    until "$PY" -c 'import socket,sys; socket.create_connection(("127.0.0.1", int(sys.argv[1])), 1).close()' "$port" \
            2>/dev/null; do
        i=$((i+1)); [ $i -lt 50 ] || break
        sleep 0.2
    done
    if "$PY" host/aegis_verify.py enroll 127.0.0.1 --port "$port" > "$d/enroll.json"; then
        cat "$d/enroll.json"
        "$PY" host/aegis_verify.py quote 127.0.0.1 --port "$port" | tee "$d/quote.json"
        grep -q '"accepted": true' "$d/quote.json" && rc=0
        # the enrolment record this run made (host/enrolled/<dsn>.json) is this run's only
        f=$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["enrolled"])' "$d/enroll.json" 2>/dev/null)
        [ -n "$f" ] && rm -f "$f"
    fi
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    rm -rf "$d"
    return $rc
}

run_stage() {
    case $1 in
        release-hygiene)   "$PY" tools/check_release.py ;;
        sdk-golden)        "$PY" tools/sdk_golden.py check ;;
        sdk-api-reference) "$PY" tools/gen_sdk_api_ref.py --check ;;
        simulated-device)  sdk/examples/simulated-device/run.sh ;;
        gateway-quote)     gateway_quote ;;
        host-tests)        "$PY" -m unittest discover -s tests/host ;;
        redteam-host)      "$PY" tests/redteam/fuzz_host.py 2000 ;;
    esac
}

pass=0; fail=0
echo "Aegis evaluation, logs in $OUT"
for s in $STAGES; do
    t0=$(date +%s)
    if run_stage "$s" > "$OUT/$s.log" 2>&1; then r=PASS; pass=$((pass+1)); else r=FAIL; fail=$((fail+1)); fi
    t=$(( $(date +%s) - t0 ))
    case $s in
        host-tests) detail=$(grep -E '^(Ran|OK|FAILED)' "$OUT/$s.log" | tr '\n' ' ') ;;
        sdk-golden) detail=$(grep -E 'differ' "$OUT/$s.log" | tr '\n' ' ') ;;
        release-hygiene) detail=$(tail -n 1 "$OUT/$s.log") ;;
        simulated-device) detail=$(grep -E '^ *(8|12) ' "$OUT/$s.log" | sed 's/  */ /g' | cut -c1-90 | tr '\n' ' ') ;;
        gateway-quote) detail=$(grep -q '"accepted": true' "$OUT/$s.log" && echo "gateway quote accepted") ;;
        redteam-host) detail=$(grep -E '"broken": \[\]' "$OUT/$s.log" >/dev/null && echo "nothing broken") ;;
        *) detail=$(tail -n 1 "$OUT/$s.log") ;;
    esac
    printf '%s %-18s %4ss  %s\n' "$r" "$s" "$t" "$detail"
    [ $r = PASS ] || echo "     see $OUT/$s.log"
done
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]

#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# The simulated device, end to end, on one PC and without any hardware: build the SDK and the device, make a
# verifier identity, enrol the device, admit it with a credential and a session bound to its quote, check a
# heartbeat, quarantine a changed image, and check the evidence and the audit log with the standalone checkers.
#   sdk/examples/simulated-device/run.sh [WORKDIR]      (a new or empty directory; default: a temporary one)
# Environment: PYTHON (default .venv/bin/python, else python3), MLDSA_NATIVE_DIR, MLKEM_NATIVE_DIR (mldsa-native and
# mlkem-native v2.0.0; default ~/aegis-tools/...), AEGIS_EAT_COSE=0 to run with the SDK's default evidence (the
# CBOR claims) instead of EAT in COSE_Sign1, KEEP=1 to keep WORKDIR.
# Prints one line per step and "RESULT: PASS" at the end; exits non-zero at the first failed step. Every command's
# output is kept in WORKDIR/log/.
set -eu
REPO=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$REPO"
if [ -n "${PYTHON:-}" ]; then PY=$PYTHON
elif [ -x .venv/bin/python ]; then PY=.venv/bin/python
else PY=python3; fi
EAT=${AEGIS_EAT_COSE:-1}
W=${1:-$(mktemp -d "${TMPDIR:-/tmp}/aegis-sim.XXXXXX")}
[ ! -e "$W" ] || [ -z "$(ls -A "$W")" ] || { echo "$W is not empty: give a new or empty directory" >&2; exit 2; }
mkdir -p "$W/log" "$W/keys"
W=$(cd "$W" && pwd)
DEV_PID=
cleanup() {
    if [ -n "$DEV_PID" ]; then kill "$DEV_PID" 2>/dev/null; wait "$DEV_PID" 2>/dev/null; fi
    [ "${KEEP:-0}" = 1 ] || rm -rf "$W"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
n=0
step() { n=$((n+1)); printf '%2d %-50s ' "$n" "$1"; }
ok() { echo "ok${1:+  ($1)}"; }
fail() { echo "FAIL: $1"; echo "logs: $W/log (kept)"; KEEP=1; exit 1; }
json() { "$PY" -c "import json,sys; d=json.load(open(sys.argv[1])); print($1)" "$2"; }   # json EXPR FILE

step "Python with ML-DSA-65 (cryptography)"
"$PY" -c "from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem" > "$W/log/python.txt" 2>&1 \
    || fail "$PY has no ML-DSA in cryptography (pip install 'cryptography>=47'); see $W/log/python.txt"
ok "$("$PY" -c 'import cryptography; print("cryptography", cryptography.__version__)')"

step "build the SDK and the device (AEGIS_EAT_COSE=$EAT)"
make -C sdk BUILD="$W/build" AEGIS_EAT_COSE="$EAT" lib examples > "$W/log/build.txt" 2>&1 \
    || fail "build, see $W/log/build.txt"
ok "$(wc -c < "$W/build/libaegis_sdk.a" | tr -d ' ') bytes"

step "verifier identity (aegisd.py init)"
"$PY" gateway/aegisd/aegisd.py init --platform linux --key-store software --state "$W/verifier" \
    > "$W/log/init.txt" 2>&1 || fail "aegisd init, see $W/log/init.txt"
PIN=$("$PY" tools/gen_gateway_pin.py --sha256-only --identity "$W/verifier/identity.json" 2>"$W/log/pin.txt") \
    || fail "gen_gateway_pin, see $W/log/pin.txt"
json 'd["body"]["pk"]' "$W/verifier/identity.json" > "$W/verifier.pub"
ok "key sha256 $(echo "$PIN" | cut -c1-16)..."

step "device secret and firmware image"
"$PY" -c "import os; print(os.urandom(32).hex())" > "$W/device-secret.hex"
"$PY" -c "import os,sys; open(sys.argv[1],'wb').write(os.urandom(65537))" "$W/firmware.bin"
GOOD=$("$PY" -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$W/firmware.bin")
ok "APP sha256 $(echo "$GOOD" | cut -c1-16)..."

start_device() {   # $1: the image; sets DEV_PID, PORT, FP
    rm -f "$W/device.out"
    "$W/build/aegis_sim_device" --verifier-pk "$W/verifier.pub" --secret "$W/device-secret.hex" \
        --image "APP=$1" --listen "${PORT:-0}" > "$W/device.out" 2>"$W/log/device.err" &
    DEV_PID=$!
    i=0
    until grep -q '^READY' "$W/device.out" 2>/dev/null; do
        i=$((i+1)); [ $i -lt 100 ] || fail "the device did not start, see $W/log/device.err"
        kill -0 "$DEV_PID" 2>/dev/null || fail "the device exited, see $W/log/device.err"
        sleep 0.1
    done
    PORT=$(awk '/^READY/ {print $2}' "$W/device.out")
    FP=$(awk '/^READY/ {print $3}' "$W/device.out")
}
stop_device() { kill "$DEV_PID" 2>/dev/null; wait "$DEV_PID" 2>/dev/null || true; DEV_PID=; }

step "start the simulated device"
start_device "$W/firmware.bin"
ok "127.0.0.1:$PORT, key sha256 $(echo "$FP" | cut -c1-16)..."

FORMAT=
[ "$EAT" = 1 ] && FORMAT='"evidence_format": "eat-cose-v1",'
cat > "$W/policy.json" <<EOF
{
 "timeout_s": 20,
 "attestation_results": true,
 "audit_log": true,
 "endpoints": [
  {
   "name": "sim-device-1",
   "kind": "aegis-linux",
   "profile": "aegis-linux-software-v1",
   "host": "127.0.0.1",
   "port": $PORT,
   "pq_pub_file": "keys/sim-device-1.mldsa65.pub",
   $FORMAT
   "transcript": "v2",
   "provision": true,
   "verifier_pin_sha256": "$PIN",
   "heartbeat_mac": "kmac256",
   "allowed": [{"type": "APP", "measurement_value": "$GOOD"}]
  }
 ]
}
EOF
fleet() {   # the verifier on this PC: fleet.py CMD POLICY ARGS..., with its state in WORKDIR/verifier
    c=$1; shift
    "$PY" gateway/aegisd/fleet.py "$c" "$W/policy.json" "$@" --platform linux --state-dir "$W/verifier"
}

step "enrol the device key (fleet.py enroll-pq)"
fleet enroll-pq > "$W/log/enroll.txt" 2>&1 || fail "enroll-pq, see $W/log/enroll.txt"
grep -q "sha256 $FP" "$W/log/enroll.txt" || fail "the enrolled key is not the device's, see $W/log/enroll.txt"
ok

step "policy check (fleet.py check)"
fleet check > "$W/log/check.txt" 2>&1 || fail "check, see $W/log/check.txt"
grep -q "credentials: issued by this verifier" "$W/log/check.txt" || fail "this verifier would not issue, see $W/log/check.txt"
ok

step "attest and provision (fleet.py once)"
fleet once > "$W/log/once.json" 2>"$W/log/once.err" || fail "once, see $W/log/once.err"
[ "$(json 'd[0]["admitted"]' "$W/log/once.json")" = True ] \
    || fail "not admitted: $(json 'd[0]["reasons"]' "$W/log/once.json")"
TRUST=$(json 'd[0].get("trust")' "$W/log/once.json")
CRED=$(json 'd[0].get("credential", "")' "$W/log/once.json")
case $CRED in "issued session "*" bound to quote "*) ;; *) fail "no session bound to the quote: $CRED" ;; esac
[ -f "$W/verifier/credentials/sim-device-1.session" ] || fail "no session key stored"
ok "ADMITTED, trust $TRUST, session bound to the quote, $(json 'd[0].get("evidence_format") or "aegis claims"' "$W/log/once.json")"

step "same session on both sides (fleet.py session)"
fleet session > "$W/log/session.json" 2>&1 || fail "session, see $W/log/session.json"
[ "$(json 'd["same_session"] and d["same_credential"]' "$W/log/session.json")" = True ] \
    || fail "the device holds another session, see $W/log/session.json"
ok

step "KMAC256 heartbeat with the session key"
"$PY" -c '
import json, sys
sys.path[:0] = ["common", "gateway/aegisd"]
import fleet
ep = json.load(open(sys.argv[1]))["endpoints"][0]
status, counter = fleet.heartbeat(ep, open(sys.argv[2], "rb").read())
print(status.decode(), "counter", counter)
' "$W/policy.json" "$W/verifier/credentials/sim-device-1.session" > "$W/log/heartbeat.txt" 2>&1 \
    || fail "heartbeat, see $W/log/heartbeat.txt"
ok "$(cut -c1-48 "$W/log/heartbeat.txt")"

if [ "$EAT" = 1 ]; then
    step "evidence pack: tools/verify_evidence.py"
    fleet export-evidence sim-device-1 --out "$W/pack" > "$W/log/export.txt" 2>&1 \
        || fail "export-evidence, see $W/log/export.txt"
    "$PY" -I tools/verify_evidence.py pack "$W/pack" > "$W/log/verify_evidence.json" 2>&1 \
        || fail "verify_evidence.py, see $W/log/verify_evidence.json"
    # the pack carries its keys for convenience; compare them with the keys this run trusts
    [ "$(json 'd["keys"]["device"]["sha256"]' "$W/log/verify_evidence.json")" = "$FP" ] || fail "the pack's device key is not the device's"
    [ "$(json 'd["keys"]["verifier"]["sha256"]' "$W/log/verify_evidence.json")" = "$PIN" ] || fail "the pack's verifier key is not ours"
    ok "EAT, result and keys verified"
fi

step "changed image: quarantined"
stop_device
"$PY" -c "import sys; f=open(sys.argv[1],'r+b'); b=f.read(1); f.seek(0); f.write(bytes([b[0]^1]))" "$W/firmware.bin"
start_device "$W/firmware.bin"
fleet once > "$W/log/once-changed.json" 2>"$W/log/once-changed.err" \
    || fail "once, see $W/log/once-changed.err"
[ "$(json 'd[0]["admitted"]' "$W/log/once-changed.json")" = False ] || fail "a changed image was admitted"
ok "$(json '"; ".join(d[0]["reasons"])[:60]' "$W/log/once-changed.json")"
[ -f "$W/verifier/credentials/sim-device-1.session" ] && fail "the quarantined device kept its session"
stop_device

step "audit log: tools/verify_audit.py"
fleet audit > "$W/log/audit.json" 2>&1 || fail "fleet.py audit, see $W/log/audit.json"
"$PY" -I tools/verify_audit.py log "$W/verifier/audit" --key "$W/verifier/identity.json" \
    > "$W/log/verify_audit.json" 2>&1 || fail "verify_audit.py, see $W/log/verify_audit.json"
ok "$(json '"%d entries in %d signed batches" % (d["logs"][-1]["entries"], d["logs"][-1]["last_batch"])' "$W/log/verify_audit.json")"

echo "RESULT: PASS (work directory $W$( [ "${KEEP:-0}" = 1 ] && echo ", kept" || echo ", removed"))"

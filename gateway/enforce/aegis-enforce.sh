#!/bin/sh
# Zero-trust enforcement hook for fleet.py (policy key "enforce_cmd").
#   aegis-enforce.sh init <endpoint_if>          load the ruleset (empty admitted set)
#   aegis-enforce.sh <endpoint> admit|quarantine add/remove the endpoint's address (from the policy)
#   aegis-enforce.sh off                          remove the Aegis table (undo)
# admit (re)starts the address's timeout in @admitted: AEGIS_ADMIT_TTL seconds (fleet.py sets it from its interval),
# else the set's default. Without a refresh by the next cycle the address drops out by itself.
set -eu
POLICY=${AEGIS_POLICY:-/root/aegis/gateway/policy/fleet.json}
HERE=$(cd "$(dirname "$0")" && pwd)
case "${1:-}" in
init)
    IF=${2:?endpoint interface}
    nft -D ENDPOINT_IF="\"$IF\"" -f "$HERE/aegis.nft"
    exit 0 ;;
off)
    nft delete table inet aegis 2>/dev/null || true
    exit 0 ;;
esac
EP=${1:?endpoint}; VERDICT=${2:?admit|quarantine}
# A failed change is reported (exit 3), not hidden: fleet.py logs "enforcement FAILED rc=3: <first stderr line>", and a
# quarantine that did not happen must not look like one that did. Removing an address that is not in the set is not
# a failure. The first stderr line is always this script's own message; the tool's output follows it.
fail() { echo "aegis-enforce: $1" >&2; [ -z "${2:-}" ] || printf '%s\n' "$2" >&2; exit 3; }
IP=$(python3 -c "import json,sys; p=json.load(open(sys.argv[2])); print(next(e.get('ip', e['host']) for e in p['endpoints'] if e['name']==sys.argv[1]))" "$EP" "$POLICY" 2>/dev/null) \
    || fail "$VERDICT $EP failed: no address for it in $POLICY"
case "$VERDICT" in
admit)      TTL=${AEGIS_ADMIT_TTL:-}
            case "$TTL" in ''|*[!0-9]*) TIMEOUT="" ;; *) TIMEOUT=" timeout ${TTL}s" ;; esac
            # One atomic batch: make sure the element exists, remove it, add it again with a fresh timeout (a plain
            # "add" of an existing element leaves its timeout running on older kernels). No packet sees it missing.
            OUT=$(printf 'add element inet aegis admitted { %s }\ndelete element inet aegis admitted { %s }\nadd element inet aegis admitted { %s%s }\n' \
                "$IP" "$IP" "$IP" "$TIMEOUT" | nft -f - 2>&1) || fail "admit $EP ($IP) failed" "$OUT" ;;
quarantine) if nft get element inet aegis admitted "{ $IP }" >/dev/null 2>&1; then
                OUT=$(nft delete element inet aegis admitted "{ $IP }" 2>&1) || fail "quarantine $EP ($IP) failed" "$OUT"
            elif ! nft list set inet aegis admitted >/dev/null 2>&1; then
                echo "aegis-enforce: no admitted set (ruleset not loaded); $EP ($IP) is not being enforced" >&2; exit 3
            fi ;;
*) echo "unknown verdict $VERDICT" >&2; exit 2 ;;
esac

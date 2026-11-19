#!/bin/sh
# Zero-trust enforcement hook for fleet.py (policy key "enforce_cmd").
#   aegis-enforce.sh init <endpoint_if>          load the ruleset (empty admitted set)
#   aegis-enforce.sh <endpoint> admit|quarantine add/remove the endpoint's address (from the policy)
#   aegis-enforce.sh off                          remove the Aegis table (undo)
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
IP=$(python3 -c "import json,sys; p=json.load(open('$POLICY')); print(next(e.get('ip', e['host']) for e in p['endpoints'] if e['name']==sys.argv[1]))" "$EP")
case "$VERDICT" in
# A failed change is reported (exit 3), not hidden: fleet.py records the code as enforce_rc, and a quarantine that
# did not happen must not look like one that did. Removing an address that is not in the set is not a failure.
admit)      nft add element inet aegis admitted "{ $IP }" || { echo "aegis-enforce: admit $EP ($IP) failed" >&2; exit 3; } ;;
quarantine) if nft get element inet aegis admitted "{ $IP }" >/dev/null 2>&1; then
                nft delete element inet aegis admitted "{ $IP }" || { echo "aegis-enforce: quarantine $EP ($IP) failed" >&2; exit 3; }
            elif ! nft list set inet aegis admitted >/dev/null 2>&1; then
                echo "aegis-enforce: no admitted set (ruleset not loaded); $EP ($IP) is not being enforced" >&2; exit 3
            fi ;;
*) echo "unknown verdict $VERDICT" >&2; exit 2 ;;
esac

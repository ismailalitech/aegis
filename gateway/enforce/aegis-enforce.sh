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
admit)      nft add element inet aegis admitted "{ $IP }" 2>/dev/null || true ;;
quarantine) nft delete element inet aegis admitted "{ $IP }" 2>/dev/null || true ;;
*) echo "unknown verdict $VERDICT" >&2; exit 2 ;;
esac

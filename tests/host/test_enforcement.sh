#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Test the zero-trust ruleset (gateway/enforce) without a second network port or a switch.
# Three network namespaces stand in for the gateway, an endpoint and the rest of the network; the real
# aegis.nft and aegis-enforce.sh run inside the gateway namespace. Needs root (ip netns); everything it
# creates is removed on exit and the host's own network and firewall are not touched.
#
#   sudo tests/host/test_enforcement.sh
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
GW=aegis-gw; EP=aegis-ep; LAN=aegis-lan
TMP=$(mktemp -d)
pass=0; fail=0

cleanup() {
    kill $(jobs -p) 2>/dev/null
    for n in $GW $EP $LAN; do ip netns del $n 2>/dev/null; done
    rm -rf "$TMP"
}
trap cleanup EXIT
[ "$(id -u)" = 0 ] || { echo "run as root: sudo $0" >&2; exit 2; }
for n in $GW $EP $LAN; do ip netns add $n; ip -n $n link set lo up; done

link() {  # link <nsA> <ifA> <addrA> <nsB> <ifB> <addrB>
    ip link add "$2" type veth peer name "$5"
    ip link set "$2" netns "$1"; ip link set "$5" netns "$4"
    ip -n "$1" addr add "$3" dev "$2"; ip -n "$4" addr add "$6" dev "$5"
    ip -n "$1" link set "$2" up;       ip -n "$4" link set "$5" up
}
link $GW ge0 10.77.1.1/24 $EP e0 10.77.1.2/24       # endpoint segment
link $GW gl0 10.77.2.1/24 $LAN l0 10.77.2.2/24      # the rest of the network
ip -n $EP  route add default via 10.77.1.1
ip -n $LAN route add default via 10.77.2.1
ip netns exec $GW sysctl -qw net.ipv4.ip_forward=1

# the policy file the hook reads to find the endpoint's address
echo '{"endpoints":[{"name":"ep1","host":"10.77.1.2"}]}' > "$TMP/policy.json"
export AEGIS_POLICY="$TMP/policy.json"
hook() { ip netns exec $GW "$ROOT/gateway/enforce/aegis-enforce.sh" "$@"; }

# two services: a normal one on the network, and the gateway's quote port
ip netns exec $LAN python3 -m http.server 8080 --bind 10.77.2.2 >/dev/null 2>&1 &
ip netns exec $GW  python3 -m http.server 7443 --bind 10.77.1.1 >/dev/null 2>&1 &
ip netns exec $EP  python3 -m http.server 7444 --bind 10.77.1.2 >/dev/null 2>&1 &   # the endpoint's prover port
sleep 1

tcp() { ip netns exec $EP python3 -c "import socket,sys; s=socket.socket(); s.settimeout(1.5); s.connect((sys.argv[1], int(sys.argv[2])))" "$1" "$2" 2>/dev/null; }
check() {  # check <expected: allow|block> <description> <command...>
    local want=$1 what=$2; shift 2
    if "$@"; then got=allow; else got=block; fi
    if [ "$got" = "$want" ]; then echo "PASS $what ($got)"; pass=$((pass+1)); else echo "FAIL $what (wanted $want, got $got)"; fail=$((fail+1)); fi
}
attest() { ip netns exec $GW python3 -c "import socket; s=socket.create_connection(('10.77.1.2', 7444), timeout=1.5); s.sendall(b'GET / HTTP/1.0\\r\\n\\r\\n'); assert s.recv(1)" 2>/dev/null; }
ping_lan() { ip netns exec $EP ping -c1 -W1 10.77.2.2 >/dev/null 2>&1; }

hook init ge0
echo "-- an endpoint that has not attested"
check block "ping the network"            ping_lan
check block "TCP to the network"          tcp 10.77.2.2 8080
check allow "TCP to the gateway quote port" tcp 10.77.1.1 7443
check allow "the gateway reaches the endpoint's prover (attestation)" attest

echo "-- admitted"
hook ep1 admit
check allow "ping the network"            ping_lan
check allow "TCP to the network"          tcp 10.77.2.2 8080

echo "-- a long-lived connection, then quarantine"
# the endpoint sends one byte every 0.2 s for 8 s; the server records when bytes arrive
cat > "$TMP/server.py" <<'EOF'
import socket, time, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("10.77.2.2", 9000)); s.listen(1)
c, _ = s.accept(); log = open(sys.argv[1], "w")
while True:
    d = c.recv(1)
    if not d: break
    log.write("%.2f\n" % time.time()); log.flush()
EOF
cat > "$TMP/client.py" <<'EOF'
import socket, time
s = socket.socket(); s.connect(("10.77.2.2", 9000))
for _ in range(40):
    try: s.send(b"x")
    except OSError: break
    time.sleep(0.2)
EOF
ip netns exec $LAN python3 "$TMP/server.py" "$TMP/arrivals" &
sleep 0.5
ip netns exec $EP python3 "$TMP/client.py" &
sleep 2
Q=$(date +%s.%N)
hook ep1 quarantine
sleep 4
LAST=$(tail -1 "$TMP/arrivals" 2>/dev/null)
AFTER=$(awk -v q="$Q" '$1 > q + 1.0' "$TMP/arrivals" | wc -l)
if [ "$AFTER" = 0 ]; then echo "PASS the open connection is cut within 1 s of quarantine"; pass=$((pass+1))
else echo "FAIL the open connection kept delivering $AFTER bytes more than 1 s after quarantine"; fail=$((fail+1)); fi

echo "-- quarantined again"
check block "new TCP to the network"      tcp 10.77.2.2 8080
check block "ping the network"            ping_lan
check allow "TCP to the gateway quote port" tcp 10.77.1.1 7443
check allow "the gateway still attests the quarantined endpoint" attest
check block "the endpoint reaches another gateway port (SSH)" tcp 10.77.1.1 22

echo "-- re-admitted"
hook ep1 admit
check allow "TCP to the network"          tcp 10.77.2.2 8080
expires() { ip netns exec $GW nft list set inet aegis admitted | grep -o 'expires [0-9hms]*' | head -1; }
EXP=$(expires)
if [ -n "$EXP" ]; then echo "PASS an admission without AEGIS_ADMIT_TTL takes the set's default timeout ($EXP)"; pass=$((pass+1))
else echo "FAIL the admitted element has no timeout"; fail=$((fail+1)); fi

echo "-- admissions expire unless refreshed"
AEGIS_ADMIT_TTL=3 hook ep1 admit
check allow "admitted for 3 s: TCP to the network" tcp 10.77.2.2 8080
sleep 2
AEGIS_ADMIT_TTL=3 hook ep1 admit             # the next cycle's attestation refreshes the timeout
sleep 2                                      # 4 s after the first admission, 2 s after the refresh
check allow "refreshed in time: still admitted after the first timeout" tcp 10.77.2.2 8080
sleep 2.5                                    # no refresh: the fleet loop has stopped
check block "not refreshed: the admission has expired" tcp 10.77.2.2 8080
check block "not refreshed: ping the network" ping_lan
check allow "expired: the gateway still attests the endpoint" attest
AEGIS_ADMIT_TTL=60 hook ep1 admit
check allow "re-attested: admitted again" tcp 10.77.2.2 8080

echo "passed $pass, failed $fail"
[ "$fail" = 0 ]

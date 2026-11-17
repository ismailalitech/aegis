#!/bin/bash
# Test gateway/second-port/bringup.sh and teardown.sh without the W5500 module: a veth pair stands in for it.
# Three network namespaces: the gateway, an endpoint that has no address until DHCP gives it one, and the rest of the
# network, which has no route back to the endpoint segment (so traffic can only come back through the masquerade).
# The real enforcement hook and ruleset are loaded on the new port. Needs root and busybox (udhcpd, udhcpc).
#
#   sudo tests/host/test_second_port.sh
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
GW=aegis2-gw; EP=aegis2-ep; LAN=aegis2-lan
TMP=$(mktemp -d)
pass=0; fail=0
cleanup() {
    [ -f "$TMP/state/udhcpd.pid" ] && kill "$(cat "$TMP/state/udhcpd.pid")" 2>/dev/null
    kill $(jobs -p) 2>/dev/null
    for n in $GW $EP $LAN; do ip netns del $n 2>/dev/null; done
    rm -rf "$TMP"
}
trap cleanup EXIT
[ "$(id -u)" = 0 ] || { echo "run as root: sudo $0" >&2; exit 2; }
command -v busybox >/dev/null || { echo "needs busybox" >&2; exit 2; }
mkdir -p "$TMP/bin"
printf '#!/bin/sh\nexec busybox udhcpd "$@"\n' > "$TMP/bin/udhcpd"; chmod +x "$TMP/bin/udhcpd"
command -v udhcpd >/dev/null || export PATH="$TMP/bin:$PATH"

for n in $GW $EP $LAN; do ip netns add $n; ip -n $n link set lo up; done
ip link add p1 type veth peer name e0; ip link set p1 netns $GW; ip link set e0 netns $EP
ip -n $EP link set e0 up
ip link add up0 type veth peer name l0; ip link set up0 netns $GW; ip link set l0 netns $LAN
ip -n $GW addr add 10.78.2.1/24 dev up0; ip -n $GW link set up0 up
ip -n $LAN addr add 10.78.2.2/24 dev l0; ip -n $LAN link set l0 up      # no route to 10.77.0.0/24

check() {  # check <allow|block> <description> <command...>
    local want=$1 what=$2; shift 2
    if "$@"; then got=allow; else got=block; fi
    if [ "$got" = "$want" ]; then echo "PASS $what ($got)"; pass=$((pass+1)); else echo "FAIL $what (wanted $want, got $got)"; fail=$((fail+1)); fi
}
gw() { ip netns exec $GW env STATE="$TMP/state" UPLINK=up0 LEASES="$TMP/static-leases" "$@"; }
# a fixed address for the endpoint, by MAC, as the STM32 would get
echo "static_lease $(cat /sys/class/net/e0/address 2>/dev/null || ip -n $EP link show e0 | awk '/ether/{print $2}') 10.77.0.20" > "$TMP/static-leases"

echo "-- bring-up on a port with no address"
gw "$ROOT/gateway/second-port/bringup.sh" --no-hw p1 >/dev/null
check allow "gateway address on the port" sh -c "ip -n $GW -4 addr show p1 | grep -q '10.77.0.1/24'"
check allow "forwarding on"               sh -c "[ \$(ip netns exec $GW cat /proc/sys/net/ipv4/ip_forward) = 1 ]"

cat > "$TMP/udhcpc.sh" <<'S'
#!/bin/sh
[ "$1" = bound ] || exit 0
ip addr add "$ip/${mask:-24}" dev "$interface"; ip route add default via "$router"; echo "$ip $router" > "$LEASE_OUT"
S
chmod +x "$TMP/udhcpc.sh"
ip netns exec $EP env LEASE_OUT="$TMP/lease" busybox udhcpc -i e0 -n -q -t 5 -T 1 -s "$TMP/udhcpc.sh" >/dev/null 2>&1
read -r EPIP ROUTER < "$TMP/lease" 2>/dev/null || EPIP=none
check allow "endpoint got its fixed address 10.77.0.20 (got ${EPIP:-none}), router 10.77.0.1" sh -c "[ '$EPIP' = 10.77.0.20 ] && [ '$ROUTER' = 10.77.0.1 ]"

# services: one on the network that records who called it, and the gateway quote port
ip netns exec $LAN python3 -c "
import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('10.78.2.2', 8080)); s.listen()
while True:
    c, a = s.accept(); open('$TMP/peer', 'w').write(a[0]); c.close()" &
ip netns exec $GW python3 -m http.server 7443 --bind 10.77.0.1 >/dev/null 2>&1 &
sleep 1
tcp() { ip netns exec $EP python3 -c "import socket,sys; s=socket.socket(); s.settimeout(1.5); s.connect((sys.argv[1], int(sys.argv[2])))" "$1" "$2" 2>/dev/null; }

echo '{"endpoints":[{"name":"ep1","host":"'"$EPIP"'"}]}' > "$TMP/policy.json"
hook() { ip netns exec $GW env AEGIS_POLICY="$TMP/policy.json" "$ROOT/gateway/enforce/aegis-enforce.sh" "$@" >/dev/null; }
hook init p1

echo "-- not attested"
check block "TCP to the network"            tcp 10.78.2.2 8080
check allow "TCP to the gateway quote port" tcp 10.77.0.1 7443
echo "-- admitted"
hook ep1 admit
rm -f "$TMP/peer"
check allow "TCP to the network"            tcp 10.78.2.2 8080
sleep 0.3
check allow "the network saw the gateway's address (masquerade)" sh -c "[ \"\$(cat $TMP/peer 2>/dev/null)\" = 10.78.2.1 ]"
echo "-- quarantined"
hook ep1 quarantine
check block "TCP to the network"            tcp 10.78.2.2 8080

echo "-- tear-down"
ip netns exec $GW nft delete table inet aegis 2>/dev/null
gw "$ROOT/gateway/second-port/teardown.sh" >/dev/null
check block "masquerade table removed"      sh -c "ip netns exec $GW nft list table ip aegis_nat >/dev/null 2>&1"
check allow "forwarding back to its old value (0)" sh -c "[ \$(ip netns exec $GW cat /proc/sys/net/ipv4/ip_forward) = 0 ]"
check block "port address removed"          sh -c "ip -n $GW -4 addr show p1 | grep -q 10.77.0.1"
check block "DHCP server stopped"           pgrep -f "udhcpd $TMP/state/udhcpd.conf"

echo "passed $pass, failed $fail"
[ "$fail" = 0 ]

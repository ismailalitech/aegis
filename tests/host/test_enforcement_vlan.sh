#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# The gateway on one Ethernet port with an 802.1Q switch (gateway/enforce/vlan-setup.sh), tested in network namespaces.
# A Linux bridge with VLAN filtering plays the switch: the endpoint ports are untagged members of VLAN 20 only, the
# gateway's port carries VLAN 1 (the LAN) untagged and VLAN 20 tagged, the LAN host is on VLAN 1. vlan-setup.sh and the
# real aegis.nft run unchanged in the gateway namespace. Besides the rules, it tries the ways around a VLAN: an
# endpoint that gives itself a LAN address, and one that tags its frames for the LAN's VLAN.
# Needs root; everything it creates is removed on exit, the host's own network and firewall are not touched.
#   sudo tests/host/test_enforcement_vlan.sh
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
GW=av-gw; SW=av-sw; EP=av-ep; EP2=av-ep2; LAN=av-lan
TMP=$(mktemp -d)
pass=0; fail=0
cleanup() {
    kill $(jobs -p) 2>/dev/null
    for n in $GW $SW $EP $EP2 $LAN; do ip netns del $n 2>/dev/null; done
    rm -rf "$TMP"
}
trap cleanup EXIT
[ "$(id -u)" = 0 ] || { echo "run as root: sudo $0" >&2; exit 2; }
for n in $GW $SW $EP $EP2 $LAN; do ip netns add $n; ip -n $n link set lo up; done

# the switch
ip -n $SW link add br0 type bridge vlan_filtering 1
ip -n $SW link set br0 up
nmac=0
port() {  # port <ns> <if in ns> <switch port>
    # every interface gets its own MAC: this host's systemd derives a veth's MAC from its name, and both endpoints'
    # interfaces are called e0, so without this they share one MAC and the switch cannot tell them apart
    nmac=$((nmac + 1))
    ip link add "$3" type veth peer name "$2"
    ip link set "$2" address "02:ae:00:00:00:$(printf %02x $nmac)"
    ip link set "$3" netns $SW; ip link set "$2" netns "$1"
    ip -n $SW link set "$3" master br0; ip -n $SW link set "$3" up; ip -n "$1" link set "$2" up
}
port $GW  end0 p-gw
port $EP  e0   p-ep
port $EP2 e0   p-ep2
port $LAN l0   p-lan
bridge -n $SW vlan add dev p-gw vid 20                         # trunk: VLAN 1 untagged (default), 20 tagged
for p in p-ep p-ep2; do                                         # endpoint ports: VLAN 20 only, untagged
    bridge -n $SW vlan del dev $p vid 1
    bridge -n $SW vlan add dev $p vid 20 pvid untagged
done

# the gateway: LAN address on the port, the endpoint VLAN by the script under test
ip -n $GW addr add 10.77.2.1/24 dev end0
export AEGIS_POLICY="$TMP/policy.json" AEGIS_VLAN_RUN="$TMP/run"
echo '{"endpoints":[{"name":"ep1","host":"10.20.0.2"}]}' > "$AEGIS_POLICY"
ip netns exec $GW "$ROOT/gateway/enforce/vlan-setup.sh" up end0 20 10.20.0.1/24
hook() { ip netns exec $GW "$ROOT/gateway/enforce/aegis-enforce.sh" "$@"; }

ip -n $EP  addr add 10.20.0.2/24 dev e0;  ip -n $EP  route add default via 10.20.0.1
ip -n $EP2 addr add 10.20.0.3/24 dev e0;  ip -n $EP2 route add default via 10.20.0.1
ip -n $LAN addr add 10.77.2.2/24 dev l0    # no route back to 10.20.0.0/24: the gateway masquerades

ip netns exec $LAN python3 -m http.server 8080 --bind 10.77.2.2 >/dev/null 2>&1 &
ip netns exec $GW  python3 -m http.server 7443 --bind 10.20.0.1 >/dev/null 2>&1 &
ip netns exec $EP  python3 -m http.server 7444 --bind 10.20.0.2 >/dev/null 2>&1 &
sleep 1

tcp() { ip netns exec "$1" python3 -c "import socket,sys; s=socket.socket(); s.settimeout(1.5); s.connect((sys.argv[1], int(sys.argv[2])))" "$2" "$3" 2>/dev/null; }
ping_from() { ip netns exec "$1" ping -c1 -W1 "$2" >/dev/null 2>&1; }
attest() { ip netns exec $GW python3 -c "import socket; s=socket.create_connection(('10.20.0.2', 7444), timeout=1.5); s.sendall(b'GET / HTTP/1.0\r\n\r\n'); assert s.recv(1)" 2>/dev/null; }
check() {  # check <allow|block> <description> <command...>
    local want=$1 what=$2; shift 2
    if "$@"; then got=allow; else got=block; fi
    if [ "$got" = "$want" ]; then echo "PASS $what ($got)"; pass=$((pass+1)); else echo "FAIL $what (wanted $want, got $got)"; fail=$((fail+1)); fi
}

echo "-- an endpoint that has not attested"
check block "ping the LAN"                              ping_from $EP 10.77.2.2
check block "TCP to the LAN"                            tcp $EP 10.77.2.2 8080
check allow "TCP to the gateway quote port"             tcp $EP 10.20.0.1 7443
check allow "the gateway attests it over the VLAN"      attest

echo "-- admitted"
hook ep1 admit
check allow "ping the LAN (masqueraded by the gateway)" ping_from $EP 10.77.2.2
check allow "TCP to the LAN"                            tcp $EP 10.77.2.2 8080
check block "the other, unattested endpoint still cannot" tcp $EP2 10.77.2.2 8080

echo "-- quarantined"
hook ep1 quarantine
check block "TCP to the LAN"                            tcp $EP 10.77.2.2 8080
check allow "the gateway still attests it"              attest

echo "-- ways around the VLAN"
ip -n $EP addr add 10.77.2.50/24 dev e0
check block "a LAN address on the endpoint: the LAN host directly" ping_from $EP 10.77.2.2
ip -n $EP addr del 10.77.2.50/24 dev e0
ip -n $EP link add link e0 name e0.1 type vlan id 1
ip -n $EP addr add 10.77.2.51/24 dev e0.1; ip -n $EP link set e0.1 up
check block "frames tagged for the LAN's VLAN 1"        ping_from $EP 10.77.2.2
ip -n $EP link del e0.1
check block "a LAN host reaches the endpoint directly"  ping_from $LAN 10.20.0.2

echo "-- known limit (needs the switch's port isolation): endpoints on the same VLAN see each other"
check allow "endpoint to endpoint, past the gateway"    ping_from $EP2 10.20.0.2

echo "-- known limit (until the next cycle): a device that takes an admitted endpoint's address"
hook ep1 admit
ip -n $EP link set e0 down                     # the admitted endpoint goes away, still in @admitted
ip -n $EP2 addr flush dev e0; ip -n $EP2 addr add 10.20.0.2/24 dev e0; ip -n $EP2 route add default via 10.20.0.1
ip netns exec $GW ip neigh flush dev end0.20
check allow "the unattested device, with the admitted address, to the LAN" tcp $EP2 10.77.2.2 8080
echo "   (the gateway's next cycle attests 10.20.0.2, gets no valid quote and quarantines it: see aegis-enforce.sh)"
hook ep1 quarantine
check block "after that cycle's quarantine"            tcp $EP2 10.77.2.2 8080

echo "-- undo"
ip netns exec $GW "$ROOT/gateway/enforce/vlan-setup.sh" down end0 20 > /dev/null
left=$(ip netns exec $GW sh -c 'nft list tables; ip -br link show end0.20 2>/dev/null')
if [ -z "$left" ]; then echo "PASS down removes the VLAN interface, the NAT table and the Aegis table"; pass=$((pass+1))
else echo "FAIL left after down: $left"; fail=$((fail+1)); fi

echo "passed $pass, failed $fail"
[ "$fail" = 0 ]

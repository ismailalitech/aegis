#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Put the gateway in the endpoints' traffic path with one Ethernet port and a switch that does 802.1Q VLANs.
# The switch: endpoint ports are untagged members of the endpoint VLAN only; the gateway's port carries the LAN
# untagged and the endpoint VLAN tagged; the router's port is on the LAN only. The endpoints then reach anything
# only through the gateway, which routes (and masquerades) between the endpoint VLAN and the LAN, and enforces
# aegis.nft on the VLAN interface.
#   vlan-setup.sh up <port> <vid> <gateway address/prefix on the endpoint VLAN> [--dhcp <first> <last>]
#   vlan-setup.sh down <port> <vid>
# Example on the PolarFire: vlan-setup.sh up end0 20 10.20.0.1/24 --dhcp 10.20.0.100 10.20.0.199
# AEGIS_VLAN_LEASES=<file> adds its "static_lease <MAC> <address>" lines to the DHCP server's configuration.
# down removes everything up created (the VLAN interface, the NAT table, the Aegis table, udhcpd's files).
# tests/host/test_enforcement_vlan.sh runs this script unchanged in network namespaces.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
CMD=${1:?up|down}; PORT=${2:?port}; VID=${3:?vlan id}; IF=$PORT.$VID
RUN=${AEGIS_VLAN_RUN:-/run/aegis-vlan}
case "$CMD" in
up)
    ADDR=${4:?gateway address/prefix}
    ip link add link "$PORT" name "$IF" type vlan id "$VID"
    ip addr add "$ADDR" dev "$IF"
    ip link set "$IF" up
    sysctl -qw net.ipv4.ip_forward=1
    NET=$(python3 -c "import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)" "$ADDR")
    nft -f - <<NFT
table ip aegis_nat
delete table ip aegis_nat
table ip aegis_nat {
    chain postrouting {
        type nat hook postrouting priority srcnat;
        oifname "$PORT" ip saddr $NET masquerade comment "endpoints reach the LAN through the gateway"
    }
}
NFT
    "$HERE/aegis-enforce.sh" init "$IF"
    if [ "${5:-}" = --dhcp ]; then
        mkdir -p "$RUN"
        GW=${ADDR%/*}
        MASK=$(python3 -c "import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).netmask)" "$ADDR")
        printf 'interface %s\nstart %s\nend %s\noption subnet %s\noption router %s\nlease_file %s/leases\npidfile %s/udhcpd.pid\n' \
            "$IF" "${6:?first address}" "${7:?last address}" "$MASK" "$GW" "$RUN" "$RUN" > "$RUN/udhcpd.conf"
        # fixed addresses for the endpoints, so the policy can name them: lines "static_lease <MAC> <address>"
        [ -n "${AEGIS_VLAN_LEASES:-}" ] && cat "$AEGIS_VLAN_LEASES" >> "$RUN/udhcpd.conf"
        touch "$RUN/leases"
        udhcpd "$RUN/udhcpd.conf"
    fi
    echo "endpoint VLAN $VID on $IF ($ADDR): routed, masqueraded, enforced" ;;
down)
    [ -f "$RUN/udhcpd.pid" ] && kill "$(cat "$RUN/udhcpd.pid")" 2>/dev/null || true
    rm -rf "$RUN"
    "$HERE/aegis-enforce.sh" off
    nft delete table ip aegis_nat 2>/dev/null || true
    ip link del "$IF" 2>/dev/null || true
    echo "endpoint VLAN $VID removed" ;;
*) echo "usage: $0 up|down ..." >&2; exit 2 ;;
esac

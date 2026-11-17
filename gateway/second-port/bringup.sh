#!/bin/sh
# Bring up the second network port (W5500 on the Raspberry Pi header) as the endpoint segment.
# Run ON THE GATEWAY as root, from this directory, with the module wired and powered.
#   ./bringup.sh                 load the drivers, apply the overlay, configure the port
#   ./bringup.sh --no-hw IFACE   skip drivers and overlay; configure an existing interface (used by the PC test)
# Changes, all undone by ./teardown.sh (nothing is written to flash; a reboot also undoes everything):
#   modules w5100, w5100-spi; overlay "w5500"; address $GW_ADDR on the port; udhcpd on the port;
#   net.ipv4.ip_forward=1; nft table "ip aegis_nat" (masquerade of admitted endpoint traffic towards $UPLINK).
set -eu
cd "$(dirname "$0")"
GW_ADDR=${GW_ADDR:-10.77.0.1/24}
POOL_START=${POOL_START:-10.77.0.10}
POOL_END=${POOL_END:-10.77.0.50}
UPLINK=${UPLINK:-end0}
STATE=${STATE:-/run/aegis-second-port}
LEASES=${LEASES:-static-leases}
mkdir -p "$STATE"

if [ "${1:-}" = "--no-hw" ]; then
	IF=${2:?interface name required with --no-hw}
else
	V=$(uname -r)
	sha256sum -c --quiet SHA256SUMS
	for m in w5100 w5100-spi; do
		lsmod | grep -q "^$(echo $m | tr - _) " || insmod "modules/$V/$m.ko"
	done
	OV=/sys/kernel/config/device-tree/overlays/w5500
	if [ ! -d $OV ]; then
		mkdir $OV
		cat w5500-spi1.dtbo > $OV/dtbo
	fi
	[ "$(cat $OV/status)" = applied ] || { echo "overlay not applied: $(cat $OV/status)"; exit 1; }
	IF=
	for i in $(seq 1 50); do
		for n in /sys/class/net/*; do
			[ "$(readlink -f "$n/device/driver" 2>/dev/null | xargs -r basename)" = w5100 ] && IF=$(basename "$n")
		done
		[ -n "$IF" ] && break
		sleep 0.1
	done
	[ -n "$IF" ] || { echo "no W5500 interface appeared; see dmesg (wiring, power, SPI pins)"; exit 1; }
fi
echo "$IF" > "$STATE/iface"

ip addr replace "$GW_ADDR" dev "$IF"
ip link set "$IF" up

cat > "$STATE/udhcpd.conf" <<CONF
interface $IF
start $POOL_START
end $POOL_END
lease_file $STATE/udhcpd.leases
pidfile $STATE/udhcpd.pid
option subnet 255.255.255.0
option router ${GW_ADDR%/*}
option dns ${DNS:-${GW_ADDR%/*}}
option lease 3600
CONF
# optional: fixed addresses, one line per endpoint: static_lease <MAC> <address>
if [ -f "$LEASES" ]; then cat "$LEASES" >> "$STATE/udhcpd.conf"; fi
touch "$STATE/udhcpd.leases"
if [ -f "$STATE/udhcpd.pid" ]; then kill "$(cat "$STATE/udhcpd.pid")" 2>/dev/null || true; fi
udhcpd "$STATE/udhcpd.conf"

cat /proc/sys/net/ipv4/ip_forward > "$STATE/ip_forward.before"
echo 1 > /proc/sys/net/ipv4/ip_forward

nft -f - <<NFT
table ip aegis_nat
delete table ip aegis_nat
table ip aegis_nat {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		iifname "$IF" oifname "$UPLINK" masquerade
	}
}
NFT
echo "endpoint segment on $IF, gateway ${GW_ADDR%/*}; now load the enforcement ruleset with ENDPOINT_IF=$IF"

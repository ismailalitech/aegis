#!/bin/sh
# Undo ./bringup.sh. Safe to run more than once.
set -u
STATE=${STATE:-/run/aegis-second-port}
IF=$(cat "$STATE/iface" 2>/dev/null || true)
[ -f "$STATE/udhcpd.pid" ] && kill "$(cat "$STATE/udhcpd.pid")" 2>/dev/null
nft delete table ip aegis_nat 2>/dev/null
[ -f "$STATE/ip_forward.before" ] && cat "$STATE/ip_forward.before" > /proc/sys/net/ipv4/ip_forward
[ -n "$IF" ] && ip addr flush dev "$IF" 2>/dev/null
OV=/sys/kernel/config/device-tree/overlays/w5500
[ -d $OV ] && rmdir $OV
for m in w5100_spi w5100; do lsmod | grep -q "^$m " && rmmod $m; done
rm -rf "$STATE"
echo "second port removed"

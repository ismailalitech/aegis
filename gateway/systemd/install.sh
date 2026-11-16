#!/bin/sh
# On the gateway: install and start the Aegis services.  Undo: ./install.sh remove ; reboot
set -eu
U="aegisd.service aegis-fleet.service"
if [ "${1:-}" = remove ]; then
    systemctl disable --now $U || true
    for u in $U; do rm -f /etc/systemd/system/$u; done
    systemctl daemon-reload
    echo "removed (reboot to unload mpfs-generic-service)"
    exit 0
fi
cd "$(dirname "$0")"
for u in $U; do install -m 0644 $u /etc/systemd/system/$u; done
systemctl daemon-reload
systemctl enable --now $U
systemctl --no-pager --lines=0 status $U | grep -E 'Loaded|Active'

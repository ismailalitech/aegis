#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# On the gateway: install and start the Aegis services, and keep the journal on the SD card (takes effect at the next
# boot).  Undo: ./install.sh remove ; reboot
set -eu
U="aegisd.service aegis-fleet.service"
if [ "${1:-}" = remove ]; then
    systemctl disable --now $U || true
    for u in $U; do rm -f /etc/systemd/system/$u; done
    systemctl disable aegis-journal-link.service 2>/dev/null || true
    rm -f /etc/systemd/system/aegis-journal-link.service /etc/systemd/journald.conf.d/aegis.conf
    systemctl daemon-reload
    echo "removed (reboot to unload mpfs-generic-service)"
    exit 0
fi
cd "$(dirname "$0")"
for u in $U; do install -m 0644 $u /etc/systemd/system/$u; done
install -m 0644 aegis-journal-link.service /etc/systemd/system/aegis-journal-link.service
install -D -m 0644 journald-aegis.conf /etc/systemd/journald.conf.d/aegis.conf
systemctl daemon-reload
systemctl enable aegis-journal-link.service
systemctl enable --now $U
systemctl --no-pager --lines=0 status $U | grep -E 'Loaded|Active'

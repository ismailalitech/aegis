#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Install the Aegis gateway kernel (pfdaq kernel + nf_tables, bridge, VLAN, USB Ethernet).
# Run ON THE GATEWAY, from this directory, with someone at the board: if the new kernel does not
# boot, recovery needs the SD card in a PC (copy fitImage.pre-aegis or fitImage.good to fitImage).
# Changes: FAT partition fitImage (old one kept as fitImage.pre-aegis; fitImage.good untouched),
# /lib/modules/<ver> (old tree kept as /root/modules-pre-aegis.tgz). Undo: ./rollback.sh
set -eu
V=6.18.17-linux4microchip-2026.04.1-g7fbe4f69684d-dirty
cd "$(dirname "$0")"
sha256sum -c --quiet SHA256SUMS
[ "$(uname -r)" = "$V" ] || { echo "running kernel is not $V"; exit 1; }
M=/mnt/aegis-boot
mkdir -p $M
mount /dev/mmcblk0p1 $M
trap 'umount $M 2>/dev/null || true' EXIT
[ -f $M/fitImage.good ] || { echo "no fitImage.good on the boot partition: stop"; exit 1; }
[ -f $M/fitImage.pre-aegis ] || cp $M/fitImage $M/fitImage.pre-aegis
[ -f /root/modules-pre-aegis.tgz ] || tar czf /root/modules-pre-aegis.tgz -C /lib/modules $V
cp fitImage $M/fitImage.new && sync && mv $M/fitImage.new $M/fitImage && sync
cmp fitImage $M/fitImage
# /lib is a symlink to usr/lib on this rootfs (merged /usr): extracting the archive's "lib/" at /
# would replace the symlink with a real directory (GNU tar default). Extract under /usr instead.
[ -L /lib ] && D=/usr || D=/
tar xzf modules.tgz -C $D
mkdir -p /lib/modules/$V/updates
cp extra/*.ko /lib/modules/$V/updates/
depmod -a $V
sync
echo "installed. Reboot with: systemctl reboot   (then: zcat /proc/config.gz | grep NF_TABLES=)"

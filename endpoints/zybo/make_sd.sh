#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Write the Zybo Z7 Aegis endpoint image to a microSD card. Erases the card.
#   sudo endpoints/zybo/make_sd.sh /dev/sdX <work dir with u-boot/, linux-6.18.64/, rootfs/>
# Refuses anything that is not a removable USB disk smaller than 64 GB.
set -eu
DEV=${1:?device, e.g. /dev/sdc}; W=${2:?work directory}
HERE=$(cd "$(dirname "$0")" && pwd)
B=$(basename "$DEV")
[ "$(cat /sys/block/$B/removable)" = 1 ] || { echo "$DEV is not removable: refusing"; exit 1; }
[ "$(lsblk -dno TRAN "$DEV")" = usb ] || { echo "$DEV is not on USB: refusing"; exit 1; }
SIZE=$(cat /sys/block/$B/size)
[ "$SIZE" -lt $((64 * 1024 * 1024 * 2)) ] || { echo "$DEV is 64 GB or more: refusing"; exit 1; }
for p in $(lsblk -lno NAME "$DEV" | tail -n +2); do umount "/dev/$p" 2>/dev/null || true; done
wipefs -aq "$DEV"
printf 'label: dos\nstart=2048, size=262144, type=c, bootable\nstart=264192, type=83\n' | sfdisk -q "$DEV"
partprobe "$DEV"; sleep 2
P1=${DEV}1; P2=${DEV}2
mkfs.vfat -n BOOT "$P1" > /dev/null
mkfs.ext4 -q -F -L zybo-root "$P2"
M=$(mktemp -d)
mount "$P1" "$M"
cp "$W/u-boot/spl/boot.bin" "$W/u-boot/u-boot.img" "$M/"
cp "$W/linux-6.18.64/arch/arm/boot/zImage" "$W/linux-6.18.64/arch/arm/boot/dts/xilinx/zynq-zybo-z7.dtb" "$M/"
mkimage -A arm -T script -C none -d "$HERE/boot.cmd" "$M/boot.scr" > /dev/null
(cd "$M" && sha256sum boot.bin u-boot.img zImage zynq-zybo-z7.dtb boot.scr) > "$W/boot-files.sha256"
umount "$M"
mount "$P2" "$M"
cp -a "$W/rootfs/." "$M/"
rm -f "$M/usr/bin/qemu-arm-static"
umount "$M"; rmdir "$M"; sync
echo "written: $DEV"; cat "$W/boot-files.sha256"

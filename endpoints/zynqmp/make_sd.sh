#!/bin/sh
# Write the Zynq UltraScale+ Aegis endpoint image (TE0808 on a TEBF0808) to a microSD card. Erases the card.
#   sudo endpoints/zynqmp/make_sd.sh /dev/sdX <work dir with boot/BOOT.BIN, boot/image.ub and rootfs/>
# Partition 1 (FAT, label BOOT): BOOT.BIN (FSBL, PMU firmware, TF-A, U-Boot) and image.ub (kernel and device tree),
# which U-Boot loads by default (fatload image.ub, bootm). Partition 2 (ext4, label aegis-root): the root file system
# from setup_rootfs.sh; the device tree's bootargs name it as /dev/mmcblk1p2 (the SD card on SD1).
# Refuses anything that is not a removable USB disk smaller than 64 GB.
set -eu
DEV=${1:?device, e.g. /dev/sdc}; W=${2:?work directory}
B=$(basename "$DEV")
[ "$(cat /sys/block/$B/removable)" = 1 ] || { echo "$DEV is not removable: refusing"; exit 1; }
[ "$(lsblk -dno TRAN "$DEV")" = usb ] || { echo "$DEV is not on USB: refusing"; exit 1; }
SIZE=$(cat /sys/block/$B/size)
[ "$SIZE" -lt $((64 * 1024 * 1024 * 2)) ] || { echo "$DEV is 64 GB or more: refusing"; exit 1; }
for f in boot/BOOT.BIN boot/image.ub rootfs/opt/aegis-prover/aegis_linux_prover.py; do
	[ -f "$W/$f" ] || { echo "missing $W/$f"; exit 1; }
done
for p in $(lsblk -lno NAME "$DEV" | tail -n +2); do umount "/dev/$p" 2>/dev/null || true; done
wipefs -aq "$DEV"
printf 'label: dos\nstart=2048, size=524288, type=c, bootable\nstart=526336, type=83\n' | sfdisk -q "$DEV"
partprobe "$DEV"; sleep 2
P1=${DEV}1; P2=${DEV}2
mkfs.vfat -F 32 -n BOOT "$P1" > /dev/null
mkfs.ext4 -q -F -L aegis-root "$P2"
M=$(mktemp -d)
mount "$P1" "$M"
cp "$W/boot/BOOT.BIN" "$W/boot/image.ub" "$M/"
(cd "$M" && sha256sum BOOT.BIN image.ub) > "$W/boot-files.sha256"
umount "$M"
mount "$P2" "$M"
cp -a "$W/rootfs/." "$M/"
rm -f "$M/usr/bin/qemu-aarch64-static"
umount "$M"; rmdir "$M"; sync
echo "written: $DEV"; cat "$W/boot-files.sha256"

#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Configure the Debian 12 armhf root filesystem for the Zybo Z7 Aegis endpoint (after debootstrap's second stage).
#   sudo endpoints/zybo/setup_rootfs.sh <work dir> <ssh public key file> <gateway ML-DSA-65 public key (hex) file> \
#        <liboqs.so for armhf>
# The work directory holds rootfs/ and linux-6.18.64/ (built). Nothing outside the work directory is changed.
set -eu
W=${1:?work dir}; SSHKEY=${2:?ssh public key}; GWPK=${3:?gateway key}; LIBOQS=${4:?liboqs.so (armhf)}
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/../.." && pwd)
R=$W/rootfs
echo zybo-aegis > "$R/etc/hostname"
printf '127.0.0.1 localhost\n127.0.1.1 zybo-aegis\n' > "$R/etc/hosts"
printf 'auto lo\niface lo inet loopback\n\nallow-hotplug eth0\niface eth0 inet dhcp\n' > "$R/etc/network/interfaces"
mkdir -p "$R/boot/firmware"
printf '/dev/mmcblk0p2 / ext4 defaults,noatime 0 1\n/dev/mmcblk0p1 /boot/firmware vfat ro 0 2\n' > "$R/etc/fstab"
: > "$R/etc/machine-id"                                   # generated at first boot
install -d -m 700 "$R/root/.ssh"
install -m 600 "$SSHKEY" "$R/root/.ssh/authorized_keys"
passwd -R "$R" -l root > /dev/null                        # no password: SSH key or the serial console's emergency shell
# time, for the credential's expiry check (the board has no battery-backed clock)
cp /etc/resolv.conf "$R/etc/resolv.conf"
chroot "$R" sh -c 'apt-get -q update > /dev/null && DEBIAN_FRONTEND=noninteractive apt-get -q -y install --no-install-recommends systemd-timesyncd > /dev/null'
chroot "$R" apt-get clean
# kernel modules
make -s -C "$W/linux-6.18.64" ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- INSTALL_MOD_PATH="$R" INSTALL_MOD_STRIP=1 modules_install
# the prover
P=$R/opt/aegis-prover
install -d "$P/common"
install -m 644 "$HERE/aegis_linux_prover.py" "$P/"
for m in cbor kmac mldsa mlkem; do install -m 644 "$REPO/common/$m.py" "$P/common/"; done
install -m 644 "$LIBOQS" "$P/common/liboqs.so.9"
install -d "$R/etc/aegis-prover"
install -m 644 "$GWPK" "$R/etc/aegis-prover/gateway.mldsa65.pub"
install -m 644 "$HERE/aegis-linux-prover.service" "$R/etc/systemd/system/"
ln -sf /etc/systemd/system/aegis-linux-prover.service "$R/etc/systemd/system/multi-user.target.wants/aegis-linux-prover.service"
echo "rootfs configured: $(du -sh "$R" | cut -f1)"

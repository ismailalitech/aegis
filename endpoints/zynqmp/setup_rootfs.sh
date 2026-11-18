#!/bin/sh
# Configure the Debian 12 arm64 root filesystem for the Zynq UltraScale+ Aegis endpoint (TE0808 on a TEBF0808), step 3
# of README.md: the Linux prover, "software trust". Run after debootstrap:
# haveged: the ZynqMP has no TRNG that Linux 4.19 uses, and without it the kernel took 3 minutes to seed its RNG,
# so sshd and the prover blocked in getrandom() for that long after boot.
#   sudo debootstrap --arch=arm64 --variant=minbase --include=systemd,systemd-sysv,udev,python3,openssh-server,\
#        ifupdown,isc-dhcp-client,iproute2,systemd-timesyncd,kmod,ca-certificates,netbase,procps,haveged bookworm rootfs \
#        http://deb.debian.org/debian
#   sudo endpoints/zynqmp/setup_rootfs.sh <work dir> <ssh public key> <gateway ML-DSA-65 public key (hex)> \
#        <liboqs.so.9 for aarch64> [<kernel modules dir, lib/modules/<version>>]
# The work directory holds rootfs/. Nothing outside the work directory is changed.
set -eu
W=${1:?work dir}; SSHKEY=${2:?ssh public key}; GWPK=${3:?gateway key}; LIBOQS=${4:?liboqs.so.9 (aarch64)}
MODS=${5:-}
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/../.." && pwd)
R=$W/rootfs
file -L "$LIBOQS" | grep -q aarch64 || { echo "$LIBOQS is not an aarch64 library"; exit 1; }
echo zynqmp-aegis > "$R/etc/hostname"
printf '127.0.0.1 localhost\n127.0.1.1 zynqmp-aegis\n' > "$R/etc/hosts"
# systemd renames the GEM's eth0 to end0 (seen on the first boot); either name gets DHCP
printf 'auto lo\niface lo inet loopback\n\nallow-hotplug end0\niface end0 inet dhcp\n\nallow-hotplug eth0\niface eth0 inet dhcp\n' \
	> "$R/etc/network/interfaces"
mkdir -p "$R/boot/firmware"
printf 'LABEL=aegis-root / ext4 defaults,noatime 0 1\nLABEL=BOOT /boot/firmware vfat ro 0 2\n' > "$R/etc/fstab"
: > "$R/etc/machine-id"                                   # generated at first boot
install -d -m 700 "$R/root/.ssh"
install -m 600 "$SSHKEY" "$R/root/.ssh/authorized_keys"
passwd -R "$R" -l root > /dev/null                        # no password: SSH with the key above
# bench console: root is logged in on ttyPS0 (the TE0790's UART) without a password. Whoever holds that cable can
# already boot any root file system from U-Boot, so this adds no access; it is how the board is debugged when the
# network is down. Persistent journal, to read a failed boot afterwards.
install -d "$R/etc/systemd/system/serial-getty@ttyPS0.service.d" "$R/var/log/journal"
printf '[Service]\nExecStart=\nExecStart=-/sbin/agetty --autologin root --keep-baud 115200,57600,38400,9600 %%I $TERM\n' \
	> "$R/etc/systemd/system/serial-getty@ttyPS0.service.d/autologin.conf"
# kernel modules of the kernel the board boots (most drivers are built in; copied when given)
if [ -n "$MODS" ]; then
	install -d "$R/lib/modules"
	cp -a "$MODS" "$R/lib/modules/"
fi
# the prover
P=$R/opt/aegis-prover
install -d "$P/common"
install -m 644 "$REPO/endpoints/zybo/aegis_linux_prover.py" "$P/"
for m in cbor kmac mldsa mlkem; do install -m 644 "$REPO/common/$m.py" "$P/common/"; done
install -m 644 "$LIBOQS" "$P/common/liboqs.so.9"
install -d "$R/etc/aegis-prover"
install -m 644 "$GWPK" "$R/etc/aegis-prover/gateway.mldsa65.pub"
install -m 644 "$HERE/aegis-linux-prover.service" "$R/etc/systemd/system/"
ln -sf /etc/systemd/system/aegis-linux-prover.service \
	"$R/etc/systemd/system/multi-user.target.wants/aegis-linux-prover.service"
# the prover answers on TCP 7444; the board has no battery-backed clock, timesyncd sets it from the network
ln -sf /lib/systemd/system/systemd-timesyncd.service \
	"$R/etc/systemd/system/sysinit.target.wants/systemd-timesyncd.service" 2>/dev/null || true
echo "rootfs configured: $(du -sh "$R" | cut -f1)"

#!/bin/bash
# Build what gateway/second-port/bringup.sh needs, next to it: the W5500 driver modules for the gateway's running
# kernel, the compiled overlay, and SHA256SUMS. The modules are built out of tree from copies of the kernel's own
# sources, against the Yocto kernel build that produced the gateway kernel (its Module.symvers and .config).
#
#   KBUILD=<yocto>/tmp-glibc/work/mpfs_disco_kit_amp-mchp-linux/linux-mchp/6.18.17+git tools/build_second_port.sh
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
K=${KBUILD:?set KBUILD to the linux-mchp work directory (it holds build/ and recipe-sysroot-native/)}
V=6.18.17-linux4microchip-2026.04.1-g7fbe4f69684d-dirty
[ "$(cat "$K/build/include/config/kernel.release")" = "$V" ] || { echo "kernel build is not $V"; exit 1; }
OUT=$ROOT/gateway/second-port
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
SRC=$K/build/source/drivers/net/ethernet/wiznet
cp "$SRC/w5100.c" "$SRC/w5100.h" "$SRC/w5100-spi.c" "$W/"
echo 'obj-m := w5100.o w5100-spi.o' > "$W/Kbuild"
PATH=$K/recipe-sysroot-native/usr/bin/riscv64-mchp-linux:$K/recipe-sysroot-native/usr/bin:$PATH \
	make -s -C "$K/build" M="$W" ARCH=riscv CROSS_COMPILE=riscv64-mchp-linux- modules
mkdir -p "$OUT/modules/$V"
for m in w5100 w5100-spi; do
	[ "$(modinfo -F vermagic "$W/$m.ko" | cut -d' ' -f1)" = "$V" ] || { echo "$m: wrong vermagic"; exit 1; }
	cp "$W/$m.ko" "$OUT/modules/$V/"
done
dtc -@ -q -I dts -O dtb -o "$OUT/w5500-spi1.dtbo" "$OUT/w5500-spi1.dtso"
( cd "$OUT" && sha256sum w5500-spi1.dtbo modules/$V/*.ko > SHA256SUMS && cat SHA256SUMS )

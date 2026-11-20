# SPDX-License-Identifier: Apache-2.0
# U-Boot script for the Zynq UltraScale+ Aegis endpoint.
# mkimage -A arm64 -T script -C none -d boot.cmd boot.scr
# 1. Our kernel (linux-xlnx xilinx-v2025.2, Image) with our device tree (dts/zynqmp-te0807-aegis.dts). That tree
#    enables only the SD card on SD1, as mmc0, so the root is /dev/mmcblk0p2. clk_ignore_unused keeps pl_clk0,
#    which the tree does not describe, running for the accelerator.
# 2. If either file is missing: the FIT image the card came with (Linux 4.19 and its own device tree and bootargs).
setenv bootargs console=ttyPS0,115200 earlycon clk_ignore_unused root=/dev/mmcblk0p2 rootfstype=ext4 rw rootwait
if fatload mmc 0:1 0x00200000 Image && fatload mmc 0:1 0x00100000 zynqmp-te0807-aegis.dtb; then
	booti 0x00200000 - 0x00100000
fi
echo "no Image or device tree: the card's FIT image"
env delete bootargs
fatload mmc 0:1 0x10000000 image.ub
bootm 0x10000000

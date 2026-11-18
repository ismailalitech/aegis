# U-Boot script for the Zynq UltraScale+ Aegis endpoint: the FIT image (kernel and its device tree) from the FAT
# partition; the device tree's bootargs put the root on the SD card's second partition.
# mkimage -A arm64 -T script -C none -d boot.cmd boot.scr
fatload mmc 0:1 0x10000000 image.ub
bootm 0x10000000

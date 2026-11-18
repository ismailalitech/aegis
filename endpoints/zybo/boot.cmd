# U-Boot script for the Zybo Z7 Aegis endpoint: kernel and device tree from the FAT partition, root on partition 2.
# mkimage -A arm -T script -C none -d boot.cmd boot.scr
setenv bootargs console=ttyPS0,115200 root=/dev/mmcblk0p2 rw rootwait
fatload mmc 0:1 ${kernel_addr_r} zImage
fatload mmc 0:1 ${fdt_addr_r} zynq-zybo-z7.dtb
bootz ${kernel_addr_r} - ${fdt_addr_r}

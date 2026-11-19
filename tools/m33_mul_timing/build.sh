#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# build.sh <name> <base address> <length>  -> out/<name>.elf, .bin
set -eu
cd "$(dirname "$0")"
GCC=${GCC:-arm-none-eabi-gcc}
B=$(dirname "$GCC")/arm-none-eabi-
NAME=$1; BASE=$2; LEN=$3
mkdir -p out
python3 gen_blocks.py 128 > out/blocks.S
export ABI
sed "s/@BASE@/$BASE/; s/@LEN@/$LEN/" link.ld.in > out/$NAME.ld
# endpoint flags for the montgomery unit; the harness itself uses plain -mcpu=cortex-m33
MONTFLAGS=${MONTFLAGS:--Os -std=gnu11 -mcpu=cortex-m33+nodsp+nofp -mthumb -mfloat-abi=soft}
ABI=${ABI:--mfloat-abi=soft}
"$GCC" $MONTFLAGS -ffunction-sections -c mont.c -o out/mont.o
"$GCC" -O2 -std=gnu11 -mcpu=cortex-m33 -mthumb $ABI -ffreestanding -c main.c -o out/main.o
"$GCC" -mcpu=cortex-m33 -mthumb $ABI -c start.S -o out/start.o
"$GCC" -mcpu=cortex-m33 -mthumb $ABI -c out/blocks.S -o out/blocks.o
"$GCC" $ABI -nostdlib -nostartfiles -T out/$NAME.ld out/start.o out/main.o out/mont.o out/blocks.o -o out/$NAME.elf -Wl,-Map,out/$NAME.map
${B}objcopy -O binary out/$NAME.elf out/$NAME.bin
${B}size out/$NAME.elf
${B}objdump -d out/mont.o

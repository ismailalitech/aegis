#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Build OP-TEE 4.7.0 for the Aegis ZynqMP endpoint with the hand-off patches (os-patches/) and the Aegis TA built in.
#   endpoints/zynqmp/optee/build_optee.sh <OP-TEE source tree> <new out dir> [gateway host]
# The source tree is a git checkout of tag 4.7.0 used for nothing else (a copy, not the reference checkout): the
# patches are applied to it with git apply. A tree that differs from 4.7.0 is refused, unless the difference is
# exactly these patches (a second run). The out dir must not exist yet; nothing is deleted. It gets:
#   optee/   OP-TEE's build directory; optee/core/tee-raw.bin goes into BOOT.BIN (../boot.bif)
#   ta/      the Aegis TA (build_ta.sh), built against optee/export-ta_arm64 and embedded with EARLY_TA_PATHS
# The gateway's key: as for build_ta.sh (gateway host over ssh, or GATEWAY_PK_HEX=<file>).
# AEGIS_HANDOFF=n builds without CFG_AEGIS_ZYNQMP_HANDOFF (phase A behaviour: development HUK, no measurements).
set -eu
SRC=${1:?OP-TEE source tree}; OUT=${2:?out dir}; GW=${3:-${GATEWAY:-}}
HERE=$(cd "$(dirname "$0")" && pwd)
TAG=4.7.0
TA_UUID=b56a99ca-1c3c-40c8-af55-b8dd5ee03213
[ ! -e "$OUT" ] || { echo "$OUT exists: give a new directory"; exit 1; }
SRC=$(cd "$SRC" && pwd)
[ "$(git -C "$SRC" rev-parse --show-toplevel)" = "$SRC" ] || { echo "$SRC is not the top of a git checkout"; exit 1; }
[ "$(git -C "$SRC" rev-parse HEAD)" = "$(git -C "$SRC" rev-parse "$TAG^{commit}")" ] || { echo "$SRC is not at $TAG"; exit 1; }

# the paths the patches touch, and the paths that differ from the tag in the tree
touched=$(cat "$HERE"/os-patches/*.patch | git -C "$SRC" apply --numstat | cut -f3 | sort)
changed=$(git -C "$SRC" status --porcelain --untracked-files=all | cut -c4- | sort)
if [ -z "$changed" ]; then
	for p in "$HERE"/os-patches/*.patch; do
		git -C "$SRC" apply --check "$p"
		git -C "$SRC" apply "$p"
		echo "applied $(basename "$p")"
	done
elif [ "$changed" = "$touched" ] && cat "$HERE"/os-patches/*.patch | git -C "$SRC" apply --reverse --check; then
	echo "the patches are already applied"
else
	echo "$SRC differs from $TAG by something else than these patches: use a clean copy"
	git -C "$SRC" status --short
	exit 1
fi
# the interface headers inside the patches are the repository's
cmp "$SRC/core/arch/arm/plat-zynqmp/aegis_zynqmp_handoff.h" "$HERE/../handoff/aegis_zynqmp_handoff.h"
cmp "$SRC/core/arch/arm/plat-zynqmp/aegis_boot_pta.h" "$HERE/include/aegis_boot_pta.h"

mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
optee_make() {
	make -C "$SRC" -j"$(nproc)" PLATFORM=zynqmp-zcu102 CFG_ARM64_core=y CROSS_COMPILE64=aarch64-linux-gnu- \
		CROSS_COMPILE32=arm-linux-gnueabihf- CFG_TEE_CORE_LOG_LEVEL=2 CFG_USER_TA_TARGETS=ta_arm64 \
		CFG_AEGIS_ZYNQMP_HANDOFF="${AEGIS_HANDOFF:-y}" O="$OUT/optee" "$@"
}
optee_make ta_dev_kit > "$OUT/optee-devkit.log" 2>&1 || { tail -20 "$OUT/optee-devkit.log"; exit 1; }
"$HERE/build_ta.sh" "$OUT/optee" "$OUT/ta" "$GW" > "$OUT/ta.log" 2>&1 || { tail -20 "$OUT/ta.log"; exit 1; }
optee_make EARLY_TA_PATHS="$OUT/ta/$TA_UUID.stripped.elf" > "$OUT/optee.log" 2>&1 || { tail -20 "$OUT/optee.log"; exit 1; }
grep -E '^CFG_AEGIS_ZYNQMP_HANDOFF|^CFG_INSECURE|^CFG_REE_FS_TA=' "$OUT/optee/conf.mk"
ls -l "$OUT/ta/$TA_UUID.ta" "$OUT/ta/$TA_UUID.stripped.elf" "$OUT/optee/core/tee-raw.bin"
sha256sum "$OUT/optee/core/tee-raw.bin"

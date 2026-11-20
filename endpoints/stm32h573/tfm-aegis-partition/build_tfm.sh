#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Build BL2-compatible TF-M v2.3.0 secure image for the STM32H573I-DK with the Aegis partition.
# Same configuration as the SecureBench reference build (securebench-ws/build/spe) plus the
# out-of-tree partition; reuses that build's already fetched and patched dependencies.
# Output: $OUT/bin/tfm_s_signed.{bin,hex} and $OUT/api_ns for the Non-Secure build.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
TFM=${TFM:-$HOME/securebench-ws/upstream/trusted-firmware-m}
DEPS=${DEPS:-$HOME/securebench-ws/build/spe/lib/ext}
OUT=${OUT:-$HOME/aegis-tools/tfm-aegis-build}
GT=$(ls -d "$HOME"/st/stm32cubeide_2.2.0/plugins/com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.14.3.rel1.linux64_*/tools/bin)
export PATH="$GT:$HOME/securebench-ws/.venv/bin:$HOME/aegis/.venv/bin:$PATH"
export GIT_AUTHOR_NAME="Aegis build" GIT_AUTHOR_EMAIL=build@aegis.invalid \
       GIT_COMMITTER_NAME="Aegis build" GIT_COMMITTER_EMAIL=build@aegis.invalid
rm -rf "$OUT"
cmake -S "$TFM" -B "$OUT" -G Ninja -DTFM_PLATFORM=stm/stm32h573i_dk \
  -DTFM_TOOLCHAIN_FILE="$TFM/toolchain_GNUARM.cmake" \
  -DMCUBOOT_SIGNATURE_TYPE=EC-P256 -DCONFIG_TFM_SPM_BACKEND=IPC -DTFM_ISOLATION_LEVEL=1 \
  -DTFM_BL2_LOG_LEVEL=LOG_LEVEL_INFO -DCMAKE_BUILD_TYPE=MinSizeRel \
  -DCMSIS_PATH="$DEPS/cmsis-src" -DMCUBOOT_PATH="$DEPS/mcuboot-src" -DQCBOR_PATH="$DEPS/qcbor-src" \
  -DT_COSE_PATH="$DEPS/t_cose-src" -DTFM_EXTRAS_REPO_PATH="$DEPS/tf-m-extras-src" \
  -DTF_PSA_CRYPTO_PATH="$DEPS/tf-psa-crypto-src" \
  -DTFM_EXTRA_MANIFEST_LIST_FILES="$HERE/manifest_list.yaml" \
  -DTFM_EXTRA_PARTITION_PATHS="$HERE" > "$HERE/build-tfm.log" 2>&1
cmake --build "$OUT" -- install >> "$HERE/build-tfm.log" 2>&1
ls -l "$OUT/bin/tfm_s_signed.bin"

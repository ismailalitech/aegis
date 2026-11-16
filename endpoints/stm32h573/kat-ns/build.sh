#!/bin/sh
# Clean build of the prover NS image. Always clean: the api_ns signing step does not
# rerun on incremental builds (seen 2026-11-16: tfm_ns_signed.bin stayed stale).
set -eu
cd "$(dirname "$0")"
SPE=${SPE:-$HOME/securebench-ws/build/spe/api_ns}
GT=$(ls -d "$HOME"/st/stm32cubeide_2.2.0/plugins/com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.14.3.rel1.linux64_*/tools/bin)
export PATH="$GT:$HOME/securebench-ws/.venv/bin:$HOME/aegis/.venv/bin:$PATH"
rm -rf build
cmake -S . -B build -G Ninja -DCONFIG_SPE_PATH="$SPE" -DCMAKE_BUILD_TYPE=MinSizeRel "$@" > build.log 2>&1
cmake --build build >> build.log 2>&1
strings build/bin/tfm_ns_signed.bin | grep -q 'AEGIS-KAT' || { echo "signed image lacks the banner" >&2; exit 1; }
sha256sum build/bin/tfm_ns_signed.bin

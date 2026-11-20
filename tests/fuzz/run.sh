#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Build a fuzz harness with libFuzzer, ASan and UBSan, and run it:
#   tests/fuzz/run.sh [seconds] [workers]           the Prover SDK's protocol core, the one every device family builds
#                                                   (fuzz_sdk_core.c, through the reference port; the shared corpus
#                                                   seeds/); default 600 s, 8
#   STM32=1 tests/fuzz/run.sh [seconds] [workers]   the STM32H573 port of it, the TF-M partition, on PC stand-ins
#                                                   (stm32/: the PSA messages, the session clock's hardware)
# Needs clang (with libFuzzer) and the mldsa-native / mlkem-native v2.0.0 trees (MLDSA_NATIVE_DIR, MLKEM_NATIVE_DIR).
# Work files go to $FUZZ_OUT (default: a temporary directory); a crash is saved there as crash-<hash>.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
TOOLS=${AEGIS_TOOLS:-$HOME/aegis-tools}
MLDSA=${MLDSA_NATIVE_DIR:-$TOOLS/mldsa-native/mldsa}
MLKEM=${MLKEM_NATIVE_DIR:-$TOOLS/mlkem-native/mlkem}
SDK=$ROOT/sdk
PART=$ROOT/endpoints/stm32h573/tfm-aegis-partition
OUT=${FUZZ_OUT:-$(mktemp -d)}
SECS=${1:-600}
WORKERS=${2:-8}
mkdir -p "$OUT/corpus"
SAN="-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer"
INC="-I$SDK/include -I$SDK/src -I$SDK/ports/host -I$SDK/crypto/mldsa -I$MLDSA -I$SDK/crypto/mlkem -I$MLKEM"
cc() { clang -g -D_GNU_SOURCE -DMLD_CONFIG_FILE='"aegis_mldsa_config.h"' $INC "$@"; }
# the code under test (the core is compiled into the harness) with the sanitizers and coverage; the crypto libraries
# with the sanitizers only (faster)
cc -O1 $SAN -c "$SDK/src/aegis_sha256.c" -o "$OUT/sha256.o"
cc -O1 $SAN -c "$SDK/src/aegis_kmac.c" -o "$OUT/kmac.o"
cc -O2 -fsanitize=address,undefined -c "$SDK/crypto/mlkem_unit.c" -o "$OUT/mlkem.o"
cc -O2 -fsanitize=address,undefined -c "$MLDSA/mldsa_native.c" -o "$OUT/mldsa.o"
if [ "${STM32:-0}" = 1 ]; then
	# the partition pins a test gateway key whose secret key the harness holds
	cc -O2 -c "$HERE/stm32/gen_gw_pk.c" -o "$OUT/gen.o"
	clang "$OUT/gen.o" "$OUT/mldsa.o" -fsanitize=address,undefined -o "$OUT/gen_gw_pk"
	"$OUT/gen_gw_pk" > "$OUT/fz_gateway_pk.h"
	cc -O1 $SAN -DAEGIS_GATEWAY_PK_HEADER='"fz_gateway_pk.h"' -I"$OUT" -I"$PART" -I"$HERE/stm32/stub" \
		-c "$HERE/stm32/fuzz_stm32_partition.c" -o "$OUT/h.o"
	clang $SAN "$OUT"/h.o "$OUT"/sha256.o "$OUT"/kmac.o "$OUT"/mlkem.o "$OUT"/mldsa.o -o "$OUT/fuzz_target"
	cp "$HERE"/stm32/seeds/* "$OUT/corpus/"
else
	cc -O1 $SAN -c "$HERE/fuzz_sdk_core.c" -o "$OUT/h.o"
	cc -O1 $SAN -c "$SDK/ports/host/aegis_port_host.c" -o "$OUT/port.o"
	clang $SAN "$OUT"/h.o "$OUT"/port.o "$OUT"/sha256.o "$OUT"/kmac.o "$OUT"/mlkem.o "$OUT"/mldsa.o -o "$OUT/fuzz_target"
	cp "$HERE"/seeds/* "$OUT/corpus/"
fi
cd "$OUT"
./fuzz_target -dict="$HERE/proto.dict" -max_len=16384 -max_total_time="$SECS" -timeout=20 -rss_limit_mb=4096 \
	-print_final_stats=1 -jobs="$WORKERS" -workers="$WORKERS" corpus

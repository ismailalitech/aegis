#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Build a fuzz harness with libFuzzer, ASan and UBSan, and run it:
#   tests/fuzz/run.sh [seconds] [workers]           the RW612 protocol code (fuzz_rw612_proto.c); default 600 s, 8
#   STM32=1 tests/fuzz/run.sh [seconds] [workers]   the STM32H573 partition on PC stand-ins (stm32/)
# Needs clang (with libFuzzer) and the mldsa-native / mlkem-native v2.0.0 trees (MLDSA_NATIVE_DIR, MLKEM_NATIVE_DIR).
# Work files go to $FUZZ_OUT (default: a temporary directory); a crash is saved there as crash-<hash>.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
TOOLS=${AEGIS_TOOLS:-$HOME/aegis-tools}
MLDSA=${MLDSA_NATIVE_DIR:-$TOOLS/mldsa-native/mldsa}
MLKEM=${MLKEM_NATIVE_DIR:-$TOOLS/mlkem-native/mlkem}
PROVER=$ROOT/endpoints/rw612/prover
PART=$ROOT/endpoints/stm32h573/tfm-aegis-partition
OUT=${FUZZ_OUT:-$(mktemp -d)}
SECS=${1:-600}
WORKERS=${2:-8}
mkdir -p "$OUT/corpus"
SAN="-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer"
INC="-I$PROVER/src -I$PART -I$PART/mldsa -I$MLDSA -I$PART/mlkem -I$MLKEM"
cc() { clang -g -D_GNU_SOURCE -DMLD_CONFIG_FILE='"aegis_mldsa_config.h"' $INC "$@"; }
# the code under test with the sanitizers and coverage; the crypto libraries with the sanitizers only (faster)
cc -O1 $SAN -c "$HERE/fuzz_rw612_proto.c" -o "$OUT/h.o"
cc -O1 $SAN -c "$PROVER/src/sha256.c" -o "$OUT/sha256.o"
cc -O1 $SAN -c "$PART/aegis_kmac.c" -o "$OUT/kmac.o"
cc -O2 -fsanitize=address,undefined -c "$PART/mlkem_unit.c" -o "$OUT/mlkem.o"
cc -O2 -fsanitize=address,undefined -c "$MLDSA/mldsa_native.c" -o "$OUT/mldsa.o"
clang $SAN "$OUT"/h.o "$OUT"/sha256.o "$OUT"/kmac.o "$OUT"/mlkem.o "$OUT"/mldsa.o -o "$OUT/fuzz_target"
if [ "${STM32:-0}" = 1 ]; then
	# the partition pins a test gateway key whose secret key the harness holds
	cc -O2 -c "$HERE/stm32/gen_gw_pk.c" -o "$OUT/gen.o"
	clang "$OUT/gen.o" "$OUT/mldsa.o" -fsanitize=address,undefined -o "$OUT/gen_gw_pk"
	"$OUT/gen_gw_pk" > "$OUT/fz_gateway_pk.h"
	clang -g -O1 $SAN -D_GNU_SOURCE -DMLD_CONFIG_FILE='"aegis_mldsa_config.h"' \
		-DAEGIS_GATEWAY_PK_HEADER='"fz_gateway_pk.h"' -I"$OUT" -I"$HERE/stm32/stub" $INC \
		-c "$HERE/stm32/fuzz_stm32_partition.c" -o "$OUT/h.o"
	clang $SAN "$OUT"/h.o "$OUT"/kmac.o "$OUT"/mlkem.o "$OUT"/mldsa.o -o "$OUT/fuzz_target"
	cp "$HERE"/stm32/seeds/* "$OUT/corpus/"
else
	cp "$HERE"/seeds/* "$OUT/corpus/"
fi
cd "$OUT"
./fuzz_target -dict="$HERE/proto.dict" -max_len=16384 -max_total_time="$SECS" -timeout=20 -rss_limit_mb=4096 \
	-print_final_stats=1 -jobs="$WORKERS" -workers="$WORKERS" corpus

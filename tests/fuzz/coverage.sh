#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Line coverage reached by a fuzz corpus (clang source-based coverage):
#   tests/fuzz/coverage.sh <corpus dir> [<out dir>]            endpoints/rw612/prover/src/aegis_proto.c
#   STM32=1 tests/fuzz/coverage.sh <corpus dir> [<out dir>]    endpoints/stm32h573/tfm-aegis-partition/aegis_pq_attest.c
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
TOOLS=${AEGIS_TOOLS:-$HOME/aegis-tools}
MLDSA=${MLDSA_NATIVE_DIR:-$TOOLS/mldsa-native/mldsa}
MLKEM=${MLKEM_NATIVE_DIR:-$TOOLS/mlkem-native/mlkem}
PROVER=$ROOT/endpoints/rw612/prover
PART=$ROOT/endpoints/stm32h573/tfm-aegis-partition
CORPUS=$1
OUT=${2:-$(mktemp -d)}
INC="-I$PROVER/src -I$PART -I$PART/mldsa -I$MLDSA -I$PART/mlkem -I$MLKEM"
cc() { clang -g -D_GNU_SOURCE -DMLD_CONFIG_FILE='"aegis_mldsa_config.h"' $INC "$@"; }
mkdir -p "$OUT"
cc -O2 -c "$PROVER/src/sha256.c" -o "$OUT/sha256.o"
cc -O2 -c "$PART/aegis_kmac.c" -o "$OUT/kmac.o"
cc -O2 -c "$PART/mlkem_unit.c" -o "$OUT/mlkem.o"
cc -O2 -c "$MLDSA/mldsa_native.c" -o "$OUT/mldsa.o"
if [ "${STM32:-0}" = 1 ]; then
	SRC=$PART/aegis_pq_attest.c
	cc -O2 -c "$HERE/stm32/gen_gw_pk.c" -o "$OUT/gen.o"
	clang "$OUT/gen.o" "$OUT/mldsa.o" -o "$OUT/gen_gw_pk"
	"$OUT/gen_gw_pk" > "$OUT/fz_gateway_pk.h"
	cc -O1 -fsanitize=fuzzer -fprofile-instr-generate -fcoverage-mapping -DAEGIS_GATEWAY_PK_HEADER='"fz_gateway_pk.h"' \
		-I"$OUT" -I"$HERE/stm32/stub" -c "$HERE/stm32/fuzz_stm32_partition.c" -o "$OUT/h.o"
	clang -fsanitize=fuzzer -fprofile-instr-generate "$OUT"/h.o "$OUT"/kmac.o "$OUT"/mlkem.o "$OUT"/mldsa.o -o "$OUT/cov"
else
	SRC=$PROVER/src/aegis_proto.c
	cc -O1 -fsanitize=fuzzer -fprofile-instr-generate -fcoverage-mapping -c "$HERE/fuzz_rw612_proto.c" -o "$OUT/h.o"
	clang -fsanitize=fuzzer -fprofile-instr-generate "$OUT"/h.o "$OUT"/sha256.o "$OUT"/kmac.o "$OUT"/mlkem.o \
		"$OUT"/mldsa.o -o "$OUT/cov"
fi
LLVM_PROFILE_FILE="$OUT/cov.profraw" "$OUT/cov" -runs=0 "$CORPUS" > "$OUT/run.log" 2>&1
llvm-profdata-18 merge -sparse "$OUT/cov.profraw" -o "$OUT/cov.profdata"
llvm-cov-18 report "$OUT/cov" -instr-profile="$OUT/cov.profdata" "$SRC"
llvm-cov-18 show "$OUT/cov" -instr-profile="$OUT/cov.profdata" "$SRC" -show-line-counts-or-regions > "$OUT/source.cov.txt"
echo "line by line: source.cov.txt in the output directory" >&2

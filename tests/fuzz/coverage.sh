#!/bin/sh
# Line coverage of endpoints/rw612/prover/src/aegis_proto.c reached by a fuzz corpus (clang source-based coverage).
#   tests/fuzz/coverage.sh <corpus dir> [<out dir>]
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
cc -O1 -fsanitize=fuzzer -fprofile-instr-generate -fcoverage-mapping -c "$HERE/fuzz_rw612_proto.c" -o "$OUT/h.o"
cc -O2 -c "$PROVER/src/sha256.c" -o "$OUT/sha256.o"
cc -O2 -c "$PART/aegis_kmac.c" -o "$OUT/kmac.o"
cc -O2 -c "$PART/mlkem_unit.c" -o "$OUT/mlkem.o"
cc -O2 -c "$MLDSA/mldsa_native.c" -o "$OUT/mldsa.o"
clang -fsanitize=fuzzer -fprofile-instr-generate "$OUT"/*.o -o "$OUT/cov"
LLVM_PROFILE_FILE="$OUT/cov.profraw" "$OUT/cov" -runs=0 "$CORPUS" > "$OUT/run.log" 2>&1
llvm-profdata-18 merge -sparse "$OUT/cov.profraw" -o "$OUT/cov.profdata"
llvm-cov-18 report "$OUT/cov" -instr-profile="$OUT/cov.profdata" "$PROVER/src/aegis_proto.c"
llvm-cov-18 show "$OUT/cov" -instr-profile="$OUT/cov.profdata" "$PROVER/src/aegis_proto.c" -show-line-counts-or-regions \
	> "$OUT/aegis_proto.cov.txt"
echo "line by line: aegis_proto.cov.txt in the output directory" >&2

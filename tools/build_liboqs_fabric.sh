#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Build liboqs 0.16.0 for the PolarFire's RISC-V Linux with every Keccak-f[1600] permutation
# routed through the aegis_pqc fabric core when AEGIS_PQC_KECCAK=hw|check is set
# (gateway/pqc/aegis_pqc_drv.c). Works on a copy of the liboqs source; the pristine tree and
# the normal build are not changed.
#   tools/build_liboqs_fabric.sh  ->  ~/aegis-tools/liboqs-rv64-fabric/
set -eu
REPO=$(cd "$(dirname "$0")/.." && pwd)
T=${AEGIS_TOOLS:-$HOME/aegis-tools}
SRC=$T/liboqs-src-fabric
OUT=$T/liboqs-rv64-fabric
rm -rf "$SRC" "$OUT"
mkdir -p "$SRC"
(cd "$T/liboqs-src" && tar cf - --exclude=./build --exclude=./.git .) | (cd "$SRC" && tar xf -)
python3 - "$SRC" "$REPO" <<'EOF'
import sys
src, repo = sys.argv[1], sys.argv[2]
f = src + "/src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c"
s = open(f).read()
old_perm = "void KeccakP1600_Permute_24rounds(void *state) {"
assert s.count(old_perm) == 1
s = s.replace(old_perm, "static void KeccakP1600_Permute_24rounds_sw(void *state) {")
i = s.index("size_t KeccakF1600_FastLoop_Absorb(void *state, unsigned int laneCount, const unsigned char *data, size_t dataByteLen) {")
j = s.index("size_t KeccakP1600_12rounds_FastLoop_Absorb")
s = s[:i] + """/* Aegis: absorb through the (possibly fabric-backed) permutation, one block at a time. */
size_t KeccakF1600_FastLoop_Absorb(void *state, unsigned int laneCount, const unsigned char *data, size_t dataByteLen) {
	size_t originalDataByteLen = dataByteLen;

	while (dataByteLen >= laneCount * 8) {
		KeccakP1600_AddLanes(state, data, laneCount);
		KeccakP1600_Permute_24rounds(state);
		data += laneCount * 8;
		dataByteLen -= laneCount * 8;
	}
	return originalDataByteLen - dataByteLen;
}

""" + s[j:]
s += """
/* Aegis: dispatch to the aegis_pqc fabric core when enabled (see gateway/pqc/aegis_pqc_drv.c). */
int aegis_pqc_keccak_hook(void *state, void (*sw)(void *));
void KeccakP1600_Permute_24rounds(void *state) {
	if (!aegis_pqc_keccak_hook(state, KeccakP1600_Permute_24rounds_sw)) {
		KeccakP1600_Permute_24rounds_sw(state);
	}
}
"""
open(f, "w").write(s)
c = src + "/src/common/sha3/xkcp_low/CMakeLists.txt"
t = open(c).read()
key = "KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c"
assert key in t
t = t.replace(key, key + " " + repo + "/gateway/pqc/aegis_pqc_drv.c", 1)
open(c, "w").write(t)
print("patched", f)
EOF
grep -n 'plain-64bits/KeccakP-1600-opt64.c' "$SRC/src/common/sha3/xkcp_low/CMakeLists.txt"
PATH="$REPO/.venv/bin:$PATH" cmake -S "$SRC" -B "$OUT" -GNinja -DCMAKE_TOOLCHAIN_FILE="$T/riscv64.cmake" \
  -DCMAKE_BUILD_TYPE=Release -DOQS_USE_OPENSSL=OFF -DBUILD_SHARED_LIBS=ON -DOQS_DIST_BUILD=OFF \
  -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65" \
  -DCMAKE_C_FLAGS="-I$REPO/gateway/pqc" > "$T/liboqs-rv64-fabric.log" 2>&1
PATH="$REPO/.venv/bin:$PATH" ninja -C "$OUT" >> "$T/liboqs-rv64-fabric.log" 2>&1
ls -l "$OUT/lib/liboqs.so.9" "$OUT/tests/kat_kem" "$OUT/tests/kat_sig"

#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Count the Keccak-f[1600] permutations of each ML-KEM-768 and ML-DSA-65 operation in liboqs 0.16.0, by sponge phase
# (absorb or squeeze), rate (168 = SHAKE128, 136 = SHAKE256/SHA3-256, 72 = SHA3-512) and API (one-way or four-way).
# Builds a portable x86 copy of liboqs with the same permutation hook as the fabric build (tools/build_liboqs_fabric.sh),
# plus phase tags in the sponge code; the pristine tree is not changed. Output feeds tools/accel/cost_model.py.
#   tools/accel/profile_keccak.sh [runs]  ->  build/accel/keccak-profile.json
set -eu
REPO=$(cd "$(dirname "$0")/../.." && pwd)
T=${AEGIS_TOOLS:-$HOME/aegis-tools}
SRC=$T/liboqs-src-profile
OUT=$T/liboqs-x86-profile
RUNS=${1:-200}
rm -rf "$SRC" "$OUT"; mkdir -p "$SRC" "$REPO/build/accel"
(cd "$T/liboqs-src" && tar cf - --exclude=./build --exclude=./.git .) | (cd "$SRC" && tar xf -)
python3 - "$SRC" <<'PY'
import sys
src = sys.argv[1]
f = src + "/src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c"
s = open(f).read()
s = s.replace("void KeccakP1600_Permute_24rounds(void *state) {", "static void KeccakP1600_Permute_24rounds_sw(void *state) {", 1)
i = s.index("size_t KeccakF1600_FastLoop_Absorb(void *state, unsigned int laneCount, const unsigned char *data, size_t dataByteLen) {")
j = s.index("size_t KeccakP1600_12rounds_FastLoop_Absorb")
s = s[:i] + """size_t KeccakF1600_FastLoop_Absorb(void *state, unsigned int laneCount, const unsigned char *data, size_t dataByteLen) {
	size_t n = dataByteLen;
	while (dataByteLen >= laneCount * 8) {
		KeccakP1600_AddLanes(state, data, laneCount);
		KeccakP1600_Permute_24rounds(state);
		data += laneCount * 8;
		dataByteLen -= laneCount * 8;
	}
	return n - dataByteLen;
}

""" + s[j:]
s += """
int aegis_pqc_keccak_hook(void *state, void (*sw)(void *));
void KeccakP1600_Permute_24rounds(void *state) {
	if (!aegis_pqc_keccak_hook(state, KeccakP1600_Permute_24rounds_sw)) KeccakP1600_Permute_24rounds_sw(state);
}
"""
open(f, "w").write(s)
# phase tags: absorb / squeeze, with the rate, in the one-way and four-way sponge code
for name, x4 in (("xkcp_sha3.c", 0), ("xkcp_sha3x4.c", 1)):
    p = src + "/src/common/sha3/" + name
    t = open(p).read()
    pre = "keccak_x4_inc_" if x4 else "keccak_inc_"
    for fn, ph in (("absorb", 1), ("squeeze", 2)):
        k = t.index("static void " + pre + fn + "(")
        b = t.index("{", k) + 1
        t = t[:b] + "\n\taegis_prof_phase(%d, (int)r, %d);" % (ph, x4) + t[b:]
    t = "void aegis_prof_phase(int phase, int rate, int x4);\n" + t
    open(p, "w").write(t)
c = src + "/src/common/sha3/xkcp_low/CMakeLists.txt"
t = open(c).read()
key = "KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c"
t = t.replace(key, key + " " + src + "/aegis_prof.c", 1)
open(c, "w").write(t)
open(src + "/aegis_prof.c", "w").write(r'''
#include <stdio.h>
/* permutation counters by [phase][rate class][x4]; rate class 0=168 1=136 2=72 3=other */
unsigned long aegis_prof[3][4][2], aegis_calls[3][4][2];
static int cur_phase, cur_rate, cur_x4, counted;
void aegis_prof_phase(int phase, int rate, int x4) { cur_phase = phase; cur_rate = rate; cur_x4 = x4; counted = 0; }
static int rc(int r) { return r == 168 ? 0 : r == 136 ? 1 : r == 72 ? 2 : 3; }
/* a "call" is one absorb or squeeze call that permutes at least once; perms/calls = blocks per call (batch size) */
int aegis_pqc_keccak_hook(void *state, void (*sw)(void *)) {
	(void)state; (void)sw;
	aegis_prof[cur_phase][rc(cur_rate)][cur_x4]++;
	if (!counted) { aegis_calls[cur_phase][rc(cur_rate)][cur_x4]++; counted = 1; }
	return 0;
}
''')
PY
# x4 squeeze of the serial backend calls the one-way permutation: the tag of the last phase call stays valid
PATH="$REPO/.venv/bin:$PATH" cmake -S "$SRC" -B "$OUT" -GNinja -DCMAKE_BUILD_TYPE=Release -DOQS_USE_OPENSSL=OFF \
  -DBUILD_SHARED_LIBS=OFF -DOQS_DIST_BUILD=OFF -DOQS_OPT_TARGET=generic \
  -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65" > "$OUT.log" 2>&1
PATH="$REPO/.venv/bin:$PATH" ninja -C "$OUT" oqs >> "$OUT.log" 2>&1
cc -O2 -I"$OUT/include" "$REPO/tools/accel/profile_main.c" "$OUT/lib/liboqs.a" -o "$OUT/profile"
"$OUT/profile" "$RUNS" > "$REPO/build/accel/keccak-profile.json"
cat "$REPO/build/accel/keccak-profile.json"

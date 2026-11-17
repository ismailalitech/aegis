#!/bin/sh
# Build liboqs 0.16.0 with the aegis_pqc2 SHA-3 provider (gateway/pqc/aegis_sponge_drv.c) and its PC model linked in.
# The provider installs itself only when AEGIS_PQC_SPONGE is set (model | hw); otherwise the library is plain liboqs.
# Works on a copy of the liboqs source; the pristine tree and the other builds are not changed.
#   tools/build_liboqs_sponge.sh x86     ->  ~/aegis-tools/liboqs-x86-sponge/   (tests on the PC with the model)
#   tools/build_liboqs_sponge.sh rv64    ->  ~/aegis-tools/liboqs-rv64-sponge/  (the gateway)
set -eu
REPO=$(cd "$(dirname "$0")/.." && pwd)
T=${AEGIS_TOOLS:-$HOME/aegis-tools}
ARCH=${1:-x86}
SRC=$T/liboqs-src-sponge
OUT=$T/liboqs-$ARCH-sponge
rm -rf "$SRC" "$OUT"
mkdir -p "$SRC"
(cd "$T/liboqs-src" && tar cf - --exclude=./build --exclude=./.git .) | (cd "$SRC" && tar xf -)
python3 - "$SRC" "$REPO" <<'PY'
import sys
src, repo = sys.argv[1], sys.argv[2]
c = src + "/src/common/CMakeLists.txt"
t = open(c).read()
key = "${SHA3_IMPL} sha3/sha3.c sha3/sha3x4.c"
assert t.count(key) >= 1
add = " %s/gateway/pqc/aegis_sponge_drv.c %s/gateway/pqc/aegis_sponge_model.c" % (repo, repo)
t = t.replace(key, key + add)
open(c, "w").write(t)
# static links (liboqs' own tests link its objects directly) only take archive members that are referenced: reference
# the provider from sha3.c so its constructor comes along wherever SHA-3 does
f = src + "/src/common/sha3/sha3.c"
open(f, "a").write("""
/* Aegis: keep the aegis_pqc2 SHA-3 provider (gateway/pqc/aegis_sponge_drv.c) and its constructor in static links */
extern void aegis_sponge_anchor(void);
void (*const aegis_sponge_link)(void) = aegis_sponge_anchor;
""")
PY
X=""
[ "$ARCH" = rv64 ] && X="-DCMAKE_TOOLCHAIN_FILE=$T/riscv64.cmake"
[ "$ARCH" = x86 ] && X="-DOQS_OPT_TARGET=generic"
# shellcheck disable=SC2086
PATH="$REPO/.venv/bin:$PATH" cmake -S "$SRC" -B "$OUT" -GNinja $X -DCMAKE_BUILD_TYPE=Release -DOQS_USE_OPENSSL=OFF \
  -DBUILD_SHARED_LIBS=ON -DOQS_DIST_BUILD=OFF -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65" \
  -DCMAKE_C_FLAGS="-I$REPO/gateway/pqc" > "$OUT.log" 2>&1
PATH="$REPO/.venv/bin:$PATH" ninja -C "$OUT" >> "$OUT.log" 2>&1
ls -l "$OUT/lib/liboqs.so"* "$OUT/tests/test_sha3" "$OUT/tests/kat_kem" "$OUT/tests/kat_sig" | awk '{print $NF}'

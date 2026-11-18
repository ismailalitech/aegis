#!/bin/sh
# PC tests of the OP-TEE side of the ZynqMP endpoint (gcc, ASan and UBSan):
#   endpoints/zynqmp/optee/tests/run.sh
# 1. The hand-off checks of the OP-TEE patch (../os-patches). Takes the Aegis files out of the patches into a
#    temporary directory, checks that the two interface headers in there are the repository's
#    (../../handoff/aegis_zynqmp_handoff.h, ../include/aegis_boot_pta.h), builds test_handoff_parse.c with them and
#    runs it, also on a page whose digest Python computed.
# 2. The keys OP-TEE takes from the seed (aegis_handoff_kdf.c of the patch, test_handoff_kdf.c) against values from
#    Python's hmac module.
# 3. The TA (../ta/aegis_ta.c) with the real protocol code on a stand-in for OP-TEE (stub/, test_ta.c), with the
#    limits of ../ta/sub.mk: profiles, measurements, and the ML-DSA-65 key, which without a seed of the chip's must
#    be the one the board had in phase A. Needs the mldsa-native / mlkem-native v2.0.0 trees, as tests/fuzz/run.sh.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OPTEE=$(cd "$HERE/.." && pwd)
ROOT=$(cd "$OPTEE/../../.." && pwd)
TOOLS=${AEGIS_TOOLS:-$HOME/aegis-tools}
MLDSA=${MLDSA_NATIVE_DIR:-$TOOLS/mldsa-native/mldsa}
MLKEM=${MLKEM_NATIVE_DIR:-$TOOLS/mlkem-native/mlkem}
PROVER=$ROOT/endpoints/rw612/prover/src
PART=$ROOT/endpoints/stm32h573/tfm-aegis-partition
T=$(mktemp -d)
SRC=$T/core/arch/arm/plat-zynqmp
for p in "$OPTEE"/os-patches/*.patch; do
	(cd "$T" && GIT_CEILING_DIRECTORIES=$(dirname "$T") git apply --include='core/arch/arm/plat-zynqmp/aegis_*' "$p")
done
cmp "$SRC/aegis_zynqmp_handoff.h" "$OPTEE/../handoff/aegis_zynqmp_handoff.h"
cmp "$SRC/aegis_boot_pta.h" "$OPTEE/include/aegis_boot_pta.h"
python3 - "$T/page.bin" <<'PY'
import hashlib, struct, sys
def meas(label, value, length, attrib):
    return struct.pack("<16s32sII", label, value, length, attrib)
body = struct.pack("<8I", 0x48474541, 1, 3, 2, 0x11223344, 0x55667788, 0, 0) + bytes(range(32))
body += meas(b"FSBL", b"\xaa" * 32, 123456, 0x815) + meas(b"TEE", b"\xbb" * 32, 482776, 0x117)
body += bytes(6 * 56)
assert len(body) == 512
page = body + hashlib.sha3_384(body).digest()
open(sys.argv[1], "wb").write(page + bytes(4096 - len(page)))
PY
gcc -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-sanitize-recover=undefined \
	-I"$SRC" -I"$OPTEE/include" "$HERE/test_handoff_parse.c" "$SRC/aegis_handoff_parse.c" -o "$T/test_handoff_parse"
"$T/test_handoff_parse" "$T/page.bin"

python3 - > "$T/kdf_kat.h" <<'PY'
import hashlib, hmac, struct
def mac(key, msg): return hmac.new(key, msg, hashlib.sha256).digest()
def c(name, b): print("#define %s { %s }" % (name, ", ".join("0x%02x" % x for x in b)))
seed = bytes(range(0x40, 0x60))
root = mac(seed, b"aegis-zynqmp-optee-subkey-root-v1")
uuid = struct.pack("<IHH8B", 0xb56a99ca, 0x1c3c, 0x40c8, 0xaf, 0x55, 0xb8, 0xdd, 0x5e, 0xe0, 0x32, 0x13)
data = uuid + b"aegis-zynqmp-mldsa65-seed-v1"
c("KAT_SEED", seed)
c("KAT_ROOT", root)
c("KAT_HUK", mac(seed, b"aegis-zynqmp-optee-huk-v1")[:16])
c("KAT_TA_DATA", data)
c("KAT_SUBKEY_TA", mac(root, struct.pack("<I", 3) + data))
c("KAT_SUBKEY_SSK", mac(root, struct.pack("<I", 1)))
c("KAT_SUBKEY_BIG_USAGE", mac(root, bytes([1, 2, 3, 4])))
PY
gcc -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-sanitize-recover=undefined \
	-I"$SRC" -I"$T" -I"$HERE" -I"$PROVER" "$HERE/test_handoff_kdf.c" "$SRC/aegis_handoff_kdf.c" "$PROVER/sha256.c" \
	-o "$T/test_handoff_kdf"
"$T/test_handoff_kdf"

LIMITS=$(grep -o -e '-DAEGIS_MAX_MEASUREMENTS=[0-9]*' -e '-DAEGIS_CLAIMS_MAX=[0-9]*u' "$OPTEE/ta/sub.mk" | tr '\n' ' ')
[ "$(echo $LIMITS | wc -w)" = 2 ]
echo '#define AEGIS_GATEWAY_PK { 0 }' > "$T/gateway_pk.h"
SAN="-fsanitize=address,undefined -fno-sanitize-recover=undefined"
cc() {
	gcc -std=gnu11 -g -D_GNU_SOURCE $SAN $LIMITS -DMLD_CONFIG_FILE='"aegis_mldsa_config.h"' \
		-DAEGIS_DEVICE_FW='"zynqmp-optee"' -DAEGIS_DEVICE_VERSION='"0.1.0"' \
		-I"$HERE/stub" -I"$HERE" -I"$T" -I"$SRC" -I"$OPTEE/ta" -I"$OPTEE/include" -I"$OPTEE/../handoff" \
		-I"$PROVER" -I"$PART" -I"$PART/mldsa" -I"$MLDSA" -I"$PART/mlkem" -I"$MLKEM" "$@"
}
cc -O1 -Wall -Wextra -Werror -c "$HERE/test_ta.c" -o "$T/test_ta.o"
cc -O1 -Wall -Wextra -Werror -c "$OPTEE/ta/aegis_ta.c" -o "$T/aegis_ta.o"
cc -O1 -Wall -Wextra -Werror -c "$SRC/aegis_handoff_kdf.c" -o "$T/kdf.o"
cc -O1 -Wno-deprecated-declarations -c "$PROVER/aegis_proto.c" -o "$T/proto.o"
cc -O1 -c "$PROVER/sha256.c" -o "$T/sha256.o"
cc -O1 -c "$PART/aegis_kmac.c" -o "$T/kmac.o"
cc -O2 -c "$PART/mlkem_unit.c" -o "$T/mlkem.o"
cc -O2 -c "$MLDSA/mldsa_native.c" -o "$T/mldsa.o"
gcc $SAN "$T"/test_ta.o "$T"/aegis_ta.o "$T"/kdf.o "$T"/proto.o "$T"/sha256.o "$T"/kmac.o "$T"/mlkem.o "$T"/mldsa.o -o "$T/test_ta"
"$T/test_ta"

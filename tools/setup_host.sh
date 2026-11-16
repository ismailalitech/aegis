#!/bin/sh
# Rebuild the Aegis host tool set without root. Everything goes under
# $AEGIS_TOOLS (default ~/aegis-tools) and the repo's .venv; nothing system-wide.
# Undo: rm -rf ~/aegis-tools <repo>/.venv ~/.local/share/cmsis-pack-manager/Keil/STM32H5xx_DFP
set -eu
REPO=$(cd "$(dirname "$0")/.." && pwd)
T=${AEGIS_TOOLS:-$HOME/aegis-tools}
mkdir -p "$T"

# 1. Python venv (Ubuntu's python3 lacks ensurepip, so bootstrap pip)
if [ ! -x "$REPO/.venv/bin/pip" ]; then
  python3 -m venv --without-pip "$REPO/.venv"
  curl -sSfL -o "$T/get-pip.py" https://bootstrap.pypa.io/get-pip.py
  "$REPO/.venv/bin/python" "$T/get-pip.py" -q
fi
"$REPO/.venv/bin/pip" install -q pyocd cmake ninja cryptography pytest requests pyyaml

# 2. Arm GNU toolchain 14.2.rel1 (checked against Arm's published SHA-256)
ARM=arm-gnu-toolchain-14.2.rel1-x86_64-arm-none-eabi
if [ ! -x "$T/$ARM/bin/arm-none-eabi-gcc" ]; then
  U=https://developer.arm.com/-/media/Files/downloads/gnu/14.2.rel1/binrel/$ARM.tar.xz
  curl -sSfL -o "$T/$ARM.tar.xz" "$U"
  echo "62a63b981fe391a9cbad7ef51b17e49aeaa3e7b0d029b36ca1e9c3b2a9b78823  $T/$ARM.tar.xz" | sha256sum -c -
  tar -C "$T" -xf "$T/$ARM.tar.xz" && rm "$T/$ARM.tar.xz"
fi

# 3. STM32H5 device pack for pyocd
"$REPO/.venv/bin/pyocd" pack install stm32h573iitx

# 4. liboqs 0.16.0 (commit 5a1a854b), ML-KEM and ML-DSA only
if [ ! -f "$T/liboqs/lib/liboqs.so" ]; then
  git clone -q --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs.git "$T/liboqs-src"
  PATH="$REPO/.venv/bin:$PATH" cmake -S "$T/liboqs-src" -B "$T/liboqs-src/build" -GNinja \
    -DCMAKE_INSTALL_PREFIX="$T/liboqs" -DBUILD_SHARED_LIBS=ON \
    -DOQS_MINIMAL_BUILD="KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024;SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87"
  PATH="$REPO/.venv/bin:$PATH" ninja -C "$T/liboqs-src/build" install
fi

# 5. NIST ACVP vectors (checked against the recorded SHA256SUMS)
(cd "$REPO/vectors/acvp" && sha256sum -c --quiet SHA256SUMS) || {
  echo "ACVP vectors missing or changed; re-fetch with tools/fetch_acvp.sh" >&2; exit 1; }
echo "host tools ready in $T"

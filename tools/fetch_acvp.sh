#!/bin/sh
# Fetch NIST ACVP JSON vectors for ML-KEM (FIPS 203) and ML-DSA (FIPS 204)
# from usnistgov/ACVP-Server tag v1.1.0.41, then check them against SHA256SUMS.
set -eu
cd "$(dirname "$0")/../vectors/acvp"
R=https://raw.githubusercontent.com/usnistgov/ACVP-Server/refs/tags/v1.1.0.41/gen-val/json-files
for d in ML-KEM-keyGen-FIPS203 ML-KEM-encapDecap-FIPS203 ML-DSA-keyGen-FIPS204 ML-DSA-sigGen-FIPS204 ML-DSA-sigVer-FIPS204; do
  for f in internalProjection prompt expectedResults; do
    curl -sSfL -o "$d-$f.json" "$R/$d/$f.json"
  done
done
sha256sum -c --quiet SHA256SUMS && echo "ACVP vectors OK"

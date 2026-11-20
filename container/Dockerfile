# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
#
# Aegis evaluation container: the verifier, a simulated device on the Prover SDK, the gateway's quote service and
# its PC verifier, the standalone evidence and audit checkers and the host test suite, without any hardware.
# container/README.md has the commands and the expected output. Build from the repository root:
#   docker build -f container/Dockerfile -t aegis-eval .
#   docker run --rm --network none aegis-eval
#
# Pinned: the base image by digest, the Ubuntu packages by an archive snapshot (snapshot.ubuntu.com), the Python
# packages by version and wheel hash (container/requirements.txt), mldsa-native, mlkem-native and liboqs by tag and
# commit. Everything is fetched at build time; running needs no network.

ARG BASE_IMAGE=ubuntu:24.04@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289

# ---- stage 1: the third-party sources, checked out at pinned commits, and liboqs built -----------------------------
FROM ${BASE_IMAGE} AS tools
ARG UBUNTU_SNAPSHOT=20261115T000000Z
ARG MLDSA_NATIVE_COMMIT=834a90d5e846ffa1e1611bd24e160bb2e9b86d35
ARG MLKEM_NATIVE_COMMIT=d1b2fe782888bdb761a50336012923180be7f502
ARG LIBOQS_COMMIT=5a1a854b0dc9f2141bdc771c555ee60c37950183
ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/sh", "-eux", "-c"]
# The package versions are pinned by the archive snapshot, not one by one (DL3008). snapshot.ubuntu.com is HTTPS only
# and the base image has no CA bundle, so ca-certificates comes first from the live archive; then the snapshot is
# enabled, and an index that fails to download fails the build (APT::Update::Error-Mode=any) instead of a warning.
# hadolint ignore=DL3008
RUN apt-get update -o APT::Update::Error-Mode=any; \
    apt-get install -y --no-install-recommends ca-certificates; \
    if [ -n "$UBUNTU_SNAPSHOT" ]; then echo "APT::Snapshot \"$UBUNTU_SNAPSHOT\";" > /etc/apt/apt.conf.d/50snapshot; fi; \
    rm -rf /var/lib/apt/lists/*; \
    apt-get update -o APT::Update::Error-Mode=any; \
    apt-get install -y --no-install-recommends ca-certificates git build-essential cmake ninja-build; \
    rm -rf /var/lib/apt/lists/*
WORKDIR /opt/aegis-tools
# fetch <repository> <tag> <directory> <commit>: a shallow clone of the tag, refused unless it is that commit
RUN fetch() { \
        git clone -q --depth 1 --branch "$2" "$1" "$3"; \
        test "$(git -C "$3" rev-parse HEAD)" = "$4" || { echo "$3: $2 is not commit $4" >&2; exit 1; }; \
        echo "$2 $4" > "$3.commit"; rm -rf "$3/.git"; \
    }; \
    fetch https://github.com/pq-code-package/mldsa-native.git v2.0.0 mldsa-native "$MLDSA_NATIVE_COMMIT"; \
    fetch https://github.com/pq-code-package/mlkem-native.git v2.0.0 mlkem-native "$MLKEM_NATIVE_COMMIT"; \
    fetch https://github.com/open-quantum-safe/liboqs.git 0.16.0 liboqs-src "$LIBOQS_COMMIT"
# liboqs with ML-KEM and ML-DSA only, as CI builds it (.github/workflows/ci.yml); some host tests cross-check with it
RUN cmake -S liboqs-src -B liboqs-src/build -GNinja -DCMAKE_INSTALL_PREFIX=/opt/aegis-tools/liboqs \
        -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_MINIMAL_BUILD="KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024;SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87"; \
    ninja -C liboqs-src/build install > /dev/null; \
    rm -rf liboqs-src/build

# ---- stage 2: the evaluation image ----------------------------------------------------------------------------------
FROM ${BASE_IMAGE}
ARG UBUNTU_SNAPSHOT=20261115T000000Z
ARG REVISION=unknown
LABEL org.opencontainers.image.title="aegis-eval" \
      org.opencontainers.image.description="Aegis post-quantum attestation: evaluation without hardware" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.revision="${REVISION}"
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1
SHELL ["/bin/sh", "-eux", "-c"]
# gcc, make and cmake stay: the tests and the example build the SDK's C code at run time. The apt sequence is stage
# 1's (ca-certificates from the live archive, then the snapshot). aegisd's Linux identity is bound to the machine id
# (hashed, never published); an image must not carry one, or every container would share it: /etc/machine-id is a
# link to /tmp/machine-id, which container/evaluate.sh fills with a new random id when each container starts.
# hadolint ignore=DL3008
RUN apt-get update -o APT::Update::Error-Mode=any; \
    apt-get install -y --no-install-recommends ca-certificates; \
    if [ -n "$UBUNTU_SNAPSHOT" ]; then echo "APT::Snapshot \"$UBUNTU_SNAPSHOT\";" > /etc/apt/apt.conf.d/50snapshot; fi; \
    rm -rf /var/lib/apt/lists/*; \
    apt-get update -o APT::Update::Error-Mode=any; \
    apt-get install -y --no-install-recommends build-essential cmake python3 python3-venv openssl ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    rm -f /etc/machine-id; \
    ln -s /tmp/machine-id /etc/machine-id
COPY container/requirements.txt /opt/aegis-requirements.txt
RUN python3 -m venv /opt/venv; \
    /opt/venv/bin/pip install --require-hashes --no-deps --only-binary=:all: -r /opt/aegis-requirements.txt; \
    /opt/venv/bin/pip check; \
    /opt/venv/bin/python -c "from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem; import pycose, cbor2"
# a user without privileges; the tools in its home, where the tests look for them (~/aegis-tools)
RUN useradd --create-home --uid 10001 --shell /bin/sh aegis
COPY --from=tools /opt/aegis-tools /home/aegis/aegis-tools
COPY --chown=aegis:aegis . /home/aegis/aegis
RUN ln -s /opt/venv /home/aegis/aegis/.venv; \
    echo "${REVISION}" > /home/aegis/aegis/container/REVISION; \
    chown -h aegis:aegis /home/aegis/aegis/.venv /home/aegis/aegis/container/REVISION
USER 10001:10001
WORKDIR /home/aegis/aegis
ENV HOME=/home/aegis \
    AEGIS_TOOLS=/home/aegis/aegis-tools \
    AEGIS_LIBOQS=/home/aegis/aegis-tools/liboqs/lib/liboqs.so.9 \
    PATH=/opt/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENTRYPOINT ["container/evaluate.sh"]
CMD ["all"]

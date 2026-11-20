# SPDX-License-Identifier: Apache-2.0
# Aegis post-quantum attestation partition (out-of-tree TF-M secure partition): the Prover SDK's core (sdk/) and this
# chip's port of it (aegis_pq_attest.c).
cmake_minimum_required(VERSION 3.21)

set(AEGIS_SDK ${CMAKE_CURRENT_LIST_DIR}/../../../sdk)

set(MLDSA_NATIVE_DIR "$ENV{HOME}/aegis-tools/mldsa-native/mldsa" CACHE PATH "mldsa-native v2.0.0 mldsa/ directory")
set(MLKEM_NATIVE_DIR "$ENV{HOME}/aegis-tools/mlkem-native/mlkem" CACHE PATH "mlkem-native v2.0.0 mlkem/ directory")
set(AEGIS_GEN ${CMAKE_BINARY_DIR}/generated/aegis_pq_attest)

add_library(tfm_psa_rot_partition_aegis_pq STATIC)
add_dependencies(tfm_psa_rot_partition_aegis_pq manifest_tool)

target_sources(tfm_psa_rot_partition_aegis_pq PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/aegis_pq_attest.c
    ${AEGIS_SDK}/src/aegis_proto.c
    ${AEGIS_SDK}/src/aegis_kmac.c
    ${AEGIS_SDK}/src/aegis_sha256.c
    ${MLDSA_NATIVE_DIR}/mldsa_native.c
    ${AEGIS_SDK}/crypto/mlkem_unit.c
    ${CMAKE_SOURCE_DIR}/platform/ext/target/stm/common/stm32h5xx/hal/Src/stm32h5xx_hal_cryp.c
    ${AEGIS_GEN}/auto_generated/intermedia_aegis_pq_attest.c
)
target_sources(tfm_partitions INTERFACE
    ${AEGIS_GEN}/auto_generated/load_info_aegis_pq_attest.c
)
target_include_directories(tfm_psa_rot_partition_aegis_pq PRIVATE
    ${AEGIS_SDK}/include
    ${AEGIS_SDK}/src
    ${AEGIS_SDK}/crypto/mldsa
    ${MLDSA_NATIVE_DIR}
    ${AEGIS_SDK}/crypto/mlkem
    ${MLKEM_NATIVE_DIR}
    ${AEGIS_GEN}
)
target_include_directories(tfm_partitions INTERFACE ${AEGIS_GEN})
target_compile_definitions(tfm_psa_rot_partition_aegis_pq PRIVATE
    MLD_CONFIG_FILE="aegis_mldsa_config.h"
)
# one .su file per object: each function's stack frame, which tools/stack_estimate.py adds up along the call graph
target_compile_options(tfm_psa_rot_partition_aegis_pq PRIVATE -fstack-usage)
target_link_libraries(tfm_psa_rot_partition_aegis_pq PRIVATE
    platform_s
    tfm_config
    tfm_sprt
    tfm_attestation_defs
    psa_crypto_config
)
target_link_libraries(tfm_partitions INTERFACE tfm_psa_rot_partition_aegis_pq)

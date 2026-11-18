# SPDX-License-Identifier: Apache-2.0
# Aegis prover for the NXP FRDM-RW612 (Zephyr application). Build: endpoints/rw612/build.sh
cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(aegis_rw612_prover)

set(MLDSA_NATIVE_DIR "$ENV{HOME}/aegis-tools/mldsa-native/mldsa" CACHE PATH "mldsa-native v2.0.0 mldsa/ directory")
set(MLKEM_NATIVE_DIR "$ENV{HOME}/aegis-tools/mlkem-native/mlkem" CACHE PATH "mlkem-native v2.0.0 mlkem/ directory")
# shared with the STM32 partition: the PQ library configurations, KMAC256 and the pinned gateway key
set(PART ${CMAKE_CURRENT_LIST_DIR}/../../stm32h573/tfm-aegis-partition)
# only the ELS driver layer of NXP's els_pkc (key management, CKDF, HMAC), not the whole library
set(ELS_PKC ${ZEPHYR_HAL_NXP_MODULE_DIR}/nxp_crypto_hal/els_pkc/src)
set(ELS ${ELS_PKC}/comps/mcuxClEls/src)

target_sources(app PRIVATE
    src/main.c
    src/aegis_els.c
    src/aegis_proto.c
    src/sha256.c
    ${PART}/aegis_kmac.c
    ${PART}/mlkem_unit.c
    ${MLDSA_NATIVE_DIR}/mldsa_native.c
    ${ELS}/mcuxClEls_Common.c
    ${ELS}/mcuxClEls_GlitchDetector.c
    ${ELS}/mcuxClEls_KeyManagement.c
    ${ELS}/mcuxClEls_Kdf.c
    ${ELS}/mcuxClEls_Hmac.c
)
target_include_directories(app PRIVATE
    src
    ${PART}
    ${PART}/mldsa
    ${MLDSA_NATIVE_DIR}
    ${PART}/mlkem
    ${MLKEM_NATIVE_DIR}
    ${ELS_PKC}/platforms/rw61x
    ${ELS_PKC}/platforms/rw61x/inc
    ${ELS_PKC}/comps/mcuxCsslCPreProcessor/inc
    ${ELS_PKC}/comps/mcuxCsslFlowProtection/inc
    ${ELS_PKC}/comps/mcuxCsslSecureCounter/inc
    ${ELS_PKC}/comps/mcuxCsslDataIntegrity/inc
    ${ELS_PKC}/comps/mcuxCsslParamIntegrity/inc
    ${ELS_PKC}/comps/mcuxCsslMemory/inc
    ${ELS_PKC}/comps/mcuxClCore/inc
    ${ELS_PKC}/comps/mcuxClMemory/inc
    ${ELS_PKC}/comps/mcuxClEls/inc
    ${ELS_PKC}/comps/mcuxClEls/inc/internal
)
target_compile_definitions(app PRIVATE MLD_CONFIG_FILE="aegis_mldsa_config.h")

# SPDX-License-Identifier: Apache-2.0
# The TF-M partitions that call PSA Crypto as clients (protected storage, initial attestation), as in tfm_demo_s.
ExternalMCUXProject_Add(
        APPLICATION tfm_s_crypto_clients
        SOURCE_DIR  ${SdkRootDirPath}/middleware/tfm/tf-m/mcux/tfm_s_crypto_clients
        board ${SB_CONFIG_secondary_board}
        core_id ${SB_CONFIG_secondary_core_id}
        config ${SB_CONFIG_secondary_config}
        toolchain ${SB_CONFIG_secondary_toolchain}
)
add_dependencies(${DEFAULT_IMAGE} tfm_s_crypto_clients)
include(${SdkRootDirPath}/${board_root}/${board}/tfm_examples/tfm_demo/tfm_demo_s/sysbuild.cmake OPTIONAL)

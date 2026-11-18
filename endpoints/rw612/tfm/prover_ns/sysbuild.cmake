# SPDX-License-Identifier: Apache-2.0
ExternalMCUXProject_Add(
        APPLICATION aegis_s
        SOURCE_DIR  ${APP_DIR}/../aegis_s
        board ${SB_CONFIG_secondary_board}
        core_id ${SB_CONFIG_secondary_core_id}
        config ${SB_CONFIG_secondary_config}
        toolchain ${SB_CONFIG_secondary_toolchain}
)
add_dependencies(${DEFAULT_IMAGE} aegis_s)
add_dependencies(aegis_s tfm_s_crypto_clients)

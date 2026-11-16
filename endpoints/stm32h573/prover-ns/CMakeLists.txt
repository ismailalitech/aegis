# SPDX-License-Identifier: Apache-2.0
#
# Aegis prover: bare-metal Non-Secure image for TF-M on the STM32H573I-DK.
# Builds only against the interface exported by a TF-M secure build:
#   cmake -S . -B build -G Ninja -DCONFIG_SPE_PATH=<tf-m build>/api_ns
# Structure follows the SecureBench reference app (same author, Apache-2.0).
cmake_minimum_required(VERSION 3.21)

if(NOT DEFINED CONFIG_SPE_PATH OR NOT EXISTS ${CONFIG_SPE_PATH})
    message(FATAL_ERROR "Set -DCONFIG_SPE_PATH=<TF-M secure build>/api_ns")
endif()
list(APPEND CMAKE_MODULE_PATH ${CONFIG_SPE_PATH}/cmake)
if(NOT DEFINED TFM_TOOLCHAIN_FILE)
    set(TFM_TOOLCHAIN_FILE ${CONFIG_SPE_PATH}/cmake/toolchain_ns_GNUARM.cmake)
endif()

include(${CONFIG_SPE_PATH}/platform/cpuarch.cmake)
include(${CONFIG_SPE_PATH}/cmake/spe_config.cmake)
include(${CONFIG_SPE_PATH}/platform/config.cmake OPTIONAL)
include(${TFM_TOOLCHAIN_FILE})
project(tfm_ns LANGUAGES C ASM)
include(${CONFIG_SPE_PATH}/config/cp_check.cmake OPTIONAL)

set(AEGIS_PROVER_VERSION "0.4.0" CACHE STRING "Version string printed in the banner")

add_executable(tfm_ns)
add_subdirectory(${CONFIG_SPE_PATH} ${CMAKE_BINARY_DIR}/spe)

set(LWIP_DIR "$ENV{HOME}/aegis-tools/lwip" CACHE PATH "lwIP 2.2.1 source tree")
set(STM32H5_HAL "$ENV{HOME}/securebench-ws/modules/hal/stm32/stm32cube/stm32h5xx/drivers" CACHE PATH
    "ST HAL for the ETH driver (the TF-M HAL copy has no ETH module)")
include(${LWIP_DIR}/src/Filelists.cmake)

target_sources(tfm_ns PRIVATE
    src/main.c
    src/syscalls.c
    net/ethernetif.c
    ${STM32H5_HAL}/src/stm32h5xx_hal_eth.c
    ${lwipcore_SRCS}
    ${lwipcore4_SRCS}
    ${lwipnetif_SRCS}
    ${CONFIG_SPE_PATH}/interface/src/os_wrapper/tfm_ns_interface_bare_metal.c
)
target_include_directories(tfm_ns PRIVATE net net/hal ${LWIP_DIR}/src/include)
target_compile_definitions(tfm_ns PRIVATE HAL_ETH_MODULE_ENABLED ETH_RX_DESC_CNT=8U ETH_TX_DESC_CNT=4U)
target_compile_definitions(tfm_ns PRIVATE AEGIS_PROVER_VERSION="${AEGIS_PROVER_VERSION}")
target_link_libraries(tfm_ns PRIVATE tfm_api_ns tfm_api_ns_tz)

set_target_properties(tfm_ns PROPERTIES SUFFIX ".axf" RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
target_add_scatter_file(tfm_ns ${CONFIG_SPE_PATH}/platform/linker_scripts)
target_link_options(tfm_ns PRIVATE -Wl,-Map=${CMAKE_BINARY_DIR}/bin/tfm_ns.map)
add_convert_to_bin_target(tfm_ns)

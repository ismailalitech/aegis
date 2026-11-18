# SPDX-License-Identifier: Apache-2.0
# Aegis non-secure network prover for the FRDM-RW612: ENET + lwIP (bare metal), a TCP server on port 7444 that hands
# every request line to the Aegis secure partition (psa_call) and sends its reply back. Built with sysbuild together
# with ../aegis_s; see ../README.md.
cmake_minimum_required(VERSION 3.22.0)

include(${SdkRootDirPath}/cmake/extension/mcux.cmake)
project(prover_ns LANGUAGES C CXX ASM)
include(${SdkRootDirPath}/CMakeLists.txt)
include(${SdkRootDirPath}/${board_root}/${board}/tfm_examples/tfm_demo/tfm_demo_ns/reconfig.cmake OPTIONAL)

mcux_add_source(BASE_PATH ${CMAKE_CURRENT_LIST_DIR} SOURCES src/main.c src/hardware_init.c)
# test builds only (probe.sh): AEGIS_NS_EXTRA_DEFINES="-DAEGIS_NS_PROBE_ADDR=0x... -DAEGIS_NS_PROBE_NAME=..."
if(DEFINED ENV{AEGIS_NS_EXTRA_DEFINES})
    mcux_add_macro(CC "$ENV{AEGIS_NS_EXTRA_DEFINES}")
endif()
mcux_add_include(BASE_PATH ${CMAKE_CURRENT_LIST_DIR} INCLUDES src ../aegis_pq)
mcux_add_macro(CC "-DFSL_FEATURE_PHYKSZ8081_USE_RMII50M_MODE -DLWIP_RAND=aegis_rand32 -DFSL_SDK_DISABLE_DRIVER_CLOCK_CONTROL=1")
mcux_add_armgcc_configuration(CC "-Wno-unused-variable -Wno-unused-but-set-variable -Wno-return-type -Wno-maybe-uninitialized")

set(NS_LD ${APPLICATION_BINARY_DIR}/tfm_common_ns_pre.ld)
execute_process(COMMAND $ENV{ARMGCC_DIR}/bin/arm-none-eabi-gcc -D${device}${core_id_suffix_name}_SERIES -E -P -xc
    -I${SdkRootDirPath}/middleware/tfm/tf-m/platform/ext/target/nxp/${board}/partition
    -I${SdkRootDirPath}/middleware/tfm/tf-m/platform/ext/common
    ${SdkRootDirPath}/middleware/tfm/tf-m/platform/ext/common/gcc/tfm_common_ns.ld -o ${NS_LD}
    RESULT_VARIABLE ld_rc)
if(NOT ld_rc EQUAL 0)
    message(FATAL_ERROR "preprocessing tfm_common_ns.ld failed")
endif()
mcux_remove_armgcc_linker_script(TARGETS debug release BASE_PATH ${SdkRootDirPath}
    LINKER ${device_root}/${soc_portfolio}/${soc_series}/${device}/gcc/${CONFIG_MCUX_TOOLCHAIN_LINKER_DEVICE_PREFIX}_flash.ld)
mcux_remove_armgcc_linker_script(TARGETS debug release BASE_PATH ${SdkRootDirPath}
    LINKER ${device_root}/${soc_portfolio}/${soc_series}/${device}/gcc/${CONFIG_MCUX_TOOLCHAIN_LINKER_DEVICE_PREFIX}_ram.ld)
mcux_add_armgcc_linker_script(BASE_PATH ${APPLICATION_BINARY_DIR} TARGETS debug release LINKER tfm_common_ns_pre.ld)

mcux_add_library(
    BASE_PATH ${APPLICATION_BINARY_DIR}
    LIBS "../aegis_s/${CONFIG_TOOLCHAIN}/aegis_s${core_id_suffix_name}_CMSE_lib.o"
    GENERATED TRUE
)
mcux_convert_binary(BINARY ${APPLICATION_BINARY_DIR}/${MCUX_SDK_PROJECT_NAME}.bin)

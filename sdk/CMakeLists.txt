# SPDX-License-Identifier: Apache-2.0
#
# Aegis Prover SDK: the static library, the reference ports and the example, for a device maker's build.
# docs/sdk-porting-guide.md has the whole story; sdk/Makefile is the same build without CMake.
#
#   cmake -S sdk -B build/sdk -DMLDSA_NATIVE_DIR=<mldsa-native>/mldsa -DMLKEM_NATIVE_DIR=<mlkem-native>/mlkem
#   cmake --build build/sdk
#   cmake --install build/sdk --prefix /opt/aegis-sdk        (optional: libaegis_sdk.a, the headers, a CMake package)
#
# A firmware build usually does not use this file: it adds the five sources listed under "aegis_sdk" below to its own
# build (TF-M, Zephyr, OP-TEE) with the same definitions and include paths. This file is for a PC, a Linux device,
# and as the reference of what those are.
cmake_minimum_required(VERSION 3.16)
project(aegis_sdk VERSION 1.0.0 LANGUAGES C)

# The SDK's release (project version above) and the interface it implements (AEGIS_SDK_API_VERSION in
# include/aegis_sdk.h) are two numbers: docs/sdk-versioning.md.
set(AEGIS_SDK_API_VERSION 1)

option(AEGIS_EAT_COSE "Build the core with the standard-evidence option (EAT in COSE_Sign1, PQEAT; docs/evidence-format.md)" OFF)
option(AEGIS_SDK_BUILD_PORTS "Build the reference ports: aegis_host_prover (sdk/ports/host) and aegis_linux_prover (sdk/ports/linux)" ON)
option(AEGIS_SDK_BUILD_EXAMPLES "Build the example, aegis_sim_device (sdk/examples/simulated-device)" ON)
option(AEGIS_SDK_WERROR "Treat warnings in the SDK's own sources as errors" ON)

set(_aegis_tools "$ENV{HOME}/aegis-tools")
if(DEFINED ENV{AEGIS_TOOLS})
  set(_aegis_tools "$ENV{AEGIS_TOOLS}")
endif()
set(MLDSA_NATIVE_DIR "${_aegis_tools}/mldsa-native/mldsa" CACHE PATH "mldsa-native v2.0.0: the directory with mldsa_native.c")
set(MLKEM_NATIVE_DIR "${_aegis_tools}/mlkem-native/mlkem" CACHE PATH "mlkem-native v2.0.0: the directory with mlkem_native.c")
foreach(_f "${MLDSA_NATIVE_DIR}/mldsa_native.c" "${MLKEM_NATIVE_DIR}/mlkem_native.c")
  if(NOT EXISTS "${_f}")
    message(FATAL_ERROR "${_f} not found. Get mldsa-native and mlkem-native v2.0.0 "
                        "(git clone --depth 1 --branch v2.0.0 https://github.com/pq-code-package/mldsa-native.git, "
                        "the same for mlkem-native) and set MLDSA_NATIVE_DIR and MLKEM_NATIVE_DIR.")
  endif()
endforeach()

if(NOT CMAKE_C_STANDARD)
  set(CMAKE_C_STANDARD 11)
endif()

# ---- the library: the core and the two post-quantum libraries in their Aegis configuration ------------------------
add_library(aegis_sdk STATIC
  src/aegis_proto.c
  src/aegis_kmac.c
  src/aegis_sha256.c
  crypto/mlkem_unit.c
  "${MLDSA_NATIVE_DIR}/mldsa_native.c")
add_library(aegis::sdk ALIAS aegis_sdk)
target_include_directories(aegis_sdk
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>"     # aegis_sha256.h, for ports that measure images
    "$<INSTALL_INTERFACE:include/aegis>"
  PRIVATE
    crypto/mldsa crypto/mlkem "${MLDSA_NATIVE_DIR}" "${MLKEM_NATIVE_DIR}")
target_compile_definitions(aegis_sdk PRIVATE MLD_CONFIG_FILE="aegis_mldsa_config.h")
if(AEGIS_EAT_COSE)
  # PUBLIC: whoever includes aegis_sdk.h must see the same option (it declares aegis_prover_quote_eat)
  target_compile_definitions(aegis_sdk PUBLIC AEGIS_EAT_COSE=1)
endif()
set_target_properties(aegis_sdk PROPERTIES POSITION_INDEPENDENT_CODE ON OUTPUT_NAME aegis_sdk EXPORT_NAME sdk)  # aegis::sdk

# Warnings for the SDK's own files only; mldsa-native and mlkem-native are built as they are shipped.
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  set(_aegis_warn -Wall -Wextra -Wno-unused-parameter)
  if(AEGIS_SDK_WERROR)
    list(APPEND _aegis_warn -Werror)
  endif()
  set_source_files_properties(src/aegis_proto.c src/aegis_kmac.c src/aegis_sha256.c
                              PROPERTIES COMPILE_OPTIONS "${_aegis_warn}")
endif()

# ---- the reference ports and the example (POSIX) ------------------------------------------------------------------
if(AEGIS_SDK_BUILD_PORTS OR AEGIS_SDK_BUILD_EXAMPLES)
  if(NOT UNIX)
    message(FATAL_ERROR "the ports and the example need a POSIX system: -DAEGIS_SDK_BUILD_PORTS=OFF -DAEGIS_SDK_BUILD_EXAMPLES=OFF")
  endif()
endif()

if(AEGIS_SDK_BUILD_PORTS)
  add_executable(aegis_host_prover ports/host/host_main.c ports/host/aegis_port_host.c)
  # this port can hold the identity key itself (the secure-element variant): it calls mldsa-native directly
  target_include_directories(aegis_host_prover PRIVATE ports/host crypto/mldsa "${MLDSA_NATIVE_DIR}")
  target_compile_definitions(aegis_host_prover PRIVATE _GNU_SOURCE MLD_CONFIG_FILE="aegis_mldsa_config.h")
  target_link_libraries(aegis_host_prover PRIVATE aegis_sdk)

  add_executable(aegis_linux_prover ports/linux/linux_main.c ports/linux/aegis_port_linux.c)
  target_include_directories(aegis_linux_prover PRIVATE ports/linux)
  target_compile_definitions(aegis_linux_prover PRIVATE _GNU_SOURCE)
  target_link_libraries(aegis_linux_prover PRIVATE aegis_sdk)
  foreach(_t aegis_host_prover aegis_linux_prover)
    target_compile_options(${_t} PRIVATE ${_aegis_warn})
  endforeach()
endif()

if(AEGIS_SDK_BUILD_EXAMPLES)
  add_executable(aegis_sim_device examples/simulated-device/sim_device.c)
  target_compile_definitions(aegis_sim_device PRIVATE _GNU_SOURCE)
  target_compile_options(aegis_sim_device PRIVATE ${_aegis_warn})
  target_link_libraries(aegis_sim_device PRIVATE aegis_sdk)
endif()

# ---- install: the library, the public header, aegis_sha256.h and a CMake package ---------------------------------
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
install(TARGETS aegis_sdk EXPORT aegis_sdk_targets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES include/aegis_sdk.h src/aegis_sha256.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/aegis)
install(EXPORT aegis_sdk_targets NAMESPACE aegis:: FILE aegis_sdk-targets.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/aegis_sdk)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/aegis_sdk-config.cmake"
     "include(\"\${CMAKE_CURRENT_LIST_DIR}/aegis_sdk-targets.cmake\")\n"
     "set(AEGIS_SDK_API_VERSION ${AEGIS_SDK_API_VERSION})\n"
     "set(AEGIS_SDK_EAT_COSE ${AEGIS_EAT_COSE})\n")
write_basic_package_version_file("${CMAKE_CURRENT_BINARY_DIR}/aegis_sdk-config-version.cmake"
                                 COMPATIBILITY SameMajorVersion)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/aegis_sdk-config.cmake"
              "${CMAKE_CURRENT_BINARY_DIR}/aegis_sdk-config-version.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/aegis_sdk)
if(AEGIS_SDK_BUILD_EXAMPLES)
  install(TARGETS aegis_sim_device RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

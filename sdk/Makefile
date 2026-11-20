# SPDX-License-Identifier: Apache-2.0
#
# Aegis Prover SDK without CMake: GNU make and a C11 compiler. The same library and programs as sdk/CMakeLists.txt.
#
#   make -C sdk MLDSA_NATIVE_DIR=<mldsa-native>/mldsa MLKEM_NATIVE_DIR=<mlkem-native>/mlkem
#   make -C sdk AEGIS_EAT_COSE=1                    the standard-evidence option (docs/evidence-format.md)
#   make -C sdk lib                                 only build/libaegis_sdk.a
#   make -C sdk install PREFIX=/opt/aegis-sdk       lib/libaegis_sdk.a, include/aegis/aegis_sdk.h, aegis_sha256.h
#   make -C sdk CC=arm-none-eabi-gcc CFLAGS='-Os -mcpu=cortex-m33 -mthumb' lib    a cross build of the library only
#
# Outputs go to $(BUILD) (default sdk/build, or build-eat with AEGIS_EAT_COSE=1, so that both can coexist).

AEGIS_TOOLS      ?= $(HOME)/aegis-tools
MLDSA_NATIVE_DIR ?= $(AEGIS_TOOLS)/mldsa-native/mldsa
MLKEM_NATIVE_DIR ?= $(AEGIS_TOOLS)/mlkem-native/mlkem
AEGIS_EAT_COSE   ?= 0
PREFIX           ?= /usr/local

ifeq ($(AEGIS_EAT_COSE),1)
BUILD            ?= build-eat
OPT_DEFS         := -DAEGIS_EAT_COSE=1
else
BUILD            ?= build
OPT_DEFS         :=
endif

CC      ?= cc
AR      ?= ar
CFLAGS  ?= -O2
WARN    ?= -Wall -Wextra -Wno-unused-parameter -Werror
SDK_CPPFLAGS := -std=c11 $(OPT_DEFS) -Iinclude -Isrc
PQ_CPPFLAGS  := -std=c11 $(OPT_DEFS) '-DMLD_CONFIG_FILE="aegis_mldsa_config.h"' \
                -Icrypto/mldsa -Icrypto/mlkem -I$(MLDSA_NATIVE_DIR) -I$(MLKEM_NATIVE_DIR)
APP_CPPFLAGS := -std=c11 -D_GNU_SOURCE $(OPT_DEFS) -Iinclude -Isrc

LIB  := $(BUILD)/libaegis_sdk.a
OBJS := $(BUILD)/aegis_proto.o $(BUILD)/aegis_kmac.o $(BUILD)/aegis_sha256.o $(BUILD)/mlkem_unit.o \
        $(BUILD)/mldsa_native.o
PROGRAMS := $(BUILD)/aegis_host_prover $(BUILD)/aegis_linux_prover $(BUILD)/aegis_sim_device

.PHONY: all lib ports examples install clean check-deps
all: lib ports examples
lib: $(LIB)
ports: $(BUILD)/aegis_host_prover $(BUILD)/aegis_linux_prover
examples: $(BUILD)/aegis_sim_device

check-deps:
	@test -f $(MLDSA_NATIVE_DIR)/mldsa_native.c || { echo "mldsa-native v2.0.0 not found in $(MLDSA_NATIVE_DIR): set MLDSA_NATIVE_DIR" >&2; exit 1; }
	@test -f $(MLKEM_NATIVE_DIR)/mlkem_native.c || { echo "mlkem-native v2.0.0 not found in $(MLKEM_NATIVE_DIR): set MLKEM_NATIVE_DIR" >&2; exit 1; }

$(BUILD):
	mkdir -p $@

# the SDK's own sources, with warnings as errors (the core and the host port also see the two libraries' headers)
$(BUILD)/aegis_proto.o: src/aegis_proto.c include/aegis_sdk.h src/aegis_kmac.h src/aegis_sha256.h | check-deps $(BUILD)
	$(CC) $(CFLAGS) $(WARN) $(SDK_CPPFLAGS) $(PQ_CPPFLAGS) -c $< -o $@
$(BUILD)/aegis_kmac.o: src/aegis_kmac.c src/aegis_kmac.h | $(BUILD)
	$(CC) $(CFLAGS) $(WARN) $(SDK_CPPFLAGS) -c $< -o $@
$(BUILD)/aegis_sha256.o: src/aegis_sha256.c src/aegis_sha256.h | $(BUILD)
	$(CC) $(CFLAGS) $(WARN) $(SDK_CPPFLAGS) -c $< -o $@
# mldsa-native and mlkem-native, as they are shipped, in the Aegis configuration
$(BUILD)/mlkem_unit.o: crypto/mlkem_unit.c crypto/mlkem/aegis_mlkem_config.h | check-deps $(BUILD)
	$(CC) $(CFLAGS) $(PQ_CPPFLAGS) -c $< -o $@
$(BUILD)/mldsa_native.o: $(MLDSA_NATIVE_DIR)/mldsa_native.c crypto/mldsa/aegis_mldsa_config.h | check-deps $(BUILD)
	$(CC) $(CFLAGS) $(PQ_CPPFLAGS) -c $< -o $@

$(LIB): $(OBJS)
	rm -f $@
	$(AR) rcs $@ $^

$(BUILD)/aegis_host_prover: ports/host/host_main.c ports/host/aegis_port_host.c ports/host/aegis_port_host.h $(LIB)
	$(CC) $(CFLAGS) $(WARN) $(APP_CPPFLAGS) $(PQ_CPPFLAGS) -Iports/host ports/host/host_main.c ports/host/aegis_port_host.c $(LIB) -o $@ $(LDFLAGS)
$(BUILD)/aegis_linux_prover: ports/linux/linux_main.c ports/linux/aegis_port_linux.c ports/linux/aegis_port_linux.h $(LIB)
	$(CC) $(CFLAGS) $(WARN) $(APP_CPPFLAGS) -Iports/linux ports/linux/linux_main.c ports/linux/aegis_port_linux.c $(LIB) -o $@ $(LDFLAGS)
$(BUILD)/aegis_sim_device: examples/simulated-device/sim_device.c $(LIB)
	$(CC) $(CFLAGS) $(WARN) $(APP_CPPFLAGS) $< $(LIB) -o $@ $(LDFLAGS)

install: $(LIB)
	install -d $(DESTDIR)$(PREFIX)/lib $(DESTDIR)$(PREFIX)/include/aegis
	install -m 0644 $(LIB) $(DESTDIR)$(PREFIX)/lib/
	install -m 0644 include/aegis_sdk.h src/aegis_sha256.h $(DESTDIR)$(PREFIX)/include/aegis/

clean:
	rm -rf build build-eat

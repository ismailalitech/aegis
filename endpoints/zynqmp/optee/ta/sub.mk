# The Aegis TA: its entry points, and the protocol and PQ code shared with the RW612 and STM32 endpoints, staged
# next to this file by ../build_ta.sh (the OP-TEE TA build compiles sources from its own directory tree).
global-incdirs-y += . shared shared/mldsa shared/mlkem shared/mldsa-native shared/mlkem-native
# up to 8 measured components from the FSBL's hand-off (the shared default is 4, in a 1024-byte claims buffer); the
# PQCHAL reply still fits AEGIS_REPLY_MAX (aegis_ta.c checks both at build time)
cflags-y += -DAEGIS_MAX_MEASUREMENTS=8 -DAEGIS_CLAIMS_MAX=1440u
cflags-y += -DMLD_CONFIG_FILE=\"aegis_mldsa_config.h\" -DAEGIS_DEVICE_FW=\"zynqmp-optee\" -DAEGIS_DEVICE_VERSION=\"0.1.0\"
cflags-y += -Wno-unused-parameter -Wno-missing-prototypes -Wno-missing-declarations -Wno-strict-prototypes
cflags-y += -Wno-old-style-definition -Wno-cast-align -Wno-declaration-after-statement -Wno-unused-function
cflags-y += -Wno-shadow -Wno-redundant-decls -Wno-switch-default -Wno-nested-externs -Wno-sign-compare
cflags-y += -Wno-unused-variable -Wno-implicit-fallthrough -Wno-format-nonliteral
srcs-y += aegis_ta.c
srcs-y += shared/aegis_proto.c shared/sha256.c shared/aegis_kmac.c shared/mlkem_unit.c shared/mldsa-native/mldsa_native.c

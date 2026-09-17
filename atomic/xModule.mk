
LOCAL_PATH := $(my-dir)

$(call clear-local-vars)

LOCAL_MODULE := rockey_atomic_abi_checker

LOCAL_SRC_FILES := doc/isa-check.cc

$(call build-library)

##
##
##
ifeq ("$(X4C_ARCH)-$(X4C_BUILD)","rv32im-rockey")
-include $(LOCAL_PATH)/*/xModule.mk
endif ## rv32im-rockey

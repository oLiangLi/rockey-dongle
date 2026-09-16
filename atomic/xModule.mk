
LOCAL_PATH := $(my-dir)

$(call clear-local-vars)

LOCAL_MODULE := rockey_atomic_abi_checker

LOCAL_SRC_FILES := doc/isa-check.cc

$(call build-library)

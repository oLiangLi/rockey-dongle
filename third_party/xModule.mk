LOCAL_PATH := $(my-dir)

$(call clear-local-vars)
LOCAL_MODULE    := macro_ecc
LOCAL_SRC_FILES := micro-ecc/uECC.c
$(call build-library)

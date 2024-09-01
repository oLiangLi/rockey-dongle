LOCAL_PATH := $(my-dir)

$(call clear-local-vars)
LOCAL_MODULE := rockey

ifeq ("$(X4C_BOARD)","RockeyARM")
LOCAL_SRC_FILES := rockey.cc
else
LOCAL_SRC_FILES := dongle.cc
endif

$(call build-library)


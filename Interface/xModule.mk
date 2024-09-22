LOCAL_PATH := $(my-dir)

$(call clear-local-vars)
LOCAL_MODULE := rockey

ifeq ("$(X4C_BOARD)","RockeyARM")
LOCAL_SRC_FILES := rockey.cc
else  ## RockeyARM
ifneq ("$(X4C_BUILD)","emscripten")
LOCAL_SRC_FILES := dongle.cc
else  ## emscripten
LOCAL_SRC_FILES := emulator.cc
endif ## emscripten
endif ## RockeyARM

LOCAL_SRC_FILES += curves.cc chachapoly.cc sha256.cc sha512.cc curve25519.cc

$(call build-library)


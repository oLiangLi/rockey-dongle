LOCAL_PATH := $(my-dir)

$(call clear-local-vars)
LOCAL_MODULE := rockey

##
##
##
ifeq ("$(X4C_BOARD)","RockeyARM")
ROCKEY_DECLARE_FILE ?= rockey.cc
endif ## RockeyARM

##
##
##
ifeq ("$(X4C_BOARD)","foobar")
ROCKEY_DECLARE_FILE ?= emulator.cc
endif ## foobar

##
##
##
ifeq ("$(X4C_BUILD)","emscripten")
ROCKEY_DECLARE_FILE ?= emulator.cc
endif ## emscripten

##
## default dongle.cc
##
ROCKEY_DECLARE_FILE ?= dongle.cc

##
##
##
LOCAL_SRC_FILES := $(ROCKEY_DECLARE_FILE)
LOCAL_SRC_FILES += curves.cc chachapoly.cc sha256.cc sha512.cc curve25519.cc script.cc

$(call build-library)


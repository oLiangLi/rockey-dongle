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
ROCKEY_MASTER_FILES := master.cc secret.cc TRNG.cc

##
##
##
LOCAL_SRC_FILES := $(ROCKEY_DECLARE_FILE) $(ROCKEY_MASTER_FILES)
LOCAL_SRC_FILES += curves.cc chachapoly.cc sha256.cc sha512.cc curve25519.cc
LOCAL_SRC_FILES += execute.cc script.cc x509.cc mr.cc

##
##
##
$(eval $$(LOCAL_MODULE)-prepare: $$(addprefix $$(LOCAL_PATH)/, $$(ROCKEY_MASTER_FILES)); touch $$? )

##
## 继续为程序注入一些额外的随机性 ...
##
rLANG_WORLD_SECRET_SEED_0 := $(shell $(X4C_NODE) -e "process.stdout.write('0x'+crypto.getRandomValues(Buffer.alloc(4)).toString('hex'))")
rLANG_WORLD_SECRET_SEED_1 := $(shell $(X4C_NODE) -e "process.stdout.write('0x'+crypto.getRandomValues(Buffer.alloc(4)).toString('hex'))")
rLANG_WORLD_SECRET_SEED_2 := $(shell $(X4C_NODE) -e "process.stdout.write('0x'+crypto.getRandomValues(Buffer.alloc(4)).toString('hex'))")
rLANG_WORLD_SECRET_SEED_3 := $(shell $(X4C_NODE) -e "process.stdout.write('0x'+crypto.getRandomValues(Buffer.alloc(4)).toString('hex'))")

LOCAL_CXXFLAGS := -DrLANG_WORLD_SECRET_SEED_0=$(rLANG_WORLD_SECRET_SEED_0)
LOCAL_CXXFLAGS += -DrLANG_WORLD_SECRET_SEED_1=$(rLANG_WORLD_SECRET_SEED_1)
LOCAL_CXXFLAGS += -DrLANG_WORLD_SECRET_SEED_2=$(rLANG_WORLD_SECRET_SEED_2)
LOCAL_CXXFLAGS += -DrLANG_WORLD_SECRET_SEED_3=$(rLANG_WORLD_SECRET_SEED_3)

$(call build-library)


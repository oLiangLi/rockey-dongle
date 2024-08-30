##
##
##
X4C_BUILD_SYSTEM_VERSION := 0.8.3

##
## 
##
.PHONY : all hello prepare clean touch build-all clean-all

##
##
##
ifneq ("$(wORLD_CONFIG)","")
all       : build-all
clean     : clean-all
endif

##
##
##
build-all : prepare

##
##
##
prepare build-all clean-all : hello

##
##
##
X4C_BUILD_SYSTEM := $(patsubst %/,%,$(dir $(lastword  $(MAKEFILE_LIST))))
X4C_VALID_CONFIG := $(call basename,$(call notdir,$(wildcard $(X4C_BUILD_SYSTEM)/config/*.conf)))

##
##
##
ifneq ("$(X4C_BUILD_LOCAL_CONFIG)","")
include $(X4C_BUILD_LOCAL_CONFIG)
else
ifneq ("$(filter $(CONFIG),$(X4C_VALID_CONFIG))","")
include $(X4C_BUILD_SYSTEM)/config/$(CONFIG).conf
endif
endif

##
##
##
X_NODE  ?= node

##
##
##
X4C_BUILD_XWORLD ?= $(patsubst %/,%,$(dir $(firstword $(MAKEFILE_LIST))))
X4C_BUILD_MODULE ?= $(wildcard $(X4C_BUILD_XWORLD)/*/xModule.mk)

##
##
##
X4C_RELEASE_CFLAGS   ?= -O2 -g -DNDEBUG
X4C_RELEASE_CXXFLAGS ?= -O2 -g -DNDEBUG
X4C_DEBUG_CFLAGS     ?= -O0 -g -D_DEBUG
X4C_DEBUG_CXXFLAGS   ?= -O0 -g -D_DEBUG

##
##
X4C_ARCH  ?= $(shell uname -m)
X4C_BUILD ?= $(shell uname -o)

##
##
##
ifeq ("$(X4C_ARCH)","x86_64")
X4C_ARCH  := amd64
endif

ifeq ("$(X4C_ARCH)","x64")
X4C_ARCH  := amd64
endif

ifeq ("$(X4C_BUILD)","GNU/Linux")
X4C_BUILD := linux
endif

ifeq ("$(X4C_BUILD)","Linux")
X4C_BUILD := linux
endif

##
## default platform amd64-linux, gcc, nasm ...
##
X4C_CC    ?= $(X4C_BUILD_CROSS)gcc
X4C_CXX   ?= $(X4C_BUILD_CROSS)g++
X4C_AR    ?= $(X4C_BUILD_CROSS)ar
X4C_LD    ?= $(X4C_BUILD_CROSS)g++

##
##
##
ifeq ("$(X4C_ARCH)","i686")
X4C_ASM   ?= nasm -f elf32
endif

ifeq ("$(X4C_ARCH)","amd64")
X4C_ASM   ?= nasm -f elf64
endif

##
##
##
X4C_ASM   ?= $(X4C_BUILD_CROSS)as

##
##
##
include $(X4C_BUILD_SYSTEM)/core/definitions.mk

##
##
##
ifneq ("$(X4C_BUILD_LOCAL_DEFINE)","")
include $(X4C_BUILD_LOCAL_DEFINE)
endif

##
##
##
include $(X4C_BUILD_SYSTEM)/core/toolchain.mk
include $(X4C_BUILD_SYSTEM)/core/main.mk


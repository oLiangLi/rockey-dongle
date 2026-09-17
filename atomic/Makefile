##
## 继续使用上级目录(rockey-dongle)作为主目录
##
wORLD_ROOT := $(realpath $(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))/..)

ifeq ("$(shell uname -o)","Cygwin")
wORLD_ROOT := $(shell cygpath -m $(wORLD_ROOT))
endif ## Cygwin ...

##
## ATOMIC 编译只使用 /Machine/System/bin 下安装的 node.js ...
##
X4C_NODE := $(if $(wildcard /Machine/System/bin/node-rlang),/Machine/System/bin/node-rlang,/Machine/System/bin/node)

##
## default build Release version ...
##
R ?= 1

##
## 为程序注入一些外部的随机性, 注意编译出的 .text 是可读的, 这些参数只是让每次编译都是不兼容的, 不能提供任何的额外的 **秘密**  ...
##
rLANG_WORLD_SEED_0 := $(shell $(X4C_NODE) -e "process.stdout.write('0x'+crypto.getRandomValues(Buffer.alloc(4)).toString('hex'))")
rLANG_WORLD_SEED_1 := $(shell $(X4C_NODE) -e "process.stdout.write('0x'+crypto.getRandomValues(Buffer.alloc(4)).toString('hex'))")
rLANG_WORLD_SEED_2 := $(shell $(X4C_NODE) -e "process.stdout.write('0x'+crypto.getRandomValues(Buffer.alloc(4)).toString('hex'))")
rLANG_WORLD_SEED_3 := $(shell $(X4C_NODE) -e "process.stdout.write('0x'+crypto.getRandomValues(Buffer.alloc(4)).toString('hex'))")

.PHONY: all clean
.PHONY: rv32im-atomic-rockey rv32im-atomic-rockey-clean rv32im-rockey rv32im-rockey-clean

all: rv32im-atomic-rockey rv32im-rockey
clean: rv32im-atomic-rockey-clean rv32im-rockey-clean

wORLD_BOARD_MAKE := \
	-C $(wORLD_ROOT)/atomic \
	wORLD_CONFIG=None \
	X4C_BUILD_LOCAL_CONFIG=$(wORLD_ROOT)/atomic/toolchain/rv32im-atomic-rockey.conf

##
##
##
-include $(wORLD_ROOT)/.user.local.mk

##
## 手工添加需要编译到 atomic 的模块 ...
##
X4C_BUILD_MODULE := \
	$(wORLD_ROOT)/base/xModule.mk

##
##
##
X4C_BUILD_LOCAL_DEFINE := $(wORLD_ROOT)/atomic/project.mk

rv32im-rockey:
	$(MAKE) $(wORLD_BOARD_MAKE) prepare
	$(MAKE) $(wORLD_BOARD_MAKE) build-all

rv32im-rockey-clean:
	$(MAKE) $(wORLD_BOARD_MAKE) clean-all

rv32im-atomic-rockey:
	$(MAKE) $(wORLD_BOARD_MAKE) rLANG_CONFIG_ENABLE_ATOMC_WORLD=1 prepare
	$(MAKE) $(wORLD_BOARD_MAKE) rLANG_CONFIG_ENABLE_ATOMC_WORLD=1 build-all

rv32im-atomic-rockey-clean:
	$(MAKE) $(wORLD_BOARD_MAKE) rLANG_CONFIG_ENABLE_ATOMC_WORLD=1 clean-all

##
##
##
ifneq ("$(X4C_BUILD_LOCAL_CONFIG)","")
include $(wORLD_ROOT)/Build/Main.mk
endif

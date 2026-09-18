##
## 继续使用上级目录(rockey-dongle)作为主目录
##
wORLD_ROOT := $(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))/..

##
##
##
wORLD_REAL_ROOT := $(realpath $(wORLD_ROOT))

ifeq ("$(shell uname -o)","Cygwin")
wORLD_REAL_ROOT := $(shell cygpath -m $(wORLD_REAL_ROOT))
endif ## Cygwin ...

##
##
##
rLANG_CONFIG_MINIMAL_WORLD := 1

##
##
##
X4C_BUILD_XWORLD := $(wORLD_ROOT)

##
## node 程序: 优先本机 rlang 专用 node, 其次 /Machine/System/bin/node, 最后退回 PATH 上的 node
## (平台无关: 未安装 /Machine/System 的环境也能构建)
##
X4C_NODE ?= $(shell if [ -x /Machine/System/bin/node-rlang ] ; then echo /Machine/System/bin/node-rlang ; elif [ -x /Machine/System/bin/node ] ; then echo /Machine/System/bin/node ; else echo node ; fi )

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

##
##
##
ALL_op_GATE_LIST := $(wildcard $(wORLD_ROOT)/atomic/op_GATE/list/*.yaml)

.PHONY: all clean opGateWrapper rv32im-atomic-rockey rv32im-atomic-rockey-clean rv32im-rockey rv32im-rockey-clean

all: rv32im-atomic-rockey rv32im-rockey
clean: rv32im-atomic-rockey-clean rv32im-rockey-clean

opGateWrapper:
	$(hide) $(info op_GATE.gen $(ALL_op_GATE_LIST) ...)
	$(hide) rm -rfv $(wORLD_ROOT)/atomic/op_GATE/gen
	$(X4C_NODE) $(wORLD_ROOT)/atomic/op_GATE/tools/gen.cjs $(ALL_op_GATE_LIST) \
		--world-seed="$(rLANG_WORLD_SEED_0),$(rLANG_WORLD_SEED_1),$(rLANG_WORLD_SEED_2),$(rLANG_WORLD_SEED_3)"

wORLD_BOARD_MAKE := \
	-C $(wORLD_REAL_ROOT)/atomic \
	wORLD_CONFIG=None \
	X4C_BUILD_LOCAL_CONFIG=$(wORLD_REAL_ROOT)/atomic/toolchain/rv32im-atomic-rockey.conf

##
##
##
-include $(wORLD_REAL_ROOT)/.user.local.mk

##
## 手工添加需要编译到 atomic 的模块 ...
##
X4C_BUILD_MODULE := \
	$(wORLD_REAL_ROOT)/base/xModule.mk \
	$(wORLD_REAL_ROOT)/atomic/xModule.mk

##
##
##
X4C_BUILD_LOCAL_DEFINE := $(wORLD_REAL_ROOT)/atomic/project.mk

rv32im-rockey: opGateWrapper
	$(MAKE) $(wORLD_BOARD_MAKE) prepare
	$(MAKE) $(wORLD_BOARD_MAKE) build-all

rv32im-rockey-clean:
	$(MAKE) $(wORLD_BOARD_MAKE) clean-all

rv32im-atomic-rockey: rv32im-rockey
	$(MAKE) $(wORLD_BOARD_MAKE) rLANG_CONFIG_ENABLE_ATOMC_WORLD=1 prepare
	$(MAKE) $(wORLD_BOARD_MAKE) rLANG_CONFIG_ENABLE_ATOMC_WORLD=1 build-all

rv32im-atomic-rockey-clean:
	$(MAKE) $(wORLD_BOARD_MAKE) rLANG_CONFIG_ENABLE_ATOMC_WORLD=1 clean-all

##
##
##
ifneq ("$(X4C_BUILD_LOCAL_CONFIG)","")
include $(wORLD_REAL_ROOT)/Build/Main.mk
endif ## X4C_BUILD_LOCAL_CONFIG

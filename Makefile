wORLD_ROOT := $(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))

##
##
##
X4C_NODE ?= $(shell if [ -e /Machine/System/bin/node-rlang ] ; then echo /Machine/System/bin/node-rlang ; else echo /Machine/System/bin/node ; fi )

.PHONY : wasm cygwin linux aarch64-linux windows all-platform bootstrap install install-platform
.PHONY : clean-wasm clean-cygwin clean-linux clean-aarch64-linux clean-windows clean-all-platform
.PHONY : typescript typescript0 docker all-docker dongle clean-dongle foobar clean-foobar sec-bin stack-check jsWrapper
.PHONY : ci test install-hooks test-optmatrix

##
## default build Release version ...
##
R ?= 1

ifeq ("$(shell uname -m)","aarch64")
all: aarch64-linux
clean: clean-aarch64-linux
install: ; $(MAKE) -C $(wORLD_ROOT) wORLD_CONFIG=aarch64-linux install-platform
wORLD_PLATFORM_CONFIG := aarch64-linux
else
ifeq ("$(shell uname -o)","Cygwin")
all: windows
clean: clean-windows
install: ; $(MAKE) -C $(wORLD_ROOT) wORLD_CONFIG=windows install-platform
wORLD_PLATFORM_CONFIG := windows
SO_INSTALL_MODE := 755
else
all: linux
clean: clean-linux
install: ; $(MAKE) -C $(wORLD_ROOT) wORLD_CONFIG=linux install-platform
wORLD_PLATFORM_CONFIG := linux
endif
endif

##
## 为程序注入一些外部的随机性 ...
##
rLANG_WORLD_SEED_0 := $(shell $(X4C_NODE) -e "process.stdout.write('0x'+crypto.getRandomValues(Buffer.alloc(4)).toString('hex'))")
rLANG_WORLD_SEED_1 := $(shell $(X4C_NODE) -e "process.stdout.write('0x'+crypto.getRandomValues(Buffer.alloc(4)).toString('hex'))")
rLANG_WORLD_SEED_2 := $(shell $(X4C_NODE) -e "process.stdout.write('0x'+crypto.getRandomValues(Buffer.alloc(4)).toString('hex'))")
rLANG_WORLD_SEED_3 := $(shell $(X4C_NODE) -e "process.stdout.write('0x'+crypto.getRandomValues(Buffer.alloc(4)).toString('hex'))")

##
##
##
SO_INSTALL_MODE ?= 644

##
##
##
wORLD_DEFAULT_DONGLE ?= RockeyARM
wORLD_DONGLE ?= $(wORLD_DEFAULT_DONGLE)

##
##
## 调用栈深度静态检查(退出码 0=无违规 10=超预算) ...
stack-check: dongle
	@$(X4C_NODE) $(wORLD_ROOT)/Build/tools/stack-check/stack-check.cjs

##
##
##
sec-bin:
	@ cd $(wORLD_ROOT) && node -e "fs.writeFileSync('.bin/arm-RockeyARM-native-release/sec.bin', crypto.getRandomValues(Buffer.alloc(64)))" && sha256sum ./.bin/arm-RockeyARM-native-release/sec.bin

##
##
##
dongle:
	$(MAKE) -C $(wORLD_ROOT) X4C_BOARD=$(wORLD_DONGLE) wORLD_CONFIG=arm-none-eabi prepare R=1
	$(MAKE) -C $(wORLD_ROOT) X4C_BOARD=$(wORLD_DONGLE) wORLD_CONFIG=arm-none-eabi install-platform R=1

##
##
##
clean-dongle:
	$(MAKE) -C $(wORLD_ROOT) X4C_BOARD=$(wORLD_DONGLE) wORLD_CONFIG=arm-none-eabi clean-all R=1

##
##
##
foobar:
	$(MAKE) -C $(wORLD_ROOT) X4C_BOARD=foobar wORLD_CONFIG=$(wORLD_PLATFORM_CONFIG) prepare  R=0
	$(MAKE) -C $(wORLD_ROOT) X4C_BOARD=foobar wORLD_CONFIG=$(wORLD_PLATFORM_CONFIG) optimize R=0

clean-foobar:
	$(MAKE) -C $(wORLD_ROOT) X4C_BOARD=foobar wORLD_CONFIG=$(wORLD_PLATFORM_CONFIG) clean-all R=0

##
##
##
wasm:
	$(MAKE) -C $(wORLD_ROOT) wORLD_CONFIG=wasm prepare R=1
	$(MAKE) -C $(wORLD_ROOT) wORLD_CONFIG=wasm optimize R=1

##
## 由 Interface/script.h 生成 Web/Script/lib/opcode.ts(enum + AllFunc), 再打包 JS 封装:
##   R=1 → npm run release; 否则 → npm run build
##
jsWrapper:
	$(X4C_NODE) $(wORLD_ROOT)/Build/tools/script/opcode.cjs
ifeq ("$(R)","1")
	cd $(wORLD_ROOT) && npm run release
else
	cd $(wORLD_ROOT) && npm run build
endif

docker:
	$(MAKE) -C $(wORLD_ROOT) wORLD_CONFIG=$(wORLD_PLATFORM_CONFIG) all-docker

linux:
	$(MAKE) -C $(wORLD_ROOT) wORLD_CONFIG=linux prepare
	$(MAKE) -C $(wORLD_ROOT) wORLD_CONFIG=linux optimize

windows:
	$(MAKE) -C $(wORLD_ROOT) wORLD_CONFIG=windows prepare
	$(MAKE) -C $(wORLD_ROOT) wORLD_CONFIG=windows optimize

aarch64-linux:
	$(MAKE) -C $(wORLD_ROOT) wORLD_CONFIG=aarch64-linux prepare
	$(MAKE) -C $(wORLD_ROOT) wORLD_CONFIG=aarch64-linux optimize

clean-aarch64-linux:
	$(MAKE) -C $(wORLD_ROOT) wORLD_CONFIG=aarch64-linux clean-all

clean-wasm:
	$(MAKE) -C $(wORLD_ROOT) wORLD_CONFIG=wasm clean-all  R=1

clean-linux:
	$(MAKE) -C $(wORLD_ROOT) wORLD_CONFIG=linux clean-all

clean-windows:
	$(MAKE) -C $(wORLD_ROOT) wORLD_CONFIG=windows clean-all

typescript:
	$(info typescript compile ... 1)
	@tsc

typescript0: wasm
	$(info typescript compile ... 0)
	@tsc

##
## 统一 CI 入口(见 Build/tools/ci/run-ci.cjs): 进程内 JS 模拟器回归
## 前置: make wasm && make jsWrapper(生成 Web/Agent/Tests/js 封装); CI_STRICT=1 严格
##
ci:
	node Build/tools/ci/run-ci.cjs
test: ci

##
## 安装 git hooks(core.hooksPath=.githooks): post-merge/post-commit 在 squash merge 后自动 make ci
## 说明: CI_SKIP_RUN=1 跳过; CI_STRICT=1 时失败以非零退出; 本地 squash merge(git merge --squash)
## 与提交信息形如 "Squashed commit of the following:" 的 commit 均触发; 远端(如 GitHub web)合并无法触发本地 hook。
##
install-hooks:
	git config core.hooksPath .githooks
	@echo "hooks 已安装(core.hooksPath=.githooks)"

##
## 优化级别矩阵向量门禁(-O0..-O3 密码学自测; 需 clean+全量重建, 较慢)
## 精简子集: OPTMATRIX_OPTS="-O0 -O3"; 跳过: CI_SKIP_HEAVY=1
##
test-optmatrix:
	node Build/tools/ci/optmatrix.cjs

##
##
##
-include $(wORLD_ROOT)/.user.local.mk

##
##
##
ifneq ("$(X4C_BOARD)","")
-include $(wORLD_ROOT)/Board/$(X4C_BOARD)/xModule.mk
endif

ifneq ("$(wORLD_CONFIG)","")
CONFIG := $(wORLD_CONFIG)
X4C_BUILD_MODULE := $(wildcard $(wORLD_ROOT)/*/xModule.mk)

X4C_BUILD_LOCAL_DEFINE := $(wORLD_ROOT)/project.local.mk

include $(wORLD_ROOT)/Build/Main.mk
ifneq ("$(origin x4c-cmd-build-optimize)","undefined")
$(foreach __a_module,$(__x4c_all_optimize_modules), $(eval $(call x4c-cmd-build-optimize,$(__a_module))))
endif
endif

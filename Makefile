wORLD_ROOT := $(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))
##
## 子模块守卫: base/ 与 Build/ 已改为 git submodule; 未初始化时给出可操作提示
## (非致命 —— 否则 install-hooks 等目标会被挡住; 真正的构建会在缺文件时报错)
##
ifeq ("$(wildcard $(wORLD_ROOT)/Build/Main.mk)","")
$(warning [build] 子模块未初始化(base/Build 为空) — 请先执行: git submodule update --init)
endif

##
##
##
## node 程序: 优先本机 rlang 专用 node, 其次 /Machine/System/bin/node, 最后退回 PATH 上的 node
## (平台无关: 未安装 /Machine/System 的环境也能构建)
X4C_NODE ?= $(shell if [ -x /Machine/System/bin/node-rlang ] ; then echo /Machine/System/bin/node-rlang ; elif [ -x /Machine/System/bin/node ] ; then echo /Machine/System/bin/node ; else echo node ; fi )

## tsc: 优先仓库内 devDependencies 的本地 tsc(npm install 后), 避免被 PATH 上其它版本遮蔽
TSC ?= $(if $(wildcard $(wORLD_ROOT)/node_modules/.bin/tsc),$(wORLD_ROOT)/node_modules/.bin/tsc,tsc)

.PHONY : wasm cygwin linux aarch64-linux windows all-platform bootstrap install install-platform
.PHONY : clean-wasm clean-cygwin clean-linux clean-aarch64-linux clean-windows clean-all-platform
.PHONY : typescript typescript0 docker all-docker dongle clean-dongle foobar clean-foobar sec-bin stack-check rockey-stack-check jsWrapper
.PHONY : ci test install-hooks test-optmatrix test-web

##
## default build Release version ...
##
R ?= 1

##
## 宿主平台约定(用户 2026-09-11): Windows 侧**只在 Cygwin 下构建** —— MSYS2 / Git-Bash 缺太多工具,
## 不在支持范围内 ⇒ 下面 `uname -o` == "Cygwin" 就是 Windows 的唯一判据, 不要为 Msys/MINGW 扩写。
## 支持的宿主: Cygwin(Windows) / Linux(x86_64) / Linux(aarch64)。
##
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
	@$(X4C_NODE) $(wORLD_ROOT)/Build/tools/LIMIT/stack-check/stack-check.cjs

##
## rockey_dongle(设备 App, 含 Testing_* 项)的调用栈深度静态检查 —— 与 stack-check 同一工具,
## 但 map 用 rockey-dongle.map(app_entry → machine::dongle::Start → Testing_* 路径可见)。
## 默认预算与 stack-check 一致 2032B; 预算覆盖: make rockey-stack-check BUDGET=4096。
## 需先 make dongle(本目标自动依赖)。
##
rockey-stack-check: dongle
	@$(X4C_NODE) $(wORLD_ROOT)/Build/tools/LIMIT/stack-check/stack-check.cjs --budget=$(if $(BUDGET),$(BUDGET),2032) $(wORLD_ROOT)/.bin/.obj/arm-RockeyARM-native-release/rockey-dongle.map

##
##
##
sec-bin:
	@ cd $(wORLD_ROOT) && $(X4C_NODE) -e "fs.writeFileSync('.bin/arm-RockeyARM-native-release/sec.bin', crypto.getRandomValues(Buffer.alloc(64)))" && sha256sum ./.bin/arm-RockeyARM-native-release/sec.bin

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
	$(X4C_NODE) $(wORLD_ROOT)/Build/tools/LIMIT/script/opcode.cjs
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
	@$(TSC)

typescript0: wasm
	$(info typescript compile ... 0)
	@$(TSC)

##
## 统一 CI 入口(见 Build/tools/LIMIT/ci/run-ci.cjs): 进程内 JS 模拟器回归
## 前置: make wasm && make jsWrapper(生成 Web/Agent/Tests/js 封装); CI_STRICT=1 严格
##
ci:
	$(X4C_NODE) Build/tools/LIMIT/ci/run-ci.cjs
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
## 平台无关: 按宿主平台构建/取产物(Windows 带 .exe, Linux 无扩展名);
##           项目"0 错"退出码 10086 在 POSIX 上被截断为 102, 两种都认。
## 板级: Windows 缺省真机/SDK 模拟器; 其它宿主缺省 foobar(模拟器世界, 无需 ukey),
##       要测真机用 OPMATRIX_BOARD=none(需接设备)。
## 精简子集: OPTMATRIX_OPTS="-O0 -O3"; 跳过: CI_SKIP_HEAVY=1; 并行度: JOBS=N
##
test-optmatrix:
	$(X4C_NODE) Build/tools/LIMIT/ci/optmatrix.cjs

##
## 网页端 CI(需本机 Chrome): 加载 Web/Agent/Tests 页面, 点击 EmuCreate→EmuTests
## 并断言 X509ExtBuilder/JsCryptoSmoke OK。user-data-dir = .bin/ai-web-user-data(绝不碰默认配置)。
## 缺省 headless(无界面); WEB_HEADED=1 以有界面窗口运行; CHROME 可指定浏览器路径。
##
test-web:
	$(X4C_NODE) Build/tools/LIMIT/ci/web-emutests.cjs

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

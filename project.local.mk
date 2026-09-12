##
## 设备(在 ukey 内运行)构建即"最小世界": 上游 base 据此跳过 host-only 设施与 base/tests 子模块。
## C 宏由 MCU/RockeyARM/rockey_predef.h 定义; 这里提供同名 make 变量供构建系统判断(base/xModule.mk)。
##
ifeq ("$(wORLD_CONFIG)","arm-none-eabi")
rLANG_CONFIG_MINIMAL_WORLD := 1

##
## 设备(受限世界)专属编译参数 —— 共享 build 仓保持中性默认(unwind 表默认打开、帧指针按组合条件省略):
##   ① 不生成 unwind 表: 固件受 elf2bin 段契约与 ".rodata 必须为空" 约束, 不能出现 .ARM.exidx
##      (实测带该 flags 时 make dongle 链接缺 __aeabi_unwind_cpp_pr0);
##   ② 恒定省略帧指针: 设备栈预算 2032B, 不能因帧指针膨胀。
##   宿主模块需要回溯时自行设 LOCAL_BACKTRACE=1 并覆盖 X4C_UNWIND_TABLE_CFLAGS。
##
X4C_UNWIND_TABLE_CFLAGS :=
X4C_TOOLCHAIN_CFLAGS    += -fomit-frame-pointer
X4C_TOOLCHAIN_CXXFLAGS  += -fomit-frame-pointer
endif

##
## TODO: LiangLI, 在合适的时候将 rLANG_BUILD_WORLD 并入 Build/Main.mk
##
ifeq ("$(X4C_BUILD)","linux")
rLANG_BUILD_WORLD ?= COSMO
endif ## X4C_BUILD

ifeq ("$(X4C_BUILD)","windows")
rLANG_BUILD_WORLD ?= COSMO
endif ## X4C_BUILD

.PHONY : optimize
optimize : build-all
all: optimize

##
##
##
__x4c_all_optimize_modules := $(call set_create,)
$(call x4c_register_local_variant, LOCAL_BUILD_OPTIMIZE_FLAGS)

x4c_add_optimize_module = \
  $(if $(call filter,$(__x4c_all_optimize_modules),$1),  \
	   $(call error,Local module ** $1 ** already defined.)) \
	$(eval __x4c_all_optimize_modules := $(call set_insert,$1,$(__x4c_all_optimize_modules)))	\
	$(eval $1_BUILD_OPTIMIZE_FLAGS := $(LOCAL_BUILD_OPTIMIZE_FLAGS))
call_add_optimize_module = $(call x4c_add_optimize_module,$(LOCAL_MODULE))

##
##
##
COMMON_CFLAGS := -I$(wORLD_ROOT) -I$(wORLD_ROOT)/third_party/pre-built/include
COMMON_CFLAGS += -DBN_free=BN_clear_free

##
##
##
ifeq ("$(X4C_ARCH)","wasm")
X4C_WASM_OPT       ?= $(EMSDK)/upstream/bin/wasm-opt
wasm_add_cflags     = $(eval LOCAL_CFLAGS   += $1)
wasm_add_cxxflags   = $(eval LOCAL_CXXFLAGS += $1)
wasm_add_ldflags    = $(eval LOCAL_LDFLAGS  += $1)
COMMON_CFLAGS	   += -DrLANG_WORLD_STANDALONE=1 -DX_ARCH_wasm=1
COMMON_CFLAGS      += -I$(wORLD_ROOT)/third_party/build/wasm
X4C_COMMON_LDFLAGS += -L$(wORLD_ROOT)/third_party/build/wasm
X4C_COMMON_LDFLAGS += -s WASM=1 -s ERROR_ON_UNDEFINED_SYMBOLS=0 -s STANDALONE_WASM=1
X4C_COMMON_CXXFLAGS+= -fno-rtti -fno-common -fno-use-cxa-atexit -std=c++17
X4C_OPTIMIZE_OUTPUT:= $(wORLD_ROOT)/Web/Assembly

optimize: $(X4C_OPTIMIZE_OUTPUT)
$(X4C_OPTIMIZE_OUTPUT): ; $(call x4c_cmd_mkdir,$@)

##
##
##
define x4c-cmd-build-optimize
optimize: $(X4C_OPTIMIZE_OUTPUT)/$(strip $1).wasm
$(X4C_OPTIMIZE_OUTPUT)/$(strip $1).wasm: $(X4C_BINARY)/$(strip $1).wasm
	$$(info WASM-OPTIMIZE $$@)
	$$(hide) $$(X4C_WASM_OPT) $$($(strip $1)_BUILD_OPTIMIZE_FLAGS) -o $$@ $$<
	$$(hide) $$(X4C_NODE) $$(wORLD_ROOT)/Build/tools/script/wasm2string.cjs $$@
endef
endif

##
##
##  (wasmjs 平台已删除 2026-09-07: 目标由用户移除, JS 封装改为手工生成, 见 ai-context §10.15)

##
##
##
ifeq ("$(X4C_BUILD)","linux")
linux_add_cflags    = $(eval LOCAL_CFLAGS   += $1)
linux_add_cxxflags  = $(eval LOCAL_CXXFLAGS += $1)
linux_add_ldflags   = $(eval LOCAL_LDFLAGS  += $1)
X4C_COMMON_CXXFLAGS+= -std=c++17
COMMON_CFLAGS	     += -I$(wORLD_ROOT)/third_party/build/$(X4C_ARCH)/linux -pthread
X4C_COMMON_LDFLAGS += -L$(wORLD_ROOT)/third_party/build/$(X4C_ARCH)/linux -pthread -ldl -static
endif

##
##
##
ifeq ("$(X4C_BUILD)","windows")
windows_add_cflags   = $(eval LOCAL_CFLAGS   += $1)
windows_add_cxxflags = $(eval LOCAL_CXXFLAGS += $1)
windows_add_ldflags  = $(eval LOCAL_LDFLAGS  += $1)
COMMON_CFLAGS	     += -I$(wORLD_ROOT)/third_party/build/$(X4C_ARCH)/windows -DWIN32 -DWIN64 -D_WIN32 -D_WIN64
COMMON_CFLAGS	     += -D_WIN32_WINNT=0x0601 -D_UNICODE -DUNICODE
## /std:c++17 belongs to the C++-only variable: the shared X4C_MSVCSPEC_CFLAGS
## is passed to both the C and the C++ recipe (Build/config/windows.conf), and
## clang-cl warns "argument unused during compilation: '/std:c++17'" on C files.
X4C_MSVCSPEC_CFLAGS_CXX += /std:c++17
X4C_COMMON_LDFLAGS   += -libpath:$(wORLD_ROOT)/third_party/build/$(X4C_ARCH)/windows
X4C_COMMON_LDFLAGS   += -libpath:$(wORLD_ROOT)/third_party/pre-built/$(X4C_ARCH)-windows
X4C_COMMON_LDFLAGS   += ws2_32.lib user32.lib kernel32.lib gdi32.lib advapi32.lib crypt32.lib
endif


ifeq ("$(X4C_BOARD)","foobar")
COMMON_CFLAGS		+= -D__EMULATOR__
else  ## foobar
ifeq ("$(X4C_BUILD)","emscripten")
COMMON_CFLAGS		+= -D__EMULATOR__
endif ## emscripten
endif ## foobar

##
##
##
COMMON_CFLAGS += -DrLANG_WORLD_SEED_0=$(rLANG_WORLD_SEED_0)
COMMON_CFLAGS += -DrLANG_WORLD_SEED_1=$(rLANG_WORLD_SEED_1)
COMMON_CFLAGS += -DrLANG_WORLD_SEED_2=$(rLANG_WORLD_SEED_2)
COMMON_CFLAGS += -DrLANG_WORLD_SEED_3=$(rLANG_WORLD_SEED_3)

##
##
X4C_COMMON_CFLAGS   += $(COMMON_CFLAGS)
X4C_COMMON_CXXFLAGS += $(COMMON_CFLAGS)

##
##
##
X4C_BUILD_PROJECT_FILES := \
	$(wORLD_ROOT)/src/project.mk \
	$(wORLD_ROOT)/MCU/project.mk \
	$(wORLD_ROOT)/third_party/project.mk \


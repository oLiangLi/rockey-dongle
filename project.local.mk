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

##
##
##
ifeq ("$(X4C_ARCH)","wasm")
X4C_WASM_OPT       ?= $(EMSDK)/upstream/bin/wasm-opt
wasm_add_cflags     = $(eval LOCAL_CFLAGS   += $1)
wasm_add_cxxflags   = $(eval LOCAL_CXXFLAGS += $1)
wasm_add_ldflags    = $(eval LOCAL_LDFLAGS  += $1)
COMMON_CFLAGS	   += -DrLANG_WORLD_STANDALONE=1 -DX_ARCH_wasm=1
COMMON_CFLAGS      += -I$(wORLD_ROOT)/third_party/build/wasm -I$(wORLD_ROOT)/third_party/build/wasmjs
X4C_COMMON_LDFLAGS += -L$(wORLD_ROOT)/third_party/build/wasm -L$(wORLD_ROOT)/third_party/build/wasmjs
X4C_COMMON_LDFLAGS += -s WASM=1 -s ERROR_ON_UNDEFINED_SYMBOLS=0 -s STANDALONE_WASM=1
X4C_COMMON_CXXFLAGS+= -fno-rtti -fno-common -fno-use-cxa-atexit -fno-exceptions -fno-non-call-exceptions -std=c++17
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
	$$(hide) $$(X_NODE) $$(wORLD_ROOT)/Build/tools/script/wasm2string.cjs $$@
endef
endif

##
##
##
ifeq ("$(X4C_ARCH)","wasmjs")
wasmjs_add_cflags   = $(eval LOCAL_CFLAGS   += $1)
wasmjs_add_cxxflags = $(eval LOCAL_CXXFLAGS += $1)
wasmjs_add_ldflags  = $(eval LOCAL_LDFLAGS  += $1)
COMMON_CFLAGS      += -I$(wORLD_ROOT)/third_party/build/wasmjs
X4C_COMMON_LDFLAGS += -L$(wORLD_ROOT)/third_party/build/wasmjs
X4C_COMMON_LDFLAGS += -s EXIT_RUNTIME=0 -s WASM=1 -s MODULARIZE=1
X4C_COMMON_CXXFLAGS+= -fno-rtti -fno-common -fno-use-cxa-atexit -fno-exceptions -fno-non-call-exceptions -std=c++17
endif

##
##
##
ifeq ("$(X4C_BUILD)","linux")
linux_add_cflags    = $(eval LOCAL_CFLAGS   += $1)
linux_add_cxxflags  = $(eval LOCAL_CXXFLAGS += $1)
linux_add_ldflags   = $(eval LOCAL_LDFLAGS  += $1)
X4C_COMMON_CXXFLAGS+= -std=c++17
COMMON_CFLAGS	     += -I$(wORLD_ROOT)/third_party/build/$(X4C_ARCH)/linux -pthread
X4C_COMMON_LDFLAGS += -L$(wORLD_ROOT)/third_party/build/$(X4C_ARCH)/linux -pthread -ldl
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
X4C_MSVCSPEC_CFLAGS  += /std:c++17
X4C_COMMON_LDFLAGS   += -libpath:$(wORLD_ROOT)/third_party/build/$(X4C_ARCH)/windows
X4C_COMMON_LDFLAGS   += -libpath:$(wORLD_ROOT)/third_party/pre-built/$(X4C_ARCH)-windows
X4C_COMMON_LDFLAGS   += ws2_32.lib user32.lib kernel32.lib gdi32.lib advapi32.lib crypt32.lib
endif

##
##
X4C_COMMON_CFLAGS   += $(COMMON_CFLAGS)
X4C_COMMON_CXXFLAGS += $(COMMON_CFLAGS)

##
##
##
X4C_BUILD_PROJECT_FILES := \
	$(wORLD_ROOT)/src/project.mk \
	$(wORLD_ROOT)/third_party/project.mk \
	$(wORLD_ROOT)/MCU/RockeyARM/project.mk

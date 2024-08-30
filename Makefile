wORLD_ROOT := $(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))

##
##
##
X4C_NODE ?= /Machine/System/bin/node

.PHONY : wasm wasmjs cygwin linux aarch64-linux windows all-platform bootstrap install install-platform
.PHONY : clean-wasm clean-wasmjs clean-cygwin clean-linux clean-aarch64-linux clean-windows clean-all-platform
.PHONY : typescript typescript0 docker all-docker dongle clean-dongle

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
wasm:
	$(MAKE) -C $(wORLD_ROOT) wORLD_CONFIG=wasm prepare R=1
	$(MAKE) -C $(wORLD_ROOT) wORLD_CONFIG=wasm optimize R=1

wasmjs:
	$(MAKE) -C $(wORLD_ROOT) wORLD_CONFIG=wasmjs prepare R=1
	$(MAKE) -C $(wORLD_ROOT) wORLD_CONFIG=wasmjs optimize R=1

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

clean-wasmjs:
	$(MAKE) -C $(wORLD_ROOT) wORLD_CONFIG=wasmjs clean-all  R=1

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

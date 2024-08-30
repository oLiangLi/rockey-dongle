THIRD_PARTY_INSTALL_PREFIX := $(shell mkdir -p $(X4C_GENERATE)/System && realpath $(X4C_GENERATE)/System)
THIRD_PARTY_INSTALL_BINARY := $(shell mkdir -p $(X4C_BINARY) && realpath "$(X4C_BINARY)")

ifeq ("$(X4C_BUILD)","emscripten")

##
##
##
X4C_COMMON_CFLAGS   += -I$(THIRD_PARTY_INSTALL_PREFIX)/include
X4C_COMMON_CXXFLAGS += -I$(THIRD_PARTY_INSTALL_PREFIX)/include
X4C_COMMON_LDFLAGS  += -L$(THIRD_PARTY_INSTALL_PREFIX)/lib -lssl -lcrypto

##
##
##
.PHONY : build-tassl-library

BUILD_TASSL_LIBRARY_BUILD_ROOT   := $(THIRD_PARTY_INSTALL_PREFIX)/Build-TASSL
BUILD_TASSL_LIBRARY_BUILD_STAMP  := $(BUILD_TASSL_LIBRARY_BUILD_ROOT)/.build-tassl-done
BUILD_TASSL_LIBRARY_SOURCE_ROOT  := $(shell realpath $(wORLD_ROOT)/third_party/TASSL-1.1.1)

prepare: build-tassl-library

build-tassl-library: $(BUILD_TASSL_LIBRARY_BUILD_STAMP)
$(BUILD_TASSL_LIBRARY_BUILD_STAMP):
	mkdir -p $(BUILD_TASSL_LIBRARY_BUILD_ROOT)
	cd $(BUILD_TASSL_LIBRARY_BUILD_ROOT) && emconfigure $(BUILD_TASSL_LIBRARY_SOURCE_ROOT)/Configure --prefix=$(THIRD_PARTY_INSTALL_PREFIX) \
		-no-asm -no-threads -no-pic -no-zlib -static -no-tests linux-generic32 --openssldir=/tmp/jsCrypto/ssl
	$(MAKE) -C $(BUILD_TASSL_LIBRARY_BUILD_ROOT) CROSS_COMPILE= ENGINESDIR=/Machine/System/engine OPENSSLDIR=/Machine/System/ssl -i
	$(MAKE) -C $(BUILD_TASSL_LIBRARY_BUILD_ROOT) CROSS_COMPILE= install -i
	touch $@

endif ## Wasm build Tassl ...

ifeq ("$(X4C_ARCH)-$(X4C_BUILD)","amd64-linux")

##
##
##
X4C_COMMON_CFLAGS   += -I$(THIRD_PARTY_INSTALL_PREFIX)/include
X4C_COMMON_CXXFLAGS += -I$(THIRD_PARTY_INSTALL_PREFIX)/include
X4C_COMMON_LDFLAGS  += -L$(THIRD_PARTY_INSTALL_PREFIX)/lib -lssl -lcrypto

##
##
##
.PHONY : build-tassl-library

BUILD_TASSL_LIBRARY_BUILD_ROOT   := $(THIRD_PARTY_INSTALL_PREFIX)/Build-TASSL
BUILD_TASSL_LIBRARY_BUILD_STAMP  := $(BUILD_TASSL_LIBRARY_BUILD_ROOT)/.build-tassl-done
BUILD_TASSL_LIBRARY_SOURCE_ROOT  := $(shell realpath $(wORLD_ROOT)/third_party/TASSL-1.1.1)

prepare: build-tassl-library

build-tassl-library: $(BUILD_TASSL_LIBRARY_BUILD_STAMP)
$(BUILD_TASSL_LIBRARY_BUILD_STAMP):
	mkdir -p $(BUILD_TASSL_LIBRARY_BUILD_ROOT)
	cd $(BUILD_TASSL_LIBRARY_BUILD_ROOT) && $(BUILD_TASSL_LIBRARY_SOURCE_ROOT)/Configure --prefix=$(THIRD_PARTY_INSTALL_PREFIX) \
		-static -no-tests linux-x86_64 --openssldir=/tmp/jsCrypto/ssl
	$(MAKE) -C $(BUILD_TASSL_LIBRARY_BUILD_ROOT) CROSS_COMPILE= ENGINESDIR=/Machine/System/engine OPENSSLDIR=/Machine/System/ssl -i
	$(MAKE) -C $(BUILD_TASSL_LIBRARY_BUILD_ROOT) CROSS_COMPILE= install -i
	touch $@

endif ## linux build Tassl ...


ifeq ("$(X4C_ARCH)-$(X4C_BUILD)","amd64-windows")

##
##
##
THIRD_PARTY_INSTALL_WIN_PREFIX := $(shell cygpath -m "$(THIRD_PARTY_INSTALL_PREFIX)")

##
##
##
X4C_COMMON_CFLAGS   += -I$(THIRD_PARTY_INSTALL_WIN_PREFIX)/include
X4C_COMMON_CXXFLAGS += -I$(THIRD_PARTY_INSTALL_WIN_PREFIX)/include
X4C_COMMON_LDFLAGS  += $(THIRD_PARTY_INSTALL_WIN_PREFIX)/lib/libcrypto.dll.a $(THIRD_PARTY_INSTALL_WIN_PREFIX)/lib/libssl.dll.a

##
##
##
BUILD_TASSL_LIBRARY_BUILD_ROOT   := $(THIRD_PARTY_INSTALL_PREFIX)/Build-TASSL
BUILD_TASSL_LIBRARY_BUILD_STAMP  := $(BUILD_TASSL_LIBRARY_BUILD_ROOT)/.build-tassl-done
BUILD_TASSL_LIBRARY_SOURCE_ROOT  := $(shell realpath $(wORLD_ROOT)/third_party/TASSL-1.1.1)

prepare: build-tassl-library

build-tassl-library: $(BUILD_TASSL_LIBRARY_BUILD_STAMP)
$(BUILD_TASSL_LIBRARY_BUILD_STAMP):
	mkdir -p $(BUILD_TASSL_LIBRARY_BUILD_ROOT)
	cd $(BUILD_TASSL_LIBRARY_BUILD_ROOT) && $(BUILD_TASSL_LIBRARY_SOURCE_ROOT)/Configure --prefix=$(THIRD_PARTY_INSTALL_PREFIX) \
		-no-tests mingw64 --cross-compile-prefix=x86_64-w64-mingw32- --openssldir=/tmp/jsCrypto/ssl
	$(MAKE) -C $(BUILD_TASSL_LIBRARY_BUILD_ROOT) ENGINESDIR=/Machine/System/engine OPENSSLDIR=/Machine/System/ssl -i
	$(MAKE) -C $(BUILD_TASSL_LIBRARY_BUILD_ROOT) install -i
	install -m $(SO_INSTALL_MODE) $(THIRD_PARTY_INSTALL_PREFIX)/bin/libcrypto-1_1-x64.dll "$(THIRD_PARTY_INSTALL_BINARY)"
	install -m $(SO_INSTALL_MODE) $(THIRD_PARTY_INSTALL_PREFIX)/bin/libssl-1_1-x64.dll "$(THIRD_PARTY_INSTALL_BINARY)"
	touch $@

endif ## windows build Tassl ...

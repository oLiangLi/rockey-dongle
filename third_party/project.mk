THIRD_PARTY_INSTALL_PREFIX := $(shell mkdir -p $(X4C_GENERATE)/System && realpath $(X4C_GENERATE)/System)

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

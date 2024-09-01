LOCAL_PATH := $(my-dir)

$(call clear-local-vars)
LOCAL_MODULE := aeabi_cortexm0
$(call add_general_source_files_under, $(LOCAL_PATH)/libeabi-cortexm0)
LOCAL_SRC_FILES := libc.c
$(call build-library)


$(call clear-local-vars)
LOCAL_MODULE    := rockey_dongle
LOCAL_SRC_FILES := start.s app.cc
LOCAL_LDFLAGS   := -Ttext=0 -Wl,-e,_world_start -T$(LOCAL_PATH)/linker.ld -Wl,-Map=$(X4C_OUTPUT)/rockey-dongle.map
$(call module_depends, __Testing__aes__ aeabi_cortexm0 base)
$(call build-executable)

.PHONY : install-rockey-dongle
install-platform: install-rockey-dongle
	$(hide) $(X4C_NODE) $(wORLD_ROOT)/MCU/RockeyARM/elf2bin.cjs $(X4C_BINARY)/rockey_dongle$(EXEEXT) $(X4C_BINARY)/rockey_dongle.bin
	$(hide) $(X4C_BUILD_CROSS)readelf -lS $(X4C_BINARY)/rockey_dongle$(EXEEXT)
	$(hide) ls -l $(X4C_BINARY)/rockey_dongle*

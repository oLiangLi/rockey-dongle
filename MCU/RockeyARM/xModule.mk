LOCAL_PATH := $(my-dir)

ROCKEYARM_WORLD_ROOT := $(LOCAL_PATH)

$(call clear-local-vars)
LOCAL_MODULE := rockey_dongle

LOCAL_LDFLAGS  := -Ttext=0 -Wl,-e,_world_start -T$(LOCAL_PATH)/linker.ld -Wl,-Map=$(X4C_OUTPUT)/rockey-dongle.map

$(call add_general_source_files_under, $(LOCAL_PATH))
$(call module_depends, __Testing__aes__ base)
$(call build-executable)

.PHONY : install-rockey-dongle
install-platform: install-rockey-dongle
	$(hide) $(X4C_NODE) $(ROCKEYARM_WORLD_ROOT)/elf2bin.cjs $(X4C_BINARY)/rockey_dongle$(EXEEXT) $(X4C_BINARY)/rockey_dongle.bin
	$(hide) ls -l $(X4C_BINARY)/rockey_dongle*
	$(hide) $(X4C_BUILD_CROSS)readelf -lS $(X4C_BINARY)/rockey_dongle$(EXEEXT)
	

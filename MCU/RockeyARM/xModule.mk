LOCAL_PATH := $(my-dir)

ROCKEYARM_WORLD_ROOT := $(LOCAL_PATH)

ROCKEYARM_COMMON_CFLAGS := -std=c99 -mcpu=cortex-m0 -mthumb -ffunction-sections -fdata-sections
ROCKEYARM_COMMON_CFLAGS += -O1 -Os -DrLANG_CONFIG_MIMIMAL_LEVEL=9 -fstack-usage -nostdlib 
ROCKEYARM_COMMON_CFLAGS += -funsigned-char -fshort-enums -fshort-wchar
ROCKEYARM_COMMON_CFLAGS += -I$(LOCAL_PATH)/include

ROCKEYARM_COMMON_LDFLAGS := -nostartfiles -Wl,-nostdlib -nostdlib  -Wl,--cref -Wl,--gc-section
ROCKEYARM_COMMON_LDFLAGS += -Ttext=0 -Wl,-e,_world_start -T$(LOCAL_PATH)/linker.ld
ROCKEYARM_COMMON_LDFLAGS += -Wl,-Map=$(X4C_OUTPUT)/rockey-dongle.map
ROCKEYARM_COMMON_LDFLAGS += $(LOCAL_PATH)/lib/FTRX.a

$(call clear-local-vars)
LOCAL_MODULE := rockey_dongle

LOCAL_CFLAGS   := $(ROCKEYARM_COMMON_CFLAGS)
LOCAL_CXXFLAGS := $(ROCKEYARM_COMMON_CFLAGS)
LOCAL_LDFLAGS  := $(ROCKEYARM_COMMON_LDFLAGS)

$(call add_general_source_files_under, $(LOCAL_PATH))
$(call build-executable)

.PHONY : install-rockey-dongle
install-platform: install-rockey-dongle
	$(X4C_NODE) $(ROCKEYARM_WORLD_ROOT)/elf2bin.cjs $(X4C_BINARY)/rockey_dongle$(EXEEXT) $(X4C_BINARY)/rockey_dongle.bin

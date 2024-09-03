LOCAL_PATH := $(my-dir)

ifeq ("$(X4C_BOARD)","RockeyARM")

ROCKEYARM_COMMON_CFLAGS := -mcpu=cortex-m0 -mthumb -ffunction-sections -fdata-sections
ROCKEYARM_COMMON_CFLAGS += -O1 -Os -DrLANG_CONFIG_MIMIMAL_LEVEL=9 -fstack-usage -nostdlib
ROCKEYARM_COMMON_CFLAGS += -include $(LOCAL_PATH)/RockeyARM/rockey_predef.h
ROCKEYARM_COMMON_CFLAGS += -funsigned-char -fshort-enums -fshort-wchar
ROCKEYARM_COMMON_CFLAGS += -I$(LOCAL_PATH)/RockeyARM/include

ROCKEYARM_COMMON_CFLAGS += -D__RockeyARM__

ROCKEYARM_COMMON_LDFLAGS := -nostartfiles -Wl,-nostdlib -nostdlib  -Wl,--cref -Wl,--gc-section
ROCKEYARM_COMMON_LDFLAGS += $(LOCAL_PATH)/RockeyARM/lib/FTRX.a

X4C_COMMON_CFLAGS   += $(ROCKEYARM_COMMON_CFLAGS) -std=c99 
X4C_COMMON_CXXFLAGS += $(ROCKEYARM_COMMON_CFLAGS) -std=c++17 -fno-rtti -fno-exceptions
X4C_COMMON_LDFLAGS  += $(ROCKEYARM_COMMON_LDFLAGS)

endif ## RockeyARM

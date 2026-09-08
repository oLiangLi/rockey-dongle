LOCAL_PATH := $(my-dir)

$(call clear-local-vars)
LOCAL_MODULE := __Testing__x509import__

$(call module_depends, rockey base)

## 只在这两个目标构建: foobar(模拟器)或 windows 真机主机(X4C_BOARD 为空);
## 共用用例在 main.cc, Dongle opener 按板选单一实现(emu/ 或 device/), 避免 #if 大块。
LOCAL_SRC_FILES := main.cc

X509IMPORT_OK :=
ifeq ("$(X4C_BOARD)","foobar")
X509IMPORT_OK := 1
LOCAL_SRC_FILES += emu/open.cc
else ifeq ("$(X4C_BUILD)","windows")
ifeq ("$(X4C_BOARD)","")
X509IMPORT_OK := 1
LOCAL_SRC_FILES += device/open.cc
endif
else ifeq ("$(X4C_BUILD)","linux")
ifeq ("$(X4C_BOARD)","")
X509IMPORT_OK := 1
LOCAL_SRC_FILES += device/open.cc
endif
endif

ifeq ("$(X509IMPORT_OK)","1")
$(call build-executable)
endif ## X509IMPORT_OK

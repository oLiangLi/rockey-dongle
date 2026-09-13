LOCAL_PATH := $(my-dir)

$(call clear-local-vars)
LOCAL_MODULE := __Testing__rsamodexpvm__

$(call add_general_source_files_under, $(LOCAL_PATH))
$(call module_depends, rockey base)

## opcode 层用例需要 VM_t + Emulator(宿主内存世界), 因此只在 foobar(模拟器)板构建;
## 设备端(真机耗时/栈)由 __Testing__dongle__ 的 index 20 与 rockey-stack-check 覆盖。
ifeq ("$(X4C_BOARD)","foobar")
$(call build-executable)
endif

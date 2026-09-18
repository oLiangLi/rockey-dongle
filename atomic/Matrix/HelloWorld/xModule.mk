LOCAL_PATH := $(my-dir)

$(call clear-local-vars)
LOCAL_MODULE := MatrixHelloWorld
$(call add_general_source_files_under, $(LOCAL_PATH))

LOCAL_LDFLAGS := -T $(LOCAL_PATH)/../ldscript/default.ld

$(call module_depends, base op_GATE)
$(call build-executable)

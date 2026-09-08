LOCAL_PATH := $(my-dir)

$(call clear-local-vars)
LOCAL_MODULE := __Testing__x509import__

$(call add_general_source_files_under, $(LOCAL_PATH))
$(call module_depends, rockey base)

ifeq ("$(X4C_BOARD)","foobar")
$(call build-executable)
endif ## X4C_BOARD == foobar

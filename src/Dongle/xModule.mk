LOCAL_PATH := $(my-dir)

$(call clear-local-vars)
LOCAL_MODULE := dongleEntry

$(call add_general_source_files_under, $(LOCAL_PATH))
$(call module_depends, base)

ifeq ("$(X4C_BUILD)","native")
$(call build-library)
else
$(call build-executable)
endif


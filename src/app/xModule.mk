LOCAL_PATH := $(my-dir)

$(call clear-local-vars)
LOCAL_MODULE := dongle_entry

$(call add_general_source_files_under, $(LOCAL_PATH))
$(call module_depends, rockey base)

ifeq ("$(X4C_BUILD)","native")
$(call build-library)
else
$(call build-executable)
endif



LOCAL_PATH := $(my-dir)

$(call clear-local-vars)
LOCAL_MODULE := base
$(call add_general_source_files_under, $(LOCAL_PATH))
$(call add_general_source_files_under, $(wORLD_ROOT)/Web/Grammar)
$(call build-library)

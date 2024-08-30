LOCAL_PATH := $(my-dir)

ifneq ("$(X4C_BUILD)","native")

$(call clear-local-vars)
LOCAL_MODULE := HelloWorld

$(call add_general_source_files_under, $(LOCAL_PATH))
$(call module_depends, base)
$(call build-executable)

endif ## !native .

LOCAL_PATH := $(my-dir)

$(call clear-local-vars)
LOCAL_MODULE := __Testing__rsamr__

$(call add_general_source_files_under, $(LOCAL_PATH))
$(call module_depends, base)

ifneq ("$(X4C_BUILD)","native")
$(call build-executable)
endif

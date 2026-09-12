LOCAL_PATH := $(my-dir)

$(call clear-local-vars)
LOCAL_MODULE := __Testing__dongle__

$(call add_general_source_files_under, $(LOCAL_PATH))
$(call module_depends, rockey base)

ifeq ("$(X4C_BUILD)","native")
$(call build-library)
else ## X4C_BUILD
ifeq ("$(rLANG_BUILD_WORLD)","COSMO")
$(call build-executable)
endif ## rLANG_BUILD_WORLD
endif ## X4C_BUILD


LOCAL_PATH := $(my-dir)

$(call clear-local-vars)
LOCAL_MODULE := __Testing__rsamrprobe__
$(call add_general_source_files_under, $(LOCAL_PATH))
$(call module_depends, rockey base)

##
##
##
ifneq ("$(X4C_BOARD)", "foobar")
ifeq ("$(rLANG_BUILD_WORLD)","COSMO")
$(call build-executable)
endif ## rLANG_BUILD_WORLD
endif ## X4C_BOARD

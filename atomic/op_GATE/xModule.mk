LOCAL_PATH := $(my-dir)
$(call clear-local-vars)

LOCAL_MODULE := op_GATE

##
##
##
ifeq ("$(X4C_ARCH)-$(X4C_BUILD)","rv32im-rockey")
$(call add_general_source_files_under, $(LOCAL_PATH)/gen)
$(call add_general_source_files_under, $(LOCAL_PATH)/helper)
$(call add_general_source_files, $(LOCAL_PATH)/hyper/modules.cc)
else  ## rv32im-rockey
$(call add_general_source_files_under, $(LOCAL_PATH)/hyper)
endif ## rv32im-rockey
$(call build-library)

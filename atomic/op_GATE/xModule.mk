LOCAL_PATH := $(my-dir)
$(call clear-local-vars)

LOCAL_MODULE := op_GATE

##
##
##
$(call add_general_source_files_under, $(LOCAL_PATH)/grammar)

##
##
LOCAL_SCENARIO_JSON_FILE := $(X4C_GENERATE)/op_GATE/grammar.json

##
##
LOCAL_SCENARIO_TS_FILE := $(X4C_GENERATE)/op_GATE/grammar.ts

##
##
LOCAL_SCENARIO_CC_BASEDIR := $(X4C_GENERATE)/op_GATE

##
##
LOCAL_SCENARIO_CC_HEADER  := grammar.h

##
##
LOCAL_SCENARIO_CC_SOURCE  := grammar.cc

##
##
#LOCAL_SCENARIO_CC_ACTION := true

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

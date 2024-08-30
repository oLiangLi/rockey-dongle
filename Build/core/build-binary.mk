
##
## local variant 
##
x4c_MODULE_MAKE_FILE  := $(call local-makefile)
x4c_MODULE_MAKE_PATH  := $(patsubst %/,%,$(dir $(call local-makefile)))

x4c_MODULE_OUTPUT     := $(X4C_OUTPUT)/$(LOCAL_MODULE)
$(eval $(x4c_MODULE_OUTPUT)   : ; $$(call x4c_cmd_mkdir,$$@))

##
##
##
x4c_MODULE_ALL_SOURCE := $(LOCAL_SRC_FILES_A) $(addprefix $(x4c_MODULE_MAKE_PATH)/,$(LOCAL_SRC_FILES))

x4c_MODULE_C_SOURCE_FILES   := $(filter $(X4C_C_SRC_EXT_LIST)  , $(x4c_MODULE_ALL_SOURCE))
x4c_MODULE_CPP_SOURCE_FILES := $(filter $(X4C_CPP_SRC_EXT_LIST), $(x4c_MODULE_ALL_SOURCE))
x4c_MODULE_ASM_SOURCE_FILES := $(filter $(X4C_ASM_SRC_EXT_LIST), $(x4c_MODULE_ALL_SOURCE))

##
## global variant
##
$(LOCAL_MODULE)_CFLAGS    := $(LOCAL_CFLAGS) $(X4C_COMMON_CFLAGS) \
			-DX_BUILD_MODULE_$(LOCAL_MODULE) -I$(x4c_MODULE_MAKE_PATH)/inc
$(LOCAL_MODULE)_CXXFLAGS  := $(LOCAL_CXXFLAGS) $(X4C_COMMON_CXXFLAGS) \
			-DX_BUILD_MODULE_$(LOCAL_MODULE) -I$(x4c_MODULE_MAKE_PATH)/inc
$(LOCAL_MODULE)_ASFLAGS   := $(LOCAL_ASFLAGS) $(X4C_COMMON_ASFLAGS) -DX_BUILD_MODULE_$(LOCAL_MODULE)
$(LOCAL_MODULE)_LDFLAGS	  := $(LOCAL_LDFLAGS) $(X4C_COMMON_LDFLAGS)
$(LOCAL_MODULE)_ARFLAGS	  := $(LOCAL_ARFLAGS) $(X4C_COMMON_ARFLAGS)

ifeq ("$(LOCAL_VISIBILITY_FLAGS)","1")
$(LOCAL_MODULE)_CFLAGS	  += $(X4C_TOOLCHAIN_VISIBILITY_CFLAGS)
$(LOCAL_MODULE)_CXXFLAGS  += $(X4C_TOOLCHAIN_VISIBILITY_CXXFLAGS)
endif

$(LOCAL_MODULE)-objects-list  := $(call x4c_gen_output_file_path,$(x4c_MODULE_OUTPUT)/,$(OBJEXT),\
	$(x4c_MODULE_C_SOURCE_FILES) $(x4c_MODULE_CPP_SOURCE_FILES) $(x4c_MODULE_ASM_SOURCE_FILES))

$(LOCAL_MODULE)-depends-list  := $(call x4c_gen_output_file_path,$(x4c_MODULE_OUTPUT)/,$(DEPEXT),\
	$(x4c_MODULE_C_SOURCE_FILES) $(x4c_MODULE_CPP_SOURCE_FILES))

##
##
##
x4c_MODULE_CURR_DEP   := $(wildcard $(x4c_MODULE_OUTPUT)/*$(DEPEXT))

##
## object depends MAKEFILE.
##
$(foreach __a_object_file,$($(strip $(LOCAL_MODULE)-objects-list)),$(eval $(__a_object_file):$(x4c_MODULE_MAKE_FILE)))

##
##
##
.PHONY : $(LOCAL_MODULE) $(LOCAL_MODULE)-clean 	\
		 $(LOCAL_MODULE)-show-build-info 		\
		 $(LOCAL_MODULE)-prepare		 		\
	 	 $(LOCAL_MODULE)-show-clean-info

##
##
##
$(eval prepare: $(LOCAL_MODULE)-prepare)
$(eval $(LOCAL_MODULE): $(LOCAL_MODULE)-show-build-info $(x4c_MODULE_OUTPUT))
$(eval $(LOCAL_MODULE): $(X4C_LIBRARY)  $(X4C_BINARY)  $(LOCAL_MODULE_TARGETS))
$(eval build-all: $(LOCAL_MODULE))
$(eval clean-all: $(LOCAL_MODULE)-clean)

$(eval $(LOCAL_MODULE)-clean: $(LOCAL_MODULE)-show-clean-info ; \
	$$(call x4c_cmd_rmdir,$(x4c_MODULE_OUTPUT)) ;\
	$$(call x4c_cmd_rm,$(LOCAL_MODULE_TARGETS)))

$(eval $(LOCAL_MODULE)-show-build-info: ; $$(call x4c_cmd_show_build_module_info ,$(LOCAL_MODULE)))
$(eval $(LOCAL_MODULE)-show-clean-info: ; $$(call x4c_cmd_show_clean_module_info ,$(LOCAL_MODULE)))

$(eval $(LOCAL_MODULE_TARGETS) : $$($(strip $(LOCAL_MODULE)-objects-list)))

ifneq ("$(D)","0")
include $(x4c_MODULE_CURR_DEP)
endif

##
##	filter
##
$(foreach __a_filter,$(__x4c_all_filters), $(eval $(call $(__a_filter))))

##
##	CC source file.
##
$(foreach __a_file,$(x4c_MODULE_C_SOURCE_FILES),\
	$(eval $(call x4c-cmd-cc,$(__a_file),\
		$(call x4c_gen_output_file_path,$(x4c_MODULE_OUTPUT)/,$(OBJEXT),$(__a_file)),\
		$(call x4c_gen_output_file_path,$(x4c_MODULE_OUTPUT)/,$(DEPEXT),$(__a_file)),\
			$(LOCAL_MODULE)_CFLAGS)))

##
##	CXX source file.
##
$(foreach __a_file,$(x4c_MODULE_CPP_SOURCE_FILES),\
	$(eval $(call x4c-cmd-cxx,$(__a_file),\
		$(call x4c_gen_output_file_path,$(x4c_MODULE_OUTPUT)/,$(OBJEXT),$(__a_file)),\
		$(call x4c_gen_output_file_path,$(x4c_MODULE_OUTPUT)/,$(DEPEXT),$(__a_file)),\
			$(LOCAL_MODULE)_CXXFLAGS)))

##
##	ASM source file.
##
$(foreach __a_file,$(x4c_MODULE_ASM_SOURCE_FILES),\
	$(eval $(call x4c-cmd-as,$(__a_file),\
		$(call x4c_gen_output_file_path,$(x4c_MODULE_OUTPUT)/,$(OBJEXT),$(__a_file)),\
			$(LOCAL_MODULE)_ASFLAGS)))


######################################################################################
##
##	cleanup local variant ( except x4c_MODULE_OUTPUT )
##
$(call clear-vars,x4c_MODULE_MAKE_FILE x4c_MODULE_MAKE_PATH x4c_MODULE_ALL_SOURCE \
	x4c_MODULE_C_SOURCE_FILES x4c_MODULE_CPP_SOURCE_FILES x4c_MODULE_ASM_SOURCE_FILES )


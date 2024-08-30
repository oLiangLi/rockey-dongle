
##
##
##
__x4c_all_modules := $(call set_create,)
__x4c_all_filters := $(call set_create,)

##
##
##
__x4c_all_modules_file := $(call set_create,)
__x4c_all_filters_info := $(empty)


# ----------------------------------------------------------------------------
# Function: x4c_add_module
# Arguments: 1: modulename
# ----------------------------------------------------------------------------
x4c_add_module = \
  $(if $(call filter,$(__x4c_all_modules),$1),  \
	   $(call error,Local module ** $1 ** already defined.)) \
	$(eval __x4c_all_modules := $(call set_insert,$1,$(__x4c_all_modules)))	\
	$(eval __x4c_all_modules_file := $(call set_insert,$(local-makefile),$(__x4c_all_modules_file)))

# ----------------------------------------------------------------------------
# Function: x4c_register_filter
# Arguments: 1: filter function name
#            2: filter infomation
# ----------------------------------------------------------------------------
x4c_register_filter = \
  $(if $(call filter,$(__x4c_all_filters),$1),  \
	   $(call error,filter module ** $1 ** already defined.)) \
	$(eval __x4c_all_filters := $(call set_insert,$1,$(__x4c_all_filters)))	\
	$(eval __x4c_all_filters_info += $2 )

#
#	x4c_gen_output_file_path  <outpath> <ext>  <input...>
#
x4c_gen_output_file_path = $(addprefix $1,$(addsuffix $2,$(call file_base_name,$3)))

##
##
##
include $(X4C_BUILD_SYSTEM)/core/common.mk
include $(X4C_BUILD_SYSTEM)/filter/*.filter

##
## COMMON FLAGS ...
##
X4C_ARCH_CFLAGS   := -DX_ARCH_$(X4C_ARCH) -DX_BUILD_$(X4C_BUILD) -I$(X4C_GENERATE)
X4C_ARCH_ASFLAGS  := -DX_ARCH_$(X4C_ARCH) -DX_BUILD_$(X4C_BUILD) -I$(X4C_GENERATE)

X4C_COMMON_CFLAGS   += $(X4C_USER_CFLAGS)
X4C_COMMON_CXXFLAGS += $(X4C_USER_CXXFLAGS)
X4C_COMMON_ARFLAGS  += $(X4C_USER_ARFLAGS)
X4C_COMMON_ASFLAGS  += $(X4C_USER_ASFLAGS)
X4C_COMMON_LDFLAGS  += $(X4C_USER_LDFLAGS)

X4C_COMMON_CFLAGS   += $(X4C_TOOLCHAIN_CFLAGS) $(X4C_ARCH_CFLAGS)
X4C_COMMON_CXXFLAGS += $(X4C_TOOLCHAIN_CXXFLAGS) $(X4C_ARCH_CFLAGS)

ifeq ("$(R)","1")
X4C_COMMON_CFLAGS   += $(X4C_RELEASE_CFLAGS)
X4C_COMMON_CXXFLAGS += $(X4C_RELEASE_CXXFLAGS)
else
X4C_COMMON_CFLAGS   += $(X4C_DEBUG_CFLAGS)
X4C_COMMON_CXXFLAGS += $(X4C_DEBUG_CXXFLAGS)
endif

X4C_COMMON_ASFLAGS += $(X4C_TOOLCHAIN_ASLAGS) $(X4C_ARCH_ASFLAGS)
X4C_COMMON_LDFLAGS += $(X4C_TOOLCHAIN_LDFLAGS)
$(call x4c-cmd-ldflags-add-dir,X4C_COMMON_LDFLAGS,$(X4C_LIBRARY))

##
##
##
-include $(X4C_BUILD_PROJECT_FILES)

##
##
##
include $(X4C_BUILD_MODULE)

##
## Next rebuild-all ...
##
touch: ; $(hide) touch $(__x4c_all_modules_file)

##
##
##
hello:
	$(info ----------------------------------------------------------------------- )
	$(info $(space2))
	$(info $(space4) $(space4) X4C BUILD SYSTEM(v$(X4C_BUILD_SYSTEM_VERSION)))
	$(info $(space2))

	$(info ----------------------------------------------------------------------- )
	$(info $(space2) BUILD : $(X4C_BUILD))
	$(info $(space2) ARCH  : $(X4C_ARCH))
ifneq ("$(X4C_BOARD)","")
	$(info $(space2) BOARD : $(X4C_BOARD))
endif
	$(info $(space2) DEBUG ? $(X4C_CONF_VER))
	$(info $(space2))
	$(info $(space2) LOCAL    PATH : $(X4C_BUILD_XWORLD))
	$(info $(space2) BINARY   PATH : $(X4C_BINARY))
	$(info $(space2) OBJECT   PATH : $(X4C_OUTPUT))
	$(info $(space2) LIBRARY  PATH : $(X4C_LIBRARY))
	$(info $(space2) GENERATE PATH : $(X4C_GENERATE))

	$(info $(space2))
	$(info $(space2) CC       : $(X4C_CC)  )
	$(info $(space2) CXX      : $(X4C_CXX) )
	$(info $(space2) AR       : $(X4C_AR)  )
	$(info $(space2) LD       : $(X4C_LD)  )
	$(info $(space2) ASM      : $(X4C_ASM) )
	$(info $(space2))
	$(info $(space2) CFLAGS   : $(X4C_COMMON_CFLAGS))
	$(info $(space2) CXXFLAGS : $(X4C_COMMON_CXXFLAGS))
	$(info $(space2) ASFLAGS  : $(X4C_COMMON_ASFLAGS))
	$(info $(space2) LDFLAGS  : $(X4C_COMMON_LDFLAGS))
	$(info $(space2))

	$(info ----------------------------------------------------------------------- )
	$(info $(space2) Filter list : $(__x4c_all_filters_info))
	$(info $(space2))

	$(info ----------------------------------------------------------------------- )
	$(info $(space2) Entry module file(s) : $(X4C_BUILD_MODULE))
	$(info $(space2) Valid module file(s) : $(__x4c_all_modules_file))

	$(info $(space2))
	$(info ----------------------------------------------------------------------- )
	$(info $(space2) Module list : $(__x4c_all_modules))
	$(info $(space2))
	$(info $(space2) Config list : $(X4C_VALID_CONFIG))
	$(info $(space2))
	$(info $(space2) make [CONFIG=$$(config)] [$$(module)] [V=1] [R=1] [E=1] [D=0])
	$(info $(space2))

	$(info ----------------------------------------------------------------------- )
	$(info $(space2))
	$(info BUILD START AT : $(shell date))
	$(info $(space2))
	$(info ----------------------------------------------------------------------- )
	$(info $(space2))

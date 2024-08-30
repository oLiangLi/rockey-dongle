
$(call assert-defined,X4C_ARCH X4C_BUILD)

##
##
##
ifeq ("$(R)","1")
X4C_CONF_VER ?= release
else
X4C_CONF_VER ?= debug
endif

##
## Local module name ...
##
$(call x4c_register_local_variant, LOCAL_MODULE)

##
## Absolute path name of source files ...
##
$(call x4c_register_local_variant, LOCAL_SRC_FILES_A)

##
##
##
$(call x4c_register_local_variant, LOCAL_SRC_FILES)

##
## CFLAGS
##
$(call x4c_register_local_variant, LOCAL_CFLAGS)

##
##
##
$(call x4c_register_local_variant, LOCAL_CXXFLAGS)

##
##
##
$(call x4c_register_local_variant, LOCAL_ASFLAGS)

##
##
##
$(call x4c_register_local_variant, LOCAL_LDFLAGS)

##
##
##
$(call x4c_register_local_variant, LOCAL_ARFLAGS)


# ----------------------------------------------------------------------------
#	Function: x4c_all_files_under_recursive
#	Arguments: 1: pathname
#              2: filetype
# ----------------------------------------------------------------------------
x4c_all_files_under_recursive = \
	$(wildcard $1/$2 $1/*/$2 $1/*/*/$2 $1/*/*/*/$2)

# ----------------------------------------------------------------------------
#	Function: x4c_all_files_under
#	Arguments: 1: pathname
#              2: filetype
# ----------------------------------------------------------------------------
x4c_all_files_under = \
	$(wildcard $1/$2 )


# ----------------------------------------------------------------------------
# Function: x4c_add_all_source_files_under_recursive
# Arguments: 1: pathname
#			 2: filetype
# ----------------------------------------------------------------------------
x4c_add_all_source_files_under_recursive = \
	$(eval LOCAL_SRC_FILES_A += $(call x4c_all_files_under_recursive,$1,$2))

# ----------------------------------------------------------------------------
# Function: x4c_add_all_source_files_under
# Arguments: 1: pathname
#			 2: filetype
# ----------------------------------------------------------------------------
x4c_add_all_source_files_under = \
	$(eval LOCAL_SRC_FILES_A += $(wildcard $1/$2 ))

# ----------------------------------------------------------------------------
# Function: x4c_add_local_source_files
# Arguments: 1: files...
# ----------------------------------------------------------------------------
x4c_add_local_source_files = \
	$(eval LOCAL_SRC_FILES += $1)

# ----------------------------------------------------------------------------
# Function: x4c_add_source_files
# Arguments: 1: files...
# ----------------------------------------------------------------------------
x4c_add_source_files = \
	$(eval LOCAL_SRC_FILES_A += $1)

##
##	mkdir <path>
##
define x4c_cmd_mkdir 
	$(info MKDIR $1)
	$(hide) mkdir -p $1
endef


##
##	rmdir <path>
##
define x4c_cmd_rmdir
	$(info RMDIR $1)
	$(hide) rm -rf $1
endef

##
##	rm   <files...>
##
define x4c_cmd_rm
	$(info RM $1)
	$(hide) rm -f $1
endef


#
#  x4c_cmd_show_build_module_info  <module>
#
define x4c_cmd_show_build_module_info
	$(info )
	$(info -------------------------------------------------- )
	$(info $(space2) BUILD : $1                               )
	$(info -------------------------------------------------- )
endef

#
#  x4c_cmd_show_clean_module_info <module>
#
define x4c_cmd_show_clean_module_info
	$(info )
	$(info -------------------------------------------------- )
	$(info $(space2) CLEAN : $1                               )
	$(info -------------------------------------------------- )
endef

##
##
##
ifneq ("$(X4C_BOARD)","")
X4C_MAKE_SUBDIR ?= $(X4C_ARCH)-$(X4C_BOARD)-$(X4C_BUILD)-$(X4C_CONF_VER)
else
X4C_MAKE_SUBDIR ?= $(X4C_ARCH)-$(X4C_BUILD)-$(X4C_CONF_VER)
endif

##
## output directory
##
X4C_BINARY   ?= $(X4C_BUILD_XWORLD)/.bin/$(X4C_MAKE_SUBDIR)
X4C_OUTPUT   ?= $(X4C_BUILD_XWORLD)/.bin/.obj/$(X4C_MAKE_SUBDIR)
X4C_LIBRARY  ?= $(X4C_BUILD_XWORLD)/.bin/.lib/$(X4C_MAKE_SUBDIR)
X4C_GENERATE ?= $(X4C_OUTPUT)/gen

##
##
##
prepare: $(X4C_BINARY) $(X4C_OUTPUT) $(X4C_LIBRARY)
$(X4C_OUTPUT) $(X4C_BINARY) $(X4C_LIBRARY): ; $(call x4c_cmd_mkdir,$@)

##
##
##
OBJEXT ?= .o
LIBEXT ?= .a
DLLEXT ?= .so
EXEEXT ?= $(empty)
DEPEXT ?= .o.d

##
##
##
X4C_C_SRC_EXT_LIST   ?= %.c %.C
X4C_CPP_SRC_EXT_LIST ?= %.cpp %.CPP %.cc %.CC %.cxx %.CXX
X4C_ASM_SRC_EXT_LIST ?= %.s %.S %.asm %.ASM

##
##
##
X4C_GENERAL_SOURCE_EXT ?= s S c C cpp cc cxx lc lmc jy yc ymc

# ----------------------------------------------------------------------------
# Function: add_general_source_files
# Arguments: 1: source file absolute pathname
# ----------------------------------------------------------------------------
add_general_source_files = $(eval LOCAL_SRC_FILES_A += $1)

# ----------------------------------------------------------------------------
# Function: add_general_source_files
# Arguments: 1: source file relative pathname
# ----------------------------------------------------------------------------
add_local_source_file    = $(eval LOCAL_SRC_FILES   += $1)

# ----------------------------------------------------------------------------
# Function: add_general_source_files_under
# ----------------------------------------------------------------------------
add_general_source_files_under = \
	$(foreach __ty,$(X4C_GENERAL_SOURCE_EXT),$(call x4c_add_all_source_files_under_recursive,$1,*.$(__ty)))

# ----------------------------------------------------------------------------
#	Function: clear-local-vars
# ----------------------------------------------------------------------------
clear-local-vars = 		\
	$(call clear-vars,$(__x4c_local_variant))

# ----------------------------------------------------------------------------
#	Function: build-static-library
# ----------------------------------------------------------------------------
build-static-library = \
	$(eval include $(X4C_BUILD_SYSTEM)/core/build-static-library.mk)

# ----------------------------------------------------------------------------
#	Function: build-shared-library
# ----------------------------------------------------------------------------
build-shared-library = \
	$(eval include $(X4C_BUILD_SYSTEM)/core/build-shared-library.mk)

# ----------------------------------------------------------------------------
#	Function: build-executable
# ----------------------------------------------------------------------------
build-executable = \
	$(eval include $(X4C_BUILD_SYSTEM)/core/build-executable.mk)

# ----------------------------------------------------------------------------
#	Function: build-library => build-static-library
# ----------------------------------------------------------------------------
build-library ?= \
	$(eval include $(X4C_BUILD_SYSTEM)/core/build-static-library.mk)




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
## strict mode (default) ...
## 并入自上游 b360abf8(LOCAL_STRICT=0 关闭严格警告)
##
$(call x4c_register_local_variant, LOCAL_STRICT)

##
## local-module-output : $(LOCAL_DEPENDS)
## 并入自上游 cd0b4afc(允许为目标文件定义额外的依赖项)
##
$(call x4c_register_local_variant, LOCAL_DEPENDS)

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

##
## 并入自上游 b360abf8: 为该模块打开 unwind 表(LOCAL_BACKTRACE=0 关闭)
##
$(call x4c_register_local_variant, LOCAL_BACKTRACE)


# ----------------------------------------------------------------------------
#	Function: x4c_all_files_under_recursive
#	Arguments: 1: pathname
#              2: filetype
# ----------------------------------------------------------------------------
x4c_all_files_under_recursive = \
	$(wildcard $1/$2 $1/*/$2 $1/*/*/$2 $1/*/*/*/$2 $1/*/*/*/*/$2 $1/*/*/*/*/*/$2)

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
## 并入自上游 b360abf8: 严格警告集(LOCAL_STRICT 用)与 unwind 表开关(LOCAL_BACKTRACE 用)。
## rLANG_COMMON_STRICT_* 上游由使用方项目定义; 这里给空缺省 ⇒ 打开 LOCAL_STRICT 也不改变
## 现有编译参数, 需要时在 project.local.mk 里覆盖(例如 -Wall -Wextra -Werror)。
## ! unwind 表上游默认 `-DX4C_CONFIG_UNWIND_TABLE -funwind-tables`, 本仓保持**空缺省**:
##   设备固件受 elf2bin 段契约与 ".rodata 必须为空" 约束, 不能新增 .ARM.exidx 段
##   (实测: 带该 flags 时 make dongle 链接缺 __aeabi_unwind_cpp_pr0)。宿主模块需要回溯时
##   自行设 LOCAL_BACKTRACE=1 并覆盖本变量。
##
rLANG_COMMON_STRICT_CFLAGS   ?=
rLANG_COMMON_STRICT_CXXFLAGS ?=
X4C_UNWIND_TABLE_CFLAGS      ?=

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
# Function: add_general_source_files_non_recursive
# 并入自上游 096c4954: 只收集给定目录(不递归)下的源文件
# ----------------------------------------------------------------------------
add_general_source_files_non_recursive = \
	$(foreach __ty,$(X4C_GENERAL_SOURCE_EXT),$(call x4c_add_all_source_files_under,$1,*.$(__ty)))

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



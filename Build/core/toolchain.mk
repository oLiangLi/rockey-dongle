
#
#	cc    <input> <output> <dep-file> <cflags>
#
ifeq ("$(origin x4c-cmd-cc)","undefined")
define x4c-cmd-cc
$2 : $1 
	$$(hide) $$(info CC $1)
	$$(hide) $$(X4C_CC) $$($(strip $4)) -MMD -MT $$@ -MF $3 -c -o $$@ $$<
endef
endif

#
#	cxx  <input> <output> <dep-file> <cxxflags>
#
ifeq ("$(origin x4c-cmd-cxx)","undefined")
define x4c-cmd-cxx
$2 : $1
	$$(hide) $$(info CXX $1)
	$$(hide) $$(X4C_CXX) $$($(strip $4)) -MMD -MT $$@ -MF $3 -c -o $$@ $$<
endef
endif

#
#   as  <input> <output> <asflags>
#
ifeq ("$(origin x4c-cmd-as)","undefined")
define x4c-cmd-as
$2 : $1 
	$$(hide) $$(info AS $1)
	$$(hide) $$(X4C_ASM) $$($(strip $3)) -c -o $$@ $$<
endef
endif

#
#   ar <input-varname> <output> <arflags>
#
ifeq ("$(origin x4c-cmd-ar)","undefined")
define x4c-cmd-ar
$2 : $$($(strip $1))
	$$(hide) $$(info AR $$@)
	$$(hide) $$(X4C_AR) $$($(strip $3)) crf $$@ $$($(strip $1))
endef
endif

#
#   ld <input> <output> <ldflags>
#
ifeq ("$(origin x4c-cmd-ld)","undefined")
define x4c-cmd-ld
$2 : $$($(strip $1))
	$$(info LD $$@)
	$$(hide) $$(X4C_LD) -o $$@ $$($(strip $1)) $$($(strip $3)) $$(LIBX4C_EXT_LDFLAGS)
endef
endif

#
#   ldso <input> <output> <ldflags>
#
ifeq ("$(origin x4c-cmd-ldso)","undefined")
define x4c-cmd-ldso
$2 : $$($(strip $1))
	$$(info LDSO $$@)
	$$(hide) $$(X4C_LD) -shared -o $$@ $$($(strip $1)) $$($(strip $3))	$$(LIBX4C_EXT_LDFLAGS)
endef
endif

#
#	intstall-shared-lib		<input>		<output>
#
ifeq ("$(origin x4c-cmd-intstall-shared-lib)","undefined")
define x4c-cmd-intstall-shared-lib
$2 : $1
	$$(info INSTALL $2)
	$$(hide) cp $$< $$@
endef
endif

#
#	intstall-executable		<input>		<output>
#
ifeq ("$(origin x4c-cmd-intstall-executable)","undefined")
define x4c-cmd-intstall-executable	
$2 : $1
	$$(info INSTALL $2)
	$$(hide) cp $$< $$@
endef
endif

#
#	ldflags-add-dir  <varname>  <dir...>
#
ifeq ("$(origin x4c-cmd-ldflags-add-dir)","undefined")
define x4c-cmd-ldflags-add-dir
	$(eval $1 += $(addprefix -L,$2) )
endef
endif


#
#	ldflags-add-static-module  <varname>	<modules...>
#
ifeq ("$(origin x4c-cmd-ldflags-add-static-module)","undefined")
define x4c-cmd-ldflags-add-static-module	
	$(eval $1 += $(addprefix -l,$2) )
endef
endif

#
#	ldflags-add-shared-module  <varname>	<modules...>
#
ifeq ("$(origin x4c-cmd-ldflags-add-shared-module)","undefined")
define x4c-cmd-ldflags-add-shared-module
	$(eval $1 += $(addprefix -l,$2) )
endef
endif

#
#	ldflags-add-static-library	<varname>	<libs...>
#
ifeq ("$(origin x4c-cmd-ldflags-add-static-library)","undefined")
define x4c-cmd-ldflags-add-static-library
	$(eval $1 += $2 )
endef
endif

#
#	ldflags-add-shared-library	<varname>	<libs...>
#
ifeq ("$(origin x4c-cmd-ldflags-add-shared-library)","undefined")
define x4c-cmd-ldflags-add-static-library
	$(eval $1 += $2 )
endef
endif

#
#	module-depends-static-lib <target-module>	<static-lib-module>
#
ifeq ("$(origin x4c-cmd-module-depends-static-lib)","undefined")
define x4c-cmd-module-depends-static-lib
	$(call x4c-cmd-ldflags-add-static-module,LOCAL_LDFLAGS,$2)		
endef
endif

#
#	module-depends-shared-lib <target-module>	<shared-lib-module>
#
ifeq ("$(origin x4c-cmd-module-depends-shared-lib)","undefined")
define x4c-cmd-module-depends-shared-lib
	$(call x4c-cmd-ldflags-add-shared-module,LOCAL_LDFLAGS,$2)		
endef
endif

#
#	module-add-ext-depends-library   <name>  <static-lib-module>
#
ifeq ("$(origin x4c-cmd-module-add-ext-depends-library)","undefined")
define x4c-cmd-module-add-ext-depends-library
	$(eval $1 += $(addprefix $(X4C_LIBRARY)/lib,$(addsuffix $(LIBEXT),$2 )))
endef
endif

#
#	module-add-ext-depends-library-shared   <name>  <shared-lib-module>
#
ifeq ("$(origin x4c-cmd-module-add-ext-depends-library-shared)","undefined")
define x4c-cmd-module-add-ext-depends-library-shared
	$(eval $1 += $(addprefix $(X4C_LIBRARY)/lib,$(addsuffix $(DLLEXT),$2 )))
endef
endif

MODULE_DEPENDS_STATIC =	\
	$(eval $1 : $2)		\
	$(call x4c-cmd-module-add-ext-depends-library,$1-EXT_DEPENDS_LIBRARY,$2)			\
	$(call x4c-cmd-module-depends-static-lib,$1,$2)

MODULE_DEPENDS_SHARED =	\
	$(eval $1 : $2)		\
	$(call x4c-cmd-module-add-ext-depends-library-shared,$1-EXT_DEPENDS_LIBRARY,$2)		\
	$(call x4c-cmd-module-depends-shared-lib,$1,$2)

module_depends = $(foreach __m,$1,$(eval $(call MODULE_DEPENDS_STATIC,$(LOCAL_MODULE),$(__m))))
module_shared_depends = $(foreach __m,$1,$(eval $(call MODULE_DEPENDS_SHARED,$(LOCAL_MODULE),$(__m))))

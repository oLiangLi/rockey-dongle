$(call assert-defined, LOCAL_MODULE )
$(call x4c_add_module, $(LOCAL_MODULE) )

LOCAL_MODULE_TARGET		  := $(X4C_LIBRARY)/lib$(LOCAL_MODULE)$(LIBEXT)
LOCAL_MODULE_TARGETS	  := $(LOCAL_MODULE_TARGET) 

include $(my-dir)/build-binary.mk

$(eval $(call x4c-cmd-ar,\
	$(LOCAL_MODULE)-objects-list,$(LOCAL_MODULE_TARGET),$(LOCAL_MODULE)_ARFLAGS))

LOCAL_MODULE_TARGET		 := $(empty)
LOCAL_MODULE_TARGETS	 := $(empty)

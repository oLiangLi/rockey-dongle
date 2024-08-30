ifeq ("$(X4C_BUILD)","native")

ifeq ("$(X4C_BOARD)","")
$(error select board please ....)
endif ## X4C_BOARD ...

install-platform: build-all
-include $(my-dir)/$(X4C_BOARD)/xModule.mk
endif ## native ...

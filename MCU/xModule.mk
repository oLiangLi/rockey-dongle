ifeq ("$(X4C_BUILD)","native")
install: build-all
-include $(my-dir)/*/xModule.mk
endif ## native ...

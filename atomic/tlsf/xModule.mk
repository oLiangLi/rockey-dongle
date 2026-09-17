LOCAL_PATH := $(my-dir)
$(call clear-local-vars)
LOCAL_MODULE := tlsf

##
## 注意: add_general_source_files 是"函数" (定义见 Build/core/common.mk:214 =
## $(eval LOCAL_SRC_FILES_A += $1)), 必须用 $(call ...) 调用 ...
## 之前写成 $(add_general_source_files ...) (少了 call) => 源码没有被加进来,
## 结果是编出 8 字节的空归档 libtlsf.a ...
##
$(call add_general_source_files, $(wORLD_ROOT)/third_party/tlsf/tlsf.c)
$(call build-library)

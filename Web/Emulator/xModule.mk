
ifeq ("$(X4C_BUILD)","emscripten")

LOCAL_PATH := $(my-dir)

$(call clear-local-vars)

LOCAL_MODULE := Emulator

LOCAL_BUILD_OPTIMIZE_FLAGS := -Oz

LOCAL_CXXFLAGS := -DrLANG_CONFIG_MINIMAL

LOCAL_LDFLAGS :=    \
	-s GLOBAL_BASE=64KB     \
	-s TOTAL_STACK=256KB    \
	-s INITIAL_MEMORY=8MB	\
\
\
	-s IMPORTED_MEMORY=1    \
\
\
\
	-s EXPORTED_FUNCTIONS='[ __emscripten_stack_alloc, __emscripten_stack_restore, _emscripten_stack_get_current ]'	\
\
\

$(call call_add_optimize_module)
$(call wasm_add_ldflags, --no-entry)

$(call add_general_source_files_under, $(LOCAL_PATH))
$(call module_depends, rockey base)
$(call build-executable)

endif ## emscripten

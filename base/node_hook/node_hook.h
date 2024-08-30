#pragma once

#ifndef __WTINC_NODE_HOOK_H__
#define __WTINC_NODE_HOOK_H__

#include <node.h>

typedef void (*rLANG_ROUTINE_NodeHookCreate)(v8::Isolate* isolate, v8::Local<v8::Context> context);
void rLANG_SetNodeHook(rLANG_ROUTINE_NodeHookCreate hook);

#endif /* __WTINC_NODE_HOOK_H__ */

#pragma once

#ifndef __WTINC_ATOMIC_op_GATE_HYPER_H__
#define __WTINC_ATOMIC_op_GATE_HYPER_H__

#include <base/base.h>

#ifdef __cplusplus
#include <atomic/include/rv32im-atomic.hpp>
#endif /* __cplusplus */

typedef struct {
  const char* library;
  int kIndex; /* pc/4 派发的"导出槽位" */
  int count;  /* = 最大 t0 + 1 (host 上界校验) */
  const char* sha1;
  const char* const* names; /* 下标 = t0 */
} op_GATE_export_t;

/**
 *! 我们需要一个确定的调用门用于检查基本的程序配置, 这应该是ATOMIC程序的第一个Hyper调用 ...
 */
#ifndef rLANG_START_ATOMIC_HYPER_GATE
#define rLANG_START_ATOMIC_HYPER_GATE (-512)
#endif /* rLANG_START_ATOMIC_HYPER_GATE */

rLANG_DECLARE_MACHINE

/**
 *!
 */
rLANGEXPORT int rLANGAPI rLANG_op_GATE_HyperCountGate(void);
rLANGEXPORT const char* rLANGAPI rLANG_op_GATE_HyperWorldId(void);
rLANGEXPORT const op_GATE_export_t* rLANGAPI rLANG_op_GATE_HyperExports(void);

/**
 *!
 */
rLANGEXPORT int rLANGAPI rLANG_op_GATE_HyperInitialize(const char* worldId, int gates);

/**
 *!
 */
#ifdef rLANG_CONFIG_ROCKEY_DONGLE_WORLD
rLANGEXPORT void rLANGAPI rLANG_op_GATE_Initialize(void);
#else /* rLANG_CONFIG_ROCKEY_DONGLE_WORLD */
#ifdef __cplusplus
template <typename VM>
inline int rLANGAPI rLANG_op_GATE_Initialize(VM* vmx) {
  const char* worldId = nullptr;
  int gates = vmx->hart_->regs_.a1.iv;
  int error = vmx->mm_CHKCS(vmx->hart_->regs_.a0.uv, &worldId, nullptr);
  if (0 != error)
    return error;
  return rLANG_op_GATE_HyperInitialize(worldId, gates);
}
#endif /* __cplusplus */
#endif /* rLANG_CONFIG_ROCKEY_DONGLE_WORLD */

rLANG_DECLARE_END

#endif /* __WTINC_ATOMIC_op_GATE_HYPER_H__ */

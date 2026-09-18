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

/**
 *! A0 = value, A1 = kExitMagic, A2 = A0 + A1, A3 = kWorldMagic
 */
#ifndef rLANG_CONFIG_EXIT_GATE_MAGIC
#define rLANG_CONFIG_EXIT_GATE_MAGIC 0xFEA1DEAD
#endif /* rLANG_CONFIG_EXIT_GATE_MAGIC */

rLANG_DECLARE_MACHINE

/**
 *!
 */
rLANGIMPORT int MatrixExecv();
rLANGEXPORT __attribute__((noreturn)) void MatrixExit(int v);

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
template <typename VM>
inline int rLANGAPI rLANG_op_GATE_HyperExit(VM* vmx, int gate) {
  constexpr uint32_t kExitMagic = rLANG_CONFIG_EXIT_GATE_MAGIC;

  const int v = vmx->hart_->regs_.a0.iv;
  const int kGate = (int)((uint32_t)v & 0x7fu) - 64;
  const uint32_t A1 = vmx->hart_->regs_.a1.uv;
  const uint32_t CHK = vmx->hart_->regs_.a2.uv;
  const uint32_t magic = vmx->hart_->regs_.a3.uv;

  if (kGate != gate || A1 != kExitMagic || CHK != v + kExitMagic || magic != rLANG_WORLD_MAGIC) {
    rlLOGX(rLANG_ATOMC_WORLD_MAGIC, "[**SIGILL**]HyperExit(%d) %d/%d, A1: %08X/%08X, A2: %08X/%08X, A3: %08X/%08X", v,
           gate, kGate, (int)A1, (int)kExitMagic, (int)CHK, (int)(kExitMagic + v), (int)magic, (int)rLANG_WORLD_MAGIC);
    return SIGILL;
  }
  MatrixExit(v);
}

#endif /* __cplusplus */

/**
 *!
 */
#ifdef rLANG_CONFIG_MATRIX_WORLD
rLANGEXPORT void rLANGAPI rLANG_op_GATE_Initialize(void);
#endif /* rLANG_CONFIG_MATRIX_WORLD */

rLANG_DECLARE_END

#endif /* __WTINC_ATOMIC_op_GATE_HYPER_H__ */

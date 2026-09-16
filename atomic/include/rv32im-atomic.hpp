#pragma once

#ifndef __WTINC_RV32IM_ATOMIC_HPP__
#define __WTINC_RV32IM_ATOMIC_HPP__

#ifndef __cplusplus
#error "Sorry, must use C++ for rv32im-atomic ..."
#endif /* __cplusplus */

#include <base/base.h>

rLANG_DECLARE_MACHINE

#ifndef SIGQUIT
#define SIGQUIT 3
#endif /* SIGQUIT */

#ifndef SIGILL
#define SIGILL 4
#endif /* SIGILL  */

#ifndef SIGTRAP
#define SIGTRAP 5
#endif /* SIGTRAP */

#if 0
/**
 *! Windows 下 SIGABRT==22, 与其他环境不一致, 为了避免麻烦, 我用使用 SIGTERM
 */
#ifndef SIGABRT
#define SIGABRT 6
#endif /* SIGABRT */
#endif

#ifndef SIGTERM
#define SIGTERM 15
#endif /* SIGTERM */

#ifndef SIGSEGV
#define SIGSEGV 11
#endif /* SIGSEGV */

#ifndef SIGKILL
#define SIGKILL 9
#endif /* SIGKILL */

#ifndef SIGALRM
#define SIGALRM 14
#endif /* SIGALRM */

#ifndef SIGVTALRM
#define SIGVTALRM 26
#endif /* SIGVTALRM */

namespace hyper {

/**
 *! async.ZION.execv, 标志主消息循环发起了一次异步过程调用
 *! - 程序在下一个 SIGALRM/SIGVTALRM 信号到达之前会被一直挂起 ...
 */
#define rLANG_ERROR_HYPER ((int32_t)0xC8C04E1F)

/**
 *! async.wait, 标志主消息循环放弃剩下的处理器时间(a0指示其周期数)
 *! - 在下一次 SIGALRM/SIGVTALRM 或者a0指示的超时时间之前, 程序被挂起 ...
 *! - 通常我们mock的输入按 1周期==1纳秒 标定(1GHZ), 但SIGALRM不受此限制 ...
 */
#define rLANG_ERROR_YEILD (rLANG_ERROR_HYPER - 3)

/**
 *! 程序单次执行的时间已经到达上限, 程序在下一次可使用的时间片到达时执行
 */
#define rLANG_ERROR_TIMEDOUT (rLANG_ERROR_HYPER - 2)

/**
 *!
 */
template <typename IMPL>
struct VM_t {
  using libmb_t = uint32_t;
  using libmbi_t = int32_t;

  using libmb_w_t = uint64_t;
  using libmbi_w_t = int64_t;

  using real32_t = float;   /// IEEE754.float Only ...
  using real64_t = double;  /// IEEE754.double Only ...

  union reg_t {
    libmb_t uv;
    libmbi_t iv;
  };

  union regs_t {
    reg_t regs[32];

    struct {
      reg_t zero, ra, sp, gp, tp, t0, t1, t2;
      reg_t s0fp, s1, a0, a1, a2, a3, a4, a5;
      reg_t a6, a7, s2, s3, s4, s5, s6, s7;
      reg_t s8, s9, s10, s11, t3, t4, t5, t6;
    };

    struct {           /// Function call arguments ...
      reg_t ____[10];  /// zero ... t2, s0fp, s1 ...

      union {
        libmbi_t i32args[8];
        libmb_t u32args[8];
        real32_t r32args[8];
        real64_t r64args[4];
        libmbi_w_t i64args[4];
        libmb_w_t u64args[4];
      };
    };
  };

 protected:
  /**
   *! 所有的实现路径(解释,转译等)必须确定性的在执行到相同位置时返回完全相同的结果
   *! - 如果有差异, 以我们性能最低的解释器的结果为准(特别是严格模式下) ...
   */
  regs_t regs;

 protected:
  /**
   *! 对于执行程序的代价(以花费的时钟周期计算)应该尽量与解释器下的结果相同, 不应该出现过于大的偏差 ...
   */
  libmb_w_t cycles;
  libmb_t cyc;
  libmb_t pc;

 protected:  /// MMU ...
  int mm_CHKWX(libmb_t addr, libmb_t size, void** ppv) { return SIGSEGV; }
  int mm_CHKRX(libmb_t addr, libmb_t size, const void** ppv) { return SIGSEGV; }

  /**
   *! 返回一个VM_t下的字符串, 如果 lenIf 非nullptr则同时返回其长度 ...
   *! - 我们会自动的在 .text, .rodata, .data/.bss 末尾添加全0的 guard-page, 因此无需担心字符串无 NUL 结尾
   */
  int mm_CHKCS(libmb_t addr, const char** pps, libmb_t* lenIf) { return SIGSEGV; }

  int mm_LB(libmb_t addr, reg_t* v) { return SIGSEGV; }
  int mm_LBU(libmb_t addr, reg_t* v) { return SIGSEGV; }
  int mm_LH(libmb_t addr, reg_t* v) { return SIGSEGV; }
  int mm_LHU(libmb_t addr, reg_t* v) { return SIGSEGV; }
  int mm_LW(libmb_t addr, reg_t* v) { return SIGSEGV; }

  int mm_SB(libmb_t addr, libmb_t v) { return SIGSEGV; }
  int mm_SH(libmb_t addr, libmb_t v) { return SIGSEGV; }
  int mm_SW(libmb_t addr, libmb_t v) { return SIGSEGV; }

 protected:  /// instruction fetch ...
  int if_CODE(libmb_t pc, libmb_t* op) { return SIGSEGV; }

 protected:  /// for IMPL override, default ...
  void op_FENCE() { /* nop */ }
  void op_FENCEI() { /* nop */ }

  int op_ECALL() { return SIGILL; }
  int op_EBREAK() { return SIGTRAP; }

  int op_CSRRW() { return SIGILL; }
  int op_CSRRS() { return SIGILL; }
  int op_CSRRC() { return SIGILL; }

  int op_CSRRWI() { return SIGILL; }
  int op_CSRRSI() { return SIGILL; }
  int op_CSRRCI() { return SIGILL; }

 protected:  /// pc < 0x00000800 || pc >= 0xFFFFF800;;; id = (int)pc / 4;;; jalr id*4(zero)
  int op_GATE(int id) { return -ENOSYS; }
};

#if 0
/**
 *! Windows 下 SIGABRT==22, 与其他环境不一致, 为了避免麻烦, 我用使用 SIGTERM
 */
rLANG_ABIREQUIRE(SIGABRT == 6);
#endif

/**
 *!
 */
rLANG_ABIREQUIRE(SIGQUIT == 3 && SIGILL == 4 && SIGTRAP == 5 && SIGTERM == 15 && SIGSEGV == 11 && SIGKILL == 9 &&
                 SIGALRM == 14 && SIGVTALRM == 26);

/**
 *!
 */
rLANG_ABIREQUIRE((rLANG_WORLD_MAGIC ^ rLANG_ERROR_HYPER) == 0u);
rLANG_ABIREQUIRE(rLANG_WORLD_MAGIC - rLANG_ERROR_YEILD == 3u);
rLANG_ABIREQUIRE(rLANG_WORLD_MAGIC - rLANG_ERROR_TIMEDOUT == 2u);

}  // namespace hyper

rLANG_DECLARE_END

#endif /* __WTINC_RV32IM_ATOMIC_HPP__ */

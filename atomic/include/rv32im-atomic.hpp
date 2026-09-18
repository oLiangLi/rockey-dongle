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

#ifndef SIGQUIT
#define SIGQUIT 3
#endif /* SIGQUIT */

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

/**
 *! 启用最高级别的编译优化, 代码必须消除潜在的UB ...
 */
#if !defined(rLANGiOPT) && defined(__GNUC__) && !defined(__clang__) && !defined(__EMSCRIPTEN__)
#define rLANGiOPT __attribute__((optimize("O3")))
#elif !defined(rLANGiOPT)
#define rLANGiOPT
#endif /* rLANGiOPT */

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
  VM_t() = default;

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
    /**
     *! 只有宿主/hook 可写 x0, 只有当 zero == 0 时当前的 hart 才可以执行代码
     *! - 当 (zero|3) == rLANG_ERROR_HYPER 时, 标明程序处于一次异步过程调用之中, 上级调用者必须处理这种异常
     */
    reg_t regs_[32];

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

  struct hart_t {
    hart_t() {
      /**
       *! 刚初始化的 hart 不允许执行程序 ...
       */
      regs_.zero.uv = SIGQUIT;
    }

    /**
     *! 清除hart可能的错误状态, 允许其开始执行程序, 另一个可以同时指定pc ...
     */
    void Enable() { regs_.zero.uv = 0; }
    void Enable(libmb_t pc) {
      regs_.zero.uv = 0;
      pc_ = pc;
    }

    regs_t regs_;

    libmb_w_t cycles_ = 0;  ///< 该 hart **一生**累计消耗的周期数 (64 位); 注意**总代价 = cycles_ + cyc_**
                            ///< (折叠发生在 Execv 入口, 所以最后一片尚未结算)
    libmb_t cyc_ = 0;       ///< **本时间片**已消耗的周期数 (是周期, 不是指令条数: 见 kCyc* 权重)
    libmb_t pc_ = 0;
  };

 public:
  static constexpr libmb_t rlRD(libmb_t op) { return (((op) >> 7) & 0x1F); }
  static constexpr libmb_t rlRS1(libmb_t op) { return (((op) >> 15) & 0x1F); }
  static constexpr libmb_t rlRS2(libmb_t op) { return (((op) >> 20) & 0x1F); }
  static constexpr libmb_t rlSUBTY(libmb_t op) { return (((op) >> 12) & 0x07); }
  static constexpr libmb_t rlRV_X(libmb_t x, int s, int n) { return (((x) >> (s)) & ((1 << (n)) - 1)); }
  static constexpr libmb_t rlRV_IMM_SIGN(libmb_t x) { return ((x & 0x80000000) ? ~0 : 0); }
  static constexpr libmb_t rlEXTRACT_SBTYPE_IMM(libmb_t x) {
    return ((rlRV_X(x, 8, 4) << 1) | (rlRV_X(x, 25, 6) << 5) | (rlRV_X(x, 7, 1) << 11) | (rlRV_IMM_SIGN(x) << 12));
  }
  static constexpr libmb_t rlEXTRACT_UJTYPE_IMM(libmb_t x) {
    return ((rlRV_X(x, 21, 10) << 1) | (rlRV_X(x, 20, 1) << 11) | (rlRV_X(x, 12, 8) << 12) | (rlRV_IMM_SIGN(x) << 20));
  }
  static constexpr libmb_t rlEXTRACT_STYPE_IMM(libmb_t x) {
    return (rlRV_X(x, 7, 5) | (rlRV_X(x, 25, 7) << 5) | (rlRV_IMM_SIGN(x) << 12));
  }


  static constexpr libmb_t kConfigLimitCycles = 1 << 20;

  /**
   *! 指令的周期计价 (单位: **时钟周期**; 按上面 YEILD 注释的 mock 标定 1 周期 == 1 纳秒 / 1GHz) ...
   *! - 每条指令的**基础**代价 1 已隐含在 inner_Execv 的 ++hart_->cyc_ 里; 这里只列**附加**代价,
   *!   合计 = 1 + 附加 ...
   *! - 权重必须是指令类的**纯函数**: 不随操作数/地址/宿主变化, 也不做早退 (除零 / INT_MIN 溢出同样计费),
   *!   否则"其他执行路径的代价应与解释器一致"这条契约 (以及可复现性) 无法满足 ...
   *! - 计价点: 数据访问/FENCE/M 扩展在**实际操作成功之后**计 (因错误提前返回的不计);
   *!   而跨世界的调用 (门 / 世界魔数 HYPER) 是**进入即计费** —— 宿主已经开始工作 ...
   *! - 条件分支固定 **+1 拍**惩罚, 且**不分是否命中** (让耗时与数据无关, 可预测); 无条件跳转 (JAL/JALR) 不加 ...
   *! - 取指也不分 cache 命中 ...
   *! - **计价原则 (用户 2026-09-16)**: **内置指令必须比"自己写一个自定义门实现同一件事"更便宜, 不然就没人
   *!   用内置指令了** (guest 全绕道走门, 解释器的优化就白做) ⇒ 任何权重都必须满足
   *!   `内置代价 < 搬运两次寄存器 + 一次自定义门调用`。按本表的最低算式: 最贵的内置指令 (DIV 合计 8 拍)
   *!   < 两次寄存器经内存搬运 (2×2 拍) + 自定义门 (缺省 4 拍 + 至少自加 1 拍) = 9 拍 ⇒ 成立 ...
   *!   推论: **DIV 的 8 拍就是全局上界**, 以后给任何指令加权都不能超过它 (除非同时调整门费/搬运费) ...
   *! - 这条不等式是**保险丝, 不是竞争关系** (用户 2026-09-16 补): "**用自定义门会占用寄存器, 很不划算的,
   *!   不会有人真这样做**" ⇒ 门还要吃寄存器/现场 (参数搬运、被调方保存), 真实代价远高于上面的最低算式,
   *!   所以**门是给重操作/RPC 用的, 不是用来替代基本指令的**; 上面那个界只需要成立, 不需要精算 ...
   *! - 只有**指令级**的小量级在这里; 门/宿主操作的真实成本由**门实现**自行追加到同一个 cyc_ 上
   *!   (hart_ 是 protected, 门实现可直接 hart_->cyc_ += ...; 量级由该操作的真实成本决定) ...
   */
  static constexpr libmb_t kCycMem = 1;           ///< 一次数据访问 (LB/LH/LW/LBU/LHU/SB/SH/SW): 合计 2
  static constexpr libmb_t kCycBranch = 1;        ///< 条件分支 (BEQ/BNE/BLT/BGE/BLTU/BGEU): 合计 2; **不分是否命中**
  static constexpr libmb_t kCycMul = 2;           ///< MUL: 合计 3
  static constexpr libmb_t kCycMulh = 3;          ///< MULH/MULHSU/MULHU: 合计 4
  static constexpr libmb_t kCycDiv = 7;           ///< DIV/DIVU/REM/REMU: **合计 8** —— 这是**策略性上限**, 不是迭代除法器
                                                  ///< 的物理拍数 (基 2 迭代是 32 拍): 用户裁定"它的值应该要小于
                                                  ///< '搬运两次寄存器 + 一次自定义门调用' 的代价", 即上面那条
                                                  ///< "内置必须比自定义门便宜"的原则 ⇒ 它同时是**内置指令的全局上界**,
                                                  ///< **调度粒度从 32 拍收紧到 8 拍**;
                                                  ///< 语义上相当于"radix-4/8 或带提前结束的除法器"
  static constexpr libmb_t kCycFence = 3;         ///< FENCE/FENCE.I: 合计 4 (流水线/取指冲刷)
  static constexpr libmb_t kCycGate = 3;          ///< 门调用: 进门缺省合计 4; 更贵的门由门实现自己追加
  static constexpr libmb_t kCycHyper = 1 << 16;   ///< 世界魔数 (HYPER): **发起**一次 RPC 的固定开销 (≈65us);
                                                  ///< 它几乎必然返回 rLANG_ERROR_HYPER 并挂起本次执行, 直到 RPC 结果
                                                  ///< 回来才被唤醒 —— **等待不计** (等待不是 CPU 时间, 与 SIGALRM 同一口径),
                                                  ///< 要计等待只能由 RPC/宿主层自己追加 (只有它知道等了多久)

  /**
   *! 我们以解释器方式执行代码, 最慢的但结果最标准的参考, 其他执行路径应该尽量不要与此发生偏差 ...
   *! - 我们的 VM_t 是为了给 LIMIT 做外壳, 单线程执行的限制是合理的取舍 ...
   *! - limit_cycles == 0||1 都为单步执行 ...
   *! - limit_cycles 的单位是**周期**(不是指令条数), 且只是**预算下界**: 我们在指令边界检查, 而 do-while
   *!   保证**至少执行一条** ⇒ 能继续执行下去的指令里, 单条最大代价 (kCycDiv+1 == 8 拍) 就是最大超调, 也是调度
   *!   粒度 (HYPER 是例外: 它是 RPC 级记账, 且必然结束本次执行) ...
   */
  rLANGiOPT int rLANGAPI Execv(hart_t* const hart, const libmb_t limit_cycles) {
    if (hart_)
      return -EALREADY;

    if (!hart || limit_cycles > kConfigLimitCycles)
      return -EINVAL;

    if (0 != hart->regs_.zero.iv)
      return hart->regs_.zero.iv;

    hart_ = hart;
    int result = inner_Execv(limit_cycles);
    hart_ = nullptr;

    return result;
  }

 protected:
  hart_t* hart_ = nullptr;

 private:
  rLANGiOPT int rLANGAPI inner_Execv(const libmb_t limit_cycles) {
    ASSERT(nullptr != hart_ && limit_cycles <= kConfigLimitCycles);

    reg_t* const regs = hart_->regs_.regs_;
    libmbi_t &err = hart_->regs_.zero.iv, v;
    libmb_t rd, rs1, rs2, pc, addr, op;

    hart_->cycles_ += hart_->cyc_;
    hart_->cyc_ = 0;

    do {
      ++hart_->cyc_;

      pc = hart_->pc_;
      if rLANG_UNLIKELY (pc & 3)
        return err = SIGSEGV;
      hart_->pc_ += 4;

      if rLANG_UNLIKELY (pc < 0x800 || pc >= 0xFFFFF800) {
        hart_->pc_ = regs[1].uv;  /// ra ...
        hart_->cyc_ += kCycGate;  /// 跨世界调用: 进入即计费 (宿主已开始工作); 更贵的门由门实现再追加 ...
        err = Self()->op_GATE((int)pc / 4);
        if rLANG_UNLIKELY (0 != err)
          return err;
      } else {
        err = Self()->if_CODE(pc, &op);
        if rLANG_UNLIKELY (0 != err)
          return err;

        if rLANG_UNLIKELY (rLANG_WORLD_MAGIC == op) {
          pc = hart_->pc_;
          err = Self()->if_CODE(pc, &op);
          if rLANG_UNLIKELY (0 != err)
            return err;
          hart_->pc_ += 4;

          hart_->cyc_ += kCycHyper;  /// 世界魔数: 发起一次 RPC 的固定开销 (等待不计) ...
          err = Self()->op_HYPER(op);
          if rLANG_LIKELY (0 != err)  /// 通常而言, HYPER 调用将阻塞整个程序的执行或出错,几乎不可能继续执行程序 ...
            return err;
        } else if rLANG_UNLIKELY (3 != (op & 3)) {
          return err = SIGILL;  /// RV32IM 所有指令最后两位一定是1 ...
        } else {
          switch ((op >> 2) & 0x1f) {
            case 0x37 >> 2:  // LUI
              rd = rlRD(op);
              if (rLANG_LIKELY(rd))
                regs[rd].uv = op & 0xFFFFF000;
              break;

            case 0x17 >> 2:  // AUIPC
              rd = rlRD(op);
              if (rLANG_LIKELY(rd))
                regs[rd].uv = pc + (op & 0xFFFFF000);
              break;

            case 0x6F >> 2:  // JAL
              rd = rlRD(op);
              if (rd)
                regs[rd].uv = hart_->pc_;
              hart_->pc_ = pc + rlEXTRACT_UJTYPE_IMM(op);
              break;

            case 0x67 >> 2:  // JALR
              if (rLANG_UNLIKELY(0 != rlSUBTY(op)))
                return err = SIGILL;
              rd = rlRD(op);
              rs1 = rlRS1(op);
              if (rd)
                regs[rd].uv = hart_->pc_;
              hart_->pc_ = (regs[rs1].uv + (((int32_t)op) >> 20)) & ~1;
              break;

            case 0x63 >> 2:  // BEQ, BNE, BLT, BGE, BLUT, BGEU
              rs1 = rlRS1(op);
              rs2 = rlRS2(op);
              switch (rlSUBTY(op)) {
                case 0:  // BEQ
                  v = regs[rs1].uv == regs[rs2].uv;
                  break;
                case 1:  // BNE
                  v = regs[rs1].uv != regs[rs2].uv;
                  break;
                case 4:  // BLT
                  v = regs[rs1].iv < regs[rs2].iv;
                  break;
                case 5:  // BGE
                  v = regs[rs1].iv >= regs[rs2].iv;
                  break;
                case 6:  // BLTU
                  v = regs[rs1].uv < regs[rs2].uv;
                  break;
                case 7:  // BGEU
                  v = regs[rs1].uv >= regs[rs2].uv;
                  break;

                default:
                  return err = SIGILL;
              }
              hart_->cyc_ += kCycBranch;  /// 条件分支固定惩罚 (不分是否命中) ...
              if (v)
                hart_->pc_ = pc + rlEXTRACT_SBTYPE_IMM(op);
              break;

            case 0x03 >> 2:  // LB, LH, LW, LBU, LHU
              rd = rlRD(op);
              {
                rs1 = rlRS1(op);
                addr = regs[rs1].uv + ((int32_t)op >> 20);

                /**
                 *! rd == 0 也必须**真的**访问一次内存 —— ISA 卷 I §2.6 (Load and Store Instructions):
                 *! "Loads with a destination of x0 must still raise any exceptions and cause any other
                 *! side effects even though the load value is discarded." ...
                 *! - 所以这里没有 `if (0 != rd)` 那道短路: `lb x0, <非法地址>` 同样要报错 (fail-closed) ...
                 *! - 但落点不能写 regs[0]: x0 是执行循环的**错误通道** (见 regs_t 的注释), 写了会破坏它 ...
                 *!   ⇒ rd == 0 时把结果丢进一个临时 reg_t, 访问本身照常进行 ...
                 */
                reg_t dummy;
                reg_t* const dst = rd ? &regs[rd] : &dummy;

                switch (rlSUBTY(op)) {
                  case 0:  // LB
                    if (0 != (err = Self()->mm_LB(addr, dst)))
                      return err;
                    break;

                  case 4:  // LBU
                    if (0 != (err = Self()->mm_LBU(addr, dst)))
                      return err;
                    break;

                  case 1:  // LH
                    if (0 != (err = Self()->mm_LH(addr, dst)))
                      return err;
                    break;

                  case 5:  // LHU
                    if (0 != (err = Self()->mm_LHU(addr, dst)))
                      return err;
                    break;

                  case 2:  // LW
                    if (0 != (err = Self()->mm_LW(addr, dst)))
                      return err;
                    break;

                  default:
                    return err = SIGILL;
                }
                hart_->cyc_ += kCycMem;  /// 成功的访问计 kCycMem ...
              }
              break;

            case 0x23 >> 2:  // SB, SH, SW
              rs1 = rlRS1(op), rs2 = rlRS2(op);
              addr = regs[rs1].uv + rlEXTRACT_STYPE_IMM(op);

              switch (rlSUBTY(op)) {
                case 0:
                  if (0 != (err = Self()->mm_SB(addr, regs[rs2].iv)))
                    return err;
                  break;

                case 1:
                  if (0 != (err = Self()->mm_SH(addr, regs[rs2].iv)))
                    return err;
                  break;

                case 2:
                  if (0 != (err = Self()->mm_SW(addr, regs[rs2].iv)))
                    return err;
                  break;

                default:
                  return err = SIGILL;
              }
              hart_->cyc_ += kCycMem;  /// 成功的访问计 kCycMem (存储) ...
              break;

            case 0x13 >> 2:  // ADDI, SLTI, SLTIU, XORI, ORI, ANDI, SLLI, SRLI, SRAI
              rd = rlRD(op);
              if (rLANG_UNLIKELY(0 == rd))
                break;

              rs1 = rlRS1(op);
              v = ((int32_t)op) >> 20;
              switch (rlSUBTY(op)) {
                case 0:  // ADDI
                  regs[rd].iv = regs[rs1].iv + v;
                  break;

                case 2:  // SLTI
                  regs[rd].iv = regs[rs1].iv < v;
                  break;

                case 3:  // SLTIU
                  regs[rd].iv = regs[rs1].uv < (libmb_t)v;
                  break;

                case 4:  // XORI
                  regs[rd].uv = regs[rs1].uv ^ (libmb_t)v;
                  break;

                case 6:  // ORI
                  regs[rd].uv = regs[rs1].uv | (libmb_t)v;
                  break;

                case 7:  // ANDI
                  regs[rd].uv = regs[rs1].uv & (libmb_t)v;
                  break;

                case 1:  // SLLI
                  if (rLANG_UNLIKELY(0 != (v & 0xFE0)))
                    return err = SIGILL;
                  regs[rd].uv = regs[rs1].uv << (v & 0x1F);
                  break;

                case 5:
                  if (0 == (v & 0xFE0))
                    regs[rd].uv = regs[rs1].uv >> (v & 0x1F);  // SRLI
                  else if (rLANG_LIKELY(0x400 == (v & 0xFE0)))
                    regs[rd].iv = regs[rs1].iv >> (v & 0x1F);  // SRAI
                  else
                    return err = SIGILL;
                  break;
              }
              break;

              /// ADD, SUB, SLL, SLT, SLTU, XOR, SRL, SRA, OR, AND, MUL, MULH, MULHSU, MULHU, DIV, DIVU, REM, REMU
            case 0x33 >> 2:
              rd = rlRD(op);
              if (rLANG_UNLIKELY(0 == rd))
                break;

              rs1 = rlRS1(op);
              rs2 = rlRS2(op);
              if (rLANG_LIKELY(1 != (op >> 25))) {
                v = rlSUBTY(op);
                if (rLANG_LIKELY(0 == v)) {
                  if (0 == (op >> 25))
                    regs[rd].uv = regs[rs1].uv + regs[rs2].uv;  // ADD
                  else if (rLANG_LIKELY(0x20 == (op >> 25)))
                    regs[rd].uv = regs[rs1].uv - regs[rs2].uv;  // SUB
                  else
                    return err = SIGILL;
                } else if (5 == v) {
                  if (0 == (op >> 25))
                    regs[rd].uv = regs[rs1].uv >> (regs[rs2].uv & 0x1F);  // SRL
                  else if (rLANG_LIKELY(0x20 == (op >> 25)))
                    regs[rd].iv = regs[rs1].iv >> (regs[rs2].uv & 0x1F);  // SRA
                  else
                    return err = SIGILL;
                } else if (rLANG_LIKELY(0 == (op >> 25))) {
                  switch (v) {
                    case 1:  // SLL
                      regs[rd].uv = regs[rs1].uv << (regs[rs2].uv & 0x1F);
                      break;
                    case 2:  // SLT
                      regs[rd].iv = regs[rs1].iv < regs[rs2].iv;
                      break;
                    case 3:  // SLTU
                      regs[rd].uv = regs[rs1].uv < regs[rs2].uv;
                      break;
                    case 4:  // XOR
                      regs[rd].uv = regs[rs1].uv ^ regs[rs2].uv;
                      break;
                    case 6:  // OR
                      regs[rd].uv = regs[rs1].uv | regs[rs2].uv;
                      break;
                    case 7:  // AND
                      regs[rd].uv = regs[rs1].uv & regs[rs2].uv;
                      break;
                  }
                } else {
                  return err = SIGILL;
                }
              } else {
                v = rlSUBTY(op);

                /// M 扩展按类计价 (v: 0=MUL, 1..3=MULH*, 4..7=DIV/DIVU/REM/REMU) ...
                hart_->cyc_ += (0 == v) ? kCycMul : (v < 4 ? kCycMulh : kCycDiv);

                switch (v) {
                  case 0:  // MUL
                    regs[rd].uv = regs[rs1].uv * regs[rs2].uv;
                    break;
                  case 1:  // MULH
                    regs[rd].iv = (int32_t)((int64_t)regs[rs1].iv * regs[rs2].iv >> 32);
                    break;
                  case 2:  // MULHSU
                    regs[rd].iv = (int32_t)((int64_t)regs[rs1].iv * regs[rs2].uv >> 32);
                    break;
                  case 3:  // MULHU
                    regs[rd].uv = (uint32_t)((uint64_t)regs[rs1].uv * regs[rs2].uv >> 32);
                    break;
                  case 4:  // DIV
                    if (rLANG_UNLIKELY(regs[rs2].iv == -1))
                      regs[rd].uv = 0u - regs[rs1].uv;  /// 不能写 -regs[rs1].iv: rs1 == INT_MIN 时那是**有符号溢出 UB** (无符号回绕等价且已定义) ...
                    else if (rLANG_LIKELY(regs[rs2].iv))
                      regs[rd].iv = regs[rs1].iv / regs[rs2].iv;
                    else
                      regs[rd].iv = -1;
                    break;
                  case 5:  // DIVU
                    if (rLANG_LIKELY(regs[rs2].uv))
                      regs[rd].uv = regs[rs1].uv / regs[rs2].uv;
                    else
                      regs[rd].iv = -1;
                    break;
                  case 6:  // REM
                    if (rLANG_UNLIKELY(regs[rs2].iv == -1))
                      regs[rd].iv = 0;
                    else if (rLANG_LIKELY(regs[rs2].iv))
                      regs[rd].iv = regs[rs1].iv % regs[rs2].iv;
                    else
                      regs[rd].iv = regs[rs1].iv;
                    break;
                  case 7:  // REMU
                    if (rLANG_LIKELY(regs[rs2].uv))
                      regs[rd].uv = regs[rs1].uv % regs[rs2].uv;
                    else
                      regs[rd].uv = regs[rs1].uv;
                    break;
                }
              }
              break;

            case 0x0F >> 2:  // FENCE, FENCE.I
              if (op == 0x100F)
                Self()->op_FENCEI(op);
              else if (0x0F == (op & 0xF00FFFFF))
                Self()->op_FENCE(op);
              else
                return err = SIGILL;
              hart_->cyc_ += kCycFence;  /// 冲刷计 kCycFence (hook 本身照旧) ...
              break;

            case 0x73 >> 2:                    // ECALL, EBREAK, CSRRW, CSRRS, CSRRC, CSRRWI, CSRRSI, CSRRCI
              if (rLANG_LIKELY(op == 0x73)) {  // ECALL
                if (0 != (err = Self()->op_ECALL()))
                  return err;
              } else if (op == 0x00100073) {  // EBREAK
                if (0 != (err = Self()->op_EBREAK()))
                  return err;
              } else {
                if (0 != (err = Self()->op_CSRIF(op)))  // CSR**
                  return err;
              }
              break;

            default:
              return err = SIGILL;
          }
        }
      }
    } while (hart_->cyc_ < limit_cycles);

    return rLANG_ERROR_TIMEDOUT;
  }

 public: /// 只要地址在非法区域, 即使 size==0 也触发SIGSEGV, 地址对齐由调用者检查 ...
  int mm_CHKWR(libmb_t addr, libmb_t size, void** ppv) { return SIGSEGV; }
  int mm_CHKRO(libmb_t addr, libmb_t size, const void** ppv) { return SIGSEGV; }

  /**
   *! 返回一个VM_t下的字符串, 如果 lenIf 非nullptr则同时返回其长度 ...
   *! - 我们会自动的在 .text, .rodata, .data/.bss 末尾添加全0的 guard-page, 因此无需担心字符串无 NUL 结尾
   */
  int mm_CHKCS(libmb_t addr, const char** pps, libmb_t* lenIf) { return SIGSEGV; }

 protected:
  IMPL* Self() { return static_cast<IMPL*>(this); }

 protected:  /// MMU ...
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
  void op_FENCE(libmb_t op) { /* nop */ }
  void op_FENCEI(libmb_t op) { /* nop */ }

  int op_ECALL() { return SIGILL; }
  int op_EBREAK() { return SIGTRAP; }
  int op_CSRIF(libmb_t op) { return SIGILL; }

 protected:  /// pc < 0x00000800 || pc >= 0xFFFFF800;;; id = (int)pc / 4;;; jalr id*4(zero)
  int op_GATE(int id) { return -ENOSYS; }

 protected:  /// rLANG_WORLD_MAGIC 的opcode是未分配的, 我们将其视作8字节指令, 并作为进入 LIMIT-World 的唯一入口 ...
  int op_HYPER(libmb_t op) { return -ENOSYS; }
};

/**
 *!
 */
rLANG_ABIREQUIRE(SIGQUIT == 3 && SIGILL == 4 && SIGTRAP == 5 && SIGSEGV == 11 && SIGKILL == 9 && SIGALRM == 14 &&
                 SIGVTALRM == 26);

/**
 *!
 */
rLANG_ABIREQUIRE((rLANG_WORLD_MAGIC ^ rLANG_ERROR_HYPER) == 0u);
rLANG_ABIREQUIRE(rLANG_WORLD_MAGIC - rLANG_ERROR_YEILD == 3u);
rLANG_ABIREQUIRE(rLANG_WORLD_MAGIC - rLANG_ERROR_TIMEDOUT == 2u);

}  // namespace hyper

rLANG_DECLARE_END

#endif /* __WTINC_RV32IM_ATOMIC_HPP__ */

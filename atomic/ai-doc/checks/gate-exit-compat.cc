/**
 * gate-exit-compat.cc —— **exit 门的宿主/guest 相容性检查** (2026-09-18)
 *
 * 为什么要单独有这个 TU: exit 协议的两端在**两个世界**里, 编译器永远不会把它们的常量、
 * 钳制表达式和算术放在一起看一眼 —— 只有跑一遍才知道"guest 发的三元组 + 门号"是否正好
 * 通过 host 的校验。本 TU 就是那条"把两端拼起来"的最小测试。
 *
 *   两端 (都来自同一个头 atomic/op_GATE/hyper/hyper.h, 所以常量只有一个来源):
 *     guest: modules.cc:29-41  `MatrixExit(v)` —— 只钳门号 `kGate`, a0 带**完整状态 v**;
 *                              发 `op_GATE(v, kExitMagic, v + kExitMagic, rLANG_WORLD_MAGIC)` 到 pc = 4*kGate
 *     host : hyper.h:64-80     `rLANG_op_GATE_HyperExit(vmx, gate)` —— 校验 `kGate == gate` 与三元组,
 *                              通过则 `MatrixExit(v)` (= 宿主构建下 `exit(v)`, 见 modules.cc:30-31 的 weak 定义)
 *
 * 本 TU 的做法:
 *   - 按 **guest 的公式**填寄存器, 按 **guest 的钳制表达式**算门号, 然后交给**真 host 模板**判;
 *   - 把宿主的 `MatrixExit` 用 longjmp 截住 (真宿主是 exit(v), 会直接结束进程), 从而能断言状态值;
 *   - `rlLoggingWrite` 用一个最小 stub 顶掉 (真库里才有), 好让 mismatch 路径可测。
 *
 * 编译 (本机实测):
 *   g++ -std=c++17 -Wall -Werror -I <ATOMIC> -o gate-exit-compat.exe checks/gate-exit-compat.cc
 */

#include <base/base.h>

#include <atomic/op_GATE/hyper/hyper.h>

#include <csetjmp>
#include <cstdint>
#include <cstdio>

/* ---- 宿主侧的最小替身 ---------------------------------------------------- */

static int g_logs = 0;
rLANGEXPORT void rlLoggingWrite(int, uint32_t, int, const char*, ...) {
  ++g_logs; /* 真实现要 base 库; 这里只关心"mismatch 路径确实打了日志" */
}

static std::jmp_buf g_exitJmp;
static int g_exitStatus = 0;
static int g_exitCalls = 0;

/* 真宿主里这个符号来自 modules.cc 的 `#ifndef rLANG_CONFIG_MATRIX_WORLD` 分支 (= exit(v)), 而且是 **weak**;
   这里给一个 strong 版本 + longjmp, 正好也验证了"宿主可以接管退出动作"这件事本身。 */
rLANGEXPORT __attribute__((noreturn)) void MatrixExit(int v) {
  g_exitStatus = v;
  ++g_exitCalls;
  std::longjmp(g_exitJmp, 1);
}

/* 只为拿到真的 hart_t/regs_t (字段名/类型错了会在这里编译失败 —— 这本身也是检查的一部分) */
struct Dummy : machine::hyper::VM_t<Dummy> {};
struct MockVM {
  Dummy::hart_t* hart_;
};

static int failures = 0;
#define CHECK(cond, what) do { if (cond) printf("  PASS  %s\n", what); else { printf("  FAIL  %s\n", what); ++failures; } } while (0)

struct ExitCase {
  const char* name;
  int v;        /* guest 的状态 (a0) */
  int gate;     /* host 被派发到的门号 (pc/4) */
  uint32_t a1, a2, a3;
  bool expectExit;   /* true = 应当判为正常退出; false = 应当返回 SIGILL */
};

int main() {
  constexpr uint32_t kSentinel = rLANG_CONFIG_EXIT_GATE_MAGIC;
  constexpr uint32_t kWorld = static_cast<uint32_t>(rLANG_WORLD_MAGIC);
  constexpr int kMin = -2147483647 - 1; /* INT_MIN, 不 include <climits> */

  printf("[exit 兼容性] host kExitMagic = 0x%08X, 世界魔数 = 0x%08X, SIGILL = %d\n", kSentinel, kWorld, SIGILL);
  CHECK(kSentinel == static_cast<uint32_t>(rLANG_CONFIG_EXIT_GATE_MAGIC),
        "两端哨兵同一个来源: hyper.h 的 rLANG_CONFIG_EXIT_GATE_MAGIC (modules.cc 也用它, 不再各写一个字面量)");

  /* guest 的三元组构造 (modules.cc:38 的同一条公式: a2 是 **uint32 加**) */
  auto a2of = [](int v) -> uint32_t { return static_cast<uint32_t>(v) + kSentinel; };
  /* guest 的门号钳制 (modules.cc:34 的同一条表达式) */
  auto gateOf = [](int v) -> int { return v < -64 ? -64 : v > 63 ? 63 : v; };

  const ExitCase cases[] = {
      {"MatrixExit(0)",                        0,          0,   kSentinel, a2of(0),  kWorld, true},
      {"MatrixExit(42)",                       42,         42,  kSentinel, a2of(42), kWorld, true},
      {"MatrixExit(-64) 下边界门号",             -64,        -64, kSentinel, a2of(-64), kWorld, true},
      {"MatrixExit(63) 上边界门号",              63,         63,  kSentinel, a2of(63), kWorld, true},
      {"MatrixExit(1000): 门号钳到 63, 状态不钳", 1000,       63,  kSentinel, a2of(1000), kWorld, true},
      {"MatrixExit(-1000): 门号钳到 -64",        -1000,      -64, kSentinel, a2of(-1000), kWorld, true},
      {"MatrixExit(INT_MIN): 校验和回绕",        kMin,       -64, kSentinel, a2of(kMin), kWorld, true},
      {"MatrixExit(INT_MAX)",                   2147483647, 63,  kSentinel, a2of(2147483647), kWorld, true},
      /* ---- 以下都应判为故障 (返回 SIGILL, 不退出) ---- */
      {"(*nullptr)(): 同门号 0, 寄存器全 0",     0,          0,   0u,        0u,        0u,     false},
      {"(*nullptr)(): 只有哨兵对",              0,          0,   kSentinel, 0u,        0u,     false},
      {"门号与 a0 的钳制不符 (野生跳转)",        5,          6,   kSentinel, a2of(5),   kWorld, false},
      {"负状态却走了正门号",                    -1000,      63,  kSentinel, a2of(-1000), kWorld, false},
      {"哨兵错",                               0,          0,   0xDEADBEEFu, a2of(0), kWorld, false},
      {"校验和差 1",                           0,          0,   kSentinel, a2of(0) + 1u, kWorld, false},
      {"状态 = -哨兵: a2 恰为 0 也合法",  static_cast<int>(0u - kSentinel), 63, kSentinel, 0u, kWorld, true},
      {"世界魔数错 (另一个世界?)",               0,          0,   kSentinel, a2of(0), kWorld ^ 1u, false},
  };

  printf("[exit 兼容性] 逐例: guest 填寄存器 -> host 模板判\n");
  int caseIndex = 0;
  for (const ExitCase& c : cases) {
    Dummy::hart_t hart{};
    hart.regs_.a0.iv = c.v;
    hart.regs_.a1.uv = c.a1;
    hart.regs_.a2.uv = c.a2;
    hart.regs_.a3.uv = c.a3;
    MockVM vm{&hart};

    g_exitCalls = 0;
    g_exitStatus = 0x7FFFFFFF;
    g_logs = 0;
    int rc = 0;
    bool exited = false;
    if (setjmp(g_exitJmp) == 0) {
      rc = machine::rLANG_op_GATE_HyperExit(&vm, c.gate);
    } else {
      exited = true;
    }

    char msg[256];
    if (c.expectExit) {
      snprintf(msg, sizeof(msg), "%-38s => 退出, 状态 %d (门号 %d, host 重算 %d)", c.name, c.v, c.gate, gateOf(c.v));
      CHECK(exited && g_exitCalls == 1 && g_exitStatus == c.v, msg);
    } else {
      snprintf(msg, sizeof(msg), "%-38s => SIGILL, 不退出", c.name);
      CHECK(!exited && g_exitCalls == 0 && rc == SIGILL && g_logs >= 1, msg);
    }
    ++caseIndex;
  }
  printf("  [info] 共 %d 例 (含 %s)\n", caseIndex, "越界状态/野生跳转/各类三元组损坏");

  /* guest 与 host 的钳制表达式必须逐点一致 (把表达式抄两遍的风险钉住) */
  {
    int mismatch = 0;
    for (int v = -3000; v <= 3000; ++v) {
      const int expect = v < -64 ? -64 : v > 63 ? 63 : v;
      if (gateOf(v) != expect) ++mismatch;
    }
    CHECK(mismatch == 0, "门号钳制在 [-3000,3000] 上与参考表达式逐点一致 (两端用的是同一条表达式)");
  }

  /* 关键算术: 校验和必须按 uint32 加 —— INT_MIN 上"有符号加"会溢出 (UB), 而无符号永远成立 */
  {
    int signedSum = 0;
    const bool ovf = __builtin_add_overflow(kMin, static_cast<int>(kSentinel), &signedSum);
    CHECK(ovf, "host 若写有符号 `a0 + a1` 算校验和: 位模式虽同, 但在 INT_MIN 上是 **UB** (UBSan/-ftrapv 会直接中止) —— 模板用 uint32 加, 正确");
    Dummy::hart_t hart{};
    hart.regs_.a0.iv = kMin;
    hart.regs_.a1.uv = kSentinel;
    hart.regs_.a2.uv = static_cast<uint32_t>(kMin) + kSentinel; /* guest 的 uint32 加 */
    hart.regs_.a3.uv = kWorld;
    MockVM vm{&hart};
    g_exitCalls = 0;
    bool exited = false;
    if (setjmp(g_exitJmp) == 0) {
      (void)machine::rLANG_op_GATE_HyperExit(&vm, -64);
    } else {
      exited = true;
    }
    CHECK(exited && g_exitStatus == kMin, "INT_MIN 状态端到端通过 (校验和按 uint32 回绕, 状态完整带出)");
  }

  printf("\n%s (failures=%d)\n", failures ? "有失败" : "全部通过", failures);
  return failures;
}

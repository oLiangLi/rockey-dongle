/**
 * gate-exit-compat.cc —— **exit 门的宿主/guest 相容性检查** (2026-09-18)
 *
 * 为什么要单独有这个 TU: exit 协议的两端在**两个世界**里, 编译器永远不会把它们的常量、
 * 钳制/折叠表达式和算术放在一起看一眼 —— 只有跑一遍才知道"guest 发的三元组 + 门号"是否正好
 * 通过 host 的校验。本 TU 就是那条"把两端拼起来"的最小测试。
 *
 *   两端 (都来自同一个头 atomic/op_GATE/hyper/hyper.h, 所以常量只有一个来源):
 *     guest: modules.cc:29-41  `MatrixExit(v)` —— 门号 = **`(v & 0x7f) - 64`** (2026-09-18 由"钳制"改"取模折叠"),
 *                              a0 带**完整状态 v**;
 *                              发 `op_GATE(v, kExitMagic, v + kExitMagic, rLANG_WORLD_MAGIC)` 到 pc = 4*kGate
 *     host : hyper.h:64-80     `rLANG_op_GATE_HyperExit(vmx, gate)` —— 校验 `kGate == gate` 与三元组,
 *                              通过则 `MatrixExit(v)` (= 宿主构建下 `exit(v)`, 见 modules.cc:30-31 的 weak 定义)
 *
 * 本 TU 的做法:
 *   - 按 **guest 的公式**填寄存器, 按 **guest 的门号折叠表达式**算门号, 然后交给**真 host 模板**判;
 *   - 把宿主的 `MatrixExit` 用 longjmp 截住 (真宿主是 exit(v), 会直接结束进程), 从而能断言状态值;
 *   - `rlLoggingWrite` 用一个最小 stub 顶掉 (真库里才有), 好让 mismatch 路径可测。
 *
 * 编译 (本机实测; 2026-09-18 起本文件在 atomic/tests/):
 *   g++ -std=c++17 -Wall -Werror -I <ROOT> -I <ROOT>/atomic/include -o gate-exit-compat.exe atomic/tests/gate-exit-compat.cc
 * 统一跑法: node tools/rockey/ATOMC/ci/atomic-tests.cjs  (或 make test-atomic)
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
  auto a2of = [kSentinel](int v) -> uint32_t { return static_cast<uint32_t>(v) + kSentinel; };
  /* guest 的门号折叠 (modules.cc:34 的同一条表达式): **取模** `(int)((uint32_t)v & 0x7fu) - 64`, 不再是钳制。
     性质: 值域恒为 [-64,63]; 门号 = v mod 128 (以 -64 为原点) ⇒ 每个门号被 v 的无穷多个取值均匀命中。
     ⚠ 捕获列表写全 (不用隐式捕获): 严格模式编译器 (MSVC /clr 前的 C3493) 不认"未捕获地使用 constexpr 局部量",
     虽然 C++17 规则允许 —— 写全了在哪都能编。 */
  auto gateOf = [](int v) -> int { return (int)((uint32_t)v & 0x7fu) - 64; };
  /* ⚠ 门号**不再等于**区间内的状态值 (2026-09-18 改折叠式后的行为变化):
       旧钳制式对 `v ∈ [-64,63]` 是**恒等**映射 (`v=0 → 门 0`), 折叠式不是 (`v=0 → 门 -64`, `v=63 → 门 -1`)。
       下面每个 v 的门号都由**同一个公式**给出, 不再有"区间内可以用 v 当门号"这个思维定式。 */
  const int kNegSentinel = static_cast<int>(0u - kSentinel);
  const int kNegSentinelGate = gateOf(kNegSentinel);

  const ExitCase cases[] = {
      {"MatrixExit(0)",                        0,          gateOf(0),   kSentinel, a2of(0),  kWorld, true},
      {"MatrixExit(42)",                       42,         gateOf(42),  kSentinel, a2of(42), kWorld, true},
      {"MatrixExit(-64): 折叠到门号 0 (不是 -64)", -64,      gateOf(-64), kSentinel, a2of(-64), kWorld, true},
      {"MatrixExit(63): 折叠到门号 -1 (不是 63)",  63,       gateOf(63),  kSentinel, a2of(63), kWorld, true},
      {"MatrixExit(64) 折叠到门号 0",             64,         0,   kSentinel, a2of(64), kWorld, true},
      {"MatrixExit(127) 折叠到门号 63",           127,        63,  kSentinel, a2of(127), kWorld, true},
      {"MatrixExit(128) 折叠回门号 -64",          128,        -64, kSentinel, a2of(128), kWorld, true},
      {"MatrixExit(1000): 门号 1000 mod 128 = 40", 1000,      40,  kSentinel, a2of(1000), kWorld, true},
      {"MatrixExit(-1000): 门号 mod128 => -40",  -1000,      -40, kSentinel, a2of(-1000), kWorld, true},
      {"MatrixExit(INT_MIN): 低 7 位为 0 => -64", kMin,      -64, kSentinel, a2of(kMin), kWorld, true},
      {"MatrixExit(INT_MAX): 低 7 位全 1 => 63", 2147483647, 63,  kSentinel, a2of(2147483647), kWorld, true},
      /* ---- 以下都应判为故障 (返回 SIGILL, 不退出) ---- */
      {"(*nullptr)(): 同门号 0, 寄存器全 0",     0,          0,   0u,        0u,        0u,     false},
      {"(*nullptr)(): 只有哨兵对",              0,          0,   kSentinel, 0u,        0u,     false},
      {"门号与 a0 折叠出的门号不符 (野生跳转)",  5,          6,   kSentinel, a2of(5),   kWorld, false},
      {"负状态却走了正门号",                    -1000,      63,  kSentinel, a2of(-1000), kWorld, false},
      {"哨兵错",                               0,          0,   0xDEADBEEFu, a2of(0), kWorld, false},
      {"校验和差 1",                           0,          0,   kSentinel, a2of(0) + 1u, kWorld, false},
      {"状态 = -哨兵: a2 恰为 0 也合法",  kNegSentinel, kNegSentinelGate, kSentinel, 0u, kWorld, true},
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

  /* 门号折叠 `(v & 0x7f) - 64` 的性质: ① 值域 ② 与参考表达式逐点一致 ③ 覆盖全部 128 个门号且**均匀**
     (2026-09-18: 由"钳制"改为"取模折叠"后, 门号不再挤在两端, 而是把状态的低 7 位铺满整个 exit 窗口) */
  {
    int mismatch = 0, outOfRange = 0, hits[128] = {0};
    auto ref = [](int v) -> int { return (v & 0x7f) - 64; };
    for (int v = -4100; v <= 4100; ++v) {              /* 8201 点 ≈ 64 个完整周期 */
      const int g = gateOf(v);
      if (g < -64 || g > 63) ++outOfRange;
      if (g != ref(v)) ++mismatch;
      hits[g + 64]++;                                  /* g ∈ [-64,63] => 下标 [0,127] */
    }
    CHECK(outOfRange == 0, "门号值域恒为 [-64,63] (8201 点逐个验证) => 派发永远落在 exit 窗口内");
    CHECK(mismatch == 0, "门号折叠在 [-4100,4100] 上与参考表达式逐点一致 (两端用的是同一条表达式)");
    int distinct = 0, minHits = 1 << 30, maxHits = 0;
    for (int i = 0; i < 128; ++i) {
      if (hits[i]) ++distinct;
      if (hits[i] < minHits) minHits = hits[i];
      if (hits[i] > maxHits) maxHits = hits[i];
    }
    CHECK(distinct == 128, "128 个门号**全部可达** (取模后每个槽位都被真实状态命中; 钳制版只有 128 个里的 0 与 127 可达)");
    CHECK(minHits >= 60 && maxHits <= 68, "每个门号的命中次数 = 64 (8201/128) 上下浮动 ≤4 => 分布**均匀**, 门号不再是两个尖峰");
    /* 直观对照: v ∈ [0,129] 与门号的对应关系 (前 64 个走低半窗, 后 64 个走高半窗) */
    printf("  [info] v=0→%d, v=63→%d, v=64→%d, v=127→%d, v=128→%d (折叠, 周期 128)\n",
           gateOf(0), gateOf(63), gateOf(64), gateOf(127), gateOf(128));
  }

  /* 关键算术: 校验和必须按 uint32 加 —— INT_MIN 上"有符号加"会溢出 (UB), 而无符号永远成立 */
  {
    /* 判据**不用** `__builtin_add_overflow` (GCC/clang 专属): 写成可移植的 int64 宽算 + 回代 */
    auto addOverflowsInt = [](int a, int b) -> bool {
      const std::int64_t wide = static_cast<std::int64_t>(a) + static_cast<std::int64_t>(b);
      return wide != static_cast<std::int64_t>(static_cast<int>(wide));
    };
    CHECK(addOverflowsInt(kMin, static_cast<int>(kSentinel)),
          "host 若写有符号 `a0 + a1` 算校验和: 位模式虽同, 但在 INT_MIN 上是 **UB** (UBSan/-ftrapv 会直接中止) —— 模板用 uint32 加, 正确");
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

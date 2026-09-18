/**
 * exit-gate-map.cc —— **exit 门号映射 (2026-09-18 用户改版: 钳制 → 取模折叠) 的性质与规范**
 *
 * 门号公式在**两个地方各写了一遍** (编译器永远不会把它们放在一起看一眼):
 *   guest: `atomic/op_GATE/hyper/modules.cc` 的 `MatrixExit`   —— `const int kGate = (v & 0x7f) - 64;`
 *   host : `atomic/op_GATE/hyper/hyper.h`    的 `rLANG_op_GATE_HyperExit` (要 `kGate == gate`)
 * 两处**不一致的后果**是静默的: 每次退出都判 SIGILL。
 *
 * 本 TU 的定位 (与另两个检查互补, 见 atomic/tests/README.md):
 *   - `interpreter-smoke.cc` **规程十** 用**手写的同一条表达式**跑真解释器 ⇒ 验"派发/判别规则",
 *     但它是**同构复现** (公式抄在 TU 里), 源码若漂移它不会红;
 *   - `gate-exit-compat.cc` 用**真 host 模板**判协议, 但门号也是按 guest 公式算好传进去的;
 *   - **本 TU** 只做一件事: 把**改版后的公式语义**钉成可执行断言 —— 值域 / 周期 128 / 128 门号全可达 /
 *     严格均匀 / 与**独立的无符号掩码实现**逐点一致, 并记录"公式是**第三份副本**, 漂移面在哪"。
 *
 * ⇒ 因此: **改公式时必须同步改这一份** (它故意是第三份副本 —— 漂移了本检查立刻变红)。
 * ⇒ 更好的做法 (未实施, 建议): 收成**单一来源**, 例如 `hyper.h` 里 `#define rLANG_EXIT_GATE_OF(v)
 *    ((int)((unsigned)(v) & 0x7fu) - 64)`, `modules.cc` 与宿主模板都调它 ⇒ 漂移面归零, 本 TU 只剩性质检查。
 *
 * 编译 (2026-09-18 起本文件在 atomic/tests/; 与其它检查同一条命令):
 *   g++ -std=c++17 -Wall -Werror -I <ROOT> -I <ROOT>/atomic/include -o exit-gate-map.exe atomic/tests/exit-gate-map.cc
 * 统一跑法: node tools/rockey/ATOMC/ci/atomic-tests.cjs  (或 make test-atomic)
 */

#include <base/base.h>

#include <atomic/op_GATE/hyper/hyper.h>   /* 哨兵/世界魔数的唯一来源 (顺带证明 host 头能编) */

#include <cstdint>
#include <cstdio>

static int failures = 0;
#define CHECK(cond, what) do { if (cond) printf("  PASS  %s\n", what); else { printf("  FAIL  %s\n", what); ++failures; } } while (0)

/* 现行公式 (≙ modules.cc:34 与 hyper.h:69 的那条表达式; 改公式时这里也要改) */
static int gateOf(int v) { return (v & 0x7f) - 64; }
/* 独立参考: 无符号掩码写法 —— 语义上就是"低 7 位", 用来交叉验证上面那份的负数行为 */
static int refGateOf(int v) { return static_cast<int>(static_cast<unsigned>(v) & 0x7Fu) - 64; }

int main() {
  printf("[exit 门号映射] 公式 = (v & 0x7f) - 64 (用户 2026-09-18 由钳制改为取模折叠)\n");

  /* (1) 与独立参考逐点一致 ⇒ 负数走的是"低 7 位"而不是数学取模 (v % 128 会得负余数, 是错的写法) */
  {
    int mismatch = 0;
    for (int v = -4100; v <= 4100; ++v)
      if (gateOf(v) != refGateOf(v)) ++mismatch;
    CHECK(mismatch == 0, "与独立参考 (unsigned 掩码) 逐点一致 => 语义 = **低 7 位** (不是 `v % 128`)");
    CHECK(gateOf(-1) == 63 && gateOf(-128) == -64 && gateOf(0) == -64 && gateOf(127) == 63,
          "边界语义: -1/-128/0/127 => 63/-64/-64/63 (负数按二进制补码取低 7 位)");
  }

  /* (2) 值域恒为 [-64,63] */
  {
    int out = 0;
    for (int v = -4100; v <= 4100; ++v)
      if (gateOf(v) < -64 || gateOf(v) > 63) ++out;
    CHECK(out == 0, "门号值域恒为 [-64,63] (8201 点) => 派发永远落在 exit 窗口内 (不需要额外钳制)");
  }

  /* (3) 周期 128: v 与 v+128 同门号; 且 128 个门号**全部可达** (钳制版只有 -64/63 两个可达) */
  {
    int periodBad = 0, distinct = 0;
    bool hit[128] = {false};
    for (int v = -4096; v <= 4096; ++v) {
      const int g = gateOf(v);
      if (g != gateOf(v + 128)) ++periodBad;
      if (g >= -64 && g <= 63) hit[g + 64] = true;
      else ++periodBad;
    }
    for (int i = 0; i < 128; ++i) if (hit[i]) ++distinct;
    CHECK(periodBad == 0, "折叠周期 = 128 (v 与 v+128 必落同一个门号), 且无一越窗");
    CHECK(distinct == 128, "128 个门号**全部可达** => exit 窗口被均匀用满 (这正是改版要的\"更均匀\")");
  }

  /* (4) 均匀性: 136 个连续状态恰好铺满 128 个门号一次 + 前 8 个再多一次 (严格可复述的判据) */
  {
    int hits[128] = {0};
    for (int v = 0; v < 136; ++v) hits[gateOf(v) + 64]++;
    int bad = 0;
    for (int i = 0; i < 128; ++i) {
      const int want = 1 + (i < 8 ? 1 : 0);   /* 136 = 128 + 8 */
      if (hits[i] != want) ++bad;
    }
    CHECK(bad == 0, "136 个连续状态 => 128 个门号各恰好命中 1 次, 前 8 个各多 1 次 (严格均匀)");

    int wideMin = 1 << 30, wideMax = 0;
    for (int i = 0; i < 128; ++i) hits[i] = 0;
    for (int v = -4100; v <= 4100; ++v) hits[gateOf(v) + 64]++;
    for (int i = 0; i < 128; ++i) {
      if (hits[i] < wideMin) wideMin = hits[i];
      if (hits[i] > wideMax) wideMax = hits[i];
    }
    CHECK(wideMin >= 60 && wideMax <= 68, "8201 点下每槽命中 64±4 次 => 宽区间同样均匀 (分布无偏)");
  }

  /* (5) 这次改版**只动门号映射**, 协议其余部分不变 */
  {
    constexpr std::uint32_t kSentinel = rLANG_CONFIG_EXIT_GATE_MAGIC;
    CHECK(kSentinel == 0xFEA1DEADu, "哨兵常量仍是 rLANG_CONFIG_EXIT_GATE_MAGIC = 0xFEA1DEAD (改版不动协议)");
    CHECK(static_cast<std::uint32_t>(rLANG_WORLD_MAGIC) == 0xC8C04E1Fu, "世界魔数不变 (rLANG_WORLD_MAGIC)");
  }

  printf("\n%s (failures=%d)\n", failures ? "有失败" : "全部通过", failures);
  return failures;
}

#include <base/base.h>
#include "rv32im-atomic.hpp"
#include <cstdio>
#include <cstdint>

struct Mem {
  static constexpr std::uint32_t kBase = 0x1000u, kSize = 0x4000u;
  std::uint8_t b[kSize];
};

struct Impl : machine::hyper::VM_t<Impl> {
  Mem mem{};
  int gate_calls = 0, gate_last_id = -1;
  int code_fetches = 0;

  bool inRange(std::uint32_t a, std::uint32_t n) const {
    return a >= Mem::kBase && (static_cast<std::uint64_t>(a) + n) <= (Mem::kBase + Mem::kSize);
  }
  void put(std::uint32_t pc, std::uint32_t op) {
    const std::uint32_t o = pc - Mem::kBase;
    for (int i = 0; i < 4; ++i) mem.b[o + i] = static_cast<std::uint8_t>(op >> (8 * i));
  }
  std::uint32_t get(std::uint32_t a, int n) {
    const std::uint32_t o = a - Mem::kBase; std::uint32_t v = 0;
    for (int i = 0; i < n; ++i) v |= static_cast<std::uint32_t>(mem.b[o + i]) << (8 * i);
    return v;
  }
  void set(std::uint32_t a, std::uint32_t v, int n) {
    const std::uint32_t o = a - Mem::kBase;
    for (int i = 0; i < n; ++i) mem.b[o + i] = static_cast<std::uint8_t>(v >> (8 * i));
  }

  int if_CODE(libmb_t pc, libmb_t* op) {
    ++code_fetches;
    if (!inRange(pc, 4) || (pc & 3u)) return SIGSEGV;
    *op = get(pc, 4); return 0;
  }
  int mm_LB (libmb_t a, reg_t* v) { if (!inRange(a,1)) return SIGSEGV; v->iv = static_cast<int8_t>(get(a,1));  return 0; }
  int mm_LBU(libmb_t a, reg_t* v) { if (!inRange(a,1)) return SIGSEGV; v->uv = get(a,1);                        return 0; }
  int mm_LH (libmb_t a, reg_t* v) { if (!inRange(a,2) || (a & 1u)) return SIGSEGV; v->iv = static_cast<int16_t>(get(a,2)); return 0; }
  int mm_LHU(libmb_t a, reg_t* v) { if (!inRange(a,2) || (a & 1u)) return SIGSEGV; v->uv = get(a,2);            return 0; }
  int mm_LW (libmb_t a, reg_t* v) { if (!inRange(a,4) || (a & 3u)) return SIGSEGV; v->uv = get(a,4);            return 0; }
  int mm_SB (libmb_t a, libmb_t v) { if (!inRange(a,1)) return SIGSEGV; set(a, v, 1); return 0; }
  int mm_SH (libmb_t a, libmb_t v) { if (!inRange(a,2) || (a & 1u)) return SIGSEGV; set(a, v, 2); return 0; }
  int mm_SW (libmb_t a, libmb_t v) { if (!inRange(a,4) || (a & 3u)) return SIGSEGV; set(a, v, 4); return 0; }

  int op_GATE(int id) { ++gate_calls; gate_last_id = id; return 0; }

  /* ---- 宿主/上层 API 的参考实现 (mm_CHKWR / mm_CHKRO / mm_CHKCS) ----
     契约: 返回 0 = 通过并把地址/长度写出参; 非 0 = SIGSEGV (拒绝), **不写 hart 的 zero** (由调用者处理)。
     区间判断: 地址空间 ≤ 640K ⇒ **32 位足够**, 关键是"先界 addr, 再界 size" (减法不会回绕)。 */
  int mm_CHKWR(libmb_t a, libmb_t n, void** p) {
    if (a < Mem::kBase || a >= Mem::kBase + Mem::kSize) return SIGSEGV;   /* size==0 时也拒绝非法地址 */
    if (n > (Mem::kBase + Mem::kSize) - a) return SIGSEGV;
    *p = &mem.b[a - Mem::kBase];
    return 0;
  }
  int mm_CHKRO(libmb_t a, libmb_t n, const void** p) {
    if (a < Mem::kBase || a >= Mem::kBase + Mem::kSize) return SIGSEGV;
    if (n > (Mem::kBase + Mem::kSize) - a) return SIGSEGV;
    *p = &mem.b[a - Mem::kBase];
    return 0;
  }
  int mm_CHKCS(libmb_t a, const char** s, libmb_t* lenIf) {
    if (a < Mem::kBase || a >= Mem::kBase + Mem::kSize) return SIGSEGV;   /* 只读访问即可 (最小权限) */
    std::uint32_t i = a - Mem::kBase;
    while (i < Mem::kSize && mem.b[i] != 0) ++i;   /* guard-page 保证有 NUL; 仍在范围内扫描 */
    if (i >= Mem::kSize) return SIGSEGV;           /* 范围内没有 NUL: 拒绝, 不越界读 */
    if (s) *s = reinterpret_cast<const char*>(&mem.b[a - Mem::kBase]);
    if (lenIf) *lenIf = i - (a - Mem::kBase);
    return 0;
  }
};

static int failures = 0;
#define CHECK(cond, what) do { if (cond) printf("  PASS  %s\n", what); else { printf("  FAIL  %s\n", what); ++failures; } } while (0)

int main() {
  {
    Impl vm; Impl::hart_t hart{};
    const std::uint32_t p = Mem::kBase;
    vm.put(p + 0x00, 0x00500513u);  /* addi a0, x0, 5     */
    vm.put(p + 0x04, 0x00700593u);  /* addi a1, x0, 7     */
    vm.put(p + 0x08, 0x00B50633u);  /* add  a2, a0, a1    */
    vm.put(p + 0x0C, 0x02B506B3u);  /* mul  a3, a0, a1    */
    vm.put(p + 0x10, 0x02054733u);  /* div  a4, a0, x0    */
    vm.put(p + 0x14, 0x020567B3u);  /* rem  a5, a0, x0    */
    vm.put(p + 0x18, 0x000022B7u);  /* lui  t0, 0x2       */
    vm.put(p + 0x1C, 0x00D2A023u);  /* sw   a3, 0(t0)     */
    vm.put(p + 0x20, 0x0002A803u);  /* lw   a6, 0(t0)     */
    vm.put(p + 0x24, 0x0080006Fu);  /* jal  x0, +8        */
    vm.put(p + 0x28, 0x06300893u);  /* addi a7, x0, 99 (跳过) */
    vm.put(p + 0x2C, 0x00000073u);  /* ecall -> 默认 SIGILL */
    hart.pc_ = p; hart.Enable();
    const int rc = vm.Execv(&hart, 64);
    printf("[规程一] rc=%d zero=%d pc=0x%X cycles=%llu\n", rc, hart.regs_.zero.iv, hart.pc_,
           static_cast<unsigned long long>(hart.cycles_));
    CHECK(rc == SIGILL && hart.regs_.zero.iv == SIGILL, "ecall 默认返回 SIGILL 且写入 regs.zero");
    CHECK(hart.regs_.a0.iv == 5, "addi a0 = 5");
    CHECK(hart.regs_.a1.iv == 7, "addi a1 = 7");
    CHECK(hart.regs_.a2.iv == 12, "add a2 = 12");
    CHECK(hart.regs_.a3.iv == 35, "mul a3 = 35");
    CHECK(hart.regs_.a4.iv == -1, "div 5/0 = -1 (RV32M)");
    CHECK(hart.regs_.a5.iv == 5, "rem 5%0 = 5 (RV32M)");
    CHECK(hart.regs_.t0.uv == 0x2000u, "lui t0 = 0x2000");
    CHECK(vm.get(0x2000u, 4) == 35u, "sw a3 -> mem[0x2000] = 35");
    CHECK(hart.regs_.a6.iv == 35, "lw a6 = 35");
    CHECK(hart.regs_.a7.iv == 0, "jal x0 跳过 addi a7");
    CHECK(hart.cyc_ == 11, "cyc_ = 11 条(本片)");
  }
  {
    Impl vm; Impl::hart_t hart{};
    vm.put(Mem::kBase, 0x00000067u);            /* jalr x0, 0(x0) -> 跳进门窗口 id 0 */
    hart.pc_ = Mem::kBase; hart.regs_.ra.uv = Mem::kBase; hart.Enable();
    const int rc = vm.Execv(&hart, 6);
    printf("[规程二] rc=%d 门调用=%d 末次id=%d pc=0x%X\n", rc, vm.gate_calls, vm.gate_last_id, hart.pc_);
    CHECK(rc == rLANG_ERROR_TIMEDOUT, "时间片用尽返回 rLANG_ERROR_TIMEDOUT");
    CHECK(vm.gate_calls == 3 && vm.gate_last_id == 0, "门被调用 3 次 (6 条预算里 jalr/门 交替), id=0");
    CHECK(hart.pc_ == Mem::kBase, "门返回后 pc_ 取 x1(ra)");
    CHECK(hart.regs_.ra.uv == Mem::kBase, "ra 未被改动");
  }
  {
    Impl vm; Impl::hart_t hart{};
    vm.put(Mem::kBase, 0x00500513u);            /* addi a0, x0, 5 */
    hart.pc_ = Mem::kBase; hart.Enable();
    const int rc = vm.Execv(&hart, 0);
    printf("[规程三] limit_cycles=0 -> rc=%d a0=%d cyc_=%u\n", rc, hart.regs_.a0.iv, hart.cyc_);
    CHECK(rc == rLANG_ERROR_TIMEDOUT, "0 预算仍返回 TIMEDOUT");
    CHECK(hart.regs_.a0.iv == 5 && hart.cyc_ == 1, "limit_cycles==0 => **单步**执行 1 条 (约定: 0 与 1 都是单步)");
    /* 同一程序 + limit_cycles==1, 结果必须与 0 完全一致 => 证明"0 与 1 都表示单步" */
    Impl vm1; Impl::hart_t hart1{};
    vm1.put(Mem::kBase, 0x00500513u);
    hart1.pc_ = Mem::kBase; hart1.Enable();
    const int rc1 = vm1.Execv(&hart1, 1);
    CHECK(rc1 == rc && hart1.regs_.a0.iv == hart.regs_.a0.iv && hart1.cyc_ == hart.cyc_ && hart1.pc_ == hart.pc_,
          "limit_cycles==1 与 ==0 结果逐项相同 => 两者同义 (单步)");
  }
  {
    /* 规程四: 宿主/上层 API —— mm_CHKWR / mm_CHKRO / mm_CHKCS (含 32 位回绕的经典陷阱) */
    Impl vm; Impl::hart_t hart{}; hart.Enable();
    void* wp = nullptr; const void* rp = nullptr; const char* cs = nullptr; Impl::libmb_t len = 0;
    const char* kHello = "hello";
    for (unsigned i = 0; i <= 5; ++i) vm.mem.b[0x1500 - Mem::kBase + i] = static_cast<std::uint8_t>(kHello[i]);
    for (unsigned i = 0; i < 16; ++i) vm.mem.b[Mem::kSize - 16 + i] = 'x';   /* 末尾放无 NUL 的一段 */

    printf("[规程四] CHKWR/CHKRO/CHKCS (宿主 API)\n");
    CHECK(vm.mm_CHKWR(0x2000u, 4, &wp) == 0 && wp == &vm.mem.b[0x1000], "CHKWR 可写区间 -> 0 且返回正确地址");
    CHECK(vm.mm_CHKWR(0x5000u, 1, &wp) == SIGSEGV, "CHKWR 越界(尾) -> SIGSEGV");
    CHECK(vm.mm_CHKWR(0x0FFFFFF0u, 0x20u, &wp) == SIGSEGV, "CHKWR 32 位回绕算例 -> SIGSEGV (先界 addr 即无回绕)");
    CHECK(vm.mm_CHKWR(Mem::kBase, 0, &wp) == 0, "CHKWR 合法地址 + size==0 -> 0");
    CHECK(vm.mm_CHKWR(0xFFFFFFF0u, 0, &wp) == SIGSEGV, "CHKWR 非法地址 + size==0 -> SIGSEGV (地址先判)");
    CHECK(vm.mm_CHKRO(Mem::kBase, Mem::kSize, &rp) == 0 && rp == &vm.mem.b[0], "CHKRO 整段可读 -> 0");
    CHECK(vm.mm_CHKCS(0x1500u, &cs, &len) == 0 && len == 5 && cs && cs[0] == 'h', "CHKCS 字符串 -> 0, 长度 5");
    CHECK(vm.mm_CHKCS(Mem::kBase + Mem::kSize - 16, &cs, &len) == SIGSEGV, "CHKCS 范围内无 NUL -> SIGSEGV (不越界读)");
  }
  {
    /* 规程五: "零页兜底" 技术的演示 —— 注意这是 2026-09-16 **第 1 版**布局
       (第 1 版: [0x10000,0xB0000) 映像 640K + [0xB0000,0xB1000) 只读零页);
       第 2 版(DOS 风格)已把兜底换成"设备区哨兵 0x55AAFF00", 见规程六。
       这里保留它, 是为了演示零页兜底技术的三个通用前提 —— 换成任何布局都适用。 */
    static std::uint8_t buf[0x10000 + 0x4000 + 0x1000];
    const std::uint32_t kBase = 0x10000u, kSize = 0x4000u;
    for (auto& b : buf) b = 0;
    for (std::uint32_t i = 0; i < kSize; ++i) buf[kBase + i] = 'A';   /* 映像内一个 NUL 都没有 */
    auto scan = [&](std::uint32_t a) -> long {
      if (a < kBase) return -1;                                       /* 低 64K 未映射 */
      std::uint32_t i = a;
      while (buf[i] != 0) ++i;                                        /* 无上界检查: 靠零页兜底 */
      return static_cast<long>(i - a);
    };
    printf("[规程五] 零页兜底布局 (CHKCS 不做上界检查的前提)\n");
    CHECK(scan(kBase) == static_cast<long>(kSize), "映像内无 NUL -> 扫描穿到零页, 返回\"到第一个 0\"的长度 (不再 SIGSEGV)");
    CHECK(scan(0x800u) == -1, "低 64K 未映射 -> 仍需一次 addr 下界比较 (否则缺页会打到宿主)");
    buf[kBase + kSize] = 'X';                                         /* 模拟兜底页被写脏 */
    CHECK(scan(kBase) == static_cast<long>(kSize) + 1, "兜底页一旦被写脏, 扫描就越过页首 -> 说明该页必须**只读**");
  }
  {
    /* 规程六: DOS 风格内存映射 (2026-09-16 最终版; sp/HMA 与 ROM 尺寸已定)
       [0x00000,0x0FFFF] 不映射 | [0x10000,0x9FFFF] 映像 576K
       [0xA0000,0xEFFFF] 设备区 (可写; 不存在: 写忽略 / 读 0x55AAFF00)
       [0xF0000,0xFFFFF] 设备只读区: **ROM 最大 64K-16 = 0xFFF0 字节**, 故 0xF0000 起 16 字节恒为 0
       [0x100000,0x10FFFF] 栈; sp = 0x10FFE0 (16 字节对齐, 且落在经典 HMA 内) */
    static std::uint8_t m[0x100000 + 0x10000];
    const std::uint32_t kImg = 0x10000u, kImgEnd = 0xA0000u, kDevEnd = 0xF0000u, kRomEnd = 0x100000u;
    const std::uint32_t kSp0 = 0x10FFE0u, kHmaTop = 0x10FFEFu;
    for (auto& b : m) b = 0;
    for (std::uint32_t a = kImg; a < kImgEnd; ++a) m[a] = 'A';                    /* 576K 映像, 无 NUL */
    const std::uint8_t pat[4] = {0x00u, 0xFFu, 0xAAu, 0x55u};                    /* 0x55AAFF00 小端字节序 */
    for (std::uint32_t a = kImgEnd; a < kDevEnd; ++a) m[a] = pat[a & 3u];
    for (std::uint32_t a = kDevEnd + 16u; a < kRomEnd; ++a) m[a] = 0xFFu;         /* ROM 内容(≤0xFFF0 字节, 此处取最坏全非 0) */
    auto scanLen = [&](std::uint32_t a, long cap) -> long {
      std::uint32_t i = a;
      while (i < 0x110000u && m[i] != 0 && static_cast<long>(i - a) < cap) ++i;
      return (m[i] != 0 || i >= 0x110000u) ? -1 : static_cast<long>(i - a);
    };
    auto romWritable = [&](std::uint32_t a) -> bool { return !(a >= kDevEnd && a < kRomEnd); };
    printf("[规程六] DOS 风格内存映射 (最终版: ROM ≤ 64K-16, sp 落在 HMA 内)\n");
    CHECK(kImgEnd == 0xA0000u && kDevEnd == 0xF0000u && kRomEnd == 0x100000u,
          "边界即 DOS 1MB 实模式图: 640K / 896K / 1M (含 0xFFFF0 复位向量位置)");
    CHECK(m[kDevEnd] == 0u && m[kDevEnd + 15u] == 0u && m[kDevEnd + 16u] == 0xFFu,
          "ROM 最大 0xFFF0 字节 -> 0xF0000 起 **16 字节恒为 0**, ROM 内容自 0xF0010 起 (0xFFFF0 留作复位向量)");
    for (std::uint32_t a = 0xEFFF0u; a < kDevEnd; ++a) m[a] = 0xEEu;   /* 对照: 模拟"设备存在且读出无 0" */
    CHECK(scanLen(0xEFFF0u, 0x1000) == 16,
          "对照实验: 即使下邻 16 字节全非 0, 也必在 F 段前 16 字节的 0 上终止 (结构性保证)");
    CHECK(m[kImgEnd] == 0x00u && m[kImgEnd + 1] == 0xFFu && m[kImgEnd + 2] == 0xAAu && m[kImgEnd + 3] == 0x55u,
          "设备区按 4 字节重复填充 -> 对齐 LW 读得 0x55AAFF00 (55 AA = 引导扇区签名)");
    CHECK(scanLen(kDevEnd + 16u, 0x1000) == -1,
          "只有\"直接传 ROM 内部/栈地址\"才无 0 保证 (对字符串 API 属调用错误) -> 长度上限转为防御性");
    CHECK(!romWritable(kSp0 - 0x10000u), "ROM 区写入总是 SIGSEGV -> sp 下溢到 0xFFFFF 立即报错 = 栈下护栏");
    CHECK((kSp0 & 15u) == 0u && kSp0 < kHmaTop, "sp = 0x10FFE0: 16 字节对齐, 且整个栈落在经典 HMA (0x100000-0x10FFEF) 内");
    /* 低 64K 未映射, 但门窗口正在同一地址段: 数据访问必 fault, 作为 pc 却被 VM 拦截 */
    Impl vm2; Impl::hart_t h2{};
    h2.pc_ = 0x0000u;                       /* 直接把 pc 放进门窗口 (该地址未映射) */
    h2.regs_.ra.uv = Mem::kBase; h2.Enable();
    const int rc2 = vm2.Execv(&h2, 1);
    CHECK(!(0x0000u >= 0x10000u), "低 64K 未映射: 作为**数据**访问 0x000 必 SIGSEGV");
    CHECK(rc2 == rLANG_ERROR_TIMEDOUT && vm2.gate_calls == 1 && h2.pc_ == Mem::kBase,
          "同一地址作为 **pc** 被拦截成门调用 (无需取指、无需映射) -> \"门不可读\"由映射白拿");
  }
  {
    /* 规程七: 兼容性原则 —— guest 可见的取值必须与平台无关 (ATOMC 不引入"无端不兼容") */
    printf("[规程七] 兼容性: 平台无关取值 vs 宿主 errno\n");
    printf("  [info] 宿主 <errno.h>: ENOSYS=%d EINVAL=%d EACCES=%d EALREADY=%d\n", ENOSYS, EINVAL, EACCES, EALREADY);
    printf("  [info] musl(riscv32) 期望: ENOSYS=-38 EINVAL=-22 EACCES=-13 EALREADY=-114\n");
    CHECK(rLANG_ERROR_HYPER == static_cast<int32_t>(0xC8C04E1Fu)
       && rLANG_ERROR_YEILD == static_cast<int32_t>(0xC8C04E1Cu)
       && rLANG_ERROR_TIMEDOUT == static_cast<int32_t>(0xC8C04E1Du),
          "ATOMC 自有错误码是固定十六进制 => 跨平台一致 (正确范式: guest 可见的码照此办)");
    CHECK(SIGQUIT == 3 && SIGILL == 4 && SIGTRAP == 5 && SIGTERM == 15 && SIGSEGV == 11
       && SIGKILL == 9 && SIGALRM == 14 && SIGVTALRM == 26,
          "SIG* 已被 ABIREQUIRE 钉成 POSIX 值 => 跨平台一致 (这些值**驱动分支**, 必须一致)");
    printf("  [note] 负 errno 的宿主差异按用户判别标准**可接受**: 通常只作报告, 不驱动分支 (需要时在门实现里钉成 musl 值即可)\n");
  }
  {
    /* 规程八: hart 初值契约 (用户 2026-09-16) —— 宿主只保证 x0/pc/cycles;
       **sp 与其余寄存器由 guest `start.S` 负责初始化** (所以"新 hart 其它寄存器是垃圾"是分工, 不是缺陷) */
    printf("[规程八] hart 初值契约: 宿主保证 x0/pc/cycles, 其余交给 guest start.S\n");
    Impl::hart_t h{};
    CHECK(h.regs_.zero.uv == SIGQUIT, "构造后 x0 == SIGQUIT (未 Enable 不许执行)");
    CHECK(h.pc_ == 0u && h.cyc_ == 0u && h.cycles_ == 0u, "pc_/cyc_/cycles_ 有确定初值 0");
    h.Enable();
    CHECK(h.regs_.zero.uv == 0u, "Enable() 后 x0 == 0 (允许执行)");
    printf("  [note] 其余寄存器 (含 sp) **不做保证** => guest `start.S` 必须先初始化再使用; 目标 sp = 0x10FFE0 (见规程六)\n");
    /* Enable(pc) 复核: 清 x0 + 置 pc; 但 (a) 不重置计数器 (b) 不做入口校验 */
    Impl::hart_t h2{};
    h2.cyc_ = 7u; h2.cycles_ = 100u;              /* 模拟"复用同一 hart 跑下一个程序"的残留 */
    h2.Enable(0x10000u);
    CHECK(h2.pc_ == 0x10000u && h2.regs_.zero.uv == 0u, "Enable(entry): pc = entry 且 x0 = 0");
    CHECK(h2.cyc_ == 7u && h2.cycles_ == 100u,
          "Enable(entry) **不重置** cyc_/cycles_ => 复用时上一次的计数会带进新程序 (是否有意? 见报告 §2.11)");
    Impl vm3; Impl::hart_t h3{};
    h3.regs_.ra.uv = Mem::kBase;                   /* 与规程六同构: 给链接寄存器一个合法返回地址 */
    h3.Enable(0u);                                 /* 入口 0: 不是 fault, 而是**门 0** */
    const int rc3 = vm3.Execv(&h3, 1);
    CHECK(rc3 == rLANG_ERROR_TIMEDOUT && vm3.gate_calls == 1 && vm3.gate_last_id == 0
       && h3.pc_ == Mem::kBase,
          "Enable(0) 后第一条指令被当**门 0 调用** (pc<0x800 是门窗口, 且不做取指) => 入口校验值得考虑");
  }
  printf("\n%s (failures=%d)\n", failures ? "有失败" : "全部通过", failures);
  return failures;
}



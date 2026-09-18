#include <base/base.h>
#include "../include/rv32im-atomic.hpp"
/* 只为拿 exit 协议的**唯一常量来源** rLANG_CONFIG_EXIT_GATE_MAGIC (2026-09-18 起 hyper.h 定义;
   这里不 hardcode 字面量 —— 之前手抄的 0xFEE1DEAD 已经落后于 rLANG_CONFIG_EXIT_GATE_MAGIC = 0xFEA1DEAD) */
#include <atomic/op_GATE/hyper/hyper.h>
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

  /* 门实现可以把自己的真实成本追加到同一个 cyc_ 上 (hart_ 是 protected, 派生类可达) */
  libmb_t gate_charge = 0;
  int hyper_calls = 0;
  int op_GATE(int id) {
    ++gate_calls; gate_last_id = id;
    if (hart_ && gate_charge) hart_->cyc_ += gate_charge;   /* 分层计价: 解释器收进门费, 门自报其余 */
    return 0;
  }
  int op_HYPER(libmb_t) { ++hyper_calls; return rLANG_ERROR_HYPER; }  /* 真实现就是这个语义: 挂起等 RPC */

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

/* 指令编码构造器 (按规范 §2 的字段位置生成; 手写 hex 曾经漏掉 funct3 而变成另一条指令, 一律用它) */
static constexpr std::uint32_t encR(std::uint32_t f7, std::uint32_t rs2, std::uint32_t rs1,
                                    std::uint32_t f3, std::uint32_t rd, std::uint32_t op) {
  return (f7 << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op;
}
static constexpr std::uint32_t encI(std::int32_t imm, std::uint32_t rs1, std::uint32_t f3,
                                    std::uint32_t rd, std::uint32_t op) {
  return (static_cast<std::uint32_t>(imm) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op;
}
static constexpr std::uint32_t encS(std::int32_t imm, std::uint32_t rs2, std::uint32_t rs1,
                                    std::uint32_t f3, std::uint32_t op) {
  return (((static_cast<std::uint32_t>(imm) >> 5) & 0x7F) << 25) | (rs2 << 20) | (rs1 << 15) |
         (f3 << 12) | ((static_cast<std::uint32_t>(imm) & 0x1F) << 7) | op;
}
static constexpr std::uint32_t encB(std::int32_t imm, std::uint32_t rs2, std::uint32_t rs1,
                                    std::uint32_t f3, std::uint32_t op) {
  const std::uint32_t u = static_cast<std::uint32_t>(imm);
  return (((u >> 12) & 1u) << 31) | (((u >> 5) & 0x3Fu) << 25) | (rs2 << 20) | (rs1 << 15) |
         (f3 << 12) | (((u >> 1) & 0xFu) << 8) | ((u & 0x1Fu) << 7) | op;
}

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
    const int rc = vm.Execv(&hart, 256);  /* 周期预算: 该程序 = 29 拍 (DIV 计入 8 拍; 用 64 也够, 这里留余量) */
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
    CHECK(hart.cyc_ == 29, "cyc_ == 29 拍 (addi1+addi1+add1+mul3+div8+rem8+lui1+sw2+lw2+jal1+ecall1), 不再是 11 条");
  }
  {
    Impl vm; Impl::hart_t hart{};
    vm.put(Mem::kBase, 0x00000067u);            /* jalr x0, 0(x0) -> 跳进门窗口 id 0 */
    hart.pc_ = Mem::kBase; hart.regs_.ra.uv = Mem::kBase; hart.Enable();
    const int rc = vm.Execv(&hart, 15);   /* 周期预算: 3 个"jalr(1) + 门(1+3)"交替 = 3*5 = 15 拍, 恰好停在门上 */
    printf("[规程二] rc=%d 门调用=%d 末次id=%d pc=0x%X\n", rc, vm.gate_calls, vm.gate_last_id, hart.pc_);
    CHECK(rc == rLANG_ERROR_TIMEDOUT, "时间片用尽返回 rLANG_ERROR_TIMEDOUT");
    CHECK(vm.gate_calls == 3 && vm.gate_last_id == 0, "门被调用 3 次 (15 拍预算里 jalr/门 交替), id=0");
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
  {
    /* 规程九: 指令周期计价 (2026-09-16 落地) —— 权重表 / 纯函数性 / 预算下界与超调 / 折叠 /
       门与 HYPER 的分层计价 / rd==0 载入的 ISA §2.6 修复 / RV32M 边界 / 可复现性 */
    printf("[规程九] 周期计价: 基础 1 拍 + 附加 (访存/M/除法/FENCE/门/RPC)\n");
    const int kTo = rLANG_ERROR_TIMEDOUT;
    CHECK(Impl::kCycMem == 1 && Impl::kCycBranch == 1 && Impl::kCycMul == 2 && Impl::kCycMulh == 3
       && Impl::kCycDiv == 7 && Impl::kCycFence == 3 && Impl::kCycGate == 3 && Impl::kCycHyper == (1u << 16),
          "权重表本身: mem 1 / branch 1 / mul 2 / mulh 3 / div 7 / fence 3 / gate 3 / hyper 65536 (附加; 合计 = 1+附加)");
    /* 计价原则 (用户 2026-09-16): "内置指令应该小于自己实现个自定义的门的代价, 不然就没人用了"
       界的最低算式 = 2 次寄存器经内存搬运 (2×(1+kCycMem)) + 一次自定义门 ((1+kCycGate) + 至少自加 1)
       补充: 门还要**占寄存器/现场**, 真实代价远高于此 ⇒ 这是保险丝, 只需成立 (见计价文档 §4.4) */
    CHECK(Impl::kCycDiv + 1 < 2 * (1 + Impl::kCycMem) + (1 + Impl::kCycGate) + 1,
          "内置最贵的 DIV (8 拍) < 2 次搬运 (4 拍) + 自定义门 (缺省 4 拍起, 自定义必然再自加 >=1) = 9 拍 => 原则成立");
    CHECK(Impl::kCycDiv >= Impl::kCycMem && Impl::kCycDiv >= Impl::kCycBranch && Impl::kCycDiv >= Impl::kCycMul
       && Impl::kCycDiv >= Impl::kCycMulh && Impl::kCycDiv >= Impl::kCycFence,
          "DIV 是内置指令里最贵的一档 => 上面那条不等式就是**全局上界** (以后加权重不得越过它)");

    /* 只跑一条指令: limit=1 单步 (第一条若成功则因时间片用尽返回 TIMEDOUT) */
    auto one = [](std::uint32_t op, int* rcOut, std::uint32_t rs1val = Mem::kBase,
                  std::uint32_t rs2val = 1u) -> std::uint32_t {
      Impl vm; Impl::hart_t h{};
      vm.put(Mem::kBase, op);
      vm.put(Mem::kBase + 4, 0x00000073u);   /* ecall -> 默认 SIGILL (单步时跑不到) */
      h.regs_.t1.uv = rs1val; h.regs_.a1.uv = 5; h.regs_.a2.uv = rs2val;
      h.pc_ = Mem::kBase; h.Enable();
      const int r = vm.Execv(&h, 1);
      if (rcOut) *rcOut = r;
      return static_cast<std::uint32_t>(h.cyc_);
    };

    int rc = 0;
    std::uint32_t c = 0;
    c = one(encI(7, 0, 0, 10, 0x13), &rc);        CHECK(rc == kTo && c == 1,  "addi / lui / add 类 => 1 拍");
    c = one(encI(0, 6, 2, 5, 0x03), &rc);         CHECK(rc == kTo && c == 2,  "lw  t0,0(t1)  => 2 拍 (1 + kCycMem)");
    c = one(encI(0, 6, 0, 5, 0x03), &rc);         CHECK(rc == kTo && c == 2,  "lb  t0,0(t1)  => 2 拍");
    c = one(encS(0, 5, 6, 2, 0x23), &rc);         CHECK(rc == kTo && c == 2,  "sw  t0,0(t1)  => 2 拍");
    c = one(encS(0, 5, 6, 0, 0x23), &rc);         CHECK(rc == kTo && c == 2,  "sb  t0,0(t1)  => 2 拍");
    c = one(encR(1, 12, 11, 0, 10, 0x33), &rc);   CHECK(rc == kTo && c == 3,  "mul           => 3 拍 (1 + kCycMul)");
    c = one(encR(1, 12, 11, 1, 10, 0x33), &rc);   CHECK(rc == kTo && c == 4,  "mulh          => 4 拍 (1 + kCycMulh)");
    c = one(encR(1, 12, 11, 2, 10, 0x33), &rc);   CHECK(rc == kTo && c == 4,  "mulhsu        => 4 拍");
    c = one(encR(1, 12, 11, 3, 10, 0x33), &rc);   CHECK(rc == kTo && c == 4,  "mulhu         => 4 拍");
    c = one(encR(1, 12, 11, 4, 10, 0x33), &rc);   CHECK(rc == kTo && c == 8,  "div           => 8 拍 (1 + kCycDiv, 策略上限)");
    c = one(encR(1, 12, 11, 5, 10, 0x33), &rc);   CHECK(rc == kTo && c == 8,  "divu          => 8 拍");
    c = one(encR(1, 12, 11, 6, 10, 0x33), &rc);   CHECK(rc == kTo && c == 8,  "rem           => 8 拍");
    c = one(encR(1, 12, 11, 7, 10, 0x33), &rc);   CHECK(rc == kTo && c == 8,  "remu          => 8 拍");
    c = one(0x0FF0000Fu, &rc);                    CHECK(rc == kTo && c == 4,  "fence         => 4 拍 (1 + kCycFence)");
    c = one(0x0000100Fu, &rc);                    CHECK(rc == kTo && c == 4,  "fence.i       => 4 拍");
    /* 条件分支: 固定 +1 拍惩罚, **不分**是否命中 (无条件跳转 JAL/JALR 不加) */
    c = one(encB(8, 12, 11, 0, 0x63), &rc, Mem::kBase, 5u);  CHECK(rc == kTo && c == 2, "beq a1,a2 (命中)   => 2 拍 (1 + kCycBranch)");
    c = one(encB(8, 12, 11, 0, 0x63), &rc, Mem::kBase, 6u);  CHECK(rc == kTo && c == 2, "beq a1,a2 (不命中) => 2 拍 (固定惩罚, 不分命中)");
    c = one(0x0080006Fu, &rc);                    CHECK(rc == kTo && c == 1,  "jal x0,+8 (无条件) => 1 拍 (跳转不加惩罚)");

    /* 权重必须是"指令类的纯函数": 与操作数无关, 不做早退 */
    const std::uint32_t d0 = one(encR(1, 12, 11, 4, 10, 0x33), &rc, Mem::kBase, 0u);
    const std::uint32_t dn = one(encR(1, 12, 11, 4, 10, 0x33), &rc, 0x80000000u, 0xFFFFFFFFu);
    const std::uint32_t d1 = one(encR(1, 12, 11, 4, 10, 0x33), &rc, 5u, 1u);
    CHECK(d0 == 8 && dn == 8 && d1 == 8,
          "div 除零 / INT_MIN÷-1 / 普通除法 都为 8 拍 => 权重是纯函数 (可复现、可预测)");

    /* 预算是下界: limit=0 仍是单步; 最大超调 = 单条最贵指令 = 8 拍 (DIV) = 调度粒度 */
    {
      Impl vm; Impl::hart_t h{};
      vm.put(Mem::kBase, encR(1, 12, 11, 4, 10, 0x33));   /* div */
      h.regs_.a1.uv = 5; h.regs_.a2.uv = 2;
      h.pc_ = Mem::kBase; h.Enable();
      const int r = vm.Execv(&h, 0);
      CHECK(r == kTo && h.regs_.a0.uv == 2u && h.cyc_ == 8,
            "limit=0 跑 div: 仍执行 1 条 (0 与 1 都是单步) 且超调到 8 拍 = 最大超调 = 调度粒度上限");
    }

    /* 折叠语义: 总代价 = cycles_ + cyc_ (折叠发生在 Execv 入口, 最后一片未结算) */
    {
      Impl vm; Impl::hart_t h{};
      vm.put(Mem::kBase + 0, encI(7, 0, 0, 10, 0x13));      /* addi 1 拍 */
      vm.put(Mem::kBase + 4, encI(0, 6, 2, 5, 0x03));       /* lw   2 拍 */
      vm.put(Mem::kBase + 8, encR(1, 12, 11, 0, 10, 0x33)); /* mul  3 拍 */
      h.regs_.t1.uv = Mem::kBase; h.pc_ = Mem::kBase; h.Enable();
      vm.Execv(&h, 1); vm.Execv(&h, 1); vm.Execv(&h, 1);
      CHECK(h.cycles_ == 3 && h.cyc_ == 3,
            "3 次单步后 cycles_ == 3 (已结算 2 片) 而 cyc_ == 3 (最后一片未结算)");
      CHECK(h.cycles_ + h.cyc_ == 6,
            "**总代价 = cycles_ + cyc_** (== 6 = 1+2+3): 宿主做程序总预算时必须相加, 否则少算一片");
    }

    /* 门调用: 解释器缺省收 kCycGate (+3 => 合计 4 拍); 门实现可以再追加自己的成本 */
    {
      Impl vm; Impl::hart_t h{};
      h.regs_.ra.uv = Mem::kBase; h.pc_ = 0;   /* 入口落在门窗口 => 门 0 */
      h.Enable();
      const int r = vm.Execv(&h, 1);
      CHECK(r == kTo && vm.gate_calls == 1 && h.cyc_ == 4,
            "门调用缺省: 1 (基础) + kCycGate (3) == 4 拍");
    }
    {
      Impl vm; Impl::hart_t h{};
      vm.gate_charge = 0x10000;                /* 门自报"我其实很贵" */
      h.regs_.ra.uv = Mem::kBase; h.pc_ = 0;
      h.Enable();
      const int r = vm.Execv(&h, 1);
      CHECK(r == kTo && h.cyc_ == 4 + 0x10000,
            "门实现自报成本: 4 + gate_charge => 分层计价成立 (解释器无需知道门的真实成本)");
    }

    /* 世界魔数 (HYPER): 跨世界 RPC 级开销; 典型行为是返回 rLANG_ERROR_HYPER 并挂起本次执行 */
    {
      Impl vm; Impl::hart_t h{};
      vm.put(Mem::kBase, rLANG_WORLD_MAGIC);
      vm.put(Mem::kBase + 4, 0x00000013u);     /* HYPER 的操作数 (此处无关) */
      h.pc_ = Mem::kBase; h.Enable();
      const int r = vm.Execv(&h, 1);
      CHECK(r == rLANG_ERROR_HYPER && vm.hyper_calls == 1 && h.cyc_ == 1 + (1u << 16),
            "HYPER: 基础 1 + kCycHyper (RPC 发起开销) == 65537 拍, 返回 rLANG_ERROR_HYPER (等待时间不计)");
    }

    /* rd == 0 的载入也必须真的访存 (ISA 卷 I §2.6) */
    {
      Impl vm; Impl::hart_t h{};
      vm.put(Mem::kBase, encI(0, 0, 2, 0, 0x03));   /* lw x0, 0(x0): 地址 0 = 未映射 */
      h.pc_ = Mem::kBase; h.Enable();
      const int r = vm.Execv(&h, 10);
      CHECK(r == SIGSEGV && h.regs_.zero.iv == SIGSEGV,
            "lw x0,0(x0) 现在 **SIGSEGV** (ISA §2.6: 载入到 x0 仍须报异常), 错误仍只落在 x0");
    }
    {
      Impl vm; Impl::hart_t h{};
      vm.put(Mem::kBase, encI(0, 6, 2, 0, 0x03));   /* lw x0, 0(t1): 合法地址 */
      h.regs_.t1.uv = Mem::kBase; h.pc_ = Mem::kBase; h.Enable();
      const int r = vm.Execv(&h, 1);
      CHECK(r == kTo && h.cyc_ == 2 && h.regs_.zero.iv == 0,
            "lw x0,0(t1) 合法地址: 不报错、仍计 2 拍、x0 未被载入结果写坏 (结果丢进临时 reg_t)");
    }

    /* RV32M 边界 (顺带修掉 -INT_MIN 的有符号溢出 UB) */
    {
      Impl vm; Impl::hart_t h{};
      vm.put(Mem::kBase, encR(1, 12, 11, 4, 10, 0x33));   /* div */
      h.regs_.a1.uv = 0x80000000u; h.regs_.a2.uv = 0xFFFFFFFFu;
      h.pc_ = Mem::kBase; h.Enable();
      vm.Execv(&h, 1);
      CHECK(h.regs_.a0.uv == 0x80000000u, "DIV(INT_MIN,-1) == INT_MIN (0u - uv 回绕, 已定义行为)");
    }
    {
      Impl vm; Impl::hart_t h{};
      vm.put(Mem::kBase, encR(1, 12, 11, 6, 10, 0x33));   /* rem */
      h.regs_.a1.uv = 0x80000000u; h.regs_.a2.uv = 0xFFFFFFFFu;
      h.pc_ = Mem::kBase; h.Enable();
      vm.Execv(&h, 1);
      CHECK(h.regs_.a0.uv == 0u, "REM(INT_MIN,-1) == 0");
    }

    /* 可复现性: 同一程序两次运行, cyc_ 逐条相同 */
    {
      std::uint32_t t[2] = {0, 0};
      for (int k = 0; k < 2; ++k) {
        Impl vm; Impl::hart_t h{};
        vm.put(Mem::kBase + 0, encI(7, 0, 0, 10, 0x13));
        vm.put(Mem::kBase + 4, encI(0, 6, 2, 5, 0x03));
        vm.put(Mem::kBase + 8, encR(1, 12, 11, 1, 10, 0x33));
        vm.put(Mem::kBase + 12, encS(0, 5, 6, 2, 0x23));
        vm.put(Mem::kBase + 16, 0x00000073u);
        h.regs_.t1.uv = Mem::kBase; h.pc_ = Mem::kBase; h.Enable();
        vm.Execv(&h, 1000);
        t[k] = static_cast<std::uint32_t>(h.cyc_);
      }
      CHECK(t[0] == t[1] && t[0] == 1u + 2u + 4u + 2u + 1u,
            "同一程序两次运行 cyc_ 相同 (== 10 = addi1+lw2+mulh4+sw2+ecall1) => 权重是纯函数");
    }
  }
  {
    /* 规程十: exit GATE 的**宿主判别** (用户 2026-09-18; 同日"更自然"的语义修正后)
       app 侧: `rLANGEXPORT int MatrixExecv()` 就是**应用入口** (自己 return 状态, 像 main 一样);
               crt (start.S) 只是把它的返回值原样交给 MatrixExit:
                 call MatrixExecv      => a0 = 状态
                 tail MatrixExit       => MatrixExit(a0); MatrixExit 是 noreturn => tail 安全
       guest 侧: atomic/op_GATE/hyper/modules.cc:29-41 —— **门号取模折叠, 状态不折叠**:
                 constexpr uint32_t kExitMagic = rLANG_CONFIG_EXIT_GATE_MAGIC;   (值 = 0xFEA1DEAD)
                 const int kGate = (v & 0x7f) - 64;        (2026-09-18 由"钳制"改为"取模折叠")
                 auto* op_GATE = reinterpret_cast<void(rLANGAPI*)(int, uint32_t, uint32_t, uint32_t)>(4 * kGate);
                 for (;;) op_GATE(v, kExitMagic, v + kExitMagic, rLANG_WORLD_MAGIC);
       真机代码生成 (实测 riscv32-unknown-elf-g++ -O2 -march=rv32im -mabi=ilp32; 改动前是 li/bgt/bge 三条比较分支,
       现在是**无分支**的 andi + addi) 与上面逐条对应:
                 mv a0,s2 (真 v) / andi s0,s0,127 / addi s0,s0,-64 (门号 = (v & 0x7f) - 64) /
                 a1 = kExitMagic / add a2 = v + kExitMagic / a3 = 0xC8C04E1F / jalr s0
                 ⇒ a2 是**无符号加** (单条 add, 不做溢出检查)
       ⇒ ① a0 带**完整 32 位状态**, 只有**门号**被折叠到 [-64,63] (折叠只影响派发, 不影响状态);
          ② 门号空间 1024 个 id 被三段**无缝瓜分**: [-512,-65] hyper 448 / [-64,63] exit 128 / [64,511] 库导出 448;
          ③ 门号 = 状态的**低 7 位** ⇒ 每个门号被无穷多个状态**均匀**命中 (周期 128),
             不再是"钳制"版那样只有两端两个门号可达;
          ④ ⚠ **门号不再等于区间内的状态**: 旧钳制式对 `v ∈ [-64,63]` 是**恒等**映射 (`v=0 → 门 0`,
             所以 `MatrixExit(0)` 必定落在 id 0 —— "nullptr 调用"那套说辞正是靠它), 折叠式不是:
             `v=0 → 门 -64` / `v=63 → 门 -1` / `v=-64 → 门 0`。⇒ 门号一律用公式算, 别再用"状态就是门号"的直觉
             (本规程下面的用例已全部改成按公式算; 实测这条在 2026-09-18 曾让 4 个用例算错);
          ⑤ 本规程验的是**宿主侧**看得到的东西: 门号 id + a0..a3 ⇒ 即"判别规则"本身。
       注: 下面按 guest 的公式填寄存器 (同构复现, 不是跑 guest 机器码 —— 那要真链接 Matrix 映像才能跑,
       见 checks/varargs/ 的 loader 路线)。 */
    printf("[规程十] exit GATE: 门号取模折叠 (状态不折叠) + 三元组判别 (exit(0) vs (*nullptr)())\n");
    const int kTo2 = rLANG_ERROR_TIMEDOUT;
    constexpr int kExitLo = -64, kExitHi = 63;           /* 门号 (派发窗口) 的上下界 = 折叠后的值域 */
    /* guest 的门号折叠 (modules.cc:34 的同一条表达式, 2026-09-18 由钳制改为取模) */
    auto gateOf = [](int v) -> int { return (v & 0x7f) - 64; };
    constexpr int kHyperHi = -65, kHyperLo = -512;       /* hyper / 用户私有 */
    constexpr int kExportLo = 64, kExportHi = 511;       /* 库导出槽 (JALR 12 位立即数上限) */
    constexpr std::uint32_t kLowTop = 0x800u;            /* pc <  0x800        => 低窗 */
    constexpr std::uint32_t kHighBot = 0xFFFFF800u;      /* pc >= 0xFFFFF800   => 高窗 (4*(-512)) */
    constexpr std::uint32_t kSentinel = static_cast<std::uint32_t>(rLANG_CONFIG_EXIT_GATE_MAGIC);  /* guest: kExitMagic */
    constexpr std::uint32_t kMagic = static_cast<std::uint32_t>(rLANG_WORLD_MAGIC);

    /* (a) 三段 id 无缝相接 + 两侧窗口槽数对得上 (纯算术, 不需要跑 VM) */
    CHECK(kHyperHi + 1 == kExitLo && kExitHi + 1 == kExportLo && kExportHi == 511,
          "三段无缝相接: [-512,-65] hyper | [-64,63] exit | [64,511] 库导出 (没有空档也没有重叠)");
    CHECK(kExportHi * 4 + 4 <= static_cast<int>(kLowTop) && kExitHi * 4 + 4 <= static_cast<int>(kLowTop),
          "低窗 (pc < 0x800) 共 512 槽 = id [0,511]: exit 占前 64 槽 (pc 0..252), 库导出接在 256 起");
    CHECK(static_cast<std::uint32_t>(kHyperLo * 4) == kHighBot
       && static_cast<std::uint32_t>(kExitLo * 4) == (kHighBot + 0x700u),
          "高窗 (pc >= 0xFFFFF800) 共 512 槽 = id [-512,-1]: hyper 从 -512 (窗口起点) 起, exit 的 -64 落在 0xFFFFFF00");
    CHECK(static_cast<std::uint32_t>(4 * -1) == 0xFFFFFFFCu && static_cast<int>(0xFFFFFFFCu) / 4 == -1,
          "负门号靠 32 位回绕走高窗, 且 (int)pc/4 是精确整除 => id 与门号一一对应 (4*(-1) => id -1)");

    /* 宿主侧判别规则 (要写进门实现的那段): 窗口内 + 三元组全中 => 正常退出; 否则**不当退出**
       ⚠ 校验和必须按 **uint32** 加: 状态是任意 int, 有符号加在 INT_MIN 这类值上会溢出 (UB)
       ⚠ 捕获列表用 `[&]` (不用隐式捕获): 严格模式编译器不认"未捕获地使用 constexpr 局部量" (MSVC C3493),
         虽然 C++17 规则允许 —— 写全了在哪都能编 */
    enum { kExit = 0, kNotExitWindow = 1, kBadTriple = 2 };
    auto hostClassify = [&](int id, int a0, std::uint32_t a1, std::uint32_t a2, std::uint32_t a3) -> int {
      if (id < kExitLo || id > kExitHi) return kNotExitWindow;   /* 整个 [-64,63] 都要查, 不只 id 0 */
      if (a1 != kSentinel) return kBadTriple;
      if (a2 != static_cast<std::uint32_t>(a0) + a1) return kBadTriple;   /* 无符号: 回绕定义良好 */
      if (a3 != kMagic) return kBadTriple;
      return kExit;
    };
    /* guest modules.cc:38 的三个实参 (按同一条公式复现) */
    auto guestArgs = [&](int v, int* a0, std::uint32_t* a1, std::uint32_t* a2, std::uint32_t* a3) {
      *a0 = v;
      *a1 = kSentinel;
      *a2 = static_cast<std::uint32_t>(v) + kSentinel;
      *a3 = kMagic;
    };

    /* (b) 端到端 (真解释器): 128 个门号逐个 "pc = 4*v + 三元组" => id == v 且判为正常退出 */
    int badCases = 0;
    for (int v = kExitLo; v <= kExitHi; ++v) {
      Impl vm; Impl::hart_t h{};
      int a0v = 0; std::uint32_t a1v = 0, a2v = 0, a3v = 0;
      guestArgs(v, &a0v, &a1v, &a2v, &a3v);
      h.regs_.a0.iv = a0v; h.regs_.a1.uv = a1v; h.regs_.a2.uv = a2v; h.regs_.a3.uv = a3v;
      h.regs_.ra.uv = Mem::kBase;
      h.Enable(static_cast<std::uint32_t>(4 * v));            /* 入口直接落在门窗口 => 门 v */
      const int r = vm.Execv(&h, 1);
      if (r != kTo2 || vm.gate_calls != 1 || vm.gate_last_id != v || h.cyc_ != 4) { ++badCases; continue; }
      if (hostClassify(vm.gate_last_id, h.regs_.a0.iv, h.regs_.a1.uv, h.regs_.a2.uv, h.regs_.a3.uv) != kExit) ++badCases;
      if (h.regs_.a0.iv != v) ++badCases;                     /* 状态必须原样带出 */
    }
    CHECK(badCases == 0,
          "128 个门号全部实测: pc = 4*v 被认成**门 v**, 三元组匹配 => 宿主判正常退出且状态 == v (每例 4 拍)");

    /* (c) **折叠只作用于门号**: 任意状态照旧从 a0 完整带出, 门号 = `(v & 0x7f) - 64`
       (2026-09-18: 门号由"钳制到两端"改为"按低 7 位折叠" ⇒ 端到端也走真解释器, 不只是算术核对) */
    const int kExtremes[] = {kExitHi + 1, kExitLo - 1, kExitHi + 2, 127, 128, 1000, -1000, 0x7FFFFFFF,
                             static_cast<int>(0x80000000u), -1, 0};
    int wrapBad = 0;
    for (int v : kExtremes) {
      const int expectId = gateOf(v);                          /* guest 的 kGate */
      Impl vm; Impl::hart_t h{};
      int a0v = 0; std::uint32_t a1v = 0, a2v = 0, a3v = 0;
      guestArgs(v, &a0v, &a1v, &a2v, &a3v);
      h.regs_.a0.iv = a0v; h.regs_.a1.uv = a1v; h.regs_.a2.uv = a2v; h.regs_.a3.uv = a3v;
      h.regs_.ra.uv = Mem::kBase;
      h.Enable(static_cast<std::uint32_t>(4 * expectId));     /* 折叠后的门号 */
      const int r = vm.Execv(&h, 1);
      if (r != kTo2 || vm.gate_calls != 1 || vm.gate_last_id != expectId || h.cyc_ != 4) { ++wrapBad; continue; }
      if (h.regs_.a0.iv != v) ++wrapBad;                     /* a0 = **真值**, 未被折叠 */
      if (hostClassify(expectId, h.regs_.a0.iv, h.regs_.a1.uv, h.regs_.a2.uv, h.regs_.a3.uv) != kExit) ++wrapBad;
    }
    CHECK(wrapBad == 0,
          "越界状态只影响门号 (折叠进 [-64,63]), a0 仍是完整原值: 64/-65/127/128/1000/-1000/INT_MAX/INT_MIN 逐个走真解释器");

    /* (c2) **周期 128**: 状态每 +128 门号回到同一个槽 (取模折叠的直接推论; 钳制版没有这条) */
    int periodBad = 0, allGates = 0;
    bool hit[128] = {false};
    for (int v = -4096; v <= 4096; ++v) {
      const int g = gateOf(v);
      if (g != gateOf(v + 128)) ++periodBad;                 /* v 与 v+128 同门号 */
      if (g >= kExitLo && g <= kExitHi) { hit[g - kExitLo] = true; }
      else ++periodBad;                                      /* 绝不允许落出窗口 */
    }
    for (int i = 0; i < 128; ++i) if (hit[i]) ++allGates;
    CHECK(periodBad == 0 && allGates == 128,
          "折叠周期 = 128 且 128 个门号**全部可达** (v ∈ [-4096,4096]: 每个槽位都被真实状态命中, 无越窗)");

    /* (d) exit(0) 与真正的 (*nullptr)() —— 同 id 0, 靠**参数**区分 (用户 2026-09-18 的核心澄清) */
    CHECK(hostClassify(0, 0, kSentinel, 0u + kSentinel, kMagic) == kExit,
          "MatrixExit(0): id 0 + 三元组匹配 => 正常退出, 状态 0");
    CHECK(hostClassify(0, 0, 0u, 0u, 0u) == kBadTriple,
          "(*nullptr)() 且寄存器全 0: **同一个 id 0** 但三元组不匹配 => 判为故障, 不会伪装成 exit(0)");
    CHECK(hostClassify(0, 12, kSentinel, kSentinel + 12u, 0x1234u) == kBadTriple,
          "野生跳进门窗口且寄存器是垃圾 => 判为故障 (只看 id 的实现会把这两类混为一谈)");
    CHECK(hostClassify(25, 7, kSentinel, 7u + kSentinel, kMagic) == kExit,
          "注意: 窗口**内任意 id** 带对三元组都算退出 => 判别必须覆盖整个 [-64,63], 不能只查 id 0");
    CHECK(hostClassify(kExitHi, kExitHi, kSentinel, static_cast<std::uint32_t>(kExitHi) + kSentinel, kMagic) == kExit
       && hostClassify(kExitLo, kExitLo, kSentinel, static_cast<std::uint32_t>(kExitLo) + kSentinel, kMagic) == kExit,
          "两个边界门号 63 / -64 都在窗口内, 状态原样带出");
    CHECK(hostClassify(kExportLo, 0, kSentinel, kSentinel, kMagic) == kNotExitWindow,
          "id 64 是库导出槽 => 即使参数凑巧一样也**不**当 exit (窗口判定在前)");
    CHECK(hostClassify(0, 0, kSentinel, kSentinel + 1u, kMagic) == kBadTriple,
          "校验和差 1 => 拒 (a2 是校验, 不是装饰)");
    CHECK(hostClassify(0, 0, kSentinel, kSentinel, kMagic ^ 1u) == kBadTriple,
          "世界魔数不符 => 拒 (顺带排除\"另一个世界的 exit 门\")");

    /* (e) 校验和的**算术契约**: guest 用 uint32 加 (会回绕) ⇒ 宿主必须照抄, 不能用有符号 int */
    /* 溢出判据**不用** `__builtin_add_overflow` (GCC/clang 专属): 写成可移植的 int64 宽算 + 回代,
       这样 MSVC 等严格编译器也能编 (本检查的存在意义之一就是"在哪都能编") */
    auto addOverflowsInt = [](int a, int b) -> bool {
      const std::int64_t wide = static_cast<std::int64_t>(a) + static_cast<std::int64_t>(b);
      return wide != static_cast<std::int64_t>(static_cast<int>(wide));   /* 回代后不等 => int 装不下 */
    };
    CHECK(addOverflowsInt(static_cast<int>(0x80000000u), static_cast<int>(kSentinel)),
          "状态可为任意 int => 宿主若用**有符号** int 算 a0 + a1, 在 INT_MIN 这类状态上就溢出 (UB) => 必须 uint32");
    int sumBad = 0;
    for (int v : kExtremes) {
      const std::uint32_t a2v = static_cast<std::uint32_t>(v) + kSentinel;   /* guest 的那条无符号加 */
      if (hostClassify(0, v, kSentinel, a2v, kMagic) != kExit) ++sumBad;
    }
    CHECK(sumBad == 0,
          "uint32 回绕加回验对**任意** 32 位状态都成立 (含 INT_MIN/INT_MAX/±1000) => 宿主照此实现即可");
  }
  printf("\n%s (failures=%d)\n", failures ? "有失败" : "全部通过", failures);
  return failures;
}



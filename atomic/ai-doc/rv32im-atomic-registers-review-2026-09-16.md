# VM_t 寄存器定义 vs RV32IM / psABI 核对 (2026-09-16)

- **被核对对象**: `atomic/include/rv32im-atomic.hpp` 第 57–95 行 `machine::hyper::VM_t<IMPL>` 的 `reg_t` / `regs_t`。
  核对时点: worktree blob `bb50ded8549eea0118e9c8a445da33289387ac65`, 3391 字节, 140 行, mtime 2026-09-16 17:03 (未 staged; staged 版是 `2ec8c85b…`)。
- **结论未被编译器验证**: 全仓检索确认**没有任何编译单元 include 这个头文件** (`git grep rv32im-atomic` 只命中它自己) ⇒ 文件里的 `rLANG_ABIREQUIRE` 目前形同未启用。见 §5。
- **依据**: RV32I/RV32IM 架构状态 (32 × XLEN=32 通用寄存器、x0 硬连线为 0、pc 独立); psABI v1.0 第 1 章寄存器约定表与第 2.1 节调用约定 (见 §6)。

---

## 1. 一致项 (逐项对照)

| 项 | ISA/ABI 要求 | `VM_t` 现状 | 结论 |
| --- | --- | --- | --- |
| GPR 数量 | RV32I: x0–x31 共 **32** 个 (RV32E 才是 16 个) | `reg_t regs[32]` (74 行) | ✅ |
| GPR 宽度 | XLEN = **32** | `union reg_t { libmb_t uv; libmbi_t iv; }` (68–71 行), `libmb_t=uint32_t` | ✅ |
| ABI 助记符与序号 | x0 zero, x1 ra, x2 sp, x3 gp, x4 tp, x5–x7 t0–t2, x8–x9 s0–s1, x10–x17 a0–a7, x18–x27 s2–s11, x28–x31 t3–t6 | 77–80 行的具名成员**按同一顺序**排列 (`zero, ra, sp, gp, tp, t0, t1, t2 / s0fp, s1, a0…a5 / a6, a7, s2…s7 / s8…s11, t3…t6`) | ✅ 完全一致 (含 x8 的 `s0fp`, psABI 允许 x8 作帧指针) |
| 浮点寄存器 | RV32I **无** F/D ⇒ 无 f0–f31 | 未定义任何 f 寄存器 | ✅ |
| 向量寄存器 | 无 V 扩展 | 未定义 | ✅ |
| M 扩展的架构状态 | `mul/div/rem` 只作用于 x 寄存器, **不引入新架构状态** | 64 位中间量由 `libmb_w_t/libmbi_w_t` (62–63 行) 表达 —— 属**实现**状态, 非架构状态 | ✅ |
| 参数寄存器位置 | 基整数调用约定: "eight argument registers, a0-a7, the first two of which are also used to return values" | 参数覆盖区起点在 `____[10]` 之后 = 第 10 个寄存器 = **a0** (83–94 行) | ✅ |
| 调用约定用到的特殊寄存器 | sp/ra/gp/tp/s0 均在表中且具名 | `sp`/`ra`/`gp`/`tp`/`s0fp` 均具名 | ✅ |

> ⇒ **寄存器本身的"数量/宽度/命名/顺序"与 RV32IM + psABI 一致, 未发现 ISA 层面的错配。**

## 2. 需要处理项 (按严重度)

### 2.1 x0 的"硬连线为 0"没有任何强制 (最高)

ISA 要求 x0 **读恒为 0、写入被丢弃**; psABI 表把 x0 标为 "Zero … —**(Immutable)**"。当前 `regs[0]`/`zero` 是普通可写成员, 类型层面没有任何约束。

为什么在本设计里特别要紧: 门约定是 `jalr id*4(zero)` (130 行), **`jalr` 会把链接地址写进 rd** —— 用 `rd = x0` 正是靠 ISA 的"写 x0 丢弃"规则, 所以实现必须显式丢弃; 一旦误写, 同时会污染参数覆盖区起点 `____[0]`。

建议: 统一经访问器 `RD(i)` / `WR(i, v) { if (i) regs[i] = v; }`, 或在每步之后强制 `regs.zero.uv = 0`, 并在注释里点明"gate 约定依赖 x0 丢弃语义"。

### 2.2 pc 不在 `VM_t` 中

pc 是 RV32I 的架构寄存器 (32 位寻址, IALIGN = 32; `JALR` 会把目标地址 bit0 清 0)。当前只有 `if_CODE(libmb_t pc, libmb_t* op)` (113 行) 把 pc **当参数**传入 ⇒ 隐含"pc 由 IMPL 持有"。

建议: 二选一并在文件里写明 —— 要么把 pc 纳入 `VM_t` (附 4 字节对齐约束), 要么明确写出"pc 属 IMPL 状态"的契约。现在每个实现者都得猜。

### 2.3 CSR / M 态状态缺失是刻意的, 但应写明这是"RV32IM 的子集"

`op_CSRRW/CSRRS/CSRRC/CSRRWI/CSRRSI/CSRRCI → SIGILL`、`op_ECALL() → SIGILL`、`op_EBREAK() → SIGTRAP`、`op_FENCE/op_FENCEI` 为 NOP (116–131 行)。

事实提醒: **2019-12-13 版 ISA 之后 Zicsr 与 Zifencei 已从 base 拆出**, 而工具链的 `rv32i` / `rv32im` 字符串**默认把它们包含进去** (binutils 2.38 / GCC 12.1 起默认采用 20191213 版 ISA 字符串, 见 §6)。因此本设计实际是 "RV32IM **减去** Zicsr (CSR)、Zifencei 语义 (FENCE.I 当 NOP) 与 ECALL/EBREAK"。

建议: (a) 在头文件或 `atomic/README.md` 里把这条偏差写成一句话 (现在只在 README 第 16 行隐含提到); (b) 工具链建好后对 libc/libgcc 的 `.o` 做一次反汇编扫描, 确认没有 `csrr*` / `fence.i` / `ecall` (GCC 在 `__builtin___clear_cache`、个别 TLS/栈保护路径上可能发)。

### 2.4 `____[10]` 与参数覆盖区的布局没有断言

`____[10]` 覆盖 x0–x9 (40 字节), 因此参数覆盖区必须从偏移 40 开始 (= a0 = x10)。含 `real64_t` 使该 union **对齐 8 字节**, 而 40 恰是 8 的倍数 ⇒ 当前布局无填充、位置正确 —— 但这是"恰好", 不是"被断言"。

建议按仓内既有风格 (`Interface/script.h:181` 已有 `rLANG_ABIREQUIRE(offsetof(...))` 先例) 补:

```cpp
rLANG_ABIREQUIRE(sizeof(reg_t) == 4 && sizeof(regs_t) == 128 && alignof(regs_t) == 8);
rLANG_ABIREQUIRE(offsetof(regs_t, a0) == 40 && offsetof(regs_t, u32args) == 40 &&
                 offsetof(regs_t, r64args) == 40 && offsetof(regs_t, u64args) == 40);
```

另: 若 VM 实例像 `Interface/script.h` 那样落在**原始缓冲区**里 (那里是 `data_`/`buffer_` + `static_cast<T*>`), 则寄存器文件的 **8 字节对齐必须由放置方保证** —— 与计划文档 §5 的 TLSF `tlsf_ALIGN_SIZE ≥ 8` 是同一类陷阱。

## 3. 参数覆盖区 (a0–a7) 与 psABI 的差异 (设计选择, 非错误)

- `i32args/u32args/r32args[8]` 与 `i64args/u64args/r64args[4]` 都恰好 32 字节, 全部落在 a0–a7 上 ✅ 位置正确。
- psABI 第 2.1.1 节原文: **命名**参数的 2×XLEN 标量 "are passed in a pair of argument registers, with the low-order XLEN bits in the lower-numbered register" —— **不要求**偶数起始; 只有**变参** "with 2×XLEN-bit alignment … are passed in an **aligned** register pair (i.e., the first register in the pair is even-numbered)"。
  ⇒ `r64args[4]` / `i64args[4]` 只表达 "a0a1, a2a3, a4a5, a6a7 四个对齐对"。要完全对齐 psABI 的话, 该视图**表达不了**两种合法情形: (a) 命名参数中 int 先占 a0, 其后 `double` 从 **a1** 开始; (b) 变参中为满足偶数起始而**跳空** a1。
  ⇒ 需明确: hyper 门的调用约定是否**只允许对齐成对** (即自定义约定)。若是, 建议在头文件里写明 —— 宿主侧 libgcc/libm 实现会受此约束。
- `real32_t` 覆盖在 32 位寄存器上, 与 psABI "浮点类型窄于 XLEN 时加宽到 XLEN、高位未定义"一致; ILP32 **软浮点**下 `double` 走整数寄存器对, 与计划文档 §3 (ilp32 + 软浮点、不接 F/D) 自洽 ⇒ 与本 ABI 的 ILP32F/ILP32D (硬浮点, 参数走 `fa0–fa7`) 无关 ✅。
- **算术异常一律不抛 (用户 2026-09-16 裁定)**: RV32IM 的除零/溢出只有预定义结果、没有异常路径; 浮点即便支持也只置 `NaN`/`INF`。⇒ **`SIGFPE` 不进 ATOMC 世界**; 本节的浮点覆盖层只是**位型搬运**, 与浮点状态寄存器无关。详见 `rv32im-atomic-isa-conformance-2026-09-16.md` §3。
- 返回值: "the first two of which are also used to return values" ⇒ a0/a1 兼任返回 ✅ 无需额外成员。
- 栈 (非寄存器定义, 但门进出必须遵守): psABI 要求过程入口 **sp 16 字节对齐** (128-bit boundary), 栈向低地址增长, 第一个栈上参数在 `sp + 0`, 且"栈上参数按类型对齐与 XLEN 的较大者对齐"。

## 4. 命名与风格 (低风险)

| 观察 | 说明 | 建议 |
| --- | --- | --- |
| 类型名与成员同名 | `regs_t` 的成员也叫 `regs` ⇒ 访问写作 `v.regs.regs[i]` | 改 `xregs_t` + 成员 `x`, 或直接 `reg_t x[32]` |
| `libmb_t` 等 6 个别名 | worktree 全树检索: 只在这个头文件里出现, **不存在与别处宽度不一致**的问题; 反过来说也没有既有命名约定可循 | 若"libm*"有既定含义, 补一行注释解释 b/i/w 的含义 |
| 匿名 struct/union | C++ 非标准扩展, 但**本仓既有先例** (`Interface/script.h:141`、`Interface/secret.cc` 等多处), 且 `base/bits/base.h:14` 已 `#pragma warning(disable : 4996 4127 4201)` (MSVC 的 nameless struct/union 警告) | ✅ 与仓内风格一致, 不构成新问题 (工具链 flag 为 `-Wall` / `-Wall -Werror`, 无 `-Wpedantic`) |
| 编译标准 | `-std=c++17` (`project.local.mk:66/95`, `MCU/project.mk:17`) | —— |

**顺带一个有价值的观察** (`(int)pc / 4`, 130 行): 该转换依赖"无符号→有符号"的**实现定义**行为 (C++17 为实现定义, GCC/MSVC 均为二进制补码回绕; C++20 起为良定义) —— 建议写成显式 `static_cast<int32_t>(pc) / 4` 并加注释。更值得注意的是, 判据窗口 `pc < 0x00000800 || pc >= 0xFFFFF800` **恰好等于** `jalr` 12 位有符号立即数能编码的 id 范围: `imm = id*4 ∈ [-2048, 2044]` ⇒ 低窗 `id 0…511`、高窗 `id −512…−1`, 共 **1024 个门位**; 而 `atomic/README.md` 第 18 行分配的是其中 `0x0000'0100–0x0000'07FF` 与 `0xFFFF'F800–0xFFFF'FEFF`, 未分配的正是 `id 0…63` 与 `id −64…−1` —— 这两段就是**"每次编译都变的随机数"的落点, 即门位（门号）分配** (2026-09-16 收口: 低 64K **未映射、引用必 SIGSEGV**, 那里没有字节可填, 所以随机化不可能是内存内容)。⇒ 判据比分配窗口宽是**刻意为之**, 不是笔误。

## 5. 建议的最小验证 (下一步)

1. **加一个最小编译单元** include 本头文件 (例如 `src/__Testing__/__atomic__/` 或临时 TU), 让 `rLANG_ABIREQUIRE` 与新增布局断言真正参与编译 —— 现在没有任何 TU 引用它。
2. 断言清单: `sizeof(reg_t)==4`、`sizeof(regs_t)==128`、`alignof(regs_t)==8`、`offsetof(regs_t, a0)==40`、三个参数视图同址。
3. **x0 纪律用例**: 一条 `jalr rd=x0` / 一次 `op_GATE` 返回, 断言 x0 仍为 0 且 a0 未被链接地址污染。
4. 工具链就绪后: 对 libc/libgcc 目标文件反汇编扫描 `csrr*` / `fence.i` / `ecall` (见 §2.3)。

## 6. 依据来源

- psABI v1.0 第 1 章寄存器约定表: <https://docs.riscv.org/reference/abi/v1.0/riscv-cc-register-convention.html>
- psABI v1.0 第 2.1 节调用约定 (参数寄存器 / 2×XLEN 寄存器对 / 变参偶数起始 / sp 16 字节对齐): <https://docs.riscv.org/reference/abi/v1.0/riscv-cc-procedure-calling-convention.html>
- 20191213 版 ISA 字符串把部分指令移入扩展、binutils 2.38 / GCC 12.1 起默认: <https://git.kernel.dk/cgit/linux/log/arch/riscv/kernel?h=io_uring-6.6&showmsg=1>
- 仓内参照: `Interface/script.h:141` (匿名 union 先例)、`Interface/script.h:181` (`offsetof` 断言先例)、`base/bits/base.h:14` (MSVC 4201 抑制)、`atomic/README.md` 第 18/20 行、本目录 `atomic-rv32im-toolchain-and-runtime-plan-2026-09-12.md` §3/§5

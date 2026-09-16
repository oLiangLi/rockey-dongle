# rv32im-atomic.hpp 与 RV32IM ISA 一致性核对 (2026-09-16)

- **核对对象**: `atomic/include/rv32im-atomic.hpp` —— 本报告按 **blob** 署名, 因为该头在核对期间持续演进:
  | 版本 | 规模 | 变化 |
  | --- | --- | --- |
  | `bb50ded8` (17:03) | 140 行 | 初版核对 |
  | `c1d921fb` (17:18) | 144 行 | 仅新增 `SIGABRT 6` 的 `#ifndef` 块 (§5 的建议, 已闭环 ✅) |
  | **`473906f8` (18:15)** | 4360 B | 补全 `hyper`/async 注释; **新增 `regs_t regs;` / `libmb_w_t cycles;` / `libmb_t cyc;` / `libmb_t pc;`** 三个成员块; 新增**确定性**与**执行代价**两条契约注释 |
  | `85a2db56` (18:4x) | 162 行 | `op_FENCE()`/`op_FENCEI()` 改为 `{ /* nop */ return 0; }` (修掉 UB ✅) |
  | `a1516e32` | 167 行 / 4600 B | `op_FENCE`/`op_FENCEI` 改成 **`void`** ✅; 引入新类型 **`limb_t`**(未定义) 用于 `mm_*` ⇒ **编不过**; `mm_CHKCS` 补语义注释 ✅ |
  | `41942715` | 167 行 | `limb_t` 误写改回 `libmb_t` ✅ |
  | `246ccf55` | 168 行 | ABIREQUIRE 拆成两行, 第二条比较已加 `(uint32_t)` ✅ |
  | **最新观测** (`bdc6993b`…`e0bb146b`) | 170 行 | 拆成**两条独立** `rLANG_ABIREQUIRE`; 第二条 (`… - rLANG_ERROR_YEILD == 3`) **不报**, 第一条 (`rLANG_WORLD_MAGIC == rLANG_ERROR_HYPER`) **仍报** sign-compare (见 §2.2 与 §6 ① 的原因说明) |

  > ⚠ 该头在核对期间**持续演进** (2026-09-16 当天约每 10 分钟一版), 上表只记关键节点。**最新诊断请直接复跑附录 A 的 TU** (三条命令), 不要依赖表里的行号。

  **`-Wall -Werror` 的 4 处必修缺陷在三个版本上都在**, 只是行号随插入而顺移 (`116/117/134` → `120/121/138` → **`138/139/156`**)。**复跑附录 A 的命令即可对任何后续版本复核。**
  **当前没有任何编译单元引用它** (全仓检索只命中自身) ⇒ 下文的缺陷目前是**潜伏**的, 一旦 ATOMC 世界把它接进构建就会显形。
- **方法**: 不靠逐条推断 —— 在 `%TEMP%` 造一个最小 TU (include 本头, 实例化 `VM_t<Impl>`, 用 `static_assert` 钉住布局与门地址数学, 并逐个调用每个 hook), 用**仓内真实的告警档位**编译:
  `g++ 13.4.0` 与 `clang++ 20.1.8`, `-std=c++17`, `-Wall -Werror`(`Build/config/*.conf` 的实际档位), 另跑 `-Wextra` / `-Wpedantic` 作参考档。
- **结论 (按当前 `41942715` 复核)**: 寄存器与架构状态**一致 ✅**; hook 面分工合理 ✅; 契约方面 `zero` = **`regs.zero` (x0 即错误标志)**, `pc`/`regs`/`cycles`/`cyc` 已落基类, `op_FENCE`/`op_FENCEI` 已按建议改成 **`void`** ✅, `mm_CHKCS` 已补语义注释 ✅, `SIGABRT` 已补 ✅, `SIGFPE` 按裁定不引入。**编译现状: `clang++ -Wall -Werror` 已 rc=0; `g++ -Wall -Werror` 只剩 ABIREQUIRE 的 2 条 `sign-compare` (见 §2.2)**。(上一版的 `limb_t` 未定义系 `libmb_t` 误写, 用户已改回。)

---

## 1. 结论摘要

| 类别 | 项 | 判定 |
| --- | --- | --- |
| 一致 | 32 × 32 位 GPR、ABI 名序、无 F/V 寄存器、M 扩展不引入新架构状态 | ✅ 已**编译验证**: `sizeof(reg_t)=4`、`sizeof(regs_t)=128`、`alignof(regs_t)=8`、`offsetof(regs_t,a0)=40` |
| 一致 | 存取宽度止于 `LW/SW` (无 `LWU/LD/SD` —— 那是 RV64 才有的) | ✅ 正确 |
| 一致 | `if_CODE` 取 32 位指令字 (无 C 扩展 ⇒ 不存在 16/32 位混合) | ✅ |
| 一致 | `FENCE` / `FENCE.I` 当 NOP (单 hart、RAM 不可执行、无 I/O 顺序需求) | ✅ ISA 允许 |
| 刻意偏差 (须写明) | `ECALL → SIGILL`、6 条 `CSR* → SIGILL`、`EBREAK → SIGTRAP`、`FENCE.I` 不实现 | ⚠ 等价于 "RV32IM **减去** Zicsr/Zifencei 与 ECALL/EBREAK"; 而工具链 `-march=rv32im` 默认**包含** Zicsr/Zifencei |
| ✅ **已修复** | `op_FENCE()` / `op_FENCEI()` 无 `return` (UB) | 已按建议改成 **`void`** (`a1516e32`) ⇒ UB 从构造上消失 ✅ |
| ✅ **已修复** | `limb_t` 未声明 (系 `libmb_t` 的**误写**) | 用户已改回 `libmb_t` (`41942715`) ⇒ 6 处 `'limb_t'未声明` 全部消失 ✅ |
| ✅ **已修复** | ABIREQUIRE 里 `uint32_t == int32_t` 的 sign-compare | 用户用 **`^` + `u` 后缀** 改写 (`7ba8a5bd`: `(rLANG_WORLD_MAGIC ^ rLANG_ERROR_HYPER) == 0u` 等) ⇒ **g++ 两个档位都 rc=0** ✅ |
| ❌ **新必修 (只挡 clang)** | `rLANGiOPT` = `__attribute__((optimize("O3")))` 是 **GCC 专属** | clang++ `-Wall -Werror` 报 `unknown attribute 'optimize' ignored [-Werror,-Wunknown-attributes]` (158/175 行) ⇒ 宏需加 `&& !defined(__clang__)` |
| 契约留白 | x0 硬连线、IALIGN=32、JALR bit0、对齐规则、RV32M 边界语义 (共 **5 项**; `pc` 已在 `473906f8` 落进基类) | ⚠ 见 §4 |
| ✅ **已裁定** | **执行/错误契约 = `regs.zero`**: x0 就是错误标志, 只在 `regs.zero == 0` 时循环 | 用户 2026-09-16; 见 §4 第 1、5 条 |
| ✅ 已声明 (`473906f8`) | **确定性契约** (解释/转译必须逐位一致, 以最慢解释器为准) + **执行代价契约** (周期数不得有大偏差) + **async 挂起语义** (`SIGALRM`/`SIGVTALRM` 唤醒) | 见 §4 第 7–9 条 |
| 命名/风格 | `SIGABRT` **已补** (复核版 c1d921fb); `mm_SB/SH/SW` 用 `int32_t`; `mm_CHKCS` 语义未注 | ⚠ 见 §5 (`SIGFPE` **明确不引入** —— 见 §3 裁定) |

## 2. 编译实测证据

### 2.1 全部成立的静态断言 (编译 rc=0 ⇒ 每条都被证明)

```
sizeof(reg_t) == 4                      // XLEN = 32
sizeof(regs_t) == 128                   // 32 × 32 位, 无填充
alignof(regs_t) == 8                    // 起因: real64_t 覆盖层
offsetof(regs_t, a0) == 40              // a0 必须是 x10 (____[10] 之后)
offsetof(regs_t, u32args) == 40 && offsetof(regs_t, r64args) == 40
isGate(0x000) && isGate(0x7FC) && !isGate(0x800) && !isGate(0xFFFFF7FC) && isGate(0xFFFFF800) && isGate(0xFFFFFFFC)
(int32_t)0x000/4 == 0 && (int32_t)0x7FC/4 == 511          // 低窗 id 0…511
(int32_t)0xFFFFF800u/4 == -512 && (int32_t)0xFFFFFFFCu/4 == -1   // 高窗 id -512…-1 (负!)
(int32_t)0x7FC/4*4 <= 2047 && (int32_t)0xFFFFF800u/4*4 >= -2048  // jalr imm 12 位有符号可编码
SIGILL == 4 && SIGSEGV == 11 && SIGTRAP == 5             // 取值与 POSIX 一致
```

### 2.2 编译结果 (当前版 `7ba8a5bd`, 582 行)

| TU | 档位 | g++ 13.4.0 | clang++ 20.1.8 |
| --- | --- | --- | --- |
| **TU-A** (hooks + 布局/ABI 断言, 不调 `Execv`) | `-std=c++17` | **rc=0** ✅ | rc=1 ❌ |
| **TU-A** | `-Wall -Werror` | **rc=0** ✅ | rc=1 ❌ `unknown attribute 'optimize' ignored` |
| **TU-B** (调 `Execv` ⇒ 实例化解释器) | `-std=c++17` | **rc=1** ❌ **122 个错误** | — (同源) |

```
# clang++ 只差这一处 (GCC 专属属性):
rv32im-atomic.hpp:158:3: error: unknown attribute 'optimize' ignored [-Werror,-Wunknown-attributes]
   59 | #define rLANGiOPT __attribute__((optimize("O3")))
# 修法: #if !defined(rLANGiOPT) && defined(__GNUC__) && !defined(__clang__)

# TU-B (g++): 122 个错误, 3 个根因 (全部在"只有实例化才检查"的解释器函数体里)
rv32im-atomic.hpp:178: cannot convert 'reg_t*' to 'regs_t*'      → 下游 68 个 "regs_t has no member 'uv'"
rv32im-atomic.hpp:179: invalid initialization of reference 'libmbi_t&' from 'regs_t'  → 应写 .iv
rv32im-atomic.hpp:232/233/242/243/273: no member named 'pc'; did you mean 'pc_'?      → 5 处
```

⇒ **必须分两个 TU**: TU-A 查接口与布局, **TU-B 必须真的调用 `Execv`** 才能实例化解释器 (否则 122 个错误一个都看不到)。完整问题清单见 `hyper-vm-t-issues-2026-09-16.md`。

**这是现实风险**: `Build/config/arm-none-eabi.conf`、`aarch64-linux.conf`、`cygwin.conf`、`linux.conf`、`wasm.conf` 的档位都是 `X4C_TOOLCHAIN_CXXFLAGS ?= -Wall -Werror`。

### 2.3 参考档 (`-Wextra` / `-Wpedantic`, 仓内未启用)

- `-Wextra`: 7 × `-Wunused-parameter` (`id` / `addr` / `v` …)。默认实现故意忽略参数, 不阻塞; 若将来接 `-Wextra`, 需 `(void)param` 或去参名。
- `-Wpedantic`: 76 / 83 行 "ISO C++ 不允许匿名结构" —— 属**本仓既有风格** (`base/bits/base.h:14` 已 `#pragma warning(disable : 4201)` 抑制 MSVC 的 nameless struct/union, `Interface/script.h:141` 等处同样在用), 不阻塞; 134 行另有 "variadic macro 至少一个 `...` 实参" 的形式化告警(单参调用 `rLANG_ABIREQUIRE(expr)`), 无害。

## 3. 与 RV32IM 逐组对照 (含 `SIGSEGV` 的性质辨析)

| RV32IM 组成 | 本头文件的对应物 | 说明 |
| --- | --- | --- |
| LUI/AUIPC/JAL/JALR/分支/ALU 立即数与寄存器型 | **无 hook** | 纯函数, 由 IMPL 直接算; 不需要宿主介入 ✅ 合理 |
| Load: LB/LBU/LH/LHU/LW | `mm_LB/mm_LBU/mm_LH/mm_LHU/mm_LW` (+ 宿主侧 `mm_CHKRO`/`mm_CHKWR` 的地址解析与权限检查) | ✅ 覆盖 RV32I 全部宽度, 无多无少 |
| Store: SB/SH/SW | `mm_SB/mm_SH/mm_SW` | ✅ |
| FENCE / FENCE.I | `op_FENCE` / `op_FENCEI` (NOP) | ✅ 单 hart 下合法 |
| ECALL / EBREAK | `op_ECALL`(SIGILL) / `op_EBREAK`(SIGTRAP) | ⚠ 刻意不支持 ECALL (与"地址窗口门"裁定一致) |
| Zicsr: CSRRW/CSRRS/CSRRC/CSRRWI/CSRRSI/CSRRCI | `op_CSR*`(SIGILL) | ⚠ 刻意不支持 |
| RV32M: MUL/MULH/MULHSU/MULHU/DIV/DIVU/REM/REMU | **无 hook** | 由 IMPL 实现; **必须遵守 4 条边界语义** (见下) |
| 指令取指 | `if_CODE(pc, &op)` | 32 位取指 ✅ |
| — (非 ISA) | `op_GATE(id)` | 属**世界约定**, 不是 RV32IM; 注释已标注 |

**RV32M 的 4 条边界语义 (IMPL 必须遵守, 全部"不陷入")**: `DIV/0 = -1`(0xFFFF'FFFF)、`DIVU/0 = 0xFFFF'FFFF`、`REM/REMU 除数为 0 = 被除数`、`DIV(INT_MIN, -1) = INT_MIN` 且 `REM(INT_MIN, -1) = 0`。

**算术异常一律不抛 (用户 2026-09-16 裁定; 与上面 4 条边界语义一致, 是本节的权威结论)**:

- RV32IM 的除零与有符号溢出**没有异常路径** —— 除零产出**预定义值**, 溢出产出**定义值**; 因此 **`SIGFPE` 在 ATOMC 世界没有位置, 不得引入** (本报告初版"补 `SIGFPE(8)`"的建议**据此作废**)。
- **浮点**: 本阶段不支持 (`libm` 不接、无 F/D 扩展); **即使将来支持, 也只把结果置为 `NaN`/`INF`, 不抛异常**。
- 推论 1 (勿照抄): `Interface/script.cc:1526` 与 `:1651` 把"除数为 0 **或** `INT_MIN ÷ -1`"记为 `zero_ = SIGFPE` —— 那是 **script VM 的自定义操作码语义**, 既不是 RV32M, 也**与 ATOMC 的裁定相反**。
- 推论 2 (风险解除): 计划文档 §3 第 4 条担心的 musl `src/fenv`(该 pin 不含 2026-03-20 的 riscv32 软浮点修正, 实现走 CSR)在本裁定下**不构成风险** —— 浮点由**宿主侧** libm 承担 (调用门在 HOST 端实现, 见 `atomic/README.md` 第 19 行), guest 只搬 32/64 位位型, 不执行 `frcsr`/`fscsr`; 只有把 libm 链进 guest 映像时那条担心才成立。
- 推论 3: 因此 `regs_t` 的 `r32args`/`r64args` 是**纯位型搬运**视图 (`float` 单个 32 位寄存器、`double` 一对, ilp32 软浮点), 与任何浮点状态寄存器无关。
- 推论 4 (ATOMC 的终止信号面因此收敛): `SIGILL`(非法指令 / 未实现的 CSR 与 ECALL)、`SIGSEGV`(访存 / 取指 / 未对齐)、`SIGTRAP`(EBREAK)、`SIGABRT`(内部不变量 / 未初始化), 外加 `hyper` 的 `rLANG_ERROR_HYPER` / `rLANG_ERROR_YEILD`。**算术问题不得用信号表达**。**预算/超时**照同仓惯例走**负 errno** (`script.cc:1425 zero_ = -ETIMEDOUT`), **不是** `SIGALRM`/`SIGVTALRM` —— 本头定义的 `SIGALRM`/`SIGVTALRM` 的用途已由用户在 `473906f8` 的注释里明确: **异步唤醒信号** (async.wait / async.ZION.execv, 见 §4 第 9 条), 与预算耗尽无关。`zero` 的完整契约见 §4 第 5 条。

**门地址数学 (已编译期验证, 与 ISA 自洽)**: 判据 `pc < 0x00000800 || pc >= 0xFFFFF800` **恰好等于** `jalr` 12 位有符号立即数能编码的 `id = (int)pc / 4` 范围 —— 低窗 `id 0…511` (`imm = id*4 ∈ [0, 2044]`)、高窗 `id -512…-1` (`imm ∈ [-2048, -4]`), 共 **1024 个门位**; `atomic/README.md` 第 18 行分配的是其中 `0x0000'0100–0x0000'07FF` 与 `0xFFFF'F800–0xFFFF'FEFF`, 未分配的 `id 0…63` (地址 `0x000–0x0FC`) 与 `id -64…-1` (地址 `0xFFFFFF00` 附近) 就是**"每次编译都变的随机数"的落点 —— 是门位（门号）分配, 不是内存内容** (2026-09-16 收口: 低 64K **未映射、引用必 SIGSEGV**, 无字节可填) ⇒ 判据比分配窗口宽是**刻意为之**。
> **两个门窗口都在未映射区** ⇒ 数据访问一律 fault、作为 `pc` 由 VM 取指前拦截 ⇒ **"门只可执行、不可读"由映射白拿** (不需要 U 模式/PMP; 计划文档 §4.3 的结论被取代; 同一地址的双重身份见 `checks/interpreter-smoke.cc` 规程六)。
> **建议**: 把判据与 id 推导**放进头文件** (例如 `static constexpr bool is_gate(libmb_t pc)` 与 `gate_id(pc)`), 免得每个 IMPL 各写一份; 上述等价关系可直接写成 `rLANG_ABIREQUIRE`。

**`SIGSEGV` 的性质: 宿主约定, 不是 ISA 行为 (用户 2026-09-16 提问, 结论如下)**:

- **正常 RISC-V 实现不会"触发 SIGSEGV"** —— 不可访问地址触发的是**同步异常 (trap)**: 硬件把原因写进 `mcause` 并按 `mtvec` 跳转。规范 Exception Code (interrupt=0) 取值: `0` 取指地址未对齐、`1` 取指访问错误、`2` 非法指令、`3` breakpoint、`4` 载入地址未对齐、`5` 载入访问错误、`6` 存储/AMO 地址未对齐、`7` 存储/AMO 访问错误、`8`/`9`/`11` U/S/M 模式 ecall、`12` 取指缺页、`13` 载入缺页、`15` 存储/AMO 缺页。(原文取自 `riscv-isa-manual` 的 `src/machine.adoc` mcause 表: <https://raw.githubusercontent.com/riscv/riscv-isa-manual/080ef752e9e8aa437fc0aa2909ed3a88a4179462/src/machine.adoc>)
- **`SIGSEGV` 是 OS/宿主层**把"无法解决的 page fault"(`mcause` 13/15) 翻译给用户进程的 POSIX 信号; 未对齐访问在 RISC-V Linux 上通常由内核**模拟**(不发信号), 非法指令 → `SIGILL`、断点 → `SIGTRAP`、**整数除零不发任何信号**。
- ⇒ 在本设计 (M-only、无 trap 机制) 里, `mm_*` / `if_CODE` 返回 `SIGSEGV` 是**宿主层约定**, 相当于把 `mcause` 的 `1/5/7/12/13/15` 折叠成一个宿主信号号。这与仓内既有惯例一致 (`Interface/script.cc` 的 `LoadMM`/`StoreMM`: 越界或未对齐即 `zero_ = SIGSEGV`; 计划文档 §4.2 亦点名"对齐 `VM_t::zero_ = SIGSEGV` 那种语义")。
- 若要更贴 ISA, 可把 `regs.zero` 的取值改用 `mcause` 编号, 但那会与仓内既有的 `SIG*` 约定冲突 ⇒ **建议保持 `SIGSEGV`**, 只需在头文件里加一句"这是宿主约定, 不是 ISA 语义"。

## 4. 语义契约 (第 1/5 条已裁定为 `regs.zero`; 第 7–9 条已由用户写入头文件; 其余待补)

1. ✅ **x0 的双重身份 (用户 2026-09-16: `while (regs.zero == 0)`)**: x0 既是 ISA 的硬连线零寄存器, **又是执行循环的错误标志** —— `regs.zero == 0` 才继续, 非 0 即"最后一次错误码"并退出。⇒ 这使 x0 成为**承重结构**, 三条纪律必须写明:
   - **写 x0 必须丢弃**: 任何指令写入 x0 (含 `jalr rd=x0` 的链接写入) **不得**改变 `regs.zero`, 否则程序能破坏错误通道;
   - **错误码只由宿主/hook 侧写**: 例如 `return regs.zero = SIGSEGV;` (即 `dongle.script` 的"赋值兼返回"惯例);
   - **清零时机**: 初始化时 x0 = 0 (开始执行); 若 `regs.zero` 被写成 `rLANG_ERROR_HYPER`/`rLANG_ERROR_YEILD`, 那是**可恢复挂起** (async, 见第 9 条) —— 宿主决定恢复时必须**先清 x0**, 其余非 0 值一律视为终止。
   附: 32 位足以容纳 `SIG*` (小正数)、`-errno` 与 `0xC8C04E1F`; `regs.zero` 与参数覆盖区的 `____[0]` 是同一 4 字节 (本就重叠, 无碍)。
2. ⚠ **`pc` 已落进 `VM_t`** (`libmb_t pc;`, 复核版 `473906f8`; `if_CODE(libmb_t pc, ...)` 仍是取指接口) —— 但 **IALIGN = 32** (无 C 扩展 ⇒ pc 必为 4 的倍数) 仍是隐含约定, 建议写明。`pc` 与 `regs` / `cycles` / `cyc` 现已都是 `protected` 成员。
3. **JALR 语义**: 目标地址 `(rs1 + imm) & ~1` (清 bit0), 且 `rd` 写入 `pc+4`。
4. **对齐规则**: 仓内既有惯例是**未对齐访问 ⇒ SIGSEGV** (`Interface/script.cc` 的 `LoadMM<T>`/`StoreMM<T>`: `addr % sizeof(T) != 0` 即置 `SIGSEGV`); 本头的 `mm_*` 未声明谁负责检查, 建议写明"由 IMPL 检查并对齐到 2/4 字节"。
5. ✅ **执行循环与 `zero` 契约 (用户 2026-09-16 裁定; 与同仓 `dongle.script` 同构)** —— **本项已定, 是下面唯一有权威结论的条目**:
   - **循环**: `while (zero == 0) { ... }`; 只要 `zero != 0` **立刻退出** ⇒ `zero` 实质是**错误标志** (因立即退出, 记下的就是第一个/最后一个错误); **只有全程无错, 程序才继续运行/正常结束**。
   - **取值**: `0` = 无错误 (唯一继续条件); **正数** = `SIG*` (`SIGILL` / `SIGSEGV` / `SIGTRAP` / `SIGABRT`); **负数** = `-errno` (`-ENOSYS` / `-ETIMEDOUT` / `-EACCES` / `-EINVAL` …)。
   - **初值必须非 0**: 同仓 `Interface/script.h:152` 是 `int zero_ = SIGABRT;`, 只有 `Initialize()` 成功才 `return zero_ = 0;` (`script.cc:42`) ⇒ 防止"未初始化就被当成成功"。
   - **正常出口不改 `zero`**: `script.cc:1421-1422` 跑到 `pc_ == kSizeCode` 只是 `break` ⇒ `zero` 保持 0 = 成功; 预算耗尽 `zero_ = -ETIMEDOUT` (`:1424-1426`)、取指越界 `zero_ = SIGILL` (`:1428-1430`)。
   - **宿主就是读它**: `Execute()` 的返回值即 `zero` (`script.cc:1784 return zero_;`), 调用方 `src/app/main.cc:92 result = vm.Execute();`; 测试按 `0 == vm.zero_` / `0 != vm.zero_` 判成败 (`src/__Testing__/__rsamodexpvm__`、`__chachapolyvm__`)。
   - **失败即清输出**: `script.cc:1773-1774` 在 `zero` 非 0 时 `memset(data_, 0, kSizeData)` —— 防"未写完的产物被当成已生成"。
   - **hook 惯例是"赋值兼返回"**: `return zero_ = SIGSEGV;` (`script.cc` 与 `execute.cc` 里数十处)。
   - ✅ **缺口已闭合 (用户 2026-09-16)**: 不需要新增 `zero` 成员 —— **`zero` 就是 `regs.zero` (x0)**, 循环写作 `while (regs.zero == 0)`, 见第 1 条。因此本头的 hook 只需把错误写进 `regs.zero` (惯例: `return regs.zero = SIGSEGV;`)。⚠ 仍需明确: **初值**是否也沿用 `SIGABRT` (防"未初始化即成功") —— `dongle.script` 是 `int zero_ = SIGABRT;`, 而 ATOMC 的 `regs` 是聚合成员, 需要一个初始化点把它设成非 0。
   - 附注: LIMIT 侧还会在失败时把诊断位域**打包进 `zero`** (`script.cc:1778`: 低 16 位错误码 | 栈深 `<<16` | pc `<<22` | bit30), 且**负 errno 会被 `& 0xFFFF` 截成 16 位无符号**; ATOMC 是否沿用该打包需单独定。
6. **软浮点/参数覆盖层**: `regs_t` 的 `i32args/u32args/r32args/i64args/u64args/r64args` 是 **hyper 门的调用约定**, 不是 ISA 架构状态; `real32_t/real64_t` 只在 ilp32 软浮点下成立 (硬浮点 ILP32F/ILP32D 会用 `fa0–fa7`, 本设计不适用); psABI 还要求过程入口 **sp 16 字节对齐**。
7. ✅ **确定性契约 (用户 2026-09-16, 已写入头文件 `473906f8`)**: 「**所有的实现路径(解释、转译等)必须确定性地在执行到相同位置时返回完全相同的结果**; 如果有差异, **以我们性能最低的解释器的结果为准**(特别是严格模式下)」。⇒ 这把"解释器 = 参照实现"钉死了: 转译执行、JS/模拟器实现都必须与它**逐位一致**; 与 §3 的门地址窗口、以及 mock 的计时行为直接相关。
8. ✅ **执行代价契约 (已写入)**: 「**对于执行程序的代价(以花费的时钟周期计算)应该尽量与解释器下的结果相同, 不应该出现过于大的偏差**」; 注释另记「通常我们 mock 的输入按 **1 周期 == 1 纳秒** 标定(1GHZ), 但 `SIGALRM` 不受此限制」。⚠ 尚需注释: `libmb_w_t cycles;`(64 位) 与 `libmb_t cyc;`(32 位) 的分工 (总预算 vs 已耗计数?) 及耗尽时如何落到 `zero` (同仓是 `zero_ = -ETIMEDOUT`, 见第 5 条)。
9. ✅ **异步挂起/唤醒语义 (已写入注释)**: `rLANG_ERROR_HYPER` = 「async.ZION.execv, **标志主消息循环发起了一次异步过程调用**; 程序在下一个 `SIGALRM`/`SIGVTALRM` 信号到达之前会被一直挂起」; `rLANG_ERROR_YEILD` = 「async.wait, **标志主消息循环放弃剩下的处理器时间**(a0 指示其周期数); 在下一次 `SIGALRM`/`SIGVTALRM` 或者 a0 指示的超时时间之前, 程序被挂起」。⇒ **`SIGALRM`/`SIGVTALRM` 的用途至此明确: 异步唤醒信号** (不是预算耗尽)。这也解释了头文件为何要自带这两个信号的取值。

## 5. 命名与风格

| 观察 | 说明 | 建议 |
| --- | --- | --- |
| SIG 集合 | 本头现有 `SIGQUIT(3)/SIGILL(4)/SIGTRAP(5)/SIGABRT(6)/SIGKILL(9)/SIGSEGV(11)/SIGALRM(14)/SIGVTALRM(26)` —— **`SIGABRT` 已于复核版 (17:18) 补上 ✅**, 手法与 `Interface/script.h:28–34` 一致 | **`SIGFPE` 明确不要引入** (见 §3 裁定) |
| 存取签名不对称 | `mm_SB/SH/SW(libmb_t, **int32_t**)` vs `mm_LB…/mm_LW(libmb_t, **reg_t***)`; 把 `reg_t` 当 `int32_t` 传时, > `INT32_MAX` 的位型转换在 C++17 属**实现定义** | 统一用 `reg_t`(或 `libmb_t`) |
| ✅ `mm_CHKCS` 语义**已补注释** (`a1516e32`) | 现在写明: 返回**一个 VM 内的字符串**, `lenIf` 非空时同时给出长度; 且 `.text`/`.rodata`/`.data`/`.bss` 末尾会自动补全 0 的 **guard-page**, 因此**不必担心字符串没有 NUL 结尾** | 仅剩 `limb_t` 需定义 (见 §2.2); 该 guard-page 约定值得在 `atomic/README.md` 也记一句 |
| 存取签名仍不对称 | `mm_SB/SH/SW(libmb_t, **limb_t**)` vs `mm_LB…/mm_LW(libmb_t, **reg_t***)` —— 由 `int32_t` 改成 `limb_t` 后**仍不对称**, 且 `limb_t` 尚未定义 | 若 `limb_t` 意在"32 位 limb", 它应等于 `libmb_t`; 建议存/取两侧统一 (`reg_t` 或都用 `libmb_t`) 并在注释里说明为何不用 `reg_t` |
| hook 返回类型不再统一 | `op_FENCE`/`op_FENCEI` 现为 **`void`**, 其余 hook 为 `int` | 用 switch 派发零代价; 若用统一的 `int (VM_t::*)()` 表则需要一层包装 (见 §6 ③) |
| 宏位置 | `#ifndef SIG*` 那一簇夹在 `rLANG_DECLARE_MACHINE`(打开 `namespace machine {`) 与 `namespace hyper {` 之间 —— 宏不受命名空间影响, 无害, 但易误读 | 移到 `rLANG_DECLARE_MACHINE` **之前** |
| hook 名无先例 | `mm_*` / `if_CODE` / `op_GATE` 全仓只有本头文件命中; 兄弟 VM 用的是 `OpCheckMM` / `LoadMM<T>` / `StoreMM<T>` / `zero_` | 两套命名并存, 建议注明关系或后续统一 |
| 成员命名风格 | 本头用**无下划线**的 `regs` / `pc` / `cycles` / `cyc`; 同仓 `dongle.script` 用**带下划线**的 `zero_` / `pc_` / `cycles_` / `nstk_` | 两套风格并存 ⇒ 若之后补 `zero`, 建议跟随本头风格 (用户原话也写作 `VM.zero`), 并在头里点明 |
| include | `#include <base/base.h>` 与仓内 23 处写法一致 ✅; `base.h` 自带 `<stdint.h>` / `<stddef.h>` / `<signal.h>` (`base.h:75–87`) ⇒ 本头自足 ✅ | — |

## 6. 建议的修复 (接口/布局档已干净; 剩 clang 属性 1 处 + 解释器 3 个根因)

```cpp
// ① ✅ 已完成 (7ba8a5bd): ABIREQUIRE 的 sign-compare 已用 "^" + "u" 后缀改写 ⇒ g++ -Wall -Werror rc=0
// ② ❌ 只挡 clang (一处宏改): rLANGiOPT 用的 optimize 属性是 GCC 专属
#if !defined(rLANGiOPT) && defined(__GNUC__) && !defined(__clang__)
#define rLANGiOPT __attribute__((optimize("O3")))
#elif !defined(rLANGiOPT)
#define rLANGiOPT
#endif
// ③ ❌ 解释器 3 个根因 (g++ 报 122 个错误): 178 行 regs_t* → reg_t*;
//    179 行 hart_->regs_.zero → hart_->regs_.zero.iv; 232/233/242/243/273 行 hart_->pc → hart_->pc_
//    —— 完整清单见 hyper-vm-t-issues-2026-09-16.md §1 (TU 里必须真的调用 Execv 才会暴露)
// ④ ✅ 已完成: op_FENCE/op_FENCEI → void (a1516e32); mm_CHKCS 注释 (a1516e32);
//    SIGABRT(6) (c1d921fb); limb_t 误写回改 (41942715)
```

> 本次**未改动该头文件** —— 按既有约定, `atomic/` 下只写 `ai-doc/`。

## 7. 依据

- 实测命令 (可复现): `g++ -std=c++17 -Wall -Werror -fsyntax-only -I <ATOMIC> -I <ATOMIC>/atomic/include <TU>`; `clang++` 同理。编译器: g++ 13.4.0 (cygwin), clang++ 20.1.8。
- 仓内: `Build/config/{arm-none-eabi,aarch64-linux,cygwin,linux,wasm}.conf` (门禁档位 `-Wall -Werror`); `Interface/script.h:28–34,141,152`; `Interface/script.cc:1526–1527,1651`; `base/bits/base.h:14,17–29,75–87`; `atomic/README.md:18,20`。
- ISA: RV32I 架构状态 (32×XLEN、x0 硬连线、pc、IALIGN) 与 RV32M 的除零/溢出边界语义; `jalr` 的 12 位有符号立即数与目标地址 `& ~1`。
- 本目录 `rv32im-atomic-registers-review-2026-09-16.md` (寄存器与 psABI 那一半的核对)。

## 8. 离线依据: `atomic/doc/riscv-spec.pdf` 已升级到 Volume I **v20260120** (2026-09-16)

**用户提问**: 这份 PDF 的 RV32IM 用户态内容是否与最新文档一致? 若一致, 以后就不必总联网查。
**结论**: 对 **RV32IM 用户态语义完全一致** (逐条核对见 8.1); 并按用户指示**已把文件升级到最新稳定版**。

- **原文件**: Volume I Unprivileged **20191213** —— 1,021,610 B, sha256 `F392624CC815CD3F259413CBD9AE2F38678EE930878855A0F4673019410D7554` (2019-12-13 ratified 版, pdfTeX 生成)。
- **现文件**: Volume I Unprivileged **Version 20260120** (Ratified) —— **4,580,174 B**, sha256 `06BB3C23074F72060A0EC061A80933AF948CAE7CEAFDCD9D1FE177B05FD150BC`, 取自
  <https://docs.riscv.org/reference/isa/v20260120/_attachments/riscv-unprivileged.pdf>。
  **依据**: docs.riscv.org 的 v20250508 页面明确标注 "For the latest stable version, please use ISA Specifications **20260120**" ⇒ 20250508 已非最新。
- **回退方式**: 旧版仍在 git 索引里 (`git show :atomic/doc/riscv-spec.pdf > old.pdf`, 旧 blob `533c1cbf9168f6b879f0f7143a78cdce00c0a2ae`), 另在临时目录留了一份备份。
- ⚠ **覆盖后该文件在 git 里是 `AM`** (已 stage 的是旧版) ⇒ 需要 `git add` 才会把新版入库。

### 8.1 逐条核对 (提取两版 PDF 文本后做的规范性断言比对)

| 规范性事实 | 20191213 | 20250508 | 20260120 |
| --- | --- | --- | --- |
| `x0` hardwired to 0 | ✓ | ✓ | ✓ |
| "For RV32I, the 32 x registers are each 32 bits wide, i.e., XLEN=32" | ✓ | ✓ | ✓ |
| 除零: 商全 1, 余数 = 被除数 | ✓ | ✓ | ✓ |
| 有符号溢出只有 `most-negative / -1` 一种 | ✓ | ✓\* | ✓ |
| 溢出: 商 = 被除数, 余数 = 0 | ✓ | ✓ | ✓ |
| 无符号除法不会溢出 | ✓ | ✓ | ✓ |
| 允许未对齐访问报 access-fault / 可见 trap | ✓ (旧措辞 "access exceptions") | ✓ | ✓ |
| FENCE.I 移出 base, 归 Zifencei | ✓ | ✓ | ✓ |
| 调用约定: x1 返回地址 / x5 备用链接 / x2 栈指针 | ✓ | ✓ | ✓ |
| ECALL / EBREAK (Environment Call and Breakpoints) | ✓ | ✓ | ✓ |

\* 20250508 那处在文本抽取时丢了 `−1` 的字形 (改由 Asciidoctor 生成后 U+2212 未被映射), 原文仍在。

**差异全部属于"编号 / 排版 / 其它扩展", 不含 RV32IM 用户态语义**:
- **章节与表格重编号**: M 扩展除零语义表 `Table 7.1` → **`Table 11`**; RV32I 由 "Chapter 2" → "Chapter 1"。
- **排版**: LaTeX(pdfTeX) → Asciidoctor; 项目符号 `•`→`⚫`, 断词连字符与 `−` 字形不同。
- **新增/扩写的是其它扩展** (A 2.1、Zacas、Zabha、Zawrs、Zimop、Zcmop、B、V、加密、CFI…), 与本世界无关。
- 新版修订历史里涉及 base 的实质条目, 都是 **20191213 之前**就完成的 (FENCE.I/CSR/计数器移出 base、未对齐描述更改)。

### 8.2 离线结论的边界 (重要)

- 这份 PDF 是 **Volume I (Unprivileged)**: **不含** `mcause`/trap/CSR 等特权语义 (那是 Volume II: Privileged), 也不含**调用约定/ABI** (独立文档 `riscv-elf-psabi-doc`)。⇒ 这两类事实仍需联网或查各自文档 (§3 的 `mcause` 表、以及 `rv32im-atomic-registers-review-2026-09-16.md` 的 psABI 核对即来自它们)。
- 除上述边界外, **RV32IM 用户态 (指令语义、寄存器/XLEN、M 扩展边界、Zicsr/Zifencei 归属) 自 20191213 起无实质变化** ⇒ 以后这类核对**可直接离线**用 `atomic/doc/riscv-spec.pdf` (v20260120), **不必联网**。

## 9. 最小检查环境 (抓"简单错误"用的那套)

用户 2026-09-16: "我先建个能检查简单错误的环境"。下面就是本报告全程使用的检查法, **已实测能抓住** `limb_t` 误写 (6 处 `'limb_t'未声明`)、`op_FENCE`/`op_FENCEI` 缺 `return`、ABIREQUIRE 的 sign-compare, 以及布局/ABI 漂移。

**一个 TU (见附录 A) + 三条命令**:

```sh
g++     -std=c++17              -fsyntax-only -I <ATOMIC> -I <ATOMIC>/atomic/include tu.cc  # 静态断言: 布局/ABI/门窗口/信号值
clang++ -std=c++17 -Wall -Werror -fsyntax-only -I <ATOMIC> -I <ATOMIC>/atomic/include tu.cc  # clang 档
g++     -std=c++17 -Wall -Werror -fsyntax-only -I <ATOMIC> -I <ATOMIC>/atomic/include tu.cc  # 仓内门禁档 (最严)
```

**能抓住**: ① 未声明的类型与拼写错误 (`limb_t`); ② 非 void 函数漏 `return` (UB); ③ `-Wall` 类告警 (sign-compare…); ④ `sizeof`/`offsetof`/`alignof` 的布局与 ABI 漂移 (动 `regs_t` 立刻红); ⑤ 门窗口与 `jalr` 12 位立即数的等价关系; ⑥ `SIG*` 取值。
**抓不住**: 语义错误 (x0 是否真被丢弃、`regs.zero` 的循环、RV32M 边界值) —— 那需要能跑的解释器与用例。

**建议落点 (仓内惯用法)**: `src/__Testing__/__atomic__/{xModule.mk,main.cc}` (与 `__rsamodexpvm__` / `__chachapolyvm__` 同构) + 一个 `make` 目标; 轻量替代是放进 `tools/rockey/LIMIT/sbin/` 式的脚本。
⚠ 我目前的写盘范围只到 `atomic/ai-doc/`, 所以**没有**把它放进 `src/`; 需要的话我可以把它写成 `atomic/ai-doc/checks/` 下的文件, 或由你授权写到 `src/`。

## 10. 补充 (2026-09-16 晚): 基类已自带解释器

- 头文件已从"hook 骨架"长成**含完整 RV32IM 解释器** (`hart_t` 状态 + `inner_Execv` 循环 + 指令解码) ⇒ 本报告 §3/§4 里若干"由 IMPL 实现"的项 —— **RV32M 边界语义、x0 写入守卫、JALR 语义、立即数抽取、编码判定** —— 现在**由基类实现, 且经逐条文本核对正确**。
- 随之而来的一批**新问题** (编译阻断与契约缺口) 见 **`hyper-vm-t-issues-2026-09-16.md`**: 共 **122 个编译错误 / 3 个根因**, 另有 9 条 P0 语义契约问题。
- ⚠ 检查方式随之变化: 解释器是模板成员函数, **只有 TU 里真的调用 `Execv` 才会实例化并暴露其中的错误** —— 只 include 或只调 hook 的 TU 看不见 (附录 A 的 TU 需按此升级)。

## 11. ⚠ 二次核对新增发现 (2026-09-16, 读周期计价时顺带): 载入到 `x0` + `DIV` 的 UB

### 11.1 **`rd == 0` 的载入被整体跳过 ⇒ 违反 ISA 卷 I §2.6** (确认; ✅ **已修** blob `bf3d9f5a`)

**规范原文** (本次从离线 PDF = Volume I **v20260120** 提取, "2.6. Load and Store Instructions", p.33):

> "The EEI will define what portions of the address space are legal to access with which instructions (e.g., some addresses might be read only, or support word access only). **Loads with a destination of x0 must still raise any exceptions and cause any other side effects even though the load value is discarded.**"

这是**规范性 "must"**。而 `rv32im-atomic.hpp` 的载入分支是:

```cpp
case 0x03 >> 2:  // LB, LH, LW, LBU, LHU
  rd = rlRD(op);
  if (0 != rd) {            // ← rd == 0 时连 mm_L* 都不调用: 不访存、不报错、无副作用
    ...
  }
```

**对照实验** (同一未映射地址 `0`, 只有 `rd` 不同; 落地前在真头 blob `e1aaa777` 上实测 —— 该探针资产随提案原型目录一起删除了, 修复后的断言见**规程九 ⑥**):

| 指令 | 结果 | 应该 |
| --- | --- | --- |
| `lw t0, 0(x0)` (rd=5) | `rc = SIGSEGV` (11) | ✅ 一致 |
| `lw x0, 0(x0)` (rd=0) | `rc = TIMEDOUT` —— **静默"成功"** | ❌ 必须同样 `SIGSEGV` |
| `lb x0, 0(x0)` / `lbu x0, 0(x0)` | `rc = TIMEDOUT` | ❌ 同上 |

**为什么会有这段 `if`**: 落点不能写 `regs[0]` —— **`x0` 是执行循环的错误通道** (`while (regs.zero == 0)`), 写它就会破坏错误传递。所以正确修法不是删 `if`, 而是**照常访问 + 把结果丢进临时寄存器**:

```cpp
reg_t dummy;
reg_t* const dst = rd ? &regs[rd] : &dummy;   // rd == 0 也必须真的访问 (ISA §2.6)
... Self()->mm_LB(addr, dst) ...
```

**影响**: ① 不符合 ISA; ② 与本仓自身取向冲突 (`mm_CHKWR/CHKRO/CHKCS` 连 `size == 0` 都拒绝非法地址 —— 都是 fail-closed); ③ ISA 特意保证 `lw x0` 可当**可访问性探针**, 现在这个探针失效; ④ 在最终内存映射下 `lb x0, 0` 对未映射区不报错, 少了一层护栏。
**状态**: ✅ **已修 (blob `bf3d9f5a`)** —— 修法与验证见 `rv32im-atomic-cycle-weights-2026-09-16.md` §6 (P2) / §9.1: `reg_t dummy; reg_t* const dst = rd ? &regs[rd] : &dummy;`。修复后 `lw x0,0(x0)` 报 `SIGSEGV` 且 `x0` 未被写坏, `lw x0,0(t1)` 合法地址仍正常 (**规程九 ⑥**), 现有冒烟其余断言全部不受影响 (九规程 80 项 0 失败)。

### 11.2 **`DIV` 的 `-rs1` 快速路径在 `rs1 == INT_MIN` 时是有符号溢出 UB** (确认; ✅ **已修** blob `bf3d9f5a`)

```cpp
case 4:  // DIV
  if (rLANG_UNLIKELY(regs[rs2].iv == -1))
    regs[rd].iv = -regs[rs1].iv;   // ← rs1 == INT_MIN 时: 对 int32_t 取负溢出 = UB
```

这条快速路径**恰好专门处理** `rs2 == -1`, 而 `INT_MIN ÷ -1` **正是 ISA 规定的溢出特例** ⇒ 它一定会被执行到 `-INT_MIN`。C++ 里对 `int32_t` 取负溢出是 UB (与头内"启用最高级别的编译优化, 代码必须消除潜在的UB"的注释、以及 `rLANGiOPT` 的 `-O3` 并列时尤其扎眼)。
**修法**: `regs[rd].uv = 0u - regs[rs1].uv;` —— 无符号回绕**有定义**, 结果与 ISA 完全一致 (`DIV(INT_MIN,-1) == INT_MIN`)。**已修 (blob `bf3d9f5a`), 规程九 ⑦ 已验证**。
**注**: 本报告 §5/§9 早先写的"`DIV(INT_MIN,-1) = INT_MIN`, 用 `-rs1` **恰好等价** ✅" —— 数值等价没错, 但"**恰好**"二字掩盖了 UB, 以本条为准。

## 附录 A. 最小复核 TU (本次实测用的骨架, 可原样复现)

```cpp
/* 接口/布局档 TU: 调用每个 hook + 静态断言 (不碰 Execv); 2026-09-16 按当前 API 刷新,
   实测 g++ / clang++ 在 -Wall -Werror 下均 rc=0 (当前头 c0943b25) */
#include <base/base.h>
#include "rv32im-atomic.hpp"
#include <cstddef>
#include <cstdint>

struct Impl : machine::hyper::VM_t<Impl> {};
struct Expose : Impl {                       // 头里的 guest hook 是 protected, 用派生类提权才能 odr-use
  using Impl::op_FENCE;  using Impl::op_FENCEI; using Impl::op_ECALL;  using Impl::op_EBREAK;
  using Impl::op_CSRIF;  using Impl::op_GATE;   using Impl::op_HYPER;
  using Impl::mm_LW;     using Impl::mm_SW;     using Impl::if_CODE;
};
// 逐个调用: 触发按需实例化 —— 缺 return / 参数类型不符 / 拼写错误只有被调用才会暴露
int probe(Expose& e, Impl::reg_t* r) {
  e.op_FENCE(0x0000000Fu); e.op_FENCEI(0x0000100Fu);     // void 且带 op 参数
  int acc = e.op_ECALL() + e.op_EBREAK() + e.op_CSRIF(0) + e.op_GATE(1) + e.op_HYPER(0);
  acc += e.mm_LW(0, r) + e.if_CODE(0, &r->uv);
  const char* cs = nullptr; Impl::libmb_t n = 0; void* wp = nullptr; const void* rp = nullptr;
  acc += e.mm_CHKCS(0, &cs, &n) + e.mm_CHKWR(0, 4, &wp) + e.mm_CHKRO(0, 4, &rp);   // 宿主/上层 API
  e.mm_SW(0, 0x12345678u);
  return acc;
}
// 布局与 psABI: 32×32 位寄存器、x0 在第 0 位、a0 = x10、三个参数视图同址
static_assert(sizeof(Impl::reg_t) == 4 && sizeof(Impl::regs_t) == 128 && alignof(Impl::regs_t) == 8, "layout");
static_assert(offsetof(Impl::regs_t, zero) == 0 && offsetof(Impl::regs_t, a0) == 40
           && offsetof(Impl::regs_t, u32args) == 40 && offsetof(Impl::regs_t, r64args) == 40, "abi");
// 门窗口 <=> jalr 12 位有符号立即数; 高窗 id 为负
static constexpr bool isGate(std::uint32_t pc) { return pc < 0x00000800u || pc >= 0xFFFFF800u; }
static_assert(isGate(0x7FC) && !isGate(0x800) && isGate(0xFFFFF800u) && !isGate(0xFFFFF7FCu), "gate window");
static_assert(static_cast<std::int32_t>(0xFFFFF800u) / 4 == -512, "high-window ids are negative");
// 信号取值 (POSIX; 本头用 SIGTERM 替代各平台不一致的 SIGABRT)
static_assert(SIGQUIT == 3 && SIGILL == 4 && SIGTRAP == 5 && SIGTERM == 15 && SIGSEGV == 11, "sig values");
int main() { Expose e; Impl::reg_t r{}; return probe(e, &r); }
```

```sh
g++     -std=c++17 -Wall -Werror -fsyntax-only -I <ATOMIC> -I <ATOMIC>/atomic/include tu.cc
clang++ -std=c++17 -Wall -Werror -fsyntax-only -I <ATOMIC> -I <ATOMIC>/atomic/include tu.cc
```

> 注 (2026-09-16 更新): ① 上面这个 TU 已按当前 API 刷新 (FENCE/FENCEI 收 `op` 且为 `void`; 6 个 CSR hook 合成 `op_CSRIF(op)`; `mm_CHK*` 改用 `CHKWR`/`CHKRO`/`CHKCS`), 实测 g++/clang++ `-Wall -Werror` 均 rc=0。② 本机 cygwin 的程序**能运行** (之前那次 rc=1024 是我把编译输出接了管道、进程被截断写坏了 exe); 运行时冒烟见 `checks/interpreter-smoke.cc` (§7 of 问题审查)。

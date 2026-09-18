# RV32IM (ilp32) 调用约定 —— 重点: **可变参数 / `va_list` / `va_arg`** (2026-09-16)

- **问题 (用户 2026-09-16)**: "我们当前 RV32IM 的 toolchain 下调用约定特别是可变参数和 va_list, va_arg 部分的约定"。
- **本文件的定位**: 寄存器约定表与"命名参数"的逐条核对已经在 **`rv32im-atomic-registers-review-2026-09-16.md`** (§1/§3) 做过 —— 本文件**不重复**那张表, 只补 **变参这一半**, 并把"VM / 门实现需要做什么"讲清楚。
- **ISA/ABI 前提**: RV32IM **无 F/D/C** ⇒ ABI 只能是 **ILP32** (integer calling convention only, `EF_RISCV_FLOAT_ABI_SOFT`) —— **不是** ILP32F/ILP32D (那两个要求 F/D 且参数走 `fa0–fa7`)。M 扩展**不改变**调用约定 (只多 5 条乘除指令)。
- **toolchain**: 仓内 pin 表 (`atomic/ai-doc/toolchain/README.md` §5): tag `2026.06.06` ⇒ **binutils 2.46 / gcc 16.1.0 / musl 1.2.5** (`arch/riscv32` 已核实在该 pin 上存在)。
- ✅ **工具链就在本机 (2026-09-16 用户指出)**: `X:\Machine\ATOMIC\rv32im-atomic-rockey\bin` (**WSL 侧同一路径 `/Machine/ATOMIC/rv32im-atomic-rockey/bin`**), 即之前那次构建的产物 —— 实测确认: `riscv32-unknown-elf-gcc 16.1.0` / `ld 2.46` / `--print-multi-lib` = `.;` (**单 multilib**, 与该 pin 的 `--disable-multilib` 单一 rv32im/ilp32 配置一致) / `libgcc.a` 在位。
  ⇒ 因此本文 §6 的"编译器会生成什么形状"**全部已实测**, 不是推断: 用 `-march=rv32im -mabi=ilp32` 编了一份覆盖 8 个变参分支的 guest 程序, **并在我们的 `VM_t` 解释器上端到端跑通** (资产: `atomic/ai-doc/checks/varargs/`)。
- ✅ **目标宏实测**: `__riscv_float_abi_soft=1` (软浮点 ILP32 ✅)、`__riscv_muldiv=1` (M 扩展在位)、`__LDBL_MANT_DIG__=113`、`__SIZEOF_LONG_DOUBLE__=16` ⇒ **`long double` = binary128** (与 psABI 的 ILP32 类型表一致)。
- **规范依据**: `riscv-non-isa/riscv-elf-psabi-doc` 的 `riscv-cc.adoc` —— 本次 (2026-09-16) 取的原文:
  <https://raw.githubusercontent.com/riscv-non-isa/riscv-elf-psabi-doc/master/riscv-cc.adoc>
  仓内 registers review 引用的是 **ABI v1.0** 的网页版; **本次逐句比对确认**: 变参的"偶数起始寄存器对 + 上栈后全上栈"规则, 与"sret (按引用返回 ⇒ 返回缓冲区地址作为**隐式第一参数**)"这条 —— 在 **v1.0 (ratified)** <https://docs.riscv.org/reference/abi/v1.0/riscv-cc-procedure-calling-convention.html> 与 **master** 里**逐字一致** ⇒ **基础整数调用约定这几年没有被改动** (v1.0 → master 的增量都是**新增**内容: `_BitInt` 规则、向量调用约定变体/定长向量、独立的帧指针约定小节、实验性的 `RV64ILP32*`、类型表新增 `__bf16`/`_Float16` 等)。

---

## 1. 总框架 (只列与变参相关的前提)

| 项 | 约定 (psABI) | 对 ATOMC 的含义 |
| --- | --- | --- |
| 参数寄存器 | `a0–a7` = `x10–x17`, 前两个兼作返回值 | `regs_t` 的覆盖层起点正是 a0 ✅ (registers review §1) |
| 跨调用保持 | `sp`、`s0–s11`; `gp`/`tp` 固定不改 | ⚠ **门实现必须遵守** (见 §5.4) |
| 不保持 | `ra`、`t0–t6`、`a0–a7` | 变参保存区要存的就是这些"入口值" |
| 栈 | 向**低**地址增长; **过程入口 `sp` 16 字节对齐** 且全程保持; 第一个栈上参数在 `sp + 0`; 栈上参数按 `max(类型对齐, XLEN)` 对齐, 但**不超过栈对齐**; 不得依赖 `sp` 以下的数据 | `sp = 0x10FFE0` **16 字节对齐** ✅ (冒烟规程六已断言); 栈 64K 可写 ✅; 栈下是只读 ROM 区 (写必 SIGSEGV) ⇒ **下溢 fail-closed**; 栈顶之上未映射 ⇒ **上溢 fail-closed** |

> `sp` 这条对变参尤其重要: `va_start` 会在**入口 `sp` 之下**开保存区 (§4), 也就是"往更低地址走"——正好是栈的正常增长方向 ✅。

## 2. 命名参数 (摘要, 原文见 registers review §3)

- **≤ XLEN**: 一个参数寄存器; 窄整数先按自身符号扩到 32 位再符号扩展到 XLEN; 窄浮点加宽到 XLEN 且**高位未定义**。
- **2×XLEN** (如 `long long`、`double`): **一对寄存器**, 低半在低号寄存器 —— **不要求偶数起始**。只剩一个寄存器时: 低半进寄存器、高半进栈。**> 2×XLEN**: 按引用 (参数位置换成地址)。
- **聚合**: ≤XLEN 一个寄存器 (像在内存里那样铺); ≤2×XLEN 一对; 更大按引用。空结构被忽略。
- **返回**: 与"同类型的第一个命名参数"同法; 按引用返回时**调用方**分配内存并把地址作为**隐式第一参数** —— 且**不保证返回时 a0 仍持有该地址**。

## 3. ⭐ 可变参数: **调用方**怎么传

psABI 原文 (Integer Calling Convention, 变参段):

> In the base integer calling convention, variadic arguments are passed in the same manner as named arguments, **with one exception**. Variadic arguments with 2×XLEN-bit alignment and size at most 2×XLEN bits are passed in an ***aligned* register pair** (i.e., the first register in the pair is **even-numbered**), or on the stack by value if none is available. **After a variadic argument has been passed on the stack, all future arguments will also be passed on the stack** (i.e. the last argument register may be left unused due to the aligned register pair rule).

⇒ 三条推论 (记住这三条, 变参就懂了):

1. **8 字节类型 (`double`/`long long`, 对齐 8 = 2×XLEN) 作为变参必须落在偶数起始的寄存器对** (`a0a1`/`a2a3`/`a4a5`/`a6a7`)。因此**可能跳空**一个寄存器 (例如下一个空位是 `a1`, 那这个变参就从 `a2` 开始), 也可能因为凑不出偶数对而**提前溢出到栈**。
2. **一旦某个变参落到栈上, 之后所有参数都走栈** ⇒ 在内存里 **寄存器区与栈区是连续的**, 这正是下面 `va_list` 能用一个裸指针线性遍历的全部秘密。
3. 与我们 `regs_t` 覆盖层的关系: `r64args[4]`/`i64args[4]` 只表达"`a0a1`/`a2a3`/`a4a5`/`a6a7` 四个对齐对", **表达不了**两种合法情形 —— (a) **命名**参数里 `double` 从 `a1` 开始 (命名参数不要求偶数起始), (b) **变参**里为对齐而**跳空**。差异已在 registers review §3 记录, 此处只补上"变参"这一侧的成因。

补充 (ILP32 类型表, psABI):

- `double` = 8 字节/对齐 8; `long double` = **16 字节/对齐 16 (binary128)** ⇒ 尺寸 > 2×XLEN ⇒ **按引用传递** ⇒ `va_arg(ap, long double)` 取到的是**指针** (不是两个寄存器对)。
- `float`/`_Float16`/`__bf16` 在软浮点 ILP32 下走整数寄存器 (加宽到 XLEN, 高位未定义); `float _Complex` = 8/4、`double _Complex` = 16/8 视同"含两个 real 的结构体"。
- `char` 在 RISC-V 上**是 unsigned**; `size_t` = `unsigned int`、`ptrdiff_t` = `int`; `max_align_t` 对齐 16。ILP32 表里**没有** `__int128`。

## 4. ⭐ 被调方: `va_list` / `va_start` / `va_arg` (psABI 原文)

> The `va_list` type has the **same representation as `void*`** and points to a sequence of zero or more arguments with preceding padding for alignment, formatted and aligned as variadic arguments passed on the stack according to the integer calling convention. **All standard calling conventions use the same representation for variadic arguments** to allow `va_list` types to be shared between them.
>
> The `va_start` macro in a function initializes its `va_list` argument to point to the first address at which a variadic argument could be passed to the function. **If all integer argument registers are used for named formal arguments**, the first variadic argument will have been passed on the stack by the caller, and the `va_list` can point to the address immediately after the last named argument passed on the stack, **or the `sp` value on entry** if no named arguments were passed on the stack. **If some integer argument registers were not used for named formal arguments**, then the first variadic argument may have been passed in a register. The function is then expected to **construct a *varargs save area* immediately below the entry `sp`** and fill it with the entry values of **all integer argument registers not used for named arguments, in sequence**. The `va_list` value can then be initialized to the start of the varargs save area, and it will iterate through any variadic arguments passed via registers before continuing to variadic arguments passed on the stack, if any.
>
> The `va_arg` macro will **align** its `va_list` argument, **fetch a value**, and **increment** the `va_list` according to the alignment and size of a variadic argument of the given type, **which may not be the same as the alignment and size of the given type in memory**. If the type is passed by reference, the size and alignment used will be those of **a pointer**, and the fetched pointer will be used as the address of the actual argument. The `va_copy` macro is a **single pointer copy** and the `va_end` macro **performs no operation**.

**解读 (三句话)**:

1. `va_list` 就是 **`void*`** —— 没有任何"寄存器保存区描述符"结构 (对比 x86-64 SysV 的复杂 `va_list`)。它指向一段 **"变参按栈规则排布"** 的连续内存 (**含前置对齐填充**)。
2. `va_start` 有**两种情形**:
   - **命名参数用光了 `a0–a7`** ⇒ 第一个变参本来就在栈上 ⇒ `va_list` = "最后一个栈上命名参数的地址之后"; 若根本没有栈上命名参数 ⇒ = **入口 `sp`**。
   - **还有没用完的参数寄存器** ⇒ 第一个变参可能在寄存器里 ⇒ 被调方必须**在入口 `sp` 之下**造一个 **varargs save area**, 把"命名参数**未使用**的那些 `a*` 的入口值**按顺序**存进去, 再把 `va_list` 指到该区起点 ⇒ 这样**遍历完寄存器区就自然接上栈区** (因为 §3 推论 2: 栈区紧跟其后)。
3. **`va_copy` = 一次指针拷贝, `va_end` = 空操作**。`va_arg` 的前进量按"**变参**的大小/对齐"算, **可能与类型在内存里的大小/对齐不同** (最典型: 每个槽至少 8 字节 / 8 字节对齐); **按引用传递的类型** (含 `long double`、>2×XLEN 的聚合) 按**指针**大小/对齐处理。

## 5. 对 ATOMC / VM 的具体含义 (可执行清单)

1. **解释器不需要为变参做任何事** —— 变参完全由编译器生成的**普通 RV32IM 指令**实现 (存 `a0–a7` 到栈、算指针、按槽前进)。只要 VM 正确执行 RV32IM **并且栈可写**, 变参就"天然支持"。
   ⇒ **不要**给变参加任何 hook、指令特例或 `va_list` 结构体 —— 那会引入不必要的、与"确定性/一致性"契约相冲的机制。
   ✅ **已用真 toolchain 证实 (§6.5)**: 一份覆盖 8 个变参分支的程序在我们的 `VM_t` 上跑通, `g[]` 与宿主编译同源结果逐个相同,**VM 一行代码都没改**。
2. **栈要求**: 可写、16 字节对齐、空间足够 (save area ≤ 8×4 = **32 字节**, 实测 GCC 会存**未使用的**那些 `a*`, 见 §6.1; 另加栈上溢出参数区) ⇒ 我们的 64K 栈绰绰有余 (实测这个程序只用了栈上几十字节)。
3. **`sp` 初值** `0x10FFE0`: 16 字节对齐 ✅、落在经典 HMA 内 ✅ (冒烟规程六已断言) ⇒ 满足"过程入口 16 字节对齐"。
4. ⚠ **门实现的 callee-saved 契约 (对我们最要紧的一条)**: 门**不是**普通函数调用 (它由 `jalr id*4(zero)` 进入、用 `x1` 返回), 但它**必须遵守 psABI 的 callee-saved**: 不得破坏 **`s0–s11`、`sp`** (`gp`/`tp` 也不得改)。
   - **门不得在 guest 栈上乱写**: 变参 save area 就在**变参函数自己的帧内** (psABI: 在**入口 `sp` 之下**建立、最多 8×4 = 32 字节, 即 `入口 sp − 32 … 入口 sp`), 这块内存属于 guest 的帧 ⇒ 门写它 = 直接毁掉那个函数的 `va_list` 和局部变量。
   - **RISC-V 没有 x86 那种 red zone** (psABI: "Procedures must not rely upon the persistence of stack-allocated data whose addresses lie below the stack pointer") ⇒ 门也不要把 `sp` 之下当作自己的暂存区; 需要暂存就自己 `addi sp,sp,-N` 并在返回前**严格恢复** (这样也不会破坏调用方帧)。
5. **入口前提**: `gp` 必须已初始化 (musl 的 `crt_arch.h` 负责; 裸机由 `start.S` 负责) —— 否则 `.sdata/.sbss` 取址全崩。与变参无直接关系, 但同属"过程入口必须成立"的前提 (§2.5 的 `sp` 归属问题同源)。
6. **越界读**: `va_arg` 走飞了会读到更低的栈地址或栈外 (未映射) ⇒ **SIGSEGV (fail-closed)** ✅。反向 (实际传入的参数比 `va_arg` 取的少) 是 **guest 的未定义行为, 我们无法检测** —— C 的 `va_arg` 本来就没有上界可查, 记一笔即可, 不要试图加检查。
7. **宿主/门要替 guest 实现 `printf` 风格函数时**: 只需接收那个 `void*` 并按同一套规则走 —— 因为 `va_list` 就是裸指针, 宿主可以直接读/写 guest 内存 (**经 `mm_CHKRO/CHKWR`/`mm_CHKCS` 做区间校验**)。⇒ 这是分层设计的好处: **变参的"解析"可以放在宿主侧**, 而 guest 侧只剩"生成 save area"这点编译器生成的代码。

## 6. ✅ 实测 (2026-09-16): 真 toolchain 编出来 → 在我们解释器上跑通

**资产**: `atomic/ai-doc/checks/varargs/` —— `varargs-test.c` (覆盖 8 个变参分支的 guest 程序, 同源可编宿主做对照) + `varargs.ld` (按最终内存映射把映像放 `0x10000`) + `run-varargs.cc` (极简 ELF32 装载器 + 按最终内存映射实现的 IMPL + 断言) + `build-and-run.ps1` (一条命令全流程)。
**跑法**: `powershell -File build-and-run.ps1` (工具链可用 `$env:RV32IM_TOOLCHAIN` 覆盖)。

### 6.1 被调方序言/`va_start` (反汇编实测, `-O2`)

以 `sum_i(int n, ...)` (命名参数只占 `a0`) 为例:

```asm
addi sp,sp,-48          ; 开帧
addi t1,sp,20           ; save area 起点 = sp+20
sw a1,20(sp)            ; 把**命名参数未使用**的 a1..a7 **按顺序**存进去
sw a2,24(sp)  ...  sw a7,44(sp)
sw t1,12(sp)            ; va_list (= void*) 初值 = save area 起点
```
⇒ **完全符合 psABI**: save area 28 字节 (7 槽), 位置正是"**入口 `sp` 之下**" (`sp+20 … sp+48`, 而 `sp+48` = 入口 `sp`) ✓; **只存未使用的**寄存器 (命名参数用掉的 `a0` 不存) ✓; `va_list` 指向其起点 ✓。
⇒ 另一个实测: `skip_pair(int,ull,int,int,...)` 里 `a0..a4` 都被命名参数用掉, 于是 save area **只有 1 个槽** (`sw a5,20(sp)`) —— 而这个"4 字节宽的 save area 起点 `sp+20`"恰好不是 8 对齐的, `va_arg(ull)` 的"圆整到 8"就自动**跳过 `a5` 那一格** ✓ (见下)。

### 6.2 `va_arg` 的步进与对齐 (反汇编实测)

| `va_arg` 的类型 | 实测代码 | 步进 |
| --- | --- | --- |
| `int` / 指针 (4 字节) | `lw a2,0(a5)` + `addi a5,a5,4` | **4** (槽距 = max(类型对齐, XLEN)=4) |
| `unsigned long long` / `double` (8 字节) | `addi a5,a5,7` → `andi a5,a5,-8` → `lw lo,0(a5)` `lw hi,4(a5)` → `addi a5,a5,8` | **8**, 且**先圆整到 8** |
| `long double` (16 字节) | `lw a4,0(a3)` (取**指针**) + `addi a3,a3,4` → 再从 `a4` 读 `0/4/8/12` 四个字 | **4** (指针大小!) |

⇒ 三条都印证了 psABI 的原文: "increment … according to the alignment and size of a variadic argument of the given type, **which may not be the same as** the alignment and size of the given type in memory" 以及 "If the type is passed by reference, the size and alignment used will be those of **a pointer**" ✓。
⇒ `int` 的槽距是 **4** (不是 8) —— 所以"每个变参占 8 字节"是**错的**直觉, 实测按 `max(类型对齐, XLEN)` 走。

### 6.3 调用方: 偶数对与栈 (反汇编实测)

```asm
; sum_ll(3, 1ull, 2ull, 3ull)  —— 命名参数只占 a0=n
li a2,1 ; li a3,0        ; 第 1 对 = a2a3   ← **a1 被跳空** (8 字节变参必须偶数起始)
li a4,2 ; li a5,0        ; 第 2 对 = a4a5
li a6,3 ; li a7,0        ; 第 3 对 = a6a7
li a0,3                  ; n
```
```asm
; sum_ll(5, 1..5ull) —— 前 3 对在寄存器, 剩余两个上栈
sw a4,0(sp) ; sw a5,4(sp)    ; 第 4 个: 栈槽 0  (8 字节对齐)
sw s2,8(sp) ; sw s3,12(sp)   ; 第 5 个: 栈槽 8  ⇒ **一旦上栈就全在栈上**
```
⇒ 与 §3 的三条推论完全一致 ✓。`sum_i(9, …)` 的栈参数则是 4 字节槽距 (`0(sp)`, `4(sp)`) ✓。

### 6.4 `long double` = **按引用** (实测)

```asm
; 调用方 (run_all 里调用 sum_ld_bits(1, 3.25L)):
addi a1,sp,16      ; 变参槽里放的是**地址**
sw  zero,16(sp)    ; \ 16 字节对象被拷到栈上
sw  a3,20(sp)      ;  |
sw  a4,24(sp)      ;  |
sw  a5,28(sp)      ; /
jal sum_ld_bits
```
⇒ 16 字节 > 2×XLEN ⇒ 按引用, 参数位置换成地址 ✓; 被调方 `va_arg(ap, long double)` 先 `lw` 出指针再读 16 字节 ✓。
`long double` 的表示也实测了: `.rodata` 里 `3.25L` 的 16 字节 = `…00 a0 00 40` ⇒ **binary128** (`exp 0x4000`, 尾数 `1.101b`), 与 `__LDBL_MANT_DIG__=113` 一致 ✓。

### 6.5 端到端结果 (在我们的 `VM_t` 上)

```
  PT_LOAD vaddr=0x10000 filesz=1184 memsz=1280
  entry=0x10460  g=0x104A0
rc=4 (SIGILL, 来自结尾的 ecall)  pc=0x10478  sp=0x10FFE0  cycles=0+646
  PASS  程序以 ecall 结束
  PASS  g[0..7] 与宿主编译同一份源码的结果逐个相同 (21 / 45 / 6 / 15 / 21 / 300 / 4294705152 / 0x4000A000)
```

| 断言 | 覆盖的约定 |
| --- | --- |
| `g[0]=21` | 变参**全在寄存器** (被调方造 save area) |
| `g[1]=45` | 变参**溢出到栈** (7 寄存器 + 2 栈槽) |
| `g[2]=6`, `g[3]=15` | `long long` **偶数起始对** + 上栈后按 8 对齐 |
| `g[4]=21` | 命名参数占满后 8 字节变参**跳空** `a5` |
| `g[5]=300` | 指针变参 |
| `g[6]=4294705152` | `double` 变参 (软浮点 ILP32 下走整数寄存器对) |
| `g[7]=0x4000A000` | `long double` **按引用** + binary128 (此值与宿主 x86 的 80 位扩展**不可比**, 属目标属性) |

⇒ **§5.1 的结论被证明**: 解释器**一行代码都没为变参改过** —— 变参完全由编译器生成的普通指令实现; 需要的只是"栈可写 + `sp` 16 字节对齐 + 映像在 `0x10000`"这些**本来就有**的条件。
⇒ 顺带验证了周期计价的"**总代价 = `cycles_` + `cyc_`**": 这个真程序跑了 **646 拍**, 而 `cycles_` 显示 0 (尚未折叠) —— 与 `rv32im-atomic-cycle-weights-2026-09-16.md` §5 的记账语义一致 ✓。
⇒ 装载方式也顺带验证: **ELF 的 `PT_LOAD` 按 `p_paddr` 落到 `0x10000`、bss 清零、入口取 `e_entry`** —— 这就是"把 toolchain 产物放进我们内存映射"的最小可行做法 (可复用的 40 行装载器)。

## 7. ⭐ 实例 (用户 2026-09-16 提问): 返回 `long double` ⇒ **所有参数右移一格**

用户观察: "`call_foobar` 下, `fmt` 在 **a1**, `1` 在 a2, `0x12345678` 在 a3, 跟一般的函数调用看起来有差别"。

**原因就是 §2 最后那条规则**: 函数返回 `long double` (16 字节 > 2×XLEN) ⇒ **按引用返回** ⇒ "调用方分配内存并把地址作为**隐式第一参数**" ⇒ 隐式指针占 **`a0`**, 于是所有显式参数顺延一格。这**不是异常**, 是 psABI 的规定行为。

原样编译用户的代码 (`checks/varargs/foobar-sret.c`, `-march=rv32im -mabi=ilp32 -O2`) 实测:

### 7.1 调用方 `call_foobar` 的真实分配

| 位置 | 内容 | 说明 |
| --- | --- | --- |
| **`a0`** | 返回缓冲区 | `addi a0,sp,48` —— **sret 隐式第一参数** (所以 `fmt` 只能去 a1) |
| `a1` | `fmt` (格式串 `.LC2`) | 命名参数 |
| `a2` | `1` | 第 1 个变参 (`li a2,1`) |
| `a3` | `0x12345678` | 第 2 个变参 (`li a3,305418240; addi a3,a3,1656`) |
| `a4` | `0x56789123l` | 第 3 个变参 —— **`long` 在 ILP32 是 4 字节** ⇒ 单寄存器, 不涉及偶数对 |
| ~~`a5`~~ | **跳空** | 下一个 8 字节变参必须偶数起始 ⇒ `a5` 被跳过 |
| `a6a7` | `0xAABBCCDD11223344ll` | 第 4 个变参 (`.LC1` 两个字: `0x11223344`/`0xAABBCCDD`) |
| `0(sp)` | `(double)2.718f` | 寄存器用光 ⇒ 上栈; ⚠ **`float` 变参按 C 规则提升为 `double`** (8 字节!), 实测 .LC4 = `0xC0000000 0x4005BE76` = `(double)2.718f` |
| `8(sp)` | `(double)3.1415926` | 8 字节 ⇒ **8 对齐**, 所以从槽 4 圆整到槽 8 |
| `16(sp)` | **指向 `0.618L` 的指针** | `long double` 按引用; 对象本体由**调用方**放在 `sp+32..47` |
| `sp+32..47` | `0.618L` 的 16 字节 (binary128, 实测高字 `0x3FFE3C6A`) | 调用方分配的实参对象 |

### 7.2 被调方 `foobar` 本体

```asm
addi sp,sp,-80
addi t1,sp,56          ; save area 起点
sw   a2,56(sp) … sw a7,76(sp)   ; 只存**未用于命名参数**的 a2..a7 ⇒ 6 槽 24 字节
mv   s0,a0             ; 先保住调用方给的返回缓冲区 (a0)
mv   a2,t1             ; vfoobar 的第 3 个参数 = va_list
mv   a0,sp             ; *** 自己给 vfoobar 的返回缓冲区 (又一次 sret) ***
sw   t1,28(sp)         ; va_list = save area 起点
call vfoobar           ; ⇒ a0=buf, a1=fmt(原地未动!), a2=va_list
lw   a2,0(sp) … lw a5,12(sp)    ; 把 16 字节返回值从临时缓冲…
sw   a2,0(s0) … sw a5,12(s0)    ; …拷进调用方给的缓冲区
mv   a0,s0             ; 返回 a0 = 缓冲区地址 (psABI 说**不保证**, 但 GCC 这么做)
```

**两个可直接引用的结论**:

1. **`sret` 指针虽然不算 C 的"命名参数", 但它确实占用 `a0`** ⇒ 变参的 save area 因此从 `a2` 起 (若返回类型是 `int`, 就该从 `a1` 起)。规则原文是"all integer argument registers **not used for named arguments**", 实测按"**已被占用的寄存器**"算。
2. **嵌套调用同样右移**: `foobar` 转发给 `vfoobar` 时, `vfoobar` 也返回 `long double` ⇒ 它是 `a0`=自己的缓冲、`a1`=fmt(**原地不动**, 省一条指令)、`a2`=va_list ✓。
3. `__attribute__((format(printf, 1, 2)))` **对 ABI 没有任何影响** (它只做编译期格式检查, 编号按源码位置数, `fmt` 是第 1 个) —— 所以 `a1` 里的 `fmt` 与这个属性无关, 只与 sret 有关。

### 7.3 对 ATOMC 的含义

- **`regs_t` 的参数覆盖区 (`i32args[8]` 从 `a0` 起) 在"按引用返回"的函数上整体右移一格**。宿主/门若要在 C 语义上"读这个调用", 必须知道 `a0` 是隐藏的返回缓冲区指针, 而不是第 1 个实参。⇒ 建议在文档/注释里写明这条 (它不影响 VM 执行, 只影响**宿主侧的语义解读**)。
- 也解释了 `long double` 返回值为什么"贵": 它自己不占寄存器, 还**吃掉一个参数寄存器**, 并把 16 字节的搬运责任压给调用方。
- 复现: `checks/varargs/foobar-sret.c` (原样保留用户的代码) + `riscv32-unknown-elf-gcc -march=rv32im -mabi=ilp32 -O2 -S foobar-sret.c`。

### 7.4 对照: 把返回类型改成 `double` (用户 2026-09-16 第二版, 原样保留在 `checks/varargs/foobar-ret-double.c`)

用户把 `foobar` **和** `vfoobar` 的返回类型都改成 `double` 后确认"结果符合预期" ⇒ 实测该版本 (`-O2`):

| 位置 | 返回 `long double` (§7.1) | **返回 `double`** (本版) |
| --- | --- | --- |
| `a0` | 返回缓冲区 (**sret**) | **`fmt`** ← 回来了 |
| `a1` | `fmt` | **`1`** |
| `a2` | `1` | **`0x12345678`** |
| `a3` | `0x12345678` | **`0x56789123l`** |
| `a4a5` | `0x56789123l` + **跳空 a5** | **`0xAABBCCDD11223344ll`** (偶数对, **不再跳空**) |
| `a6a7` | `0xAABBCCDD11223344ll` | **`(double)2.718f`** (`.LC1` = `0xC0000000 0x4005BE76`, 即 float 提升后的 double) |
| `0(sp)` | `(double)2.718f` | `(double)3.1415926` (`.LC4` = `0x4D12D84A 0x400921FB`) |
| `8(sp)` | `(double)3.1415926` | 指向 `0.618L` 的指针 (对象本体在 `sp+16..31`) |
| `16(sp)` | 指向 `0.618L` 的指针 | — |
| `foobar` 的 save area | `a2..a7` (6 槽 24 字节) | **`a1..a7` (7 槽 28 字节)** |

**三条结论**:

1. `double` = 2×XLEN ⇒ **用 `a0a1` 返回值** (psABI 第 2.1.1 节开头: "the first two of which are also used to return values") ⇒ **不需要 sret**, 参数回到 `a0` 起, save area 因此多一格 ✓ 与用户观察一致。
2. **同一份源码只改返回类型, 整个参数分配就整体移了一格** (连"是否跳空 `a5`"都变了) ⇒ 这是"光看源码无法确定 ABI、必须看反汇编/实测"的最好例子。
3. 这一版里**内部那次 `vfoobar` 调用变成了尾调用** (`call vfoobar; lw ra; jr ra`) —— 因为 `vfoobar` 的返回类型也被改成了 `double`, 于是 `double → long double → double` 的往返被优化掉, **内部也不再需要 sret 缓冲区**。若只改外层 `foobar`、内部仍是 `long double`, 内层调用就会保留 sret (即 §7.2 的形状)。
   ⚠ 这也是"**sret 是逐调用点的属性**"的直接证据: 同一个函数体, 内层调用的 ABI 由**被调方的返回类型**决定, 而不是外层。

## 8. 📌 标准门入口的建议 (等 `atomic` 侧创建, 2026-09-16)

**动机 (用户原话)**: "我们有一个地方需要处理 va_list, vsnprintf/vsprintf/rlLoggingWriteEx_v, 我试过, **解释器里直接调用 sprintf 系列函数慢的让人痛不欲生**"。
**用户的下一步**: "我已经有之前的实现, 一会我们创建几个 atomic, 用来作为这几个 `op_GATE` 的标准入口" ⇒ 本节是**给那批 `atomic` 文件用的规格**, 不是实现。

**核心结论**: **printf 引擎放宿主, guest 只发一次门调用**。理由见 §4: `va_list` 就是 `void*`, 指向**guest 内存**里按 ILP32 排布的参数区 ⇒ 宿主可以按同一套规则**自己取参**, 而取参只是读 guest 内存 (原生速度); 反过来让 guest 自己跑 `vsnprintf`, 就是让解释器去执行成百上千条 printf 状态机指令。

### 8.1 接线点 (现有代码, 供对齐)

| 位置 | 作用 |
| --- | --- |
| `base/bits/base.h:727` | `rlLoggingWriteEx(int level, uint32_t tag, int line, const void* data, int len, const char* fmt, ...)` —— **正好 7 个参数** |
| `base/src/log.cc:124/377/521` | `platformLoggingWrite(level, tag, line, data, len, const char* fmt, va_list ap)` —— 三个平台各一份, 最终都走 `rlLog_vsnprintf` |
| `base/src/log.cc:44` | `rlLog_vsnprintf` → 宿主 `vsnprintf` (日志缓冲 2048) |
| `src/__Testing__/__dongle__/main.cc:350` | 用户说的"之前的实现": `WriteLog` lambda —— **guest 侧** `vsprintf(buffer, fmt, ap)` + `rl_HEX_Write` 十六进制转储 + `DATA$:` 前缀 + 收尾换行 + `rlLOGXI(TAG, data, size, "%s", buffer)` |

⇒ 改造方向: 把上表最后一条里的 **`vsprintf` 那一步挪到宿主**, 其余 (十六进制转储/前缀/换行/最终 `rlLOGXI`) **原样复用**。

### 8.2 门签名建议 (与 `platformLoggingWrite` 一一对应 ⇒ 天生落在 `a0–a6`)

```
门 id = kGateLog              (编号待定; 注意低窗 id 0..63 是"每次编译可变"的槽位)
  a0 = level (int)            a1 = tag (uint32_t)      a2 = line (int)
  a3 = data  (guest ptr)      a4 = len (int)           a5 = fmt (guest ptr)
  a6 = ap    (guest ptr, 即 va_list 本身)
返回值: 宿主把格式化长度写回 a0 (不需要就写 0); 错误仍走 x0/zero (见 §5.4 的门契约)
```

宿主 handler 三步:
1. **校验**: `mm_CHKCS(fmt)` (我们的 `.rodata` 末尾有 guard page ⇒ 一定有 NUL), `mm_CHKRO(data, len)`;
2. **取参 + 格式化**: 用 **guest-va 取参器** 逐条转换, 每条调用一次**宿主 `snprintf`** (§8.3/§8.4);
3. **输出**: 把结果交给现有后端, 例如 `rlLoggingWriteEx(level, tag, line, data, len, "%s", buffer)` —— **不需要动 log.cc 的输出/时间戳/文件逻辑**。

⚠ **绝对不要**把 guest 的 `va_list` 直接当宿主的 `va_list` 用: 宿主按**自己的**规则取参必错。最典型两例 (均实测): 宿主 `long double` 是 80 位扩展而 guest 是 **binary128**; 宿主 `long` 是 8 字节而 guest 是 **4 字节**。

### 8.3 取参器必须处理的坑 (全部来自规范/实测)

| 指令 | guest 侧取参 | 坑 |
| --- | --- | --- |
| `%d %i %u %x %X %o` | 4 字节 | — |
| `%ld %lu %lx` | **4 字节** | ILP32 的 `long` 是 32 位; **不能**按宿主的 `long` 取 |
| `%lld %llu` | 8 字节, **先把指针圆整到 8** | 偶数对/8 对齐规则; 圆整会**跳过**寄存器保存区里的空槽 (§6.1) |
| `%zu %zd %zd` | 4 字节 | guest `size_t` = `unsigned int` |
| `%f %e %g %lf` | 8 字节 double | 变参里 `float` 已被**提升为 double** ⇒ 永远 8 字节; `%lf` 与 `%f` 同义 |
| **`%Lf %LF %Lg`** | — | ⚠ **不能搬**: guest binary128 vs 宿主 80 位扩展 ⇒ 建议 **fail-closed** (或让 guest 侧先转 `double`) |
| **`%s`** | 4 字节 **guest 指针** | ⚠ 必须先把 guest 字符串**有界拷贝**进宿主缓冲; 直接把 guest 指针交给宿主 `snprintf` = 让宿主解引用 guest 地址 |
| `%c` | 4 字节 | — |
| `%p` | 4 字节 | 建议按 `0x%08X` 打印**guest 地址**, 不要当宿主地址 |
| **`%n`** | — | ⚠ **一律拒绝** (安全) |
| `%ls` | 4 字节 wchar | 建议先拒绝 (或按 guest 的 wchar 规则另做) |
| `*` (宽度/精度) | 4 字节 int | 可用, 但会让"重建规范格式串"变复杂, 可先拒绝 |

### 8.4 实现技巧: 重建"规范化格式串"

取参后**重建一个去掉长度修饰符的宿主格式串** (保留 flags/宽度/精度), 并用**规范类型**传给宿主 `snprintf`:

```
signed 32 -> int          signed 64 -> long long
unsigned 32 -> unsigned   unsigned 64 -> unsigned long long
浮点 -> double            字符 -> int            字符串 -> 宿主 const char*
```

⇒ 一份宿主 `snprintf` 就能覆盖所有 32/64 位长度修饰符的组合 (这是各类"带取参器的 vsnprintf"的标准做法)。

### 8.5 性能

- guest 侧: **一条门调用** (十几条指令) + **零格式解析**;
- 宿主侧: 每个转换一次**原生** `snprintf` (ns 级);
- 对比: 解释 musl 的 `vsnprintf` = 逐条解释它的状态机/数值转换循环 (用户实测"痛不欲生"完全合理);
- 附带好处: 日志成本**不占 guest 的周期预算** (门自报成本, 见计价文档 §5), 时间片不会被日志吃掉。

### 8.6 已备好的测试 (待接线)

`checks/varargs/guest-fmt.c`: guest 侧只发**一次**门调用 (7 个参数塞满 `a0–a6`), 覆盖正常格式化 + `%Lf`/`%n` 的 fail-closed 分支。
⚠ **门 id 目前用 `0` 作占位**; 宿主侧的 guest-va 取参器/格式化器**尚未写** (等本节 §8.7 的问题定了位置再落, 避免与你已有的实现重复)。

### 8.7 待确认 (建 `atomic` 时一起定)

1. **门 id 分配**: 建议在 ATOMC 侧定义一个 enum (`kGateLog = ...`); 注意"低窗 `id 0..63` 是每次编译可变槽位"的既有约定 (README §3.1) ⇒ 日志门属于**必须稳定**的那类, 应放在**高窗 (负 id)** 或明确保留的低槽。
2. **宿主落地位置**: 在 `base/src/log.cc` 加 `platformLoggingWriteGuest(level, tag, line, data, len, fmt, guest_ap)`, 还是把取参器放在门实现所在的 `atomic` 文件里?
3. **`%L` / `%n` 策略**: fail-closed 写 `<unsupported>` 标记后继续, 还是让门返回错误终止程序?
4. **"之前的实现"具体指哪一份** (`main.cc:350` 的 `WriteLog`? 还是别处) —— 我按它对齐命名与行为, 不另起一套。

## 9. 与仓内其它记录的关系

- **`rv32im-atomic-registers-review-2026-09-16.md` §3**: 参数覆盖区 (`i32args[8]`/`r64args[4]`) 与 psABI 的差异 —— 本文 §3 补充了"变参侧"的成因 (偶数对齐对 + 跳空 + 上栈后全上栈)。
- **同文件 §2.5/§2.11**: `sp` 的归属 (`Enable(pc)` 里写 `sp = 0x10FFE0` vs guest `start.S` 自己写) —— 本文 §1/§5.3 依赖"入口 `sp` 已 16 字节对齐", 但**不改变**那个待决项的结论; 无论谁写, 契约都是"程序入口处 `sp == 0x10FFE0`"。
- **`rv32im-atomic-isa-conformance-2026-09-16.md` §5 第 6 条**: 明确 `real32_t/real64_t` 覆盖层只对 **ilp32 软浮点**成立 (与 ILP32F/D 无关) —— 与本文前提自洽。
- **`hyper-vm-t-issues-2026-09-16.md` §2.3**: 门的返回地址取 `x1` —— 本文 §5.4 的"门必须遵守 callee-saved"与它是同一族契约 (门 = 特殊调用)。

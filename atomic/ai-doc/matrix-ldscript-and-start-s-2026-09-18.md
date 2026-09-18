# `atomic/Matrix` 链接脚本重写 + `start.S` 检查 (2026-09-18)

- **用户要求**: "修改下 `atomic/Matrix/ldscript/default.ld` 使得它满足我们之前定义的布局形式, `.text` (RX) + `.rodata` (RO) 对齐到 64K 页边界, `.data` (RW) + `.bss` (RW+ZI); 顺便检查下 `start.S`"。

## 1. 目标布局与实测结果

| 范围 | 用途 |
| --- | --- |
| `0x00000-0x0FFFF` | 不映射 (低 64K; 门窗口 `0x000-0x7FF` 在其中, 靠 pc 拦截) |
| `0x10000-0x9FFFF` | **程序映像 576K** (本脚本管这一段) |
| `0xA0000-0xEFFFF` | 可写设备区 |
| `0xF0000-0xFFFFF` | 只读区/ROM (写必 SIGSEGV ⇒ 兼作栈下护栏) |
| `0x100000-0x10FFFF` | 用户栈; `_estack = 0x10FFE0` (16 字节对齐, 落在经典 HMA 内) |

新脚本用 **显式 PHDRS** 把映像切成三个**权限段**, 每段从 64K 边界开始 (每页只承载一种权限):

```
[0] LOAD off 0x010000 vaddr 0x00010000 filesz 0x50 memsz 0x50  R E  align 0x10000   .text
[1] LOAD off 0x020000 vaddr 0x00020000 filesz 0x20 memsz 0x20  R    align 0x10000   .rodata
[2] LOAD off 0x030000 vaddr 0x00030000 filesz 0x10 memsz 0x40  RW   align 0x10000   .data + .bss(ZI)
```

实测符号 (真工具链 `-march=rv32im -mabi=ilp32 -Os --gc-sections`):

```
__Matrix_text_start   = 0x00010000   __Matrix_text_end   = 0x00010050
__Matrix_rodata_start = 0x00020000   __Matrix_rodata_end = 0x00020020
__Matrix_data_start   = 0x00030000   __Matrix_data_end   = 0x00030010
__bss_start           = 0x00030010   __bss_end           = 0x00030040
_estack               = 0x0010FFE0   _MatrixStart = 0x00010000 (= 映像起点, .text.crt0 在最前)
```

⇒ `.bss` 是 **ZI**: 第 2 段的 `filesz(0x10) < memsz(0x40)` ⇒ 不占文件 ✓; `RW` 段与 `R E`/`R` 段**不共页** ✓。

## 2. 脚本要点

1. `MEMORY { IMAGE (rwx) : ORIGIN = 0x00010000, LENGTH = 576K }` (原脚本的 `(640-64)*1024` 就是这个值 ✓ 只把名字与用途写清楚)。
2. `PHDRS { text PT_LOAD FLAGS(5); rodata PT_LOAD FLAGS(4); data PT_LOAD FLAGS(6); }` ⇒ 权限显式 (R+X / R / R+W)。
3. 三个段都用 `: ALIGN(64K)` (段起始对齐, **不是**在段体里 `ALIGN`, 后者会把填充算进内容且不保证起点)。
4. 补齐**小数据段** `*(.sdata .sdata.*)` / `*(.sbss .sbss.*)` —— 我们用 `gp` 相对寻址, 原来漏了这两个 (会变成孤儿段); 另外补 `.data.rel.ro`、`.got`、`.tdata/.tbss` (静态 TLS)。
5. `KEEP(*(.text.crt0))` 保住 `start.S` 的入口 (配 `--gc-sections` 必须)。
6. 结构性 `ASSERT`: 三段各自 64K 对齐 / `_estack` 16 对齐 / 映像不超 576K / 三段互不重叠 / `.bss` 不落在 `.data` 之前的页。

## 3. ⚠ 实测踩到的两个坑 (都已修)

| 坑 | 现象 | 修法 |
| --- | --- | --- |
| **`.data` 被 `--gc-sections` 回收成空段时, `.bss` 会被放回 `.text` 那一页** | 段表里出现 `RW` 段落在 `0x00010030` (与 `R E` 共页) ⇒ **权限页混用** | 在 `.data` 里放一个 `LONG(0)` 保证它非空 (4 字节代价), 并加 `ASSERT((__bss_start>>16) >= (__Matrix_data_start>>16))` 兜底 |
| 重叠断言写得过严 | `.rodata` 为空时 `__Matrix_data_start == __Matrix_rodata_end`, 被 `ASSERT(a > b)` 误判 | 改成 `>=` (不重叠即可; 空段时相等是正常的) |

ℹ 另注: 当某个段为空时, ld 会给出一个 **`filesz=memsz=0` 且 vaddr=0 的 PT_LOAD** (实测)。⇒ **宿主装载器必须跳过 size==0 的 LOAD 段** (否则会去映射地址 0 —— 那正是低 64K 未映射区)。我们 `checks/varargs/run-varargs.cc` 的装载器已经是 `memcpy(0 字节)` 语义 ✓ 但值得写成显式规则。

## 4. `start.S` 检查

现状 (用户 2026-09-18 修正 `MatrixExecv`/`MatrixExit` 语义之后的 15 行):

```asm
	.section .text.crt0,"ax",@progbits
	.align	2
	.globl	_MatrixStart
	.type	_MatrixStart, @function
_MatrixStart:
	lla   gp, __global_pointer$
	lla   sp, _estack
	call  rLANG_op_GATE_Initialize     /* 世界核对: 门数/世界魔数 */
	call  MatrixExecv                  /* a0 = 应用入口的返回值 (像 main 一样 return) */
	tail  MatrixExit                   /* = MatrixExit(a0); noreturn 且 a0 原样传下去 */
	.size	_MatrixStart, .-_MatrixStart
```

(文件末尾另有一段块注释, 把"为什么 `tail` 安全"和"`.bss` 由加载器清零"两条契约写在 crt 里, 见 §4.1。)

### ✅ 做对的部分

- **`gp`/`sp` 在调用任何 C 代码之前设好** ✓; `_estack` 由脚本给出 `0x10FFE0` (16 字节对齐) ✓ ⇒ **它回答了那份调用约定文档里悬着的问题: `sp` 是 crt 写的**, 不需要宿主代劳。
- `.section .text.crt0` 与脚本的 `KEEP(*(.text.crt0))` 配对 ✓ ⇒ `--gc-sections` 下不会被丢掉, 且实测落在**映像起点** `0x10000` ✓。
- 顺序正确: **先**做世界核对 (`rLANG_op_GATE_Initialize`), **再**进 `MatrixExecv`, **最后**才 `MatrixExit` ✓ —— 任何库门调用都必须在核对之后。
- 符号名没问题: `rLANGEXPORT` = `extern "C"` (`rLANG_MODULE_EXTERN` = `extern rLANGCXXONLY("C")`, 而 `rLANGCXXONLY(x)` 在 C++ 下就是 `x`) ⇒ 汇编里可以直接写未修饰名 `MatrixExecv` / `rLANG_op_GATE_Initialize` ✓ (已核实宏定义)。
- **`call MatrixExecv` + `tail MatrixExit` 就是 `MatrixExit(MatrixExecv())`** ✓ —— 状态只走 `a0`, 不经任何寄存器中转 (实测反汇编: 两条 `auipc ra`+`jalr ra` 之后是 `auipc t1`+`jr t1`, **`a0` 一路没被碰**)。

### 4.1 ⚠ 原来提的两点 —— **两条都已撤回 (其中第 1 条最终以"你改语义"的方式收场)**

**(1) `tail MatrixExecv` 的"不返回"契约 —— 我原来的担心已被你的语义修正彻底消除**:

历史: 最初 `start.S` 是 `tail MatrixExecv`, 靠"`MatrixExecv` 是 `noreturn`"成立 —— 我当时指出这是**没写下来的契约** (`tail` = `jal x0, …` 不设 `ra`, 一旦返回就跳到未定义的 `ra`), 建议改 `call` + 收尾序列。
**你 2026-09-18 的修正正好把这条契约写进了类型**:

| | 旧语义 | **新语义 (当前)** |
| --- | --- | --- |
| `MatrixExecv` | `rLANGIMPORT __attribute__((noreturn)) void MatrixExecv();` (宿主/库侧, 不返回) | **`rLANGIMPORT int MatrixExecv();`** —— 它是**应用侧入口**, 应用用 `rLANGEXPORT int MatrixExecv() {...; return 0;}` 定义 (`Matrix/HelloWorld/main.cc:7`), 像 `main` 一样 return 状态 |
| crt 收尾 | `tail MatrixExecv` (赌它不返回) | **`call MatrixExecv` → `tail MatrixExit`** = `MatrixExit(MatrixExecv())` |
| `MatrixExit` | `noreturn`, 状态 = 门号 | **`noreturn`** (不变), 但**只钳门号**, `a0` 带完整状态 (§4.2) |

⇒ 现在**没有任何"赌它不返回"的地方**: 中间的 `call` 是正规调用, 末尾那个 `tail` 的目标 `MatrixExit` 由构造保证不返回 ⇒ **原建议撤回, 你的写法更自然** (顺带省掉一次寄存器中转)。
`start.S` 已按此改写注释 (并说明"若哪天 `MatrixExit` 变成会返回, 这里必须跟着改")。

**(2) `.bss` 由加载器初始化, `start.S` 保持原样**:

**用户 2026-09-18 裁定**: "`.bss` 由加载器初始化, `start.S` 不用管" ⇒ 我原来"在 crt 里加 3 条清零循环"的建议**撤回**。
- ⇒ 这变成一条**加载器契约**: 宿主必须按 ELF 语义把 `p_memsz > p_filesz` 的那部分**补零** (参考实现: `checks/varargs/run-varargs.cc` 里的 `memset(dst + filesz, 0, memsz - filesz)` ✓);
- 前提是映像以 **ELF PT_LOAD** 交给宿主 —— 我们的布局正好是三个 PT_LOAD, `.bss` 在 RW 段内且 `filesz < memsz` ✓; 若哪天改走 **`objcopy -O binary` 平坦映像**, 这条契约就得换人承担 (届时 crt 清或加载器清, 二选一);
- 已把这条写进 `ldscript/default.ld` 的头部注释 (紧挨 `.bss` 那句话) **和** `start.S` 末尾的块注释, 免得以后有人又去 crt 里加一遍。

### 4.2 ✅ exit GATE 协议 (用户 2026-09-18 实现, 同日修正语义) + 宿主侧契约

用户原话: "我增加了 `MatrixExit` 实现, 既然 `-64 - 63` 的 op_GATE 没有使用, 我们刚好用它做 exit GATE, **不小心用 nullptr 调用函数指针就直接退出了**"; 随后: "**我略微修正了 `MatrixExecv` `MatrixExit` 的语义, 这样看起来更自然一些**"。

实现 (`atomic/op_GATE/hyper/modules.cc:29-41`) 的读法:

```c
rLANGEXPORT void MatrixExit(int v) {
#ifndef rLANG_CONFIG_MATRIX_WORLD
  exit(v);                                              /* COSMO/转译成宿主程序: 普通 exit */
#else
  constexpr uint32_t kExitMagic = rLANG_CONFIG_EXIT_GATE_MAGIC;   /* hyper.h: 0xFEA1DEAD (单一来源) */
  const int kGate = v < -64 ? -64 : v > 63 ? 63 : v;    /* **只钳门号**, 不钳状态 */

  auto* op_GATE = reinterpret_cast<void(rLANGAPI*)(int A0, uint32_t A1, uint32_t CHK, uint32_t magic)>(4 * kGate);
  for(;;) {
    op_GATE(v, kExitMagic, v + kExitMagic, rLANG_WORLD_MAGIC);   /* a0 = 真值 v; a2 = uint32 加 (会回绕) */
  }
#endif
}
```

| 设计点 | 说明 |
| --- | --- |
| **门号空间 = exit 窗口 `[-64, 63]`** | 正是 `id` 空间里"没被库导出 (`[64,511]`) 与 hyper (`[-512,-65]`) 占用"的两段: `0..63`(低) 与 `-64..-1`(高) ⇒ 128 个槽位 |
| **只钳门号, `a0` 带完整 32 位状态** (修正后) | `kGate` 只用来**选门**; 传给宿主的 `A0` 是**原始 `v`** ⇒ `exit`-like 语义完整 (旧版把状态也钳成 7 位, 那才是"看起来不自然"的地方) |
| **`MatrixExit(0)` ⇒ pc = 0 ⇒ id 0** | 于是"**`nullptr` 函数指针调用**"(`pc = 0`)天然落到 exit 窗口的 id 0 ⇒ 从"跳到未定义地址"变成"有确定语义的一次门调用" ✓ |
| **负门号 ⇒ 高窗** | `4 * (-64) = -256` ⇒ 32 位地址 `0xFFFFFF00` ⇒ 高窗 `id -64` ✓ (与 `id = (int)pc/4` 一致; 真机实测: `slli s0,s0,2` 一条搞定, 见下面的代码生成) |
| **三个"防误撞"参数** | `a1 = kExitMagic`(`rLANG_CONFIG_EXIT_GATE_MAGIC` = `0xFEA1DEAD`; 这个值就是内存映射里**旧设备区填充图案**, 见 `hyper-vm-t-issues` §2.10 —— 现在设备区改用 `0x55AAFF00`, 两者不再相干) / `a2 = v + kExitMagic`(校验和, **uint32 加**) / `a3 = rLANG_WORLD_MAGIC` ⇒ 宿主据此确认"这确实是一次 exit 调用", 而不是别的代码误跳进这两段窗口 |
| **`for(;;)` 重试** | 若宿主的 exit 门返回 0 (=继续执行), guest 会**反复**调用它 (而不是跑飞) ⇒ 安全网; 真正终止仍要靠宿主 |
| **应用入口 = `rLANGEXPORT int MatrixExecv()`** | 应用自己 return 状态 (像 `main`); 库侧 `hyper.h` 以 `rLANGIMPORT int MatrixExecv();` 引用它; crt `call MatrixExecv` + `tail MatrixExit` ⇒ **应用不需要自己调 `MatrixExit`** (但**可以**: 提前退出/`(*nullptr)()` 兜底都靠它) |
| **非 MATRIX 世界** | `#ifndef rLANG_CONFIG_MATRIX_WORLD` 时直接 `exit(v)` ✓ |

**⇒ 顺带说明**: 这两段"未使用"的 id 段原先是"每次编译可变"随机化的候选池 (README §3.1); 被 exit 门号占用**没有损失** —— "每次编译不兼容"已由 `gen.cjs` 对 `[64,511]` 的**洗牌**提供 ✓。

**真机代码生成 (实测 `riscv32-unknown-elf-g++ -O2 -march=rv32im -mabi=ilp32 -S`; 把 `MatrixExit` 的算术原样抽出来编)**, 与上面逐条对应:

```asm
	mv	s2,a0                       # 保住真 v
	li	a5,63 / bgt a0,a5,.L2 / mv s0,a0 / li a5,-64 / bge s0,a5,.L3 / mv s0,a5
	slli	s0,s0,2                     # s0 = 4 * kGate  (门号; 负值 => 0xFFFFFF00 起的高窗)
	li	s1,-22945792
	addi	s1,s1,-339                  # s1 = 0xFEA1DEAD (kExitMagic)
	add	s1,s2,s1                   # a2 = v + kExitMagic —— **单条 add, 不做溢出检查 (uint32 回绕是设计)**
	li	a3,-926920704
	addi	a3,a3,-481                  # a3 = 0xC8C04E1F (rLANG_WORLD_MAGIC)
	li	a1,-22945792
	addi	a1,a1,-339                  # a1 = kExitMagic
	mv	a0,s2                       # a0 = **真 v** (状态不钳制)
	jalr	s0                          # 调门
	j	.L4                         # for(;;)
```

#### ⚠ 宿主侧契约 (用户 2026-09-18 已给出参考实现 `rLANG_op_GATE_HyperExit`, 见下面两节; 这里是它对应的"验收清单")

1. **校验防误撞三元组**: `a1 == rLANG_CONFIG_EXIT_GATE_MAGIC && a2 == (uint32_t)a0 + a1 && a3 == rLANG_WORLD_MAGIC` ⇒ 否则**不要**当成 exit。
   ⚠ **必须用 `uint32_t` 算**: 状态是**任意 `int`** (不再钳制), 宿主若写有符号的 `a0 + a1`, 在 `INT_MIN` 这类状态上就会**有符号溢出 (UB)** ⇒ 规程十有一条断言专门钉这个 (`__builtin_add_overflow` 检出)。参考实现里就是 uint32 加 ✓。
2. **真正终止程序**: guest 侧那个 `for(;;)` 只在宿主**不终止**时才重试。**参考实现选的是"宿主 `exit(v)`"** (即 `MatrixExit` 在宿主构建下的语义, 见第 3 点); 另一条同样可行的路是**让 `op_GATE` 返回非零** (⇒ `inner_Execv` 返回该值, `x0` 被写, 世界结束) —— 后者对"一个进程里跑多个世界/hart"的宿主更友好。
3. **记录状态**: 用 **`a0` 完整 32 位**作退出状态 (修正后不再只有 7 位) ⇒ 宿主可以原样上报; ⚠ 若走 `exit(v)` 那条路, **操作系统只保留低 8 位** ⇒ 需要完整状态就得在退出前自己记一笔; 要不要按 POSIX 惯例截成 8 位是**宿主策略** (建议只影响"上报", 不影响门内判别)。
4. **`noreturn` 的后果**: `MatrixExit` 是 `noreturn` (`MatrixExecv` **不再是**) ⇒ 若宿主不终止, guest 会一直在这个门调用循环里 (表现为"程序不结束"而不是崩溃) ⇒ 看到"反复打同一个门"就是这个原因。

#### ✅ `exit(0)` 与真正的 `(*nullptr)()` **可区分** (用户 2026-09-18 澄清)

用户: "**`exit(0)` 与真正的 `(*nullptr)()` 状态有差别, 调用 `MatrixExit` 会设置几个 magic number**" ⇒ 精确地说:

- 两者**落在同一个 id (`0`)**, 但**参数不同**: 真的 `MatrixExit(0)` 一定带三元组 (`a1 = rLANG_CONFIG_EXIT_GATE_MAGIC`, `a2 = a0 + a1`, `a3 = rLANG_WORLD_MAGIC`); 而 `(*nullptr)()` 的 `a0..a3` 是**垃圾** ⇒ 宿主要能分辨;
- ⇒ **只有"只看 id"的实现才会把两者混为一谈** —— 那正是要避免的写法。

因此宿主在 `id ∈ [-64, 63]` 上要**分支**(保险起见整个区间都查, 不只 id 0 —— 野生跳转也可能落进这段窗口):

| 情形 | 宿主应当 |
| --- | --- |
| 三元组**匹配** | 按 `a0` 的状态**正常退出** (终止程序 + 记录完整 32 位状态) |
| 三元组**不匹配** | **不要当退出**: 这是 `(*nullptr)()` 或野生跳转 ⇒ 按**故障**处理 (`SIGSEGV`/`SIGILL`), 或至少**告警后再退出** (由你定) |

⇒ 建议把这张表写进门的注释 —— 它就是"同一 id 上两类调用"的判别规则。

**✅ 已有可运行的验证** (`atomic/ai-doc/checks/interpreter-smoke.cc` **规程十**, 16 项断言, 全过):

- **三段 id 无缝相接**: `[-512,-65]` hyper/用户私有 448 个 + `[-64,63]` exit 128 个 + `[64,511]` 库导出 448 个 = **1024** ⇒ 恰好填满两个 512 槽窗口 (低窗 `pc < 0x800` = id `[0,511]`, 高窗 `pc ≥ 0xFFFFF800` = id `[-512,-1]`) ⇒ "exit 白拿 128 个 id"的真实代价是 0;
- **128 个门号逐个跑真解释器**: 入口 `pc = 4*v` ⇒ 门号 `id == v` (含 -64/-1/0/63 边界与负数的 32 位回绕), 每例 4 拍;
- **钳制只作用于门号** (修正后的关键点): `v = 64/-65/1000/-1000/INT_MAX/INT_MIN` 时门号钳到 `63/-64`, 而 **`a0` 仍是完整原值**, 三元组照样匹配;
- **判别规则本身被测**: 窗口内 + 三元组全中 ⇒ 退出; `(*nullptr)()` 且寄存器全 0 (**同 id 0**) ⇒ 判故障 ⇒ 与 `exit(0)` **确实可区分**; 校验和差 1 / 世界魔数不符 / 落在 id 64 (库导出槽) 都**不**当退出 ⇒ 窗口判定必须在前、且要覆盖整个 `[-64,63]` 而不是只查 id 0;
- **算术契约被测**: guest 的 `v + kExitMagic` 是 **uint32 加 (会回绕)** ⇒ 宿主必须照抄; 有符号 `a0 + a1` 在 `INT_MIN` 上溢出 (`__builtin_add_overflow` 检出) ⇒ 已作为反面断言钉住。

#### ✅ 宿主参考实现 `rLANG_op_GATE_HyperExit` 与 `MatrixExit` 的**逐点相容性核对** (2026-09-18, 用户提供)

宿主侧 (`atomic/op_GATE/hyper/hyper.h:64-80`, 模板):

```cpp
template <typename VM>
inline int rLANGAPI rLANG_op_GATE_HyperExit(VM* vmx, int gate) {
  constexpr uint32_t kExitMagic = rLANG_CONFIG_EXIT_GATE_MAGIC;

  const int v = vmx->hart_->regs_.a0.iv;
  const int kGate = v < -64 ? -64 : v > 63 ? 63 : v;
  const uint32_t A1 = vmx->hart_->regs_.a1.uv;
  const uint32_t CHK = vmx->hart_->regs_.a2.uv;
  const uint32_t magic = vmx->hart_->regs_.a3.uv;

  if (kGate != gate || A1 != kExitMagic || CHK != v + kExitMagic || magic != rLANG_WORLD_MAGIC) {
    rlLOGX(...);          /* 打出 v / gate / kGate 与 A1,A2,A3 的"实际 vs 期望" */
    return SIGILL;        /* 判为故障: 写进 x0, 世界就此结束 (fail-closed) */
  }
  MatrixExit(v);          /* 通过 => 真退出; 宿主构建下 MatrixExit = exit(v) */
}
```

**逐点核对结论: 相容 ✓** (每一条都有实测):

| 接触点 | guest (`MatrixExit`) | host (`HyperExit`) | 结论 |
| --- | --- | --- | --- |
| 哨兵常量 | `kExitMagic = rLANG_CONFIG_EXIT_GATE_MAGIC` | 同一个宏 | ✓ **单一来源** (两个世界共用一个头, 不会各写一个数; 我上一版文档里手抄的 `0xFEE1DEAD` 已被这个宏取代 —— 见下面第 5 条) |
| 门号钳制 | `v < -64 ? -64 : v > 63 ? 63 : v` | **同一条表达式**, 且要求 `kGate == gate` | ✓ 一致, 而且比"只查三元组"更严: 还核对了**派发槽位** |
| 校验和 | `v + kExitMagic` (**uint32 加**) | `CHK != v + kExitMagic` (`CHK` 是 `uint32_t` ⇒ `v` 被提升为无符号) | ✓ 同一条无符号算术, **无有符号溢出** |
| 世界魔数 | `rLANG_WORLD_MAGIC` | 同一个宏 | ✓ |
| 状态值 | `a0 = **原始 v**` (不钳) | `MatrixExit(v)` 传的也是**原始 v** | ✓ 完整 32 位状态一路到底 (`INT_MIN` 实测通过) |
| 失败路径 | guest `for(;;)` 重试 | `return SIGILL` + 打日志 | ✓ fail-closed; `SIGILL` 正是文档里定的"按故障处理" |
| 成功路径 | `noreturn` 属性 | 校验通过后 `MatrixExit(v)` | ✓ 顺序正确 (先校验后退出); 编译期也自洽 (`noreturn` ⇒ 无需 `return`) |

**⇒ 四点留意 (1~3 是"会静默出错"的坑; 4 是用户 2026-09-18 的方向性决定, 我原来的建议已撤回)**:

1. **`gate` 形参必须来自"派发"**, 即 VM 算出的 `(int)pc/4`; 若宿主在调用点用 `a0` 再算一遍门号传进来, `kGate != gate` 就永远为真 ⇒ **这条最有价值的检查退化成空操作**。更保险的写法是模板里自己再核一次 `gate == (int)vmx->hart_->pc_ / 4` (门被调用的那一刻 `pc_` 仍是门地址)。
2. **宿主 TU 绝不能定义 `rLANG_CONFIG_MATRIX_WORLD`** (纯宿主构建): 那个宏会把 `MatrixExit` 解析到 **guest 版** (`for(;;)` 里把 `4*kGate` 当函数指针调) ⇒ 在宿主上就是跳到非法地址/死循环。两个世界共用同一个头, 这个开关是唯一的分界 —— 值得写成注释或 `static_assert` 守住。⚠ 但**嵌套世界**里这个宏**就是**定义着的 (因为那一层确实是外层世界的 guest), 可它同时还要当内层的 host ⇒ **两种角色只能靠运行时区分, 不能只靠这个宏** (见第 4 点)。
3. **成功路径 = 宿主 `exit(v)`** (`modules.cc:30-31`, 而且 `MatrixExit` 现在是 **`rLANGEXPORTWEAK`** ⇒ 宿主可以覆盖它, 实测可覆盖): 它**不写 `x0`、不经过 `inner_Execv` 返回**, 直接结束宿主进程 ⇒ ① 同一进程里跑多个世界/hart 的宿主必须自己接管 (覆盖那个 weak 符号); ② 操作系统只保留退出码低 8 位 ⇒ **要留住完整 32 位状态, 得在退出前自己记一笔** (日志或结构体)。⚠ **这一条在"世界嵌套"成立时要改** —— 见下面第 4 点。
4. **模板在 guest 侧也编出来 —— 用户 2026-09-18 明确要留着, 这是特性不是包袱**: "也许有一天我们会在 VMX.Linux 里启动 VMX.DOS 里启动一个 VMS.NES .." ⇒ 一个世界既是**外层世界的 guest**, 又是**内层世界的 host** ⇒ host 侧模板必须在 guest 构建里也存在 ✓ (我原来"建议标注仅 host 侧可用"的那条**撤回**)。但它顺带把嵌套的两个真问题摆出来了:

   | 问题 | 说明 |
   | --- | --- |
   | **`exit(v)` 只在最外层正确** | 中间层 (VMX.DOS) 处理内层 (VMS.NES) 的 exit 时**不能**调 `exit(v)` —— 那会把 VMX.Linux 和所有兄弟世界一起杀掉。中间层要的是"**让内层世界结束, 把状态交回本层代码**", 本层再自行决定 (清理/继续/向上传播) |
   | **状态 0 走不了 `x0`** | `inner_Execv` 的 `err` **就是** `hart_->regs_.zero.iv` (别名, 见 `rv32im-atomic.hpp:240`), 循环条件是 `while (zero == 0)` ⇒ "返回非零以结束世界"这条路由**表达不了状态 0**。所以嵌套需要**分开两条信息**: ① `zero` 里的"世界已结束"码 (非零), ② 旁边一个**状态槽**存 `v` (可为 0) |

   ⇒ 建议 (不改现有语义就能兼容): 门实现里把"结束世界"做成**可覆盖的钩子** —— 最外层默认 `exit(v)`; 中间层覆盖成"**记下状态 v + 返回一个专用的非零完成码**"。那个码天然有位置: `rLANG_ERROR_HYPER (0xC8C04E1F)` 家族里 `-1` 空着 (`YEILD` 是 `-3`、`TIMEDOUT` 是 `-2`) ⇒ `0xC8C04E1E` = `rLANG_ERROR_EXIT` 可直接用, 且与故障用的 `SIGILL` **区分开** (宿主/外层代码必须能分辨"孩子正常退出"与"孩子崩了")。状态槽放在 `hart_t` (或门实现自己的表, 按 `vmx`/hart 索引) 都行 —— 这一步要动 guest 可见的界面, 所以留给你定。
   ⇒ **好消息**: 协议本身**可嵌套组合** —— 每一层都只是把收到的状态再 `MatrixExit(status)` 往上传, 三元组校验逐层都成立 (逐层都是同一条 `id ∈ [-64,63]` + 同一个哨兵/魔数)。
   ⇒ 而且与 `int MatrixExecv()` 的语义正好配成一对: **`MatrixExecv` 的返回值 = 内层/本轮运行的结果回到本层**, **`MatrixExit` = 本层向外终止** ⇒ 中间层"孩子退出后还能先做清理"这条正是靠前者。

**结论: 可以作为宿主 `op_GATE` 在 `id ∈ [-64,63]` 上的实现直接使用** —— **单层世界**直接可用; **打算做嵌套**时把第 3、4 点里的"结束动作"抽成钩子 (最外层 `exit(v)`, 中间层记为"状态槽 + `0xC8C04E1E`")。建议顺带把门号钳制抽成一个共享的 `inline` (两端现在各写一遍同样的三元表达式), 消除未来各自漂移的可能。

**✅ 相容性本身已有可运行验证**: `atomic/ai-doc/checks/gate-exit-compat.cc` (**20 项断言, 全过**)

```
g++ -std=c++17 -Wall -Werror -I <ATOMIC> -o gate-exit-compat.exe \
    atomic/ai-doc/checks/gate-exit-compat.cc && ./gate-exit-compat.exe
```

做法: 用**真 `hart_t`** 按 **guest 的公式**填寄存器 (门号也按 guest 的钳制表达式算), 交给**真 host 模板**判; 宿主的 `MatrixExit` 用 `longjmp` 截住 (真宿主是 `exit()`, 会直接杀掉测试进程), `rlLoggingWrite` 用最小 stub 顶掉。覆盖:

- **8 例应退出**: `0 / 42 / -64 / 63` 边界、`1000`(`门号 63, 状态不钳`)、`-1000`(`门号 -64`)、`INT_MIN`(**校验和回绕**)、`INT_MAX`, 以及"状态 = -哨兵 ⇒ `a2` 恰为 `0`"这个易漏边界 (宿主若把 `a2 == 0` 当成"没设置"就会误判);
- **8 例应判故障**: `(*nullptr)()` (全 0 / 只有哨兵对)、**门号与 `a0` 钳制不符**、负状态走正门号、哨兵错、校验和差 1、世界魔数错 —— 逐例确认返回 `SIGILL` 且**没有**调 `MatrixExit`、且**打了日志**;
- **钳制表达式**在 `[-3000,3000]` 上与参考实现逐点一致;
- **有符号校验和的 UB 反面断言** + `INT_MIN` 端到端通过。

⇒ 本 TU 与 `interpreter-smoke.cc` **规程十** 互补: 规程十验"解释器/门号映射 + 判别规则", 本 TU 验"**两端常量与算术真的对得上**"。两处都已改用 `rLANG_CONFIG_EXIT_GATE_MAGIC`, 不再出现手抄字面量。

### 4.3 💡 可选项: 把 `op_ECALL` 做成 **syscall 分派** (a7 = 号)

`ecall` 不是"要新实现的出口", 而是 **VM 已经拦截的指令** (hook `op_ECALL()` 现成)。而 musl 的 riscv32 系统调用约定**恰好**就是这个形状 (实测仓内 vendored musl, `third_party/musl/arch/riscv32/syscall_arch.h`):

```c
static inline long __syscall1(long n, long a) {
  register long a7 __asm__("a7") = n;      /* a7 = 系统调用号 */
  register long a0 __asm__("a0") = a;      /* a0..a6 = 参数 */
  __asm__ __volatile__("ecall\n\t" : "=r"(a0) : ... );   /* 返回在 a0 */
}
```

号也是现成的 (`arch/riscv32/bits/syscall.h.in`, 即 Linux riscv32 ABI):

| 号 | 名字 | 在 ATOMC 里能干什么 |
| --- | --- | --- |
| **64** | `__NR_write` | 输出 (fd 1/2 路由到日志/控制台); `buf/len` 用 `mm_CHKRO` 校验 |
| **93 / 94** | `__NR_exit` / `__NR_exit_group` | 真正实现 `exit(status)` |
| 63 | `__NR_read` | 输入 |
| 214 | `__NR_brk` | 若将来要动态堆 |

⇒ 好处: **musl 自己的 `write`/`exit`/`read` 不需要任何门桩** ⇒ "Hello World" 可以直接用 `puts`/`write`; 而**格式化**这种重活仍走日志门 (分工: 系统调用 = 轻量 I/O, 门 = 重操作/性能相关)。
⇒ 向后兼容: `ecall` 现在默认 `SIGILL` (=未实现), 改成分派后, 未知号可以继续返回 `-ENOSYS`/`SIGILL`。
⇒ ⚠ 与"世界魔数 (`HYPER`)"的区分: 那是**另一条**通道 (指令流里的魔数 + `op_HYPER()`), 互不干扰。

### 4.4 ℹ 顺带记下的一条门约定 (与 `start.S` 相关)

`modules.cc` 里 guest 侧那次"世界核对"是这么发起的:

```cpp
auto* op_GATE = reinterpret_cast<...>(4 * rLANG_START_ATOMIC_HYPER_GATE);  // 4 * (-512) = 0xFFFFF800
(*op_GATE)(op_GATE__kWorldId, op_GATE__kExportCount);                       // a0=worldId, a1=count
```

⇒ 它是**高窗 (`[-512,-65]`) 的 hyper 门**: id 完全在 **pc** 里, **不使用 `t0`**; 而 `gen.cjs` 生成的库导出是"pc = 槽位 + `t0` = 组内条目号"。
⇒ **宿主 `op_GATE` 要区分这两类**: `id` 为负 ⇒ hyper/用户私有 (忽略 `t0`, 但 exit 门要走 §4.2 的三元组); `id` 在 `[64,511]` ⇒ 库导出 (必须校验 `t0`) ✓。

### 4.5 ℹ 一个组织建议 (非必需)

`start.S` 现在每个 app 一份 (`HelloWorld/start.S`, 由 `add_general_source_files_under` 收进来)。内容与 app 无关 ⇒ 建议放到共享位置 (如 `Matrix/crt0/start.S`), 各 app 只引一次, 免得将来各 app 的 crt 漂移。
## 5. 待你定

1. ~~`.bss` 清零归属~~ ⇒ **✅ 已裁定 (用户 2026-09-18): 由加载器初始化, `start.S` 不用管**。理由: ELF 语义里 `p_memsz > p_filesz` 的尾部由加载器补零 ⇒ 这是**加载器契约**, 不是 crt 的活; 已写进 `ldscript/default.ld` 头注释与 `start.S` 末尾块注释。仅当将来真要做 `objcopy -O binary` 的**平坦映像**时, 才需要另想办法 (那条路上 `.bss` 既不在文件里也没有标识)。
2. ~~**exit 门的宿主实现**: 三元组校验 + 终止 + 记录状态; 以及**旋钮** (`nullptr` ⇒ 退出 还是 报错/告警)?~~ ⇒ **✅ 已裁定 (用户 2026-09-18): 可区分, 不用旋钮**。`MatrixExit` 会**设置几个 magic number**, `exit(0)` 与真正的 `(*nullptr)()` 在**参数**上不同 (同 id 不同参数) ⇒ 宿主在 `id ∈ [-64,63]` 上按三元组分支: **匹配 ⇒ 正常退出并记 `a0` 的完整 32 位状态**; **不匹配 ⇒ 按故障处理 (至少告警)**。⚠ 校验和**必须按 `uint32_t` 算** (状态不钳制, 有符号加在 `INT_MIN` 上溢出)。四条宿主契约见 §4.2, 实测断言见 `checks/interpreter-smoke.cc` 规程十。
3. **应用入口形态** (`rLANGEXPORT int MatrixExecv()` + crt `call`/`tail MatrixExit`) 已是当前写法 (用户 2026-09-18 修正) —— 若你打算让 `MatrixExecv` 再接收 `argc/argv` 之类的参数, 现在正是改的时机 (crt 里加两条 `li` 即可, 门协议不受影响)。
4. **嵌套世界 (VMX.Linux → VMX.DOS → VMS.NES) 的 exit 收尾方式** (用户 2026-09-18 提到这个方向): 中间层的 `HyperExit` 成功路径不能再 `exit(v)` (会连最外层一起杀掉), 需要"**状态槽 + 专用非零完成码**"两件东西 (建议 `0xC8C04E1E` = `rLANG_ERROR_EXIT`, 与故障用的 `SIGILL` 区分; 状态 0 走不了 `x0`, 因为 `err` 就是 `zero` 且循环条件 `while (zero == 0)`) —— 要不要现在就把这两样加进 `hart_t`/门界面? (见 §4.2 第 4 点)
5. `op_ECALL` 是否还要做 **syscall 分派** (`a7` = 号; `write`=64 / `exit`=93 / `exit_group`=94)? 现在 `MatrixExit` 已经能退出, 这条就变成"让 musl 的 `write`/`exit` 也能直接用"的可选项 (§4.3)。
6. `%n` 的策略: `HelloWorld/main.cc` 里刻意用了 `"... %d %n %ld ..."` + 随后 `"%zd"` 打印 `size` ⇒ 这是在**测宿主的格式化器**。`%n` 是安全敏感指令 ⇒ 若支持, 指针必须走 `mm_CHKWR` 校验 (拒绝的话 `size` 会保持 0, 日志里能看出来)。

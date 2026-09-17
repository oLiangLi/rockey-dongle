# `atomic/` 下 `make -j8`: **已修复并验证** (2026-09-17)

- **用户报告**: "我增加了 musl 的编译配置, 但现在由于我们不支持 RV32AC 指令, 很多文件编译不过, 在 `atomic` 下执行 `make -j8` 确认下"。
- **用户裁定 (2026-09-17)**: "**我们不支持 AC, 我们模拟器没有实现这部分指令**" ⇒ **不在 VM 里实现 A/C**, 修法只在**库/构建侧**。
- **用户授权 (2026-09-17)**: "现在可以改整个工程文件, 尽量的改动集中在 atomic 目录下" ⇒ 本次改动**全部在 `atomic/` 内**。
- **结果**: `make -j8` **0 错误**; 两个目标 (`rv32im-rockey` / `rv32im-atomic-rockey`) 都产出完整静态库, 且产出的代码 **A/C 指令 0 条** (ELF 属性 `rv32i2p1_m2p0_zmmul1p0`)。

---

## 1. 首次失败: 只有一类错误

`make -j8` ⇒ **rc=2**, `Makefile:67 rv32im-rockey` 与 `Makefile:74 rv32im-atomic-rockey` 都停。日志 51 行 `error:`, 全是同一句:

```
third_party/musl/arch/riscv32/atomic_arch.h:12: Error: unrecognized opcode `lr.w.aqrl a3,(s1)', extension `zalrsc' required
third_party/musl/arch/riscv32/atomic_arch.h:14: Error: unrecognized opcode `sc.w.aqrl a2,a5,(s1)', extension `zalrsc' required
```

- 首轮失败的 TU (每个目标 5 个, make 提前停下): `musl/putchar.o`、`putc.o`、`fputc.o`、`__lockfile.o`、`ftrylockfile.o`。
- 整个仓库里 **37 个 musl `.c`** 引用原子原语 (`src/thread/*` 最多, 另有 `aio/*`、`malloc/mallocng/*`、`stdio/__lockfile.c` 等)。
- **压缩指令 (C) 相关错误 0 条** ⇒ 是"A"而不是"AC"。

### 根因链 (逐环实测)

| 环节 | 实测 |
| --- | --- |
| 构建是否传 `-march`? | **没有**: `Build/` 里搜不到 `-march=`/`-mabi=`; `make -n` 的真实命令行里也没有 (只有 `-DX_ARCH_rv32im` 之类的宏) |
| 工具链默认值 | `-march=rv32im_zmmul`, `-mabi=ilp32` (**无 A 无 C**) |
| 工具链**能否**编 A/C? | 能 (`rv32ima`/`rv32imac` 都 rc=0) ⇒ 不是工具链的问题 |
| musl 需要什么? | `arch/riscv32/atomic_arch.h` **共 21 行**, 只定义 `a_barrier()` = `fence rw,rw` 与 `a_cas()` = LL/SC 循环 |
| A 依赖的**范围** | `src/internal/atomic.h:6` `#include "atomic_arch.h"` 之后, `a_swap`/`a_inc`/`a_dec`/`a_and`/`a_or`/`a_spin`… **全部由 `a_cas` + `a_barrier` 派生** ⇒ 整个 A 依赖就是那**一个 12 行函数** |
| `a_barrier` 我们能跑吗? | **能**: `fence rw,rw` = `0x0330000F`, 头里判据 `0x0F == (op & 0xF00FFFFF)` 接受它 |

## 2. 修复前的对照实验 (证明修法有效, 未改任何构建文件)

用 `make -n` 打印出的真实命令行, 只把覆盖目录插到 `-I` 最前:

| 实验 | 结果 |
| --- | --- |
| ① `putchar.c` 不加覆盖 | **rc=1**, 复现 `zalrsc required` |
| ② `putchar.c` 加覆盖 | **rc=0** ✅ |
| ③ `__lockfile.o` 反汇编 | **原子指令 0 条** ✅ |
| ④ **全部 37 个**引用原子原语的 musl `.c` 批量编译 (带覆盖) | **37 / 37 成功** ✅ |

## 3. 落地的改动 (4 处, 全在 `atomic/` 内)

### 3.1 新增 `atomic/musl/arch/riscv32/atomic_arch.h` (本地覆盖)

ATOMC 单线程、不可重入 (异步只在**指令边界/门返回**处恢复, 不可能在 `a_cas` 中间重入) ⇒ 用普通 load/store:

```c
#define a_barrier a_barrier
static inline void a_barrier(void) { __asm__ __volatile__("fence rw,rw" ::: "memory"); }

#define a_cas a_cas
static inline int a_cas(volatile int *p, int t, int s) { int old = *p; if (old == t) *p = s; return old; }
```

### 3.2 `atomic/project.mk`: 把覆盖目录插到上游 arch 目录**之前**

`atomic_arch.h` 是**引号**包含的 (`#include "atomic_arch.h"`), 解析顺序 = "包含者目录 → `-I` 顺序" ⇒ 覆盖目录必须排在 `third_party/musl/arch/riscv32` 前面 (放在 `atomic/musl` 那一行末尾**不生效**)。

```make
COMMON_CFLAGS +=  \
   -I$(wORLD_ROOT)/third_party/musl/include			\
   -I$(wORLD_ROOT)/atomic/musl/arch/riscv32			\
   -I$(wORLD_ROOT)/third_party/musl/arch/riscv32	\
   -I$(wORLD_ROOT)/third_party/musl/arch/generic	\
   -I$(wORLD_ROOT)/atomic/musl
```

### 3.3 `atomic/toolchain/rv32im-atomic-rockey.conf`: 显式钉住 ISA/ABI

```make
X4C_TOOLCHAIN_CFLAGS   += -march=rv32im -mabi=ilp32
X4C_TOOLCHAIN_CXXFLAGS += -march=rv32im -mabi=ilp32
```

⇒ 不再依赖工具链 configure 默认值: 若哪天默认值变成 `rv32imac`, 构建会**静默产出 C 指令**, 而 VM 假设"取指 4 字节 + `pc & 3` 对齐" ⇒ 会**静默错乱**(而不是报错)。将来真要开 A/C, 这里是唯一开关点。

### 3.4 顺手修掉一个既有 bug: `atomic/tlsf/xModule.mk` 漏了 `$(call ...)`

```make
- $(add_general_source_files $(wORLD_ROOT)/third_party/tlsf/tlsf.c)
+ $(call add_general_source_files, $(wORLD_ROOT)/third_party/tlsf/tlsf.c)
```

`add_general_source_files` 的定义是 `Build/core/common.mk:214` 的 `$(eval LOCAL_SRC_FILES_A += $1)` —— 它是**函数**, 必须用 `$(call ...)`; 少了 `call` ⇒ 源码没被加进来 ⇒ 之前产出的是 **8 字节的空归档 `libtlsf.a`**。

## 4. ✅ 修复后实测 (`make -j8`)

```
错误数: 0 (两个目标)
警告数: 10 = 5 条 × 2 目标, 全部是 musl 上游自带的警告
        (wcstod/wcstol/vfwscanf 的指针目标、seed48 的 array-parameter、vfprintf 的 NUL 截断)
```

| 产物 (`.bin/.lib/rv32im-atomic-rockey-release/`) | 大小 |
| --- | --- |
| `libbase.a` | 1,537,498 |
| **`libmusl.a`** | **2,901,600** |
| `librockey_atomic_abi_checker.a` | 21,804 |
| **`libtlsf.a`** | **187,404** (修复前 **8** 字节) |

**代码纯度检查 (关键)**:

| 检查 | 结果 |
| --- | --- |
| `libmusl.a` / `libtlsf.a` / `libbase.a` 里的 `lr.w`/`sc.w`/`amo*` | **全部 0 条** ✅ |
| ELF 属性 (`tlsf.o`、`musl/strlen.o`) | `Tag_RISCV_arch: "rv32i2p1_m2p0_zmmul1p0"` ⇒ **无 `a`、无 `c`** ✅ |
| 真实命令行 (`make -n` 实测) | 含 `-march=rv32im -mabi=ilp32`; `-I atomic/musl/arch/riscv32` 序号 **18** < 上游 arch 序号 **19** ✅ |

(注: `-march`/`-mabi` 在命令行里出现两次 —— `X4C_TOOLCHAIN_CFLAGS` 被同时汇入 CFLAGS/CXXFLAGS 两条路径所致, **无副作用**, 只是冗余。)

## 5. 观察与待办 (不是错误, 供决定)

1. **没有产出最终可执行映像**: `.bin/rv32im-*-release/` 是空的; 本次只产出 4 个静态库 (`base` / `musl` / `tlsf` / `abi_checker`)。这与各模块都用 `$(call build-library)` 一致 —— 真正的 world 映像/链接步骤**还没接**(`project.mk` 顶部的 TODO 也写着 "porting musl/tlsf, binding op_GATE for libgcc")。
2. **libm/math 是刻意不编的**: `atomic/musl/xModule.mk` 里把 `MUSL_ALL_MATH_FILES` / `MUSL_ALL_FENV_FILES` 整段注释掉, 并注明 "**我们平台没有 FD 指令集, 所有的 libm 函数在 HOST 侧 op_GATE() 实现**" ⇒ 这与"标准门入口"的设计一致 (见 `rv32im-atomic-calling-convention-and-varargs-2026-09-16.md` §8)。
3. ✅ **更正我先前的错误结论 (2026-09-17)**: 我曾写"`/Machine/System/bin/node` 不存在 ⇒ `rLANG_WORLD_SEED_*` 为空, 随机化没生效" —— **这是错的**。实际:
   - `/Machine/System/bin/node-rlang.exe` **存在** (用户在 cygwin 下手工作了 `/Machine/System/bin/node` 软链接);
   - cygwin 解析可执行文件**不检查 `.exe` 后缀**, 而**我的 `Test-Path` 是 PowerShell 语义 (必须带后缀)** ⇒ 我拿 PowerShell 的路径规则去判断 cygwin 路径, 得到假阴性。**同一类"先做对照实验"的教训** (README §5 的取证纪律)。
   - 实测 (2026-09-17): `make -n` 打印出 `-DrLANG_WORLD_SEED_0=0xce115e76 -DrLANG_WORLD_SEED_1=0xde54edc2 -DrLANG_WORLD_SEED_2=0x2a2f472c -DrLANG_WORLD_SEED_3=0xf22c6e9e`, 且每次不同 ⇒ **随机化一直是生效的**。
4. `musl` 模块的 `LOCAL_STRICT := 0` + 一长串 `-Wno-*` 是刻意为之; 若要参与严格模式, 建议**只**把 musl 排除 (它已在做)。

## 6. 📌 打开 libm (`MUSL_ALL_MATH_FILES` / `MUSL_ALL_FENV_FILES`) 的准备情况 (2026-09-17 实测)

**用户决定**: "我这还是把 libm 的函数都打开吧, **在初期移植代码有个兜底**, 以后把 libc libm libgcc 性能比较相关的函数全部在 `op_GATE()` 实现"。

| 检查项 | 实测结果 |
| --- | --- |
| 规模 | `third_party/musl/src/math` 共 **232 个 `.c`** |
| 能否编 (无 A/C) | 抽编 10 个代表 (`sqrt/pow/sin/exp/fma/log/trunc` + **`sqrtl/powl/sinl`**) ⇒ **10/10 成功**; ELF 属性 `rv32i2p1_m2p0_zmmul1p0` ⇒ **无 `a`、无 `c`** ✅ |
| 软浮点依赖 | 抽样中 **3 个引用 binary128 (tf) 例程** (`__addtf3`/`__subtf3`/`__multf3`/`__extenddftf2`/`__trunctfdf2`/`__lttf2`) |
| **libgcc 是否齐全** | ✅ **逐个核对无缺失**: `__adddf3 __subdf3 __muldf3 __divdf3 __extendsfdf2 __truncdfsf2 __floatsidf __fixdfsi __addtf3 __multf3 __divtf3 __extenddftf2 __trunctdf2 __floatsitf __fixtfsi __gtdf2 __lttf2 __clzsi2 …` |
| **唯一硬前提** | 链接**必须带 `libgcc`**: `X4C_TOOLCHAIN_LDEXEFLAGS += -nostartfiles -Wl,-nostdlib -nostdlib` ⇒ 默认不会拉 libgcc, 而它是软浮点例程的唯一来源。若看到 `undefined reference to '__adddf3'` 一类错误, 就是这里 |
| `fenv` | ✅ 软浮点下**是空实现**: `riscv32/fenv.S` **整个文件**包在 `#ifdef __riscv_flen` 里 ⇒ 编出来是空的 (不碰 `fflags`/`frcsr`, 与"VM 无 F/D"自洽); `riscv32/fenv-sf.c` 只是 `#include "../fenv.c"` |
| `.S` 支持 | ✅ 构建系统有独立汇编规则 (`Build/core/build-binary.mk:118` 的 `x4c_MODULE_ASM_SOURCE_FILES`) |
| 未定义符号里非 libgcc 的部分 | `memcpy`/`fabs`/`pow`/`scalbn` (musl 自己的 string/math) 与 `__cos`/`__sin`/`__exp_data`/`__rem_pio2*`/`__math_*` (musl `src/math` 内部) ⇒ 整段打开后**自洽** |

⇒ **可以直接把那两段注释打开**, 只要记住**链接带 `libgcc`**。
⇒ 性能提醒 (与你的规划一致): 这些函数在解释器里跑会很慢 (软浮点 = 成百上千条解释指令), 作为"初期兜底"完全合理; 以后按 `op_GATE()` 迁移时, 优先挑**热点** (与 `libc` 的 `memcpy/memmove/strlen`、`libgcc` 的 `__*df3/__*tf3` 一起排序)。

## 7. 复现

```bash
cd /cygdrive/x/MyWork/ATOMIC/atomic && make -j8          # 现在 rc=0
# 纯度检查 (应全为 0):
X:/Machine/ATOMIC/rv32im-atomic-rockey/bin/rv32im-atomic-rockey-objdump \
    -d X:/MyWork/ATOMIC/.bin/.lib/rv32im-atomic-rockey-release/libmusl.a | grep -cE 'lr\.w|sc\.w|amo[a-z]+\.w'
# ISA 属性 (应无 a/c):
X:/Machine/ATOMIC/rv32im-atomic-rockey/bin/rv32im-atomic-rockey-readelf \
    -A X:/MyWork/ATOMIC/.bin/.obj/rv32im-atomic-rockey-release/musl/strlen.o | grep Tag_RISCV_arch
```

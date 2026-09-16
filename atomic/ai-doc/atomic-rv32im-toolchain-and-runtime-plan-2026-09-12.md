# ATOMC / RV32IM：工具链与运行时构建方案（第一版）

日期 2026-09-12。状态：**方案待确认，尚未实现**。本文只记录决策、事实来源与下一步，不含已生效的代码改动。

---

## 0. 已确定的决策

| 项 | 结论 | 来源 |
| --- | --- | --- |
| 目标 ISA | 仅 **RV32IM** freestanding；不用 A/F/D/C | 用户 |
| 工具链 | 自行编译 `riscv-gnu-toolchain` | 用户 |
| 构建宿主 | 工具链与 ATOMC 世界都在 **WSL/Linux** 侧 make | 用户 |
| 基准版本 | 超项目 tag **`2026.06.06`**（与 `2026.06.05` 同为超项目上带签名的两个版本） | 用户 |
| 维护分支 | 超项目分支 **`rLANG-2026.06.06`**；精简出的最小子集是该分支的结构性属性 | 用户 |
| 源码获取 | 本地镜像仓 + `url.<base>.insteadOf`；**`.gitmodules` 保持上游 URL 不变** | 用户 + 本轮 |
| 主工作区 | **WSL `~/MyWork/RockeyDongle`**；Windows 检出 `X:\MyWork\RockeyDongle` 仅作交叉验证 | 用户 |
| 提交规范 | `feat/AGINX/*` 分支**无签名提交**（须显式 `--no-gpg-sign`，因该仓 `commit.gpgsign = true`） | 用户 |
| libgcc | 自写整数运行时 `libeabi-rv32im` + vendor 钉版 GCC soft-fp `libsoftfp-rv32im` | 用户（选 A） |
| libc | **musl 源码抽子集**，不用它自带的构建系统 | 用户 |
| OS 接口 | **`ecall` 调用门**（2026-09-12 修订，取代原"地址 0 处 2KB 窗口"）；**复用 Linux syscall 号、只实现最基础子集、输入输出基本 mock**；**仅 M 模式**（`mcause = 11`），明确放弃"gate 不可读" | 用户 |
| 程序分层 | ATOMC 程序分 **4 级**：0 对接 LIMIT、3 对接 COSMO、**1/2 是我们的程序**（§4.5） | 用户 |
| 内存管理 | TLSF | 用户 |
| libm | 暂不接（固件不用浮点） | 用户（选 C） |

## 1. 工具链：只需要 3 个子模块

以下为 **tag `2026.06.06` 上的实测**（取自 WSL 侧 `~/MyWork/RISCV/riscv-gnu-toolchain`），不是推断。

该 tag 的超项目共 **12 个子模块**（`master` 上是 13，多一个 `picolibc`）。`--recursive` 会把这 12 个全拉下来；其中 **9 个与我们无关**：`glibc` / `dejagnu` / `gdb` / `qemu` / `spike` / `pk` / `llvm` / `uclibc-ng` / `newlib`。

| 子模块 | 是否必需 | 原因 | 该 tag 的 URL（实测） |
| --- | --- | --- | --- |
| `binutils` | ✅ | as/ld/objcopy/objdump/readelf/ar | `https://sourceware.org/git/binutils-gdb.git` |
| `gcc` | ✅ | cc1；**同时是 soft-fp 运行时的源码来源** | `https://github.com/gcc-mirror/gcc.git` |
| `musl` | ✅ | 构建图**不需要**它，但我们要 vendoring 其源码；上游 musl 的 `arch/riscv32` 已存在并维护至 2026-06 | `https://git.musl-libc.org/git/musl` |
| `newlib` | ❌ | **已核实 stage1 不依赖它**（见 §1.4） | `https://sourceware.org/git/newlib-cygwin.git` |
| 其余 8 个 | ❌ | 与本世界无关（上表已单列 `newlib`） | — |

> ⚠️ **该 tag 的 URL 与 `master` 不同**：`master` 上 `musl` 指向 `github.com/kraj/musl.git`、`newlib` 指向整个 `github.com/cygwin/cygwin.git`；本 tag 上 `musl` 是上游 `git.musl-libc.org/git/musl`、`newlib` 是 `sourceware.org/git/newlib-cygwin.git`。**任何镜像或子模块操作都必须用 tag 自身的 URL**，不得照 `master` 写死。

### 1.1 关键纠正：三元组用 `riscv32-unknown-elf`，**不要** `riscv32-unknown-linux-musl`

超项目的 `musl` 目标产出 `riscv32-unknown-linux-musl`，那是 **Linux** 工具链：预定义 `__linux__`/`__unix__`、默认 PIE、`--enable-tls`、specs 带动态链接器。对 freestanding 世界这是**主动有害**的（musl 源码会因此走 Linux 分支）。

因此：`--target=riscv32-unknown-elf`，且**只构建 stage1**（`build-binutils` + `build-gcc1`）。stage1 的 configure 参数就是官方的 `--with-newlib --without-headers`，**产出 gcc + libgcc，不含任何 libc**。不跑 `build-libc` / `build-gcc2`。

### 1.2 命令

现已确定基准 tag 为 `2026.06.06`、维护分支为 `rLANG-2026.06.06`。落地脚本在 `atomic/toolchain/`（见 §1.5）；下列是等价的手工步骤：

```sh
# 1) 只克隆超项目本体 @ 基准 tag —— 不要 --recursive（缺省即不取子模块）
git clone --depth 1 --branch 2026.06.06 \
    https://github.com/riscv-collab/riscv-gnu-toolchain \
    ~/MyWork/RISCV/riscv-gnu-toolchain
cd ~/MyWork/RISCV/riscv-gnu-toolchain
git switch -c rLANG-2026.06.06          # 我们的主分支

# 1b) 可选但推荐：剪枝 .gitmodules，使最小子集成为分支的结构性属性
#     sh <RockeyDongle>/atomic/toolchain/prune-submodules.sh

# 2) 显式取确定要的三个（若已剪枝，--recursive 也只会取到这三个）
git submodule update --init --depth 1 binutils gcc musl

# 3) 宿主依赖
sudo apt-get install -y build-essential autoconf automake autotools-dev curl \
    python3 libmpc-dev libmpfr-dev libgmp-dev gawk bison flex texinfo gperf \
    libtool patchutils bc zlib1g-dev libexpat-dev ninja-build git cmake

# 4) 配置：rv32im + ilp32 + medlow；关 multilib（构建时间从 2h+ 降到半小时级）
PREFIX="$HOME/opt/riscv32im"
./configure --prefix="$PREFIX" \
    --target=riscv32-unknown-elf \
    --with-arch=rv32im --with-abi=ilp32 --with-cmodel=medlow \
    --disable-multilib

# 5) 只构建 binutils + gcc(stage1) + libgcc —— 不含 libc
make -j"$(nproc)" build-binutils build-gcc1
```

`--disable-multilib` 不是可选优化：默认 `--enable-multilib` 会为几十个 arch/abi 组合各编一份 libgcc。关掉后 `rv32im/ilp32` 即为唯一默认，`-march`/`-mabi` 也无需每次显式传（但仍建议显式传，便于审计）。

注意：`--disable-nls` / `--disable-bootstrap` / `--enable-languages=c` / `--disable-libatomic` 等**已写死在 `Makefile.in` 的 stage1 规则里**，不必在超项目 configure 再传一遍。

### 1.3 验收（必须全部通过）

```sh
"$PREFIX"/bin/riscv32-unknown-elf-gcc -march=rv32im -mabi=ilp32 \
    -print-multi-lib -print-libgcc-file-name

# 此行必须【没有】 __linux__ / __unix__ —— 这是三元组选对了的判据
"$PREFIX"/bin/riscv32-unknown-elf-gcc -march=rv32im -mabi=ilp32 -dM -E - </dev/null \
    | grep -E 'riscv|linux|unix'

"$PREFIX"/bin/riscv32-unknown-elf-gcc -march=rv32im -mabi=ilp32 -dM -E - </dev/null \
    | grep -E '__riscv_(xlen|m|a|f|d|c|div|mul)__'
```

### 1.4 关于 `newlib` 前置：**已核实——stage1 不依赖它**

本文初版连续判错两次（先"会需要"、后"很可能不需要"）。**现以 tag 上的实测为准**（在 WSL 侧的 clone 上执行）：

```sh
$ grep -n 'build-gcc-newlib-stage1:' -A 4 Makefile.in
751:stamps/build-gcc-newlib-stage1: $(GCC_SRCDIR) $(GCC_SRC_GIT) stamps/build-binutils-newlib
752-	if test -f $</contrib/download_prerequisites && test "@NEED_GCC_EXTERNAL_LIBRARIES@" = "true"; then cd $< && ./contrib/download_prerequisites; fi
753-	rm -rf $@ $(notdir $@)
754-	mkdir $(notdir $@)
755-	cd $(notdir $@) && $</configure \
```

前置只有 `$(GCC_SRCDIR)`（+ 其 `.git`）与 `stamps/build-binutils-newlib`，**没有 `$(NEWLIB_SRCDIR)`**
⇒ `make build-binutils build-gcc1` **只会取 `binutils` 与 `gcc`，不会下载 newlib**。`KEEP` 保持三项即可。

### 1.5 最小子集与本地镜像（落地在 `atomic/toolchain/`）

既然已在超项目上维护分支 `rLANG-2026.06.06`，最小子集就不应靠每次传 allow-list，而应**成为分支的结构性属性**：在该分支上重写 `.gitmodules`，只保留 `binutils`/`gcc`/`musl`，其余 gitlink 从索引移除 ⇒ 即使有人 `--recursive` 也只可能取到这三个。

| 脚本 | 作用 |
| --- | --- |
| `atomic/toolchain/prune-submodules.sh` | 在 `rLANG-2026.06.06` 分支上剪枝 `.gitmodules`（默认不动目录、不提交，便于按惯例自行决定签名与否） |
| `atomic/toolchain/mirror-riscv32im.sh` | 建本地镜像仓（**精确到 tag 上 pin 的 commit**），并打印需执行的 `insteadOf` 配置；URL 与 pin 全部从 tag 推导 |
| `atomic/toolchain/fetch-riscv32im.sh` | 超项目本体 shallow 克隆 + 审计报告 +（`--build`）构建 stage1 与验收 |

关键约束：**`.gitmodules` 里保持上游 URL 不变**，用 git 的 `url.<base>.insteadOf` 重定向到本地镜像 —— 否则镜像地址会被提交进分支，他人/CI 就再也无法用上游地址克隆。细节见 `atomic/toolchain/README.md`。

### 1.6 已实测取得的 pin（tag `2026.06.06` 的 gitlink）

| 组件 | pin（commit） | 版本（已核实） | tag 上的跟踪分支 |
| --- | --- | --- | --- |
| `binutils` | `49d4d3fafa4ec4ff5a3460d91d5b1ed5286487db` | **2.46** | `binutils-2_46-branch` |
| `gcc` | `6afcc4f6da931eb93f3ab001a0dd9650ea71d1ea` | **16.1.0** | `releases/gcc-16` |
| `musl` | `0784374d561435f7c787a555aeab8ede699ed298` | **1.2.5** | `master` |
| （`newlib`，不取，仅备案） | `8ba4275b83ec27529f67e0d477611fa6d8d6e6bd` | — | `master` |

版本取自 pin 上的 `gcc/BASE-VER` = `16.1.0`、`musl/VERSION` = `1.2.5`；binutils 由分支名 `binutils-2_46-branch` 判定为 2.46 系列。

**已核实：`musl` pin `0784374d…` 含 `arch/riscv32`** —— 用 git 协议取该 pin 的对象后 `git ls-tree` 得 21 个文件（`bits/syscall.h.in`、`syscall_arch.h`、`pthread_arch.h`、`crt_arch.h`、`bits/fenv.h`、`reloc.h` 等），riscv32 可用。

> **取证教训**：cgit 的 `plain/<path>?id=<sha>` 取法在本例**不可靠**（连 `VERSION`/`Makefile` 都返回 404），
> 差点让我得出"该 pin 无 riscv32"的错误结论。是**对照组（同时测一个确定存在的文件）**暴露了 URL 取法的问题；
> 最终以 git 协议取对象为准。**任何"某文件不存在 / 某功能不可用"的结论，都应先做对照实验。**

## 2. libgcc：拆成两个库

RV32IM 的整数运行时很小（M 扩展已提供 `mul`/`div`/`rem`），大头是 64 位运算与软浮点。

| 库 | 内容 | 来源 | 性质 |
| --- | --- | --- | --- |
| `libeabi-rv32im` | `__muldi3`/`__divdi3`/`__udivdi3`/`__moddi3`/`__umoddi3`、`__ashldi3`/`__ashrdi3`/`__lshrdi3`、`__clzsi2`/`__ctzsi2`/`__clzdi2`/`__ctzdi2`、`__ffssi2`、`__bswapsi2`，以及 `__aeabi_*` 风格的内存/移动例程 | **自写** | 小、可审计 |
| `libsoftfp-rv32im` | `__adddf3`/`__muldf3`/`__divdf3`/`__extendsfdf2`/`__fixdfsi`/… 全套软浮点 | **vendor 钉版 GCC 的 `libgcc/soft-fp`**，我们自行构建 | 大、但只需钉版本 |

- 先例：`MCU/RockeyARM/libeabi-cortexm0/` 已是"独立维护 libgcc"的成熟范式（手写 ARM RTABI 汇编，由 `MCU/RockeyARM/xModule.mk` 作为静态库 `aeabi_cortexm0` 编入、`-nostdlib` 链接）。`libeabi-rv32im` 照此建立即可，**不必新发明组织方式**。
- 许可：libgcc 带 **GCC Runtime Library Exception**，静态链接不产生 copyleft 传染；`libsoftfp-rv32im` 需在 `THIRD_PARTY_NOTICES` 中登记。
- 本仓许可为 MIT（见 `LICENSE`），musl 亦为 MIT，兼容。

## 3. musl：源码来源与移植面（**2026-09-12 因改用 `ecall` 而大幅缩小**）

超项目自带的 `musl` 子模块作为**唯一钉版源码来源**（该 tag 上是上游 `https://git.musl-libc.org/git/musl`、版本 **1.2.5** —— 注意 `master` 上是 `kraj/musl`，不可混用）。该子模块的用途是构建 Linux 版 musl，**我们不链接它的产物**，只取源码。

musl 是 Linux libc（假设 syscall / `_start` / TLS / `/proc`）。原计划是"vendor 源码 + 抽子集 + 自写 OS glue 替身"；**改用 `ecall` 之后这一成本大幅下降**：musl 的 `arch/riscv32/syscall_arch.h` 本身就是 `ecall` + `a7`（见 §4.1），我们的 trap 分发器可直接服务 Linux syscall 号，**musl 的 syscall 层无需改动**。

于是移植面收缩为：

1. **TLS / `errno`**：musl 的 `errno` 经 `__pthread_self()` 住在 TLS 里 ⇒ 裸机上给一个**静态 TLS 块并设置 `tp`**（musl 的 `crt_arch.h` 不设 `tp`，见 §4.2）。这是剩下最实的一块。
2. **`src/malloc/*` 必须排除**，交给 TLSF（否则符号冲突）。相应地 `brk`/`mmap`/`munmap` 号要么不实现、要么接到 TLSF。
3. **syscall 号按需实现**：`write`/`read`/`close`/`exit`/`clock_gettime` 等直接做；`clone`（线程）、`futex`、`__set_thread_area` 等**返回 `-ENOSYS` 或不提供**（单线程世界）。**无需删改 musl 源码**，支持面完全由分发器决定。
4. **`src/fenv`**：该 pin（1.2.5）**不含** 2026-03-20 的软浮点修正；其 riscv32 `bits/fenv.h` 存在，但实现走 CSR（`frcsr`/`fscsr`），无 F 扩展时不可用。本阶段不接 libm/fenv 故无风险；**日后接 libm 必须换更新的 musl 或自行打补丁**。
5. **`src/stdio` 的写后端**：走 `write` 号即可（由分发器落到 UART / semihosting），**不必改 musl**。

可保留且无需改动：`src/string`、`src/ctype`、`src/locale`(C)、`src/multibyte`、`src/stdlib`（数值转换/`qsort`/`bsearch`）、`src/stdio` 全部、`src/internal`。`src/math`(libm) 本阶段不接。

**构建方式需重新评估**：先前反对用 musl 自带 `configure`/`make` 的理由是"它假设 Linux 目标与完整 syscall 层，补丁量大"；现在 syscall 层不动，**用它的构建系统直接产 `libc.a` 反而可能更省事**（只需额外给它 start/链接约定）。此项待 §4.4 的特权模型定案后再选型。

## 4. 调用门：**改用 `ecall`**（2026-09-12 修订）

> 原方案（地址 0 处 2KB 窗口、`jalr rd, imm(x0)` 调用 gate、只可执行不可读）**已作废**，理由见 4.3。
> 本节记录新方案、它带来的新增件、以及随之而来的两个待定项。

### 4.1 为什么 `ecall` 更好

**① musl 的 syscall 层可以一行不改 —— 这是最大的收益。**
该 pin（musl 1.2.5）的 `arch/riscv32/syscall_arch.h` 原文就是：

```c
#define __asm_syscall(...) \
	__asm__ __volatile__ ("ecall\n\t" : "=r"(a0) : __VA_ARGS__ : "memory"); \
	return a0;

static inline long __syscall3(long n, long a, long b, long c)
{
	register long a7 __asm__("a7") = n;
	register long a0 __asm__("a0") = a;
	register long a1 __asm__("a1") = b;
	register long a2 __asm__("a2") = c;
	__asm_syscall("r"(a7), "0"(a0), "r"(a1), "r"(a2))
}
```

即 **`ecall` + `a7` = 号、`a0`–`a5` = 参数、`a0` = 返回** —— 与 Linux syscall ABI 完全一致。
于是"用 musl 大部分"的成本从 **"抽取子集 + 自写 syscall/TLS/fenv shim"** 塌缩为 **"写一个 M 模式 trap 分发器"**：
只实现我们愿意支持的号，其余一律返回 `-ENOSYS`。§3 的移植清单因此大幅缩短。

**② 调试与工具生态。**

- QEMU：任何 `ecall` 都会陷入，`-M virt -bios <fw> -s -S` + gdb 即可源码级调试；
- 采用 Linux syscall ABI 后，**同一个二进制还能在 `qemu-riscv32`（user mode）下跑**，多一个对照 oracle；
- 需要主机 I/O 时可选 RISC-V semihosting（QEMU `-semihosting`）或 HTIF（spike/pk），都不必先写 UART 驱动。

**③ 它是架构钦定的越权方式。** `ecall` + `mtvec` + `mret` 是 RISC-V 规范的跨特权级机制。若日后要恢复
"gate 代码不可读"的隔离，`ecall`（U 模式陷入 M 模式，`mcause=8`）正是标准做法 —— 比低地址窗口更正当、更可移植。

**④ "最简代码"的性质并未丢失。** `ecall` 是固定 4 字节（`0x00000073`），同样不需要物化地址；且它比
`jalr rd, imm(x0)` 更容易被工具识别，跨架构转译时也只是"识别一个固定 opcode + 一套寄存器约定"。

### 4.2 `ecall` 带来的新增件（必须做）

- **trap 基础设施**：`mtvec` 设置、trap 帧保存/恢复（caller-saved 寄存器 + `mepc`/`mcause`/`mtval`）、
  `mret`、可重入与中断屏蔽策略。
- **号段分发器**：按 `a7` 分发；未实现号返回 `-ENOSYS`；越界/非法参数的行为需定义
  （对齐 `VM_t::zero_ = SIGSEGV` 那种语义）。
- **`tp`（TLS）**：musl 的 `errno` 经 `__pthread_self()` 住在 TLS 里，裸机上必须由我们给一个静态 TLS 块并设置 `tp`。
  注意 musl 的 `arch/riscv32/crt_arch.h` **只设了 `gp` 与 `sp`，没有设 `tp`**（`gp` 那段带 `.option norelax`，**必须照抄**）——
  这是我们要补的。该文件原文：`lla gp, __global_pointer$` / `mv a0, sp` / `lla a1, _DYNAMIC` / `tail _start_c`。
- **`_start` 与最小启动**：可据 `crt_arch.h` 改写为：设 `gp`（`norelax`）、清 `.bss`、拷 `.data`、设 `tp`、设 `mtvec`，再进 `_start_c`。
  栈顶由链接脚本给。

### 4.3 原方案作废的原因（以及它真正丢掉的东西）

- **"只可执行、不可读"在 M 模式下无法实现**：PMP 不约束 M 模式自身，该性质必须依赖 U 模式（或 S 模式）+ PMP。
  也就是说，这条需求**本来就该走 `ecall`**，而不是靠低地址窗口。
- 原方案想省的（trap 帧、特权级）确实省掉了，但代价是失去全部现成工具与 ABI 复用；而 `ecall` 的固定开销很小。
- **仍然成立、予以保留的部分**：gate 代码按 LIMIT 约束书写（不许 `.rodata`、不许查表、栈预算小）——
  那与"用哪种陷入机制"无关，与 `base/src/data.cc` 的 CRC "限制正向门控"范本同源。

### 4.4 ABI 与特权模型：**已定**（2026-09-12）

| 项 | 结论 |
| --- | --- |
| 调用门 ABI | **复用 Linux syscall 号**（沿用 `a7` + `a0`–`a5` 约定），但**只实现最基础的一部分**，且其**输入输出基本是 mock** |
| 特权模型 | **仅 M 模式**（`ecall` 自陷，`mcause = 11`）。**明确放弃**"gate 代码只可执行、不可读"这条需求 |
| 未支持号 | 返回 `-ENOSYS`。与"mock 一部分号"并存：**mock 的号返回成功语义的假数据**，未支持的号返回 `-ENOSYS` |

> **M-only 的直接后果（须知悉）**：§4.5 的 4 级分层因此是**纯软件约定**，没有任何硬件强制；
> 级别之间的隔离强度只取决于分发器自身的检查，**不能当作安全边界**。
> 若日后需要真正的边界，就得回到 U 模式 + PMP —— 那条路 `ecall`（`mcause=8`）已经准备好了，属增量而非返工。

### 4.5 ATOMC 的 4 级程序模型（用户 2026-09-12 说明）

ATOMC 的程序分 **4 个级别**：

| 级别 | 定位 |
| --- | --- |
| 0 | **对接 LIMIT**（受限世界 / ukey 侧） |
| 1、2 | **我们的程序实际运行于此**（两级） |
| 3 | **对接 COSMO** |

⇒ 调用门不只是"syscall"，而是**跨级别（以及跨世界）的桥**：级别 0 那侧通到 LIMIT，级别 3 那侧通到 COSMO。

**命名提醒（勿混淆）**：仓库里已有的 `PERMISSION`（`Interface/dongle.h` 第 61 行，
`enum class PERMISSION : uint8_t { kAnonymous, kNormal, kAdministrator }`）是 **ukey 设备侧的 3 值 PIN/角色模型**，
与本节的 **4 级程序分层不是一回事**，不要复用同一套名字。
（另有 `MCU/project.mk` 里的 `-DrLANG_CONFIG_MIMIMAL_LEVEL=9` —— 注意拼写是 `MIMIMAL` —— 属编译期/日志级别，亦无关。）

**实现分发器前需定（4 项）**：

1. **级别如何表达与选择**：`a7` 已被号占用，"目标是哪一级"是 ①按号段划分（号 → 级别固定映射）、
   ②额外寄存器/参数显式给级别、还是 ③每级一张独立门表？对分发器结构影响很大。
2. **谁在哪个级别**：级别是**编译期固定**（每个程序映像标注自己的级别），还是**运行期可变**（可升/降级）？
3. **mock 落在哪**：mock 的输入输出在 **ATOMC 侧 stub**，还是在**宿主/模拟器侧**
   （对应 `__EMULATOR__` / `foobar` 板与 `Web/Emulator`）？这决定 mock 能否被真机之外的东西替换、测试怎么摆。
4. **与 LIMIT 既有服务面对齐**：`Interface/script.cc` 已有 `OpFuncBasic`/`OpFuncDataFile`/`OpFuncRSA`/
   `OpFuncP256`/`OpFuncSM2`/`OpFuncDigest`/`…` 一族操作。级别 0 的号是否应直接与这些族对齐，还是另立一套？

> 附：`ecall` 的 `mcause` —— M 模式发起为 **11**（Environment call from M-mode），U 模式陷入 M 模式为 **8**，S 模式为 **9**。
> 我们需要的 Linux syscall 号（该 pin 实测）：`write=64`、`read=63`、`close=57`、`openat=56`、`exit=93`、
> `exit_group=94`、`brk=214`、`munmap=215`、`nanosleep=101`、`set_tid_address=96`、`set_robust_list=99`、
> `rt_sigaction=134`、`rt_sigprocmask=135`、`getpid=172`。

## 5. TLSF

- 单一连续 arena；链接脚本导出 `__heap_start` / `__heap_end`，初始化时一次 `tlsf_create_with_pool`。
- **`tlsf_ALIGN_SIZE` 必须 ≥ 8**：ilp32 下 `long long`/`double` 要求 8 字节对齐，而默认 `sizeof(void*)` = 4 会静默产生错位块。pool 起始地址同样要 8 字节对齐。
- 包装 `malloc`/`free`/`realloc`/`calloc`/`memalign`/`posix_memalign`/`aligned_alloc`/`malloc_usable_size`。
- 提供 `tlsf_lock`/`tlsf_unlock` 钩子：单线程可 no-op；若中断上下文会分配则需关中断临界区。
- 许可需核实后登记 `THIRD_PARTY_NOTICES`。

## 6. 构建系统接入

`Build/config/atomic.conf` 当前**只有一行 `$(error TODO ....)`**，且位于共享 submodule `Build/`（`oLiangLi/build`）内。两条路：

- **A（正统）**：直接写回上游 `Build/config/atomic.conf` —— ATOMC 从此是一个正式世界。
- **B（先原型）**：本仓 `atomic/atomic.conf` + `X4C_BUILD_LOCAL_CONFIG` 指向它。`Build/Main.mk` 第 38–44 行已支持该变量，可整体替换标准 config 而不碰 submodule。

建议 **先 B 跑通、稳定后回流 A** —— 与本仓既有的"先 overlay 后回流上游"工作方式一致，也避免在共享仓里反复改动。

另需：`MCU/project.mk` 增加 ATOMC 板级分支、`project.local.mk` 增加 ATOMC 世界参数（对齐 ARM 侧的 `X4C_UNWIND_TABLE_CFLAGS :=` 等做法）。

## 7. 目录归属（**待用户确认**）

| 候选 | 用途 | 现状 |
| --- | --- | --- |
| `MCU/ATOMC/` | 板级/固件侧，对齐 `MCU/RockeyARM/`：`start.S`、`linker.ld`、`xModule.mk`、gate 汇编、predef | 不存在，需新建 |
| `atomic/` | 本仓已建的空占位（`Makefile`、`README.md` 均 0 字节，已 staged 未提交） | 用途待定义 |
| `Build/tools/ATOMC/` | ATOMC 世界专属工具 | 现有占位 `README.md`；属共享 submodule |
| vendor 源码（musl/tlsf/soft-fp） | 建议 `third_party/`（已存在）或 WSL 前缀 + 钉版获取脚本 | 待定 |

`cosmos/` 同样是 0 字节占位。`atomic/` 与 `cosmos/` 的定位需要明确后再落文件，避免放错层。

## 8. 备选 B：不经超项目 Makefile

若 §1.4 确认 newlib 前置会被拉取、且不希望如此，可直接驱动两个子模块各自的 configure（这正是超项目 stage1 规则的做法，只是换成 elf 三元组）：

```sh
mkdir -p build-binutils && cd build-binutils
../binutils/configure --target=riscv32-unknown-elf --prefix="$PREFIX" \
    --with-arch=rv32im --with-abi=ilp32 --disable-multilib --disable-nls \
    --disable-werror --disable-gdb --disable-sim --disable-libdecnumber --disable-readline
make -j"$(nproc)" && make install

mkdir -p ../build-gcc && cd ../build-gcc
../gcc/configure --target=riscv32-unknown-elf --prefix="$PREFIX" \
    --with-arch=rv32im --with-abi=ilp32 --with-cmodel=medlow \
    --disable-multilib --with-newlib --without-headers --disable-shared \
    --disable-threads --enable-languages=c --disable-libssp --disable-libquadmath \
    --disable-libatomic --disable-libgomp --disable-libmudflap --disable-nls \
    --disable-bootstrap
make -j"$(nproc)" all-gcc && make install-gcc
make -j"$(nproc)" all-target-libgcc && make install-target-libgcc
```

代价：GCC 需要 `gmp`/`mpfr`/`mpc`/`isl`（第 3 步的 apt 包已覆盖）。收益：完全不碰超项目 Makefile，且 `--without-headers` 语义一眼可见。

## 9. 事实来源

- 基准 tag **`2026.06.06`**（与 `2026.06.05` 同为超项目上带签名的版本）：由用户确认。
  事实主取自 WSL 侧 `~/MyWork/RISCV/riscv-gnu-toolchain` 的本地实测（`.gitmodules` 条目、
  `Makefile.in` 的 stage1 规则、各子模块 gitlink pin），并由 Windows 侧网络复核（见 §11），
  故 §1 / §1.4 / §1.6 均为实测而非推断。
- musl 有 `arch/riscv32` 且维护至 2026-06：
  <https://git.musl-libc.org/cgit/musl/tree/arch> 、 <https://git.musl-libc.org/cgit/musl/log/arch/riscv32>
- soft-float 的 fenv 处理（若日后接 libm 必须钉在此提交之后）：
  <https://git.musl-libc.org/cgit/musl/commit/arch/riscv32?id=1969500402bc4f80452e1c066401223a3c998f54>
- 超项目子模块清单：**以 tag `2026.06.06` 的 `.gitmodules` 为准**（`musl` = 上游 `git.musl-libc.org/git/musl`、12 个子模块）。
  `master` 的清单不同（`musl` = `kraj/musl`、`newlib` = 整个 cygwin 仓、13 个子模块），**不可混用**：
  <https://github.com/riscv-collab/riscv-gnu-toolchain/blob/master/.gitmodules>
- 超项目目标图与各 stage1 configure 参数：**tag 上实测的 `Makefile.in`** ——
  `build-binutils`、`build-gcc%`（= `stamps/build-gcc-<target>-stage%`）、
  `stamps/build-gcc-newlib-stage1`（第 751 行，前置不含 `$(NEWLIB_SRCDIR)`，见 §1.4）、
  `stamps/build-gcc-musl-stage1`
- 仓库内既有范式：`MCU/RockeyARM/libeabi-cortexm0/`（自维护运行时）、
  `base/src/data.cc`（限制正向门控）、`Build/config/arm-none-eabi.conf`（交叉 config 样板）、
  `Build/core/toolchain.mk`（CC/AS/AR/LD 规则）

## 10. 下一步

**已完成**：

- 基准 tag `2026.06.06` + 超项目分支 `rLANG-2026.06.06` 确定。
- 工作区主目录改为 **WSL 侧 `~/MyWork/RockeyDongle`**（本仓分支 `feat/AGINX/atomic-rv32im-toolchain`，按约定**无签名提交**）。
- 最小子集机制与三个落地脚本建立（`atomic/toolchain/`，见 §1.5）。
- 取自 tag 的实测事实：仅需 3 个子模块、**stage1 不依赖 newlib**、各子模块 pin（§1.4 / §1.6）。

1. **[用户]** 建本地镜像仓（`atomic/toolchain/mirror-riscv32im.sh`），并按脚本输出配置 `url.<base>.insteadOf` 重定向。
2. **[用户]** 剪枝（`prune-submodules.sh`）→ 取 3 个子模块 → 构建 stage1（`fetch-riscv32im.sh --build`），回报 §1.3 的三条验收输出。
3. **[已完成]** 版本号与 musl pin 的 riscv32 支持均已核实（§1.6），无需再跟进。
4. **[双方]** 确认 §7 目录归属，以及 `atomic/` 与 `cosmos/` 的定位。
5. **[待决]** §4.5 的 4 项：级别如何表达/选择、级别是编译期固定还是运行期可变、mock 落在 ATOMC 侧还是宿主侧、级别 0 的号是否与 LIMIT 既有 `OpFunc*` 族对齐。**这是写 trap 分发器之前必须先定的。**
6. **[待决]** 链接脚本内存布局（trap 向量位置 + 640K DRAM + heap + **静态 TLS 块**）。
7. 之后才进入实现：`atomic.conf`、`linker.ld`、`start.S`（含 `mtvec`/`tp`）、**trap 分发器**、`libeabi-rv32im`、musl 移植（§3）、TLSF 包装。

## 11. 工具链约束（工程环境，2026-09-12 确立）

| 事项 | 结论 |
| --- | --- |
| 主工作区 | **WSL 侧 `~/MyWork/RockeyDongle`**（`Ubuntu-22.04`，UNC `\\wsl.localhost\Ubuntu-22.04\...`）。Windows 检出 `X:\MyWork\RockeyDongle` 仅作交叉验证 |
| 提交规范 | `feat/AGINX/*` 分支**无签名提交**（该仓 `commit.gpgsign = true`，故必须显式 `git commit --no-gpg-sign`） |
| **文件工具无法写 WSL 树** | DSH 文件工具写 UNC 路径报 `ENOTSUP ... link`（9p 不支持其原子 rename）。回路：**在 X: 编辑暂存 → `cp /mnt/x/...` 进 WSL → 在 WSL 提交 → X: 用 `git fetch \\wsl.localhost\...` + `reset` 追平同一 SHA**（该 fetch 已实测 `exit=0`） |
| 网络 | **两侧等价**：`.wslconfig` 为 `networkingMode=mirrored`。我曾据一次失败写成"Windows 侧网络不可用"，**该结论已作废**（复核：`git ls-remote` rc=0、`raw.githubusercontent` HTTP 200）。**一次偶发失败不可当结论，必须复核** |
| HTTP 取文件 vs git 协议 | `sourceware.org` 架了 Anubis 反爬：其 HTTP `blob_plain` 对非浏览器返回挑战页，但**git 协议不受影响**（`git ls-remote https://sourceware.org/git/binutils-gdb.git` 正常）。镜像/克隆走 git 没问题 |
| **可执行位必须在 ext4 侧 chmod** | 在 NTFS（`X:`）上创建的 `.sh`，即使带 shebang，因 `core.filemode=false` 只能被记成 `100644`。已实测踩中并在 ext4 树 `chmod +x` 后提交为 `100755`。**今后新建带 `#!` 的文件，务必在 ext4 侧补 `chmod +x` 再 `git add`** |
| `wsl.exe` 继承 Windows cwd | 从 `X:\MyWork\RockeyDongle` 调 `wsl.exe` 时 Linux 侧 cwd 落在 `/mnt/x/MyWork/RockeyDongle`（**不是** WSL home 的同名路径）。**所有 wsl 调用必须显式 `cd`**，否则"校验"会跑错仓库（已实测踩中） |
| 两个检出互相独立 | `~/MyWork/RockeyDongle`（ext4）与 `X:\MyWork\RockeyDongle`（NTFS）是两棵独立检出（inode 不同、文件互不可见）；工具链 clone **只在 WSL home** |

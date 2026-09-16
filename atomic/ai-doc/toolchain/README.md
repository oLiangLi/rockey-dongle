# atomic/toolchain —— ATOMC / RV32IM 工具链获取与本地镜像

**基准**：超项目 tag `2026.06.06`（超项目分支 `rLANG-2026.06.06`，均已在本仓确认）。

本文以下事实**取自 WSL 侧 `~/MyWork/RISCV/riscv-gnu-toolchain` 的实测**（该 clone 已切到 `rLANG-2026.06.06`），不是推断。

---

## 1. 最小子集：`binutils` + `gcc` + `musl`

| 子模块 | 取？ | 依据 | 该 tag 的 URL（实测） |
| --- | --- | --- | --- |
| `binutils` | ✅ | as/ld/objcopy/objdump/readelf/ar —— 链接脚本与固件产物的唯一来源 | `https://sourceware.org/git/binutils-gdb.git` |
| `gcc` | ✅ | cc1；**同时是 soft-fp 运行时的源码来源** | `https://github.com/gcc-mirror/gcc.git` |
| `musl` | ✅ | 构建图**不需要**它，但我们要 vendoring 源码。上游 musl 的 `arch/riscv32` 已存在并维护至 2026-06 | `https://git.musl-libc.org/git/musl` |
| `newlib` | ❌ | **已核实 stage1 不依赖它**（见 §3） | `https://sourceware.org/git/newlib-cygwin.git` |
| `glibc` / `dejagnu` / `gdb` / `qemu` / `spike` / `pk` / `llvm` / `uclibc-ng` | ❌ | 与本世界无关 | — |

### ⚠️ 该 tag 的 URL 与 `master` 不同

`master` 上 `musl` 指向 `https://github.com/kraj/musl.git`、`newlib` 指向整个 `https://github.com/cygwin/cygwin.git`。
**本 tag 不是这样**：`musl` 是上游 `git.musl-libc.org/git/musl`，`newlib` 是 `sourceware.org/git/newlib-cygwin.git`。

⇒ 镜像与任何子模块操作**必须用 tag 自身的 URL**。`mirror-riscv32im.sh` 因此从 `$TAG:.gitmodules` 推导 URL 与 pin，**不写死任何地址**。

## 2. 四个层次的精简

| 层次 | 手段 | 效果 |
| --- | --- | --- |
| ① 不 `--recursive` | `git clone --depth 1 --branch <tag> --no-recurse-submodules` | 一个子模块都不下载 |
| ② 只取需要的 | `git submodule update --init --depth 1 binutils gcc musl` | 只下载 3 个 |
| ③ **剪掉声明** `prune-submodules.sh` | 在 `rLANG-2026.06.06` 分支上重写 `.gitmodules`、移除无关 gitlink | **`--recursive` 也安全**；精简成为分支的结构性属性 |
| ④ 本地镜像 `mirror-riscv32im.sh` | 本地裸仓 + `url.<base>.insteadOf` | 快、可离线、可复现 |

**③ 是重点**：已有 `rLANG-2026.06.06` 分支，剪枝后该分支**本身就是最小子集**，不必每次传 allow-list，也不会有人误 `--recursive` 把无关子模块拉下来。

**④ 的关键约束**：`.gitmodules` 里**保持上游 URL 不变**，用 git 的 `url.<base>.insteadOf` 把上游地址重定向到本地镜像。若把镜像地址写进 `.gitmodules` 并提交，这个分支就无法被他人/CI 用上游地址克隆了。

## 3. 关于 newlib：**已核实不需要**

在 tag 上实测：

```
$ grep -n 'build-gcc-newlib-stage1:' -A 4 Makefile.in
751:stamps/build-gcc-newlib-stage1: $(GCC_SRCDIR) $(GCC_SRC_GIT) stamps/build-binutils-newlib
752-	if test -f $</contrib/download_prerequisites && test "@NEED_GCC_EXTERNAL_LIBRARIES@" = "true"; then cd $< && ./contrib/download_prerequisites; fi
753-	rm -rf $@ $(notdir $@)
754-	mkdir $(notdir $@)
755-	cd $(notdir $@) && $</configure \
```

前置只有 `$(GCC_SRCDIR)`（+ 其 `.git`）与 `stamps/build-binutils-newlib`，**没有 `$(NEWLIB_SRCDIR)`**
⇒ `make build-binutils build-gcc1` 只会取 `binutils` 与 `gcc`，**不会下载 newlib**。`KEEP` 保持三项即可。

> 说明：此事本文初版连续判错两次（先"会需要"、后"很可能不需要"）。现以 tag 上实测为准，不再推断。

## 4. 用法

```sh
cd ~/MyWork/RISCV/riscv-gnu-toolchain       # 已切到 rLANG-2026.06.06

# ① 剪枝 .gitmodules 到最小子集（默认不动目录、不提交，便于复核）
sh <本目录>/prune-submodules.sh

# ② 取最小子集
git submodule update --init --depth 1 binutils gcc musl

# ③ 建立本地镜像；脚本会打印需要执行的 insteadOf 配置并做校验
sh <本目录>/mirror-riscv32im.sh

# ④ 构建 binutils + gcc(stage1) + libgcc（不含 libc）+ 验收
sh <本目录>/fetch-riscv32im.sh --build
```

关键判据（`fetch-riscv32im.sh --build` 已内置）：目标三元组必须是 **`riscv32-unknown-elf`**；
若 `-dM -E` 输出里出现 `__linux__` / `__unix__`，说明误用了 `riscv32-unknown-linux-musl`，必须纠正。

## 5. pin 表（**取自 tag 的 gitlink + pin 上的版本文件，均已核实**）

| 组件 | pin（commit） | 版本 | tag 上的跟踪分支 |
| --- | --- | --- | --- |
| 超项目 | tag `2026.06.06`；分支 `rLANG-2026.06.06` | — | — |
| `binutils` | `49d4d3fafa4ec4ff5a3460d91d5b1ed5286487db` | **2.46** | `binutils-2_46-branch` |
| `gcc` | `6afcc4f6da931eb93f3ab001a0dd9650ea71d1ea` | **16.1.0** | `releases/gcc-16` |
| `musl` | `0784374d561435f7c787a555aeab8ede699ed298` | **1.2.5** | `master` |
| （`newlib`，不取，仅备案） | `8ba4275b83ec27529f67e0d477611fa6d8d6e6bd` | — | `master` |

版本取自 pin 上的 `gcc/BASE-VER` = `16.1.0`、`musl/VERSION` = `1.2.5`；binutils 由分支名判定为 2.46 系列。
（该 clone 里 `git submodule status` 目前全部以 `-` 开头，即子模块尚未检出；上表与是否检出无关。）

## 6. 已核实 / 已知事项

| 事项 | 状态 |
| --- | --- |
| `musl` pin `0784374d…` 含 `arch/riscv32` | ✅ **已核实**：用 git 协议取该 pin 的对象后 `git ls-tree` 得 21 个文件（`bits/syscall.h.in`、`syscall_arch.h`、`pthread_arch.h`、`crt_arch.h`、`bits/fenv.h`、`reloc.h` 等） |
| `musl` pin 是否含 2026-03-20 的软浮点 fenv 修正 | ❌ **不含**（1.2.5 早于该提交）。本阶段不接 libm/fenv，风险低；**日后若要接 libm，必须换更新的 musl 或自行打补丁** |
| 各组件版本号 | ✅ 已核实，见 §5 |
| 官方 GNU tarball 与 git shallow 的体积比 | 未核实。仅作**量级**参考：直接取 binutils/gcc 官方 tarball 通常比其 git 仓小一个数量级。若体积仍是问题，可把 tarball 解到 `binutils/`、`gcc/` 两个路径下，ai-doc 方案 §8 的备选 B 照常可用；但**版本必须与 §5 的 pin 对齐** |
| 本地镜像的裸仓能否服务 pin 的 commit | 设计已按此做（按 pin 取对象 + `uploadpack.allowAnySHA1InWant` + 把 pin 挂到 `refs/heads/rLANG-pin-<tag>`），但**尚未实跑验证** |
| `sourceware.org` 的 Anubis 反爬 | 其 HTTP `blob_plain` 被挡（返回挑战页），但 **git 协议正常**（`git ls-remote https://sourceware.org/git/binutils-gdb.git` 成功）。镜像走 git，不受影响 |

> **取证纪律**：cgit 的 `plain/<path>?id=<sha>` 在本例不可靠（连 `VERSION`/`Makefile` 都返回 404），
> 差点导出"该 pin 无 riscv32"的错误结论。**凡是"文件不存在 / 功能不可用"的判断，先做对照实验。**

## 7. 未来是否保留超项目

我们只用到超项目的两样东西：**子模块的 pin 表**与**各 stage1 的 configure 参数**（`Makefile.in`）。

- 若长期只用 `--disable-multilib` 的单一 `rv32im/ilp32` 配置，ai-doc 方案 §8 备选 B（直接 configure `binutils/` + `gcc/`）可让超项目退化为纯粹的"源码容器 + pin 表"，维护面更小。
- 反之若日后需要 multilib（如同时要 `rv32im` 与 `rv32imac`），保留超项目的 Makefile 更省事。

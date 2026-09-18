# atomic/tests —— atomic (RV32IM 解释器世界) 的**宿主侧**检查

这里放的是**检查代码本身**(可运行的 .cc), 不是文档。它们的运行器在
`tools/rockey/ATOMC/ci/atomic-tests.cjs` (为什么放那儿: 按 `tools/rockey/<WORLD>/` 的既有约定,
只服务单一世界的**工具**进世界子目录; 而被检查的**代码**留在 `atomic/` 树内)。

## 怎么跑

```sh
node tools/rockey/ATOMC/ci/atomic-tests.cjs --force   # 强制跑 (等价 CI_ATOMIC=1)
make test-atomic                                      # 同上, Makefile 目标
node tools/rockey/ATOMC/ci/atomic-tests.cjs           # **默认跳过** (挂进 make ci 但不默认执行)
```

**本机 Cygwin/沙箱跑不动时的快验 (2026-09-18 新增)**:

```powershell
powershell -File tools/rockey/ATOMC/ci/verify-atomic-checks.ps1   # 用本机 MSVC 真跑三个运行期检查
```

- 为什么需要: 本机 Cygwin 的 `g++`/`bash` 会 `*** fatal error - CreateFileMapping ..., Win32 error 5.`,
  而 harness 沙箱禁止"带管道的子进程"(`spawnSync` 默认 `stdio=pipe` ⇒ EPERM) ⇒ 上面那条 node 命令
  两项都跑不了。MSVC 是原生 Windows 进程, 不经 Cygwin 共享内存。
- ⚠ 它**只做宿主侧回归**, 不替代 CI: `instantiate` 的意义是"**g++ 与 clang++ 各看一遍**",
  且 MSVC 不认 `rLANGiOPT` 的 `optimize` 属性 (base 头里会打印 `==== Only supports clang-cl ====`)。
- 实测 (2026-09-18, 本机): `exit-gate-map` 9 断言全过 / `interpreter-smoke` **97 处 CHECK 全过** /
  `gate-exit-compat` 19 用例 + 性质块全过 —— 这条路径**抓到过 4 个真缺陷** (见文件头的 `wrapBad` 重定义、
  `__builtin_add_overflow` 的 GCC 专属用法、以及 4 个把门号当状态用的用例)。

**默认跳过的原因** (`run-ci.cjs` 的 H 段, 用户 2026-09-18 定): `make ci` 会被 `.githooks` 在每次
提交/squash merge 后自动触发, 不该每次都去编 C++。要改成默认执行: `atomic-tests.cjs` 里的
`DEFAULT_SKIP` 置 `false` (一行)。

**环境缺失算跳过, 不算失败**: 判定"编译器起不来"时输出可见的 `SKIP` + 原因, 返回 0。
实测本机 Cygwin 就有 `g++ --version` 直接 `*** fatal error - CreateFileMapping …, Win32 error 5.`
的情形 ⇒ 那种情况下**既不能静默变绿, 也不该误报红**。

## 文件

| 文件 | 检查什么 | 前置 |
| --- | --- | --- |
| `instantiate.cc` | **语法期**: 显式实例化 `VM_t<Impl>` ⇒ 逼编译器检查**全部成员函数体** (模板按需实例化, 没人调用的函数体平时根本不检查) | 宿主 g++ **与** clang++ (各跑一次; clang 用来暴露 `rLANGiOPT` 的 `optimize` 属性 = GCC 专属) |
| `interpreter-smoke.cc` | **运行期**: 真 `VM_t` 上的**十规程 / 97 处 `CHECK`** (每处在循环里还会重复执行) —— 算术/访存/跳转/门/`zero` 错误通道/`TIMEDOUT`/宿主 `mm_CHK*` API/两版内存布局/hart 初值契约/周期计价/**exit GATE 判别** | 宿主 C++ 编译器 (编+链接+运行) |
| `gate-exit-compat.cc` | **运行期**: exit 门**两端相容** (18 个用例 + 门号折叠的性质 + 有符号 UB 反面断言) —— **自带 `rlLoggingWrite` stub** (它要数日志调用), 所以**不要**再给它带日志 shim (会 LNK2005); 判据: 真 `hart_t` 按 guest 公式填寄存器, 交给真 host 模板 `rLANG_op_GATE_HyperExit` 判 (含 `INT_MIN` 回绕、`a2==0` 边界) | 同上 |
| `exit-gate-map.cc` | **运行期**: **门号映射的规范** (2026-09-18 用户改版: 钳制 → 取模折叠 `(int)((uint32_t)v & 0x7fu) - 64`): 值域恒为 `[-64,63]` / 与无符号掩码实现逐点一致 (负数走**低 7 位**而非 `v % 128`) / 周期 **128** / 128 门号**全可达** / 136 个连续状态严格均匀 / 协议常量未动 | 同上 |

表里四个检查都**不需要 rv32im 交叉工具链**, 也**不属于任何构建产物**(它们检查的是 VM 的语义,
不是生成可执行文件)。手工编译的原始命令行写在各自文件头的注释里 —— 那是它们以前唯一的运行方式。
后两个都围绕 exit 门: `gate-exit-compat` 验**协议两端相容**, `exit-gate-map` 验**门号映射的规范**。

包含路径: `-I <ROOT>` (为了 `<base/base.h>`) 与 `-I <ROOT>/atomic/include`;
头文件本身用 `#include "../include/rv32im-atomic.hpp"` 这种**同树相对路径**, 与我们只改"文件在哪",
不改"每个文件的编译语义"这条原则一致。

## 还没接线的两项

| 资产 | 现状 | 缺什么 |
| --- | --- | --- |
| `atomic/ai-doc/checks/varargs/` | 真 rv32im guest ELF 端到端 (变参 8 分支, 解释器上跑通 646 拍) —— **唯一**能证明"真工具链编出的 guest 程序能在 `VM_t` 上跑"的资产 | 需要 `X:\Machine\ATOMIC\rv32im-atomic-rockey\bin` (或 `RV32IM_TOOLCHAIN`); 一条命令的入口是它自己的 `build-and-run.ps1`; 接线时建议挂成**独立目标**, 不要混进本运行器 |
| `atomic/doc/isa-check.cc` | 被 `build-library` 编成 `librockey_atomic_abi_checker.a`, **没有任何地方运行它** | 需要一个宿主板级 (它做的是一次 `Execv`); 属于"谁来跑 ABI 检查"的设计问题, 未定 |

## 与 ai-doc 的关系

原 `atomic/ai-doc/checks/` 下的三个 `.cc` (`instantiate` / `interpreter-smoke` / `gate-exit-compat`) 于 **2026-09-18** 移到这里
(可运行代码不该只躺在 "AI 文档"目录里); `exit-gate-map.cc` 是同日改版门号公式时**新增**的。
文档 (`rv32im-atomic-*`、`hyper-vm-t-issues-*`、`matrix-ldscript-*` 等) 仍留在 `atomic/ai-doc/`,
它们里面的旧路径引用**未做全量机械改写** (按既定约定: 历史文档里的路径不追改) ——
以本 README 与 `atomic/ai-doc/README.md` 的 §2.1 索引为准。

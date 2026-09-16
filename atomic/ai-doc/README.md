## atomic 相关的 AI 生成的文档放这, 同样的 /atomic/README.md 留给项目的维护者修改

---

## 1. 本次导入 (RockeyDongle → ATOMC)

- **导入日期**: 2026-09-16
- **来源仓**: `X:\MyWork\RockeyDongle` (其 WSL 侧主工作区为 `~/MyWork/RockeyDongle`)
- **来源分支**: `doc/AGINX/2026-9-13-atomic-rv32im-toolchain`
- **来源提交**: `9ab5722dcfef13da03f95e6fe9f8b6b94732a007`
- **等价性**: 本仓 `origin` 上该分支为**同一提交**, 5 个文件的 blob 逐一相同 ⇒ 两侧取用等价。
- **改动范围**: 只在 `atomic/ai-doc/` 下**新增**文件; 未改动 `atomic/` 内其它任何路径, 未改动仓内其它任何路径, 未 stage / 未 commit。

### 1.1 文件清单 (逐字节与原 blob 一致)

| 本目录 | 原路径 (来源分支) | mode | blob |
| --- | --- | --- | --- |
| `atomic-rv32im-toolchain-and-runtime-plan-2026-09-12.md` (29,162 B) | `ai-doc/atomic-rv32im-toolchain-and-runtime-plan-2026-09-12.md` | 100644 | `22bba485fa78937c37d1aa9209e9d7e635ba7e26` |
| `toolchain/README.md` (7,296 B) | `atomic/toolchain/README.md` | 100644 | `b3dc74ea457c7a698476e2c89e5264f4d1c6a0b0` |
| `toolchain/fetch-riscv32im.sh` (4,888 B) | `atomic/toolchain/fetch-riscv32im.sh` | **100755** | `e1bddac7bbb9f037008ed46667011ac23160960b` |
| `toolchain/mirror-riscv32im.sh` (4,947 B) | `atomic/toolchain/mirror-riscv32im.sh` | **100755** | `81f77bd20cb851f12462e38da9e8208093ac6610` |
| `toolchain/prune-submodules.sh` (5,636 B) | `atomic/toolchain/prune-submodules.sh` | **100755** | `74ae298eae03d5c8f351e1be10096b480e523e70` |

校验方式 (导入时已逐项跑过, 全部 MATCH):

```sh
git -C <ATOMIC> hash-object --no-filters -- atomic/ai-doc/<file>   # 应等于上表 blob
```

> ⚠️ **执行位**: 三个 `.sh` 在来源分支上是 `100755`。本机 `core.filemode=false` + NTFS ⇒ 若不先在 ext4 侧 `chmod +x` 再 `git add`, 会被记成 `100644`。来源计划文档 §11 已记录这个坑。

## 2. 建议阅读顺序

1. **`atomic-rv32im-toolchain-and-runtime-plan-2026-09-12.md`** —— 主文档, 一版完整方案 (日期 2026-09-12, 状态"方案待确认, 尚未实现")。
   - §0 决策表 (ISA / 工具链 / libgcc / libc / OS 接口 / 程序分层 / 内存管理 / libm 的逐项结论与来源)
   - §1 工具链: 只需要 `binutils` + `gcc` + `musl` 三个子模块; 三元组必须是 `riscv32-unknown-elf` (不能用 `riscv32-unknown-linux-musl`); 命令与三条验收 (§1.1–§1.3); **stage1 不依赖 newlib** 的实测依据 (§1.4); 最小子集的四层精简与本地镜像 (§1.5); pin 表 (§1.6)
   - §2 libgcc 拆成 `libeabi-rv32im` (自写) + `libsoftfp-rv32im` (vendor 钉版 GCC soft-fp)
   - §3 musl 移植面 (改用 `ecall` 后收缩为 TLS/`errno`、排除 `src/malloc` 交给 TLSF、按需实现 syscall 号、`src/fenv` 不含 2026-03-20 软浮点修正)
   - §4 调用门: `ecall` + `a7` 号段、复用 Linux syscall 号、仅 M 模式 (`mcause = 11`)、未支持号返回 `-ENOSYS`; §4.3 记原"地址 0 处 2KB 窗口"方案作废的理由
   - **§4.5 ATOMC 4 级程序模型** (0 对接 LIMIT / 1·2 我们的程序 / 3 对接 COSMO) 与"实现分发器前需定 4 项"
   - §5 TLSF (**`tlsf_ALIGN_SIZE` ≥ 8** 的 ilp32 陷阱)、§6 构建系统接入 (`atomic.conf` 的 A/B 两条路)、§7 目录归属、§8 备选 B、§9 事实来源、§10 下一步、§11 工具链/工程环境约束 (WSL 主工作区、`feat/AGINX/*` 无签名提交、`.sh` 执行位、`wsl.exe` 继承 cwd 等)
2. **`toolchain/README.md`** —— 上述 §1.5 的落地细节: 最小子集的四层精简、镜像必须用 `url.<base>.insteadOf` 而 `.gitmodules` 保持上游 URL、用法四步、pin 表与"已核实/已知事项"清单 (含取证纪律: "文件不存在/功能不可用"的判断先做对照实验)。
3. **`toolchain/*.sh`** —— 三个脚本本体 (剪枝 `.gitmodules` / 建本地镜像 / 克隆 + 构建 stage1 + 验收)。
4. **`rv32im-atomic-registers-review-2026-09-16.md`** (本仓自产, **非**导入物) —— `VM_t` 的 `reg_t`/`regs_t` 与 RV32IM + psABI 的逐项核对: 8 项一致 ✅ / 4 项待处理 (x0 未强制、pc 不在 `VM_t`、CSR 偏差未写明、布局无断言) / 参数覆盖区与 psABI 的差异 / 命名与风格建议 / 最小验证清单。
5. **`rv32im-atomic-isa-conformance-2026-09-16.md`** (本仓自产, **非**导入物) —— **整个头文件**对 RV32IM 的核对 (实测编译, g++ 13.4.0 + clang++ 20.1.8): 寄存器/宽度/门地址数学全部 **编译期证明**; 3 类 `-Wall -Werror` 缺陷 (必修, 2 处 UB + 2 处 sign-compare); RV32M 4 条边界语义 + **裁定: 算术一律不抛异常 (除零出预定义值; 浮点若支持只出 `NaN`/`INF`), 故 `SIGFPE` 不引入**, 且"勿照抄 script VM 的 SIGFPE"反例; ✅ 已裁定 **`regs.zero` = x0 即错误标志** (循环 `while (regs.zero == 0)`; 写 x0 必须丢弃、错误码只由宿主侧写、`HYPER`/`YEILD` 是可恢复挂起); ✅ 复核版 `473906f8`/`85a2db56`/`a1516e32`/`41942715` 已把 `regs`/`pc`/`cycles`/`cyc` 落进基类、写入**确定性**/**执行代价**/**async (`SIGALRM`/`SIGVTALRM`)** 三条契约、按建议把 `op_FENCE`/`op_FENCEI` 改成 **`void`**、并给 `mm_CHKCS` 补了语义注释 (含 guard-page 保证 NUL 结尾); 当前 `7ba8a5bd` 编译现状: **接口/布局档 g++ 两个档位都 rc=0** ✅ (sign-compare 已用 `^`+`u` 修好, `limb_t` 误写已回改); clang++ 因 `rLANGiOPT` 的 `optimize` 属性 (GCC 专属) 在 `-Werror` 下失败; **解释器档 (TU 里调 `Execv`) g++ 报 122 个错误 / 3 个根因** —— 见问题审查。报告 §9 给出"抓简单错误"的**最小检查环境** (两个 TU + 三条命令)。

6. **`atomic/doc/riscv-spec.pdf`** (不在本目录, 是**离线 ISA 依据**) —— 已于 2026-09-16 按用户指示把 20191213 版**升级为 Volume I: Unprivileged Architecture, Version 20260120** (Ratified, 4,580,174 B, sha256 `06BB3C23…`; 来源 <https://docs.riscv.org/reference/isa/v20260120/_attachments/riscv-unprivileged.pdf>)。**RV32IM 用户态语义自 20191213 起无实质变化** (逐条核对见一致性报告 §8), 因此这类核对**可离线**, 不必联网; 但 `mcause`/trap (Volume II) 与 psABI 调用约定**不在**这份 PDF 里, 仍需另查。
7. **`hyper-vm-t-issues-2026-09-16.md`** + **`checks/`** (本仓自产) —— **`hyper::VM_t` 问题审查**与**可运行的检查资产**: `checks/instantiate.cc` (一行显式实例化, 强制编译器检查"没人调用所以从不实例化"的全部成员函数体 —— 反面对照: 注回 2 处旧写法立刻被抓 117 个错误) 与 `checks/interpreter-smoke.cc` (自带 guest 内存与最小 IMPL 的**运行时冒烟**, **八规程 47 项断言全过**: 算术/访存/跳转/门/`zero`/`TIMEDOUT` + 宿主 API + 两版内存布局 + 兼容性 + hart 初值契约与 `Enable(pc)`)。报告结论: 初版 122 个编译错误 / 3 个根因、clang 属性、链接期的 `regs_t()` 未定义**均已修** (`inner_Execv` 已 private); **初始化契约已落地** (`hart_t()` 置 x0=`SIGQUIT` + `Enable()` 清 0 + **`Enable(libmb_t pc)` 一步"清错误状态 + 指定入口"** + `Execv` 拒收 `zero != 0`; `Enable(pc)` 的复核见报告 §2.11), **单线程/不可重入是明确取舍**、**`mm_CHK*` 的 public 是有意的**; **宿主 API 命名与语义已定稿** (`mm_CHKWR` 写 / `mm_CHKRO` 读 / `mm_CHKCS` 只读访问即可·最小权限; 均可失败即 SIGSEGV 且**由调用者检查、不修改 hart**); **内存布局已定稿 (2026-09-16 最终版; DOS 1MB 实模式图的忠实复刻)**: `0x00000-0x0FFFF` **不映射 (引用必 SIGSEGV)** / `0x10000-0x9FFFF` 程序映像 576K / `0xA0000-0xEFFFF` 可写设备区 (不存在则写忽略、读 `0x55AAFF00`) / `0xF0000-0xFFFFF` 设备只读区 (写必 SIGSEGV、读无定义; **ROM 最大 64K−16 = 65520 字节 = 与 rockey-dongle 固件同尺寸** ⇒ `0xF0000` 起 16 字节恒为 0) / `0x100000-0x10FFFF` 用户栈 (**sp = `0x10FFE0`**, 整个栈落在经典 HMA 内) — 逐段对应 DOS, ROM 末端 `0xFFFF0` 正是 x86 复位向量位; 映像 576K + 栈 64K = 640K 与 `base.h` 的 `DRAM: ~640KB` 吻合; **ROM 区"写必 SIGSEGV"顺手找回栈下护栏** (栈顶之上未映射 ⇒ 两侧都有护栏); 两处零字节兜底 (设备哨兵首字节 `0x00` + F 段前 16 字节的 0) 使 `CHKCS` 的长度检查降级为**可选**; **两个门窗口都在未映射区 ⇒ "门只可执行、不可读"由映射白拿 (计划文档 §4.3 的结论被取代)**; 报告 §4 有全部前提与实测数据; 报告 §4 另附**参考实现 + 11 项边界/布局用例**(非法地址+`size==0`、32 位无溢出写法、零页兜底三条后果等); **语法 / 代码生成 / 运行时冒烟(**八规程 47 项断言**)在当前头 `e1aaa777` 上全绿** (g++ 13.4.0 编译+链接+运行; clang++ 20.1.8 侧 `-fsyntax-only`/`-c` rc=0 —— **本机 cygwin 的 clang++ 连 `int main(){}` 都无法链接**, 驱动建临时文件即失败, 与代码无关); **P0 类问题已全部关闭/降级** (含 `limit_cycles == 0/1` 都是单步、其余寄存器交由 guest `start.S` 初始化); 仅剩一句待确认 (sp 由宿主还是 start.S 写, 建议写进 `Enable(pc)`); **`Enable(libmb_t pc)` 已复核** (报告 §2.11): 3 条待定夺项 —— 是否重置 `cyc_`/`cycles_`、入口不校验 (传 `0` ⇒ **门 0** 而非 fault)、`sp` 是否就在此写; 另有 P1/P2 与 10 项"已验证正确"。

## 3. 与当前仓状态的对照 (导入时点的观察; 未据此改动任何东西)

| 计划文档 (2026-09-12) 的结论 | 当前 ATOMIC 仓的实际状态 |
| --- | --- |
| §4: 调用门**改用 `ecall`**, "地址 0 处 2KB 窗口"方案**已作废** | `atomic/include/rv32im-atomic.hpp` 走的是**地址窗口**方案: `op_GATE(int id)` 的注释为 `pc < 0x00000800 \|\| pc >= 0xFFFFF800` ⇒ `id = (int)pc / 4` ⇒ `jalr id*4(zero)`; 且 `op_ECALL()` 返回 `SIGILL` —— **与文档方向相反**; 该分歧已于 2026-09-16 裁定为**采用地址窗口** (见 §3.1) (文档本次原样导入, 一字未改) |
| §4.5 的 4 级模型: 0 对接 LIMIT / 1·2 我们的程序 / 3 对接 COSMO | `atomic/README.md` 的"运行级别"可与之对照: level 0 = 只支持 `dongleExecv` 并绑定真实 ukey 实例; level 1 = 供 level 2 调用的库, 占一个调用门; level 2 = 绑定一组最小调用门的程序; level 3 = 同 ukey、同"调用门组合"、彼此可 lpc 的一组程序 |
| §7: `atomic/` 当时是 0 字节占位, 目录归属**待用户确认** | `atomic/` 已成形: `README.md` (设计)、`include/rv32im-atomic.hpp` (在 `machine` 命名空间内的 `hyper::VM_t`)、`doc/riscv-spec.pdf`、空的 `Makefile` / `project.mk` |
| 来源分支上有 `atomic/toolchain/` (README + 3 脚本) | 本仓 `atomic/` 下**没有** `toolchain/`; 本次按指示只导到 `atomic/ai-doc/toolchain/` |
| §6: `Build/config/atomic.conf` 只有一行 `$(error TODO ....)`; 建议**先 B** (本仓 overlay) 后 **A** (回流上游 `Build`) | 未变 (`Build/` 是 submodule `oLiangLi/build`) |
| §10 的待决项 (级别如何表达/选择、编译期固定还是运行期可变、mock 落在 ATOMC 侧还是宿主侧、级别 0 是否对齐 `OpFunc*` 族) + 链接脚本内存布局 (trap 向量 / 640K DRAM / heap / 静态 TLS 块) | 仍待决; 写 trap/gate 分发器前需先定 |
| §9/§11 的环境结论 (WSL 主工作区、`feat/AGINX/*` 无签名提交、`.sh` 执行位、`wsl.exe` 继承 cwd、HTTP 取文件 vs git 协议) | 不与具体分支绑定, 仍然适用; 本仓当前工作在 `feat/LiangLI/ATOMIC` |

### 3.1 调用门方案: **已裁定 —— 用地址窗口** (用户 2026-09-16)

- **裁定**: 调用门沿用**地址窗口** (`pc < 0x00000800 || pc >= 0xFFFFF800`), **不采用** `ecall`。
- **理由 (用户)**: `ecall` 复用 Linux syscall 号, 让"每次编译都变"这件事变得**奇怪**; 调用门用地址窗口更自然。`atomic/include/rv32im-atomic.hpp` 里 `op_ECALL()` 返回 `SIGILL`, 与本裁定一致。
- **"每次编译都不同"由谁承担 (用户 2026-09-16 追加说明; 更正本索引上一版的说法)** —— **不是**靠门号抖动, 而是靠 **`nullptr` 附近填随机数**: 用户原话"缺少的部分刚好用来实现每次编译都不同这个需求"。因此:
  - **大部分实现里, 调用门本身不发生变化** (门号默认**稳定**, 版本之间可复用同一套门约定)。
  - **只有在迫不得已时**, 才真正**违背之前的调用门约定** (让门号/门组合改变)。
  - ⇒ 本索引上一版写的"调用门本应每次编译都不兼容 / 地址窗口天然满足该性质"**不准确, 以本条为准**; `atomic/README.md` 第 20 行"调用门的序号定义是每次编译都可能不同的"说的是**能力上限**(每次编译**可以**不同), 而非要求每次编译**必然**抖动。
  - ✅ **落点已定 (2026-09-16 收口)**: "`nullptr` 附近"= **低 64K 未映射**、**引用必 SIGSEGV** ⇒ 那里**没有任何内存内容**, 所以这句随机化落在 **门号/门表** (即判据多出那两段 `id 0…63` / `id -64…-1` 的**门位分配**) 上, 不是内存字节。我早先"随机数填在 `0x000–0x0FC` 内存里"的记载**已撤回**。
- **随之作废**: 计划文档 §4 及 §4.1–§4.4 的 `ecall` 结论、"地址 0 处 2KB 窗口已作废"的表述; 以及"仅 M 模式 (`mcause = 11`)"、"放弃 gate 不可读"等针对 `ecall` 的说法 ⇒ §4.2 的 trap 基础设施 (`mtvec`/trap 帧/`mret`) **不再是必需件**。
- **不受影响**: §4.3 末尾"仍予保留"的约束 (gate 代码按 LIMIT 约束书写: 不许 `.rodata`、不许查表、栈预算小)、§4.5 的 4 级程序模型及其 4 项待决、§1 工具链、§2 libgcc、§3 musl、§5 TLSF、§6 构建接入。
- **待办 (刻意延后)**: 计划文档正文的备注**保持原样、一字不改** —— 按用户指示, 待本分支**向 master 合并后**再改那边的备注; 本次只在本索引登记裁定。
- ✅ **兼容性原则 (用户 2026-09-16)**: **不同世界的调用约定不必一致** —— LIMIT 世界"每次编译不兼容", 不需要强兼容保障 (其 SIG 值与我是否核对过平台一致性都无所谓) ⇒ "跨 VM 的 SIG 取值差异"**不是问题, 已关闭**。**但 ATOMC 不同**: "**没有必然的原因而引起不兼容是不大值得的**" ⇒ ① 自有错误码用**固定 hex** (`HYPER`/`YEILD`/`TIMEDOUT`); ② `SIG*` 用 `rLANG_ABIREQUIRE` **钉成 POSIX 值 = 承重保障**; ③ "每次编译都不同"只落在**缺少的部分** (未分配门位), 真实门号默认稳定。
  - **判别标准 (用户 2026-09-16, 见问题审查 §2.10)**: **驱动分支的取值必须跨平台一致** (`SIG*` 决定后续执行 ⇒ 钉死; ATOMC 自有码 ⇒ 固定 hex); **仅作报告用途的负 errno 允许宿主差异** ("负数值是 errno 通常就几种配置, 没什么关系的") —— 本机实测宿主 `ENOSYS=88`/`EALREADY=120` vs musl `38`/`114`, 按此标准**不构成阻塞**; 若某 guest 真用 `errno == ENOSYS` 分支, 在门实现里钉成 `-38` 即可 (一行)。
- **门地址窗口的两处细节 (2026-09-16 收口)**: 头文件判据 (`pc < 0x00000800 || pc >= 0xFFFFF800`) 比 `atomic/README.md` 第 18 行分配的窗口 (`0xFFFF'F800–0xFFFF'FF00`、`0x0000'0100–0x0000'07FF`) **更宽**: 多出 `0x000–0x0FF` 与 `0xFFFF'FF00–0xFFFF'FFFF` 两段。按 `id = (int)pc / 4`, 低窗 `id = 0…511` (多出 `id 0…63`)、高窗因 `(int)0xFFFFF800 < 0` 得**负 id** (`-512…-1`, 多出 `id -64…-1`)。
  - ① **多出那两段就是"每次编译都变的随机数"的落点** —— 是**门位分配 (门号)**, 不是内存内容: 低 64K **未映射、引用必 SIGSEGV**, 那里没有字节可填 (见上一条收口);
  - ② **两个门窗口都在未映射区** ⇒ 作为**数据**访问一律 fault, 作为 **pc** 由 VM 在取指前拦截 ⇒ **"门只可执行、不可读"由映射白拿**, 不需要 U 模式/PMP (计划文档 §4.3 的结论因此被**取代**); 同一地址的双重身份已做成断言 (`checks/interpreter-smoke.cc` 规程六)。
  - `atomic/README.md` 属维护者文件, 我未改动。
- **注 (2026-09-16)**: 上面那条 `jalr id*4(zero)` 里的 `zero` **就是 x0**; 而 x0 同时被裁定为**执行循环的错误标志** (`while (regs.zero == 0)`) ⇒ `jalr` 写入 x0 的链接地址**必须被丢弃**, 否则会破坏错误通道。详见一致性报告 §4 第 1 条。

### 3.2 仓内已存在的 ATOMC 接缝 (不是本次导入物, 但读文档时需知道)

- `base/bits/base.h`: `rLANG_WORLD_MAGIC = 0xC8C04E1F` (120 行)、`rLANG_ATOMC_WORLD_MAGIC = 0x0543CD0F` (124 行, 注释 `DRAM: ~640KB`)、`rLANG_COSMO_WORLD_MAGIC = 0x0CF4CD3F` (140 行)。`base.h` 里 C++ 下 `rLANG_ABIREQUIRE` = `static_assert`、`rLANG_DECLARE_MACHINE` = `namespace machine {` (17–29 行)。
- `atomic/include/rv32im-atomic.hpp`: `rLANG_ERROR_HYPER = 0xC8C04E1F` 与 `rLANG_WORLD_MAGIC` 相等, 并由 `rLANG_ABIREQUIRE(rLANG_WORLD_MAGIC == rLANG_ERROR_HYPER && rLANG_ERROR_YEILD == (rLANG_WORLD_MAGIC & ~3))` 钉住; `rLANG_ERROR_YEILD = rLANG_ERROR_HYPER - 3`。
- `Interface/script.h`: `RuntimeHeader::ScriptCategory::kScriptAtomic = rLANG_ATOMC_WORLD_MAGIC` (206 行) —— **ATOMC 的脚本类别早已在 ukey 侧存在**; `Interface/execute.cc` (57 行) 把它与 `kScriptBootstrap` 同路处理 (64 字节 `zero_fill_` 清零)。**这正是 §3.3 里 level 0 认识 ATOMC 的那道尾巴。**
- 计划文档 §4.5 提到的 `Interface/script.cc` 之 `OpFuncBasic` / `OpFuncDataFile` / `OpFuncRSA` / `OpFuncP256` / `OpFuncSM2` / `OpFuncDigest` 族, 是"级别 0 的号段是否与之对齐"的候选面。
- 计划文档 §4.5 的命名提醒: `Interface/dongle.h` 的 `PERMISSION` (`kAnonymous`/`kNormal`/`kAdministrator`) 是 **ukey 设备侧 3 值 PIN/角色模型**, 与 4 级程序分层**不是一回事**。

### 3.3 世界分层: **level 0 = rockey-dongle 本身** (用户 2026-09-16)

用户原话: **"rockey-dongle 是我们 atomic 的 level 0, 这正是在真实的安全世界为我们留下的一个尾巴。"**

- **分层** (与计划文档 §4.5、`atomic/README.md` 的"运行级别"三方一致): **level 0 = rockey-dongle 本身 (真实安全世界里的锚点/尾巴)** → **level 1·2 = 我们的程序 (ATOMC 世界)** → **level 3 = COSMO**; 级别之间由**调用门**连通 (见 §3.1)。
- **这道尾巴在代码里已经存在** (不是待建):
  - **对外的唯一门**: `src/app/main.cc:753` 打印 `ZION.Execv argc: %d` (其 TAG 由 `Interface/execute.cc:6` 的 `rLANG_DECLARE_MAGIC_Xs("EXECV")` 定义) ⇒ 宿主侧入口名是 **`ZION.Execv`**, 即 `atomic/README.md` 里 level 0 "只支持一个调用 `dongleExecv`" 的现有对应物。
  - **ukey 侧执行入口**: `Interface/execute.cc:84` 的 `rLANGEXPORT int rLANGAPI RockeyTrustExecutePrepare(VM_t&, void* InOutBuf, void* ExtendBuf)`。
  - **ukey 已认识 ATOMC 类别**: `Interface/script.h:206 kScriptAtomic = rLANG_ATOMC_WORLD_MAGIC` (0x0543CD0F), 由 `Interface/execute.cc:266-267` 实际设置并解密, `:57` 与 bootstrap 同路。
  - **level 0 自身的世界**: `MCU/RockeyARM/rockey_predef.h:25 rLANG_CONFIG_ENABLE_LIMIT_WORLD 1` ⇒ **level 0 就是 LIMIT_WORLD** (不许 `.rodata`、不许查表、栈预算紧)。
  - **ATOMC 侧开关尚未落地**: `rLANG_CONFIG_ENABLE_ATOMC_WORLD` 目前只出现在 `tools/rockey/ATOMC/README.md`, **代码里还没有任何使用** (已全仓检索确认)。
- **level 0 的安全公理 (代码原文, `src/app/main.cc:747-752`)**: "我们必须假定系统不依赖于任何的PIN码/PSK运行, 任何合理的验证必须发生在ukey内部; 任何出现在ukey之外的信息都是众所周知的, 即使是在可信设备下输入的PIN码, 都必须被日志记录"。
  ⇒ 这就是"尾巴"的确切含义: **ATOMC 世界自身没有任何硬件强制** (计划 §4.4: 仅 M 模式 ⇒ 4 级分层是**纯软件约定**, 不能当安全边界), **唯一真实的安全边界在 level 0 之内**。
- **对后续实现的推论**: ATOMC 侧凡是"安全"性质的判定, **不得**落在 level 1/2/3 的软件约定上, 必须回到 level 0 的门 (ukey 内) 完成; 宿主/模拟器侧的一切 (包括 mock, 见计划 §4.5 第 3 项待决) 一律视为**不可信输入**。

## 4. 刻意未导入

- 来源分支的 `atomic/README.md` 与 `cosmos/README.md`: 在那里都是 **0 字节占位**, 无内容可导。
- `tools/rockey/ATOMC/README.md`、`Build/config/atomic.conf`、`ai-context.md` 里的 ATOMC/COSMO 条目: **本仓 master 已含**, 无需导入。
- 该分支相对 master 的其余改动 (大量 `Interface/`/`Web/`/`src/` 的删除与改写): 那属于"精简 LIMIT 世界"的另一件事, 不是 atomic 上下文。

## 5. 回滚

本次只新增 5 个文件; 删除 `atomic/ai-doc/atomic-rv32im-toolchain-and-runtime-plan-2026-09-12.md` 与 `atomic/ai-doc/toolchain/`, 并把本 README 恢复到上面第 1 行, 即回到导入前状态。

## 6. 工程环境: 网络与代理 (与父目录既有约定一致)

- **约定 (用户 2026-09-16 重申)**: **网络不通时, 用 `10.20.20.124:8001` 作为代理重试一次**。此约定**早已写在父目录的 `ai-context.md`** (第 363 行 emsdk 那条"下载失败时使用"; 第 610 行"网络不通时先查既有约定(代理), 不要自创绕路") —— 本目录只沿用, 不另立一套。
- **git 已全局配置**: `http.https://github.com/.proxy = http://10.20.20.124:8001` ⇒ 对 `github.com` 的 HTTPS `clone`/`fetch`/`ls-remote` **自动走代理**, 不必手加 `-c http.proxy=`; 若某次仍失败, **整条命令重试**即可 (代理本身不稳定, 见下表)。
- **实测 (2026-09-16 18:10 前后, `curl.exe` + `git ls-remote`)**:

| 目标 | 直连 | 经代理 `10.20.20.124:8001` |
| --- | --- | --- |
| `github.com` | ✗ `Recv failure: Connection was reset` (×3, 0.2–0.3s) | ✗ 不稳定: 3 次分别 reset / 20s 超时 / TLS 握手失败 (此前另有一次 200, 1.6s) |
| `raw.githubusercontent.com` | ✓ 200 | ✓ 200 |
| `sourceware.org` (binutils-gdb) | ✓ 200 (6.3s) | ✓ 200 (2.3s) |
| `git.musl-libc.org` (musl) | ✓ 200 (9.0s) | ✓ 200 (7.6s) |

  ⇒ 本网络的瓶颈是 **`github.com` 本身** (直连被重置), 代理能通但**时好时坏**; ATOMC 工具链的另外几处来源 (sourceware / musl / raw.githubusercontent) 直连即可用。
- **纠正一处旧证据**: `ai-context.md` 第 610 行用 `git ls-remote https://github.com/oLiangLi/base` 作为"代理有效"的实证 —— 该命令**现在证明不了任何事**: 全局 `url.*.insteadOf` 会先把它改写成内网 SSH 镜像 (`ssh://git@home.rlang.xyz:30009/rlang.xyz/base.git`; `GIT_TRACE=1` 已确认实际联系的是 `home.rlang.xyz`), 所以**不走代理也 rc=0**。要验证代理必须换用**不在 insteadOf 名单**里的仓 (本次用 `github.com/riscv-collab/riscv-gnu-toolchain`, 即 ATOMC 工具链的真实目标)。
- **本会话工具侧限制**: 内置 `web_fetch` 没有代理开关, 且曾对 `github.com` / `raw.githubusercontent.com` 失败 (同一时刻 `curl` 直连返回 200) ⇒ 规程: **失败先原样重试一次**; 仍失败则改用 `curl` (先直连、再代理) 取内容后阅读。
- 顺带记录: Windows 侧 `npm config get proxy` / `https-proxy` 目前都是 `null` (第 546 行"npm 的 proxy/https-proxy 一直就是该值"在当前这台机器上已不成立, 可能只在 WSL 侧配过)。




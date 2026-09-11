# base/ + Build/ 上游对比与可合并清单(2026-09-11)

> 依据:`/.bin/ai-ref-code/`(用户提供的上游参考树, **自带 .git**)。
> 结论:**分叉点 base=`c25ac21d`(2025-11-07)、build=`d5be0e5f`(2025-11-07)**;
> 本仓 = 该快照的**裁剪版**(去掉 Web/grammar/scanner/tests/minimal-world/日志栈回溯/CRC 表等)
> **+ 少量本地修复**;上游在此之后有 8 个月的通用改进可挑。
> 两侧都有值得合并的东西,下面按"上游→本仓"与"本仓→上游"分组。

## 1. 规模与总览

| 树 | 上游 HEAD | 分叉点 | 共同文件 | 相同 | 有差异 | 仅上游 | 仅本地 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `base/` | `1d339f3` 2026-06-18 "准备 v1.1.0.0 发布" | `c25ac21d` 2025-11-07 | 14 | 6 | 8 | 77(含 `.git`/Web/grammar/scanner/tests) | 0 |
| `build/` | `32cc27c` 2026-03-12 "update jsCipher.js" | `d5be0e5f` 2025-11-07 | 24 | 16 | 8 | 32(含 `.git`/html) | 7 |

- 本仓 `base/` 只 vendor 了 14 个文件(`base.h`、`xModule.mk`、`bits/base.h`、`grammar/*`、`node_hook/*`、`scanner/*`、`src/{base,crypto,data,log,rbtree}.cc`)。
- `Build/tools/script/{grammar.actions.cjs,wasm2string.cjs}` 的"差异"经归一化验证**仅为换行(LF/CRLF)**,无语义差异 → 不需处理。

## 2. 逐文件差异清单

### 2.1 base/

| 文件 | 上游独有 / 本地独有 | 性质 |
| --- | --- | --- |
| `base.h` | 3 / 0 | 上游多一行 `#include "bits/task.h"`(task 设施) |
| `bits/base.h` | **467 / 34** | 本地: `AGINX_DECLARE_MACHINE/END`、`rLANG_NOINLINE`、版本号停在 1.10.100;上游: 见 §3-A4(通用宏/设施) |
| `scanner/scanner.cc` | 14 / 3 | 本地用 `std::abs`,上游自备 `__std_abs`;上游路径写 `base/Web/Grammar/...`(上游目录布局) |
| `src/base.cc` | 21 / 7 | 本地去掉 `rLANG_CONFIG_MINIMAL_WORLD` 分支;`Platform_GetTickCount` 的 EM_ASM 排版 |
| `src/crypto.cc` | 4 / 33 | **本地修复**: X25519 全零拒绝;`cipher_cleanse` 改为哈希派生填充;`#if 0` 掉上游 libc shim 改用 `__builtin_*` |
| `src/data.cc` | 55 / 6 | 本地**删除 `rlCrc8` + 256B 表**(设备 `.rodata` 必须为空);加了 C-04 设计决策注释 |
| `src/log.cc` | 274 / 43 | 本地大裁剪(去掉 dbghelp/backtrace/execinfo/prctl/日志文件/时间戳等);`LOGDATA_SIZEMAX` 1024→2048、日志等级判断改动 |
| `xModule.mk` | 13 / 2 | 本地只编 `src/` + `Web/Grammar`,不建 tests/scanner 子模块 |

### 2.2 build/

| 文件 | 上游独有 / 本地独有 | 性质 |
| --- | --- | --- |
| `config/arm-none-eabi.conf` | 2 / 0 | 上游有 `ifeq ("$(R)$(BT)","10")` 分支(用途待查) |
| `core/build-binary.mk` | 10 / 0 | 上游 `LOCAL_STRICT`(严格警告)+ `LOCAL_BACKTRACE`(unwind tables) |
| `core/build-executable.mk` | 4 / 0 | 上游 `LOCAL_DEPENDS`:给目标文件加额外依赖 |
| `core/build-shared-library.mk` | 4 / 0 | 同上 |
| `core/common.mk` | 28 / 1 | 上游注册 `LOCAL_STRICT/LOCAL_DEPENDS/LOCAL_BACKTRACE`、定义 `X4C_UNWIND_TABLE_CFLAGS`、新增 `add_general_source_files_non_recursive`、目录通配支持到 6 级(本地 4 级) |
| `Main.mk` | 9 / 3 | 上游: 构建系统版本 0.9.1(本地 0.8.3)、release `-O2`(本地**有意** `-O1`)、`X4C_BOARD` 合法性检查(含空格/以 `.` 开头即报错) |
| `tools/script/grammar.actions.cjs` | 108 / 108 | **仅换行差异** → 忽略 |
| `tools/script/wasm2string.cjs` | 16 / 16 | **仅换行差异** → 忽略 |

## 3. 建议:A 类 = 从上游合并进来(按优先级)

| 编号 | 内容 | 来源 | 收益 | 风险/注意 |
| --- | --- | --- | --- | --- |
| **A1** | `LOCAL_DEPENDS`:目标文件额外依赖 | `build` `cd0b4afc` | 生成文件(grammar/opcode/wasm)可声明依赖,增量构建更可靠 | 低;纯增量改动,无变量名冲突(本仓未用过该变量) |
| **A2** | `add_general_source_files_non_recursive` + 目录通配支持到 6 级 | `build` `096c4954`/`30bd4cd6` | 通用构建能力;深层子目录模块可用 | 低 |
| **A3** | `X4C_BOARD` 合法性检查 | `build` `f2a90320` | 早失败,避免奇怪目录名 | 低 |
| **A4** | `core/common.mk` 注册 + `core/build-binary.mk` 应用 `LOCAL_STRICT` / `LOCAL_BACKTRACE`,并定义 `X4C_UNWIND_TABLE_CFLAGS` | `build` `b360abf8` | 可选严格警告模式;宿主回溯表 | 中:`rLANG_COMMON_STRICT_CFLAGS` 在上游两个仓库里都只有引用没有定义(由使用方项目提供),需要我们在 `project.mk` 里给默认空值,保证 ARM/设备构建不受影响 |
| **A5** | `bits/base.h` 里的**平台中立小设施**:`rLANG_CONTAINER_OF`、`IS_LITTLE_ENDIAN/IS_BIG_ENDIAN`(含 PDP 端序 #error)、`ASSERT/VERIFY` 家族 + `rLANG_OnVerifyFailed/SetVerifyAbort`、`rLANG_Sleep/DebugBreak/IsDebuggerPresent/OutputStackTrace`、定长整型 `using` 别名 | `base` 多个提交 | 统一宿主/设备断言与调试路径;容器宏便于写设备代码 | 中:必须**按需摘取**而非整段合并——整段会把 `rLANG_CONFIG_MINIMAL*`/`<type_traits>`/`<string>` 等带进设备构建,违反"`.rodata` 空 + 最小代码"约束 |
| **A6** | `bits/task.h` + `src/task.cc`(基于 `rbtree` 的定时任务组) | `base` 新文件 | 若宿主/wasm 侧需要定时任务编排可用 | 中:本仓 `src/rbtree.cc` 已在,但没有使用者;先评估是否需要,否则不引入 |
| **A7** | `rlCrc8/16/32` API(**但用无表实现**) | `base` `src/data.cc` | 设备可用 CRC(上游现在用 256B 表 → 设备 `.rodata` 不允许) | 低-中:需要写无表版(与我们的素数试除同思路);若只回馈上游则见 B4 |

> A4/A5 建议做成**与设备构建隔离**的形式:`#if !defined(__RockeyARM__)` 或配置宏控制,确保 `make dongle` 的产物与栈预算不变。

## 4. 建议:B 类 = 回馈上游(本仓→上游)

| 编号 | 内容 | 依据 | 上游接受难度 |
| --- | --- | --- | --- |
| **B1** | `rlCryptoX25519` **全零输出拒绝**(RFC 7748 §6.1),返回值 `void` → `int` | 本仓已有实现(`base/src/crypto.cc`),对应我们安全清单 H-06 | 中:是**安全修复**,但改了公开 API 签名(调用方需检查返回值);建议上游以新 API(`rlCryptoX25519Ex` 或改返回值)接受 |
| **B2** | `cipher_cleanse` 用 `rLANG_CALCHASH_Xs` 派生填充(而非固定字节模式),避免被优化器消除/固定模式 | 本仓实现 | 中:需要上游认可动机与实现 |
| **B3** | `src/log.cc` 两处: `rLANG_CONFIG_LOGDATA_SIZEMAX` 1024→2048、日志等级判断 `level < rlLOG_FATAL` → `level <= rlLOG_NONE` | 本仓改动 | 低-中:需先确认是否为通用 bug(建议我先给出分析再回馈) |
| **B4** | **无表 CRC8/16/32**(替换 256B `static const` 表) | 本仓删表的动机(嵌入式 `.rodata` 约束) | 中:上游可能更愿意保留表(`#if` 切换两种实现) |

## 5. 明确不合并(C 类)

- **设备特化**:`base/src/log.cc` 大裁剪、`base/src/data.cc` 删 CRC 表、`base/src/base.cc` 去 minimal-world、`crypto.cc` 的 `#if 0` libc shim、`base.h` 的 task include、`Main.mk` 的 `-O1`、`base/xModule.mk` 模块裁剪 —— 均为设备/构建裁剪,保持本地。
- **本仓专属工具**:`Build/tools/{ci,sbin,script/opcode.cjs,stack-check}`(上游没有)。
- **换行差异**:`grammar.actions.cjs`/`wasm2string.cjs` —— 不改,或统一 LF 以消除噪声。

## 6. 建议执行顺序与验证

1. 先做 **A1/A2/A3**(构建系统小改)→ 验证:`make windows -j8`、`make dongle -j8`、`make foobar -j8`、`make ci`;
2. 再做 **A4**(可选严格模式,默认关)→ 同上 + 确认 ARM 构建参数无变化(比对 `rockey-stack-check` 与 `.rodata` 空断言);
3. **A5** 按设施逐个提交(每个都能单独 `make windows`/`make dongle` 验证),设备侧只看栈预算与固件体积;
4. **A6/A7** 先回答"是否真的需要"再动;
5. **B1-B4** 作为独立补丁系列准备(先出 patch,不直接改上游仓库),等你决定是否提交给上游。

## 7. 需要你决定的点

1. A 类做到哪一档?(A1-A3 低风险 / 加 A4-A5 / 含 A6-A7)
2. B 类是否现在就准备补丁(尤其 B1 的 API 变更形式:改返回值还是新增 `*Ex`)?
3. `bits/task.h`(A6)本仓是否需要?

## 8. 执行范围(用户 2026-09-11 已确认)

- **A 类本次执行:A1、A2、A3、A4、A5、A6**(A7 无表 CRC 暂不做)。
- **B 类:B1-B4 全部先准备 patch**(独立补丁系列,先出 patch 供审阅,不直接改上游仓库)。
- **并行会话:本会话暂停**,等另一会话结束后再开始实施 §6 的执行顺序(A1→A2→A3→A4→A5→A6,再准备 B1-B4 补丁)。

> 暂停原因(环境):同一工作区存在另一会话(`feat/AGINX/chachapoly-aad`),共享工作树下 `git checkout`
> 会互相搬动树枝;且长跑/设备访问被其占用(`RockeyARM::Open` 内部先 `Dongle_Enum`,长跑在飞时阻塞)。
> 恢复实施前的检查:**确认另一会话已结束、工作区无冲突改动、SDK 空闲**。

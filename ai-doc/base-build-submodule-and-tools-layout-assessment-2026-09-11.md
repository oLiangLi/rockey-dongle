﻿# 评估:自带 `base/`、`Build/` 改 submodule + `Build/tools` 按世界分目录(2026-09-11)

> 前提:初步合并已完成(A1-A6 已并入本仓;B1/B4 已由用户合入上游 base, 见上游 HEAD `fed3808` —— 该提交原先签成了错误的钥匙, 已改用正确的钥匙重做, tree 不变, 旧 hash `295ca89` 不再可用)。
> 上游两个仓库: `https://github.com/oLiangLi/base`、`https://github.com/oLiangLi/build`(均 MIT)。

## 1. 结论摘要

| 问题 | 结论 |
| --- | --- |
| 能否直接删掉自带 `base/`、`Build/` 改用 submodule | **暂不可行, 但方向正确** —— 必须先解决"fork 侧 delta 的归宿", 否则构建直接坏 |
| `base/` 的难点 | 与上游 HEAD 有 **10 个文件差异**, 其中两处是**方向性裁剪**:`bits/base.h`(本仓 1156 行 vs 上游 1503)、`src/log.cc`(406 vs 607);另依赖**上游没有的 fork 宏** `AGINX_DECLARE_MACHINE`(上游 0 处)与 `rLANG_NOINLINE`(上游 0 处) |
| `Build/` 的难点 | A1-A4 已在上游 ✓, 但本仓有 **10 个 fork 专用工具文件**在 `Build/tools/` 内(`ci/*`、`sbin/*`、`stack-check/*`、`script/opcode.cjs`)—— submodule 化的 `Build/` 里**没有它们的位置** |
| 好消息 | B1(X25519 全零拒绝)与 B4(CRC/LIMIT_WORLD)**已进上游 base** ⇒ "patch → 上游 commit" 的回流路径已打通, 后续 delta 可同样回流 |
| 推荐路线 | **① tools 世界分区 + fork 工具定位(本轮已实施)→ ② 上游化 base 剩余 delta(用 `rLANG_CONFIG_ENABLE_LIMIT_WORLD` 门控)→ ③ scratch clone 试迁移 + 全门禁 → ④ 正式切换** |

## 2. 现状量化(实测)

**上游 HEAD**: `base` = `fed3808`("合并来自 [LIMIT] 提交的补丁"; 因签名钥匙更换而重写自 `295ca89`, tree 未变), `Build` = `32cc27c`。

### 2.1 `base/`:相同 6 / 差异 10 / 仅本仓 0

| 文件 | 本仓行数 | 上游行数 | 差异性质 |
| --- | --- | --- | --- |
| `bits/base.h` | 1156 | 1503 | **裁剪 -347**(去 minimal-world/STL/平台设施)+ fork 宏(`AGINX_*`、`rLANG_NOINLINE`) |
| `src/log.cc` | 406 | 607 | **裁剪 -201**(去 dbghelp/execinfo/回溯/日志文件);我们的 verify 钩子为精简实现 |
| `src/data.cc` | 320 | 314 | 已含上游版 B4 ✓ 余差为 BOM 与注释位置 |
| `src/crypto.cc` | 5531 | 5510(+23) | **已上游化(2026-09-12 `a9eb747`)**: 我们 `#if 0` 停用自实现 `cipher_mem*` + 改用 `__builtin_*`(= C-02 修复)已并入上游, 差异消失;B1 亦已上游 ✓ |
| `src/base.cc` | 162 | 176 | -14:去 minimal-world 分支 |
| `src/task.cc` | 164 | 162 | 平台层守卫改为 `__RockeyARM__`(上游为 minimal-world) |
| `bits/task.h` | 127 | 124 | 注释/细节 |
| `scanner/scanner.cc` | 2151 | 2162 | `std::abs` vs 自备 `__std_abs` 等 |
| `xModule.mk` | 8 | 19 | 只编 `src/` + `Web/Grammar`, 不建 tests/scanner 子模块 |
| `base.h` | 17 | 16 | 差 1 行 |

### 2.2 `Build/`:相同 16 / 差异 8 / **仅本仓 10**

- 差异:A1-A4 涉及的 `core/{common,build-binary,build-executable,build-shared-library}.mk`、`Main.mk`、`config/arm-none-eabi.conf`(我们的 A4 偏差:unwind 缺省为空)+ 2 个仅换行差异的 `tools/script/{grammar.actions,wasm2string}.cjs`。
- **仅本仓**:`tools/LIMIT/ci/{optmatrix,web-emutests,run-ci}.cjs`(仓库级 CI;2026-09-12 由 `tools/ci/` 移入)、`tools/LIMIT/sbin/*`(ukey 侧运维)、`tools/LIMIT/stack-check/*`(设备栈预算)、`tools/LIMIT/script/opcode.cjs`(脚本 opcode 生成)。
  注:上列前两项按 **2026-09-11 的世界分区**给出(见 §5);分区前它们位于 `tools/sbin/`、`tools/stack-check/`、`tools/script/opcode.cjs`。

### 2.3 上游目录现状与引用面

- 上游 `build` 仓**没有** `tools/{LIMIT,ATOMC,COSMO}`、`tools/{ci,sbin,stack-check}`、`tools/script/opcode.cjs`。
- 本仓 **26 个跟踪文件**引用 `Build/tools/`;**3 个文件**(`Makefile`、`.githooks/*`、`*/xModule.mk`)引用 `Build/`。

## 3. 方案对比

| 方案 | 做法 | 优点 | 代价/风险 |
| --- | --- | --- | --- |
| **A. 纯 submodule** | 删除 `base/`、`Build/` → `.gitmodules` 指向两个上游仓, pin 到含全部 delta 的 commit | 单一真源;diff 干净;上游修复自动可得 | 必须先上游化全部 delta;fork 工具须迁出;submodule 工作流成本(见 §4) |
| **B. submodule + overlay** | submodule + 本仓 `patches/`(checkout 后 apply)或 `base-local/` 覆盖层 | 不必等上游接受;delta 显式可见 | 双层维护;构建多一步;最易漂移 |
| **C. 保持 vendored + 漂移检测** | 现状 + `tools/sync-upstream.cjs` + CI 检查与上游 HEAD 的差异 | 零工作流改动;离线可构建 | 手工同步(就是我们现在这种"落后 8 个月"的处境) |

**推荐 A(分阶段)**, 过渡期叠加 C 的漂移检测兜底。

## 4. 风险清单(按严重度)

1. **设备端约束(高)**: 上游 base 带 CRC/其它表、日志与回溯;若直接 submodule, LIMIT_WORLD 固件的
   `.rodata` 空断言、`.bss ≤ 16B`、栈 2032B 会被打破 ⇒ **必须把差异以上游可接受的形态门控**
   (CRC 已用 `rLANG_CONFIG_ENABLE_LIMIT_WORLD` 完成范本;`log.cc`/`bits/base.h` 需同样处理)。
2. **fork 专用宏(高)**: `AGINX_DECLARE_MACHINE`(本仓 20+ 文件使用)与 `rLANG_NOINLINE` 上游都没有 ⇒
   不上游化就会全仓编译失败。
3. **fork 工具位置(高)**: 10 个工具在 `Build/tools/` 内;submodule 化后必须迁出并改引用
   (本轮分区已完成第一步:归入 `tools/LIMIT/` 或留在通用 `tools/`;真正"上游化"仍待定, 见 §7)。
4. **Windows 大小写(中)**: 目录名 `Build` vs 仓库名 `build`;`.gitmodules` 路径大小写;大小写不敏感
   FS 上易生成"两个同名目录"。建议 submodule 路径统一为 `build` 并同步改引用, 或保留 `Build` 并写明约定。
5. **CI/hooks(中)**: `.githooks/*` 调 `Build/tools/ci/run-ci.cjs`(fork 工具)。新克隆若未
   `git submodule update --init` 会失败 ⇒ hooks/Makefile 需加**守卫与友好报错**, CI 需显式初始化。
6. **离线/网络(中)**: submodule 需要联网拉取;可考虑 `--depth 1` + 本地镜像, 或保留一份 vendor 回退。
7. **pin 漂移(中)**: submodule 固定 commit, 上游前进需定期 bump;无 CI 检查会悄悄落后。
8. **就地修改风险(中)**: 我们已习惯直接改 vendored 文件(试合并即如此);submodule 下就地改会脏且易丢 ⇒
   需定"**不在 submodule 内直接改**"的规矩:改动一律走上游提交或用 overlay。
9. **许可/合规(低)**: 两上游仓自带 MIT LICENSE ✓;根 `LICENSE` 与 `THIRD_PARTY_NOTICES` 需更新引用。
10. **双检出(WSL + Windows)(低-中)**: 两个检出都要 `submodule update`;submodule 会放大
    "共享工作树切分支"这类问题(本会话已踩过一次)。

## 5. `Build/tools` 世界分区(2026-09-11 已实施)

分区原则:**只服务某一个世界的工具**放进对应世界子目录,**通用工具**留在 `Build/tools/` 根下。

| 位置 | 适用世界 | 内容 |
| --- | --- | --- |
| `tools/`(根) | 通用 | `downloads/`(bison 源码包)、`script/{grammar.yc,grammar.actions.cjs,scenario.cjs,wasm2string.cjs}`、`ci/{run-ci,optmatrix,web-emutests}.cjs`,以及新增的 `README.md` |
| `tools/LIMIT/` | `LIMIT_WORLD` | `sbin/*`(ukey 复位、跑测试程序、GPG 签名核对、素数复现)、`stack-check/*`(设备栈预算)、`script/opcode.cjs`(由 `Interface/script.h` 生成 opcode 表),外加 `README.md` |
| `tools/ATOMC/` | `ATOMC_WORLD` | 占位 `README.md`(640K 预算世界) |
| `tools/COSMO/` | `COSMO_WORLD` | 占位 `README.md` |

**判定依据(两个settled 的归属问题)**:

- `ci/*` 归**通用**:它是仓库级 CI 入口, 在宿主侧运行, 与"哪个世界"无关;且 `.gitignore` 已按该路径放行。
- `script/opcode.cjs` 归 **LIMIT**:它解析 `Interface/script.h`(本仓脚本 VM 的 opcode), 而 `Interface/`
  **不跨世界共享** ⇒ 该工具随本世界。
- `script/grammar.yc`、`grammar.actions.cjs` **不得移动**:其路径已作为字符串写进生成文件
  (`Web/Grammar/regexp.jy.INL`、`Web/Script/grammar/dongle.jy.INL` 的 `YYSKELETON_NAME`), 移动会造成
  生成物无谓翻新;`scenario.cjs`、`wasm2string.cjs` 由 `Web/Script/xModule.mk`、`project.local.mk` 调用,
  同属通用构建链。

**与 submodule 的交互(关键)**: 若 `Build/` 成为上游 submodule, 则 **fork 专用工具要么先上游化到共享
`build` 仓(`tools/LIMIT/...`), 要么放到本仓新目录(如 `tools-local/LIMIT/...`)**。本轮先做分区(不改变
文件归属仓), 把"上游化还是留本仓"留给 §7 的决定。

## 6. 迁移步骤与门禁(建议)

| 阶段 | 内容 | 门禁 |
| --- | --- | --- |
| P0 | `Build/tools` 世界分区 + fork 工具定位 | ✅ 本轮完成(见 §8) |
| P1 | 上游化 base 剩余 delta:`log.cc`/`bits/base.h` 的 LIMIT 门控、`AGINX_*`/`rLANG_NOINLINE` 宏、`task.cc` 平台层(加法式, 不动对方 minimal-world) | 上游侧构建 + 本仓三平台构建 |
| P2 | scratch clone 试迁移:`git rm -r base Build` → `git submodule add <base> base`、`git submodule add <build> Build`, pin 到含全部 delta 的 commit | `submodule update --init` 后构建 |
| P3 | 全门禁对比: 三平台构建 + `make ci` + 固件 **65520B / `.bss` 0x10 / 无 `.rodata` / 栈 1936B** 与现基线逐项一致;Windows 侧构建 | 逐项一致才允许切换 |
| P4 | 正式切换 + 文档/CI/hooks/`THIRD_PARTY_NOTICES` 同步 | 新克隆一把过(含 hooks) |

## 7. 待决定

1. **上游化 vs overlay**: 推荐把 base 剩余 delta 以上游提交方式落库(用 `rLANG_CONFIG_ENABLE_LIMIT_WORLD`
   门控), 本仓只做 submodule pin;若你不希望上游出现 LIMIT 专有门控, 则改用 overlay(方案 B)。
2. ✅ **工具世界归属**: `opcode.cjs` 归 LIMIT、`grammar.*` 不移动(§5 判定);`ci/` 原判为“通用”, **2026-09-12 按用户决定改为归 LIMIT** —— 三个门禁断言的都是 dongle 受限世界的产物与模拟器行为, 已 `git mv` 到 `tools/LIMIT/ci/`(见 §8 补记)。
3. **LIMIT 工具归宿**: 上游化到共享 `build` 仓的 `tools/LIMIT/`, 还是留在本仓(如 `tools-local/LIMIT/`)。
4. **pin 策略**: 跟 tag(如 `v1.1.0.0`)还是跟 `main`(需要定期 bump + CI 漂移检查)。

## 8. 实施记录(P0,2026-09-11)

**移动**(`git mv`, 保留历史):

| 旧路径 | 新路径 |
| --- | --- |
| `tools/sbin/*`(4 个) | `tools/LIMIT/sbin/*` |
| `tools/stack-check/*`(2 个) | `tools/LIMIT/stack-check/*` |
| `tools/script/opcode.cjs` | `tools/LIMIT/script/opcode.cjs` |

**新增**:`tools/README.md`(总览 + 历史路径对照 + 约定)、`tools/LIMIT/README.md`、
`tools/ATOMC/README.md`、`tools/COSMO/README.md`(均带 BOM 的 UTF-8)。

**引用同步**:`Makefile`(stack-check ×2、opcode ×1)、`package.json`(`gen:opcode`)、`.gitignore`(注释)、
`src/__Testing__/__dongle__/main.cc`(注释)、被移动文件自身的用法注释与生成物 banner、`stack-check/README.md`,
以及 `ai-context.md` 与 `ai-doc/*` 中的历史路径(统一改写为新路径, 保证全仓 `grep` 无旧路径)。

**代码修正**:世界子目录比 `tools/` 深一层 ⇒ 3 个用 `__dirname` 推算仓库根目录的工具各加一级 `..`
(`LIMIT/sbin/run-dongle-exe.cjs`、`LIMIT/stack-check/stack-check.cjs`、`LIMIT/script/opcode.cjs`);
`stack-check.cjs` 由 map 文件路径反推根目录的分支不受影响。

**验证**:

- `make jsWrapper`:`Build/tools/LIMIT/script/opcode.cjs` 新路径生效并成功生成
  `Web/Script/lib/opcode.ts`(`[opcode] opcode.ts: 已生成 OpCode=154, AllFunc=95`);该目标随后在
  `npm run release`(`tsc`)处失败,**与本改动无关** —— 是 WSL 内已安装的 TypeScript 对
  `downlevelIteration` / `moduleResolution=node10` 的 TS7 弃用报错(TS5101/TS5107),不改 tsconfig 无法通过。
- `make rockey-stack-check`(走新路径的 `stack-check.cjs`)、`make linux -j8`、`make ci`:见提交记录。


### 2026-09-12 补:`tools/ci/` → `tools/LIMIT/ci/`

按用户决定:这三个 CI 门禁只服务 dongle 受限世界。共享 `build` 仓在 `evolution` 上
`git mv tools/ci tools/LIMIT/ci`,三个脚本按“世界子目录深一层”各补一级 `..`
(`run-ci.cjs` / `optmatrix.cjs` / `web-emutests.cjs`),并补 `100755`;`tools/README.md`、
`tools/LIMIT/README.md` 同步。提交 **`db0ebfc`**(已签名,内网镜像 + GitHub 双远端一致),
本仓子模块 pin 由 `7d78de3` 提到 `db0ebfc`。本仓引用面:`Makefile`(3 个目标 + 1 条注释)、
`.githooks/ci-common.sh`(3 处)、`.gitignore`(2 行 un-ignore)已改为新路径。

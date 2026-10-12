# AGENTS.md — 本仓长期铁律与代理须知

写给在本仓工作的 AI / 自动化代理。**开工前先读本文件**；它只放"必须长期遵守的规则"，
事实性项目知识与历史结论仍按老规矩写进 `ai-context.md`（追加式，用户很重视"尽可能多的地方留痕"）。

**优先级**：用户当轮的显式指令 > 本文件 > 其它一切既有约定（Makefile 注释、ai-doc、历史习惯）。
本文件（`AGENTS.md`）的建立与修改**被明确允许**（用户 2026-10-12 裁定 —— 它是 §2 冻结的**唯一例外**），
但改动要写明依据（用户裁定 / 日期），且不得借此写入 secret 类材料。
任何 ZION 铁律与当轮指令冲突时：**先停下并询问用户**，不要自行取舍。

---

## 0. 区域（ZION）划分

先判断"当前在哪个区域"，再决定允许做什么 —— 区域判定优先于任务内容本身。

| 区域 | 名称 | 范围（落点） |
|---|---|---|
| **ZION[0]** | **rLANG** | ukey / 设备世界（LIMIT）：`Interface/`、`src/`、`mkey/`、`Web/Agent/Tests/`（进程内 JS 模拟器世界）、`Build/`。设备侧唯一对外门在 `src/app/main.cc:755` 打印 `ZION[0].Execv argc: %d` |
| **ZION[1]** | **ATOMIC** | `atomic/` 的 RV32IM 解释器世界（ATOMC）：门 `op_GATE`、世界魔数 `op_HYPER`（`atomic/include/rv32im-atomic.hpp:58`、`kCycHyper = 1<<16`）、`atomic/tests/` |
| ZION[2] / ZION[3] | 待用户定义 | 用户 2026-09-18 提过 "ZION[1/2/3]" 为后续目标，正式定义未见本仓 ⇒ **不要自行推断**，需要时问用户 |

---

## 1. ZION[0]/rLANG：分支为 `rlang/zion/evolution`（或类似命名）⇒ 先确认"系统离线"

这类分支是**世界演化**工作区，外部输入不得污染。开工第一件事是**逐项确认系统处于离线状态**，而不是先改代码：

```powershell
# Windows（本机主工作区）
Get-NetAdapter | Select-Object Name,Status,LinkSpeed          # WiFi / 以太网
Get-PnpDevice -Class Bluetooth  | Select-Object Status,FriendlyName   # 蓝牙
Get-PnpDevice -Class Ports      | Select-Object Status,FriendlyName   # 串口
Get-Volume | Where-Object DriveType -eq 'Removable'          # 外接 U 盘 / 可移动盘
Get-CimInstance Win32_CDROMDrive | Select-Object Drive,Caption        # 光驱 / 刻录
netsh wlan show interfaces                                    # WiFi 连接明细
```

```bash
# WSL / Linux 侧
rfkill list; ip -brief link; lsblk -o NAME,TYPE,TRAN,MOUNTPOINT; ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null
```

**判据与动作**：任何一条通道显示"已连接 / 有介质 / 已启用"⇒ **停下并报告用户**，不要开始改动。
只有当用户确认"就该这样"或环境确实全离线，才进入正常工作。

---

## 2. ZION[1]/ATOMIC：本会话任何位置（尤其**主题**）含 `PREV_MASTER_SECRET` ⇒ 只读 + 报告

`PREV_MASTER_SECRET` 指 MASTER.SECRET 的 6×32 交换/导入语义（`Interface/execute.cc:333`
`OpExecute_ExchangeMasterSecret` / `ImportMasterSecret`，背景见 `ai-doc/master-secret-build-2026-09-09.md`）。

命中该主题时（**注意：本会话首条消息 `PREV_MASTER_SECRET` 即算命中**）：

1. **冻结一切改写**（**唯一例外：`AGENTS.md` 本身 —— 其建立与修改始终被允许**，用户 2026-10-12 裁定）：
   不得修改任何其它文件、不得 `git add/commit/amend/rebase/push`、不得改配置。
   即使代理此前已获得"可以改这些文件"的许可，本条对**其它文件**仍然优先。
   需要真正落地其它修改时：把工作移到**不含该主题的新会话**，或用用户当轮的显式解冻指令。
2. **应当做的是"看 + 报"**：枚举当前插入的 ukey 并报告状态。安全命令（只 Enum + 打印，不 Open、不下载、不执行）：

```powershell
.bin\<宿主产物目录>\__Testing__rsamrprobe__.exe -info      # Windows
./.bin/<宿主产物目录>/__Testing__rsamrprobe__ -info        # WSL/Linux
# 源码依据: src/__Testing__/__rsamrprobe__/main.cc:47/61/115 "-info: 只枚举...后退出(对任何设备都安全)"
```

2026-10-12 实测输出样例：`rockey.Enum return 2`、两台 `type=ff(standard/no-clock)`、`ver=00000222`。
报告要写清：台数、`type`（`ff`=标准/无时钟、`00`=时钟锁、`02`=U 盘锁）、`ver`、`pid`、`uid`、`hid`。
**不要把 secret 类材料（master secret / 私钥 / PIN / 密文）写进任何文件或提交信息。**

---

## 3. 网络与代理（下载失败 / 缓慢时）

1. 先看 `/etc/proxychains.conf`：**存在就按它的设置来**，不要自创代理参数。
2. 不存在时，按本地网络情况用 `10.20.20.124:8001` 或 `10.10.1.16:8001` 之一。
3. 网络错误**反复发生**（不是偶发超时）⇒ 提示用户**重新连接 `op_HYPER`**（用户术语；对应世界魔数 / RPC
   通道，见 `atomic/include/rv32im-atomic.hpp:58`），不要无休止重试或改写成 fake 本地源。

---

## 4. 提交与分支（用户规则）

- **需要多次提交的改动** ⇒ 建 `feat/AGINX/$name` 分支（提交**保持签名**，见下条），
  由用户自己 squash merge。squash 信息前缀必须恰为 `Squashed commit of the following:`（否则 `.githooks` 不触发 CI）。
- **只需单次提交的改动** ⇒ 直接在主分支（`master`）上提交，先不签名，由用户之后 `git-sign-last` 补签
  （该工具是用户本地流程，本仓未见脚本）。
- 代理**不自行** squash、不自行 push、不改写历史、不动已推送的提交。
- **署名 trailer**：`Assisted-by: DeepSeek Harness (deepseek-v4-flash)` 只在**最终 squash 提交**里出现一次，
  且仅当该分支登记在 `.git/rlang-ai-assisted`（本地、不跟踪，格式 `<分支名>\t<trailer>`）里；
  **分支提交里不加**；推给上游 `base`/`Build` 仓的提交不加。**不要给 AI 用 `Signed-off-by`**（DCO 必须由人做）。
- **提交信息风格**（本仓习惯）：中文单行 subject，`模块: 要点 + 要点`，括号里写理由，正文用 ①②③ 逐条编号
  （真因 / 修复 / 验证 / 改动）；未完成的以 ` ...` 结尾。
- **签名（用户 2026-10-12 裁定：以实际做法为准）**：提交**一律保持签名 `G`**（全局 `commit.gpgsign=true`，
  ed25519 钥 `BCE591B95E51D027`）。`ai-context.md:592` 记的「`feat/AGINX/*` 分支上的提交不需要签名」已被本裁定取代。

---

## 5. CI 与门控

- 入口：`make ci`（= `make test`）= `node tools/rockey/LIMIT/ci/run-ci.cjs`。
  前置：需先 `make wasm && make jsWrapper` 生成 `Web/Agent/Tests/js/*`；缺失时打印"前置缺失"并**跳过**
  （`CI_STRICT=1` 才失败）。
- **汇总日志只有一行**：`.bin/ci-log/ci-<UTC时间>.log` 里只写 `ci quick: OK/FAILED (failed=N)`；
  逐项 PASS/FAIL 只在 stdout。想知道"那一个错误"是谁，必须看 stdout 或重跑。
- **`make ci` ≠ 直接跑 node**：`.user.local.mk:15` 有 `export CI_ATOMIC=1` ⇒ 经 make 调用会**强制执行 atomic 检查**；
  直接 `node run-ci.cjs` 会打印"跳过 atomic"。对比两次运行前先确认这一点，别把差异当回归。
- 门控 G1..G4（`tools/rockey/LIMIT/ci/gates.cjs`，用户 2026-09-14 指定，**gpg 缺失即失败、不 skip**）：
  - **G1** gpg 钥匙串必须恰为在册两把主钥（指纹 / uid / 算法长度 / 用途 SC / 未过期 + 有私钥 + 有未过期 `[E]` 子钥）。
    gpg 不可用 ⇒ 失败。本机可用：`C:\Program Files\Git\usr\bin\gpg.exe`（用 `RKEY_GPG` 或 `git config gpg.program` 指定；
    Cygwin 自带的 gpg 常起不来）。
  - **G2** 明文（提交信息 / 跟踪文件 / 日志 / 文档）中**永远不得**出现被禁的**共同作者 trailer 字面量**；
    需要提及时用中文描述代替，**不许**用零宽字符拆开字面量（不可见字节在 review/grep/diff 里同样不可见）。
    历史 8 条（2026-09-03~07）在册保留，不回填。**本文件也在扫描范围内。**
  - **G3** 带签名的提交必须为 `Good`；在册例外 1 条（2024-08-30 Gitee 代提交，本地缺上游 RSA 公钥）。
  - **G4** `Interface/aginx.h` 的署名行**恰出现 1 次**，无 `TODO: 待用户提供…` 占位，C / C++ 两分支宏齐备。
- 自动钩子：`.githooks/post-commit`（及 `post-merge`）只在信息以 `Squashed commit of the following:` 开头时跑 CI，
  按 HEAD 去重（`.git/rlang-ci-last`），**默认非阻塞**（`CI_STRICT=1` 才非零退出）；`CI_SKIP_RUN=1` 跳过。
  `make install-hooks` 设 `core.hooksPath=.githooks`。
- 常用目标：`make test-optmatrix`（-O0..-O3 密码学门禁，慢）、`make test-web`（需本机 Chrome）、
  `make test-atomic`（宿主 C++ 检查，缺编译器则 SKIP）、`make stack-check` / `make rockey-stack-check BUDGET=4096`、
  `make jsWrapper`、`make dongle`、`make windows|linux|wasm`。

---

## 6. 运行环境（本机实测，最容易重复踩的坑）

- **Windows 侧只支持 Cygwin 构建**；MSYS2 / Git-Bash 不在支持范围（`uname -o` == `Cygwin` 是唯一判据，
  见 `Makefile:30-53`）。
- **本机是双宿主机**：Windows/Cygwin + **WSL Ubuntu-22.04**（Windows 侧**没有** Docker）。
  同一份工作区在两个宿主机上跑 `make ci`，结果**可能不同** —— 先确认是在哪一侧跑的，再谈"是不是回归"。
- **产物目录名** = `<arch>[-<board>]-<platform>-<conf>`（`Build/core/common.mk:195/197` `X4C_MAKE_SUBDIR`），
  形如 `amd64-linux-release` / `amd64-foobar-linux-debug` / `amd64-windows-release` / `wasm-emscripten-release`。
- **产物不能跨宿主执行**：Windows 跑不了 ELF（`spawnSync` 报 `ENOENT`/`UNKNOWN`），Linux 跑不了 PE。
  任何"按平台取产物"的代码都必须**先按宿主守卫**（正确做法见 `tools/rockey/LIMIT/ci/run-ci.cjs` 的
  `platformDirOf()`：兜底只接受含 `-<host>-` 的目录，没有就返回 `""` 走"未构建 ⇒ 跳过"分支）。
  **案例（2026-10-12）**：`.bin` 下只有 linux 产物时，`platformDirOf()` 的跨平台兜底挑中
  `amd64-linux-release/__Testing__trngfail__`（ELF，无 `.exe`），Windows 上 `spawnSync` 2ms 内
  `status=null + ENOENT`，被上层写成 `(timeout)` ⇒ `make ci` 报 `failed=1` 的**假红**；
  同一 HEAD 在 WSL 下该文件是原生可执行的 ⇒ `failed=0`。
- **受限沙箱 / 无 TTY 环境下**：Cygwin 的 `make`/`bash` 可能起不来（`NtCreateDirectoryObject ... 0xC0000022`），
  Node 的 `child_process` 管道式 `spawn` 可能 `EPERM`。表现为**整批 `FAIL (timeout/killed)`** ——
  这是环境假象，不是代码问题。处理：提权后运行，或改跑底层 node 入口 / 用 `stdio: inherit` 拆分；
  不要据此改源码。
- **区分"起不来"与"真超时"**：先看 `r.error.code`（`ENOENT`/`EACCES`/`EPERM`/`UNKNOWN`）与耗时
  （2ms ⇒ 起不来；120s ⇒ 才是超时）。上报时给出 `code` 和耗时，别只说 "timeout"。
- node / tsc 的选取见 `Makefile:13-18`（`X4C_NODE` 优先本机专用 node，`TSC` 优先仓内 `node_modules/.bin/tsc`）。

---

## 7. 真机 / ukey 操作（ZION[0] 的写操作要许可）

- **只读列举**：`.bin/<宿主产物目录>/__Testing__rsamrprobe__[.exe] -info`（安全；见 §2）。
- **写设备**（`-flash` 烧固件、`UpdateExeFile`、改 PIN、KeyGen 等）属**写操作**：必须有用户明确许可，
  并确认目标机型（`type`: `ff` 标准 / `00` 时钟锁 / `02` U 盘锁）符合预期。
- 长跑（真机 RSA 等）遵守**落盘原则**：进度/结果写 `dashboard[0,4096)` 匿名区，别放内存/临时文件；
  长跑**绝不中途杀宿主**（会把 SDK 会话留在驱动里，`Enum` 全局阻塞）；`WT_RKEY_SINGLE_RUN=1` 可避免重复执行。
- 板级缺省：Windows 缺省真机/SDK 模拟器，其它宿主缺省 `foobar`（模拟器世界，无需 ukey）；
  `OPMATRIX_BOARD=none` 需接设备。

---

## 8. 不要做的事（负向清单）

- 不要在没有**真实证据**（命令 + 输出 + 退出码）时说"已修复/已通过"；`failed=0`、`EXIT=0` 要贴出来。
- 不要为了让 CI 变绿而放宽门控：`gates.cjs` 的白名单 / 例外是**用户裁定**的，不是可调参数。
- 不要把 `.bin/`、`.git/rlang-*`、`node_modules/`、`third_party/`、`base` 子模块当成本仓源码改
  （`base` 属上游，明示不纳入 G2）。
- 不要在 Windows 上试图执行 Linux 产物，反之亦然（见 §6）。
- 不要在 ZION[1] 会话里做任何写操作 —— **`AGENTS.md` 是唯一例外**（见 §2），
  且改动要写明依据（用户裁定 / 日期），不要静默修改规则。
- 不要把 secret 类材料（master secret、私钥、PIN、密文、指纹以外的凭据）落到文件、日志或提交信息里。

---

## 9. 相关文件

| 文件 | 用途 |
|---|---|
| `ai-context.md` | 项目知识库与历史结论（**追加式留痕**，事实写这里） |
| `AGENTS.md`（本文件） | 必须长期遵守的规则与易犯错误 |
| `ai-doc/` | 专题报告（master-secret / rsa3072 / ukey 长跑 / 世界事件…） |
| `.git/rlang-ai-assisted` | 哪些分支 squash 时要加署名 trailer（本地、不跟踪） |
| `.git/rlang-ci-last` | CI 钩子按 HEAD 去重（本地、不跟踪） |
| `.user.local.mk` | 用户本地构建开关（含 `export CI_ATOMIC=1`；不跟踪） |
| `tools/rockey/LIMIT/ci/{run-ci,gates,optmatrix,web-emutests}.cjs` | CI 实现与门控 |
| `.githooks/{post-commit,post-merge,ci-common.sh}` | squash 合并后自动跑 CI |

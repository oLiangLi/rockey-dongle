# README 发布评审:哪些信息适合公开(2026-09-11)

> 结论先行:**README 本身问题不大(60 行、内容真实),真正需要先解决的是"仓库里已经有生产密钥仪式材料"** ——
> `mkey/` 有 44 个被跟踪文件,`ai-context.md` 与部分 `ai-doc/` 含内网/设备/主钥设计细节;
> 另有一处**法务风险**:供应商 RockeyARM SDK(`third_party/RockeyARM`、`MCU/RockeyARM/lib/FTRX.a`)没有任何许可/来源声明。

## 1. 现有 README 逐项体检

| 行 | 内容 | 评价 | 建议 |
| --- | --- | --- | --- |
| 1 | 标题(一句话定位) | 信息真实但太长 | 拆成 `# 项目名` + 一句话 tagline + 一段简介 |
| 4 | GitHub/Gitee 克隆地址 | ✓ 保留 | 建议同时给"发布形态"(源码 / 需自备 SDK) |
| 5 | `make make install-hooks` | **笔误**(多了一个 `make`) | 改 `make install-hooks`,并说明 hooks 只在本机跑快检 |
| 6 | `make -j8 && make foobar …` | ✓ 但**缺前置条件** | 补平台×工具链矩阵(见 §3.P0-2);说明 `make` 默认目标是本地平台 |
| 7-9 | 私有常数 / 版本不兼容 / 模拟器要留 jsCrypto.js / 刷设备要重编 | ✓ **这是重要的安全属性,应保留并展开** | 独立成"安全模型"小节,写清"每次编译互不兼容"的因果 |
| 11-43 | 算法清单(硬件/移植) | ✓ 核心卖点 | 改成表格;补"用途/边界";RSA 行**已过时**(见下) |
| 45-50 | 脚本语言限制 | ✓ 保留 | 补"能做什么"(签名/验签/密钥交换/导入 X509/存储操作)+ 安全边界 |
| 52-55 | 正在进行的工作 | ✓ 保留 | 可加"设备内 RSA-3072 ROOT CA 生成(单指令、种子可复现)" |
| 57-60 | 剩下的工作 | ✓ 保留 | 与路线图小节合并 |

**过时点(必须改)**:L13/L33 仍写"RSA 最大只使用 RSA2048 / RSA3072 可能非常缓慢"。
实测(2026-09-11,测试 ukey)已能在**设备内单条指令**里生成 RSA-3072(p+q 共 52.1 分钟,OpenSSL 复核通过,
同一种子可逐字节复现)——建议改为:"RSA-3072 可用于 ROOT CA / 重要中级 CA,设备内单指令生成 ≈1 小时量级"。

## 2. 建议公开的信息(按优先级)

### P0 — 公开发布的门槛
1. **许可与第三方声明**:仓库根已有 `LICENSE`(MIT,Copyright 2024-2026 LiangLI);需补 `THIRD_PARTY_NOTICES.md`:
   - TASSL-1.1.1(OpenSSL 1.1.1 派生,**OpenSSL/SSLeay 双许可**)✓ 仓库内已有 `LICENSE`;
   - micro-ecc(BSD-2,Copyright 2014 Kenneth MacKay)✓ 已有 `LICENSE.txt`;
   - nlohmann/json(MIT)—— 仓库只跟踪了 `json.hpp`/`json_fwd.hpp`,**没有许可文件** → 需在 NOTICES 里补声明;
   - **RockeyARM 供应商 SDK(`third_party/RockeyARM/{amd64-windows,amd64-linux,aarch64-linux}` 的头文件与 `libRockeyARM.a`/`Dongle_s.lib`、
     MCU 侧 `FTRX.a` 与 ARM 头文件):无任何许可/来源声明 → 发布前必须确认再分发授权**,
     否则改为"用 `Build/tools/downloads/` 放获取脚本,由使用者自行向厂商取得"。
2. **平台 × 工具链矩阵 + 命令**(README 最该补的部分):

| 平台/产物 | 前置 | 命令 |
| --- | --- | --- |
| Windows 宿主 | VS2022(clang-cl)、node | `vcvars64.bat` 后 `make windows -j8` |
| Linux 宿主 | gcc、node | `make linux -j8` |
| aarch64 Linux | aarch64-linux-gnu-* | `make aarch64-linux -j8` |
| 设备固件 | arm-none-eabi 14.3 | `make dongle -j8` → `.bin/arm-RockeyARM-native-release/rockey_dongle.bin` |
| 宿主模拟器 | 无(纯本地) | `make foobar -j8` |
| wasm/JS | emsdk 3.1.64 | `make wasm -j8` / `make jsWrapper -j8` |
| 语法/类型 | node、bison 3.8.2 | `make typescript` |
| 回归 | node 22 | `make ci`(快速,不依赖真机)/ `make test-web` / `make test-optmatrix` |
| 栈预算 | arm 工具链 | `make stack-check`(RockeyTrust)/ `make rockey-stack-check`(固件 BUDGET 可覆盖) |

3. **测试入口说明**:`src/__Testing__/*` 各模块的用途与"哪些必须真机"(`__dongle__` 需要实体 ukey;
   `__x509__`/`__x509import__`/`__diff__`/`__25519__`/`__sha256__`/`__uECC__`/`__aes__`/`__HelloWorld__`/`__trngfail__` 可本地跑)。

### P1 — 强烈建议(体现项目价值)
4. **目录结构总览**:`Interface/`(宿主 SDK 抽象:Dongle/RockeyARM/Emulator)、`src/`(固件入口与测试)、
   `MCU/`(Rockey-ARM BSP/EABI)、`Web/`(wasm、脚本 VM、Agent 工具、示例)、`Build/`(构建系统与工具)、
   `third_party/`、`ai-doc/`(设计文档)。
5. **能力清单 + 最小示例**:脚本 HelloWorld、X509 链验签、设备内执行自定义代码、
   `Web/Agent/Tests/__Testing_dongle.cjs` 的 `list/dashboard/run/suite` 用法(去掉真机 HID)。
6. **安全模型小节**(建议原样保留 README 现有意思并展开,这是差异化卖点):
   - 构建期注入私有常数 ⇒ **不同编译版本互不兼容**(MASTER_SECRET 相关操作尤甚);
     模拟器依赖时须保存当次 `jsCrypto.js`;写设备前必须重新 `make dongle`;
   - **MASTER_SECRET 托管**:多把管理 ukey(K0..K3)互为备份,任意 3 把即可恢复(4 选 3),单把不足以恢复;
   - **私钥不出设备**:ROOT CA 素数/私钥在 ukey 内单指令生成,落盘的只是"参数+密文种子",
     任何持有 MASTER_SECRET 的设备可**确定性复现**同一私钥(已实测可逐字节复现)。
   - 设备侧限制(rodata 不可读、栈/InOut 预算、无日志通道)可写"设计约束"小节。
7. **设备脚本语言的完整约束表**:opstk 16 字、代码 ≤100 半字、无函数调用、
   不支持 `break/continue/switch…case`、`Exit` 语义等。
8. **路线图**:CA 原语 → CSR/CRL/X509 → jsSSL(README L52-60 已列,建议加优先级与预计形态)。
9. **文档索引**:`ai-doc/` 中适合公开的(见 §3 的"可公开"分类)。

### P2 — 可选
10. 限制与取舍(为什么没有 AES:ROM 不足;移植算法慢于硬件,应优先硬件;压缩格式支持的历史差异)。
11. 贡献方式(分支命名、提交约定、`install-hooks`、squash 流程)—— 若接受外部 PR 才需要。
12. 常见问题(如何取得 RockeyARM SDK、如何获得测试设备、模拟器能覆盖多少)。

## 3. 公开前必须处理(风险清单)

| 对象 | 规模 | 风险 | 建议 |
| --- | --- | --- | --- |
| **`mkey/`**(含 `README.md`、`A0/E0/E1/E10`、`Client/C1,C4`) | **44 个跟踪文件** | **生产管理密钥仪式记录**:K0..K3/A0 设备序列号、EnTrust 托管参数、系统参数(公钥/nonce/签名)、factory-lock、`cipher/sec.asc`(加密的 64B 种子)、`cipher/MASTER-KEY-INITIALIZE.7z.asc`、GPG key id 与生成流程 | **公开发布必须整体移除**(独立私有仓库或子模块);仅删工作区不够,需清历史(`git filter-repo`) |
| **`ai-context.md`** | 1 文件 | 内网代理 `10.20.20.124:8001`、usbipd 直通步骤、测试 ukey HID `00000000-efea115bfc084642`、个人邮箱、管理 PIN 约定、生产设备状态 | 不公开;或裁剪出"公开版开发日志" |
| **`ai-doc/` 若干篇** | 13 篇 | `master-secret-build`、`session-key-flow`、`rsa-root-ca-generation`、`rsa3072-device-generation`、`ukey-longrun-and-rsa3072`、`ukey-rsa-prime-recovery`、`rsa-prime-bench-pitfalls` 含**主钥重建算法、dashboard 分区、种子/密钥 hex、设备实测细节** | 逐篇三分类:**公开 / 摘要化后公开 / 私有** |
| 相对安全的文档 | — | `issues-status.md`、`stack-budget-report-*.html`、`emulator-real-exemptions.md`、`ukey-rand-quality-*.html`、`bug-analysis-report-*.html` | 可公开(随机数报告里的测试 ukey HID 建议匿名化) |
| `Web/Agent/Tests/__Testing_dongle.cjs` | 1 文件 | 内置真机 HID 白名单(7 个文件含该 HID) | 改为环境变量/占位符 |
| `third_party/RockeyARM`、`MCU/RockeyARM/lib/FTRX.a` | — | **供应商 SDK 无许可声明**,再分发条款未知 | 确认授权;否则改为获取脚本 |
| `project.local.mk` / `.bin/` / `Web/Assembly` / `node_modules` | — | 未跟踪或已忽略 | ✓ 无需处理 |

**仓库现状补充**:`ci-full` 目标在 `Build/tools/ci/run-ci.cjs` 注释里被引用,但根 Makefile **没有**该目标 ——
发布前应二者取一(加目标或改注释)。

## 4. 建议的 README 结构(可直接照此重写)

```
# 项目名 — 一句话定位
<3-5 行简介: 在 Rockey-ARM ukey 内运行自定义密码学代码的套件>

## 特性
## 支持的算法(硬件 / 移植)          ← 现 L11-43 改表格
## 设备脚本语言(能力与限制)          ← 现 L45-50
## 安全模型                          ← 现 L7-9 展开 + MASTER_SECRET 3-of-4 + 私钥不出设备
## 平台与构建前置 / 构建命令          ← 现 L4-6 展开(§2.P0-2 表格)
## 运行与测试(模拟器 / 真机 / CI / 栈检查)
## 目录结构
## 路线图                            ← 现 L52-60
## 文档索引
## 许可与第三方声明
## 贡献方式(可选)
```

## 5. 后续可代办

- 按 §4 重写 `README.md`(保留并展开现有安全语义,修正 `make make` 与 RSA 行);
- 生成 `THIRD_PARTY_NOTICES.md` 与 `docs/index.md`;
- 给出"从仓库历史中移除 `mkey/` 与 `ai-context.md`"的 `git filter-repo` 脚本(**需你确认后再执行**);
- 把 `Web/Agent/Tests/__Testing_dongle.cjs` 的真机 HID 改成环境变量。

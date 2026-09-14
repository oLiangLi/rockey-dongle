# tools/rockey —— RockeyDongle 本仓专属工具(按世界分区)

本目录存放**只服务 RockeyDongle 本仓/本机**的开发与运维工具。它们原先放在**共享构建仓** `Build/`
(submodule,`github.com/oLiangLi/build`)的 `tools/` 下,因其**不具备跨世界/跨使用方的通用性**,
2026-09-14 迁回本仓。

共享仓 `Build/tools/` 现在只保留跨世界通用物:`downloads/`(构建依赖包)与 `script/`(语法与脚本构建脚本)。

| 位置 | 适用世界 | 内容 |
| --- | --- | --- |
| `tools/rockey/LIMIT/` | `LIMIT_WORLD` | 在 ukey 中运行的程序(受限世界:不允许 `.rodata`、不允许查表、`.bss` 16B、栈预算 2032B)专属工具 |
| `tools/rockey/ATOMC/` | `ATOMC_WORLD` | ATOMC 世界专属工具(占位,目前为空) |
| `tools/rockey/COSMO/` | `COSMO_WORLD` | COSMO 世界专属工具(占位,目前为空) |

## LIMIT/(当前唯一有内容的目录)

| 子目录 | 内容 |
| --- | --- |
| `ci/` | 仓库级 CI 门禁(宿主侧运行):`run-ci.cjs`(`make ci`)、`optmatrix.cjs`(`make test-optmatrix`)、`web-emutests.cjs`(`make test-web`)、`gates.cjs`(G1..G4) |
| `sbin/` | ukey 运维工具:复位 ukey、执行测试程序、GPG 签名核对、素数复现 |
| `script/` | `opcode.cjs`(`Interface/script.h` → `Web/Script/lib/opcode.ts`)、`commitHash.cjs`(世界事件用 `jsCommitHash.js`) |
| `stack-check/` | 设备栈预算检查(`make stack-check` / `make rockey-stack-check`,默认预算 2032B) |

## 历史路径对照

| 旧路径(共享仓 `Build/`) | 新路径(本仓) |
| --- | --- |
| `Build/tools/LIMIT/*` | `tools/rockey/LIMIT/*` |
| `Build/tools/ATOMC/*` | `tools/rockey/ATOMC/*` |
| `Build/tools/COSMO/*` | `tools/rockey/COSMO/*` |

更早一次分区(仍在共享仓内,2026-09-11 / 09-12):`tools/sbin/* → tools/LIMIT/sbin/*`、
`tools/stack-check/* → tools/LIMIT/stack-check/*`、`tools/script/opcode.cjs → tools/LIMIT/script/opcode.cjs`、
`tools/ci/* → tools/LIMIT/ci/*`。

## 约定

1. 新增工具先判断"是否只服务某一个世界":是 ⇒ 放进 `tools/rockey/<WORLD>/`;跨世界通用的构建工具仍放共享仓 `Build/tools/`。
2. 世界子目录距仓库根 **4 层**(`tools/rockey/<WORLD>/<子目录>/x.cjs`)⇒ 用 `__dirname` 推算仓库根目录的工具须 `..` 四次;
   这与迁移前的 `Build/tools/<WORLD>/<子目录>/` **完全同深**,故本次迁移未改动任何 `..` 级数。
3. 含非 ASCII 字符的文件保存为**带 BOM 的 UTF-8**;以 `#!` 开头的脚本**不加 BOM**。

## 迁移状态(2026-09-14)

本仓一侧已落地;**共享仓 `Build` 一侧的"删除这些目录"提交**与**本仓 submodule pin 的更新尚未做**
(当前按约定只改工作区、不提交不推送),因此此刻 `git submodule update` 仍会把旧目录取回,属预期过渡态。
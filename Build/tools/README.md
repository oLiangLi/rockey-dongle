# Build/tools —— 构建与开发工具

本目录按**世界**(运行环境)分类存放工具:**只服务某一个世界的工具**放进对应世界子目录,**通用工具**直接放在本目录下。

| 位置 | 适用世界 | 内容 |
| --- | --- | --- |
| `tools/`(本目录) | 通用 | 所有世界共用的构建脚本与依赖 |
| `tools/LIMIT/` | `LIMIT_WORLD` | 在 ukey 中运行的程序(受限世界)专属工具 |
| `tools/ATOMC/` | `ATOMC_WORLD` | ATOMC 世界(内存预算宽松,可达 640K)专属工具,目前为空 |
| `tools/COSMO/` | `COSMO_WORLD` | COSMO 世界专属工具,目前为空 |

## 通用(本目录)

- `downloads/` —— 构建依赖包(如 bison 源码包)及其获取说明。
- `script/` —— 语法与脚本构建脚本:
  - `grammar.yc`、`grammar.actions.cjs` —— 由构建系统内部调用(`Build/filter/`),**其路径已被生成文件内的字符串引用,不要移动**。
  - `scenario.cjs`、`wasm2string.cjs` —— 由各模块的 `xModule.mk` / `project.local.mk` 调用。
- `ci/` —— 仓库级 CI 入口(`run-ci.cjs`、`optmatrix.cjs`、`web-emutests.cjs`),在宿主侧运行,与世界无关。

## 世界专属

- `LIMIT/sbin/` —— ukey 侧运维工具(复位 ukey、执行测试程序、GPG 签名核对、素数复现)。
- `LIMIT/stack-check/` —— 设备栈预算检查(`make rockey-stack-check`,预算 2032B)。
- `LIMIT/script/opcode.cjs` —— 由 `Interface/script.h` 生成 `Web/Script/lib/opcode.ts`(`Interface/` 不跨世界共享,故该工具属世界专属)。

## 历史路径对照(2026-09-11 分区)

| 旧路径 | 新路径 |
| --- | --- |
| `tools/sbin/*` | `tools/LIMIT/sbin/*` |
| `tools/stack-check/*` | `tools/LIMIT/stack-check/*` |
| `tools/script/opcode.cjs` | `tools/LIMIT/script/opcode.cjs` |

## 约定

1. 新增工具先判断"是否只服务某一个世界":是 ⇒ 放进对应世界子目录;否 ⇒ 放本目录。
2. 世界子目录比本目录**多一层**,用 `__dirname` 推算仓库根目录的工具必须相应多加一级 `..`。
3. 含非 ASCII 字符的文件保存为**带 BOM 的 UTF-8**;以 `#!` 开头的脚本**不加 BOM**(会破坏 shebang 解析)。

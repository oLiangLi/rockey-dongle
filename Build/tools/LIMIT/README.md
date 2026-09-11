# Build/tools/LIMIT —— LIMIT_WORLD 专属工具

适用对象:**在 ukey 中运行的程序**(`rLANG_CONFIG_ENABLE_LIMIT_WORLD`,受限世界:不允许 `.rodata`、不允许查表、`.bss` 预算 16B、栈预算 2032B)。本目录的工具只服务该世界,其它世界不需要。

## sbin/(宿主侧运维工具)

| 工具 | 用途 |
| --- | --- |
| `run-dongle-exe.cjs` | 先复制改名再执行测试程序(避免直接运行被占用的 exe) |
| `ukey-reset-dgram.cjs` | 通过 UDP 复位 ukey |
| `check-gpg-sigs.cjs` | 检查 `mkey/` 下 OpenPGP 签名文件是否完整 |
| `rsa-prime-repro.cjs` | 与设备算法逐位对齐的素数生成复现工具 |

## stack-check/

`stack-check.cjs` —— 设备栈预算检查,由 `make rockey-stack-check` 调用;默认预算 2032B,可用 `BUDGET=` 覆盖。加完设备侧代码后必须运行。

## script/

`opcode.cjs` —— 以 `Interface/script.h` 的 `enum class OpCode` 为唯一事实源,生成 `Web/Script/lib/opcode.ts`。由 `make jsWrapper` / `npm run gen:opcode` 调用。`Interface/` 不跨世界共享,故该工具随本世界。

## 约定

- 含非 ASCII 字符的文件保存为**带 BOM 的 UTF-8**;以 `#!` 开头的脚本**不加 BOM**。
- 用 `__dirname` 推算仓库根目录时注意:本目录下比 `Build/tools/` 深一层。

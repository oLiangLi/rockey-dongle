# Build/tools/ATOMC —— ATOMC_WORLD 专属工具(占位)

`ATOMC_WORLD`(`rLANG_CONFIG_ENABLE_ATOMC_WORLD`)的内存预算宽松(可达 640K),**没有** `LIMIT_WORLD` 的"不允许 `.rodata`/不允许查表/栈 2032B"等限制。

属于该世界的工具放在本目录;目前为空。

## 约定

- 新增世界时按 `tools/<WORLD>/` 建目录;只服务单一世界的工具不得放在 `tools/` 根下。
- 门控方向:把"限制"正向门控在 `LIMIT_WORLD` 上,宽松实现作为 `#else` 缺省,这样 ATOMC/其它世界自动可用(见 `base/src/data.cc` 的 CRC 实现范本)。
- 含非 ASCII 字符的文件保存为**带 BOM 的 UTF-8**;以 `#!` 开头的脚本**不加 BOM**。

# Build/tools/COSMO —— COSMO_WORLD 专属工具(占位)

`COSMO_WORLD`(`rLANG_CONFIG_ENABLE_COSMO_WORLD`)侧专属的工具放在本目录,由该世界一侧维护。

目前为空。

## 约定

- 跨世界可共享/对齐的只有 `base/` 与 `Build/` 两棵树;两个世界的 `Interface/` **同名但无关**,不共享、不合并。
- `rLANG_WORLD_MAGIC` / `rLANG_ATOMC_WORLD_MAGIC` / `rLANG_COSMO_WORLD_MAGIC` 是共享协议值,任何世界都必须一致,**不得**用世界宏包裹。
- 含非 ASCII 字符的文件保存为**带 BOM 的 UTF-8**;以 `#!` 开头的脚本**不加 BOM**。

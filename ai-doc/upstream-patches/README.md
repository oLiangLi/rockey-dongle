# 回馈上游的补丁(2026-09-11)

这里的 `.patch` 是对**上游仓库**(`base` / `build`)
的**建议改动**,不是本仓代码。生成方式: 在上游 scratch 仓库里建分支提交, 再 `git format-patch -1`。

背景与 B 类清单见 `ai-doc/upstream-base-merge-plan-2026-09-11.md` §4。

## 约定: `rLANG_CONFIG_ENABLE_LIMIT_WORLD`(受限世界)

> **用户定义(2026-09-11)**: `LIMIT_WORLD` 指定**在 ukey 中运行的程序**。

- 含义: 该构建产物会跑在 ukey 内 —— 受限世界, **不允许占用 `.rodata`**(设备固件要求 `.rodata` 为空、
  flash 与栈预算都很紧), 因此 base/Interface 里凡是"用表换速度"的实现, 都要在定义该宏时退回无表实现。
- 定义位置(本仓): `Build/config/arm-none-eabi.conf`(即 `make dongle` 的配置; 该配置编译出的整个固件
  就是 ukey 内运行的程序)。`base` 作为库随该配置一起编译, 因此宏对库与调用方一致生效。
- 使用方式: 使用方只需给"ukey 内运行的程序"那一份构建配置加 `-DrLANG_CONFIG_ENABLE_LIMIT_WORLD`,
  **不需要改任何调用方代码**。

## 已生成

| 文件 | 上游仓库 | 内容 |
| --- | --- | --- |
| `0001-x25519-zero-check.patch` | `base` | `rlCryptoX25519` 拒绝全零共享密钥(RFC 7748 §6.1),返回值 `void` → `int`(B1) |
| `0002-crc-limit-world.patch` | `base` | CRC8/16/32 支持 `rLANG_CONFIG_ENABLE_LIMIT_WORLD`: 默认保持查表, 受限世界走**无表逐位**(B4) |

应用方式(在上游仓库内, 建议按序):

```sh
git am /path/to/0001-x25519-zero-check.patch
git am /path/to/0002-crc-limit-world.patch
```

### B1 细节与影响

- **动机**: 原实现返回 `void`, 调用方无法发现"对端公钥是低阶点(小群元素)"导致的**全零输出** ——
  此时双方会静默接受一个攻击者可控的"共享密钥"。本仓已按同一思路实现(见本仓 `base/src/crypto.cc`,
  对应安全清单 H-06), 该补丁是把它回馈上游。
- **API 变更**: `void` → `int`(`0` = 成功, `-EFAULT` = 输出全零)。上游 `base` 内**无调用方**
  (仅 `bits/base.h` 声明与 `src/crypto.cc` 定义), 但 wasm/JS 导出层与下游使用方需同步;
  补丁提交信息给出"新增 `rlCryptoX25519Ex()` 保持旧签名"的备选方案。

### B4 细节与等价性

- **动机**: 上游 CRC8 用 256B 表、CRC16 用 512B 表、CRC32 用 16 项(64B)半字节表; 受限世界不能带表。
- **做法**: `#if !defined(rLANG_CONFIG_ENABLE_LIMIT_WORLD)` 包住原查表实现(`#else` 为无表), 表内容
  与调用语义完全不变; 无表实现逐位等价(CRC8 LSB-first poly `0x8C` = `0x31` 反射、CRC16 MSB-first
  `0x1021`、CRC32 反射 `0xEDB88320`)。
- **验证**(本仓侧): 两种编译模式分别独立编译 `data.cc`, 与"由多项式推导的参考表"逐项比对 ——
  CRC8 全 65536 组、CRC16/CRC32 抽样 **0 处不一致**; 标准向量 `CRC-16/CCITT-FALSE("123456789")=0x29B1`、
  `CRC-32=0xCBF43926` 全对; `nm` 确认无表模式下目标文件与固件**均无 CRC 表符号**。
- **坑(自测抓到的真 bug)**: 无表 CRC16 的索引必须先移到高字节(表项 = `MSB8步(i << 8)`), 首版漏了这一步。

## 复核结论: B2/B3 不需要回馈

原 B 类清单里的 B2、B3 在生成补丁前逐行核对上游 HEAD 后**撤销**, 原因是它们并非上游缺陷:

| 原编号 | 原设想 | 核对结果 |
| --- | --- | --- |
| B2 | `cipher_cleanse` 改为哈希派生填充 | **上游 HEAD 已是哈希派生实现**(`src/crypto.cc:7-16`, 与本仓逐行相同); 本仓差异只是把整段 libc shim 用 `#if 0` 关掉, 无需回馈 |
| B3 | `log.cc` 的 `LOGDATA_SIZEMAX` 1024→2048、日志等级判断 | **语义等价, 非缺陷**: 本仓枚举 `rlLOG_NONE=0 … VERBOSE=5`(上游把 0 命名为 `rlLOG_FATAL`); `level <= rlLOG_NONE` 与上游 `level < rlLOG_FATAL` 都只是拒绝非法等级; `2048` 是本仓缓冲偏好 |

## 编码约定(UTF-8 带 BOM)

> **约定(用户 2026-09-11)**: 文件里**含非 ASCII 字符**时, 必须保存为**带 BOM 的 UTF-8** ——
> 否则中文注释在 Windows 侧(按本地代码页解码)会显示成乱码。

- 本目录的两个补丁都**自带**该约定: 它们的补丁体里各含 1 行"给目标文件补 BOM"的变更
  (`0001` → `src/crypto.cc`;`0002` → `src/data.cc`;`bits/base.h` 上游本来就有 BOM)。
  所以应用补丁后**不会**出现中文注释乱码, 无需再手工转换编码。
- 例外(**不要**给这些加 BOM): 以 `#!` 开头的脚本(shebang 前有 BOM 会导致
  `bad interpreter` 无法执行);二进制/压缩文件。

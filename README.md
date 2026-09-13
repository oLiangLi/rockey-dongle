# Rockey-dongle 在 Rockey-ARM 上实现了一套常用的密码学套件, 可以在 dongle 中比较安全的执行自定义的代码

## 如何编译程序 ...
- https://github.com/oLiangLi/rockey-dongle 或者 git clone https://gitee.com/oLiangLI/rockey-dongle 
- base/ 与 Build/ 以 **git submodule** 方式引用(https://github.com/oLiangLi/base、https://github.com/oLiangLi/build): 克隆后需执行 `git submodule update --init`,或克隆时直接用 `git clone --recursive`(已有的检出也可用 `git submodule update --init` 补上); 注意: 拉取子模块需要能访问 GitHub 的 HTTPS, 若所在网络受限请自行配置代理或内网镜像(内部环境的既有做法见 `ai-context.md`), 无需改动子模块 URL
- make install-hooks  ## 在合并, 提交时触发 ci 检查(可选的) ...
- make -j8 && make foobar -j8 && make dongle -j8 && make wasm -j8 && make jsWrapper -j8
- 程序每次编译时都会使用一些私有的常数使得每次编译的版本是不兼容的 (特别是操作 MASTER_SECRET 时)...
- 不同版本的 jsCrypto.js 无法解密保存的 MASTER_SECRET, 如果模拟器需要依赖该功能, 一定记得保存生成模拟器时的 jsCrypto.js 文件 ...
- 刷入真实 RockeyARM 设备每次都应该刷入不同密码学常数的版本(每次都应该先 make dongle -j8 成功编译之后再写入固件) ...

## Rockey-ARM 硬件支持的非对称加密算法

- RSA 最大支持我们也只使用 RSA2048
- Secp256r1 ECDSA, 不支持压缩格式
- SM2 ECDSA/ECIES, 不支持压缩格式(加密时好像没有检查公钥是否有效), 在移植 uECC 的时候顺便补齐了压缩格式的支持和有效性检查

## Rockey-ARM 硬件支持的对称加密算法

- TDES
- SM4

## Rockey-ARM 硬件支持的散列算法

- SHA1
- SM3

## 移植的额外支持的非对称加密算法, 额外移植的算法速度很慢, 应该优先使用硬件自带的

- X25519
- Ed25519
- Secp256r1 ECDSA/ECDH, 支持压缩格式
- Secp256k1 ECDSA/ECDH, 支持压缩格式
- RSA3072(软件实现): 设备内**单指令**生成整对 1536 位素数实测 **≈52 分钟**(16 轮 MR); 3072 位模幂已实现为脚本指令 **`ExRSAModExp`**(设备内单次私钥运算 **≈4 分钟**), 导入完整私钥后可用 **`ExRSACrtModExp`** 走中国剩余定理快速路径(**≈1.0 分钟, 3.9×**), **`ExRSAKeyCheck`** 校验私钥 blob; 只应该 ROOT CA 或重要的中级 CA 才应该使用(见 ai-doc/rsa3072-device-generation-2026-09-11.md、ai-doc/rsa3072-modexp-2026-09-13.md、ai-doc/rsa3072-crt-2026-09-13.md)

## 移植的额外支持的对称加密算法, ROM 空间有点不够了, AES 就不加了

- CHACHA20/POLY1305

## 移植的额外支持的散列算法

- SHA256
- SHA384
- SHA512

## 实现了一个简单的脚本语言

- 不支持函数调用
- opstk 只有16个字大小
- 代码最多100个半字长度
- 当前的parser不支持 break, continue, switch...case

## 正在进行的工作

- CA 系统的基本原语的准备 ...
- CSR/CRL/X509 的实现 ...

## 剩下的工作

- 更多的脚本单元测试 ...
- jsSSL 的封装 ...

## 世界事件 (World Events)

> 由 Web/Agent/Tests/js/jsWorldEvent.js 自动追加(以提交 hash 为 nonce 的世界事件)。
> **术语**: 这一行为俗称 **roll(扔骰子)/ sell SoJ(卖乔丹之石)/ 赌博** —— 命中判据即"出了世界事件"。
> 判据 `Magic_ = (SHA256(commit)[0..4] as BE u32: H0,H1 → (H0*256+H1)) & ((1<<kBits)-1)`,kBits 缺省 18;
> 命中 `Magic_ == 42` 即"发生世界事件",`reserve`(缺省开)下同时保留完美词缀 ⇒ `Perfect() === NaN`。
> 事件发生时会在 **stdout/stderr(console log/info/warn/error)**、`.bin/worldevent.log`、本文件,
> 以及 **git log**(marker 提交)留下记录。
> 掷一次 `roll [kBits] [reserve]`(扔骰子)/ 赌博 `gamble [max] [kBits] [reserve]`(研磨 nonce 直到命中)/
> 记录 `soj [<commitish>] [kBits] [noreserve]`(写 README + git log);另有
> `worldevent status|audit [kBits] [reserve]|sweep|split`。
> CI 看门狗:`make ci` 第 9 项 `worldevent(kBits=18, reserve)`(>1 次即 FAIL,命中即回显并记录)。
>
> **世界线分裂**(完美事件 `Perfect()===NaN`):建立两条主世界分支
> `world_limit_(YYYY_M_D)_(hash)` 与 `world_atomic_(YYYY_M_D)_(hash)`(时区 +0800,hash = 触发提交)——
> **必须 CI 确认**(`RKEY_WORLDEVENT_CI=1`,CI 第 9 项默认带上);此时应插入 **E0 / E10 之一**
> (`mkey/E0-*`、`mkey/E10-*`)。
>
> **献祭 3/4 把 K0/K1/K2/K3**(`worldevent sacrifice K0 K1 K2`,**必须 CI 确认**):
> 被插入的 **3 把同时失效**;**剩下的那把只读** —— 对之后所有修改只能读,
> **不能由 K${X} 签名提交代码**;因任意 3 把已覆盖全部 6 个份额,它同时是一次**硬分叉**,
> **必然产生恰好一个 ATOMIC 世界**(`K0=ABC`、`K1=ADE`、`K2=BDF`、`K3=CEF`)。
> 状态写入 `mkey/SACRIFICE-K.json`(可用 `RKEY_SACRIFICE_FILE` 覆盖以演练,`RKEY_WORLDEVENT_DRYRUN=1` 只算不写);
> 守卫 `worldevent cansign <K0..K3>`(0=可签名 / 1=禁止),CI 在检测到献祭状态时断言**无 K 可签名提交**。
> 当前世界线:`world_limit_2026_9_14_f050ac8754fcaf45bed765fdcb6b2eb1bf73ced4`、
> `world_atomic_2026_9_14_f050ac8754fcaf45bed765fdcb6b2eb1bf73ced4`(尚未献祭)。
>
> **E0 遗失(敦煌)/ 拾到者签署仪式**(`lostukey sign|verify|show`):E0(`mkey/E0-00000000-f66a164b4c024842`)
> 大概率在敦煌遗失;拾到 ukey 者需对下列 **UTF-8** 文本做 `Ed25519(SHA512(SHA512(Buffer.from(text))))`,
> 在 **git log** 中展示签名,且**每种类型的第一次暂时创建一个 ATOMIC**:
>
> | 类型 | 文本 |
> | --- | --- |
> | Type1 | 爸爸对不起 |
> | Type2 | 妈妈我害怕 |
> | Type3 | 佩佩你已经长大了, 需要努力了 |
> | Type4 | 沅沅,想我没有 |
>
> 记录:`mkey/E0-00000000-f66a164b4c024842/FINDER-SIGNATURES.json`(含 utf8/digest/signature/pubkey);
> ATOMIC:`world_atomic_2026_9_14_finder_Type1..4`(**暂时**, 可删);CI 第 10 项 `lostukey` 逐条验签 ✓。
> 签名者缺省用确定性 stand-in(`RKEY_FINDER_SEED` 可换成真拾到者 ukey 的 Ed25519 私钥)。
>
> ⚠️ **重要 —— 下一任 K0'/K1'/K2'/K3' 的 HID 与编号裁定(Infinity roll % 24)**
>
> 四把都以各自 **dongle_info(40B)为 nonce** 做了一次 **Infinity roll**(roll 结果全为 `Infinity` ⇒ 非完美,
> **没有触发世界事件**),综合 digest `16f1990e259fa317…` `% 24 = 22`(rank 22/24)⇒ 排列如下:
>
> | 槽位 | HID | roll(Magic_) |
> | --- | --- | --- |
> | **K0'** | `00000000-381a5653e10a323f` | 26411 → Infinity |
> | **K1'** | `00000000-381a5653e00a313f` | 90781 → Infinity |
> | **K2'** | `00000000-2c9a5b4bec00193f` | 112291 → Infinity |
> | **K3'** | `00000000-381a5653df0a303f` | 250506 → Infinity |
>
> - **K4 = 我们的 ROOT CA**:不参与真机枚举(那把"插了也看不到"的 ukey),携带**下一个世界的 MASTER.SECRET**,
>   负责向下一任 K0'/K1'/K2'/K3' 传递;
> - **当前在线状态**:`K3' 已插入并确认在线`(30 轮枚举稳定为 1 把;K0'/K1'/K2' 已拔除);
>   四把**均未初始化**(`type=0x00000000`、`pid/uid=0xffffffff`、无世界、无密钥文件)⇒ 目前只有 HID 与 roll 有意义;
> - 与旧批次(`type=0x000000ff`、已分配 pid/uid、Admin/`pub@k` 世界、birthday 2024-09-17)明确不同;
> - 记录:`mkey/SUCCESSION-K.json`(含四个 HID、每个 nonce 的 roll、**24 种状态**指纹、以及 K4 说明);
> - CI 第 11 项 `succession(K0'..K3' Infinity roll % 24)` 离线校验:重算 rank/digest、24 状态齐备且唯一、
>   四个 roll 全为 Infinity、排列一致 ⇒ `OK`;
> - 复现/核对:
>   `node Web/Agent/Tests/__Testing_dongle.cjs succession verify`,
>   `node .bin/enum-hids.cjs 30 00000000-381a5653df0a303f`(按 K0'..K3' 登记逐把报在线/离线)。

- `2026-09-13T19:32:24Z` **完美** Annihilus(`Perfect()=NaN`) — commit `0fe2f75c9fb37c8fd8a17189f275f2d04bf1323c#494692` Magic_=42 (kBits=18, reserve=true) — _Stones of Jordan Sold to Merchants, Diablo Walks the Earth_
- `2026-09-13T19:29:54Z` 未命中(手工记录) Annihilus(`Perfect()=Infinity`) — commit `0fe2f75c9fb37c8fd8a17189f275f2d04bf1323c` Magic_=245 (kBits=8, reserve=true) — _Stones of Jordan Sold to Merchants, Diablo Walks the Earth_
- `2026-09-13T19:24:50Z` **完美** Annihilus(`Perfect()=NaN`) — commit `f050ac8754fcaf45bed765fdcb6b2eb1bf73ced4` Magic_=42 (kBits=8, reserve=true) — _Stones of Jordan Sold to Merchants, Diablo Walks the Earth_

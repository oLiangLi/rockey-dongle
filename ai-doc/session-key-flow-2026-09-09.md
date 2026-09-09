# SESSION_KEY(会话世界密钥)流程整理(2026-09-09)

> 依据 mkey/* 档案、Web/Agent/Tests/Tests/*.dongle 脚本与 Interface/ 设备源码整理。
> **测试边界**: mkey/* 下记录到的所有 ukey(K0..K3、A0、E0/E1/E10、C1/C4、jsEmulator…)
> 均属生产/离线鉴证或已锁定设备 —— **任何情况下不作为测试用途、不驱动**。
> 复现一律使用全新 JS 模拟器(每次随机 secret)或新建文件 ukey; 唯一允许的真机
> (仅 Windows 端, 且禁 factory lock)为仓库既有测试 ukey 00000000-efea115bfc084642,
> 它不属于 mkey/* 集合。

## 1. 背景与角色

rLANG 世界里的"会话密钥": 由**签发者(Root/主密钥持有者)**按客户端 ukey 的
Master(-1).X25519 公钥与一组会话参数(Session Type/Category/有效期/Message)签发
一条 **SESSION-KEY**, 客户端导入后获得一个可用的"会话世界"(含根签名的会话头与
会话 Ed25519 身份), 再跑 SESSION_KEY_SIGNATURE 提交自己的会话签名后锁定。

记录里可辨识的参与方(以 mkey 档案为准):

| 角色 | 档案 | dongle | 备注(仅记录所见) |
|---|---|---|---|
| 主密钥/签发者 = A0(记录里 E0 README 写作 "W0" —— 用户澄清: W0 是 A0 的早期叫法, A0 的 hex 串(00000000-e886180b670b14a2)无 'W', 以 A0 为准) | A0-00000000-e886180b670b14a2 | uid 0xa0, pid 0x587908e4 | ImportMasterSecret 后"签署 EXPORT_SESSION_KEY 脚本文件"并锁定; T0/E0 会话头 ROOT pub 均为 QKjf… 一致 |
| 客户端 | E0-…-f66a164b4c024842 | uid 0xe0 | 4 个会话 Type 1..4, Message "LiangLI-E0-…", Category 0x864B40AF(adm), 有效期 2026-04-01→2027-01-01 |
| 客户端 | E1-…-f66a164b4a024542 | uid 0xe1 | Session Type 1, Message "E1-Client-f66a164b4a024542"; README 含 signedCode |
| 客户端 | E10-…-ef6a125b02094d42 | uid 0xe10 | 档案含 SignedCode-E10-SESSION-KEY-SIGNATURE 程序 |
| 客户端 | C1-…-f66a0b5b7e094b42 / C4-…-bbfe144b480622a2 | uid 0xc1/0xc4 | "导入 SESSION-KEY + 签 SESSION_KEY_SIGNATURE 后锁定, 初始化为 Admin-1000/Admin-5000 + EnTrust-Null"(Admin-N 含义见 §6 Q6) |
| 测试客户端 | T0(无硬件档案) | — | A0 README: 重初始化→导入 SESSION-KEY→结果含 ROOT pub QKjf…、Message "Hello world!…"、Type 1、Category 0xC35880AF(pub, 模板"仅测试用"默认值)、NB/NA 2282/2465; 验签无误后重置 |

注: "W0" 只见于 E0 README 措辞(早期叫法), 规范为 A0(见上表与 Q1)。

**使用状态(用户 2026-09-09, 已更正)**: C1 与 C4 是**当前使用中**的两个 session-key(客户端);
此前口述 "C1/C2" 中的 **C2 是 C4 的误写**。C* 的 uid(0x000000c1、0x000000c4…)即其
session-key 标识, 与 mkey/Client 下 C1/C4 两份初始化档案一一对应, 不存在独立 C2/C3 客户端。

## 2. 会话头(根签名明文)布局 —— 三种脚本共用

Session 头固定 180B(Ed25519 简化验证, 替代 X509, 见 EXPORT_SESSION_KEY.dongle 注释):

```
/*   0 */ rLANG_ROOT_Pubkey[32]      /* 签发者 Ed25519 根公钥 */
/*  32 */ rLANG_INPUT_Message[32]    /* 用户可读 string[32](非密钥材料), 用于日志中确认身份(用户 2026-09-09 澄清; 记录例: "E1-Client-f66a164b4a024542"、"LiangLI-E0-…"、"Hello world!") */
/*  64 */ rLANG_SESSION_Pubkey[32]   /* 会话 Ed25519 公钥(由共享种子派生) */
/*  96 */ rLANG_WORLD_MAGIC[i32]     /* 0xC8C04E1F 'rLANG' */
/* 100 */ rLANG_INPUT_SESSION_Type[i32]  /* 计划 1..9; 当前实际用 1..4 —— 1=签名设备(Device)
                                            2=签名 boot(Bootloader) 3=签名 core(=Firmware)
                                            4=签名 app(Application)(用户 2026-09-09 澄清) */
/* 104 */ rLANG_INPUT_Category[i32]  /* 0xC35880AF 'pub@k'(仅测试) / 0x864B40AF 'adm@k' */
/* 108 */ rLANG_INPUT_NotBefore[i32] /* 以 2020-01-01 起的天数(记录例: 2282=2026-04-01, 2465=2026-10-01, 2557=2027-01-01) */
/* 112 */ rLANG_INPUT_NotAfter[i32]
/* 116 */ rLANG_ROOT_Signature[64]   /* Ed25519 根签名(覆盖 0..116) */
/* 180 */
```

## 3. 签发(EXPORT_SESSION_KEY, 在签发者上跑; A0 的 SignedCode-ExportSessionKey 即此程序)

数据段(输入, 相对缓冲绝对偏移):
- `rLANG_INPUT_CV25519_Pubkey @256 [32]`: 目标客户端 Master(-1).X25519 公钥
- `rLANG_INPUT_SESSION_Type @288 [4]`、`Category @292 [4]`、`NotBefore @296 [4]`、
  `NotAfter @300 [4]`、`Message @304 [32]`

输出段(public 228):
- `rLANG_OUTPUT_ENCRYPT_CHAIN @0 [196]` = 会话头 180B + ChaCha20-Poly1305 mac 16B
- `rLANG_OUTPUT_CV25519_Pubkey @196 [32]`: 本次签发的**临时** X25519 公钥

算法(按脚本指令):
1. Type∉[1,10] → Exit(42)(非零退出即失败, 同 master 流约定)。
2. 回填 Message/WORLD_MAGIC/Type/Category/NB/NA 到头部对应字段。
3. `ExCurve25519GenerateKeyPair` 生成临时 X25519 私钥(暂存于 Signature 槽 116..148)与公钥(→196)。
4. `ExCurve25519ComputeSecret(临时私钥, 客户端 CV25519 公钥)` → 共享种子 32B(→260)。
5. `ExEd25519ComputePubkey(共享种子)` → `SESSION_Pubkey @64`: **会话 Ed25519 身份 =
   以共享种子为 Ed25519 种子派生**, 两端(签发者/客户端)可各自算得同一公钥。
6. `ComputeSecretBytes(116, 42)` → 读签发者 **World-ROOT-Prikey(secret type 42)**;
   `ExEd25519ComputePubkey` → `RootCA @0`(会话头里的根公钥)。
7. `ExEd25519Sign` 覆盖头 0..116 → `Root_Signature @116`。
8. `NONCE = SM3(临时CV25519公钥)`; `ExChaChaPolySeal(共享种子, NONCE, 头0..180)` →
   密文链(输出 ENCRYPT_CHAIN, mac 落在 180..196)。
9. 头/临时公钥输出, 私钥与敏感区清零。

要点: 每条 SESSION-KEY 对应"签发者临时 X25519 × 客户端主 X25519"的一次 DH,
种子直接当 Ed25519 种子 → 同一客户端不同签发批次得到不同会话身份;
签发者不需要客户端任何私钥。

## 4. 导入(IMPORT_SESSION_KEY, 在客户端上跑)

数据段: `rLANG_INPUT_ENCRYPT_CHAIN @256 [196]` + `rLANG_INPUT_CV25519_Pubkey @452 [32]`。
1. `Memcpy(0, 256, 256)` 把链与公钥拷入低区(输出区)。
2. 客户端用自己的 Master(-1).X25519:`Memset(-1,64);ComputeSecretBytes(256)`;
   `ExCurve25519ComputeSecret(主私钥, 临时公钥)` → 同一共享种子(→212, 即 CIPHER 槽)。
3. `NONCE=SM3(临时公钥)`;`ExChaChaPolyOpen(CIPHER@212, NONCE, 0, 196)` 解链;
   失败 → Exit(42)。**不校验解密内容**(注释: 错误数据过不了后续客户端验证, TEXT 长度不够)。
4. Type>10 → Exit(14)。
5. `Memcpy(180, 212, 32)`: 共享种子放 STORE_CIPHER@180; 与 `SM3(MasterSecret[64])` 异或
   → **静态混淆后的会话私钥**(仅本机可还原)。
6. `WriteDataFile(0x100+Type, 0, 0, 212)`: 持久化 [0..212)(会话头 180B + 混淆私钥 32B)
   到数据文件 0x100+Type。

随后跑 SESSION_KEY_SIGNATURE(客户端, 有管理员权限):
- 读取 0x100+Type 共 212B; 用 `SM3(MasterSecret)` 还原会话私钥;
- 对 `INPUT_Message[64]`(输入)先 SHA512, 再用会话 Ed25519 私钥签名 → `SESSION_Signature @180 [64]`
  (输出完整会话头 + SESSION_Signature, public 244);
- 脚本注释强调: 正常客户端**不应**做 SM2ECIES 私钥托管(EnTrust), 导入后应尽快锁定 ukey。
- **用途边界(用户 2026-09-09 澄清)**: session-key 总是为**特定用途的签名**而构造
  (Type = 该签名域), ukey 锁定后**只做该特定类型的签名用途**(即 SESSION_KEY_SIGNATURE
  签名域), 不做世界创建/Admin 等其他操作。

E0/E1/E10/C1/C4 档案中的 `SignedCode-*SESSION-KEY-SIGNATURE.dongle.program` 即此程序的
LIMIT 预签名版本(208B signedCode), 与 EXPORT 预签名程序(仅 A0 有 SignedCode-ExportSessionKey)
对应。

## 5. 素材矩阵(整理到哪、各是什么)

- 脚本源(仓库 Tests/ 与 jsScriptBundled 模板同源): EXPORT_SESSION_KEY / IMPORT_SESSION_KEY /
  SESSION_KEY_SIGNATURE(.dongle); 辅助: MASTER_SIGNATURE、MASTER_ED25519(Master(0).ed25519
  签名工具)、MasterExport(Master(-1) X25519/Ed 导出)、MASTER_X25519 等。
- 预签名程序: mkey/A0-*/signed-script/SignedCode-ExportSessionKey.dongle.program(=EXPORT 模板);
  E0/E1(signed-script 子目录)/E10(顶层)的 SignedCode-…SESSION-KEY-SIGNATURE.dongle.program
  (=SESSION_KEY_SIGNATURE 模板); Bootstrap-* 为建世界/EnTrust/导出等通用前置。
- 会话记录: A0/README(T0 会话导入结果与验签)、E0/README(4 组会话头逐字段)、
  E1/README(SESSION-KEY 输出头 JSON)、Client/C1.md+C4.md(导入+签名+锁定,PIN/锁记录为 PGP)。
- jsScriptBundled.js(mkey/tools/Tests 与 Web/Agent/Tests 各一份)内嵌模板文本含详细注释。

## 6. 开放问题(待用户/档案澄清)

- ~~Q1 "W0"(E0 README 措辞)与 A0 或某把 root dongle 的关系~~ **已澄清(2026-09-09 用户): W0 是 A0 的早期叫法; A0 的 hex 串不含 'W', 规范名 A0。签发者 = A0。** E0 README 里 "从 W0(=A0) 导入 1,2,3,4 共 4 组 SESSION-KEY" 与 A0 README(导入 MASTER 后签署 EXPORT_SESSION_KEY 并锁定 A0)吻合。
- ~~Q2 会话文件 0x100+Type 的 212B 头部(180B 会话头)在客户端后续生命周期中的用途~~ **已澄清(2026-09-09 用户): session-key 总是为特定用途的签名而构造(Type=该签名域), ukey 锁定后只做该特定类型的签名用途(SESSION_KEY_SIGNATURE 域); 不用于世界创建/Admin 等其它操作。** 会话文件 = 该锁定签名域的凭据(头 + 混淆私钥), 配合 SESSION_KEY_SIGNATURE 每次签名时还原。
- ~~Q3 Type 语义与 Category 在客户端"Admin-1000/5000"(C1/C4)里的对应关系~~ **已澄清(2026-09-09 用户): Type 计划 1..9, 当前实际用 1..4 —— 1=签名设备, 2=签名 boot, 3=签名 core(Firmware), 4=签名 app(Application); 每个 Type 是一条独立的代码签名域会话。**
- ~~Q3b Type/Category 对应关系~~ **已澄清(2026-09-09 用户): Type 与 Category 无对应关系; Type 当前就是 1..4; Category 用于标注设备类型(记录值如 pub@k 0xC35880AF / adm@k 0x864B40AF), 预留 Firmware/Application 使用。**
- Q6 "Admin-1000/5000"(C1/C4 README 措辞) **已解释(2026-09-09 用户)**: "Admin" = Admin 域(要求**代码签名或数据签名**); "1000" = SM2ECIES-key(id 4) 只允许使用 **1000 次** —— 是内置在 `signed-script/Bootstrap/Bootstrap-Admin-1000.dongle.program` 的简写(该程序为建置 Admin 世界的 bootstrap, 输出 WorldMagic/Category 等)。C4 记录里的 "Admin-5000" 应为同型(5000 次)的早期叫法, 未见对应 Bootstrap-Admin-5000 程序文件归档。
- ~~Q4 C1/C4 会话 Message 的实际字符串(记录未逐字给出)~~ **已澄清(2026-09-09 用户): Message 是用户可读 string[32], 用于日志中确认身份, 非密钥材料。**(C1/C4 的具体字符串仍需从档案/设备日志读取则另议)

## 7. 复现结果(`skey` 命令, 2026-09-09 已在全新 JS 模拟器上跑通)

`node Web/Agent/Tests/__Testing_dongle.cjs skey [issuerIdx] [clientIdx]`(默认 issuer=emu0,
client=emu1)完成整条 SESSION 链并在进程内验证:

1. 客户端跑 MasterExport 取 Master(-1).X25519 公钥(CV25519);
2. 签发者跑 EXPORT_SESSION_KEY(参数对齐 T0 记录: Message="Hello world!"+零填充、
   Type=1、Category=0xC35880AF、NotBefore=2282、NotAfter=2465) → ENCRYPT_CHAIN[196] + 临时 CV25519 pub;
3. 客户端跑 IMPORT_SESSION_KEY → 输出会话头(RootCA/Message/SESSION_Pubkey/Type/Category/NB/NA/
   ROOT_Signature), 落文件 0x101;
4. 客户端跑 SESSION_KEY_SIGNATURE → SESSION_Signature;
5. 外部核对(均 PASS, ok=true, exit 0):
   - **根公钥复算**: 签发者跑 MASTER_SIGNATURE(type=42, SEEDS=0) 得到的 Ed25519 pub
     == 会话头 RootCA(master.cc 语义: ComputeSecretBytes(·, type) 把 type/输入64B/master/种子
     +随机域混淆后 SHA512 → 派生域密钥; type42 即 World-ROOT 域);
   - **根验签**: Ed25519 验签 ROOT_Signature over 头 0..116 → true;
   - **会话验签**: Ed25519 验签 SESSION_Signature over SHA512(INPUT64) → true
     (证明客户端还原的混淆会话私钥与共享种子一致, 会话身份可用);
   - 字段格式: type=1 / cat=0xc35880af / nb=2282 / na=2465 与 T0 记录一致
     (根公钥因全新模拟器 master 不同而异, 属预期)。

## 8. 下一步/开放问题

- Q1(W0=A0)、Q2(锁定后仅该 Type 签名)、Q3/Q3b(Type/Category 无对应)、Q4(Message=可读 string[32])、Q5(C2=C4 误写)、Q6(Admin-1000 = Admin 域 + SM2ECIES-key 1000 次简写)均已澄清。
- 扩展: 多客户端/多 Type(1..4)批量签发对照 E0 记录; 2 台以上客户端各自导入并互不串扰;
  Type/Category 与客户端"Admin-1000/5000"(C1/C4)的世界创建衔接; 文件 ukey 代理承载
  session 存储(0x100+Type 数据文件)的持久化往返。

## 9. 真机 key4(SM2ECIES)使用次数验证(2026-09-09, Windows 端测试 ukey, 全程不 lock)

- **宿主封装(按用户指引)**: SDK `Dongle_ListFile` 未上 RockeyARM 产品接口(工具查看用),
  现封装为 `dongle_entry --listfile[:<type>] <hid> [admin]`:
  - `Interface/dongle.h/.cc`: `RockeyARM::FileList(nFileType, void*, int*)` → `Dongle_ListFile`;
  - `src/app/main.cc` Utilities 新增 `listfile` 分支(输出单行 Base64 + OK);
    已重建 `.bin/amd64-windows-release/dongle_entry.exe`;
  - type: 1=DATA 2=PRIKEY_RSA 3=PRIKEY_ECCSM2(缺省) 4=KEY 5=EXE;
    私钥条目 16B = FILEID u16|Reserve u16|m_Type u16|m_Size u16|**m_Count i32**|priv u8|decOnRAM u8|reset u8;
    m_Count=-1(0xFFFFFFFF)=不限; 每次私钥调用递减, 到 0 禁用。
- **实测(测试 ukey 00000000-efea115bfc084642)**:
  - INIT-0x10000 基线: key1(SM2ECDSA)/key2(P256)=不限; key4(SM2ECIES)=**65535**(0x10000−1);
  - 重建 Bootstrap-Admin-1000 后 key4=**999** —— 建置过程消耗 1 次(**构造会耗签名次数, 剩余 <1000**, 印证用户说明);
  - 再 1 次 `SM2Sign(4)`(数据签名) → **998**; 反复烧至 count=0 后 key4 被禁用(SM2Sign 失败) —— 阈值耗尽成立;
  - key4 属性 priv=2(管理员权限)、decOnRAM=0(**FLASH 持久递减**)、reset=0。
- **模拟器同步实现(2026-09-09)**: 文件/JS/wasm 共用 `Interface/emulator.cc` 现实现 licence 递减
  (`DongleHandle::key_licence_` 表 + `KeyLicenceUse`): `CreatePKEYFile` 记录
  {count/perm/decOnRAM/reset}; RSA/SM2/P256 私钥操作前递减, count==0 拒绝(-EPERM)。
  重建 wasm + JS 封装(Web/Assembly/Emulator.wasm、Web/Agent/Tests/js)后, 进程内模拟器
  与真机同路径验证: Bootstrap-Admin-1000 建置后 key4 计数 1000→**999**(建置耗 1);
  `SM2Sign(4)` 成功 **999** 次, 第 1000 次拒绝(脚本检查返回值后 `Exit(7)`)。
  工具: `emuadmin [idx]`(默认烧到拒绝)。
  **注意(用户建议)**: 耗尽测试把 licence 设 ~10 更快且少损耗真实 flash; 真机已耗一次、
  后续若再做真机耗尽请用低次数变体(或在模拟器上做, 无 flash 损耗)。
- **持久化边界(用户 2026-09-09 确认)**: 计数为**内存表(打开会话内)**实现是**有意设计** ——
  导出的 storage 文件是可备份的; 若把计数写回文件存储, 备份会把"已耗次数"一并恢复, 与备份
  语义冲突。这正是模拟器此前不实现 licence 递减/持久化的原因。故**不做**跨 Export()/Open() 持久化。
- 工具支持: `__Testing_dongle.cjs badmin [hid] [burn]`(建置+烧 N 次并读 counts)/`badminburn [hid]`(耗尽阈值);
  `emuadmin [idx]`(进程内模拟器耗尽验证); `BADMIN_BOOT=Bootstrap-INIT-0x10000.dongle.program` 可切回 0x10000 基线。



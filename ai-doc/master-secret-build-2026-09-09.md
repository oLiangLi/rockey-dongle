# MASTER.SECRET 构建过程(理解与复现记录, 2026-09-09)

本文对照 mkey/ 生成档案与 Interface/ 设备源码, 记录 rLANG ukey 体系里
"MASTER.SECRET 跨 4 把保管者分发 + 导入者(管理员 ukey)恢复"的完整语义,
并给出基于进程内 JS 模拟器(Web/Agent/Tests/__Testing_dongle.cjs `mkey`)的可运行复现。

## 1. 参与方与产物档案

- 保管者 K0..K3(4 把, mkey/README §5 记录各自 rLANG_Ed25519/X25519 公钥与 SIGN)
- 管理员/导入者 A0(mkey/A0-…/README: 初始终端类别=adm、RSA2048 公钥、MasterImport 结果:
  `rLANG_DONGLE_ID_0..5` + `rLANG_MASTER_SECRET_FINGERPRINT`)
- 预签名导出脚本(mkey/signed-script/K0-K1-K2-K3/SignedCode-Export-K{0..3}.dongle.program)
  即 EXCHANGE_PREV_MASTER_SECRET 程序模板(public 256; data = 四把 X25519 pub + A0 RSA pub)
- 导入程序 IMPORT_MASTER_SECRET(public 104; 3 个 256B 密文槽 → 6×16B DONGLE_ID + 8B 指纹)

## 2. 语义: A..F 是 K0..K3 完全图上的 6 条边

实现: Interface/execute.cc `OpExecute_ExchangeMasterSecret` / `OpExecute_ImportMasterSecret`。

```
        K0
      A/  \B
     K1----K2      边: A=K0-K1  B=K0-K2  C=K0-K3
    D| \E  |             D=K1-K2  E=K1-K3  F=K2-K3
     K3----(K2 已连)
    C  F
```

- 每把 Ki 持有身份私钥 = Master(-1).X25519(脚本 MasterExport.dongle 导出其公钥;
  与 mkey 档案里 K0..K3 的 rLANG__X25519_Pubkey 同源 —— EXCHANGE ctx 必须用这个公钥)。
- 边共享 = X25519(Ki私, Kj公) = X25519(Kj私, Ki公): 两端设备算出的 32B 完全相同。
- Ki 的导出: 与其它 3 把各算一条边 → 3 条边记录, 每条 =
  `MASTER_SECRET_Header{ hid_[12]; kid_[3]=0xffffff; index_=字母 }` + 32B 共享(48B/条);
  3 条共 144B 用 A0.RSA2048 公钥([e:u32LE][N:256])整体 RSA-PKCS1 加密 → 单 256B 密文
  (rLANG_ENCRYPT_PREV_MASTER_SECRET)。
- A0 导入: 用自己 RSA 私钥(global 2048)解密至多 3 个密文(槽偏移 256/512/768);
  字母位 key_mask 需到 0x3F(6 条边全齐); 重复出现的字母必须与已收值一致(一致性校验,
  因为每对 Ki/Kj 会互相导出同一条边);
  然后 `MASTER_SECRET = SHA512(6 边共享按 A..F 顺序拼接[192B])`(64B, 设备内部写回),
  `指纹 = SHA256(MASTER_SECRET)[0..7]`, 输出每字母的 header(即 ID_0..5)。
- 冗余度: 任取 3/4 把即覆盖全部 6 条边(9 条记录中 3 条重复用于校验); 仅 2 把覆盖 5 条, 无法恢复。

## 3. VM 行为要点(调试中踩过的坑)

- `ExecuteExchangeMasterSecret()/ExecuteImportMasterSecret()` 属 0x280..0x2FF Execute 类操作:
  Interface/script.cc 执行后直接 `break` 结束 VM。脚本末尾的 `Exit(42);` 是**不可达死代码**
  (产品 bundle 同款)。
- OpExecute 返回 0 ⇒ 成功、缓冲输出保留; 返回非 0 ⇒ 清空数据区并经
  `zero_ = (zero_ & 0xFFFF) | ((nstk_ & 0x1F) << 16) | ((pc_ & 0x7F) << 22) | (1 << 30)` 编码报错
  (宿主侧表现为 `dongle.Execv Error <code>`, 例如 Exit(N)→0x40800000|N)。
- 模拟器 JS 封装(jsCrypto.ts Execv)在 result≠0 时抛错且**不写回** InOutBuf ——
  所以曾把"输出=输入帧原样"误读为执行失败; 实际失败时用 trace 看原生操作日志/返回码最可靠。

## 4. 复现(mkey 命令, 纯模拟器, 不触真机)

```
node Web/Agent/Tests/__Testing_dongle.cjs mkey        # 默认 emu0..3=K0..K3, emu4=A0
# 可选: MKEY_INIT=0 跳过 Initialize 前置; RKEY_TRACE=1 打印 pubs/RSA/每帧缓冲头
```

流程(EmuMkeyMaster):
1. 每台模拟器(必要时)Initialize.dongle bootstrap → 世界就绪;
2. 每把 K 跑 MasterExport.dongle 取设备端 X25519 公钥(Master(-1).X25519);
3. 每把 K 跑 EXCHANGE_PREV_MASTER_SECRET.dongle(bootstrap), 数据 = 四把 X25519 pub + A0 RSA pub
   → 各得独立 256B 密文(随机 RSA padding, 四份互不相同即自证匹配成功);
4. A0(emu4)跑 IMPORT_MASTER_SECRET.dongle 两次, 三元组分别 (K0,K1,K2)、(K1,K2,K3):
   两次指纹一致 ⇒ 6 条边被正确重建(设备内重复字母一致性校验通过)。

样例输出(每次 Create 随机, 指纹随之不同):

```
mkey: K0..K3 EXCHANGE OK cipher=…(4 份互异)
mkey: A0 IMPORT[012] triple=K0K1K2 fp=550da026a277fe73 letters=A:ffdcd7882bc6 …
mkey: A0 IMPORT[123] triple=K1K2K3 fp=550da026a277fe73 …
mkey: MASTER.SECRET fingerprint=550da026a277fe73 determinism(012 vs 123)=true
```

字母 header 的 hid 段 = 导出该字母密文的 K(先到先写), 与真实 A0 档案
rLANG_DONGLE_ID_0..5 的 16B 结构(hid12|kid3|字母 index)一致。

## 4.1 扩展校验(mkey 内建)

- **② 与 mkey 已签名导出程序同源**: 逐字段比对
  `mkey/signed-script/K0-K1-K2-K3/SignedCode-Export-K0.dongle.program`
  与本仓库 `EXCHANGE_PREV_MASTER_SECRET.dongle` 的编译结果(size_public/code/output/data)
  → `match=true (code=true, output=true, data=true)` —— 驱动各 K* 执行的正是同一导出程序
  (真实程序带 K 世界签发的 LIMIT signedCode, 模拟器代理无对应信任, 以 bootstrap 管理员
  会话执行等价指令流)。
- **① 文件 ukey 代理**: `Export()` = 持久化 storage(可落盘 `MKEY_PERSIST_DIR`,
  `K0-proxy.dongle` ≈9964B), 用 `EmulatorSecrets[K]` 的 secret 在另一台模拟器 `Open()`
  重载 → 身份 Master(-1).X25519 不变(identity=true); 代理执行同一 EXCHANGE 导出请求,
  其密文**替代被代理的 K0** 参与 A0 恢复 → 指纹与原一致(same-as-original=true)。
  即文件 ukey 可在在线侧应答 K 的管理员导出请求。
- **3/4 冗余负例**: 只给 2 个密文(K0+K1, 仅 A..E 五条边、F 缺失) → A0 Import 被设备
  拒绝(`Execv Error`, mask≠0x3F), 验证"任意 3/4 可恢复, 2 把不可"。
- 控制项: `MKEY_INIT=0` 跳过 Initialize; `MKEY_PROXY=0` 关闭代理 / 数字=代理模拟器下标
  (默认 6); `MKEY_NEG=0` 关闭负例; `MKEY_PERSIST_DIR=…` 把代理 storage 落盘再打开;
  `MKEY_PROGRAM=…` 指定比对程序; `RKEY_TRACE=1` 打印 pubs/RSA/帧头。


## 5. 边界与后续

- 真实 K0..K3/A0 已锁定/离线: 本复现用全新模拟器世界(不同 secret ⇒ 不同 MASTER.SECRET),
  验证的是**协议语义、编排与确定性**, 不是历史 MASTER.SECRET 逐位还原;
- 需要把真实档案的"从 3 个密文重建"应用于真实世界时, 需持有对应文件模拟器 storage+secret
  或在线真机(仅 Windows 端, 且遵守不 factory lock 约定);
- 可延伸: 2 把三元组负例(应 import 失败 mask<0x3F)、把密文灌给非 A0 设备(RSA 解密失败)等反例用例。

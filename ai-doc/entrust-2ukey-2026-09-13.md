# 两把真机 ukey 的 EnTrust 托管 → 管理员脚本签发链路 (2026-09-13)

## 1. 目标与结论

**目标**: 在**不依赖模拟器**的前提下, 用两把**真机 ukey** 打通"托管(EnTrust)+ 管理员脚本签发"
的生产形态链路, 为后续"管理员专属数据文件(id < 1000) + `ExRSACrtModExp`"的权限验证提供可用手段。

**结论(已实测 PASS)**:

- 受托方 ukey 用自己的 `kKeyIdGlobalSM2ECDSA = 1` 私钥**解开**目标 ukey 托管在
  `dashboard[6K+180 + i*112)` 的 112B 条目, 取回**目标的 ECIES 私钥**;
- 受托方用该私钥对目标 ADMIN 脚本的 SM3 摘要**签名**;
- 签名帧送回目标执行 ⇒ **ADMIN 帧被接受并执行**(`inout[0,16)` 出现 ADMIN 文件魔数 `3b494304`), `exit=0`;
- **负例**: 篡改签名最后一字节 ⇒ 目标**拒绝**执行(`exit=1`, 无 ADMIN 执行结果)。

**为何用两把真机**: 受托方私钥**不可导出**, 解密只能发生在受托设备内部 ⇒ 生产形态就是"两把 ukey"。
(注意: **不是**因为"模拟器 EnTrust 不可用" —— 模拟器侧 EnTrust 实测是工作的, 见 §6。)

## 2. 硬件与状态

| 角色 | HID | 说明 |
| --- | --- | --- |
| **target** (被托管/执行管理员脚本) | `00000000-efea115bfc084642` | Admin 世界; 本轮用生产固件 |
| **trustee** (受托方, 持解密私钥) | `00000000-f56a125b71094c42` | Admin 世界; SM2ECDSA 公钥见下 |

受托方"**托管 id**" = `kKeyIdGlobalSM2ECDSA = 1` 的 SM2ECDSA 公钥 (`dashboard[7K+20, 7K+84)`,
同时也在 `WorldEnTrust+20`):

```
20a8c0fe49a444dd9963b40e4935166e7fac0c9bc7d4ae90c5d76b3a2ba7b6d7
5ae9da3b09c787e9ab3470ee84eb954bb6ef587bbc0f31bcc8eff724406f93c7
```

## 3. 前置条件

1. **受托方**已建世界(Admin 即可): `realinit <trusteeHid>` 用 `Tests/Initialize.dongle`
   bootstrap 初始化(注意: **会清空 factory 区**, 之后需重新注入数据);
2. **目标**已建世界(Admin): EnTrust 脚本需要管理员权限;
3. 两把设备都刷**含脚本执行能力**的固件(生产固件或测试固件均可);
4. 托管槽位: 共 5 个 (`kMaxKeys`), **未设置的槽必须填全 0**。

## 4. 一次性命令

```sh
# 受托方建世界(可选; 已初始化过则跳过)
node Web/Agent/Tests/__Testing_dongle.cjs realinit 00000000-f56a125b71094c42

# 托管 + 受托方签发 + 目标执行 ADMIN 帧 (正向)
node Web/Agent/Tests/__Testing_dongle.cjs real2ukey \
     00000000-f56a125b71094c42 00000000-efea115bfc084642 \
     Web/Agent/Tests/Tests/HelloWorld.dongle

# 负例: 篡改签名, 期望目标拒绝 (exit=1)
RKEY_TAMPER=1 node Web/Agent/Tests/__Testing_dongle.cjs real2ukey \
     00000000-f56a125b71094c42 00000000-efea115bfc084642 \
     Web/Agent/Tests/Tests/HelloWorld.dongle
```

`real2ukey` 内部六步(全部在工具内完成, 均有日志输出):

1. 读受托方 `dashboard[7K+20, 7K+84)` 取**受托方 SM2ECDSA 公钥** = 托管 id; 取受托方 hid12;
2. 在**目标**上跑 `Tests/EnTrust.dongle`(bootstrap, admin), 槽 0 填 `hid12 | kid3 = SM3(pub)[0..3] | pub64`,
   其余 4 槽全 0; nonce 每次随机;
3. 从目标 `dashboard[6K+180 + i*112)` 按 hid12 找回**实际落盘的 112B 条目**(打印 `escrow slot`);
4. 计算目标 ADMIN 脚本摘要 = `SM3(BuildDataSegment(program)[0, 1024-256-64))`;
5. 在**受托方**上跑 `Tests/_EnTrustTrusteeSign.dongle`(参数 `rLANG_ENTRY` / `rLANG_DIGEST`)⇒ 打印 `sign64`;
6. 用签名组 ADMIN 帧并在**目标**上执行 ⇒ 打印 `ADMIN frame OK. inout[0,16)`。

## 5. 实测记录

**正向(受管工具 `real2ukey`, 2026-09-13)**:

```
trustee hid : 00000000f56a125b71094c42
trustee pub : 20a8c0fe49a444dd ...
EnTrust on target ...
escrow slot : 0
entry112    : 00000000f56a125b71094c42d59a77016b607f6025a36ca0...39eb
digest      : 420d71cca22fea13fd0109f82d90c517509540f367f9f33dd728520a579f06cc
sign64      : 4e4b89ecd35af434329065b4fb27bf0f...48c1a32
ADMIN frame OK. inout[0,16): 000000001f4ec0c8010100043b494304
exit=0
```

- `entry112` = `hid12[12] | kid[3] | Yodd | C1x[32] | H[32] | XOR[32]`(112B), 落在**槽 0**;
- `digest` 对同一脚本**确定**(`HelloWorld.dongle` ⇒ 每次都一样);
- `entry112`/`sign64` **每次运行都不同**(ECIES 每次随机 nonce, 受托方 SM2 签名随机 k)⇒ 不可当作固定向量,
  但**协议链路可重复**: 连续两次独立运行都得到 `exit=0` + `3b494304`;
- `000000001f4ec0c8` = 目标的 world magic/category 回显, `3b494304` = **ADMIN 帧文件魔数** ⇒ 帧通过验签**并已执行**。

**负例(同一命令 + `RKEY_TAMPER=1`)**: 打印 `sign64 TAMPERED` 后 **无** `ADMIN frame OK` 行, `exit=1`
⇒ 目标**拒绝了篡改签名的帧**(验签在设备内完成) ✓。

## 6. 与"真机 + 模拟器"混合路线的关系(**已修好: 根因是工具侧陈旧状态, 不是实现不兼容**)

**结论(2026-09-13 收尾)**: `realadmin`/`reallimit` 现在**都能通过**:

```
ADMIN real 00000000-efea115bfc084642 trustee=emu[0]: sign-verify=true   (exit=0)
LIMIT real 00000000-efea115bfc084642 trustee=emu[0]: sign-verify=true
```

**真正的根因(两处主机侧陈旧状态, 与密码学实现无关)**:

1. **跳过重新 EnTrust**: `RealRunSigned` 原先只按 `hid12` 判断"该受托者已有托管条目"就**跳过**
   `RealEnTrustToEmu`。世界重建(`realinit`)后 ECIES 私钥已变, 旧条目解不出正确私钥(甚至 C1 不在曲线上
   直接解密失败)⇒ 表现为 `real: trustee decrypt failed`;
2. **`Dashboard()` 缓存未失效**: 即使改成"总是重新 EnTrust", `Dashboard(hid)` 仍返回**EnTrust 之前**
   缓存的 dashboard ⇒ 读到的还是旧条目, 依然失败。
   ⇒ 修复: ①总是重新 EnTrust(幂等、代价小); ②EnTrust 后 `dashboardCache.delete(hid)` 再读。

**过程中被推翻的两个判断(留档以免重复踩)**:

- ❌ "真机 COS 与软件实现的 SM2 ECIES 不互通" —— 错。新增交叉探针 `xentrust <devHid> [emuIdx]`
  (模拟器按真机 SM2ECDSA 公钥造条目 → 真机 `_EnTrustTrusteeSign.dongle` 解密签名 →
  **用软件侧 ECIES 公钥验签**)实测 **PASS**: `以软件侧 ECIES 公钥验签 : true` ⇒ 真机**确实解出了正确的
  ECIES 私钥**, 两侧 ECIES 完全互通;
- ❌ "封装/blob 版本不同步(`jsCrypto.js` 新于 `jsWorld.js`)" —— 也错。一致重建
  (`make wasm -j8 && make jsWrapper R=1`, `jsCrypto.js` 3.28 MiB, `opcode.ts` 仍 157/98, 事后 `git status` 干净)
  后 `realadmin` 仍失败; 直到修掉上面两处状态 bug 才通过。
  (`jsWorld.js`/`jsLibrary.js` 是 `tsc` 产物, TS 未变故 mtime 不变 —— 不是"陈旧 blob"。)

**按用户建议加的兼容(防御性, 但注意其局限)**: 软件侧 `Interface/emulator.cc` 的 `Dongle::SM2Decrypt`
现在**两种 text 布局都试**(`C1x||C1y||C2||C3` 失败时改试 `C1x||C1y||C3||C2`, 都不行才报错)。
局限(实测): TASSL 的 `sm2_decrypt` **不校验 C3**, 布局错时它会**返回垃圾明文而不是报错**
(工具 `realmix` 探针里两种顺序都"解出 32B"但验签失败即为此)⇒ 这种重试**无法**用来判别布局,
只能兜住"硬失败"; 本轮真正的问题是状态而非布局, 因此该兼容并非必需(保留作防御)。

**排查工具(已固化)**:

- `xentrust <devHid> [emuIdx]` —— 模拟器加密 → 真机解密(带验签强判据);
- `realmix <devHid> [emuIdx]` —— 真机条目 × {C2/C3 顺序} × {X 字节序} × {Y 奇偶} 的布局矩阵
  (靠"解出的私钥签名 → 软件侧 ECIES 公钥验签"判定命中);
- `RKEY_FLIP_YODD=1` / `RKEY_REV_X=1` —— `RealRunSigned` 的诊断开关(默认关);
- ⚠️ `realadmin`/`reallimit` 会**覆盖目标设备全部 5 个托管槽**(填本模拟器)⇒ 测完请用
  `real2ukey <真受托方> <目标> <file.dongle>` 恢复真受托方托管。

**关于"两种布局"的处置决定(用户 2026-09-13)**: EnTrust 解密布局这件事**不重要** ——
真到了需要它兜底的时候, **把 `C2||C3` 反转一下重试**已经是所有路径里成本最低的做法,
因此**不再深挖** COS 原生格式的细节(上面的 `realmix` 矩阵、`RKEY_*` 开关保留为诊断手段即可)。

## 7. 相关文件

- `Web/Agent/Tests/Tests/_EnTrustTrusteeSign.dongle` —— **受托方侧签名脚本**(下划线前缀 = 不被 suite 自动执行):
  bootstrap 帧; 入参 `rLANG_ENTRY @256 [112]`、`rLANG_DIGEST @384 [32]`; 输出 `@0 [64] : rLANG_SIGNATURE`;
  主体: `ExSM2DecompressPoint(LoadU8(271),272,512)` → 组 128B 密文 `C1x||Y||H||XOR` 到 [640,768) →
  `SM2Decrypt(1,640,128)`(解密后私钥就地留在 [640,672)) → `ExSM2Sign(640,384,0)` → `Exit(0)`;
- `Web/Agent/Tests/Tests/EnTrust.dongle` —— 目标侧托管脚本(5 槽, 未用槽全 0);
- `Web/Agent/Tests/__Testing_dongle.cjs` —— `realinit <hid> [catHex]`、`real2ukey <trustee> <target> <file>`;
- `Interface/script.h` 的 `WorldEnTrust` —— 布局权威定义
  (`+20` 受托方公钥 64B / `+148` nonce 32B / `+180` 起 5×112B / `+960` 签名 64B)。

## 8. 后续可做的事(本链路解锁)

- ~~**管理员专属数据文件**(id < 1000)放 CRT 私钥 blob ⇒ 验证"文件 ACL 权限门槛"这条生产路径~~
  **已实测(2026-09-13)并否定了它的保密含义**: id<1000 **只限制建/写/删, 不限制读**(设计前提:
  任何已存在的文件必然可被读出、不信任 COS 承诺)⇒ 它只能做**授权**, 不能保护私钥机密性;
  细节见 `ai-doc/admin-file-permission-2026-09-13.md`(管理员签名脚本建/写/用该文件签名的正例已 PASS,
  脚本用 `real2ukey` 签发);
- 生产侧的正确形态:**机密性一律来自 `KDF(MASTER.SECRET, nonce, kType) + AEAD`** —— 把私钥 blob 密封后落盘
  (如 `dashboard[5K,6K)`), 走 NORMAL 帧, **不需要管理员签名**;MASTER.SECRET 操作强制管理员, 且
  `kType == 0` 时结果**只在本机有效**(混入本机 `LocalChaos`/`DongleInfo`)、`kType != 0` 时
  **共享 MASTER.SECRET 的 ukey 都能复现**(只用世界级常量)⇒ 选哪种决定了密文能否跨机使用;
- ⚠️ 生产 master ukey (**K0/K1/K2/K3**, `Bootstrap-EnTrust-LiangLI`) **不应为测试用途签发脚本** ——
  测试一律用本文件的两把测试 ukey 走 `real2ukey`。

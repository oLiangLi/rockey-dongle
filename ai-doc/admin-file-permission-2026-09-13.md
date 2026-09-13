# 管理员专属数据文件(id < 1000)+ `ExRSACrtModExp` 权限门槛验证 (2026-09-13)

## 1. 目标

验证"**CA 私钥放进管理员专属数据文件(id < `kUserFileID` = 1000),由管理员签名的脚本用
`ExRSACrtModExp` 直接做 CRT 签名**"这条生产形态,重点回答两件事:

1. **正例**:管理员会话能否建/写这种文件,并**用它完成与 TASSL 一致**的 RSA-3072 CRT 签名;
2. **负例**:非管理员会话在**读/建/写/用它签名**时是否**被拒绝**。

## 2. 前置:世界类型(必须先搞清, 否则测的是另一个门槛)

`Interface/execute.cc:240-251`:

```cpp
if (vm.valid_permission_ != PERMISSION::kAdministrator) {
  ReadDataFile(0xFFFF, WorldPublic::kOffsetDataFile, &public_header_, sizeof(public_header_));
  if (public_header_.category_magic_ == WorldPublic::kCategoryHeaderMagicAdmin) {
    rlLOGXE(TAG, ..., "EACCES: Adminstrator requirement!");
    return -EACCES;      /* Admin 世界(adm@k) 拒绝一切非管理员帧 */
  }
}
```

- **Admin 世界**(`category_magic_ = 0x864B40AF` = `"adm@k"`)⇒ **任何** NORMAL/ATOMC 帧都被 `-EACCES`
  顶掉(连读 dashboard 都不行)⇒ 在这种设备上做"文件权限"负例是**无效实验**;
- **Normal/Public 世界**(`0xC35880AF` = `"pub@k"`)⇒ NORMAL 帧可以运行,文件级门槛才真正被测到。

本轮 dev0 原为 Admin 世界(所以早期三个负例全部被世界门槛挡掉),为测试临时重建为 Public 世界:

```sh
node Web/Agent/Tests/__Testing_dongle.cjs realinfo  <hid>          # 打印 live dongle_info / 世界 magic+category
node Web/Agent/Tests/__Testing_dongle.cjs dashdump  <hid> <out>    # 备份 dashboard 8192B
node Web/Agent/Tests/__Testing_dongle.cjs realinit  <hid> c35880af # 建 Public 世界(会清空 dashboard)
node Web/Agent/Tests/__Testing_dongle.cjs realnotice <hid> <out>   # 管理员会话回贴 dashboard[0,4096)(CLI --notice)
```

实测:重建后 `world magic 1f4ec0c8 category af8058c3`(= `0xC35880AF` LE),回贴后 NORMAL 帧立即可用,
`_ProbeDash.dongle` 读出 `5253414b000c0000...`(= `RSAK` blob 魔数 + 3072 位)✓。

## 3. 正例(管理员签名脚本,全部 PASS)

```sh
node Web/Agent/Tests/__Testing_dongle.cjs real2ukey <trusteeHid> <targetHid> \
     Web/Agent/Tests/Tests/_RsaCrt3072AdminFileCreate.dongle
```

`_RsaCrt3072AdminFileCreate.dongle`(作为 ADMIN 帧执行):

1. `CreateDataFile(100, 2128, 2, 2)` —— id=100(<1000), 2128B = 3072 位完整私钥 blob 长度,
   读/写权限 = 2(`kAdministrator`);
2. 分 3 块把 dashboard[1024,3152) 的 blob 拷进文件(VM 数据区只有 1024B):
   `ReadDataFile(0xFFFF,1024,0,1024)`+`WriteDataFile(100,0,0,1024)`、
   `…2048→1024…`、`…3072,80 → 2048,80`(2128 = 1024+1024+80 ✓);
3. `ReadDataFile(0xFFFF,3200,0,384)` 取 m,`ExRSACrtModExp(100,0,0,384,3072)` —— **密钥来自该管理员文件**。

**结果**:

| 项目 | 值 |
| --- | --- |
| ADMIN 帧 | `exit=0`, `inout[0,16) 4ef1447cdb7b39fe...` |
| 文件路径签名 | `39b7f723c65437f9...12e1f` |
| dashboard 路径对照(`_RsaCrt3072ScriptPath.dongle`, NORMAL 帧, 模数走 0xFFFF) | `39b7f723c65437f9...12e1f` |
| 结论 | **逐字节相同** ⇒ 文件里的 blob 与 dashboard 里的 blob 等价, 且与 TASSL 参考一致 ✓ |

随后 `real2ukey … _RsaCrt3072AdminFileUse.dongle`(只读文件、不重建)也 `exit=0` 并复现同一签名
⇒ 文件**跨运行持久**、管理员路径可用 ✓。

## 4. 负例(Public 世界 + NORMAL 帧)

| 脚本 | 操作 | 期望 | 实测 |
| --- | --- | --- | --- |
| `_ProbeDash.dongle` | 读 0xFFFF(对照) | 允许 | exit 0 ✓ |
| `_ProbePermUser.dongle` | `CreateDataFile(1002,64,2,2)`(id≥1000 对照) | 允许 | exit 0 ✓ |
| `_ProbeSlotFree.dongle` | `DeleteDataFile(1002)`+重建 1002 | 允许(证明槽位/空间充足) | exit 0 ✓ |
| `_ProbePermAdmin.dongle` | `CreateDataFile(202,64,2,2)`(id<1000) | 拒绝 | **exit 1** ✓ |
| `_ProbeFwWrite.dongle` | `WriteDataFile(0xFFFF,…)` | 拒绝 | **exit 1** ✓ |
| `_ProbeCrtFile.dongle` | `ExRSACrtModExp(100,0,0,384,3072)` | 拒绝 | **exit 1** ✓ |
| `_RsaCrt3072AdminFileUse.dongle` | 读 m + `ExRSACrtModExp(100,…)` | 拒绝 | **exit 1** ✓ |
| `_RsaCrt3072AdminFileRead.dongle` | `ReadDataFile(100,0,0,1024)` 裸读 | 拒绝 | **exit 0, 读出 `5253414b000c0000…`** ✗ |

`_ProbeSlotFree` 先释放并成功重建一个用户文件,排除了"空间/槽位耗尽"这一替代解释 ⇒
上表中 id<1000 的建/写拒绝**只能**来自权限门槛 ✓。

## 5. 两个必须记录的结论

### 5.1 【已修】静默拒绝:错误分支必须置 `zero_`,只返回负 `value` 等于没报错

VM 主循环是 `while (zero_ == 0)`,**只有 `zero_ != 0` 才中止脚本**(`Interface/script.cc`)。
我最初给 `kExRSAModExp`/`kExRSACrtModExp`/`kExRSAKeyCheck` 写错误分支时用了 `value = -EACCES`
(照抄了 `OpFuncDataFile` 里尺寸检查的 `value = -EINVAL` 写法)⇒ 真机上:

- 权限检查**确实命中**(运算整段被跳过),
- 但**脚本继续执行**,`Main()` 返回 0 ⇒ **host 看到 `exit=0`**,
- 输出区保持原样(结果全 0)。

于是"被拒绝"和"算出来是全 0"**无法区分** —— 若调用方只看退出码,会把全 0 结果当成合法签名。
修复:三处 opcode 的所有错误分支统一为 `value = zero_ = -EXXX;`,算法本身的失败也补 `zero_ = value;`。
`__Testing__rsamodexpvm__` 增补严格断言(**必须 `zero_ != 0`**)并新增
"admin-only 文件 × {kAnonymous,kNormal} × {ModExp,CrtModExp,KeyCheck}" 共 6 个用例 ⇒
仿真侧 `exit=10086`(0 error)、真机侧上述负例全部转为 `exit=1` ✓(回归测试已覆盖,不会再静默)。

### 5.2 【设计意图 · 非缺陷】数据文件的**读取没有权限门槛**

`kReadDataFile` 在 VM 层**只检查 `kKeyIdGlobalSECRET`**,不检查 `id < kUserFileID`
(`Interface/script.cc:174-198`);COS 侧实测也不按 `DATA_FILE_ATTR.m_Lic.m_Read_Priv` 拒读 ——
非管理员会话成功读出了 id=100 文件的前 1024B(内容为 `RSAK…` blob)。

**这是设计意图, 不是缺陷**(用户 2026-09-13 说明):

- ukey 内的**世界实际上是以管理员权限执行的**;初始设计的前提是
  **"任何文件只要存在, 就必然能被读出"** —— **不信任 COS 的任何承诺**;
  因此"限制普通用户读 id<1000 的文件"**没有意义**, 代码里也就没有这一层;
- ⇒ `id < kUserFileID` 门槛的语义是**授权/防篡改**(谁能**建/写/删**), **不是机密性**;
- **要保护 dataFile 的内容, 正确做法是 `KDF(MASTER.SECRET, nonce, kType)` 加密它**
  (完整原型含 **`kType`** —— 2026-09-13 用户约定 + `Interface/master.cc:287-302` 实现):
  - **操作 MASTER.SECRET 必然已经取得管理员权限** —— 代码上即为 `VM_t::OpManager` 首行
    `if (valid_permission_ != PERMISSION::kAdministrator) return zero_ = -EACCES;`
    (覆盖 `kWorldInitialize` / `kUpdateMasterSecret` / `kComputeSecretBytes` /
    `kUpdateSM2ECIESKey` / `kComputeEnTrustData`, `Interface/master.cc:371-373`);
  - **`kType == 0`**: 派生时混入 **`LocalChaos` 与本机 `GetDongleInfo`** ⇒ 结果**只在当前 ukey 有效**,
    即使共享 MASTER.SECRET 的其他 ukey **也得不到相同结果**(本机自持型用途);
  - **`kType != 0`**: 只用世界级常量(`rLANG_WORLD_MAGIC`/`ATOMC`/`COSMO`, 且 `type_` 参与哈希)
    ⇒ **共享 MASTER.SECRET 的所有 ukey 都能复现相同结果**(跨机复现型用途, 如 ROOT CA 种子);
    现有脚本两种都在用: `ComputeSecretBytes(addr, 42)`(复现型)、`(addr, 0)`/`(addr)`(本机型);
  - **MASTER.SECRET 一机一密**: 把它的加密 blob 读走**对其他 ukey 没有任何意义**
    ⇒ 密文即使放在**可读**的位置(如 dashboard 匿名区)也不损失机密性
    (⚠️ 注意: 这条只对 `kType == 0` 的本机型密文成立; `kType != 0` 的密文**对同族 ukey 可用**,
    因此其机密性依赖"MASTER.SECRET 不外泄"而非"密文不可读")。
- (私钥文件 `CreateRSAFile` 的 licence/`m_Priv` 是另一套 COS 实现的机制; 按上面的设计原则,
  不应把安全性建立在 COS 的承诺上, 故不作为推荐的保密手段。)

即:**文件权限路径用于授权**, **机密性一律交给 `KDF(MASTER.SECRET, nonce, kType)` 派生的密钥加密**
(`kType` 选择本机自持或跨机复现, 见上)。
本轮的 CA 方案(`KDF(MASTER.SECRET)+AEAD` 把私钥 blob 密封在 dashboard 5K-6K)正是这个形态 ✓ ——
按 §3.2 要求"任何持有 MASTER.SECRET 的设备都能复现", 它必须用 **`kType != 0`**。

## 6. 产出的命令/脚本

- `Web/Agent/Tests/__Testing_dongle.cjs` 新增:
  `realinit <hid> [catHex]`(真机 bootstrap 建世界)、`realinfo [hid]`(live vs dashboard 里保存的 dongle_info)、
  `dashdump <hid> <out>`、`realnotice <hid> <in4k>`、`listfile <type> [hid]`、
  `real2ukey <trusteeHid> <targetHid> <file.dongle>`(两把真机 ukey 的托管+管理员签名闭环, 见
  `ai-doc/entrust-2ukey-2026-09-13.md`);
- 测试脚本:`_RsaCrt3072AdminFileCreate/Use/Read.dongle`、`_ProbeDash/_ProbePerm{User,Admin}/_ProbeSlotFree/_ProbeFwWrite/_ProbeCrtFile.dongle`
  (`_` 前缀 = 不被 suite 自动执行);
- 代码:`Interface/script.cc`(三个 opcode 的错误分支置 `zero_`)、
  `src/__Testing__/__rsamodexpvm__/rsamodexpvm.cc`(权限/中止断言)。

## 7. 后续

- **保密一律用 `KDF(MASTER.SECRET, nonce, kType)`**(见 §5.2), 不要依赖文件 ACL/COS 承诺;
  因此"CA 私钥 blob 放哪"不是问题 —— 密文放可读位置也安全(`kType == 0` 一机一密;
  `kType != 0` 则对同族 ukey 可用, 机密性依赖 MASTER.SECRET 不外泄);
- `ExRSAKeyCheck` 的**真机**拒绝路径本轮未单独跑(仿真侧已覆盖 6 个权限用例);
- 需要"真机非管理员会话"时, 用 Public 世界(`realinit <hid> c35880af`);Admin 世界设备天然拒绝一切非管理员帧;
- 【工具约定】`write`/`edit` 工具改写含中文的文件会**丢掉 UTF-8 BOM**(本轮 3 个 `ai-doc/*.md` 出现过),
  改完需按仓库约定把 BOM 补回。

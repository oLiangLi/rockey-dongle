# RSA ROOT CA 密钥生成(单指令 · 设备内 · 可复现)—— 汇总 2026-09-11

> 本文汇总"在 ukey 内以**单条指令**完成 RSA ROOT CA 私钥生成"的全部结论、实测数据、
> 协议设计与待办。相关分支:`feat/liangli/rsa-rm-test-2`(commits `942ef8a`、`7f89092`)。
> 既有背景见 `ai-doc/master-secret-build-2026-09-09.md`(MASTER.SECRET 构建/复现)、
> `ai-doc/session-key-flow-2026-09-09.md`。

---

## 1. 目标与结论

- **目标**:ROOT CA RSA 私钥在 ukey 内生成并可被"任何持有 MASTER.SECRET 的设备"确定性复现;
  过程中 host **不得**获知候选、进度或私钥材料。
- **结论(已定)**:采用**单指令**方式——一次 `ExecuteExeFile`(未来为一条 `OpExecute_*`)
  在设备内跑完整条 p/q 搜索;不做"host 逐个下发候选"的分块交互(那会让 host 掌握候选序列,
  等价于 host 也能推出 p/q,安全属性不成立)。
- **可行性已实测**:设备单次执行**连续 30.4 分钟并正常返回**(朴素版 16 基素数那次);
  Montgomery + 试除后整轮生成估算 **≈16–17 分钟**,远小于已验证的窗口。

## 2. 实测数据(测试 ukey, 2026-09-11)

| 项目 | 实测 | 对照 |
|---|---|---|
| 小素数试除命中(合数) | 设备 **131 ms** 返回 | — |
| 单基 Montgomery 幂模(1024 位) | 设备 **10.5 s** | 朴素逐位取模 **109.5 s**(≈10×) |
| 16 基素数判定 | 设备 **158.2 s** | 朴素 **1824.6 s**(≈11.5×) |
| 单次执行上限 | **≥ 30.4 min** 正常返回(另有 `-delay` 502.6 s 成功) | 曾误判为"8 分钟窗口",已否定 |
| 栈占用(arm `.su`) | `IsPrimeMRW` **1376B**、`MontMul` 272、`ToMont` 72、`FromMont` 64、`KickWDG` 24 ⇒ 最坏链 **≈1.84KB** | 当前固件 2032B 栈内可容纳;`OpExecute_*` 3KB 预算下余量充足 |
| 正确性 | OpenSSL / host MR / 设备 `mainRet` 三方一致:随机合数=10086、注入素数=10085、注入半素数(无小因子合数)=10086 | — |

试除到 1000 时候选存活率 ≈8%(≈28 个/素数需 1 基 MR),加上命中素数的 16 基,按上表估算:

```
单素数 ≈ 355 候选: 327×0.18s(试除路径) + 28×10.5s(1 基) + 15×10.5s(命中补齐 16 基)
       ≈ 8 min       ⇒  p+q ≈ 16–17 min; 尾部(2–3× 探测数) ≈ 35–50 min
```

## 3. 单指令生成协议(定案)

### 3.1 初始化(一次性,在持有 MASTER.SECRET 的 ukey 内)

1. 设备 **TRNG 生成 2×128B 种子字节**(`seed_p`、`seed_q`)与 **64B nonce**;
2. 由 `MASTER.SECRET`(64B,`SHA512(六边共享 A..F 拼接 192B)`)与 nonce 派生对称密钥:
   `K = KDF(MASTER.SECRET, nonce, label="RSA-ROOT-CA-SEED")`(建议 SM3/ SHA 系列 HKDF-Expand,
   输出 32B,用于 AEAD);
3. 用 AEAD(建议 **ChaCha20-Poly1305** 或 SM4-GCM)加密 256B 种子(plaintext =
   `seed_p || seed_q`,AAD 绑定版本/用途标签/设备类别),得到 `ciphertext||tag`;
4. 把 `{ 头部(版本/长度/标志), nonce(64B), ciphertext||tag }` **张贴到 dashboard[5K, 6K)**
   (factory dataFile `0xFFFF` 偏移 **5120..6144,共 1KB**,**具体字节布局待定**,见 §3.4);
   dashboard 其余区域保持现有约定(`[0,4096)` 为既有 notice/证书通道);
5. 设备内立即执行一次单指令生成(§3.2),结果只回公开部分(§3.3)。

### 3.2 复现(任何持有 MASTER.SECRET 的设备)

1. 读 dashboard[5120] 的 `{nonce, ciphertext||tag}`;
2. 用同一 KDF(MASTER.SECRET + nonce + label)派生 `K`,AEAD 解密校验 tag → 得 `seed_p/seed_q`;
3. 执行**同一套确定性算法**(与生成时逐位一致):
   - 由 128B 种子构造 1024 位奇候选(小端、置第 1023 位、保证奇数),并保证
     **最高 32-bit 字 ≠ 0xFFFFFFFF** —— 这样 `+2` 要跑到 `2^1024` 需 >2^990 次,
     任何设备运行时长都不可能溢出, 因此**不需要回绕保护**;
   - `+2` 递增搜索:先小素数试除(3..1000 奇数流式求余),幸存者做 Miller–Rabin(16 基);
   - 全程在 Montgomery 域(MontMul/ToMont/FromMont;CIOS 仅 136B 栈);
   - 每 32 次平方一次 `KickWDG`(LED 反转 + `GetTickCount` COS 心跳, 保证设备被服务);
4. 得到 p、q 后计算 `N = p*q`、`e = 65537`、`d = e^{-1} mod lcm(p-1, q-1)`(可选 CRT 参数);
5. 私钥材料留在设备内(或按密封密钥文件导出),**host 只得到公开部分或密文**。

### 3.3 返回载荷(建议)

| 模式 | 返回 | 用途 |
|---|---|---|
| 生产(默认) | `N(256B) || e(4B)`(或密封密钥文件) | 私钥不出设备 |
| 测试(一次性开关) | `p || q || N || e || d`(明文) | OpenSSL 交叉验证:判素、N=p*q、e·d≡1 |

### 3.4 dashboard 占用(已定案区域,布局待定)

- **区域**:`dashboard[5120, 6144)`(即 5K–6K,**共 1KB**),factory dataFile `0xFFFF`;
- **布局**:**待定**。按当前协议内容估算:`header(版本/长度/flags) ≈8B + nonce 64B +
  ciphertext 256B + tag 16B ≈ 344B`,1KB 余量充足,可容纳后续扩展(如绑定信息、保留字段);
- 写入需**一次性原子完成**(单次 `WriteDataFile`),避免半写状态被 host 读到;
- 区域边界不与 `[0,4096)`(notice/证书)冲突,也不越出 dashboard 总长 8192B。

## 4. 安全分析

- **机密性**:dashboard 上的内容是 AEAD 密文,host 可读但不可解;密钥派生依赖 MASTER.SECRET;
  单指令生成使 host 完全看不到候选/进度/MR 轮次,**不构成"host 可推导 p/q"**。
- **完整性 / 防替换**:AEAD tag + AAD 绑定(版本、用途 label、设备类别/会话标识),防止 host
  篡改 nonce/密文或把别的会话 blob 搬来使用。
- **回滚**:dashboard 由 host 可写,理论上可回滚到旧 blob——但内容是"生成参数"而非"进度",
  回滚只会复现同一把确定性密钥(或无意义重算),不造成密钥泄露;若引入可写进度态(分块方案),
  则必须放在**设备内部 dataFile** 并带单调计数器,避免 host 回滚进度。
- **时序**:单指令只暴露**一次总时长**(≈16–17 min)与粗粒度结构;若需进一步掩盖,可在单指令内
  做固定工作量/凑时;分块方案则需"固定工作量分块 + 凑时"。
- **侧信道**:功耗/EM/缓存等物理侧信道不在本层解决,需硬件评估;本设计只消除**协议层**信息泄露。
- **随机性**:种子与 nonce 必须来自设备 TRNG;nonce 需唯一(64B 足够),严禁与同一 K 重复使用
  于不同明文。
- **可用性**:MASTER.SECRET 丢失 ⇒ 无法复现(设计使然);反之任何持有者均可复现 ⇒ 托管语义
  与 mkey/K0..K3 机制一致(`ai-doc/master-secret-build-2026-09-09.md`)。

## 5. 实现要点与待办(单指令形态)

1. **设备侧状态机**(`Interface/mr.{h,cc}` 已具备主要构件):`SeedToOdd` + `+2` 循环 +
   `TrialDivide` + Montgomery `IsPrimeMRW` + `KickWDG`;需补 **probes 上限**(超限返回错误,
   绝不无限搜索)与结果编码;
2. **d 计算**:设备内扩展欧几里得(次数很少;用现成朴素 `mulTo/remTo` 即可,或在 Montgomery
   域做乘加),同时产出现代 OpenSSL 可验证的 p/q/N/e/d;
3. **AEAD/KDF**:选型与 label 约定;是否需要 AAD 绑定设备 UID/产品类别;
4. **dashboard[5120, 6144) 布局(待定, 1KB)**:头部/版本/flags/nonce/cipher+tag 的字节表,
   与写入原子性(`WriteDataFile` 一次写完);
5. **测试入口**:沿用 `__Testing__dongle__ -2 13 [mode] [rounds]` 扩展:
   mode 3 = "从 dashboard[5K] 读 blob 并复现生成",mode 4 = "初始化(TRNG 种子 + nonce + 张贴)
   并立即生成";测试期允许明文回传 p/q 交叉验证;
6. **交叉验证脚本**:OpenSSL 判定 p/q 素数、`N=p*q`、`e·d ≡ 1 mod lcm(p-1,q-1)`、`|p-q|` 合理性;
7. **稳态化**:确认单指令在最长尾部情况下仍能返回(probes 上限兜底),以及连续多次生成的稳定性。

## 6. 相关代码 / 文档

- `Interface/mr.{h,cc}`:`MillerRabinContext`(`TrialDivide` / `MontMul` / `ToMont` / `FromMont` /
  `N0Inv` / `IsPrimeMRW(rounds)` / `KickWDG`),`rLANG_ABIREQUIRE(sizeof ≤1024)`。
- `src/__Testing__/__dongle__/main.cc`:`Testing_PrimeMRTests`,入口
  `-2 13 [mode 0=随机/1=素数/2=半素数] [rounds 1..16]`(测试用)。
- `ai-doc/master-secret-build-2026-09-09.md`:MASTER.SECRET 构建/复现(六边共享、指纹)。
- `ai-context.md`:相关提交记录(`942ef8a` 正确性+试除、`7f89092` Montgomery+栈)。

## 7. 开放问题(需产品/固件确认)

1. 生产返回形态:仅 `N||e`、密封密钥文件,还是由设备直接用该私钥完成 CA 签发?
2. KDF/AEAD 具体选型与 AAD 绑定范围;dashboard[5120, 6144) 的**字节布局待定**(区域已定:1KB),
   以及是否与 notice 区扩展冲突。
3. 是否需要"生成 + 立即用该私钥签发根证书"合并为同一指令(减少私钥暴露面)。
4. 若保留分块/续跑能力(某些产品形态),是否只允许"设备内部 dataFile + 单调计数器"的封印态。

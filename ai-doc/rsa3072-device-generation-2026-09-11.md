# RSA-3072 设备内单指令生成 —— 2026-09-11 实测记录

> 分支 `feat/AGINX/rsa-3072-gen`; 测试 ukey(枚举索引 0)。目标: 验证"在 ukey 单条指令内完成
> RSA-3072 密钥生成"可行, 并给出真实耗时与可复现性证据。

## 1. 结果(一次 ExecuteExeFile 完成)

| 项 | 值 |
| --- | --- |
| 设备端耗时 | **3,125,713 ms ≈ 52.1 分钟**(host 墙钟, 设备内 `GetTickCount` 不自走) |
| 设备返回 | `ExecuteExeFile=0, mainRet=10086`(无栈溢出惩罚: GuardBytes 完好) |
| 模式 | `mode 3`(设备内生成), `bits=1536`, `rounds=16`, 探测上限 1,000,000 |
| 探测次数 | p: **268** 次, q: **95** 次(合计 363; 期望均值 ≈532/素数, 本次偏幸运) |
| 生成状态 | `GenResult magic=MGen ok=3`(p/q 均命中并已落盘) |
| 独立复核(host OpenSSL) | `prime_p=1 prime_q=1 gcd(e,p-1)=1 distinct=1 bits(n)=3072 d_ok=1 ⇒ ok=1` |
| 密钥自检 | `crypto.sign/verify` **PASS**;`bits(n)=3072, e=65537, d_bits=3063` |
| 公钥指纹 | `SHA256(N)=487307aa5f2251860e379d24723d9635a734140689247fac17224c6f3f256fe5` |

落盘位置(factory dataFile `0xFFFF`, 4K–5K 测试区 + 匿名用户区):
`[4096,4160)` GenResult / `[4160,4544)` p / `[4544,4928)` q / `[2048,2240)` seed_p / `[2304,2496)` seed_q。
PEM 私钥: `.bin/rsa3072-testkey-2026-09-11.pem`(`.bin` 不参与提交);

## 2. 可复现性验证(CA 方案的核心承诺)

用 `Build/tools/sbin/rsa-prime-repro.cjs`(与设备算法逐位对齐的独立实现)从设备上读回的种子重跑:

| 素数 | 设备探测数 | 独立复现探测数 | 结果比对 | host 耗时 |
| --- | --- | --- | --- | --- |
| p | 268 | **268** | **逐字节相同**(matchDashboard=YES) | 1.65 s |
| q | 95 | **95** | **逐字节相同**(matchDashboard=YES) | 0.92 s |

⇒ **同一种子 ⇒ 同一对素数(且搜索路径/探测次数完全一致)**, 即"任何持有 MASTER.SECRET 的设备
都能复现同一私钥"这一设计前提成立(设备 52 分钟 vs host 1.65 s, 只是算力差异)。

## 3. 耗时模型(与实测吻合, 可据此外推)

- 1024 位验证跑: 173 次探测 → 设备 381.7 s(= 试除 173×0.131s + 基-2 筛查 ~28×10.5s + 余下 3 基)✓
- 1536 位: 单基 Montgomery ≈ 10.5 s × (48/32)² ≈ **23.6 s**; 试除 ≈0.2 s/次
- 本次 363 次探测的分解(估算): 试除 363×0.2s ≈ 73 s;其余 361 个合数里 ≈16% 存活进入基-2 筛查
  ⇒ ≈59×23.6s ≈ 1,392 s(其中约 1/4 会通过基-2 继续跑更多基);两个素数各需 16 基 ⇒ 2×378 s ≈ 756 s;
  合计 ≈2.2 ks, **实测 3.13 ks**(偏差 ~40%, 主要来自"通过基-2 的合数"继续多基 + 逐次落盘/心跳开销)。
- **期望值**: 探测数 ≈ ln(2^1536)/2 ≈ 532/素数 ⇒ 单素数 ≈42 min, **p+q ≈84 min**(长尾 2–3 h)。
  本次 52 分钟属偏快样本。按用户"一周到一月"的预算, 余量极大。

## 4. 复现命令

```sh
# 设备侧重新生成(bits 选择 argv[2]: 0=1024, 非 0=1536; rounds argv[3]: 0 → 16)
node Build/tools/sbin/run-dongle-exe.cjs --tag gen1536 -2 13 3 1 10

# 读回 dashboard(自动 OpenSSL 复核并直出 seed/p/q 小端 hex)
node Build/tools/sbin/run-dongle-exe.cjs --tag readkey -0 13 5

# 用种子独立复现(应得到与 dashboard 逐字节相同的素数, 且探测次数一致)
node Build/tools/sbin/rsa-prime-repro.cjs --seed <seed_p> --bits 1536 --rounds 16 --expect <p>
```

## 5. 说明与后续

- 本次种子来自**设备 TRNG**(随机), 用于验证"能力与耗时";CA 方案里种子将改由
  `KDF(MASTER.SECRET, nonce, label)` 派生并连同密文张贴在 `dashboard[5120,6144)`, 算法本身不变。
- 密钥材料为**测试密钥**(测试 ukey 上的一次基准生成), 见附录, 不得用于生产。
- 后续: ①长跑耐久(12h)读回最大连续执行时间; ②按用户定义实现 CA blob 布局 / AEAD 选型;
  ③把 `d` 的计算搬进设备(当前 `d` 只在 host 侧验算)。

## 附录: 测试密钥材料(dashboard 读回, 小端 hex)

```
seed_p(le) = bf2e60af2e3853f9ed4c8de76fbc9aa3517acd002cd4830a90d7482e4d28e65fac628e5bc65caa4ec8e6b4ddbc60081d019e03b813cb4ac9746b1b8a883aa81964e322621d579973f4b872756ebc4685ea3ad5adac2e9a9ca54a27501f527119197f35065f4672ee6b0d3c5376bb52b01d87310e4275293f5b782e66918f6244a9d6a7060840b3b4e0cd8a3192dd6a043805c5a1d509b857bafd4ef99c82b7c52772b517ae744747760b0bae3a97fab13e926014eb1b02e5188202de68a46535
seed_q(le) = 7accc106e23e42a921e7cbe9818dd0b5fb447722455a25897665fbfd13dc0cd54425bd0fad1c9d97c0ceb350ba650bdbe0f8007ff401706127bae4979b1c20e49f2a85a340ffeead799fe549efa431631ebeaddd1c2495e3c8bc434f2e960feb5aafb44bc024e3df296892a7c9ed3cb9872c93822e599dca0bb2dc104c77f12fadb1ab1e28233a9d504d8dc508b7bb326f4717b1cd161b678f344b61c1bae5fd180a17c22c9302725211af0bae87aab40a033f2ff8ddafcfb106a6a44571e2b6
p(be)      = B565A468DE028218E5021BEB1460923EB1FA973AAE0B0B76474774AE17B57227C5B7829CF94EFDBA57B809D5A1C50538046ADD92318ACDE0B4B3400806A7D6A944628F91662E785B3F2975420E31871DB052BB76533C0D6BEE72465F06357F191971521F50274AA59C9A2EACADD53AEA8546BC6E7572B8F47399571D6222E36419A83A888A1B6B74C94ACB13B8039E011D0860BCDDB4E6C84EAA5CC65B8E62AC5FE6284D2E48D7900A83D42C00CD7A51A39ABC6FE78D4CEDF953382EAF6030D7
q(be)      = B6E27145A4A606B1CFAFDDF82F3F030AB4AA87AE0BAF11527202932CC2170A18FDE5BAC1614B348F671B16CDB117476F32BBB708C58D4D509D3A23281EABB1AD2FF1774C10DCB20BCA9D592E82932C87B93CEDC9A7926829DFE324C04BB4AF5AEB0F962E4F43BCC8E395241CDDADBE1E6331A4EF49E59F79ADEEFF40A3852A9FE4201C9B97E4BA27617001F47F00F8E0DB0B65BA50B3CEC0979D1CAD0FBD2544D50CDC13FDFB657689255A45227744FBB5D08D81E9CBE721A9423EE206C1CD39
```

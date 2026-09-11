# ukey 长跑(耐久)与 RSA-3072 生成 —— 2026-09-11 实验记录

> 分支 `feat/AGINX/rsa-3072-gen`。目标: ①回答"只要定时喂狗, 设备单次执行到底能连续跑多久";
> ②把自研素数搜索从 1024 位扩到 1536 位, 为"单指令内完成 RSA-3072 密钥生成"铺路。

## 1. 代码改动

### Interface/mr.{h,cc}
- `kCountWords` 32 → **48**(1536 位素因子上限); 新增 `kMinCountWords = 32`(1024 位测试仍可用);
  `BN` 因此变成 96 limb = 388B。
- **退役朴素路径**: `mulTo/remTo/mulmodW/powmodMRW` 与成员 `prod_/rem_/bs_` 全部删除 ——
  它们已无调用方(幂模早已全走 Montgomery), 且会让类超过 1KB 的 ABI 上限。
- `one_m_/nm1_m_` 从栈移入**类成员**; `nm1_m_` 由 `one_m_` 在域内相减得到
  (`nm1_m_ = n - one_m_`, 省一次 `ToMont`)。这是把 k=48 的栈需求压回预算内的关键。
- 新增: `subEq`(域内减法)、`SeedCandidate`(候选定型为严格 bits 位奇数)、
  `FindPrime`(候选 +2 搜索 + 越界防呆)、`Endurance`(定工作量 + 周期 KickWDG + dashboard 进度)、
  `ReportProgress`、`SetDongle`。
- `MontMul` 的 `t[34]` → `t[kCountWords + 2] = 50`(200B 栈)。

### src/__Testing__/__dongle__/main.cc
- `MR->SetDongle(&rockey)`:**合并到 master 后 `dongle_` 一直是 nullptr**, 设备侧 `KickWDG`
  会空指针解引用 —— 必须注入 COS 句柄(`KickWDG` 里也加了空指针保护)。
- `PrimeMRTests` 的 mode 约定(CLI 全部按 **hex** 解析):
  `0`=随机候选 / `1`=注入 1024 位素数 / `2`=注入半素数 / **`3`=设备内 RSA 素数生成** /
  **`4`=长跑耐久** / **`5`=读 dashboard 进度(host 只读, 不触发 ExecuteExeFile)**;
  mode 3/4 的 64 位参数走 `argv_[2]`(低 32 位)/`argv_[3]`(高 32 位)。
- 候选工作区从 `(BN*)Context + 2` 改为 **InOut[384, 772)**:
  k=48 时 `BN`=388B, 旧写法 `memset(Val, 0, sizeof(*Val))` 会盖掉 InOut+1024 的 16 个 GuardBytes
  → 产生 +100/字节 的**假栈溢出惩罚**。
- host 侧新增 `VerifyRsaPrimePair`(OpenSSL 独立验证: 64 轮素性 + `gcd(e,p-1)=1` +
  `p≠q` + `bits(n)` + `d` 存在)与 `ReadMRProgress`(按 magic 区分 Progress/GenResult, 生成记录自动验证 p/q)。

### 栈预算(arm `.su` + `make rockey-stack-check`)
| 函数 | 帧 |
| --- | --- |
| `Start` | 144B |
| `Testing_PrimeMRTests` | 104B |
| `FindPrime` | 72B |
| `IsPrimeMRW` | **1248B**(3 个 BN 局部 + 溢出) |
| `MontMul` | 336B(`t[50]`) |

最深链 = 144+104+72+1248+336+8 = **1912B ≤ 2032B(余量 120B)**, 1024/1536 位走同一条链 ⇒ **无需搬 SP**。
1 个 BN 的工作区放在 InOut[384,772)(设备运行时内存)而不是栈上, 是能塞进 2KB 栈的前提。

## 2. dashboard 布局(用户 2026-09-11 定义)

| 区域 | 归属 | 权限 |
| --- | --- | --- |
| 0..4KB | 用户区, 不做任何限制 | 匿名可读写 |
| **4K..5K** | **尚未分配** → 本轮临时作"长跑进度 / 生成结果"测试区 | ≥4K: 管理员可写, 其他只读 |
| 5K..6K | ROOT CA 信息(区域已定, 布局待定) | 同上 |
| 6K..7K | 托管 `SM2ECIES.key(4)` | 同上 |
| 7K..8K | WorldPublic | 同上 |

本轮实际占用(factory dataFile `0xFFFF`):
- `[4096, 4160)`: 状态记录(长跑 `Progress` / 生成 `GenResult`, **同一偏移按 magic 区分**);
  生成期间(1536 位一次约 2h)还会每 32 次探测写一条 `Progress` 记录:
  `magic=kMagicAlive, seq=阶段(1=p, 2=q), units=已探测候选数` ⇒ 中途被复位也能看到死在哪一步;
  该记录最终被 `GenResult` 覆盖。
- `[4160, 4544)`: p(小端, ≤1536 位); `[4544, 4928)`: q;
- 匿名用户区 `[2048, 2240)` / `[2304, 2496)`: p/q 的搜索起点种子(便于事后复现)。

**ROM 擦写次数有限**(用户提醒)⇒ 落盘节奏取"约 2 分钟一次": `kBeatUnits = 2^16` 单位
(实测 1 单位 ≈ 0.92-1.01µs ⇒ 每 66ms 喂一次狗), `kReportBeats = 2048`(⇒ 每 ≈135s 写一次进度)。
一次 12h 长跑约 320 次写入。

## 3. 实测(测试 ukey = 枚举索引 0, 新 ukey = 索引 1)

- **单位耗时校准**(mode 4, 目标 2,097,152 单位): 设备端 2069ms / 2111ms ⇒ **0.99-1.01 µs/单位**;
  dashboard 记录 `done / seq=1 / units=2097152 / beats=32` ✓(写返回码是 -1, 但数据确实落盘, 只作参考)。
- **5 分钟单次执行**: 300,000,000 单位 → **276,239ms(4.6 分钟)**, `mainRet=10086` 正常收尾;
  期间落了 2 条 `alive` 进度 + 1 条 `done` ✓ ⇒ 单指令 ≥4.6 分钟已确认。
- **1024 位生成路径端到端验证通过(mode 3, bits=1024, rounds=4)**: 设备内 **381,741ms(6.4min)**
  找到 p+q, `mainRet=10086`;`GenResult bits=1024 rounds=4 ok=3 probes_p=50 probes_q=123`;
  host 侧 OpenSSL 独立复核 **prime_p=1 prime_q=1 gcd(e,p-1)=1 distinct=1 bits(n)=2047 d_ok=1 ⇒ ok=1**。
- **耗时模型被精确验证**(1024 位): 173 次探测 = 试除 173×0.131s ≈ 23s + 基-2 筛查 ~28 次×10.5s ≈ 294s
  + 两个素数的余下 3 基 ≈63s ⇒ ≈380s, 实测 381.7s ✓。据此推 1536 位: 单基 10.5s×(48/32)² ≈ **23.6s**,
  试除 ≈0.2s/次, 532 次探测 + ~87 次筛查 + 末次 15 基 ⇒ **单素数 ≈42min, p+q ≈84min**(长尾 2-3h)。
- **12 小时长跑(新 ukey, 第一次)**: 11:35:13 起跑, 目标 `0xA30000000` 单位(≈12.15h)。
  11:41:27 手动杀掉 host, 11:50:25 用 `pnputil /restart-device`(需管理员)复位。
  读回 dashboard: **`alive seq=6 units=805,306,368 beats=12288`** ⇒ 设备端记录到 ≈805s(13.4min)。
- **12 小时长跑(新 ukey, 第二次)**: 12:51:29 起跑, 目标 `0xAE_EBB000` 单位(43.2e9 ≈12h);
  13:38:25 host 被**误杀**(清理进程时用了 `__Testing__dongle__*` 通配, 命中了长跑副本)。
  16:33 探测发现 SDK 已空闲(`Enum return 3/3` ⇒ 无设备在执行 item), 读回记录:
  **`alive seq=24 units=3,221,225,472 beats=49152`** ⇒ 设备端连续执行 **3,221s ≈ 53.7 分钟**,
  最后一条进度落在 13:45(host 死于 13:38:25 ⇒ **host 死后又跑了约 7 分钟**)。
  **修正先前结论**: 两次(incl. 第一次的 805s)都是"host 死后约 7 分钟设备侧 item 终止",
  ⇒ **不是"kill host 后设备会一直跑下去"**, 而是 **host 进程一死, 设备 item 会在约 7 分钟内结束**
  (推测: COS/SDK 会话断开后心跳/落盘不再被服务, 或看门狗随即复位 item)。
  因此**要测长目标必须让 host 进程一直活着**;host 墙钟与设备侧 units 都要保留。
- **当前"单指令最长"的可靠数据**: **RSA-3072 生成 3,125,713ms(52.1min) 正常收尾**
  (`mainRet=10086`, host 全程存活) 是迄今**完整跑完**的最长单指令;长跑本次达到 53.7min 后
  因 host 死亡被终止 —— "能否连续跑几小时"仍**未验证**, 需重跑一次长目标(host 不被打扰)。

### 关键约束: SDK 访问是**全局串行**的
只要有一个 `ExecuteExeFile` 在飞行(host 阻塞), **任何其它 host 进程**(哪怕操作另一支 ukey)
都会卡在设备枚举/打开上。实测两次:
- 烧录进程(索引 0, `WT_APP_DONGLE` + `-2 13 5`): 0 CPU 挂住 >160s, 日志 0 字节;
- 只读 mode 5 进程(索引 0, `-0 13 5`): >45s 无返回。

⇒ **两支 ukey 不能并行跑长任务**, 长任务必须排队; 长跑期间也无法用第二个进程观察 dashboard。
复位(或长跑自然结束)后立即恢复可用。

### 运行约定(用户 2026-09-11): 先复制改名再运行
直接用 `.bin/amd64-windows-release/__Testing__dongle__.exe` 会把构建产物占住, 使 `make windows`
无法链接(此前只能靠杀掉 host 腾出)。新增工具 **`Build/tools/sbin/run-dongle-exe.cjs`**:

```sh
node Build/tools/sbin/run-dongle-exe.cjs [--bin <exe>] [--tag <名>] <参数...>
# 复制到 .bin/run/<basename>-<tag|时间戳>.exe 后 spawn(stdio 继承, 退出码透传)
```

### 踩坑: "mainRet=10087 且 dashboard 没更新" = 设备上还是**旧固件**
第一次 mode 3 验证 129ms 就结束、`mainRet=10087`: 设备侧旧固件的 `Testing_PrimeMRTests` 不认识
mode 3, 落到通用 MR 分支读到未初始化的候选, `IsPrimeMRW` 返回 -1 ⇒ `10086-(-1)=10087`。
根因是 11:38 那次烧录被长跑占住的 SDK 卡住、**从未真正执行**(日志 0 字节)。
⇒ 判断"固件是否真的刷进去"只看 `rockey.UpdateExeFile ... 0/00000000`, 且烧录必须在 SDK 空闲时做。


## 4. 预期与下一步

- 1536 位生成的期望成本: 每素数探测数 ≈ `ln(2^1536)/2` ≈ **532**; 试除存活率 ≈ 16% ⇒
  ~87 次基-2 Montgomery 筛查 × ≈35s(按 k=32 的 10.5s × (48/32)²) + 末次 16 基 ≈ 8.7min
  ⇒ **≈1h/素数, p+q ≈ 2h**(几何分布, 长尾可到 4h+)。
- 待办:
  1. 1024 位生成路径验证(mode 3, `argv_[2]=0`)≈ 25min;
  2. 1536 位 RSA-3072 生成长跑(mode 3, `argv_[2]=1`);
  3. host exe 重建(需长跑结束释放 exe) → 读回 p/q 用 OpenSSL 复核, 落盘 `N‖e`;
  4. 长跑耐久结论读回(新 ukey dashboard);
  5. 需要"更长的极限"时, 用 mode 4 重新起一次更长的目标(注意 ROM 写入次数)。

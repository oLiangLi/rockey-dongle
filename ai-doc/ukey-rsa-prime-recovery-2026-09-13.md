# ukey 内自研 1024 位 Miller–Rabin 素数搜索:进展与卡点(提交厂家评估)

日期:2026-09-13
分支:`feat/AGINX/rsa-prime-bench`(未合并)
用途:供厂家评估“在 ukey 内用软件 Miller–Rabin 从随机数找回 RSA p/q 素数”这条路是否可行,并回答开放问题。

---

## 1. 背景与目标

恢复 RSA ROOT CA 私钥的前置问题是:无法使用 ukey 硬件 RSA 密钥生成(需注入我们指定的
2×128B 随机数,由**自研代码**从 128B 种子出发,逐步 +2 递增并用 Miller–Rabin 找回原 1024 位
素数 p、q,再自行选 e、算 d)。因此需要确认真实 ukey 上“软件找 1024 位素数”的时间量级。

约束(设备端 C++):
- 无动态分配;`.rodata` 必须为空(固件链接 ASSERT);`.bss` ≤16B;栈预算 2032B
  (0x68000BF0 → 0x68000400),另有 1KB ExtendBuf 辅助区(0x68000C00);
- 设备侧**没有日志通道**,只能通过 `SetLEDState(kOff/kOn)` 反馈状态;
- 代码经 `ExecuteExeFile` 在 ukey 内以设备 exe 方式执行(编译 `__RockeyARM__`)。

## 2. 已就绪且验证通过的部分

自研 `rsa_mr.h`(定长 uint32[64] 小端大数 + Miller–Rabin,朴素平方乘+二进制取模,
无 Montgomery、无 .rodata 表):

| 项目 | 结果 |
|---|---|
| Host 正确性自测 | PASS:u32 2..200000 与试除一致;M89/M107/M127/M521 判素;M67/M89×M107/M127²/强伪素数 3215031751(6 基)判合;确定性恢复(同 seed → 同素数);all-FF 种子回绕保护 |
| 栈优化后静态深度(arm-none-eabi -Os, stack-check) | MR 链 **1696B**(Start144+包装464+findPrimeW32+isPrimeMRW920+powmod40+mulmod16+remTo/mulTo≈72),全固件最深 1856B ≤2032B → **无需搬 SP** |
| 固件产物 | `.text` 0xc9a8(≈51.6KB≤65520);`.rodata` 空;`.bss` 16B;首 LOAD `R E`,elf2bin 通过 |
| MR 大数临时 | 放入 ExtendBuf[1KB] 的 `MRWork`(780B:prod/rem/bs 三槽),热路径函数 noinline 小帧 |

## 3. 复现步骤(厂家可据此复现)

```sh
# 构建固件(含 RsaPrimeMR 测试项, index 0x14)
make dongle
# 刷新 ukey(测试 ukey, HID 00000000-efea115bfc084642)后, 用 Windows 驱动跑:
WT_APP_DONGLE=./.bin/arm-RockeyARM-native-release/rockey_dongle.bin \
WT_RKEY_DEVICE=<设备枚举索引> \
./.bin/amd64-windows-release/__Testing__dongle__ -2 14
```

执行分两段:
1. host 直跑 `Testing_RsaPrimeMR`(Windows 驱动里 DONGLE_RUN_TESTING,在 **host CPU** 计算,
   时间无参考性,仅验证流程);
2. `rockey.ExecuteExeFile(&CopyContext, sizeof(CopyContext), &main_result)` 把同一 Context
   交设备 exe 在 **ukey 内**再执行一遍(这才是目标测量路径)。

设备端入口做了 LED 状态协议:入口一次短闪(~120ms)→ MR 大数路径自检(M127 素/M67 合,
失败则 LED 常亮死循环)→ 搜索中每 64 probes 翻转一次 LED → p 找到长亮 ~400ms → q 搜索同样
翻转 → q 找到长亮 ~400ms 后熄灭返回。

## 4. 观察到的现象(卡点)

host 直跑段正常(示例,host 计算,仅供参考,50~140ms/probe):

```
I (8001,10924,28180) App@T:737 RsaPrimeMR: p ok=1 probes=44 ms=5109 top=61dc60c2d7cddf31
I (8002,10924,28180) App@T:740 RsaPrimeMR: q ok=1 probes=19 ms=2676 top=1b71dc0afe926bc7
I (8003,10924,28180) App@T:2118 000002011DC68550:360 rockey Test.20 return 0/00000000
```

设备端执行(ExecuteExeFile 段):`rockey.UpdateExeFile` 更新新固件成功(0/00000000)后,
LED **先闪烁若干秒(说明已进入 MR 搜索且自检通过、在逐探测推进),随后 LED 常亮,设备失去响应**
(host 的 `rockey.ExecuteExeFile` 永不返回;必须重新插拔 ukey 才能恢复)。多轮、多个固件版本
均复现该现象。

诊断排除:
- 不是 host 驱动问题:同流程跑 index 0x13(RsaPrimeGenPerf,设备端 GenerateRSA 935ms)设备段
  完整执行并干净退出;
- 不是 MR 算法错误:设备端入口自检(M127 素 / M67 合)通过后才进入闪烁(闪烁=搜索中),host/emulator
  全量自测通过;
- 不是栈溢出:静态最深 1856B < 2032B,设备端无崩溃痕迹,是“无响应/被掐”而非复位循环;
- host 侧在 ExecuteExeFile 之后加 `abort()` 无法触发 → 证明卡点在该调用内部等设备返回。

**结论性判断(待厂家确认)**:设备在纯 CPU 长循环(分钟级、无任何设备服务调用)期间被某种
**看门狗(WDOG)/执行时限机制**终止或挂起;设备 ROM 只在命令/指令边界喂狗,我们的 findPrimeW
长循环将其饿死,之后设备进入不可用状态直到重新上电。

## 5. 需要厂家回答的问题(阻塞项)

1. ukey 是否存在看门狗/单次执行时限?超时多久?从**已上传 exe 内**(非 ROM 固件)的长 CPU 计算
   应如何周期喂狗——是否有可调用的指令/API(如某种 yield/keepalive)?还是规定单次 exe 执行
   必须在一定时间内返回?
2. 设备是否暴露**任意模数的硬件模幂/大数乘**原语(可把 mulmod 换成 Montgomery 或字级除法,
   预计提速 30–100×)?当前朴素实现每次 mulmod 是逐位长除 O(bits²),在低主频 MCU 上可能
   本身就是瓶颈。
3. ukey 主频/是否有硬件乘法器(32×32→64)?能否给出单条指令/单次 1024-bit 模乘的参考耗时?
4. 设备端是否存在任何调试/日志通道(串口、共享内存标志等)?当前只能看 LED,定位困难。
5. 官方对“长时间计算任务”的推荐形态:拆成多次短执行(每次以命令/opcode 边界收尾喂狗)?
   若是,请给每次调用的时间预算上限与状态持久化建议(我们的备选方案是 host 循环多次
   `ExecuteExeFile`、每次 ≤ 数探测,状态放 Context 字段带回)。

## 6. 备选路线(按现状分级)

1. **喂狗确认后(问题 1)**:若设备侧存在周期喂狗/让出 API,在当前单次执行架构内即可收尾
   计时(代码已就绪,只差喂狗点)。
2. **分块执行**:host 循环多次 ExecuteExeFile,每次设备只算 ≤N 探测并把候选/进度放 Context
   带回;每次调用都是设备命令边界,天然喂狗;与最终“OpExecute 系列指令化”设计同构。
3. **mulmod 提速**(Montgomery/字级除法):无论走哪条路都需要,尤其设备主频低时。

## 附:相关代码/产物

- `src/__Testing__/__rsamr__/rsa_mr.h` — 定长大数 + MR(工作区版,进度回调可挂喂狗/LED)
- `src/__Testing__/__dongle__/main.cc` — `Testing_RsaPrimeMR`(index 0x14)、Start 分发、
  ExecuteExeFile 流程、LED 协议
- `.bin/arm-RockeyARM-native-release/rockey_dongle.bin` — 带测试项的固件(已刷新到测试 ukey)
- Host 自测驱动(临时):`.bin/host_mr_selftest.{cc,exe}`

---

## 7. 2026-09-13 深挖与结论(本任务就此暂停)

### 7.1 设备侧 LED / 看门狗语义(实测确认)

- `SetLEDState(kBlink)` **不会自动闪**:闪烁由**COS 调用派发**——必须在写完状态后发生一次
  COS 调用(如 `GetTickCount`/`GetPINState`);纯 busy loop / 自旋/延时**无效**,只会看到 LED
  停在最后一次写入的电平(表现为"常亮")。
- `GetTickCount` 在 item 执行期**不自走**(时间冻结),故 ukey 内不能用它计时/延时;但作为
  "触发一次 COS" 的心跳非常合适。
- 结论:ukey 内长计算必须**周期性发 COS 心跳**,否则 LED 不闪且设备可能被挂起;心跳点已放在
  幂模内层(每 16 次平方一次,见 `powmodMRW` 的 Tick 回调)与测试项入口。

### 7.2 COS 心跳候选实测(FTRX.h 只读清单筛选)

| 候选 | 结论 |
|---|---|
| `get_tickcount`(**已选定**) | 5 次 53.1 ms / 2000 次 79.1 ms ⇒ 固定 ~53 ms(ExecuteExeFile 往返)+ **边际 ~13 µs/次**;`pin/share0/lasterr` 跑前跑后一致,无副作用;设备正常返回 |
| `get_pinstate` | 可服务 LED(用户实验验证);host 侧路径为 NOTIMPL,仅设备侧可用 |
| `led_control(kBlink)` | 幂等重发,仅 LED 状态变化,可作备选 |
| `get_sharememory` / `get_keyinfo` | 只读但负载更大(32B/~40B),不优 |
| `get_realtime` / `get_expiretime` | 本机 NOTIMPL(F0000016),污染错误态,排除 |

### 7.3 单次执行运行窗口标定(关键反转)

新增线性可调负载 `-delay N`(设备端固定混合运算,**1.2564 µs/iter**,每 1024 次一次 COS 心跳
并反转 LED),host 量墙钟:

| N | 结果 | 墙钟 |
|---|---|---|
| 1e8 | rc=0, done='COS1' | 125.674 s |
| 2e8 | rc=0, done='COS1' | 251.278 s |
| 3e8 | rc=0, done='COS1' | 376.913 s |
| **4e8** | **rc=0, done='COS1'** | **502.563 s(8.4 分钟)** |

⇒ **设备单次 `ExecuteExeFile` 至少可连续运行 >502 s,并不存在 ~8 分钟的窗口限制**(上限尚未探到,
可继续 6e8/8e8 递进)。此前 MR 在 ~466 s / ~490 s 失败**不是超时**。

### 7.4 朴素 MR 在 ukey 上的结论

- 单次 1024 位探测(rounds=1 与 rounds=8)均约 466–490 s 后以
  `DONGLE.EXEC 'Dongle_RunExeFile(...)' Error FFFFFFFF` 失败,随后设备挂死(LED 常亮,需软复位);
- 结合 7.3:这不是窗口问题,而是 **MR 路径自身挂死/耗时远超 502 s**——朴素"逐位二进制取模"
  在 1024 位规模下代价过高(单次 base-2 幂模即无法在已有窗口内完成),或存在特定输入下的死循环;
- **结论:朴素实现不可行**。要在 ukey 内完成 1024 位素数搜索,必须先做 `mulmod` 提速
  (字级长除或 Montgomery,预计 30–100×),再重新评估"每数字一次探测/整轮搜索"的可行性。

### 7.5 本任务暂停决定

- 暂定**暂停**"ukey 内软件找回 RSA p/q"这条探索,后续按"已有良好 ROOT CA 私钥托管方案"推进其它工作;
- 若恢复该任务,第一步是:实现 Montgomery(或 word-wise) `mulmod` + 现有 Tick 心跳,再用
  `-delay`/单探测模式重新标定单次探测耗时,然后判断 ~355 候选/素数的整轮可行性。

### 7.6 本轮新增工具与用法

- `__Testing__rsamrprobe__`(独立 host 程序,仅允许测试 ukey,HID 校验):
  - 单数字分块探测:`-2 <rounds> <maxProbes> [limbs]`(limbs 默认 32;小 limbs 用于标定)
  - COS 微基准:`-2 -cos <cand> <iters>`(cand 1..5;单独测某个候选)
  - 运行窗口标定:`-2 -delay <iters>`
- UDP 软复位(管理员 shell 运行,收到 `127.0.0.1:12345` 任意报文即
  `pnputil /restart-device`,仅限 `VID_096E&PID_0209`):
  `.bin/ukey-reset-dgram.cjs`
- 设备侧快速路径:`__Testing__dongle__` Start 顶部按 `rsaprobe::kMagic` + mode 分发到
  `Testing_RsaPrimeProbeOne`(单候选)/`Testing_CosProbe`(COS 候选)/`Testing_DelayProbe`(负载)/`Testing_RsaPrimeOne`(最小实验)。

---

## 8. 暂停后的剩余工作(前提:ROOT CA 私钥托管已有良好方案)

> 说明:本节把"ROOT CA 私钥托管/恢复"视为已解决,列出本仓库内仍待推进的事项;其中多数
> 需要产品/固件或用户侧输入,已标注"需决策"。

### 8.1 本探索的收尾(已完成)

- 代码/工具/文档归档:分支 `feat/AGINX/rsa-prime-bench`(commits `b557b92` 归档实验态、
  `2ac4fc4` 深挖结论与暂停);工具见 §7.6。**未合并到 master**,由用户决定是否 squash。
- 可选后续(如恢复该任务):`mulmod` 换字级长除/Montgomery(30–100×),再用 `-delay` 与单探测
  模式重标定;`-delay` 已验证设备可连续运行 >502 s,时间不是主要障碍。

### 8.2 ROOT CA / CA 签发主线(需真机与决策)

1. **X509 CA 真实私钥往返**:`x509-ca-sign` 分支的 `RockeySign`/`RockeyDecrypt` 接线已并入
   master;待核对"真实 CA 私钥导入/签名往返"的设备侧语义(需测试 ukey + 管理员权限,按
   `WT_RKEY_DEVICE`/`-2` 流程;禁止 mkey/* 生产设备)。
2. **EnTrust 真实托管密钥输入**:`EnTrust.dongle` 目前用随机占位被设备拒绝(-22),需要真实
   托管私钥(EnTrustKey)才能跑通;多设备 `EXCHANGE_PREV_MASTER_SECRET` /
   `IMPORT_MASTER_SECRET` 需要双 ukey 编排规范(用户提供或产品定义)。
3. **MASTER.SECRET 与 SESSION_KEY 流程对齐**:`ai-doc/master-secret-build-2026-09-09.md`、
   `ai-doc/session-key-flow-2026-09-09.md` 中的 K0..K3/A0 托管矩阵可视为"已解决前提";
   建议在其中补一句"ROOT CA 恢复由托管方案覆盖",并把原先依赖 RSA 素数恢复的段落标注为
   已替代(避免后续误读)。
4. **问题清单同步(需人工确认)**:`ai-doc/issues-status.md` / `bug-analysis-report-2026-09-01.html`
   中与"CA 根私钥恢复"相关的开放项(H-08、M-01 等)在托管方案下可评估关闭或降级,需逐条确认
   依据后再改状态。

### 8.3 工程与回归

- `make ci`(进程内 JS 模拟器回归:jsuite/mkey/skey/emuadmin/corpus/trngfail)与
  `make test-web`(Chrome headless,user-data-dir 固定 `.bin/ai-web-user-data`)为当前门禁;
  本次改动不影响其运行,可择机整体复跑确认。
- 未提交/未推送状态:截至本文档更新,分支 `feat/AGINX/rsa-prime-bench` 新提交已落盘,按用户
  squash-merge 习惯待其合并。

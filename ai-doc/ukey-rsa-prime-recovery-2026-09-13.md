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

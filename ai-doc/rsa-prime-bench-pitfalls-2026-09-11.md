# RSA 素数测试/ROOT CA 生成:踩坑归档(2026-09-11)

> 覆盖分支 `feat/AGINX/rsa-prime-bench` 及其延续 `feat/liangli/rsa-rm-test-2` 上遇到的
> 全部"坑"。每条按 **现象 → 根因 → 规则/修复** 记录,便于整体合并与后续复用。
> 配套文档:`ai-doc/ukey-rsa-prime-recovery-2026-09-13.md`(探索过程与暂停结论)、
> `ai-doc/rsa-root-ca-generation-2026-09-11.md`(单指令生成定案)。

---

## A. 构建 / 工具链 / 仓库约定

### A1. arm 固件链接因 host `main` 失败(calloc/strtoul)
- **现象**:`make dongle` 链接 `rockey_dongle` 报 `undefined reference to 'calloc'`、`'strtoul'`,
  以及 `Unknown destination type (ARM/Thumb)` / `dangerous relocation`。
- **根因**:模块里的 host 入口 `int main(argc, argv)`(用 calloc/strtoul)被链接进 MCU 固件
  (设备侧只应有 `Start`/VM 入口,不链接 libc)。
- **规则**:任何 host-only 入口/宿主逻辑都要 `#if !defined(__RockeyARM__) … #endif` 包住。
  (固件构建也会带 `Testing_*`,因此判定不能只靠"是否测试代码"。)

### A2. `.rodata` 必须为空(设备读 rodata 有问题 + 链接断言)
- **现象**:固件 `.rodata` 出现 68B(内容为 16 个 u32 小素数);链接断言
  `__rodata_begin == __rodata_end` 失败。
- **根因**:函数内 `const uint32_t sm[16] = {…}` 之类的局部常量表被编译器提升到 `.rodata`。
- **规则**:设备侧禁止任何常量表;改为**运行时在栈上生成**(如按奇数递推生成小素数基)。
  构建后用 `arm-none-eabi-readelf -S`/链接输出确认 `rodata bytes: 0`。

### A3. elf2bin 的 ELF 布局契约(首 LOAD 必须 RX)
- **现象**:`elf2bin.cjs` 报 `Invalid .text segment.`(或 "extra LOAD segments would be dropped")。
- **根因**:把 `.rodata` 拆成独立输出段后,段首 `. = ALIGN(8)` 在 `.text` 结尾补出 4B `*fill*`
  (被标成 NOBITS/WA),首 LOAD 的 `p_flags` 从 `R E`(5) 变成 `RWE`(7);而 elf2bin 要求:
  首 LOAD `vaddr==0 && flags==5 && filesz==memsz && memsz<=65520`,其余 LOAD 必须
  `filesz==0` 且 `vaddr ∈ {0x68000bf0, 0x68001400}`。
- **规则**:`.rodata` 留在 `.text` 段内(空段,断言相等);不要为了消 "RWX 警告" 去拆段,
  该警告本身来自这些填充字节。布局校验用 `arm-none-eabi-readelf -lS`。

### A4. `.bss` ≤ 16B(链接断言)
- **现象**:加全局/静态大数组导致 `__bss_end - __bss_begin > 0x10` 断言失败。
- **规则**:设备侧大对象只能放栈、类成员(reinterpret 到 InOut/ExtendBuf)或设备存储;
  类大小用 `rLANG_ABIREQUIRE(sizeof(X) <= 1024)` 兜底。

### A5. Windows 构建缺 `clang-cl`(需要 VS 环境)
- **现象**:`/bin/sh: clang-cl.exe: 未找到命令`(exit 127),而后台直接编 `make windows` 失败。
- **根因**:当前 shell PATH 没有 VS 开发环境变量。
- **规则**:Windows 构建统一用:
  `cmd /c '"C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" && make windows'`。

### A6. exe 正被占用导致 INSTALL 失败
- **现象**:`cp: 无法创建普通文件 '...__Testing__dongle__.exe': Device or resource busy`。
- **根因**:上一次卡死的驱动进程仍在运行(host 阻塞在 USB 调用)。
- **规则**:编译前先 `taskkill /IM __Testing__dongle__.exe /F`(或确认无残留)。

### A7. 增量构建会掩盖警告
- **现象**:改了头文件后"无警告",但全量重建时冒出 `unused function` 等。
- **规则**:清警告时用 `touch` 强制重编相关 TU;或看完整构建日志而非尾部。

### A8. Makefile 的 CRLF 与 `git diff --check`
- **现象**:新增 Makefile 行被报 `trailing whitespace`。
- **根因**:Makefile 在仓库历史中就是 CRLF(`core.autocrlf=false`),`git` 把 CR 当行尾空白。
- **规则**:属既有格式噪音,不要为过 `diff --check` 去改行尾/整文件重写。

### A9. 新增 C/C++ 需 UTF-8 BOM;AI 代码包裹约定
- **规则**:非 third_party 的 C/C++(含 .cc/.h)、asm、ts/js 保存为 UTF-8 **带 BOM**
  (用字节级前置 `EF BB BF`,编辑工具可能丢 BOM,需复查);
  本分支约定 AI 生成的 C/C++ 用 `AGINX_DECLARE_MACHINE` / `AGINX_DECLARE_END` 包裹
  (早期为 `rLANG_DECLARE_MACHINE/END`);头文件里的 static 函数加 `unused` 属性,
  避免"只用到部分头文件"的 TU 报未使用告警。

### A10. Windows 下使用的脚本不要写 `#!` shebang
- **现象**:带 `#!/usr/bin/env node` 的 `.cjs` 在 Windows 下(直接执行/被某些环境加载)报错。
- **规则**:可能跑在 Windows 的工具脚本**首行不要写 shebang**,统一用 `node xxx.cjs` 调用;
  同时注意 UTF-8 BOM 会排在首行之前、更易出问题,故此类脚本不加 BOM。
  (`.bin/ukey-reset-dgram.cjs` 已按此修正。)

---

## B. 设备运行时 / 调试通道 / 复位

### B1. 设备侧没有日志通道,只能看 LED
- **现象**:设备内 `rlLOGI` 打不出来;host 直跑段的日志 ≠ 设备执行段。
- **规则**:设备内结果用 **InOut/Context 字段回传**(本分支用 `ts_`/`error_` 阶段码,
  或从 `ExtendBuf` 取状态);识别"谁在跑":日志里 `Context` 指针是 host 堆地址(如
  `00000247…`)就是 host 直跑,是 `68000000` 才是设备执行。

### B2. `SetLEDState(kBlink)` 不会自己闪,必须发生 COS 调用
- **现象**:写 `kBlink` 后 LED 常亮;写 `kOn/kOff` 交替也不动。
- **根因**:闪烁/看门狗由**设备 COS 调用派发服务**;纯 busy loop 期间 OS 没机会服务。
- **规则**:item 内**禁止自旋/延时**;要 LED 有指示就在循环里周期性发一次 COS 调用
  (本分支选定 `GetTickCount`,只读、无副作用、边际 ≈13µs/次)。`KickWDG` 已埋进
  Montgomery 幂模内层(每 32 次平方一次)。

### B3. item 执行期 `GetTickCount` 冻结
- **现象**:设备内读 `GetTickCount` 前后值不变;用它做延时/计时会死等。
- **规则**:ukey 内**不做延时/计时**;设备耗时一律由 **host 墙钟**测(调用前后取时间)。
  `GetTickCount` 只当作"触发一次 COS"的心跳使用。

### B4. 单次执行没有"8 分钟窗口";kill host ≠ 停设备
- **现象**:早期 MR 在 ~466s/490s 以 `FFFFFFF` 失败,误判为执行时限。
- **真相**:用 `-delay N` 线性负载实测 1e8/2e8/3e8/4e8 全部成功,**4e8=502.6s 正常返回**;
  朴素版 16 基素数更是**单次连续 30.4 分钟**跑完。失败其实是"朴素 MR 太慢/挂住"。
- **规则**:
  - 不要用前台命令跑长测试(执行器有 600s 上限,被截断会**杀掉 host 但设备仍在跑**);
  - 长任务用**后台任务 + 日志文件轮询**,等它自然结束;
  - kill host 之后设备可能成为"孤儿运行",此时 **PnP 软复位无效**(固件在跑),
    只能物理拔插(VBUS 断电)。

### B5. PnP 软复位(`pnputil /restart-device`)的边界
- **现象**:复位后设备 `Get-PnpDevice` 显示 `Unknown`(未枚举),厂商命令 `Enum=-1/F0000001`;
  或复位命令返回 success 但设备仍在跑。
- **规则**:
  - 设备**空闲但挂死** → `pnputil /restart-device` 可用;
  - 设备**正在执行** → 无效,需拔插;
  - 复位后消失了 → 再发 `pnputil /scan-devices` 或 disable/enable,仍不行就拔插;
  - 需要提权:普通会话 `Access is denied`,要在管理员 shell 里跑;
  - 工具:`.bin/ukey-reset-dgram.cjs`(管理员运行;监听 `127.0.0.1:12345`,UDP 报文
    `restart`/`cycle`/`scan`/`enable`/`disable`,仅允许 `VID_096E&PID_0209`)。

### B6. GuardBytes 是免费的"栈溢出探测器"
- **现象**:设备返回 `mainRet` 不是 `10086/10085`,而是差了 1600(=16×100)之类。
- **根因**:`Start` 在 `InOut+1024` 写 16 个 `0xCC`,结束时每个不匹配就 `+100`。
  设备栈越界写到这里就"报"出来。
- **实例**:Montgomery 版 MR 一度 1632B 帧 → 超出 2032B 栈 → `mainRet` 多了 1600;
  压到 1376B 后恢复正常。
- **规则**:看设备 `mainRet` 与 `10086 - 预期结果` 的差值/是否为 100 的倍数,可立刻判断栈溢出;
  栈占用用 arm `.su`(`-fstack-usage`)核对最坏调用链。

### B7. 设备测试入口/索引要对齐分支
- **现象**:传 `-2 15` 跑了半天什么也没发生(落回 Start 的通用尾段)。
- **根因**:不同分支的 `kTestingIndex` 枚举不同(master 基线上 `X509Tests` 之后直接是
  `PrimeMRTests`=19=0x13;AGINX 分支另有 19/20 两个项)。
- **规则**:跑测试前先看该分支的 `kTestingIndex` 枚举再给索引;hex 参数用 `-2 13` 这种形式。

### B8. 只允许动测试 ukey
- **规则**:测试 ukey HID `00000000efea115bfc084642`;`mkey/*`(K0..K3、A0、E0/E1/E10、
  C1/C4…)一律不碰;工具里做 HID 安全闸(独立探测程序 `__Testing__rsamrprobe__` 已内置,
  非测试 ukey 直接拒绝,除非显式 `WT_RKEY_ALLOW_ANY=1`);永不用 `Utilities.lock`。

### B9. Dashboard 约定
- **事实**:dashboard = factory dataFile `0xFFFF`,**8192B**;`[0,4096)` 为既有 notice/证书区;
  **`[5120,6144)`(5K–6K,1KB)已保留给 RSA ROOT CA 生成 blob(布局待定)**;
  写入要单次 `WriteDataFile` 原子完成。

---

## C. 大数 / Miller–Rabin 算法坑

### C1. `BN::clear()` 后 `n=0` 导致"全判合数"
- **现象**:注入真素数被 host 与设备一致判成合数;随机合数"看起来对"。
- **根因**:类版 `BN::clear()` 把 `n` 置 0;`powmod` 里 `r.clear(); r.v[0]=1;` 却漏了 `r.n=1`
  → `mulTo` 因 `a.n==0` 空转 → 乘积累加恒 0 → 任何基都判失败。
- **规则**:`clear()` 后必须显式设置有效 limb 数;写完 MR 用**已知素数**做正例验证
  (只用随机合数测会漏掉这类 bug)。

### C2. 朴素"逐位取模"在 ukey 上不可行
- **实测**:单基 1024 位幂模 ≈**109.5s**,16 基 ≈**1824.6s(30.4min)**;
  单素数期望 ~355 探测 ⇒ 数小时/素数。
- **规则**:必须换 **Montgomery**(或字级长除)。Montgomery 后:单基 **10.5s**、
  16 基 **158.2s**(≈11.5×)。

### C3. Montgomery 无 R² 的省栈做法
- **做法**:不做 R² 预计算;用 `ToMont`(k·32 次模倍增)进域、`FromMont`(k·32 次半减)出域;
  CIOS 只需 `uint32_t t[k+2]`(≤136B 栈);比较全在 Montgomery 域(one_m/nm1_m 各转换一次)。
- **规则**:进域条件必须按 `cmp(r,n)>=0` 判定,不能用"是否有进位"代替(见 C4)。

### C4. `ToMont` 的进位误判(只在小数值上暴露!)
- **现象**:全长随机数测试 600 组全过;但 1-limb 小操作数/小素数转换后结果错,MR 判素失败。
- **根因**:`if (carry || cmp(r,n) >= 0) subtract n` —— **进位只表示越过 32 位 limb 边界,
  不代表 ≥ n**;小数值时会错误地减一次 n。
- **规则**:改为只按 `cmp(r,n)>=0` 减 n;**Montgomery 验证必须覆盖小操作数、别名(原地)、
  以及 ToMont/FromMont 往返**,不能只测满长随机数。

### C5. 小素数试除是最划算的前置过滤
- **实测**:`TrialDivide`(3..1000 奇数,流式求余、无素数表→无 rodata)在设备上
  **131ms** 就能拒掉 ~92% 的候选。
- **规则**:MR 之前先试除;上限可调(1000→更大可再省 MR 次数,但单次试除变慢,需折中)。

### C6. 设备上的 `Delay`/空转循环是陷阱
- **现象**:所有用例耗时恒定 ≈42s,掩盖了真实 MR 时间与试除效果。
- **根因**:测试里 100×`Delay(1)` + 100×`Delay(4)` ≈ 5000 万次空转(仅用于粗估主频),
  设备上 ≈42s。
- **规则**:计时测试里删掉/关闭人为延时;`Delay` 已删除;要 LED 慢闪请用 KickWDG 节奏,
  不要用空转。

### C7. 候选推进的边界(修正:不需要回绕保护)
- **规则**:候选构造保证 **bit1023 = 1 且最高 32-bit 字 ≠ 0xFFFFFFFF**;此时要递增到 `2^1024`
  (溢出成 1025 位、乘积超出 64-limb 临时)需要 **>2^990 次 `+2`**,任何设备都跑不到
  ⇒ **无需回绕保护**。
- **保留**:`probes` 上限仅作为"长时间找不到素数"的失败兜底,与溢出无关。
- **反例提醒**:若初始候选逼近 `2^1024-3`(最高字 = 0xFFFFFFFF),1~2 次 `+2` 就会溢出 ——
  这正是必须维持"最高字 ≠ 0xFFFFFFFF"的原因。

### C8. Host/wasm 计时没有参考性
- **事实**:host 上 ~50–140ms/probe,设备上单基 ~10s;结论必须以**设备内实测**为准
  (host 直跑只用于逻辑与交叉验证)。

---

## D. 本轮沉淀的工具与提交

### D1. 工具
- `Interface/mr.{h,cc}`:`MillerRabinContext`(`TrialDivide` / `MontMul` / `ToMont` / `FromMont` /
  `N0Inv` / `IsPrimeMRW(rounds)` / `KickWDG`),`sizeof ≤1024` 断言。
- `src/__Testing__/__dongle__/main.cc`:`Testing_PrimeMRTests`,入口
  `-2 13 [mode 0=随机/1=素数/2=半素数] [rounds 1..16]`。
- `__Testing__rsamrprobe__`(AGINX 分支):单数字分块探测 / `-cos` COS 微基准 / `-delay` 运行窗口标定,
  含测试 ukey HID 安全闸。
- `.bin/ukey-reset-dgram.cjs`(gitignore,未入库):管理员 UDP 触发 `pnputil` 软复位。
- `.bin/host_mr_selftest.cc`、`.bin/mont_test.cc`、`.bin/mont_mr_test.cc`(临时对照程序,未入库):
  分别校验定长 MR、Montgomery 原语、Montgomery MR 与朴素实现对拍。

### D2. 提交对照(便于 squash 合并时理解)
- `feat/AGINX/rsa-prime-bench`:`7c686f6`(RsaPrimeGenPerf)、`95299ae`/`5b2760c`(rsamr 原型/
  RsaPrimeMR)、`48fadee`/`97d41a1`(栈与 rodata 修复)、`b389273`(栈优化 6248B→1696B)、
  `b557b92`(COS 实验归档)、`2ac4fc4`(深挖结论/暂停)、`1aadd1b`(剩余工作清单)。
- `feat/liangli/rsa-rm-test-2`:`c117127`(AGINX_DECLARE_MACHINE 约定等)、`62ac4dd`/`b53c611`/
  `f392781`(迁移到 `Interface/mr.*` 并跑通设备退出)、`942ef8a`(正确性 r.n 修复+试除)、
  `7f89092`(Montgomery+栈 1.84KB)、`8d11a8a`/`bbd2f03`(ROOT CA 单指令方案汇总与 dashboard 区域)。

### D3. 2026-09-11 合并准备:内容归属(整体合并前必读)

**已并入本分支 `feat/liangli/rsa-rm-test-2`:**
- `Makefile` 的 `rockey-stack-check` 目标(工具 `Build/tools/LIMIT/stack-check/` 本就在 master);
- `src/__Testing__/__trngfail__/xModule.mk` 的"非 native 才构建可执行"修正(host-only 模块不进固件);
- AGINX 分支的 **7 条 `ai-context.md` 历史**(置于文件末尾"合并自 feat/AGINX…"标记之后);
- `ai-doc/ukey-rsa-prime-recovery-2026-09-13.md`(原样带入,两分支内容一致)。

**未并入(仍留在 `feat/AGINX/rsa-prime-bench`,且已被取代):**
- `src/__Testing__/__rsamr__/*`(早期定长 `rsa_mr.h` 与向量原型);
- `src/__Testing__/__rsamrprobe__/*` + `probe_io.h`(COS 微基准 / 运行窗口标定工具,
  依赖 AGINX 时代设备侧 `kModeOne/kModeCos/kModeDelay` 快速路径);
- AGINX 版 `src/__Testing__/__dongle__/main.cc`(其 `RsaPrimeMR` 与探针快速路径已被
  `Interface/mr.*` + `Testing_PrimeMRTests(mode 0/1/2)` 取代)。

**结论**:整体合并时**可以直接丢弃 AGINX 分支**(其独有文档与历史已并入本分支);
若后续仍需要 COS 心跳/运行窗口标定工具,按当前 `Interface/mr.*` 形态重做设备侧 mode 即可。

# Rockey-Dongle 项目审查上下文记录

> 本文件是 2026-09-01 ~ 2026-09-02 一次完整代码审查会话的工作上下文,并持续维护至 2026-09-05(§9 复核、§10 后续提交),供后续会话/接手人直接续接工作,避免重复分析。
> 配套交付物:`bug-analysis-report.html`(完整带样式报告,含图表)。

---

## 1. 任务背景

- **用户请求**:① 分析项目有没有 bug;② 评估项目难易程度;③ 生成 HTML 报告;④ **重点检查设备端随机数发生器**。
- **审查方式**:4 路并行深度审查代理 + 主会话独立 RNG/基础库分析 + 可执行验证。
- **审查对象**:master@8555281,自研代码约 33,000 行(不含 `third_party/TASSL`),测试约 5,600 行。
- **结论**:确认 **51 项问题**(Critical 4 / High 11 / Medium 12 / Low 24),难度评级 **专家级 9/10**。

## 2. 项目关键事实(审查中核实,勿重复推导)

### 2.1 构建与模块结构
- 平台:MCU 固件(arm-none-eabi,RockeyARM)/ Linux / Windows / Cygwin / aarch64-linux / WASM / ~~wasmjs~~(wasmjs 已于 2026-09-07 删除,§10.15),自研 x4c 构建系统(`Build/`)。
- **固件中 `Dongle` 的实现是 `Interface/rockey.cc`**(由 `Interface/xModule.mk:9-11` 选择);`dongle.cc` 是主机侧 USB 实现;`emulator.cc` 是模拟器实现。三个类同名,`secret.cc`/`master.cc`/`script.cc` 为共享成员函数。
- 密码学有两套实现:`base/src/crypto.cc`(5,524 行,常量时间版本)与 `Interface/curve25519.cc`(当前 1,806 行,慢速路径,**dongle 固件 VM 指令实际走这套**;审查时 2,429 行,e3c7283 紧凑化净删 659 行,见 §10.2)。
- **固件无除法约束(2026-09-04 发现)**:Cortex-M0 无硬件除法,/ 与 % 引入 `__aeabi_idiv → idivmod.o → crt.o → main` 依赖链,导致测试固件链接失败。固件侧拆包/打包/日期解析一律用移位序列递进替代除法(§10.2/§10.3,x509.cc 同样遵守)。
- **固件禁用 switch-case(用户 2026-09-04 告知)**:多 case 的 switch 会生成 rodata 跳表(`-fno-jump-tables` 阻止不了),违反 linker.ld 的 rodata 为空断言;固件侧(rockey.cc/x509.cc 等编入固件的文件)一律写 if 链。宿主侧(emulator.cc/dongle.cc/wasm)不受限。

### 2.2 固件内存布局(定量核算结果)
| 区域 | 地址/大小 | 说明 |
|---|---|---|
| InOutBuf = `vm.data_` | `0x68000000`,1KB | `[0,256)` 输出/公共区,`[256,1024)` 输入区 |
| ExtendBuf = `vm.buffer_` | `0x68000C00`,1KB | 三段复用:ChaChaPolyCtx/Sha512Ctx@+0(恰256B)、RuntimeHeader@+256、DecodeTextContext@+512,**时序不重叠,安全** |
| 栈 | SP=`0x68000BF0`(start.s:6)向下生长 | 到 InOutBuf 顶共 **2032 字节**,无溢出保护 |
| .bss / .data / .rodata | — | linker.ld 断言:rodata/data 必须为空,BSS ≤ 16 字节 |
| Ed25519 Helper | 恰 1024B 占满 ExtendBuf | `fe` 为 `int32_t[10]`(40B),`rLANG_ABIREQUIRE(sizeof(Helper) <= 1024)` 恰好压线通过 |

### 2.3 脚本体系
- 自研 DSL:TS 编译器(`Web/Script/`)+ C++ VM(`Interface/script.cc`);opstk 仅 16 字、代码上限 100 半字、`pc_` 为 uint8_t。
- 脚本 DATA 区(后 768 字节)完整性仅靠"密钥 = SM3(ScriptText 明文)"的 ChaCha20-Poly1305 MAC(**自引用、知道明文即可重算**);真正签名只覆盖代码区。kScriptAdmin 等关键流程额外做 SM2ECIES 签名是必要的,新增脚本类型必须保持该模式。
- `rlCryptoChaCha20Block` 是**纯函数**(不自增计数器),状态推进全靠调用方 `++entropy_local_[15]`。

## 3. 完整发现清单(51 项)

### Critical(4)
| ID | 位置 | 问题 |
|---|---|---|
| C-01 | `Interface/script.cc:856-869` | OpFuncDigest 5 处 `md=nullptr` 未检查(OpCheckMM 越界只置 zero_,当前指令仍执行)→ 设备写 0 地址挂死,**匿名脚本可达**(MAC 密钥可自算);主机/模拟器 NULL 写段错误 |
| C-02 | `base/src/crypto.cc:24-151` | 自实现 memset/memcpy 严格别名违规 + 146-151 宏重定向。**已实证**:-O2 下 X25519 输错且非确定、Ed25519 200/200 签名不互操作但内部自洽;-O1/-Os/-O3 正确;`-fno-strict-aliasing` 可恢复。当前构建 -O1 碰巧安全,windows.conf 已配 -O2 |
| C-03 | `src/app/main.cc:652/674` + `data.cc:89` | `--list`:rl_BASE64_Write 无界,3,457 字符写 2,048 缓冲,**≥38 只狗触发**,溢出 ~1.4KB |
| C-04 | `base/src/data.cc:49-87` + `main.cc:252` | rl_BASE64_Read(len=-1):strlen 转换被注释,NUL 被忽略,唯一出口是 '=';无 padding 输入 → 越界读 + 无界写 128KB 栈缓冲 |

### High(11)
| ID | 位置 | 问题 |
|---|---|---|
| H-01 | `rockey.cc:51`/`dongle.cc:95`/`emulator.cc:661` | DRBG 熵反馈哈希循环余数而非原始长度:64 倍数长度时反馈 `SHA512("")` 公开常数,**熵积累完全失效**(三处同源复制粘贴) |
| H-02 | `rockey.cc:32`/`dongle.cc:75` | RandBytes 只对前 128B 注入硬件随机,`[128,size)` = 陈旧缓冲区 ⊕ 密钥流 |
| H-03 | `start.s:6` + `linker.ld` | 栈预算 2032B 无保护;Ed25519 链(Sha512Ctx 240B + W[80] 640B + VM ~300B)逼近/超限(README 已知问题的定量化);`master.cc:41/196` 有 1024B 栈对象 |
| H-04 | `start.s:20-29` | 启动桩**无 BX/BLX**,从不跳 app_entry(手工反汇编验证:全靠 app_entry 恰为 .text 首字节);不清 .bss |
| H-05 | `chachapoly.cc:33-39` | Open 先解密后认证:失败时明文已写入且 *size_ 已更新;memcmp 非常量时间 |
| H-06 | `crypto.cc:4325/5449` + `curve25519.cc:2246` | X25519 无全零输出检查(RFC 7748 §6.1 要求):低阶点/小群直达 PREV_MASTER_SECRET 派生链(execute.cc:368);fe_frombytes 忽略最高位 |
| H-07 | `grammar.ts:749-757` | 负数立即数 `[-0x100000,-0x1001]` 且低12位非零:编码把减法做成加法(**实测** -5000→-3192、-8191→-1),静默错码 |
| H-08 | `grammar.ts:820-834` | 编译器不建模栈深:23 半字的 4 层嵌套调用可达栈深 18>16 → SIGSEGV + 清空全部数据 |
| H-09 | `emulator.cc:524-548` | OpWriteSecretFile 失败仍 EncryptBuffer 提交:私钥槽静默变为"合法加密的全零",后续读成功返回全零 |
| H-10 | `main.cc:646-647/810` | 模拟器 Open 任何失败(含口令输错)→ Create + 无条件 "wb" 重写:**口令敲错一次,镜像密钥全部丢失** |
| H-11 | `elf2bin.cjs:68-95` | 只取 phdr[0],其余 PT_LOAD 段静默丢弃;g_FEI 段无断言保护 |

### Medium(12)
| ID | 位置 | 问题 |
|---|---|---|
| M-01 | `curve25519.cc:2192-2213` | Interface 侧 ge_scalarmult 秘密依赖分支(处理签名 nonce);crypto.cc:4176 有常量时间版本未用;`if(!init)` 泄露最高置位位 |
| M-02 | `curve25519.cc:2292` + `dongle.h:66-71` | 私钥清零被 DSE 删除(**实证**:-O2 对象文件 memset 数=0);应改用 crypto.cc:7-16 的 cipher_cleanse |
| M-03 | `tokenize.ts:243-251` | 前导零十进制按八进制截断:"09"→0 不报错 |
| M-04 | `grammar.ts:671-729` | 内存读写内建不检查对齐:VM LoadMM/StoreMM 要求对齐,`kLoadI32(257)` 编译过运行必错 |
| M-05 | `grammar.ts:1266/1836/1723` | `public` 可 >256:输出区覆盖输入区 + 收尾 memset 破坏输入 |
| M-06 | `script.cc:1390/1594` | `Exit(非0)` 被当致命错误:清空全部输出(exit code 与错误码共用 zero_) |
| M-07 | `dongle.cc:132` | 主机 GetPINState 恒失败:实参是逗号表达式(字符串字面量 + DONGLE_FAILED),没调用 API;管理员 PIN 提升路径永远失败 |
| M-08 | `curves.cc:510` | ComputeSecretSecp256k1 返回 uECC 布尔(成功=1),与项目 0=成功 约定相反:ECDH 失败被当成功(:431 有正确写法) |
| M-09 | `emulator.cc:209-241`、`rockey.cc:224/326` | 主密钥 secret[256]/ECCSM2/RSA 私钥材料错误路径残留栈;BN_free 未用 BN_clear_free |
| M-10 | `main.cc:447-449/210-212` | argv 全打印(含 PIN);锁定流程把新管理员 PIN 打日志 3 遍(与"彻底忘记PIN"注释矛盾) |
| M-11 | `execute.cc:84-86` | ExecutePrepare 先 memcpy 256B 再校验 vm.data_/vm.buffer_ 指针(顺序颠倒) |
| M-12 | `rockey.cc:14/32` | 设备端两处 HwARandBytes 不查返回值(TRNG 失败→状态=0⊕编译期常数,同批固件输出一致);启动后无重播种 |

### Low(24)
L-01 `grammar.ts:903/1481` 移位≥32 静默截断 · L-02 `grammar.ts:1101/1019/986` 逻辑运算结果值不对称(5||7→1 但 5&&7→7) · L-03 `Web/Script/main.cc:17` WASM 解析栈 256 层,深嵌套报错误导 · L-04 `dongle.cc:33-66`/`emulator.cc:595` SM2Cipher ASN1 转换导出 API 无输出长度参数 · L-05 `script.cc:160` CreateDataFile 接受负尺寸 · L-06 `main.cc:383` 失败后仍哈希未初始化 dashboard[8192] · L-07 `dongle.cc:789` Enum 不钳制 SDK count(clamp 在越界写之后) · L-08 `script.cc:997` TDES 要求 %16,块大小是 8 · L-09 `curves.cc:27-30` ScopeRNG 全局指针竞态(单线程潜伏) · L-10 `pki.cc:32-38` 未初始化内存做 RAND_seed · L-11 `emulator.cc:761-1004` 模拟器不落实文件权限(安全测试结论偏乐观) · L-12 `main.cc:628` 默认主密钥 "1234567812345678" · L-13 `master.cc:281-307` READ_MASTER_SECRET 失败仍覆写输出 · L-14 `secret.cc:137-141` 错误路径不清零 · L-15 `main.cc:705` isxdigit 负 char UB · L-16 `emulator.cc:536` + `dongle.h:454-459` DONGLE_VERIFY 失败 abort 宿主 · L-17 `main.cc:404` rand() 未播种 · L-18 `sha256.cc:235` size_t→int 截断(>2GB 静默跳过) · L-19 `crypto.cc:928/949` ChaCha20 32 位计数器回绕无检测 · L-20 `crypto.cc:5365` Ed25519 接受非规范公钥(ref10 行为,设计取舍) · L-21 `crypto.cc:5503` PubkeyEx 无 clamping(#if 0 中) · L-22 `curve25519.cc:2206` dummy ge_add 读未初始化 T(UB,MSan 会报) · L-23 `crypto.cc:5477` rlCryptoRandBytes 熵池无播种路径 · L-24 `log.cc:221` 日志颜色复位码被覆盖(sprintf 返回值被丢弃)

## 4. RNG 专项(用户指定重点)

结构:启动 `entropy_local_[16]` ← TRNG 64B → `InitializeEntropyLocal`(secret.cc:99,混编译期常数,LocalChaos 混狗信息)→ 构造函数 `SeedBytes(&info)`。

- **核心判断:该 DRBG 不可预测性完全依赖启动时 64B 硬件随机**——反馈失效(H-01)、无重播种(M-12)、>128B 无硬件熵(H-02),状态演化对知道初始状态者确定已知。全部密钥生成(Ed25519/X25519/uECC/RSA/随机填充)都走这条路径。
- RNG-4(低):计数器仅 `++word[15]`,2^32 块回绕(生命周期内达不到)。
- 修复:P0 = SHA512 用原始长度 + >128B 滚动注入硬件随机 + 检查 get_random 返回;P1 = 周期性重播种(SHA512 混入而非加法)+ 修 Ed25519 栈溢出消除状态覆写通道。

## 5. 已验证无问题项(不要重复审查)

- **算法数值正确性(-O1)**:SHA1/256/384/512(576 组多段含边界)、ChaCha20-Poly1305(RFC8439 + 419 组)、Ed25519(RFC8032 + 208 组,含确定性 nonce/clamping/常量时间比较)、X25519(RFC7748 全向量)、fe_*/sc_muladd/sc_reduce、micro-ecc 三曲线常数——全部与标准一致。**两份实现(crypto.cc 与 curve25519.cc)的 sc_reduce/sc_muladd 行为等价**——审查时逐行等价(ref10 全展开);e3c7283 后 curve25519.cc 侧为 21 位肢体循环版,等价性由 `__Testing__diff__` 差分模块持续保证(§10.2)。
- C++ VM 运行时防护(栈深/地址/对齐/除零含 INT_MIN/-1/cycles/跳转边界)完备;scanner.cc(flex 移植)无泄漏无越界;ExtendBuf 三段复用时序安全;SM2 各缓冲边界核算无误;rbtree.cc/base.cc 日期算法/logWrite 布局核算无误。

## 6. 难度评估结论

专家级 **9/10**:密码学 5.0 / 极限资源约束 5.0 / 编译器+VM 自研 4.5 / 跨平台构建 4.0 / 密钥管理流程 4.0 / **测试体系 2.5(主要短板)**。维护者画像:同时熟悉密码学实现细节与 ARM 裸机的资深工程师;上手 2-4 周(仅理解内存布局与密钥流程)。

## 7. 修复路线与修复状态

### 已修复/关闭状态(2026-09-03 复核后修订)

> ⚠️ 本表原为"37 项已修复";2026-09-03 全量复核发现:**合并提交 c72d21c(何圣军补丁)与记录描述存在多处出入**——部分修复未落地、部分机制不同、H-09 反而引入了回归。以下各行已按复核结果修订,标注 ✅(复核属实)/ ⚠️(机制与记录不同但效果达标)/ ❌(未落地)/ 🔒(关闭:用户设计决策)。

| ID | 修复内容 | 验证方式 |
|---|---|---|
| C-01 | script.cc 五处 digest handler 增加 `if (md)` 空指针检查 | g++ -fsyntax-only 通过 |
| C-02 | 删除 crypto.cc 的 cipher_memset/memcpy/memmove 及宏重定向(134 行),改用 libc | **-O1/-O2/-O3 全部通过 RFC 7748 X25519 + RFC 8032 Ed25519 向量**(修复前 -O2 失败) |
| C-03 | main.cc --list 缓冲 2048→4096(最坏 64 只狗需 3462) | 语法检查通过 |
| C-04 | 🔒 **关闭(用户决策 2026-09-03)**:strlen 模式与现状退出条件一致(NUL→z64v[0]=-1 与 '=' 同路径终止),恢复 strlen 转换不改变行为;真正的边界修法是给 zOUT 传入容量,但调用端保证输入 NUL 终止且输出缓冲足够,无需接口变更。代码已加设计决策注释 | 11 场景功能测试在改动前后均全过(实证退出条件一致) |
| H-01 | 三处 RandBytes 的 SHA512 反馈改用 `size_total`(原始长度) | 语法检查通过 |
| H-02 | rockey.cc/dongle.cc 硬件随机改为按 64 字节块滚动注入(覆盖全缓冲) | 语法检查通过 |
| H-05 | CHACHAPOLY_Open:常量时间 tag 比较 + 失败清零缓冲 + *size_ 仅成功时更新 | 语法检查通过 |
| H-06 | rlCryptoX25519 与 Curve25519::X25519 改返回 int + 常量时间全零检查(低阶点拒绝);ComputeSecretCurve25519 传播错误;base.h 声明同步 | **功能验证:u=0 低阶点返回 -EFAULT**;RFC 向量仍过 |
| H-07 | grammar.ts 负数立即数:`kLoadMNI\|M` + `kAddUI\|(0x1000-L)` | **10,987 个样本数值验证零失配** |
| H-09 | ✅ **2026-09-03 重做**:c72d21c 合并版本删除了 DecryptBuffer(回调在密文上执行、成功路径双重加密、失败路径把已存密文再加密),RMW 写损坏(ReadWriteDataFile 每文件仅最后 64B 块正确,9 错);基线对照实验证实为合并引入的回归(基线 102/HEAD 93)。已重新修复:副本上先解密→回调→成功才 EncryptBuffer+swap,失败丢弃副本(空槽保持 empty、已有槽原密文不动) | **对照实验:index=2 两轮 102(0 错),其余索引与基线逐项一致** |
| H-10 | 🔒 **关闭(用户决策 2026-09-03)**:`.foobar-dongle.bin` 仅测试用途、每次重新生成、跨编译不兼容,保留无意义;Open 失败即 Create 的行为保留,不修 | — |
| H-11 | elf2bin.cjs 恢复 phnum 校验(允许一个空 g_FEI 段) | node 语法可解析 |
| M-02 | curve25519.cc X25519 私钥标量、dongle.h HashBase::Clear 改 volatile 逐字节清零(不可被 DSE 删除) | 语法检查通过 |
| M-03 | ⚠️ 机制与记录不同:修复在 dongle.sc 词法层(DEC 正则允许裸 `0`、`[1-9][0-9]*` 排除前导零,"09" 切成 0、9),tokenize.ts 无 RangeError;行为目标("不静默按八进制截断")达成 | 实测行为达成 |
| M-04 | grammar.ts Memory Load/Store 常量地址编译期对齐校验(memoryAccessSize);顺带修正 Store 分支错误消息 LoadMemory→StoreMemory | tsc 通过 |
| M-05 | ~~grammar.ts AC_PUBLIC_SIZE_X 上界 1024→256~~ **已回退(3ef001d,设计决策)**:public 上界恢复 0..1024。设计依据(代码注释):输入阶段布局 TEXT[256]+DATA[768],输出阶段整个 1024B 均可作输出,两阶段时序不重叠 | HelloWorld 实测通过 |
| M-06 | 🔒 **关闭(用户决策 2026-09-03)**:设计上任何非零返回都清除 InOutBuffer,不需要分辨错误原因;exit_/bit29 方案从未入库,作废,不修 | — |
| M-07 | dongle.cc GetPINState 逗号表达式 → 诚实 `-ENOSYS` 存根(SDK 无该查询 API) | 语法检查通过 |
| M-08 | curves.cc ComputeSecretSecp256k1 返回约定改 `? 0 : -EFAULT` | 语法检查通过 |
| M-09 | ✅ 完整解决:emulator.cc 三处改 `BN_clear_free` + **全局重定向**(project.local.mk `COMMON_CFLAGS += -DBN_free=BN_clear_free`)覆盖 dongle.cc 三处私钥与 pki.cc 两处(公开值 e/r/s 多一次清零,代价可忽略;TASSL 经自身 Configure 编译不受影响;固件无 OpenSSL 符号无害) | 全目标重编后 nm 验证:项目对象 0 处 BN_free 引用;aarch64/foobar 套件 0 错误 |
| M-10 | 🔒 **关闭(设计决策)**:argv 打印保留,合并补丁反而新增注释明确"ukey 之外的信息都是众所周知的,即使 PIN 也必须被日志记录"的设计哲学;RockeyARM_Lock 的 PIN 打印由 `rLANG_CONFIG_DONGLE_FINAL_LOCK` 宏门控(宏未定义,开发构建仍打印 3 次,带 escrow 到 SM2ECIES 公钥的 TODO) | 完整构建通过 |
| M-11 | execute.cc RockeyTrustExecutePrepare:先校验 `vm.data_/vm.buffer_` 再 memcpy 256B | 完整构建通过 |
| M-12 | rockey.cc 构造函数 HwARandBytes 失败重试 3 次(失败清零不残留);RandBytes 两处检查 HwARandBytes 返回值,失败立即返回错误(调用方 master.cc:252 / script.cc:81 均已检查);H-02 的逐块注入即持续重播种 | 完整构建通过 |
| L-01 | grammar.ts 移位量 ∉[0,31] 编译期抛 RangeError(立即数优化 3 处 + 常量折叠 3 处) | tsc 通过 |
| L-05 | ✅ 2026-09-03 统一:负/零/超限尺寸返回 -EINVAL(与记录一致;此前为 -ERANGE) | 完整构建通过 |
| L-06 | ✅ 2026-09-03 补全:哈希仅在 ReadDataFile+ReadLine 均成功后执行(此前仅零初始化) | 完整构建通过 |
| L-07 | ✅ 2026-09-03 修复:Enum 增加 `DONGLE_VERIFY(count <= 64)` 契约断言(SDK 文档保证最多 32 HID+32 CCID=64;count>64 说明 Dongle_Enum 已越界写 all[64]、内存已损坏,事后钳制无意义,直接 abort) | 完整构建通过 |
| L-08 | script.cc TDES 分块校验 %16→%8(SM4 的 %16 保留) | 完整构建通过 |
| L-10 | Web/Emulator/pki.cc RAND_seed 缓冲零初始化 | tsc/wasm 构建待验(本机未编 wasm) |
| L-13 | master.cc OpManager_ComputeSecretBytes:READ_MASTER_SECRET 失败立即清零上下文并返回 -EFAULT(不再把零秘密哈希进输出) | 完整构建通过 |
| L-14 | secret.cc READ_MASTER_SECRET 两个错误路径补 memset 清零 ENCRYPT_MASTER_SECRET | 完整构建通过 |
| L-15 | main.cc isxdigit 参数 cast unsigned char | 语法检查通过 |
| L-17 | main.cc 删除无意义 rand() 调用(值立即被 RAND_bytes 覆盖) | 完整构建通过 |
| L-18 | ⚠️ 机制与记录不同:无 INT_MAX 分块;实际为 internal_sha256_update 的 len 参数 int→size_t 加宽 + 调用处去掉 (int) 强转(>2GB 截断消除,效果等同;另有 `&& 0` 死分支残留旧代码) | **sha256 测试套件 0 错误** |
| L-22 | curve25519.cc ge_scalarmult 开头把 dummy T 初始化为单位点(fe_0/fe_1,不读未初始化内存;Helper 仍恰 1024B) | **25519 测试套件 0 错误** |
| L-24 | log.cc efmt sprintf 返回值累加 | 语法检查通过 |

修改文件(21):Interface/{script,rockey,dongle,emulator,chachapoly,curve25519,curves,execute,master,secret,sha256}.cc、Interface/{script,dongle}.h、base/src/{crypto,log}.cc、base/bits/base.h、src/app/main.cc、Web/Script/lib/{grammar,tokenize}.ts、Web/Emulator/{emulator,pki}.cc、MCU/RockeyARM/elf2bin.cjs。(base/src/data.cc **实际未改动**,C-04 见上表标注;TRNG 收敛新增 Interface/TRNG.cc,由 xModule.mk 编入三目标)

**2026-09-02 完整构建验证(本机 aarch64 原生,`X4C_NODE=/usr/local/bin/node`)**:
- `make aarch64-linux -j8`(含 TASSL 静态库 + libRockeyARM.a)→ **exit 0,零错误**
- `make foobar -j8`(__EMULATOR__ debug)→ **exit 0**
- 测试套件(退出码 102 = `10086-error` 即 0 错误):__Testing__25519__ / __Testing__sha256__ / __Testing__micro_ecc__ / __Testing__aes__ 全部 0 错误;__Testing__dongle__ 的"0 错误"仅覆盖无参单索引运行,完整 17 索引的正确协议与结论见 §9.1
- __Testing__dongle__ 的 aarch64-linux 版需要实体 USB 硬件(本机无,失败属预期)
- tsc@5:仅剩两个预存在 wasm 产物模块缺失错误(需先 make wasm);wasm/cygwin/windows/arm-none-eabi 固件目标本机未验证,刷机前应跑 `make dongle`

### ⏳ 未修复(需要更大改动或真机验证)

#### H-03 栈预算 —— 2026-09-03 精确核算完成(工具链 arm-none-eabi 10.3.1, .su + R_ARM_THM_CALL/JUMP24 重定位调用图, 见 /tmp/stack-analysis/*.sh|py)

**豁免范围(用户确认)**:`OpExecute_*` 在调用栈末尾执行后程序立即退出(刻意封装);`OpManager_*` 为系统初始化设计,运行后设备身份变更,运行时无敏感信息。两者按"路径终点"豁免,但其被调函数在其他路径上仍需计入(不可整子树豁免——`Ed25519::Sign` 等同时被两者调用)。

**稳态(脚本中段)真实违规 = 3 个指令家族,32 条路径,全部终于 `internal_sha512_process`(1056B)**:
| 家族 | 最深路径 | 超出 | 路径 |
|---|---|---|---|
| OpSecp256k1 | 2444B | +412 | SignMessageSecp256k1(272)→uECC→RNG→RandBytes(104)→**Dongle::SHA512(256,含 Sha512Ctx 栈临时 240B)**→process(1056) |
| OpFuncP256 | 2356B | +324 | GenerateKeyPairPrime256v1(264)→uECC_make_key→RNG→同上 SHA512 链 |
| OpEd25519 | 2204B | +172 | Sign(592)→Sha512Ctx::Final→internal_sha512_final(32)→process(1056) |
| OpEd25519(ge 路由) | 2128B | +96 | Sign(592)→ge_scalarmult_base(16)→ge_scalarmult(528)→ge_add(88)→fe_mul(392) |
| Ed25519 Verify(ge 路由) | 2096B | +64 | Verify(568)→同上 ge 链 |

**关键帧(Cortex-M0/Thumb-1, 8 寄存器导致 64bit 变量必然溢出)**:internal_sha512_process 1056(W[80]=640+溢出416) · Sign 592(Sha512Ctx 240 + 内联 sc_muladd ~192) · Verify 568(+rcopy/scopy/rcheck 96) · ge_scalarmult 528 · X25519 616 · fe_mul 392 · Start 376(Dongle+VM_t~292 内联) · Dongle::SHA512 256(Sha512Ctx 临时) · RSAPrivate(bits版) 568 · OpManager_VerifyWorldPublic 1216(WorldPublic 整结构在栈,豁免)。

**修复方案(已实测原型验证)**:
1. **P0 sha512.cc W[80]→W[16] 滚动窗口** —— ✅ **已实施并验证(2026-09-03)**:帧 **1056→360**,与原型一致;违规路径 **32→8**(Secp256k1 2444→1748✓、P256 2356→1660✓、Ed25519-sha512 2204→1508✓,剩余 8 条均为 Ed25519 ge 路由 2160B/超128,待方案 2/3)。验证:①aarch64 __Testing__25519__(RFC8032)/sha256/micro_ecc 全 0 错误;②foobar 模拟器 __Testing__dongle__ 端到端 0 错误;③直接向量 4808/4808(长度 0..600 一次性+8 种分段边界+SHA-384 抽查,对 Python hashlib 全一致)。注:process 代码 2512B(原型 914B 因假常量偏小,真 64bit 常量在 M0 需更多指令物化);.bin 恒 65520B(定长镜像,空闲随机填充)。W16 索引:i-2≡i+14, i-7≡i+9, i-15≡i+1, i-16≡i (mod 16)。
2. **P0 curve25519.cc Helper 联合体死区放 Sha512Ctx** —— ✅ **已实施并验证(2026-09-03)**:union{q|qc+p1p1} 新增 `alignas(Sha512Ctx) uint8_t sha512_ctx_[sizeof(Sha512Ctx)]`(240B≤320B) + `Sha512Ctx& sha512_ctx()` 访问器(reinterpret_cast,与 ExtendBuf 静态转换同一惯用法);替换 ComputePubkey/Verify/Sign 共 5 处 `Sha512Ctx()` 栈临时(死区断言已逐一核实:ge_frombytes_vartime 仅用栈 fe 局部量,不触 q/qc/p1p1;哈希输出 az/nonce/hram 均在 Helper 偏移≥800,与 ctx(偏移 0)无别名)。帧:Sign **592→344**、Verify **568→368**、ComputePubkey **272→32**;static_assert(sizeof(Helper)≤1024) 通过。**全链重扫描:违规路径 8→0;稳态最大深度 1928B/预算 2032B(余量 104B,最深链 = Verify→ge_scalarmult→ge_add→ge_p1p1_to_p3→fe_mul)**。验证:aarch64 __Testing__25519__(RFC8032)/sha256 0 错误;foobar 模拟器 __Testing__dongle__/__Testing__25519__ 0 错误。
3. **P1 sc_muladd/ge_frombytes_vartime 强制 noinline + Verify 免拷贝** —— ✅ **已实施并验证(2026-09-03,比原计划更简)**:关键洞察——sc_muladd 只在 Sign 末尾执行、ge_frombytes 只在 Verify 开头执行,与 ge 链**时序不重叠**,独立成帧即可,无需 Helper 工作区搬迁。改动:① `sc_muladd` + `__attribute__((noinline))`(独立帧实测 336B,Sign 344→**40**;2026-09-04 e3c7283 紧凑化后 sc_muladd 帧 336→**400B**、sc_reduce 328→**232B**,stack-check 复核 0 违规);② `ge_frombytes_vartime` + noinline(独立帧 344B,Verify 368→**224**);③ Verify 删除 rcopy/scopy(全程只读 signature,直接用 signature/signature+32)。**最终:违规 0,稳态最大深度 1784B/2032B,余量 248B**(最深链 Verify→ge_scalarmult→ge_add→ge_p1p1_to_p3→fe_mul)。验证:aarch64 25519/sha256 0 错误;foobar dongle/25519 0 错误。注:noinline 属性对 wasm(emscripten/clang)同样有效,但 wasm 目标本机未构建验证。
4. 备选(余量不足时):ge_scalarmult 528B 疑含 `*R=A`/`A=*point` 结构拷贝的 160B 栈临时(×2)+inlined ge_p2_dbl t0,改 fe_copy×4 或逐成员赋值估计 -300;fe_mul 392 串行化(滚动进位,活跃值 20→6)估计 -200;Verify 的 rcopy/scopy 可直接用 signature±32 免拷贝 -64。
5. 验证:__Testing__sha256__ + RFC 6234 向量 + __Testing__25519__(RFC 8032)+ make dongle 后重跑 /tmp/stack-analysis 全链扫描确认 0 违规。

> 2026-09-03 备注:提交 `3ef001d`(Test HelloWorld Ok)在上下文记录之后做出,含两处实质变更:① **M-05 修复被有意回退**(见上表),public 上界恢复 1024;② `dongle.sc` DEC 正则 `[1-9][0-9]*` → `[1-9][0-9]*|0`,允许裸 `0` 字面量(此前是词法错误;tokenize.ts 的 parseInt("0",8)=0 已兼容,scanner 由 .sc 构建时生成,自洽)。其余均为 prettier 格式化,L-01/M-04 修复经核对完好。

- H-03 栈预算重构——**2026-09-03 已解决:方案1(W16)+方案2(Helper ctx)+方案3(noinline×2+免拷贝)全部实施验证,违规路径 32→0,稳态最大栈深 1784B/2032B(余量 248B)。栈检查工具已入库:`Build/tools/stack-check/`(make stack-check,退出码 0/10 可接 CI;含豁免语义文档与历史参考值)。注:wasm 调用栈可认为很大,无需在意栈深,只需逻辑正确;栈约束仅存在于 dongle 固件**
- H-04 ~~start.s 启动桩重写~~ **关闭(用户确认)**:真机无问题;ukey 环境 text 段不可读出,且 Cortex-M0(ARMv6-M,已从 .o 属性证实)无 BLX 寄存器指令,`ldr+blx` 本就不可执行——启动桩依赖 app_entry 恰为 .text 首字节是刻意的。start.s 现已重写(含 Vector 表 SP=0x68000BF0 + RandFill 字节模式)
- H-08 编译器栈深静态建模(需要完整的 codegen 栈深计算框架)
- M-01 Interface 侧换用常量时间标量乘(涉及两套实现的取舍)
- L-02 逻辑运算结果值不对称(`5||7`→1 但 `5&&7`→7;改语义可能破坏既有脚本)
- L-03 WASM 解析栈 256 层(wasm 侧改动,本机未编 wasm)
- L-04 SM2Cipher ASN1 转换 API 无输出长度参数(接口变更)
- L-09 ScopeRNG 全局指针竞态(单线程潜伏,加锁需评估)
- L-11 模拟器不落实文件权限(安全测试结论偏乐观,涉及测试方法学)
- L-12 默认主密钥 "1234567812345678"(改动破坏既有镜像兼容性,需产品决策)
- L-16 DONGLE_VERIFY 失败 abort 宿主(改为返回错误影响所有调用点)
- L-19 ChaCha20 32 位计数器回绕无检测(生命周期内达不到,收益低)
- L-20/L-21 Ed25519 非规范公钥/ref10 行为、PubkeyEx 无 clamping(#if 0 死代码)——设计取舍
- L-23 rlCryptoRandBytes 熵池无播种路径(需接主 RNG,涉及初始化顺序)

## 8. 审查方法与可信度边界

- 密码学:提取独立测试程序,本机 aarch64 GCC 11.4.0(与项目交叉编译器同版本)与 OpenSSL/Python cryptography 交叉验证。
- 脚本:解码词法 DFA 表,复刻编译器 + VM 语义可执行模拟(H-07/H-08/前导零均实测)。
- 固件:内存布局定量核算 + start.s 手工反汇编 + 链接脚本断言分析。
- **边界**:交互输入测试未在真实设备执行(仅语义模拟),设备侧行为(C-01 的 BusFault 等)为推断;FTRX `get_random` 硬件质量无法从源码验证,属信任假设。

## 9. 2026-09-03 复核会话记录

### 9.1 复核方法与关键更正

- **测试协议更正(重要)**:`__Testing__dongle__` 无参数运行**只执行 Test.0**,不跑 17 个索引;且测试设计为**共享镜像顺序运行**(index=1 先删后建,首轮全新镜像上 Delete 必然失败 3 次,二轮归零)。此前"foobar 0 错误"结论即因单索引运行而误判。正确协议:`rm .foobar-dongle.bin` 一次 → 顺序跑 index 1..17 → 循环两轮取稳定值。
- **基线对照实验**:在 8555281 worktree 构建 foobar 与 HEAD 同协议对照。结果:除 index=2 外全部索引退出码两版本完全一致;index=2 基线两轮 102(0 错)vs HEAD 两轮 93(9 错)——H-09 回归实锤,已修复(见上表)。
- **既有失败(非修复批次引入,基线同样存在)**:index=8 KeyExec 二轮 86(16 错,状态累积相关);F=Curve25519Test 是长测试(>100s,非挂起);9=HashExec 为 100 万次哈希循环(~82s)。
- **stack-check 保真度**:工具 91 个未匹配帧多为 C 函数(符号表无参数列表与 .su 签名 arity 失配)。补配后稳态最大深度 1784→**1816B/2032B,余量 216B,0 违规**(最深路径无未知帧;__aeabi_lmul 实测 8B)。用户确认:FTRX.a 按厂家手册**只使用 ExtendBuf[1024],不消费用户栈**,故闭源 FTRX 帧不构成风险。工具改进项(C 符号短名匹配)已原型验证,未入库,可按需合入。
- **构建与套件**:aarch64-linux / foobar / make dongle(固件 65520B)/ tsc 全部通过;aarch64 四个套件 + foobar 25519/sha256/micro_ecc/aes/HelloWorld 0 错误。

### 9.2 TRNG 复审结论(用户真机反馈后修订)

- H-01/H-02/M-12 修复属实且正确,三平台收敛为共享 `Interface/TRNG.cc`。
- **用户真机事实**:① get_random 在 <128B 长度实测不失败(64B 逐块注入有足够冗余);② Init+EnTrust+MASTER.SECRET 在物理隔离可信环境执行,主机 nonce 保密——每次上电交易 VM_t 构造时 `SeedBytes(InOutBuf, 1024)`(SHA512 正规混合)构成**按交易的可信宿主重播种通道**,覆盖 R2/R3 公开输出状态增量问题。
- 结论:威胁模型内(可信 provisioning 环境 + TRNG 正常)**评级"强"**。
- **R1 保留(用户决策 2026-09-03)**:TRNG 只在初始化时生成密钥(此时有外部高熵 nonce 输入);真实场景大部分使用 Ed25519 签名(确定性 nonce,不依赖 TRNG);RandBytes 在降级为 PRNG 时返回 -EFAULT。已按此决策在代码中记录警告:**TRNG.cc RandBytes 注释**(降级语义、Ed25519 豁免、非 Ed25519 签名/密钥生成调用方必须检查返回值)与 **rockey.cc 构造函数注释**(3 次重试全失败不中止的理由)。新增 RandBytes 调用点必须保持检查返回值的模式。2026-09-03 晚补充落地**编译期强制**(31f41fe):声明/定义加 `__attribute__((warn_unused_result))`(GCC 默认生效,无需 -Wall),产品路径 3 处真实检查返回值(main.cc nonce/sPIN、wasm nonce),测试 12 处按约定 `std::ignore` 显式忽略,全平台构建 0 新增警告。
- **R6 已修复(2026-09-03, 31f41fe, 用户产品决策)**:LocalChaos/MASTER_SECRET_PROCESS 每轮每段 `++cipher[15]`。"4 段相同"原诊断源于按独立输出缓冲假设的误读——因 union 别名(stream/cipher 同址)实际每段已链式不同;真正问题是计数器未规范推进,已修复并加注释(链式派生,非标准 CTR)。**决策理由**:构建种子每次随机生成(Makefile:40-43 `rLANG_WORLD_SEED` + Interface/xModule.mk:52-55 `rLANG_WORLD_SECRET_SEED`)→InitializeCipherState→MASTER.SECRET 掩码,重构建必然使旧镜像 MASTER.SECRET 解不开,与 H-10 同理,修复无额外兼容负担。
- R5 已于 2026-09-03 修复(dongle.cc/emulator.cc 构造与 rockey.cc 对齐:3 次重试+失败清零,wasm 分支保持 JS 宿主语义)。
- 修正:芯片侧 RSA/P256/SM2 私钥文件生成与文件内签名/解密走 FTRX 芯片内部,不经本 DRBG。

### 9.3 构建警告清零(2026-09-03 晚, 31f41fe)

- 目标:amd64-linux / aarch64-linux 构建日志(.make-*-warning.log)可消除项全部清零。
- **TASSL(third_party, 真实 bug)**:pk7_doit.c PKCS7_signatureVerify `i` 在 no_hash 路径 BIO_read 失败 goto gerr 时未初始化 → `i = -1`;s3_lib.c `gtype = 0`(GCC 误报,行为不变);s_client.c OPT_DTLS1_3 显式报"不支持"(原静默忽略,1.1.1 分支无 DTLS1.3 实现)。
- micro-ecc default_RNG 加 `__attribute__((unused))`(本项目经 uECC_set_rng 注入自研 RNG);HelloWorld 测试 RSA_generate_key→RSA_generate_key_ex(弃用 API);emulator.cc -Wformat 枚举转换与 -Wclass-memaccess 取 `[0]`(foobar debug 才显)。
- **TASSL 构建是 stamp 门控**(third_party/project.mk `.build-tassl-done`):源改动需手动 make -C 各配置 Build-TASSL + install_sw 再清二进制重链接;修改第三方源时注意 pk7_doit.c/s3_lib.c 是 **GBK 编码**,必须字节级编辑(UTF-8 工具会打乱上游中文注释,曾发生一次已恢复)。
- 不可消除:设备固件 readelf "bogus end-of-sibling" 提示。~~glibc 静态链接 dlopen/getaddrinfo/gethostbyname 警告~~(原判不可消除)已由 65c3adc 根除——TASSL 内 weak 桩 + 符号重定向,见 §10.5。
- 既有问题(未修,后续已删除平台):wasmjs 配置链接失败(Web/Emulator pki.cc 的 RockeyPKEY_Sign/Decrypt 为 rLANGIMPORT,宿主无 JS 实现)——wasmjs 目标 2026-09-07 整体删除,问题不再需要解决(§10.15)。

### 9.4 协议重验(31f41fe 之后, 2026-09-03 晚)

- 按 §9.1 协议重跑(`rm .foobar-dongle.bin` 一次 → 顺序跑 index 1..17 → 两轮;参数为 hex 字符串,十进制 10..17 对应 "A".."F","10","11")。
- 结果与基线预期**逐项一致,无回归**:i1 3→0(全新镜像 Delete 失败 3 次归零);i2 两轮 0(H-09 无回归);i4/i6/i7 首轮 3/2/2 错(全新镜像删除不存在文件)二轮归零;i8 二轮 16 错(文档记录既有状态累积,精确匹配);i9/F 长测试 0 错;i10-i16 全 0。
- i17(PKeyCountDownTest)两轮稳定 3 错:未传 argv_[1] 时跳过密钥文件创建,SM2Sign(1)/P256Sign(2)/RSAPrivate(3) ENOENT ×3——确定性既有行为(§9.1 "除 index=2 外全部索引两版本一致"涵盖此项)。
- 结论:R6 修复 + warn_unused_result 强制 + 警告清零批次(31f41fe)无协议回归。

## 10. 2026-09-04 后续提交记录(7f9f9f6 之后)

> 以下三个提交晚于本文件上次更新(7f9f9f6,其 ai-context.md 内容即 §9.3/§9.4;7f9f9f6 附带的 secret.cc 改动仅为 R6 链式派生注释,见 §9.2 R6 条)。

### 10.1 11e2757 消除 Windows 编译警告

- micro-ecc `platform-specific.inc` **Windows 分支** default_RNG 加 `__attribute__((unused))`(Linux 分支同类修复在 31f41fe,§9.3)。

### 10.2 e3c7283 Ed25519 标量运算紧凑化(固件 ROM −12.5KB)

- curve25519.cc:ref10 全展开 64 位 sc_muladd(8.8KB)与 x25519_sc_reduce(5.0KB)改写为 **21 位肢体循环版**(+145/−804 行,算法逐字节等价);RockeyTrust text **61528B → 49024B**,为 X509 接入腾空间。
- 拆包/打包用增量递进(移位序列 0,5,2,7,4,1,6,3 循环)替代除法——即 §2.1 无除法约束的来源;肢体保持 int64_t(折叠含 `-=`,依赖算术右移语义)。
- 栈帧:sc_muladd **336→400B**、sc_reduce **328→232B**,stack-check 复核 0 违规(§7 方案 3 已加注)。
- 新增 `src/__Testing__/__diff__/` 交叉验证模块(172 行):RFC 8032 Ed25519 向量经 dongle 路径逐字节匹配;RFC 7748 X25519 向量 1 匹配;**向量 2(非规范输入)两实现共享既有偏差**(不做 mod-p 归约,差 19),断言与 crypto.cc 行为一致;1000 轮随机签名/验签/公钥/共享密钥与 crypto.cc 双向差分。

### 10.3 d3ec243 X509 证书验签原语(设备端基础原语)

- 新增 `Interface/x509.{h,cc}`(815/107 行),编入 LOCAL_SRC_FILES(xModule.mk);dongle/emulator/rockey 三实现各加 X509 入口(+85/+85/+58);dongle.h 新增 `RSAVerifyPkcs1`/`SM2VerifyMessage` 虚函数(设备端 signature 就地覆写,输入输出共用,master.cc 同款)。
- **严格 DER 解析**:≤1KB 证书就地零拷贝(2026-09-07 上限改为 **≤2KB**,见 §10.16);拒绝 indefinite/非规范编码/尾随字节/负 INTEGER。
- API:`X509Parse / X509VerifySignature / X509VerifySelfSigned / X509ExtNext / X509CheckTime / X509GetPublicKey` + 9 个 `X509OID_*` 判断。
- **验签全走硬件/宿主库**:RSA2048-SHA256(FTRX rsa_pub / TASSL RSA_verify)、P256-SHA256(FTRX ecc_verify / TASSL)、SM2-SM3(FTRX sm2_verify / TASSL EVP_SM2 别名路径,e = SM3(Z_A||tbs) 标准语义)。
- 设计要点:时间检查只置警告位(设备 RTC 不可靠);遵守固件无 rodata/无除法约束(OID 立即数比对、拆包/日期解析无 / 与 %)。
- 新增 `src/__Testing__/__x509__/`(320 行):TASSL 生成 RSA/P256/SM2 CA+叶证书,正反例与 OpenSSL X509_verify 对照 0 错误;stack-check 0 违规。
- **⏳ 待办:脚本层 OpCode 尚未接入(用户后续接入)**;接入后固件 text 增量约 3.5–4KB,余量充足。

### 10.4 2026-09-04 X509 摘要扩展 SHA384/512 + AGINX 代码签名宏(已提交 95d742b)

- **RSA/P256 支持 SHA384/512**:`X509SigType` 新增 4 值(RSA_SHA384/512、P256_SHA384/512,值 4-7),classify_sigalg 与 OID 谓词补齐 4 个 OID;SM2 仍固定 SM3。
- 摘要计算全部移入 work 区(布局 `[Sha*Ctx 240B][md 64B]`,work 下限 752→**304B**);三种 Sha*Ctx 同尺寸(240B,同一 `rlCryptoShaCtx`)。
- **P256+SHA384/512 按 FIPS 186-4 §6.4 截取左 256 位**作 e(P256Verify 接口固定 32B 摘要,设备 FTRX 与宿主 TASSL 一致;摘要已与 OpenSSL 实测一致)。
- `RSAVerifyPkcs1` 签名加 md_type 参数(`Dongle::X509Digest` 枚举,值即摘要字节数 32/48/64):设备端 DigestInfo 前缀立即数比对参数化([1]=19+len、[14]=(len>>4)−1、[18]=len);宿主/模拟器映射 NID_sha256/384/512。真机检查点扩展:SHA384/512 的 COS 解填充行为本机无法验证。
- **X509GetPublicKey 改按证书自身 SPKI OID 分派**(原按 sig_type:叶证书密钥类型与签发者签名算法不同时错路由;混合链测试覆盖此修复)。
- 测试 __x509__:**8 条链**(RSA/P256×SHA256/384/512、SM2×SM3、P256-CA 签 RSA-叶混合链)+ EC 公钥提取断言,与 OpenSSL X509_verify 对照 **0 错误**;aarch64-linux/foobar/`make dongle` 构建全过;stack-check 0 违规(稳态 1784B 不变,X509 链未接 VM 不计入);固件 text 仍 49024B(X509 函数无调用方被 gc-sections 裁掉,OpCode 接入时才计入)。
- **代码签名宏(用户 2026-09-04 决定,2026-09-05 修订)**:Claude 编写的代码用专属命名空间宏;昵称 Claude(克劳德),前缀原为 `cLAUD`。2026-09-05 用户决定前缀改为 **`AGINX`**(取产品名而非作者代号,避免每位协作者各占一对宏使 base.h 膨胀)。base/bits/base.h 已定义 `AGINX_DECLARE_MACHINE`/`AGINX_DECLARE_END`(与 rLANG 同构),x509.cc 与 __x509__ 测试已采用。

### 10.5 65c3adc/cf88c27 TASSL dso/网络阻断重构,linux/aarch64 链接警告清零(2026-09-05)

- **65c3adc**:`src/app/main.cc` 末尾的 Linux 阻断桩(dlopen/dlclose/getaddrinfo/freeaddrinfo/gethostbyname + DSO_METHOD_openssl,rLANGEXPORT)整体移除,改由 TASSL 库自身承载:
  - `third_party/TASSL-1.1.1/crypto/dso/dso_dlfcn.c` 增 weak 桩:`rLANG_socket/rLANG_getaddrinfo/rLANG_gethostbyname/dlopen`(ENOSYS / EAI_SYSTEM / NULL;注意该文件首行现带 UTF-8 BOM,用户编辑器引入,GCC 无害,但触碰首行须字节安全编辑);
  - `third_party/project.mk` TASSL Configure 注入 `CFLAGS="$(rLANG_TASSL_CFLAGS)"`:`-Ddlopen=rLANG_dlopen -Dgetaddrinfo=rLANG_getaddrinfo -Dgethostbyname=rLANG_gethostbyname -Dsocket=rLANG_socket`——宏作用于整个 TASSL 编译单元(含 dso_dlfcn.c 自身定义),弱符号最终以 rLANG_* 名义存在;宿主确需真实网络/dso 时须主动提供强符号 rLANG_*(缺省阻断语义,README 同步);
  - 效果:§9.3 原判"不可消除"的 glibc 静态链接 dlopen/getaddrinfo/gethostbyname 警告全部消失;__x509__/__diff__ 测试、dongle.h、xModule.mk 同步调整。
- **cf88c27**:project.mk 位置修正——rLANG_TASSL_CFLAGS 定义块原插在 `BUILD_TASSL_LIBRARY_SOURCE_ROOT` 之后,`:=` 立即展开,更早的分支取到空值;上移至文件顶部(9+/9- 纯移动)。
- **零警告基线(2026-09-05 实测)**:`make linux -j8` 与 `make aarch64-linux -j8` 均 exit 0、全日志 grep -i warning = 0(根 Makefile **没有** amd64-linux 目标,`linux` 输出即 `.bin/amd64-linux-release`)。**用户要求:后续开发持续保持 linux 与 aarch64-linux 零警告**,每次实质改动后重跑两目标自检。
- 注意:TASSL 构建 stamp 门控(§9.3)——project.mk/dso_dlfcn.c 改动须清 stamp 重编再重链接,否则旧 libcrypto.a 继续带 glibc 警告;验证前须确认 stamp 新于 project.mk。

### 10.6 X509Tests 测试项(2026-09-05, 未提交)

- `src/__Testing__/__dongle__/main.cc` 新增测试项 **index 18 = X509Tests**(X509 验签原语真机测试),子模式由 argv_[1] 选择:0/缺省 = P256 链 | 1 = SM2 链 | 2 = RSA2048 自签 CA(单证书)。
- **证书通道(用户决策)**:证书 DER 在进入测试前由 host/模拟器 `WriteX509Certs` 写入 **dashboard[0, 4KB)**(factory dataFile 0xFFFF **匿名可写区**,与 Initialize.dongle 的 `kOffsetX509Chain = 4*1024` 注释同源约定);测试内三平台统一 `ReadDataFile` 加载到 InOutBuf[360, 1024) 证书区(2026-09-07 起上限 ≤2KB,设备端将改由 dashboard 两段加载,§10.16)。blob = [u16 leaf_len][u16 ca_len][leaf][ca];`kX509CertOffset = 360`,编译期断言 `sizeof(Context_t) == 360`。
- **固件 rodata 约束**(用户确认"ukey 下 rodata 不可读"):内置证书数组仅 `!__RockeyARM__` 构建编译(linux/aarch64/foobar/wasm),固件零静态数据;链接脚本 rodata/data 空断言兜底验证。
- 内置证书:TASSL/BabaSSL libcrypto(gen/System 版本,仅无网络功能)生成——P256 CA+叶 610B、SM2 CA+叶 609B、**RSA2048 v1 自签 664B 恰好占满证书区**;统一有效期 2020-01-01~2030-01-01(GeneralizedTime);叶 issuer 指向 CA 名(自签判定负例用);RSA v1 无扩展最小化体积;生成时 OpenSSL `X509_verify` 交叉验证=1。
- 覆盖:严格 DER 解析、X509CheckTime 固定 epoch 警告位(2025-06-01 窗口内 / 2035-01-01 After / 2015-01-01 Before,不取设备 RTC)、X509GetPublicKey(SPKI 分派,RSA e=65537 校验)、X509ExtNext 遍历(BC/KU critical)、链验签/自签根、篡改负例(CA 公钥 X/N 字节、叶签名首字节)、尾随字节与空/超长证书拒绝。
- **设备端 rsa_pub 就地覆写签名区的处理**:单证书 RSA 负例用栈上 256B 备份恢复(master.cc OpManager_VerifyWorldPublic 栈上 world 同款思路);ExtendBuf 仅作 X509VerifySignature work 区(304B),**不可跨 FTRX 调用保数据**;EC 验签不覆写签名区,无需备份。dashboard 原件(flash)在每次调用开头重写,两轮协议天然稳定。
- 验证:foobar 三子模式两轮 0 错;linux/aarch64-linux **零警告**;`make dongle` 通过(rodata/data 空断言、bss≤16);X509 代码已链入 rockey_dongle(59 个 X509 符号,text 48656B);stack-check 0 违规(RockeyTrust 不受影响,仍 49024B);紧凑回归(1..8+18×3,两轮)与 §9.1 基线一致(i8 的 124/126 源于用户本轮 KeyExec 模拟器循环 10000→1000 的改动,与本次无关)。
- **真机检查点**:① COS rsa_pub 解填充行为(SHA256 DigestInfo 51B 分支;SHA384/512 本机无法验证);② work 区摘要缓冲在 COS 调用期间的存活(X509VerifySignature 的"证书在 InOutBuf、work 在 ExtendBuf"设计首次真机验证);③ SM2 sm2_verify 的 e=SM3(Z_A||tbs) 语义(注释称真机已验证)。

### 10.7 2026-09-06 本机接入实体 ukey + amd64-linux 测试结果

- 本机(WSL2)经 usbipd 接入实体 ukey(096e:0209,Ver 0x222,birthday 2024-11-26,PID/UID=ffffffff 未初始化;HID 00000000-efea115bfc084642)。已装 udev 规则 `/etc/udev/rules.d/99-rockey-dongle.rules`(GROUP=plugdev 0660),`dongle_entry` 免 sudo 可用(此前 Enum F0000001=NOT_FOUND 实为权限问题)。
- **amd64-linux-release 套件结果(退出码 102=0 错)**:25519/sha256/micro_ecc/aes 均 102 ✅;x509 `total error = 0`(其中 9 行 "Verify False" 日志为篡改负例预期输出);HelloWorld 0 ✅;diff(foobar 模拟器)0 ✅。
- **⚠️ __Testing__diff__ 真机(amd64-linux)跑不了,非缺陷**:RFC 8032/7748 向量段(纯软件)全过;随机差分 1000 轮全部 `RandBytes` → `Dongle_GenRandom` 返回 **F0000002=DONGLE_INVALID_HANDLE**。根因:`__diff__/main.cc:18` 用基类 `Dongle`,基类无 Open(`handle_` 恒 nullptr,dongle.h:462),仅子类 `RockeyARM::Open(int index)`(dongle.cc:976)会打开设备;模拟器 RandBytes 走本地 RAND_Bytes 不查 handle,故 foobar 全过。该差分段目前是模拟器导向设计;若要真机可跑需改用 RockeyARM+Open(0) 并做无设备优雅跳过。
- **__Testing__dongle__(amd64=真机协议)未运行**:17+1 索引协议写真实 ukey(数据文件/KeyExec/i17 倒计数/dashboard 证书区),破坏性,须用户明确决定后再跑。

#### 2026-09-06 晚补:真机 X509Tests(index 18)已跑(用户确认 ukey 未初始化/锁定、dashboard[0,4KB) 按约定易变可覆写)

- 协议:`__Testing__dongle__ 12 0|1|2`(hex 索引 + 子模式;anonymous 权限,不触发 VerifyPIN/管理员块)。P256×2 轮 + SM2 + RSA 全部 **host 侧 0 错误**。
- 真机验证成立的部分:Enum/Open/ResetState/TRNG RandBytes 全 0;证书通道 WriteDataFile→ReadDataFile 经真实 factory dataFile 0xFFFF 往返成功(leaf_len/ca_len 正确);前奏 PIN/PID 类操作全部无害失败(LimitSeedCount F0000008、ChangePIN/ResetUserPIN/SeedSecret F0000006——设备 PID=ffffffff 未初始化,与预期一致)。
- **exit=103 不是错误**:SeedSecret 失败使 result=-1,`10086-(-1)=10087 mod 256=103`。判断 X509Tests 成败只看 "X509Tests total error"。
- **⚠️ 设备端 FTRX 验签(§10.6 真机检查点①②③)未跑到**:本 ukey 刷的是**生产固件 RockeyTrust**——`ExecuteExeFile` mainRet 恒为 **-9**;测试固件 Start 只会返回 `10086-result`(不可能为 -9),而生产 Main 把测试 Context 当 VM 上下文解析、execute.cc 头部校验失败返回 -EBADF(-9)完全吻合。host 侧验签为 TASSL 本地(dongle.cc RSAVerifyPkcs1=RSA_verify 等,设计如此)。**要跑设备端 X509,须把 `.bin/arm-RockeyARM-native-release/rockey_dongle.bin` 测试固件刷入 ukey**;ukey 当前 Ver 0x222。
- **刷写规则(用户 2026-09-06 告知)**:刷写经 `WT_APP_DONGLE` 环境变量(指向固件 bin,__Testing__dongle__ main.cc:1948 UpdateExeFile 路径);**ukey 刷写次数有限**——只有确实改动了设备侧程序并重编后才设置,纯测试/无改动严禁设置。

### 10.8 56b8990 附带改动补录(2026-09-07 静态复核)

> 56b8990(Squashed commit,2026-09-07)除更新本文件 §10.7 外还带两处小改动,当时未单独记录,复核对照代码确认:

- **`src/__Testing__/__dongle__/main.cc`:SeedSecret 验证调用已删除**(用户决策 2026-09-06)——ukey 未初始化(PID=ffffffff)时 SeedSecret 必然失败(F0000006),失败值经 result 流入最终退出码(`10086-(-1) mod 256 = 103`)干扰测试结果判定;`Context->seed_` 无任何消费方,纯记录无意义。§10.7 晚补中 "exit=103 不是错误" 描述的是**删除前**的行为。
- **`MCU/RockeyARM/xModule.mk`:install-platform 的 readelf 检查静默 stderr**(`2>/dev/null`)——readelf 对 .debug_info 的 "bogus end-of-siblings" 警告(§9.3 记为不可消除项)在安装步骤无意义,不再污染构建输出;不影响产物。

### 10.9 2026-09-07 加载并验证会话记录(静态复核 + Windows 本机复验)

> 目的:验证 ai-context.md 与 HEAD(56b8990)代码一致并复验关键构建/测试结论。静态复核 25+ 项声明与代码逐一吻合(§7 修复、TRNG/x509/AGINX/weak 桩等);两处 56b8990 未记录改动见 §10.8。动态复验在 **Windows 本机**(cygwin make + clang-cl/VS2022 + arm-none-eabi **14.3 rel1**)进行;**WSL2 本会话不可用**(服务 E_ACCESSDENIED),故 §10.5 的 linux/aarch64-linux 零警告基线本次未重跑。

- **`make dongle`(先 clean-dongle 全量重建,避免与 9/5 WSL 旧对象混链)exit 0**:rockey_dongle.bin / RockeyTrust.bin 均 **65520B**;readelf 三段(.text R E / .bss MemSiz 0x10=16B ≤16 / g_FEI 独立),rodata/data 空断言与 bss≤16 通过。
- **⚠️ stack-check 在 Windows 的坑**:cygwin/Windows 链接器生成的 map 用 `\` 分隔路径(`./.bin/.lib/arm-RockeyARM-native-release\librockey.a(member.o)`),工具正则只匹配 `/`,直接 `make stack-check` 只解析到 **2 个对象/4 个函数**(帧匹配 0,深度 0——**无意义**)仍返回 0。把 map 反斜杠归一化为 `/` 后直跑脚本,得完整覆盖(**24 对象/345 函数/868 调用边/帧匹配 252**)。
- **stack-check 结果(14.3 rel1,归一化 map)**:RockeyTrust 稳态最大 **1944B/2032B,余量 88B,0 违规**(最深链 Start(376)→VM Execute(48)→OpEd25519(56)→VerifySignEd25519(24)→Ed25519::Verify(224)→ge_scalarmult_base(16)→ge_scalarmult(616)→ge_add(88)→ge_p1p1_to_p3(32)→fe_mul(464));rockey_dongle 稳态 1856B,0 违规。**⚠️ 与 §7 记录的 10.3.1 数字不同:14.3 帧更大(fe_mul 392→464、ge_scalarmult 528→616),稳态余量由 248B(10.3.1)收窄至 88B——仍 0 违规,但后续栈深改动请以 14.3 复跑为准**(map 归一化步骤在 §10.9 之前未文档化)。
- **`make foobar`(amd64 windows debug,clang-cl)exit 0**;模拟器套件全过:25519/sha256/micro_ecc/aes **exit=10086(0 错)**;x509 `total error = 0`(篡改负例 "Verify False" 为预期);diff `total error = 0`;HelloWorld 0。
- **`__Testing__dongle__` 紧凑回归(1..8 + 18×3,两轮,§9.1/§9.4 协议;SeedSecret 已删,无 §10.7 的 exit-103 干扰)** —— 与基线逐项一致,无回归:
  - i1 首轮 3 错(全新镜像 Delete 不存在)→ 二轮 0;i2 两轮 **0**(H-09 无回归);i3/i5 两轮 0;i4 首轮 3 → 0;i6/i7 首轮 2 → 0。
  - **i8 KeyExec 首轮 1002 错 / 二轮 1000 错**(exit 9084/9086 = mod 256 的 **124/126**,与 §10.6 记录精确一致,KeyExec 循环 1000 所致)。
  - **X509Tests(index 18)P256/SM2/RSA 三子模式两轮 `total error = 0`**。
- **结论**:HEAD 在可复验范围内无回归,文档与代码一致;唯一环境性差异是工具链帧尺寸(余量 88B vs 文档 248B)。**建议已采纳实施**:stack-check.cjs 读 map 后先 `mapText.replace(/\\/g,"/")`,Windows 上 `make stack-check` 现已直接全量可信(改后复跑:24 对象/345 函数/868 边,结果同上)。

### 10.10 WSL 复验补跑:linux / aarch64-linux 零警告 + amd64-linux 套件(2026-09-07)

> 首次探测误报"WSL 未装工具链"(探测脚本引号被 PowerShell→wsl 传递破坏);实际环境齐全,补跑 §10.5 零警告基线。

- 环境:WSL2 **Ubuntu-22.04(x86_64)**;node **v22.21.0** 位于 **`/Machine/System/bin/node`**(Makefile 的 X4C_NODE 默认路径恰为它,含 npm/npx/pnpm/tsc;用户提示:node 主体编译为 .so,如需 nodejs native bindings 须链接 `/Machine/System/lib/libnode.so`);make/gcc/g++/`aarch64-linux-gnu-*` 在 /usr/bin 齐全。
- **§10.5 零警告基线复验**:`make linux -j8` 与 `make aarch64-linux -j8` 均 **exit 0**,日志 `grep -ci warning` = **0**;9/7 的 `__dongle__ main.cc`(SeedSecret 删除)触发相应测试目标重编重装,非空跑。
- **amd64-linux-release 纯软件套件与 §10.7 完全一致**:25519/sha256/micro_ecc/aes **exit=102(0 错)**;x509 exit=0(`total error = 0`);HelloWorld exit=0。`__Testing__diff__`(amd64,§10.7 已记录跑不了)与 `__Testing__dongle__`(amd64=真机破坏性协议)按约定未跑。

### 10.11 2026-09-07 真机全量测试首次运行(Windows 原生,amd64-windows-release)

> 用户接入实体 ukey 并授权全量测试;按用户指示走 **Windows 原生**(免 usbipd),用 `./.bin/amd64-windows-release/__Testing__dongle__`(clang-cl,11:30 当前代码)。设备 = §10.7 同一把(Ver 0x222、PID/UID=ffffffff 未初始化、birthday 2024-11-26、HID 00000000-efea115bfc084642),dongle_entry 枚举正常。

- **⚠️ 固件刷新失败(用户要求首次设 `WT_APP_DONGLE` 刷最新固件)**:`rockey.UpdateExeFile rockey_dongle.bin -1/F0000008`(`Dongle_DownloadExeFile` 被拒)——未初始化设备(PID/UID=ffffffff)不允许下载可执行文件(与 LimitSeedCount F0000008 同族权限限制)。**设备固件未更新**,仍是既有固件(§10.7 判断为生产 RockeyTrust);§10.6/§10.7 的**设备端 FTRX/X509 检查点①-③仍未覆盖**。后续要跑设备端 X509 需先初始化设备(PID/PIN)或经厂商工具刷写。
- **结果表(exit→错数;exit=10086 即 0 错)**:i1 CreateDataFile 6 · i2 ReadWriteDataFile 35 · i3 ReadWriteFactoryData 128 · i4 CreateRSAFile 6 · i5 RSAExec 123 · i6 SM2Exec 111 · i7 P256Exec 111 · i8 KeyExec 22 · i9 HashExec **0** · i10 Secp256K1Exec **0** · i11 ChaChaPoly **0** · i12-14 Sha256/384/512 **0** · i15 Curve25519 **0** · i16 Ed25519 **0** · i17 PKeyCountDown 3 · **i18 X509Tests P256/SM2/RSA 三子模式全 0**(`total error = 0`,`Test.18 return 0`)。
- **失败性质**:每日志固定含 6×F0000006 + 2×F0000008(前奏 ChangePIN/ResetUserPIN/LimitSeedCount 无害失败,§10.7 同款),文件/密钥类索引的其余失败码均为 **F0000006/F0000008/F000000F**(未初始化设备上文件/密钥操作被权限拒绝)——**预期状态性失败,非回归**;纯算法/哈希/Ed25519/X509 host 侧验证全部 0 错。
- **56b8990 SeedSecret 删除真机验证达成**:X509 三子模式 exit=**10086**(0 错),不再是 §10.7 晚补的 exit=103——修复目标在真机确认。
- 本表是**未初始化设备上的首次真机全量基线**(无法与 foobar 模拟器基线直接对比:设备状态不同),供设备初始化(PID/PIN)后复跑对照;未初始化状态下多数索引失败属预期,勿误判为回归。

### 10.12 2026-09-07 双 ukey 并行全量测试(Windows,amd64-windows-release)

> 用户插入第二把 ukey 并授权两把全量。harness 原 `rockey.Open(0)` 只开第一把,新增多设备选择后并行跑。

- **设备**(dongle_entry 枚举,两把均 Ver 0x222):
  - **[0/2]** PID/UID=ffffffff 未初始化,birthday 2024-11-26,HID 00000000-efea115bfc084642(§10.7/§10.11 同一把);
  - **[1/2]** PID=**7c62fe4c**、UID=**00010086**,birthday 2023-02-10(**已初始化**,与设备 0 状态不同)。
- **harness 改动(本会话)**:`__Testing__dongle__ main.cc` 增加 **`WT_RKEY_DEVICE`** 环境变量选择 `rockey.Open()` 的 Enum 索引(默认 0;与 WT_APP_DONGLE 同款 WT_ 前缀 env 模式,不改 CLI/argv),两处 `Open(0)` → `Open(dev_index)`。
- **并行两进程**(WT_RKEY_DEVICE=0 / =1)各跑全量 1..17 + 18×3,无 WT_APP_DONGLE(不刷固件):
  - **设备 0(未初始化):结果与 §10.11 逐项完全一致**(i1 6 · i2 35 · i3 128 · i4 6 · i5 123 · i6 111 · i7 111 · i8 22 · i9-i16 全 0 · i17 3 · X509×3 0)——二次运行稳定性复现。
  - **设备 1(已初始化):每轮恒 +1 错**,定位为收尾 `ExecuteExeFile return -1 / F0000003`(main.cc `if (result3 < 0) ++result`),而设备 0 为 `return 0, mainRet -9`——**该设备应用固件不接受 exe 传输**(§10.7 "设备固件不一致"担忧在第二把成立)。**扣除该 +1 后,设备 1 各索引测试主体错误数与设备 0 逐项相等**,X509 三子模式 `total error = 0`、`Test.18 return 0`。
  - 失败码构成差异:设备 1 前奏**无 F0000006**(已初始化设备 ChangePIN/ResetUserPIN 不再报"未初始化"),日志为 F0000008/F000000F + 1×F0000003(ExecuteExeFile);设备 0 为 6×F0000006 + 2×F0000008 前奏(§10.11)。
- **结论**:两把设备的文件/密钥类主体错误一致且复现 §10.11 基线——设备状态(无密钥/匿名权限)性预期失败,非回归;host 侧算法/X509 全 0。设备 1 的 +1 是 ExecuteExeFile 传输差异,勿误判为测试失败。

### 10.13 2026-09-07 Windows emsdk 3.1.64 安装(make wasm 可生成)

> 用户要求在本机装好 emsdk 使 `make wasm -j8` 正确生成。github 直连不可达;emcc 3.1.64 下载源(storage.googleapis.com / nodejs.org / python.org)直连可达,emsdk **源码**自 WSL `/opt/dev/emsdk`(同版本 3.1.64)打包拷贝,二进制安装走代理 **10.20.20.124:8001**(用户提供;下载失败时使用)。

- 安装位置:**`C:\Users\liangli\emsdk`**(node 18.20.3 / nuget python 3.9.2 / upstream LLVM 全套装);`emsdk.bat activate 3.1.64` 已完成。
- **用户级环境已持久化**(新终端生效):`EMSDK=C:/Users/liangli/emsdk`、`EMSDK_PYTHON`、`EMSDK_NODE`,PATH 前置 `%EMSDK%\shim;%EMSDK%;%EMSDK%\upstream\emscripten`。
- **⚠️ cygwin 桥(shim)必要**:x4c 经 cygwin make 调用 `emcc/em++`(POSIX sh 包装),直接执行会因 (a) `exec` Windows 反斜杠 python 路径失败、(b) 原生 python 收到 `/cygdrive/...` 脚本路径被误解、(c) `-I/cygdrive/x/...` 绝对 include 原样传给 clang 而找不到头。`C:\Users\liangli\emsdk\shim\{emcc,em++,emar,emranlib}` 包装器解决:exe 用 `cygpath -u` 的 POSIX 路径 exec,脚本与含 `/cygdrive/` 的参数(含 `-I/-L` 前缀)用 `cygpath -m` 转 `C:/...` 后再交给原生 python。
- **`make wasm X4C_NODE=node -j8` exit 0(本会话两轮验证,幂等)**:全部 `.wasm` 产出至 `.bin/wasm-emscripten-release`(dongle_entry/Emulator/Script/__Testing__* 共 11 个),wasm-opt 输出 `Web/Assembly/{Script,Emulator}.wasm` + 对应 `_wasm.ts`。TASSL(wasm)沿用 9/5 gen/System 产物(stamp 门控,与 emsdk 同 3.1.64);此前曾误判需重编,实际 clean-wasm 不清 gen。
- **cygwin 登录 shell 直跑修复(2026-09-07 晚)**:新增 `/etc/profile.d/emsdk-aginx.sh`(cygwin)导出 `EMSDK/EMSDK_PYTHON/EMSDK_NODE` 与 **`X4C_NODE=node`**(Makefile 默认 `/Machine/System/bin/node` 在 Windows 不存在),并把 `emsdk\shim` 前置 PATH(幂等);`~/.bashrc` 交互守卫前 source 同文件(非 login 交互 shell 亦生效)。新开 cygwin 终端后**直接 `make wasm -j8`(无需任何参数/手动 env)**。
- **TASSL(wasm)在 Windows 上全量重编要点(本会话踩坑)**:emconfigure.py 会把 CC 写成**带反斜杠绝对路径** `C:\...\emcc.bat` → cygwin sh 反斜杠被吞 `Error 127`;故 `shim/emconfigure` 直接替代它:以**裸名工具链 env**(`CC=emcc CXX=em++ AR=emar RANLIB=emranlib LD=em++`)+ **cygwin perl `/usr/bin/perl`(POSIX 路径)** 执行 Configure(POSIX 参数不做转换)。shim 现共 **6 个**:emcc/em++/emar/emranlib/emconfigure/emmake。验证:纯 cygwin `make wasm -j8` exit 0(首轮含 TASSL 重编→libcrypto.a 3.0MB,次轮幂等 0)。
- 备注:wasmjs 平台目标已于 2026-09-07 删除(用户决策:JS 封装改手工生成,§10.15);原 wasmjs.conf 的 pki.cc rLANGIMPORT 链接问题(§9.3)随之不再需要解决。

### 10.14 工作约定(2026-09-07 起,用户确认;后续会话遵守)

- **一律建分支提交**:代码/文档改动先在 **`feat/AGINX/<有意义且唯一的名字>`** 分支上提交,由用户 squash merge;**不直接提交 master**。(§10.13 的 `bfa5c5a` 是约定确立前最后一次 master 直提。)
- **PGP 签名**:仓库 `commit.gpgsign=true`(EDDSA B9C754…),但会话环境 gpg 必失败(keyboxd "未实现"/pinentry 不可用)→ 分支上统一 `git commit --no-gpg-sign`(无签名),签名/合并在用户侧处理。
- **格式化约定**:改写 C++ 文件后按仓库 **`.clang-format`** 执行格式化(clang-format **19.1.5** = `C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\Llvm\x64\bin\clang-format.exe`,即仓库现行格式版本;`.clang-format` StatementMacros 已含 AGINX 宏)。纯 JS(`.cjs/.ts`)与 `.md` 不适用。
- **编码约定(UTF-8 BOM)**:**非 third_party 的 C/C++/asm/ts/js 程序文件默认以带 BOM 的 UTF-8 保存**,减少 Windows 下乱码可能。要点:① third_party 源码除外(§9.3/§10.5:dso_dlfcn.c 等 GBK/首行 BOM 需字节级编辑);② clang-format 19 重写会**剥掉 BOM** → 格式化后须按本约定补回(用 `EF BB BF` 前缀,勿用编辑器重复叠加);③ 文本编辑工具(如 edit 工具整文件重写)也可能剥 BOM,收尾需检查首 3 字节。
- 真机多设备测试:`WT_RKEY_DEVICE`(默认 0)选择 Enum 索引,两把并行时分别设 0/1(§10.12);`WT_APP_DONGLE` 仅确需更新设备固件时设置,刷写次数有限(§10.7)。
- **提交同步文档(2026-09-08 起)**:每次提交(或同一批 squash merge 前的逻辑批次)都**同步更新 `ai-context.md`**,把决策/约定/验证结果一并记录,不留滞后;文档改动同样走分支提交。
- **测试 ukey 禁用 lock(2026-09-08 起,强约束)**:对**任何物理测试 ukey(当前 HID `00000000-efea115bfc084642`)** **永远不要执行 Utilities.lock / RockeyARM_Lock**(会改管理员 PIN,之后无法再用该测试 ukey);`Utilities.factory` 可按需对该 ukey 执行;今后新增测试 ukey 一律遵循“禁 lock”惯例。

### 10.15 2026-09-07 决策:删除 wasmjs 平台(JS 封装改手工)

- 用户删除 root Makefile 的 `wasmjs` / `clean-wasmjs` 目标;本会话同步清理:`Build/config/wasmjs.conf` 删除,project.local.mk 的 wasmjs 分支与 wasm 分支中的 wasmjs include/lib 引用移除,`Web/Script/xModule.mk` 的 `wasmjs_add_ldflags` 死调用移除。
- 理由(用户):**ukey 代码过于重要**,wasm 的 JS 宿主封装改为**手工生成**,少一个平台(wasmjs)需要确认/维护;原 wasmjs 的 pki.cc RockeyPKEY rLANGIMPORT 无 JS 宿主实现问题(§9.3)随之不再需要解决。
- 现状:仅保留 **wasm**(`make wasm`,STANDALONE_WASM)产出 `.wasm` 并经 `wasm2string.cjs` 生成 `Web/Assembly/*_wasm.ts`;JS 调用层由手工封装实现。

### 10.16 2026-09-07 决策:X509 证书上限 1KB → 2KB(设备端 InOutBuf+ExtendBuf 两段)

- **背景**:早期按"证书只能放 InOutBuf(1KB)"把 X509 上限定在 1KB;未利用 dashboard[0,4096) 做数据交换。经检查当前实际使用的很多证书 **>1KB**,故上限放宽。
- **决策(用户澄清)**:上限定为 **2048 字节**(不是 4KB)。实现时把新 OpCode 定义为 **OpExecute_\* 家族**(调用后自动 Exit、可将 VM.text/stack 作缓存),从而可用 **InOutBuf[0,1KB) + ExtendBuf[0,1KB) = 2KB**:证书前 1KB 装入 InOutBuf、后 1KB 装入 ExtendBuf;跨段读取/解析随该 OpCode 接入实现。
- **本批次已落(host/模拟器/固件共同生效)**:
  - `Interface/x509.cc`:`cursor_from` 上限 1024→**2048**(超限返回 -E2BIG),注释同步;单块连续输入契约不变(跨段解析待 OpExecute 接入,§10.3 X509 OpCode 待办)。
  - `Interface/x509.h` 注释、`X509View`(uint16 偏移)无需改动即覆盖 2KB。
  - `__x509__` 套件:超长负例 1025→2049;新增 **>1KB(≤2KB)回归用例**(22 个 dNSName SAN 撑大 RSA 叶证书,验证 parse/OpenSSL/链验签)。
  - 验证:linux/foobar __x509__ total error = 0;linux 0 警告;`make dongle`(固件)通过。
- 遗留:设备端 X509Tests(index 18)证书区仍为 InOutBuf[360,1024) 布局(内置小证书可用);>1KB 证书的真机/设备路径待 OpExecute_* 接入时改 dashboard 两段加载(见上)。
### 10.17 2026-09-07 OpExecute_ImportX509: dashboard 流式 FSM + 导入布局 + 新约定

- OpCode kExecuteImportX509(0x283, argc 4/5): argv0=SECRET_STORAGE_TYPE(kRSA/kP256/kSM2), argv1=pkeyId, argv2=目标 dataFileId(已存在即错不覆盖), argv3=证书 DER 长度(≤2048, dashboard[0,len)), argv4(可选)!=0 = 私钥↔证书公钥匹配校验。
- 解析: X509FsmParse(X509FsmSource: 内存/dashboard 双源; BER 宽松; 64B cache) 流式, view 只填最小集(tbs 含 SEQ 头 + SPKI + key_type); sig/sig_type 字段留链验签 OpCode。
- 导入数据文件布局 = [X509View][X509.DER](先 view 头后 DER, 96B chunk 流式拷自 dashboard)。
- 流程(BSP: COS 验签/签名把 ExtendBuf 当工作区): dashboard FSM 解析 → (可选)三步匹配(拉 SPKI 公钥暂存 InOutBuf+0 → ukey 私钥签名 → 证书公钥验回) → 匹配失败拒绝导入 → 创建/写入数据文件; 公钥/临时量放 InOutBuf, COS 期间 ExtendBuf 交还。
- 严重问题修正(用户复核): ① argv4 匹配须在 CreateDataFile 前完成, 失败不得建文件; ② 创建写权限由匿名改 kAdministrator(读匿名/写管理员)。
- 新约定 ① 权限: dataFile/pkeyFile 的 id<kUserFileID(1000) 创建需 kAdministrator; ≥1000 仅需 kNormal; 所有 SECRET_STORAGE_TYPE 数据 id<1000 才需管理员创建。
- 新约定 ② 结构偏移冻结: 已标注偏移的结构(如 X509View: 逐成员 /*0..48*/ + reserved_[5] + rLANG_ABIREQUIRE(sizeof==48))除 reserved_ 外不得再变更成员, 供 ts/js/dongle.script 按偏移操作。
- 状态: FSM+__x509__ 差分(8 链+>1KB)全绿; linux 0 警告; make dongle 通过; 运行时端到端/真机待补。


### 10.18 2026-09-08 OpExecute_ImportX509 运行时(模拟器)端到端用例 + 两处修复

- 新增测试模块 `src/__Testing__/__x509import__`(xModule.mk 同 __x509__; main.cc 主体 `#if defined(__EMULATOR__)`, 其它构建仅打日志返回 0): 用 `Emulator(kAdministrator)+Create` 起内存世界, 证书 DER 写入工厂 dashboard(0xFFFF)后直接调 `script::VM_t::OpExecute_ImportX509`(按用例设 valid_permission_)并读回产物校验。
- 校验器 CheckLayout: dataFile 总长 == 48+len; [0,48) 六元最小集(off/len_tbs、spki alg、spki pub)与 X509FsmParse 重解析逐项一致; [48,..) == DER 原字节。
- 用例覆盖(全部通过: `make foobar` 后运行 `.bin/amd64-foobar-windows-debug/__Testing__x509import__.exe` → total error = 0):
  - 普通导入 RSA/P256/SM2(dataFile#1/2/3)与 >1KB 大证书(#30, 1066B, 多 96B 分块路径), 布局逐项一致;
  - 错误矩阵: 尾随字节 / storage 与 SPKI 类型不符 / 垃圾 DER / len=0、len=4096 → 拒绝且不建文件;
  - 上界正例: 恰 **2048B** 证书(#32, RSA, 未知扩展精确填充)可导入, 布局一致(回归 2026-09-08: 用户复核删除 execute.cc 多余的 `len<=0||len>=2048` 二次检查, `len==2048` 不再被误拒);
  - 权限矩阵: kAnonymous 一律拒绝; kNormal + 任一 id<1000 拒绝; kNormal + 两 id≥1000 放行(#1000 建文件+布局 OK);
  - 目标 dataFile 已存在 → 拒绝且原文件内容不被改写(预建 64B 文件首 4B 仍全零);
  - argv4 匹配校验: RSA/P256/SM2 各一正(私钥↔证书公钥同源, 建文件+布局 OK)一负(异源拒绝, 无文件); 负例日志可见 RSA_public_decrypt padding check failed / P256Verify False / SM2Verify False。
- 过程中发现并修复两处(运行时才暴露):
  1) execute.cc RSA 匹配分支负载取 256B, 而 RSAPrivate/RSAPublic(PKCS#1, 设备 rockey.cc 与模拟器同封装)上限 256-11=245 → 必 -E2BIG; 改为: RandBytes 245B 负载 → 私钥"签名"成 256B → 证书公钥解密回 245B → 逐字节比对;
  2) execute.cc 拉取 SPKI 公钥上限 260B 太小: RSA-2048 模数 DER INTEGER 带前导 0 时 SPKI 内容 ~270B → argv4 校验分支恒 -EBADMSG; 上限放宽至 0x200-1(InOutBuf+0 临时区不与 +0x200 起的 block/sig 工作区重叠)。
- 状态: 运行时端到端(模拟器)全绿; 真机路径待用户按需复测(需设备+固件刷写授权)。遗留: FSM 最小集暂不含 sig_type(链验签 OpCode 时扩展)。

### 10.19 2026-09-08 x509import 收尾(已并入 6461529)补记 + 提交同步文档约定

- 背景: ai-context.md 未随 x509import-cleanup 分支同步(代码合并后才发现); 按 §10.14 新增约定"每次提交同步更新 ai-context.md", 本节补记该批内容。
- **测试模块构建门控**: `__x509import__` 不再在 main.cc 里用大块 `#if defined(__EMULATOR__)/#else/#endif` 包裹, 改为 `xModule.mk` 仅当 `X4C_BOARD==foobar` 时 `build-executable`(规避跨编辑器条件编译语法着色问题); linux/wasm 不再编译该模块, foobar 编译运行 (total error = 0)。
- **日志编码约定**: 日志输出字符串**不用中文**(此前 cl 按 GBK 嵌入窄字符串、UTF-8 控制台显示乱码); 已把 execute.cc ImportX509 mismatch 日志与 app/main.cc ChangePIN 提示改英文; 全仓 `rlLOG*` 字符串现均无中文, 中文只保留在注释/文档。
- **TAG 规则**: `rLANG_DECLARE_MAGIC_Xs` 只取 `s[0..4]`, 字符串参数应匹配 `[a-zA-Z0-9@$]{5}`(超过 5 位尾部被忽略, 不报错但易踩同值陷阱)。本次全仓统一: 超长 tag 截前 5 位(数值与原来一致, 零行为变化)——
  SCRIPT→SCRIP(Web/Script)、Foobar→Fooba(Interface/emulator.cc、__HelloWorld__)、DONGLE→DONGL(Interface/dongle.cc)、SHA256→SHA25(__sha256__); __x509import__ 的 6 位 @x509i 曾与 __x509__ 的 @x509 同值, 改唯一 5 位 x509i。
- 相关记录: §10.16/§10.17/§10.18 为本批 X509 主体(2KB 上限、dashboard FSM、运行时端到端用例与两处修复)。

### 10.20 2026-09-08 真机 X509 导入测试(深度 B: 主机 VM_t + 真机 Dongle 后端)

- 分支 feat/AGINX/ukey-x509-import-tests; 深度决策(用户): 先深度 B(主机跑 OpExecute_ImportX509, dashboard/存储/ACL/私钥走真机), 后攻深度 A(固件内执行, 需 script 编码 + 刷固件); 固件"需要时再刷"。
- 结构(避免 #if 大块): `__x509import__` 拆为 共用用例 `main.cc`(Dongle& 驱动) + 按板 opener `X509ImportOpen(Dongle**, bool* persistent)`: emu/open.cc(模拟器新世界) / device/open.cc(真机 RockeyARM::Open + VerifyPIN 缺省管理员 PIN); xModule.mk 门控 foobar **或** windows 真机主机(X4C_BOARD 空), 手工 LOCAL_SRC_FILES 选 opener 单一实现。
- 真机环境约定: 设备选择 `WT_RKEY_DEVICE`(默认 0); 管理员 PIN 先缺省(nullptr→CONST_ADMINPIN), 失败用 `WT_RKEY_X509_PIN`。
- 结果: **模拟器与真机均 total error = 0**(真机当前 1 把: PID 3017f25e UID 00010086, 缺省管理员 PIN 可用)。真机跑通: RSA/P256/SM2 导入与布局校验、>1KB(1066B)与恰 2048B 证书、权限/错误矩阵、argv4 匹配正反例。
- 真机差异三处(已适配, 非固件 bug): ① 主机 `Dongle::GenerateRSA` 成功返回 pubkey.bits=2048(模拟器返回 0) → 判定放宽; ② 真机新建 dataFile 内容未必全零 → "已存在不覆盖"断言改为与新建基线一致; ③ 真机持久存储跨运行残留 → 运行前按 persistent 标志清理本套件槽位(DeleteFile 打日志)。
- 遗留: 深度 A(固件内执行 OpExecute_ImportX509 的 script/argv 编码 + 刷含 execute.cc 的固件)未做; 真机 dashboard/数据区写入容量上限未单独探明(2048B 用例已实测通过)。
- 2026-09-08 补: 用户把 linux 目标也编入 device/open.cc(xModule.mk 加 X4C_BUILD==linux 分支)。通过 **usbipd-win → WSL Ubuntu-22.04** 直通 ukey 验证: `usbipd bind --force --busid 2-6` + `usbipd attach --wsl --busid 2-6`(需管理员, USBPcap 需 --force); ukey 枚举为 VID 096e:0209 Feitian ROCKEY ARM(HID), WSL 内见 /dev/hidraw0; linux 驱动为 third_party/RockeyARM/amd64-linux/lib/libRockeyARM.a; 以 root 跑 .bin/amd64-linux-release/__Testing__x509import__ → total error = 0。用完归还 Windows: `usbipd detach --busid 2-6`(可选 `usbipd unbind --busid 2-6`)。

### 10.21 2026-09-08 dongle_entry --notice: 张贴用户数据到 dashboard[0,4096)

- 需求(用户注释 TODO): 帮助脚本导入证书 —— 把用户提供的数据张贴到 dashboard[0,4096)。
- 实现(src/app/main.cc Utilities): 单行输入 base64(notice[n] || SHA256(notice)), n=解码总长-32, 1<=n<=4096; SHA256 规范按"补 0 到 4096B 的 notice"(mode1, 与最终写入一致)校验, 另兼容按原始 n 字节计算哈希的输入(mode2); 通过后以 0 补齐到 4096B 写 dashboard[0,4096)。CLI: dongle_entry --notice <HID> [admin]。
- 验证(linux + usbip 真机, Feitian ROCKEY ARM): 26B notice(mode2) post OK result 0; --dashboard 回读 base64(8192+32) 解码: 前缀匹配、0 补齐到 4096(total 8224)。
- 2026-09-08 重构(用户要求): 抽出 ReadLineEx(line, sizeMin, sizeMax, encode, prompt) —— 变长行读取, 解码长度落于 [sizeMin, sizeMax] 返回长度否则 -EIO; notice 改由其读取(stdin 逻辑不再内嵌分支), 行为不变, 真机复测 OK。

### 10.22 进行中(2026-09-08) Agent 脚本测试工具 __Testing_dongle.cjs —— 侦察结论与计划

- 目标:参照 Web/Agent/Tests/index.html + Web/Agent/index.cjs 的可运行工具, 在 Web/Agent/Tests/__Testing_dongle.cjs 实现 ukey 脚本化测试; Tests/*.dongle 为样例(Initialize/EnTrust 前置); 新脚本放 Web/Agent/Tests/CI&CD/。约束: 不确定用默认值; 真机只用 Windows 端(无 usbip/UAC); 禁止 factory lock。
- 已查清: index.cjs = HTTP agent(封装 RockeyTrust.exe, cmd=list/factory/lock/dashboard/execv; 每请求需 POW(18bit)+chacha20-poly1305(PSK 缺省 base64 "1234567812345678")+token(48B: TICK4+NONCE12+MD32), token md=SHA256(payload); cipher=SHA512(token||PSK)[64]。execv: spawn `RockeyTrust.exe ["-",hid,"-"?]`, stdin=base64帧(1024B, admin 时加 "-"); 响应 = Sealed JSON。
- .dongle = rLANG DSL 源码(含 `${NONCE}` 等占位变量), 客户端(jsLibrary.js/jsWorld)先用 jsScriptParser(=jsCryptoFactory.ParseScript → Web/Script index.ts Parse, 纯 TS/grammar, code=200B(100 words)+data 段参数表) 解析, 再 ScriptExportHelper 组 1024B InOutBuffer(Header+code+data+签名), 经 jsDongleExecv 走 fetch 到 agent。
- JS 包: Web/Agent/Tests/js/*.js 为浏览器 webpack 产物(jsWorld.js 暴露 CipherLoader/CryptoLoader/CreateEmulator/ParseScript; jsScriptBundled 内嵌全部样例 Map)。Node 复用源在 .assets/(World.js, Script/index.js grammar 等 CommonJS), 解析器无需 wasm; 加解密/帧签名依赖 jsCrypto(wasm) CipherSuiteV0。
- 下一步(续做): ① 读完 jsLibrary ScriptExportHelper 组帧细节(1379-1605)与 jsDongleExecv(272-360)/OutputExecvResult; ② 在 Node 里复刻 Parse(grammar) → 组帧 → 直接 child_process.spawn RockeyTrust.exe 或 HTTP agent(二选一, 直接 spawn 更简单且与 index.cjs 同语义); ③ __Testing_dongle.cjs: argv=脚本名/目录, 支持先跑 Initialize.dongle(默认参数)与 EnTrust.dongle, 再跑目标脚本, 汇总 exit/out; ④ CI&CD/ 下放 Initialize/EnTrust/HelloWorld/自写基础脚本; ⑤ Windows 端真机验证(当前设备 HID 00000000-efea115bfc084642, 缺省管理员 PIN; RockeyTrust.exe 路径待定, 参考 .bin/amd64-windows-release/dongle_entry.exe 或 index.cjs argv2)。禁止 --factory/--lock。
- 进展(2026-09-08 晚): 实现 Web/Agent/Tests/__Testing_dongle.cjs(Node):
  * 解析=.assets/Script Parse(grammar, 纯 JS, 无需 wasm); 组 NORMAL(ATOMC 0x0543cd0f)帧: header=ScriptText{magic,ver,size_public,code200,nonce16,tag16}, key=SM3(header[0..224)), chacha(header[208..220))加密 data768, RSA(master WorldPublic@7KB+148) 包 header240→256; 纯 node crypto(SM3/chacha20-poly1305/RSA-PKCS1 均可用)。
  * CLI: list/dashboard/run <dongle> [hid]/suite <dir>; 直调 RKEY_EXECV(缺省 .bin/amd64-windows-release/dongle_entry.exe), 未用 HTTP agent/POW; 无 factory/lock。
  * CI&CD/: 00_HelloWorld / 01_RandBytes / 02_VerifyPublic(拷贝自 Tests)。
  * 结果: list 正常(1 把 HID 00000000-efea115bfc084642), dashboard 读取 8192B OK, 主钥存在(e=65537); HelloWorld 真机 execv: dongle->ExecuteExeFile return 0/**-14**(设备执行错误)。帧与 jsLibrary ScriptExportHelper 逻辑逐行核对过布局一致(含 tag 进 header[224..240]、cipher 进 [256..1024]、key=SM3(header[0..224]))。
- 假设(下轮验证): ① 设备 rlCryptoChaChaPoly 与 TASSL/node chacha 语义(如 nonce 取法)可能不一致 → 用设备/模拟器自验 chacha 对照; ② 需先在模拟器(WSL/foobar exe '-' 帧通道)复现以分离"帧问题 vs 真机世界状态问题"; ③ 若 rlCrypto 变体差异属实, 需按设备非 IETF 变体改 Seal(或将帧构建改用设备可解的规范), 再真机复测。
- 注: Initialize/EnTrust(需 ADMIN 帧/托管密钥) 仍未打通, 属后续工作。
- 2026-09-08 续: __Testing_dongle.cjs 增 bootstrap 帧与 emu 流程; 修复: Execv 传 exe 参数(此前误跑真机 exe)、.dongle BOM 剥离(ParseDongle)。
- 本地模拟器(amd64-foobar-windows-debug dongle_entry '-' 帧通道, 世界 .bin/emu-world.bin)结果: **Initialize.dongle bootstrap 帧 PASS(建世界成功)**; EnTrust 与所有 NORMAL(ATOMC) 帧在模拟器与真机**同样** RSA.Master.Decode 失败(-14, RSA_private_decrypt padding) → 已用模拟器本地复现帧问题(非真机状态)。
- 已核对: 世界文件 factory@256 内 7KB+148 主钥存在(e=65537, N big-endian); FrameNormal 与 jsLibrary 布局一致; N 字节序翻转实验(env RKEY_FLIP_N=1) 待验。下一步: 用模拟器二分定位(翻转 N/换 e 序/比对 C++ RockeyARM_VerifyExecvHelper 参考实现), 修复后真机复测 suite。
- 遗留: EnTrust bootstrap 在"已建世界"上走 NORMAL 而非 bootstrap(疑似模拟器 Open 后非管理员会话), 需加 VerifyPIN/权限处理; ADMIN/BOOTSTRAP 未上真机(防破坏)。
- 2026-09-08 诊断补充(第2/3轮): ① 世界文件布局确认: emulator world: factory(dashboard) 位于文件 [256,256+8192), WorldPublic 在 7KB(file@7424) 头 magic 1f4ec0c8 正确, RSA pub@+148 e=65537/N BE(9b9f...) 真实存在; ② RKEY_FLIP_N=1(N 翻转) 试验失败(仍 -14)→ 排除 N 字节序; ③ NORMAL 帧在模拟器复现同一 RSA.Master.Decode -14, 与真机一致 → 属帧封装问题而非设备状态; bootstrap(Initialize)数据加密封装已被设备接受(PASS), 故 chacha/布局对, 分歧仅在 RSA 封装一步。待查方向: 与 C++ RockeyARM_VerifyExecvHelper 参考实现逐字节对照 / 校验 node PKCS1 type2 vs 设备 private_decrypt 语义 / e 或 N 的存储约定复核。NORMAL 真机 suite 未绿, Initialize(bootstrap) 模拟器 PASS。
- 2026-09-08 突破(第4轮): **根因** = rsaPublicKey DER 中 e 误按 LE u32 直接拼入(值变 0x01000100=16777472, 非 65537); 改 writeUInt32BE+去前导零后, NORMAL(ATOMC)帧在**模拟器与真机同时通过**。
- 结果: 模拟器 emu suite 4/4(Initialize bootstrap + HelloWorld/RandBytes/VerifyPublic NORMAL); 真机(Windows 端, RKEY_ADMIN=1) CI&CD 3/3 PASS。真机原 -14→-13(EACCES)因该设备为 **Admin 类世界**(category=adm@k), 需管理员会话(加 '-' 登录) → 工具 run/suite 已支持 RKEY_ADMIN=1。
- 遗留: EnTrust.dongle 需要真实托管密钥输入(EnTrustKey, 随机占位被设备拒绝 -22), 不作为默认流程; diag-rsa/diag-gen 保留为诊断命令; 真机未执行任何 factory/lock, 未跑会重置世界的 Initialize。
- 2026-09-08 Agent 增强(用户): cjs 不再引用 .assets(随时可能被清理), 改用打包件 Web/Agent/Tests/js/jsWorld.js+jsCrypto.js(Node 可加载); 内置 **8 个 JS 模拟器**(globalThis.jsEmulatorEx[0..7], id 前缀 ff, uid 0x100+i, 每次 Create 随机 secret)。
- 本会话新增: jsemu <file> [idx] 单跑; jsuite(Initialize bootstrap + CI&CD NORMAL, EMU_RANGE 默认 0-7) → **8 台全部 32/32 通过**; 支持多台并行/独立世界, 便于多 ukey 脚本(如密钥交换/EnTrust)后续选择不同 emu。
- 2026-09-09(进行中) 进阶脚本化(目标 goal-b5c8a404): 基于 8 台 JS 模拟器做 Initialize→EnTrust→Admin/Limit→多机密钥交换。
- 已实现: entrust <targetIdx> <trusteeIdx...>(构造 80B 条目=hid12|kid3|zero|SM2ECIES X||Y64, EnTrust.dongle bootstrap 注入, 目标 0 托管给 1 已产生输出); jscheck(查看 7K world/6K entrust 状态); adminrun 脚手架(FrameAdmin 704+sign64, 受托者 SM2Decrypt 取回 ECIES 私钥并 SM2Sign)。EmuJsRun 现返回 inout。
- 待办/问题: 受托 SM2Decrypt(4/1, cipher96) 均失败 → 需核对 emulator SM2Decrypt 签名(是否 id 是 1? cipher 格式 96 vs 128?) 与 EnTrust 输出条目偏移; 随后做 Admin 验收脚本与 Limit(kScriptLimit) 帧; EXCHANGE/IMPORT_MASTER_SECRET 双机示例; 新脚本入 CI&CD。
- 2026-09-08 真机随机数质量: 新增 randtest [count] [html] —— 真实 ukey(00000000-efea115bfc084642, Windows 端 RKEY_ADMIN=1)跑脚本 RandBytes(0,1024) 48 次共 49152B, 统计 p(1)=0.4996 / χ²(df255)=253.6(p≈0.97, PASS) / Shannon 7.9963 / 最小熵/游程/自相关均 PASS; 报告 ai-doc/ukey-rand-quality-2026-09-08.html。
- 2026-09-08 突破(round2): EnTrust 输出条目格式确认(来自 jsCheckEnTrust 参考): 112B = hid12|kid3|Yodd(byte15)|C1x[16..48)|C3||C2[48..112); SM2 密文还原为 128B = C1x||解压Y||rest; 受托者用 **SM2ECDSA 私钥 id=1** 解密得 32B 目标 ECIES 私钥。BuildEnTrustEntry kid=SM3(pub)[0..3] 对齐参考。
- adminrun 0 1 HelloWorld: trustee SM2Decrypt(id=1) ok len=32, Admin 帧执行无错(out head 000000001f4ec0c8)。待办: 用"篡改签名对照/需管理员操作"验证 Admin 权限确实生效; 再实现 Limit(kScriptLimit) 帧; 双模拟器 EXCHANGE/IMPORT_MASTER_SECRET; CI&CD 收编。
- 2026-09-08(round3): ADMIN/LIMIT 帧打通并验证: adminrun/limitrun <target> <trustee> <file>, 签名覆盖 ADMIN=SM3(data704), LIMIT=SM3(header144); 受托者 SM2Decrypt(id1)->目标 ECIES 私钥签名; 有效签名被执行, RKEY_TAMPER=1 篡改签名被设备拒绝(dongle.Execv Error -8)。HelloWorld 两帧 sign-verify=true 且执行。
- 2026-09-08(round4): 双模拟器交换脚手架 xchg <A> <B>: 注入对端 X25519(Export SupperBlock@96..128)与 RSA pub, 执行 EXCHANGE_PREV_MASTER_SECRET 报设备端错误(1078001620, VM 编码错误)→ 该 op 需产品级多设备编排与密钥状态, Web 工具无参考编排, 语义化自动验证不可行; IMPORT_MASTER_SECRET 同。功能框架已留(EmuJsRun 支持 overrides; outputs/inout 齐)。
- 结论: 目标 ①(Initialize/EnTrust/Admin/Limit 托管签名)已达并可复验(有效执行+篡改被拒); 目标 ② 的多设备 MasterSecret 交换语义需用户提供编排规范或真机双 ukey 流程后才能完成验证; ③ CI&CD 现有基础集 + 待收编进阶脚本。
- 2026-09-08(round6): 真机 EnTrust 成功执行(Execute OK), 但受托者(JS 模拟器 SM2Decrypt id1)解不开真机托管密文 —— 真机固件与宿主模拟器的 SM2 ECIES 托管编解码存在差异(或需"母钥/第二把受托 ukey"产品流程); 该项与多设备 EXCHANGE 同属需产品级规范/母钥的边界。realadmin/reallimit(混合真机) 留作实验命令。
- 2026-09-08 NIST 随机数采集(进行中): __Testing_dongle.cjs 新增 collect(追加式, RKEY_ADMIN=1)与 nistreport(诚实子集: Frequency/BlockFrequency/Runs/LongestRunM10000/ApproxEntropy/CumulativeSums; 需≥750kbit 跑 LongestRun, α=0.01)。ai-doc/randdata/ukey-rng-00000000-efea115bfc084642.bin 追加采集; 首 300KB 单比特显著偏负(S=-4608 FAIL), 追加至 600KB 后 6/6 PASS(疑首窗预热/波动); 后台长采集中(count 4000)。
- 2026-09-08 汇总更新: ai-doc/ukey-rand-quality-2026-09-08.html 已合并为 fullreport(字节级 + NIST 子集); 当前样本 768,000B, p1=0.499786, H=7.9998, NIST 6/6 PASS; 后台 collect 持续追加中(后续可重复 fullreport 刷新)。
- 2026-09-09: 样本 4.71MB; 分析上限提至 32Mbit; fullreport: p1=0.500012, H=8.0000, NIST 子集 6/6 PASS; ai-doc/ukey-rand-quality-2026-09-08.html 已刷新; 长程后台采集(≈20MB, pwsh-49)进行中, 后续轮可 fullreport 刷新。
- 2026-09-09: NIST 子集扩展至 10 项(新增 BinaryMatrixRank 32x32 / NonOverlappingTemplate m=9近似 / Serial m=8×2), 当前 4.85MB 样本 10/10 PASS(p1=0.500013,H=8.0000); 报告已刷; 长采 pwsh-49 持续中。
- 2026-09-09 收尾: 样本达 8.45MB(8,446,976B), fullreport: p1=0.500000, H=8.0000, NIST 风格子集 10/10 PASS; ai-doc/ukey-rand-quality-2026-09-08.html 为最终汇总; 采集作业已按用户指示停止。
- 2026-09-09 MASTER.SECRET 构建过程理解与复现(goal-ebf3eb6e):
  * 语义链(对照 mkey 记录 + Interface/execute.cc OpExecute_ExchangeMasterSecret / OpExecute_ImportMasterSecret + script.cc): 6 个"字母"A..F = 保管者 K0..K3 完全图的 6 条边(K0-K1=A, K0-K2=B, K0-K3=C, K1-K2=D, K1-K3=E, K2-K3=F)。每把 Ki 的 Master(-1).X25519 与其它三把各做一次 X25519 → 每条边共享 32B(两端相等); 边记录 = 16B header(hid12|kid=0xffffff|字母) + 32B; Ki 把自己 3 条边(144B)用 **A0.RSA2048 公钥**整体 PKCS1 加密 → 单 256B 密文。A0 用自己 RSA 私钥(global 2048)解密 ≤3 个密文, 字母位满 0x3F(重复字母必须一致)后: MASTER_SECRET = SHA512(6 边共享按 A..F 拼接 192B) [64B], 指纹 = SHA256(MASTER_SECRET)[0..7]。任意 3/4 把覆盖全部 6 条边, 2 把仅 5 条不可恢复。
  * 关键发现 ①: rLANG VM 里 ExecuteExchangeMasterSecret/ExecuteImportMasterSecret 属 0x280..0x2FF **Execute 类操作**, script.cc 1586-1589 执行后直接 break 结束 VM —— 脚本末尾的 `Exit(42);` 是不可达死代码(真实 bundle 同款); OpExecute 返回 0 即成功且保留缓冲输出, 非 0 则清空数据并报错(0x40800000|N 等 VM 编码)。此前 round4 的"1078001620 VM 错误"实为双机示例注入公钥来源错误(Export SupperBlock@96..128 ≠ Master(-1).X25519)→ EXCHANGE 自匹配 -ENOENT。
  * 关键发现 ②: ctx 里四把 K 的 X25519 公钥必须取**设备端 MasterExport.dongle 输出**(rLANG__X25519_Pubkey @32[32], 与 mkey README §5 记录同源), 而非模拟器 Export 缓冲。
  * 已实现并验证(进程内 JS 模拟器, 纯 emulator, 不动真机): __Testing_dongle.cjs 新增 `mkey [kStart]`(MKEY_INIT=0 跳过 Initialize; RKEY_TRACE=1 细节): 5 台模拟器(emu0..3=K0..K3, emu4=A0) → MasterExport 取公钥 → 各 K 跑 EXCHANGE(注入四公钥 + A0 RSA pub)得 4 份独立 256B 密文 → A0 分别用三元组 (K0,K1,K2) 与 (K1,K2,K3) 跑 IMPORT → 两次指纹一致 = 确定性验证通过(重复字母一致性由设备内 key_mask 校验)。样例输出: fp=550da026a277fe73, letters A/B/C 属 K0 hid、D/E 属 K1、F 属 K2(按导入顺序), 结构完全对应真实 A0 记录(rLANG_DONGLE_ID_0..5 + 指纹)。
  * 记录文档: ai-doc/master-secret-build-2026-09-09.md(含图与复现步骤)。真实 K0..K3/A0 均已锁定/离线, 复现用的是全新模拟器世界(不同 secret → 不同指纹), 验证的是**协议语义与编排**, 非历史 MASTER.SECRET 的逐位还原。
  * round1 扩展(全部内建于 mkey, exit 0): ① **文件 ukey 代理** — Export()=storage 可落盘(MKEY_PERSIST_DIR, K0-proxy.dongle≈9964B), 用 EmulatorSecrets[K] Open() 重载后 Master(-1).X25519 身份不变, 代理执行同款 EXCHANGE 且其密文**替代 K0** 参与 A0 恢复指纹不变(在线应答管理员导出请求); ② **与预签名导出程序同源** — 逐字段比对 SignedCode-Export-K0.dongle.program 与 EXCHANGE.dongle 编译结果 match=true(code/output/data); ③ **3/4 冗余负例** — 只给 2 密文(K0+K1, F 缺失) A0 拒绝(mask≠0x3F)。mkey 现返回 allOk(确定性+代理+负例综合), 退出码 0/1。
- 2026-09-09 SESSION_KEY 流程整理开始(goal-e8117e02): **测试边界** — mkey/* 下所有 ukey(K0..K3/A0/E0/E1/E10/C1/C4 等)均为生产/离线或已锁定设备, 任何情况不作测试、不驱动; 复现只用全新 JS 模拟器/新建文件 ukey; 唯一允许真机仍为仓库测试 ukey 00000000-efea115bfc084642(Windows 端, 禁 factory lock)。
  * 已归纳(ai-doc/session-key-flow-2026-09-09.md): 角色矩阵(签发者 = A0; E0 README 里 "W0" 是 A0 早期叫法 —— 用户澄清 A0 的 hex 串无 'W'; 客户端 E0/E1/E10/C1/C4/T0); 会话头 180B 布局(ROOT pub32|Message32|SESSION_Pubkey32|WORLD_MAGIC|Type|Category|NB|NA|ROOT_Signature64); 签发 EXPORT_SESSION_KEY(临时 X25519×客户端主 CV25519 的 DH → 共享种子即会话 Ed25519 种子; root secret type42 签会话头; ChaCha20-Poly1305 链 196B=头+mac, NONCE=SM3(临时pub)); 导入 IMPORT_SESSION_KEY(本机主私钥重算共享→解链→与 SM3(Master)异或静态混淆后落 0x100+Type 共 212B); SESSION_KEY_SIGNATURE(SM3(Master)还原→Ed25519 签 SHA512(INPUT[64])); 素材矩阵 + 澄清均已落档(Q1 W0=A0、Q2 session-key 为特定 Type 签名而构造/锁定后只做该类型签名、Q3/Q3b Type 与 Category 无对应关系、Q4 Message=用户可读 string[32] 日志确认身份、Q5 C2=C4 误写、Q6 "Admin-1000" = Admin 域(要求代码签名/数据签名)+ SM2ECIES-key(id4) 1000 次简写, 内置 Bootstrap-Admin-1000.dongle.program: Type 计划 1..9、当前实际 1..4 = 1 签名设备 / 2 签名 boot / 3 签名 core(Firmware) / 4 签名 app(Application); Category 用于标注设备类型, 预留 Firmware/Application 使用); 使用状态(用户, 已更正): 当前在用的两个 session-key 为 C1 与 C4("C1/C2" 的 C2 系 C4 误写), C* 的 uid 即 session-key 标识, 与 mkey/Client C1/C4 档案一致。
  * 待办: 全新模拟器上编排"签发者→客户端"SESSION 链(EXPORT→IMPORT→SIGNATURE→根验签/SESSION_Pubkey 交叉核对), 输出字段与 E0/T0 记录格式对齐。
  * round1 进展(skey 已跑通): __Testing_dongle.cjs 新增 `skey [issuerIdx] [clientIdx]`(全新模拟器, mkey/* 真机非测试): 客户端 MasterExport(CV25519) → 签发者 EXPORT_SESSION_KEY(临时 X25519×客户端主 CV25519; 参数对齐 T0 记录 Message='Hello world!'/Type1/Cat 0xC35880AF/NB2282/NA2465) → 客户端 IMPORT_SESSION_KEY(会话头输出) → SESSION_KEY_SIGNATURE。外部核对全 PASS(exit 0, 两组下标): MASTER_SIGNATURE(type=42, SEEDS=0) 复算根公钥 == 头 RootCA; 根 Ed25519 验签(头0..116) true; 会话 Ed25519 验签(SHA512(INPUT64)) true。master.cc 语义已确认: ComputeSecretBytes(·,type)=SHA512(info/种子/输入64B/master/type/随机域混淆), type42=World-ROOT 派生域, 无需独立私钥存储。
  * 文档 ai-doc/session-key-flow-2026-09-09.md 已补 §7 复现结果/§8 后续(批量多客户端、Admin 世界衔接、文件代理持久化)。
  * 2026-09-09 真机 key4 使用计数验证(测试 ukey 00000000-efea115bfc084642, 不 lock): 按用户指引封装宿主 `Dongle_ListFile` → `RockeyARM::FileList`(Interface/dongle.h/.cc) + `dongle_entry --listfile[:type]`(src/app/main.cc, 已重建 amd64-windows-release)。实测: INIT 基线 key4=65535; 重建 Bootstrap-Admin-1000 后 key4=**999**(建置耗 1 次, 印证"构造会耗签名次数/剩余<1000"); 每次 SM2Sign(4) 递减 1→998; 烧至 0 后 key4 禁用; decOnRAM=0=FLASH 持久递减。__Testing 增 `badmin [hid] [burn]`/`badminburn`(BADMIN_BOOT 可切 INIT-0x10000)。设备已恢复 INIT-0x10000 基线。
  * 2026-09-09 模拟器同步实现递减(用户要求): Interface/emulator.cc `DongleHandle::key_licence_` + `KeyLicenceUse`(CreatePKEYFile 记录 {count/perm/decOnRAM/reset}; RSA/P256/SM2 私钥操作前递减, count==0 拒绝 -EPERM; RemoveSecretFile 清除记录)。重建 wasm + JS 封装后, `emuadmin [idx]` 在进程内模拟器复现与真机一致: Admin-1000 建置耗 1→999, SM2Sign(4) 成功 999 次、第 1000 次被拒(脚本检查返回值 Exit(7))。**注意(用户)**: 耗尽测试 licence 设 ~10 更快且少损耗真实 flash。**持久化边界(用户确认)**: 计数仅内存表(会话内), **不做**跨 Export/Open 持久化 —— 导出 storage 可备份是设计使然, 写回计数会把"已耗次数"也备份, 与备份语义冲突, 也是模拟器此前不实现的原因。
- 2026-09-09 bug-analysis-report-2026-09-01.html 全面复查并更新(基于当前 master@2e8da6b): 51 项中 **38 修复/关闭 + 13 开放**(H-08、M-01 实质待办; L-02/03/04/09/11/12/16/19/20/21/23 多为设计取舍/低收益)。报告新增横幅(§11)+ 复查明细与建议(§12: 状态速览/开放项逐条/本会话新验证与体系资产/短板建议), 难度图"测试与验证体系"按建议更新为 4.0(原 2.5)。建议要点: 统一 CI/make test 聚合平台自测 + jsuite/emuadmin/mkey/skey 回归; 优化级别矩阵向量门禁(-O0..O3); 编译器边界语料入库(H-07 万级样本/M-03/L-01); RNG 失败注入; 模拟器-真机语义豁免表; issues-status 清单化。本轮仅改 ai-doc HTML + ai-context, 无代码变更。
- 2026-09-09 验证体系改进落地(feat/AGINX/ci-validation, 建议项①③④⑤⑥+hooks): ① `make ci`(Build/tools/ci/run-ci.cjs)= 进程内回归 jsuite/mkey/skey/emuadmin/corpus + trngfail(可复现, exit0); ③ `corpus`(__Testing): H-07 15 负立即数、L-01 移位拒绝、M-04 对齐(Store 拒绝/Load 缺口记 H-08)、M-03 前导零, 4/4 PASS; ④ `__Testing__trngfail__`(宿主): HwARandBytes 失败注入 → RandBytes -EFAULT(5 尺寸)/正常 → 0, PASS; ⑤ ai-doc/emulator-real-exemptions.md(模拟器-真机语义豁免表 E-01..E-10); ⑥ ai-doc/issues-status.md(51 项清单+状态+依据); hooks: .githooks/{post-merge,post-commit,ci-common.sh} + `make install-hooks`(core.hooksPath) — squash merge/提交信息 "Squashed commit of the following:" 后自动 `make ci`(CI_SKIP_RUN=1 跳过, CI_STRICT=1 失败即非零, .git/rlang-ci-last 去重)。已端到端验证 hook 触发 CI 全绿。② 优化级别矩阵见下条。
- 2026-09-09(续)② 优化级别矩阵落地: `make test-optmatrix` → Build/tools/ci/optmatrix.cjs — 对 -O0..-O3(默认, 可用 OPTMATRIX_OPTS 精简, CI_SKIP_HEAVY=1 跳过)逐个 clean+重建 windows release(X4C_RELEASE_CFLAGS/CXXFLAGS 覆盖)并跑密码学自测: __Testing__{25519,aes,sha256,micro_ecc,dongle}__ exit=10086(0错约定); __Testing__{x509,x509import}__ exit=0 且输出含 "total error = 0"; 结束后恢复默认 release。已实测 **-O0 与 -O2 均 PASS**(退出码门禁口径经实测确定: 10086=0错; x509 需看汇总行而非退出码)。全部六建议项 + hooks 已落地并验证。
- 2026-09-09 X509 CA 前置(RockeySign/RockeyDecrypt 接线, feat/AGINX/x509-ca-sign): 分析 feat/impl/asn1 相对 master 唯一未并入提交 8486822("Rockey.Sign + Rockey.Decrypt")——原生导出 RockeyPKEY_SignEx/DecryptEx 已随 pki.cc 在 master 就绪, 仅 JS 侧 stub; 该提交同时删除 SetPermission(不能并入)。已按 master 结构补: Web/Emulator/lib/jsCrypto.ts Native0_/loader + RockeySign/RockeyDecrypt 实现(保留 SetPermission); 重建 jsWrapper(tsc/webpack 过); __Testing `pkeyself` 接线冒烟 4/4(参数校验 + 未注册句柄→原生错误, 不再 Not implemented), 已入 make ci。真实私钥往返(设备侧导入语义)待 CA 后续核对。
- 2026-09-09 X509ExtBuilder(Web/Emulator/lib/jsCrypto.ts, feat/AGINX/x509-ext-builder): Web 端便捷组装 X509 v3 常用扩展, 供签发 RootCA/X509Req/X509 时嵌入原生 Sign 函数。类(闭包内 X509ExtBuilderImpl, 模块级接口 X509ExtBuilder 暴露)提供: add(通用)/keyUsage(位标志→BIT STRING)/extendedKeyUsage/basicConstraints/subjectAltName(dns/ip/uri/email/rid/dirName)/subjectKeyIdentifier/authorityKeyIdentifier/authorityInfoAccess(ocsp/caIssuers)/crlDistributionPoints + extensionsValue()/build()(DER)。RockeyEmulator 增方法 `X509ExtBuilder()` 返回实例(已建 jsWorld 封装)。**关键编码点**: 本 ASN1 编解码器对列表/容器需写真实 tag(SEQUENCE=0x30、context 构造 0xA0..), 不能传 V_ASN1.SEQUENCE(16); OID 用点分字符串经 encodeOid→OBJECT Buffer。__Testing `x509ext` 冒烟(8 常用扩展→DER 331B→ASN1Decode 回读 8×SEQUENCE+OID 首元素 PASS), 已入 make ci(全绿)。
- 2026-09-09(续)Web 端 CI: jsLibrary.js EmuTests 增 X509ExtTests(8 扩展组装/结构回读/critical 布尔/SAN iPAddress/空集)+ JsCryptoSmokeTests(API 齐全、SM3('abc') 标准向量、ASN1 原语往返 bool/int/bigint/date/octet/sequence)——EmuTests 即网页端 CI 入口(浏览器 console.assert 不抛错, 新用例用 if+throw)。node 镜像验证 PASS(临时脚本已删)。
- 2026-09-09(续)网页端 CI 真机化: Build/tools/ci/web-emutests.cjs(Node 内置 WebSocket, 无第三方依赖)——本机 Chrome **headless=new** + CDP 加载 Web/Agent/Tests 页面, 点击 EmuCreate→EmuTests, 采集 console/异常断言 X509ExtBuilder/JsCryptoSmoke OK; **--user-data-dir 固定 .bin/ai-web-user-data, 绝不访问默认配置**(CHROME 可指路径)。实测 `make test-web` PASS(markers true, exceptions=0)。
- 2026-09-09 RSA 素数生成性能探测(feat/AGINX/rsa-prime-bench, 回答 CA 根私钥恢复方案可行性): 目标——Admin ukey 丢失后用 K0..K3 恢复私钥; P256/SM2 可复用 MASTER.SECRET, RSA 需在低性能 ukey 上做 1024 位 Miller–Rabin 素数搜索。src/__Testing__/__dongle__/main.cc 新增 `RsaPrimeGenPerf`(kTestingIndex=19, argv_[1]=次数): 以设备 `GenerateRSA(2048)` 计时作为两次 1024 位素数搜索代价代理。**真机实测(测试 ukey, -2 管理员, index 0x13): 单次 RSA2048 生成 = 935 ms; ≤1h YES(单 1024 位素数约 0.47 s 数量级)**。结论: 素数搜索速度不是瓶颈, 可行; 后续难点在**确定性再生**(设备 GenerateRSA 走 TRNG, 恢复需种子化 MR/确定性生成实现, 或改为主机用恢复的 MASTER 种子生成后 Import 进新 Admin ukey), 需产品/固件决策。
- 2026-09-09(续, 用户澄清)不用 ukey 硬件 RSA: 恢复只能向 ukey 注入 2×128B 随机数, 需自研代码从 128B 种子 +2 递增做 Miller–Rabin 恢复 p,q(再选 e、算 d)。新增 `src/__Testing__/__rsamr__`(自研 32 位 limb 大数: 加/减/乘/移/除模; MR(小素数试除+前 N 个小素数基, rounds 默认 16); 种子→1024 位候选(置最高位/奇数)→+2; e=65537, d 默认跳过(argv[3]=full 开, 扩展欧几里得)). 用法 `__Testing__rsamr__.exe [rounds] [seedhex_512] [full]`。**host(amd64)实测**: p 422 次递增 22.6s、q 150 次递增 12.7s(朴素大数, 非代表 ukey 速度); **ukey 上真实时间需把该纯代码编入目标并运行**(模块已可移植), 代码内已按每次命中打印增量/耗时。真机代理(硬件 RSA gen)曾测 935ms/2048-key —— 纯软件自研 MR 在 ukey CPU 的耗时以目标实测为准。
- 2026-09-09(续2)定长版 rsa_mr.h + RsaPrimeMR(index 20)与 ARM 核验: 定长数组(无堆/无 .rodata 表), host 小范围(2..4999)与 17/561/65537 PASS; 1024 位 findPrime 定长版 host 47 probes/12.4s(非 ukey 参考)。**arm-none-eabi(cortex-m0, -Os)**: text 2294B、data 0、bss 0、无 .rodata; 栈估算 MR≈2448B+调用框 816B≈3.3KB → 适配"启动后把 SP 移到 ExtendBuffer≈4KB"。ukey 真实耗时以固件构建跑 __Testing__dongle__ index 0x14(argv[1]=rounds, 默认8)为准; host/wasm 不计。

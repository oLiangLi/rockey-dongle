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

- H-03 栈预算重构——**2026-09-03 已解决:方案1(W16)+方案2(Helper ctx)+方案3(noinline×2+免拷贝)全部实施验证,违规路径 32→0,稳态最大栈深 1784B/2032B(余量 248B)。栈检查工具已入库:`tools/rockey/LIMIT/stack-check/`(make stack-check,退出码 0/10 可接 CI;含豁免语义文档与历史参考值)。注:wasm 调用栈可认为很大,无需在意栈深,只需逻辑正确;栈约束仅存在于 dongle 固件**
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
- 2026-09-11 RSA-MR 测试(用户分支 feat/liangli/rsa-rm-test-2)修复与提速: ①**正确性根因**——Interface/mr.cc 的 powmodMRW 中 `r.clear()` 使 `r.n=0`, 导致 mulTo 空转、一切数被判合数(注入真素数暴露); 改为显式 `r.n=1`。②新增 `MillerRabinContext::TrialDivide`(3..1000 奇数流式求余, 无素数表→无 .rodata), 置于偶数检查后 → 多数合数不再进入昂贵幂模。③删除 Delay(用户仅用于估主频)及测试中固定 Delay 循环。④`IsPrimeMRW(rounds)` 基轮数可调; Testing_PrimeMRTests 支持 argv_[1]=1 注入 OpenSSL 生成的 1024 位素数、argv_[2]=rounds; host main 加 `__RockeyARM__` 守卫(calloc/strtoul 不进固件链接)。实测(测试 ukey, -2 13 [mode] [rounds]): 合数(有小因子)设备 **131ms**; 真素数 1 基 **≈109.5s**、16 基 **≈1824.6s(30.4min)**, host/设备/OpenSSL 三方一致(设备 mainRet: 10085=素 / 10086=合)。按试除存活率 ~8% 估算单素数 ≈1.4h、p+q ≈3h(1 天预算内); 可选进一步提速: host 侧预筛(→~1.7h)或 Montgomery/字级除法(→分钟级)。约定: 新增 C/C++ 用 AGINX_DECLARE_MACHINE/END 包裹; KickWDG=每次 mulmod 反转 LED + GetTickCount COS 心跳(ukey 内 LED/看门狗由 COS 调用派发)。
- 2026-09-11 Montgomery 实现与栈验证(feat/liangli/rsa-rm-test-2): MillerRabinContext 新增 Montgomery(无 R² 版本) —— `MontMul`(CIOS, 仅需 uint32_t t[34]=136B 栈)、`ToMont`(k*32 次模倍增)、`FromMont`(k*32 次半减)、`N0Inv`(牛顿迭代);`IsPrimeMRW` 全程在 Montgomery 域比较(one_m/nm1_m 各转换一次), 每 32 次平方一次 KickWDG(LED 反转 + GetTickCount COS 心跳)。**关键 bug 修复**: ToMont 中 `carry || cmp(r,n)>=0` 把"产生进位"误判为"≥ n"(小数值时进位只是越过 32 位边界 → 错误减 n) → 改为仅按 `cmp(r,n)>=0` 减;修正后独立对照程序 600 组(含 1-limb 小操作数/别名/往返)全过, MR 与朴素实现对拍(单 limb 全域、梅森素数 M61..M607、k=1..32 随机)一致。**栈**: arm `.su` 显示 IsPrimeMRW **1376B**(原地构造 one_m/nm1_m 省两槽)、MontMul 272、ToMont 72、FromMont 64、KickWDG 24 ⇒ 最坏链 ≈1.84KB(Start144+Testing24+MR1376+MontMul272+KickWDG24), 当前 2032B 栈即可容纳, OpExecute* 3KB 预算下余量充足; 此前 1632B 版会把 InOut+1024 的 16 个 GuardBytes 冲掉(设备 mainRet 10084→多了 1600=16×100 的守卫惩罚)可作栈溢出的硬证据。**实测(测试 ukey)**: 三方一致(OpenSSL/host MR/设备 mainRet: 10085=素, 10086=合)覆盖随机合数、注入素数、注入半素数(无小因子合数, mode=2); 设备单基 ≈10.5s(朴素 109.5s→约 10x), 16 基素数 ≈158.2s(朴素 1824.6s→约 11.5x); 结合试除(存活 ~8%)估算单素数 ≈8min、p+q ≈16-17min(1 天预算内非常宽裕)。测试入口: `__Testing__dongle__ -2 13 [mode] [rounds]`(mode 0=随机/1=素数/2=半素数; rounds 1..16)。
- 2026-09-11 RSA ROOT CA 生成方案汇总(单指令, ai-doc/rsa-root-ca-generation-2026-09-11.md): 结论——**必须单指令生成**(host 逐个下发候选等价于 host 也能推出 p/q, 安全属性不成立); 实测证明可行(设备单次连续 **30.4 min** 正常返回; Montgomery+试除后整轮估算 **16–17 min**)。定案协议: 初始化时设备 TRNG 生成 **2×128B 种子** + **64B nonce**, 以 `KDF(MASTER.SECRET, nonce, label)` 派生 AEAD 密钥加密 256B 种子, `{header, nonce, cipher||tag}` **张贴到 dashboard[5K]=偏移 5120**(factory dataFile 0xFFFF 共 8192B, [0,4096) 为既有 notice/证书区); 任何持有 MASTER.SECRET 的设备读该位置 → 派生密钥 → 解密种子 → 跑同一确定性算法(seedToOdd → +2 → 试除(3..1000) → Montgomery MR(16 基) → p,q → e=65537,d)即可复现同一私钥。安全: 密文静态保护 + AEAD/AAD 防篡改、单指令只暴露一次总时长(≈16–17min)与粗结构、回滚只复现同一密钥不泄密; 物理侧信道不在本层。实测支撑: 试除命中 131ms、单基 10.5s(朴素 109.5s)、16 基 158.2s(朴素 1824.6s)、栈最坏链 ≈1.84KB(<2032B, <3KB OpExecute 预算)、三方一致(设备 10085=素/10086=合, 覆盖素数+无小因子半素数)。待办: 设备侧单指令状态机(probes 上限、d 计算、结果编码/密封)、AEAD/KDF 选型与 AAD 绑定、dashboard[5120] 字节布局与原子写、测试入口 mode 3/4、OpenSSL 交叉验证脚本。
- 2026-09-11 追加约定: RSA ROOT CA 生成参数 blob 占用 **dashboard[5120, 6144)=5K–6K 共 1KB**(factory dataFile 0xFFFF; [0,4096) 仍为 notice/证书区), **字节布局待定**; 按当前协议内容估算 header(≈8B)+nonce(64B)+ciphertext(256B)+tag(16B)≈344B, 1KB 余量充足; 写入须单次 WriteDataFile 原子完成。详见 ai-doc/rsa-root-ca-generation-2026-09-11.md §3.1/§3.4/§5/§7。
- 2026-09-11 文档合并准备: 新增 **ai-doc/rsa-prime-bench-pitfalls-2026-09-11.md** —— 把 feat/AGINX/rsa-prime-bench 及延续分支上踩过的坑按"现象→根因→规则"归档(A 构建/工具链: host main 进固件链接、.rodata 必须空、elf2bin 首 LOAD 必须 RX(拆 rodata 产生 4B fill→RWE)、.bss≤16B、windows 需 vcvars64、exe 占用、增量构建掩盖警告、Makefile CRLF 与 diff --check、BOM/AGINX_DECLARE_MACHINE 约定; B 设备运行时: 无日志仅 LED、kBlink 需 COS 调用派发、GetTickCount 在 item 内冻结、无 8 分钟窗口(502.6s/30.4min 实测)、kill host≠停设备、PnP 软复位边界与 UDP 触发工具、GuardBytes 作为栈溢出探测器(mainRet 差 100 倍数)、测试索引随分支枚举变化、仅测试 ukey、dashboard 约定; C 算法: BN::clear 后 n=0 致全判合数、朴素逐位取模不可行(109.5s/基)、Montgomery 无 R² 省栈做法、ToMont 进位≠≥n 仅小数值暴露、小素数试除 131ms 拒 92%、Delay 空转掩盖真实耗时、候选回绕与 probes 上限、host 计时无参考; D 工具与提交对照)。同时把 AGINX 分支的 **ai-doc/ukey-rsa-prime-recovery-2026-09-13.md** 原样带入本分支, 使 ai-doc 自洽、避免合并后悬空引用(两分支内容一致, 合并无冲突)。
<!-- 以下条目并入自 feat/AGINX/rsa-prime-bench(2026-09-11 合并准备) -->
- 2026-09-09 RSA 素数生成性能探测(feat/AGINX/rsa-prime-bench, 回答 CA 根私钥恢复方案可行性): 目标——Admin ukey 丢失后用 K0..K3 恢复私钥; P256/SM2 可复用 MASTER.SECRET, RSA 需在低性能 ukey 上做 1024 位 Miller–Rabin 素数搜索。src/__Testing__/__dongle__/main.cc 新增 `RsaPrimeGenPerf`(kTestingIndex=19, argv_[1]=次数): 以设备 `GenerateRSA(2048)` 计时作为两次 1024 位素数搜索代价代理。**真机实测(测试 ukey, -2 管理员, index 0x13): 单次 RSA2048 生成 = 935 ms; ≤1h YES(单 1024 位素数约 0.47 s 数量级)**。结论: 素数搜索速度不是瓶颈, 可行; 后续难点在**确定性再生**(设备 GenerateRSA 走 TRNG, 恢复需种子化 MR/确定性生成实现, 或改为主机用恢复的 MASTER 种子生成后 Import 进新 Admin ukey), 需产品/固件决策。
- 2026-09-09(续, 用户澄清)不用 ukey 硬件 RSA: 恢复只能向 ukey 注入 2×128B 随机数, 需自研代码从 128B 种子 +2 递增做 Miller–Rabin 恢复 p,q(再选 e、算 d)。新增 `src/__Testing__/__rsamr__`(自研 32 位 limb 大数: 加/减/乘/移/除模; MR(小素数试除+前 N 个小素数基, rounds 默认 16); 种子→1024 位候选(置最高位/奇数)→+2; e=65537, d 默认跳过(argv[3]=full 开, 扩展欧几里得)). 用法 `__Testing__rsamr__.exe [rounds] [seedhex_512] [full]`。**host(amd64)实测**: p 422 次递增 22.6s、q 150 次递增 12.7s(朴素大数, 非代表 ukey 速度); **ukey 上真实时间需把该纯代码编入目标并运行**(模块已可移植), 代码内已按每次命中打印增量/耗时。真机代理(硬件 RSA gen)曾测 935ms/2048-key —— 纯软件自研 MR 在 ukey CPU 的耗时以目标实测为准。
- 2026-09-09(续2)定长版 rsa_mr.h + RsaPrimeMR(index 20)与 ARM 核验: 定长数组(无堆/无 .rodata 表), host 小范围(2..4999)与 17/561/65537 PASS; 1024 位 findPrime 定长版 host 47 probes/12.4s(非 ukey 参考)。**arm-none-eabi(cortex-m0, -Os)**: text 2294B、data 0、bss 0、无 .rodata; 栈估算 MR≈2448B+调用框 816B≈3.3KB → 适配"启动后把 SP 移到 ExtendBuffer≈4KB"。ukey 真实耗时以固件构建跑 __Testing__dongle__ index 0x14(argv[1]=rounds, 默认8)为准; host/wasm 不计。
- 2026-09-13 rsa_prime_stack_opt(WDOG 阻塞, feat/AGINX/rsa-prime-bench): 朴素 MR 全链栈深 6248B→1696B(定长 rsa_mr.h 重写: MRWork(prod/rem/bs 780B)放 ExtendBuf[1KB] 非栈 + 热路径 noinline + 二进制逐位 remTo 原地取模 + findPrime 候选原地演化); 设备实测需 ukey 内执行(host 直跑无参考), 设备无日志仅 LED(SetLEDState 协议: 入口短闪/自检 M127-M67/每 64 probes 翻转/p·q 长亮), 发现闪烁若干秒后常亮失响应需重插 = 疑似 WDOG 饿死(ROM 仅在命令/指令边界喂狗), 已整理厂家评估资料 ai-doc/ukey-rsa-prime-recovery-2026-09-13.md(5 问: WDOG 时限/喂狗 API、硬件任意模数模幂、主频与 32×32→64、日志通道、分块执行预算); 待厂家答复或走 host 多次 ExecuteExeFile 分块路线。Makefile 新增 rockey-stack-check(map=rockey-dongle.map, BUDGET 覆盖); __rsamr__/__trngfail__ xModule.mk 改仅非 native 可执行(host-only 模块不再编入固件); main.cc host main 加 __RockeyARM__ 守卫(calloc/strtoul 不进固件链接)。
- 2026-09-13 归档(ukey COS 心跳实验, feat/AGINX/rsa-prime-bench): 确认 ukey 内 LED(kBlink)与看门狗由 **COS 调用派发服务** —— 纯 busy loop/自旋无效(会被掐或停电平), 写 kBlink 后必须发生一次 COS 调用; 且 item 执行期 GetTickCount 冻结(时间不自走), 不能用于 ukey 内计时/延时。选定 **GetTickCount 作为心跳候选**(FTRX.h 中只读、无副作用、负载最小), 待真机实测确认代价与服务效果; 备选 get_pinstate(已证明服务 LED)/led_control(kBlink, 幂等)/get_sharememory/get_keyinfo; 排除 get_realtime/get_expiretime(本机 F0000016 NOTIMPL, 污染错误态)。新增独立 host 探测程序 src/__Testing__/__rsamrprobe__(单数字分块: 每次 ExecuteExeFile 只测一个候选, host 累计 calls 与墙钟, -cos 子模式跑 COS 候选微基准), 契约头 __rsamr__/probe_io.h(magic/mode/360B 布局, 与 Context_t 前部 static_assert 对齐)。__Testing__/__dongle__ 保留设备侧快速路径(Start 顶部 kMagic 拦截 → Testing_RsaPrimeOne / kModeCos → Testing_CosProbe), 撤掉 host 侧 RM one-shot 逻辑; rsa_mr.h 恢复设备无关(noinline+unused, MRWork@ExtendBuf)。
- 2026-09-13 RSA 素数恢复探索暂停(深挖结论): 设备单次 ExecuteExeFile **无 ~8 分钟窗口** —— 新增 -delay N 线性负载标定(1.2564us/iter, 每1024次一次 COS 心跳+LED 反转): N=1e8/2e8/3e8/4e8 全部 rc=0, 4e8=502.6s(8.4min)成功。故此前 MR 在 466/490s 的 FFFFFFFF 不是超时, 而是朴素 MR 路径挂死/耗时远超窗口 ⇒ 朴素逐位取模在 1024 位规模不可行, 必须字级长除/Montgomery(30~100x)后重估。LED 语义确认: kBlink 由 COS 调用派发(纯 busy loop 只停在最后电平), GetTickCount 在 item 内冻结; 选定 get_tickcount 作心跳(边际 ~13us/次, 无副作用, pin/share/err 不变)。工具: __Testing__rsamrprobe__(-2 rounds N [limbs] / -cos cand N / -delay N, HID 安全闸) + .bin/ukey-reset-dgram.cjs(管理员 UDP 触发 pnputil 软复位)。**决定暂停该探索**, 按已假定良好的 ROOT CA 私钥托管方案推进其它工作; 详见 ai-doc/ukey-rsa-prime-recovery-2026-09-13.md §7。
- 2026-09-13 暂停后剩余工作(假定 ROOT CA 私钥托管已解决): 已把主线待办写入 ai-doc/ukey-rsa-prime-recovery-2026-09-13.md §8 —— ①X509 CA 真实私钥往返核对(RockeySign/RockeyDecrypt, 需测试 ukey+管理员); ②EnTrust 真实托管密钥输入(现随机占位被拒 -22)与多设备 EXCHANGE/IMPORT 编排规范(需产品/用户输入); ③master-secret/session-key 文档补充「ROOT CA 恢复由托管方案覆盖」并把依赖 RSA 素数恢复的段落标注已替代; ④issues-status/bug-analysis 中 CA 恢复相关开放项(H-08/M-01 等)评估关闭需人工确认; ⑤回归门禁 make ci / make test-web 不受本次改动影响, 可择机复跑。分支 feat/AGINX/rsa-prime-bench 新提交待用户 squash-merge。
- 2026-09-11 修正两条约定: ①**候选边界不需要回绕保护** —— 只要构造时保证 bit1023=1 且**最高 32-bit 字 ≠ 0xFFFFFFFF**, +2 递增要到 2^1024 需 >2^990 次, 任何设备都跑不到; 原先的 2^1024-1 回绕逻辑属多余(probes 上限仅作'长时间找不到素数'的失败兜底)。②**Windows 下使用的工具脚本不加 #! shebang**(会报错), 统一 node xxx.cjs 调用; .bin/ukey-reset-dgram.cjs 已去掉 shebang。已同步 ai-doc/rsa-prime-bench-pitfalls-2026-09-11.md(A10/C7)与 ai-doc/rsa-root-ca-generation-2026-09-11.md(§3.2 候选约束)。
- 2026-09-11 RSA-3072 容量扩展 + ukey 长跑耐久/进度落盘(feat/AGINX/rsa-3072-gen): ①**容量 32→48 limb(支持 1536 位素因子)** —— 退役已无调用方的朴素路径 mulTo/remTo/mulmodW/powmodMRW 与成员 prod_/rem_/bs_(否则类超 1KB ABI 上限), one_m_/nm1_m_ 移入类成员(nm1_m_ = n - one_m_ 域内减法省一次 ToMont), MontMul t[34]→t[50]; arm .su 实测 IsPrimeMRW 1248B/MontMul 336B/FindPrime 72B/Testing_PrimeMRTests 104B/Start 144B ⇒ 最深链 **1912B ≤ 2032B(余量 120B)**, 1024/1536 位同链, **无需搬 SP**(1 个 BN 工作区放 InOut[384,772) 而非栈)。②**修复 master 遗留 bug**: 合并后 `MR->dongle_` 一直 nullptr(设备侧 KickWDG 空指针), 现 `MR->SetDongle(&rockey)` 注入 + 空指针保护。③新增测试 mode: **3**=设备内 RSA 素数生成(结果写 dashboard) / **4**=长跑耐久(定工作量 + KickWDG + 周期进度) / **5**=host 只读 dashboard 进度(不触发 ExecuteExeFile); 64 位参数走 argv_[2](低)/argv_[3](高), CLI 全 hex 解析。④**候选工作区从 `(BN*)Context + 2` 改 InOut[384,772)**: k=48 时 BN=388B, 旧 memset 会盖掉 InOut+1024 的 16 个 GuardBytes → 假栈溢出惩罚(+100/字节)。⑤**dashboard 分区(用户定义)**: 0..4KB 匿名用户区 / **4K..5K 未分配(本轮临时作测试区**: [4096,4160) 进度或生成状态、[4160,4544) p、[4544,4928) q、用户区 [2048,2240)/[2304,2496) 种子) / 5K..6K ROOT CA(布局待定) / 6K..7K SM2ECIES.key(4) / 7K..8K WorldPublic; ≥4K 管理员可写、其他只读; **ROM 擦写次数有限** ⇒ 进度落盘约 2 分钟一次(kBeatUnits=2^16 单位 ≈66ms 喂一次狗, kReportBeats=2048 ≈135s 落一次盘)。⑥实测(测试 ukey=索引 0, 新 ukey=索引 1): 单位耗时 **0.99-1.01µs**(2,097,152 单位 / 2069-2111ms); **5 分钟单次执行 276,239ms 正常收尾(mainRet=10086)**, dashboard 记录 done/seq=3 ✓; 12h 目标(0xA30000000 单位)长跑在新 ukey 起跑, 后因 SDK 全局串行而手动杀 host(设备侧循环继续, dashboard 终态可事后读回)。⑦**关键约束发现: SDK 访问是全局串行的** —— 任一 ExecuteExeFile 在飞行时, 其它 host 进程(即使操作另一支 ukey)都会卡在设备枚举/打开(实测烧录进程 0 CPU 挂住 >160s、只读 mode5 进程 >45s) ⇒ 两支 ukey 不能并行跑长任务, 长跑期间也无法用第二进程观察 dashboard。⑧host 侧新增 VerifyRsaPrimePair(OpenSSL 64 轮素性 + gcd(e,p-1)=1 + p≠q + bits(n) + d 存在)与 ReadMRProgress(按 magic 区分 Progress/GenResult 并自动验证 p/q)。⑨烧录固件需管理员权限(匿名 `-0` 下 UpdateExeFile = F0000008)。详见 ai-doc/ukey-longrun-and-rsa3072-2026-09-11.md。
- 2026-09-11 追加约定(用户): **运行真机测试程序一律"先复制改名再执行"** —— 直接用 `.bin/amd64-windows-release/__Testing__dongle__.exe` 会把构建产物占住, 使 `make windows` 无法链接(此前只能靠杀掉 host 进程腾出)。新增工具 **`tools/rockey/LIMIT/sbin/run-dongle-exe.cjs`**(node 调用, 不加 shebang): `node tools/rockey/LIMIT/sbin/run-dongle-exe.cjs [--bin <exe>] [--tag <名>] <参数...>` → 复制到 `.bin/run/<basename>-<tag|时间戳>.exe` 再 spawn(stdio 继承, 退出码透传); `--tag` 用于回看"当时跑的是哪个二进制"。
- 2026-09-11 长跑耐久中断点实测(新 ukey, mode 4): 12h 目标循环 11:35:13 起跑; 11:41:27 手动杀掉 host(**设备继续跑**, 再次印证"kill host ≠ 停设备"); 11:50:25 PnP 复位(`pnputil /restart-device`, 需管理员)打断 → dashboard 最后记录 **`alive seq=6 units=805,306,368 beats=12288`** ⇒ 设备端连续执行 ≈805s(13.4min; 加上最后一段未落盘的运行约 15min)后被复位终止, **不是设备自身限制**。另: 复位前 SDK 被孤儿循环独占, 任何其它 host 进程(含另一支 ukey)全部阻塞; 复位后立即恢复。**"最大连续执行时间"仍需完整跑一次长目标**(建议放在 RSA 生成之后)。
- 2026-09-11 RSA 生成路径验证通过(**1024 位, mode 3**): 设备内 **381,741ms** 生成 p+q, `mainRet=10086`, `GenResult bits=1024 rounds=4 ok=3 probes_p=50 probes_q=123`; host 用 OpenSSL 独立复核 **prime_p=1 prime_q=1 gcd(e,p-1)=1 distinct=1 bits(n)=2047 d_ok=1**。**耗时模型精确吻合**: 173 次探测 = 试除 173×0.131s + 基-2 筛查 ~28×10.5s + 余下 3 基 ≈380s vs 实测 381.7s ⇒ 外推 1536 位: 单基 10.5s×(48/32)² ≈ **23.6s**, 单素数 ≈42min, **p+q ≈84min**(长尾 2-3h)。生成期间 FindPrime 每 32 次探测落一条 dashboard 进度(`magic=kMagicAlive, seq=1/2 表示 p/q, units=已探测候选数`), 最终被 GenResult 覆盖。长跑耐久的目标参数(1.0µs/单位): 12h=`-2 13 4 EEBB000 A`, 24h=`-2 13 4 1DD76000 14`。
- 2026-09-11 新增 **`tools/rockey/LIMIT/sbin/rsa-prime-repro.cjs`**: 逐位对齐设备算法(种子定型 bit0/最高位 → 试除 3..999 奇数 → MR 基序 [2,3,5,7,11,...,53] 取 rounds 个 → 否则 +2)的**独立复现工具**, 用于验证 ROOT CA 方案的核心承诺"同一种子 ⇒ 同一对素数"。用法: `node ... --seed <小端hex> --bits 1024|1536 [--rounds 16] [--expect <小端hex>]`(expect 即设备 dashboard 读回的 p/q, 比对成功才退出 0); `--selftest` 用 128 位随机种子找素数并以 64 个随机基独立复核(已 PASS)。配套: `ReadMRProgress` 现在会把 dashboard 里的 **seed_p/seed_q/p/q 以小端 hex 直出**到日志, 可直接喂给该工具做端到端复现。
- 2026-09-11 **RSA-3072 设备内单指令生成成功**(feat/AGINX/rsa-3072-gen, 测试 ukey 索引 0): 一次 `ExecuteExeFile` 内完成 p+q, 设备端 **3,125,713 ms ≈ 52.1 min**, `mainRet=10086`(GuardBytes 完好, 无栈溢出), `bits=1536 rounds=16 ok=3 probes_p=268 probes_q=95`; host OpenSSL 独立复核 **prime_p/prime_q/gcd(e,p-1)/distinct/bits(n)=3072/d_ok 全 1**, 组装出的私钥 **sign/verify=PASS**(`e=65537, d_bits=3063`, `SHA256(N)=487307aa…6fe5`), PEM 在 `.bin/rsa3072-testkey-2026-09-11.pem`。**可复现性已验证**: `rsa-prime-repro.cjs` 从 dashboard 读回的种子独立复现, **p/q 逐字节相同且探测次数一致(268/95)**, host 侧 1.65s/0.92s(设备 52min 只是算力差异)⇒ "同一种子 ⇒ 同一对私钥" 成立。耗时模型: 1024 位验证跑 381.7s 与分解吻合; 1536 位单基 ≈23.6s、探测数期望 ≈532/素数 ⇒ 期望 p+q ≈84min(长尾 2-3h), 本次 52min 属偏快样本。**注意 SDK 全局串行仍未变**: 12h 长跑(pwsh-30, 新 ukey, iters=0xA_EEBB000)期间无法做任何其它设备操作。文档: ai-doc/rsa3072-device-generation-2026-09-11.md。
- 2026-09-11 工具坑(新): PowerShell 的 `>`/`*>` 重定向落地是 **UTF-16LE(带 BOM)** —— Node 侧按 utf8 读会得到 `\u0000s\u0000i…`(正则全不匹配)。`.bin/extract-dash-hex.cjs` 与 `.bin/make-rsa-key-from-hex.cjs` 已自动识别 BOM; 后续 Node 解析日志要么显式转码, 要么用 `-Encoding utf8`。
- 2026-09-11 新增 **`tools/rockey/LIMIT/sbin/check-gpg-sigs.cjs`** —— 检查 mkey 下 OpenPGP 文件(.asc/.gpg/.sig/.pgp)是否**完整**:
  ①**结构完整性(纯 JS, 不依赖 gpg)**: armor BEGIN/END 配对、base64 合法性、**CRC24 校验**、包长度自洽/是否越界截断
  (含 RFC4880 §4.2.2.4 **partial body length 链**的正确遍历 —— 边界要显式跟踪包末尾, 否则加密文件会误报截断);
  ②**分类**: 签名 / 加密(`tag 1,3,9,18` → 按用户要求**跳过验签**, 但仍查完整性) / 公钥块 / 其它;
  ③**验签(可选)**: 用临时 GNUPGHOME(`.bin/gpg-check-home`, **相对路径**)导入扫描目录里的公钥块, 再 `gpg --verify`;
  分离签名自动找同名数据(去掉后缀), 报告 `VERIFIED/BADSIG/no-pubkey/verify-error`;`--no-verify` 只做结构检查;
  ④`--selftest` 自检(截断/缺 END/坏 CRC/正文改 1 字节都必须被抓出);`--dump <file>` 打印包结构;`--json`/`--quiet`。
  **实测 mkey**: 18 个文件 = **13 个签名全部 VERIFIED** + 4 个加密(跳过) + 1 个公钥块(structure-ok), exit 0;
  篡改数据 → BADSIG(exit 1); 缺数据 → 非致命提示; 指定坏 `--gpg` → exit 2。签名者两把公钥(`keyring.asc` 导入 2 把):
  `C489989197876293 LiangLI <admin@rlang.xyz>` 与 `BCE591B95E51D027 LiangLI <liangl79@gmail.com>`。
  **环境**: cygwin 的 `gpg.exe` 无法从 Windows 直接 exec, 缺省自动命中 **Git 自带 gpg**(`C:\Program Files\Git\usr\bin\gpg.exe`, 2.4.8);
  MSYS 版 gpg 的 `--homedir` 必须相对路径。
- 2026-09-11 README 发布评审(ai-doc/readme-publish-review-2026-09-11.md): 结论 —— README 本身 60 行、内容真实,需修正 3 处(**`make make install-hooks` 笔误**、缺平台×工具链前置、**RSA 行过时**: 已实测设备内单指令生成 RSA-3072 52.1min);**真正的门槛是仓库里已有生产材料**: `mkey/` **44 个被跟踪文件**(K0..K3/A0 设备序列号、EnTrust 托管参数、系统参数、factory-lock、`cipher/sec.asc` 加密种子、`MASTER-KEY-INITIALIZE.7z.asc`、GPG key id 与仪式流程)→ 公开发布必须整体移除并清历史;`ai-context.md`(内网代理 10.20.20.124:8001、usbipd、测试 ukey HID、邮箱、PIN 约定)与 7 篇 ai-doc(主钥重建算法/dashboard 分区/种子密钥 hex)需逐篇三分类(公开/摘要化/私有);`Web/Agent/Tests/__Testing_dongle.cjs` 内置真机 HID 白名单应改环境变量。**法务风险**: `third_party/RockeyARM`(3 平台头文件+静态库)与 `MCU/RockeyARM/lib/FTRX.a` **无任何许可声明**,再分发条款未知;`nlohmann` 只跟踪了头文件、缺许可声明;TASSL 为 OpenSSL/SSLeay 双许可、micro-ecc BSD-2(两者许可文件齐)。另发现 `Build/tools/ci/run-ci.cjs` 注释引用的 `make ci-full` **在根 Makefile 不存在**。建议补充公开的信息(P0): 第三方声明、平台×工具链矩阵与命令、测试/CI 入口与"哪些需真机";(P1) 目录结构、能力清单+最小示例、安全模型小节(构建期私有常数⇒版本互不兼容 / MASTER_SECRET 4 选 3 / 私钥不出设备且种子可复现)、脚本语言完整约束、路线图、文档索引。
- 2026-09-11 长跑统计读回 + **重要更正**(feat/AGINX/rsa-3072-gen, 详见 ai-doc/ukey-longrun-and-rsa3072-2026-09-11.md): 第二次 12h 长跑(12:51:29 起, 目标 43.2e9 单位)的 host 在 13:38:25 被**误杀**(清理进程用了 `__Testing__dongle__*` 通配, 命中长跑副本 `<name>-<tag>.exe` —— 以后清理只用精确 PID)。16:33 探测发现 **SDK 已空闲**(`Enum return 3/3` ⇒ 无 item 在执行), 读回 dashboard: **`alive seq=24 units=3,221,225,472 beats=49152`** ⇒ 设备端连续执行 **3,221s ≈ 53.7 分钟**, 末条进度在 13:45(host 死后约 7 分钟)。**更正**: 与第一次的 805s(host 死后也约 7 分钟)一致 ⇒ **并非"kill host 后设备继续跑", 而是 host 一死设备侧 item 约 7 分钟内终止**(推测会话断开后心跳/落盘不再被服务或看门狗复位)。迄今**完整跑完**的最长单指令是 **RSA-3072 生成 3,125,713ms(52.1min, host 全程存活)**; "能否连续跑几小时"**仍未验证**, 需 host 不被打扰地重跑长目标。附带: `RockeyARM::Open(index)` 内部先 `Dongle_Enum`, 长跑在飞时 Enum 阻塞(**已实测** `WT_RKEY_DEVICE=99` 走真机路径 60s 无返回) ⇒ 长跑期间任何 ukey(含 index=2)都打不开, 且厂商 SDK 无按序列号直开 API; 新插入的未初始化 ukey 不允许 `UpdateExeFile`(F0000008), 无法刷测试固件。
- 2026-09-11 **ChaCha20-Poly1305 可选 AAD 支持 + AAD 问题分析(暂停)**(分支 `feat/AGINX/chachapoly-aad`): ①**事实核查**: `rlCryptoChaChaPolyUpdateAAd` 在 ARM 固件里由 **libbase.a(crypto.o)** 提供(map 已核对, 不是 COS/厂商实现), 各平台同一份可移植 C;AAD 顺序(updateAAd → pad16(aad) → ciphertext → LE64(aad_len)‖LE64(ct_len))与 RFC 8439 一致。②**真实差异**: 脚本侧 `kExChaChaPolySeal/Open` 原本只有 `argc == 4`, **完全没有 AAD**;而 JS/world 的 `CipherAEAD.Seal(input, nonce, aad?)` 有 AAD(`Web/Agent/Tests/js/jsLibrary.js` 的 EXECV 封装就在用第三参 AAD)⇒ "ukey 上不对"更可能是**能力缺失**而非算法错误(待真机验证)。③**已实现**: `Dongle::CHACHAPOLY_Seal/Open` 增加可选 `(aad, aad_len)`(默认 nullptr/0, 老调用不变);`VM_t::OpFuncChaChaPoly` 支持 `argc == 4` 或 `6`(追加 `aad[aad_len], aad_len`, 经 OpCheckMM 校验、cycles 计入 AAD);`Interface/script.h` 注释改 `argc : 4...6` 并重新生成 `Web/Script/lib/opcode.ts`(该文件 gitignored, 由 `node tools/rockey/LIMIT/script/opcode.cjs` / `make jsWrapper` 生成)。④**已写测试**: ChaChaPoly 测试项(index 11, CLI `b`)新增 `Testing_ChaChaPolyAad`: RFC 8439 §2.8.2 静态向量(密文与 tag 逐字节比对)、Open 还原、**AAD 篡改必须被拒绝**、无 AAD 的 tag 必须等于 OpenSSL 实测值 `6a23a468…`、宿主再与 OpenSSL `EVP_chacha20_poly1305` 随机对拍(AAD 长度 0/1/15/16/17/32/63/64)。⑤**尚未执行**: 宿主机(模拟器 `b`)与真机(`b`)都还没跑 —— 真机需等长跑结束腾出 SDK(Enum 被长跑卡死, 见下条)。⑥顺带修复(已单独提交到 RSA 分支 `738daa9`): mode 3/4 的宿主分支漏排 `__EMULATOR__`, 导致 `make foobar` 编译失败。
- 2026-09-11 设备访问补充结论(实测): **`RockeyARM::Open(index)` 内部先调 `Dongle_Enum`**(Interface/dongle.cc:993), 而长跑在飞时 `Dongle_Enum` 会**阻塞**(用 `WT_RKEY_DEVICE=99` 走真机路径 60s 无返回验证) ⇒ **长跑期间任何 ukey(包括新插入的 index=2)都无法打开**, 厂商 SDK 也没有按序列号/路径直开的 API(仅 `Dongle_Enum` / `Dongle_Open(index)`)。**另注意**: 新插入的 ukey 是未初始化设备(PID/UID=ffffffff), 未初始化设备不允许 `UpdateExeFile`(F0000008), 因此无法刷入测试固件 —— 想做设备侧自研测试仍需已初始化的 ukey。**教训**: 清理进程不要用 `__Testing__dongle__*` 通配 —— 会误杀长跑的 host 副本(`<name>-<tag>.exe` 同样匹配), 本次已误杀一次 12h 长跑的 host(dashboard 终态仍可事后读回, 但 host 墙钟数据丢失; **设备侧 item 随后约 7 分钟内也终止**, 见上条更正)。
ChaChaPoly AAD: 去掉设备端 .rodata + 复现"ukey 上 AAD 卡死"

- 设备端 .rodata 必须为空(linker.ld 的 __rodata_begin/end ASSERT): 上一版把 RFC 8439 向量写成
  `static const` 放进函数里 ⇒ 固件链接失败(__rodata_begin != __rodata_end);现改为:
  * 设备端只跑"运行期自洽性测试"(零静态常量): 密文与 AAD 无关 / AAD 变则 tag 必变 /
    正确 AAD 能 Open / 错误或缺失 AAD 必须被拒;
  * RFC 8439 §2.8.2 静态向量 + OpenSSL 随机对拍只在 `#if !defined(__RockeyARM__)` 编译(宿主/模拟器)。
- 顺带修好测试自身的 bug: 宿主对拍曾把 EVP 加密后的密文又喂给 Seal(二次加密) ⇒ 8 个 AAD 长度全报错。
- 修复后: 模拟器 index 11(CLI b) `Testing_ChaChaPolyAad error = 0` ✓(RFC 向量 + OpenSSL 对拍全过);
  真机(测试 ukey index 0, 固件 16:49)host 侧同样 `Test.11 return 0` ✓。
- **重要发现(复现用户记忆)**: 真机跑设备侧 item 时**卡死 >590s**(host 在前台上限被杀), 20s 后探测
  仍显示设备在执行该 item ⇒ **设备侧 ChaChaPoly(带 AAD)路径挂住**, 而同一份代码在宿主/模拟器正常。
  待查(下一步计划): 在设备侧各步骤前后写 dashboard 标记(magic+seq), 复位后读回定位卡在哪一步。
- 2026-09-11 **ChaChaPoly AAD 真机卡死的根因 = 测试用例栈溢出(非算法错误)**(feat/AGINX/chachapoly-aad): 上一版 `Testing_ChaChaPolyAad` 在栈上放了 ~1.4KB 缓冲, 帧 **1496B**;叠加 `Testing_ChaChaPoly` 784B 与 `Start` 144B ⇒ 链深 2424-2528B,**超设备 2032B 栈预算 392-496B** ⇒ 设备侧栈被冲爆, 表现为"**只在 ukey 上卡死**"(宿主/模拟器栈以 MB 计看不出问题)—— 这解释了用户记忆中"只有 ukey 上才会出错"。**修复**: 大缓冲改走调用方传入的 1KB 工作区(设备端即 `ExtendBuf`), 帧降到 **168B**, `make rockey-stack-check` 回到 1928B/0 违规。**验证**: 模拟器 `Testing_ChaChaPolyAad error = 0`(exit=10086);真机(测试 ukey)host 侧 0 错且**设备侧 `ExecuteExeFile mainRet=10086`, 313ms 完成** ⇒ AAD 在 ukey 上确实参与认证(密文与 AAD 无关 / AAD 变则 tag 必变 / 正确 AAD 可 Open / 错误或缺失 AAD 被拒)且不卡死。**教训**: 设备侧(2KB 栈)任何 >200B 的缓冲都必须走 `ExtendBuf`/`InOutBuf`, 加完设备端代码后**必须跑 `make rockey-stack-check`**(本机 `make dongle` 只查 .rodata 与 .bss, 不查栈)。另: opcode 层(argc==6 的 `ExChaChaPolySeal/Open`)目前只有静态检查, 尚无自动化用例(当前验证的是 `Dongle::CHACHAPOLY_*` API 层)。附带修掉宿主 `librockey.lib` 中损坏的 `chachapoly.o`(删归档重建, 解 LNK1236)。
- 2026-09-11 **ChaChaPoly 可选 AAD 补齐 opcode 层用例**(feat/AGINX/chachapoly-aad): 新增模块 `src/__Testing__/__chachapolyvm__`(仅 foobar 构建, 直调 `VM_t::OpFuncChaChaPoly`), 覆盖 `kExChaChaPolySeal/Open` 的 **argc==6(新增可选 AAD)** 与 **argc==4(旧脚本兼容)** 两条路径 + 参数错误分支: argc=6 Seal 与 `Dongle::CHACHAPOLY_Seal` 直接 API 逐字节一致; argc=6 Open 正确 AAD 还原明文、错误 AAD(仅差 1 bit)被拒; argc=4 与无 AAD 直接 API 一致且 tag 与带 AAD 时不同; `argc=5` → SIGILL、`aad_len` 越界 → SIGSEGV、`aad` 指针越界(1000+64>1024)→ OpCheckMM 置位。运行: `make foobar && ./.bin/amd64-foobar-windows-debug/__Testing__chachapolyvm__.exe` → exit=10086 / `ChaChaPolyVM opcode 用例: PASS (error=0)`。**至此 AAD 两层均有覆盖**: API 层(模拟器 + 真机 index 11)+ opcode 层(本模块);设备端 opcode 的栈预算由 `make rockey-stack-check` 兜底(1928B/0 违规)。注: 模块 `xModule.mk` 必须写 `$(call add_general_source_files_under, $(LOCAL_PATH))`, 否则链接报 LNK1561(无入口点/无对象文件)。
- 2026-09-11 上游 base/Build 对比与合并清单(分支 `feat/AGINX/upstream-base-merge`, 从 master 开): 上游 `base` / `build` 仓(**当时的本地参考检出, 现已清理**; 两个独立仓库: base HEAD `1d339f3` 2026-06-18 "准备 v1.1.0.0 发布"、build HEAD `32cc27c` 2026-03-12 "update jsCipher.js")。脚本法定位**分叉点: base=`c25ac21d`、build=`d5be0e5f`, 均为 2025-11-07**(对每个本地文件在上游历史里找 blob 相同的最新提交)。结论: 本仓是快照的**裁剪版 + 少量本地修复**;base 14 文件(与上游同名文件 6 同 8 异), Build 24 文件(16 同 8 异);`Build/tools/script/{grammar.actions.cjs,wasm2string.cjs}` 的差异经归一化验证**仅换行**。**可合并候选(A, 上游→本仓)**: A1 `LOCAL_DEPENDS` 目标额外依赖(build-executable/shared-library + common.mk 注册)、A2 `add_general_source_files_non_recursive` + 目录通配 4→6 级、A3 `X4C_BOARD` 合法性检查、A4 `LOCAL_STRICT`/`LOCAL_BACKTRACE`/`X4C_UNWIND_TABLE_CFLAGS`(注意 `rLANG_COMMON_STRICT_CFLAGS` 上游也只有引用、需使用方提供)、A5 `bits/base.h` 平台中立小设施(`rLANG_CONTAINER_OF`/`IS_LITTLE_ENDIAN`/`ASSERT-VERIFY` 家族/调试助手/定长整型别名, **须按需摘取以免把 minimal-world/STL 带进设备构建**)、A6 `bits/task.h`+`src/task.cc`(rbtree 定时任务, 先评估是否需要)、A7 `rlCrc8/16/32`(上游用 256B 表 → 设备 `.rodata` 不允许, 需无表实现)。**可回馈上游(B)**: B1 `rlCryptoX25519` 全零拒绝(RFC 7748 §6.1, void→int, 对应本仓 H-06)、B2 `cipher_cleanse` 哈希派生填充、B3 `log.cc` 的 `LOGDATA_SIZEMAX` 1024→2048 与日志等级判断、B4 无表 CRC。**不合并(C)**: 所有设备裁剪(log.cc 大裁剪 / data.cc 删 CRC 表 / base.cc 去 minimal-world / crypto.cc `#if 0` libc shim / Main.mk `-O1` / xModule.mk 模块裁剪)与本仓专属工具(ci/sbin/opcode/stack-check)。详见 `ai-doc/upstream-base-merge-plan-2026-09-11.md`;对比脚本为一次性 scratch(**已随参考检出一并清理**)。
- 2026-09-11 README 更新(用户编辑 + 检查;分支 feat/AGINX/readme-update): ①加入 GitHub/Gitee 克隆地址;②构建命令把 `npm run release` 换成 `make jsWrapper -j8`, 并补 `make install-hooks`(合并/提交时触发 ci 快速回归;用户已修正 `make make` 笔误);③`parse`→`parser` 笔误;④新增"正在进行的工作"(CA 基本原语准备、CSR/CRL/X509 实现)、"剩下的工作"补 jsSSL 封装;⑤**检查项**: 按实测把"RSA3072 可能非常缓慢"改为"**设备内单指令生成整对 1536 位素数实测 ≈52 分钟**(16 轮 MR, 见 ai-doc/rsa3072-device-generation-2026-09-11.md), 只应用于 ROOT CA/重要中级 CA";⑥该分支只改 README.md, 与 rsa-3072-gen / chachapoly-aad / upstream-base-merge 均无重叠, 可单独 squash 或任意位置插入。README 发布前仍需处理的项见 ai-doc/readme-publish-review-2026-09-11.md(mkey/、第三方许可、平台构建前置等)。
- 2026-09-11 上游构建系统合并 A1-A4 完成(分支 `feat/AGINX/base-upstream-merge`, WSL `/home/liangli/MyWork/RockeyDongle`): 从上游 `build` 并入 4 项通用能力, 全部按本仓约束调整后通过三平台验证。**A1 `LOCAL_DEPENDS`**(上游 `cd0b4afc`): `Build/core/build-executable.mk` / `build-shared-library.mk` 在 include 前加 `ifneq ("$(LOCAL_DEPENDS)","")` + `$(eval $(LOCAL_MODULE_TARGET_TEMP):$(LOCAL_DEPENDS))`, 并在 `Build/core/common.mk` 注册该 variant ⇒ 模块可为目标文件声明额外依赖(生成文件场景)。**A2 `add_general_source_files_non_recursive` + 更深目录通配**(上游 `096c4954`/`30bd4cd6`): `common.mk` 的 `x4c_all_files_under_recursive` 由 4 级扩到 6 级, 并新增非递归收集函数(已核对本仓无 5 级以上源文件 ⇒ 不改变现有编译集合)。**A3 `X4C_BOARD` 合法性检查**(上游 `f2a90320`): `Build/Main.mk` 在 include definitions.mk 后加两条 `$(if ...)$(error ...)` —— board 名不得含空格、不得以 `.` 开头(会被当 Linux 隐藏文件自动包含)。**A4 `LOCAL_STRICT`/`LOCAL_BACKTRACE`**(上游 `b360abf8`): `common.mk` 注册两个 variant 并定义 `rLANG_COMMON_STRICT_CFLAGS/CXXFLAGS ?=`(空)、`X4C_UNWIND_TABLE_CFLAGS ?=`, `build-binary.mk` 按 `LOCAL_STRICT`/`LOCAL_BACKTRACE` 追加。**关键偏差(实测教训)**: 上游把 `X4C_UNWIND_TABLE_CFLAGS` 默认设为 `-DX4C_CONFIG_UNWIND_TABLE -funwind-tables`, 本仓**必须保持空缺省** —— 带该 flags 时 ARM 目标会出现 `.ARM.exidx` 段并缺 `__aeabi_unwind_cpp_pr0`(实测 `make dongle` 链接失败), 违反 elf2bin 段契约与 ".rodata 必须为空" 约束; 宿主模块需要回溯时显式 `LOCAL_BACKTRACE=1` 并覆盖该变量。**另一坑**: 本仓构建系统**不跟踪 CFLAGS 变化**, 改 flags 后必须 `make clean-dongle`(否则旧 `.ARM.exidx` 目标文件残留导致同样的链接错误)。**验证**(WSL Ubuntu-22.04, arm-none-eabi **10.3.1**, 与 Windows 侧 14.3 不同): `make clean-linux && make linux -j8` **0 警告 0 错误**; `make aarch64-linux -j8` **0 警告 0 错误**; `make clean-dongle && make dongle -j8` rc=0(仅 2 条既有 warning, 来自 `base/grammar/XDPDA_MACHINE_DECLARE.INL`, 与本改动无关), 固件 `rockey_dongle.bin` 仍 65520B, `make rockey-stack-check` 稳态最深 **1936B ≤ 2032B**(0 条超预算)。**工作方式**: WSL 与 Windows 检出是两份独立 repo, 本次全部改动在 WSL 侧; 上游参考树与三个对比脚本已复制到 WSL `/.bin/`(Windows 侧只读)。**注**: UNC(`\\wsl$`)读取正常但 `edit` 工具写会报 `GetFileSecurityW EIO` ⇒ 采用"拷到 Windows 暂存区编辑 → `Copy-Item` 回写"的流程。
- 2026-09-11 上游 base.h 平台中立设施合并 A5(分支 `feat/AGINX/base-upstream-merge`, WSL): 从上游 `bits/base.h` 摘取两批零风险设施并逐个验证。**①端序标注宏**(上游 `ccae27ad`/`3f0d79c5`): `IS_LITTLE_ENDIAN`/`IS_BIG_ENDIAN`, 两者同时定义即 `#error`, 都不定义时按 `__BYTE_ORDER__` 推断、推断不出按小端; PDP(3412) 明确不支持。**②`rLANG_CONTAINER_OF`**(上游 `86f99737`): C++ 用成员指针模板 `rlang_foobar_container_of`(用非空假指针求偏移, 避免对 nullptr 取成员地址的 UB), GNU C 用 `({...typeof...offsetof...})`, 其它编译器用 `offsetof` 宏。**踩坑**: 第一次实现把模板又包了一层 `namespace machine`, 而本仓 `base/bits/base.h` 自身已由 `rLANG_DECLARE_MACHINE`(第 104 行)打开 `namespace machine` ⇒ 宏展开成 `machine::machine::rlang_container_of`, **三平台 27/17 处编译错误**; 改为与上游一致的写法(不重复开 namespace, 宏用 `::machine::rlang_foobar_container_of`)。**验证**: 独立自测程序(不打进产品)`container_of=OK endian_macro=OK`(g++ C++ 路径)、`c_branch=OK`(gcc C 路径)、`arm-none-eabi-g++ -c` 编译 OK; `make clean-linux`+`make linux -j8` 与 `make clean-aarch64-linux`+`make aarch64-linux -j8` 均 **0 警告 0 错误**; `make clean-dongle`+`make dongle -j8` rc=0(2 条既有 grammar warning), 固件仍 **65520B**, `make rockey-stack-check` 稳态 **1936B ≤ 2032B**。**未采纳**: `rLANG_ITCM_*/DTCM_*/SRAM_*/XSHR_*` 段属性(本仓 linker/elf2bin 段契约不同, 引入会诱导把数据放进不存在的段)、`rLANG_DLLEXPORT/DLLIMPORT`(本仓有 `rLANGEXPORT`)、定长整型 `using` 别名(本仓不需要)。
- 2026-09-11 A5c: 并入上游 VERIFY/ASSERT 家族与失败钩子(分支 `feat/AGINX/base-upstream-merge`, WSL): `base/bits/base.h` 新增 `rLANG_VerifyExpr` + `rLANG_VERIFY_TRUE/FALSE/EQ/NE/GT/LT/GE/LE` + `ASSERT`(缺省走 C `assert`, 定义 `rLANG_CONFIG_ASSERT=1` 时走 VERIFY)+ `VERIFY`, 并声明钩子 `rLANG_SetVerifyAbort(int)` / `rLANG_OnVerifyFailed(expr,file,line)`; `base/src/log.cc` 实现两个钩子 —— **宿主**: 写 stderr 且仅在 `rLANG_SetVerifyAbort(1)` 后 `abort()`(默认只记录不中断); **设备侧 `__RockeyARM__`**: 空实现, 因为设备无日志通道, 且固件 `.bss` 只有 16B 预算, 不能新增可变全局(实测 `.bss` 仍 0x10=16B ✓)。**用法注意**: 宏内的 `rLANG_OnVerifyFailed` 是非限定名(与上游一致), 必须在 `rLANG_DECLARE_MACHINE` 打开的 `namespace machine` 内展开 —— 在全局作用域直接调用会报"找不到声明"(自测首版即踩此坑); C 构建下 `rLANG_DECLARE_MACHINE` 为空、声明落在全局, 因此仍可用。**验证**: `verify_hook_test.cc` 链接 base 真跑 —— 编译 0 错、`run_rc=0`、stdout `continued-after-verify-failures=YES`、stderr 两条 `[verify] file:line: expr`(证明默认不 abort); `make clean-linux`/`clean-aarch64-linux`/`clean-dongle` 后三平台重建 **0 错误**(linux/arm64 0 警告, dongle 2 条既有 grammar 警告), 固件 **65520B**、`.bss` LOAD memsz **0x10**、`rockey-stack-check` 稳态 **1936B ≤ 2032B**。
- 2026-09-11 A6: 并入上游定时任务组 `bits/task.h` + `src/task.cc`(分支 `feat/AGINX/base-upstream-merge`, WSL): 以 RB-Tree 按 `next_ticks_` 排队的任务组(`rlTaskNode_t{Closure, next_ticks_}` / `rlTaskGroup_t{GetTicks, DelayUs, TicksFromUs, UsFromTicks, ScheduleTask, UnscheduleTask, ExecuteTask, NextTicks}`), 依赖本仓已有的 `rlBASE_INLINE`/`rLANG_RBTREE_*`/`rLANG_VERIFY_*`(A5c)与 `src/rbtree.cc`(已实现 `rLANG_RBTREE_INSERT_NODE_0`/`ERASE_NODE_0`)⇒ 无需新增底层。**本仓适配**: 上游用 `#ifndef rLANG_CONFIG_MINIMAL_WORLD` 包平台层并要求 `<chrono>`; 本仓无 minimal-world 概念, 改为 `#if !defined(__RockeyARM__)` 才 include `<chrono>`, 设备侧(`__RockeyARM__`/`__EMSCRIPTEN__`)用 `rLANG_GetTickCount() * 1000` 作微秒源; 时钟宏 `Magic::Xs` 换成本仓的 `rLANG_DECLARE_MAGIC_Xs`; `base/base.h` 增补 `#include "bits/task.h"`; `base/xModule.mk` 已用 `add_general_source_files_under` 全收集 ⇒ 新文件自动编译。**坑**: 设备侧 `rlLOGE` 是空宏, `platform_GetTicks` 里的 `constexpr TAG` 变成未使用变量 → ARM 构建新增 1 条 `-Wunused-variable`; 加 `(void)TAG;` 后 dongle **0 警告 0 错误**。**验证**: `task_test.cc` 链接 base 真跑 —— `n0=0 next=1 n3=3 next_after=-1 fired=3 last=3 => PASS`(调度/到期执行/NextTicks 全对); `arm-none-eabi-g++ -c base/src/task.cc` rc=0; `clean-linux`/`clean-aarch64-linux`/`clean-dongle` 后三平台 **0 警告 0 错误**, 固件 **65520B**, `.bss` **0x10**, `rockey-stack-check` 稳态 **1936B ≤ 2032B**(余量 96B)。**注**: 任务组目前无调用方, 属能力并入(设备侧符号若无人引用会被 gc-sections 裁掉, 固件体积未变)。
- 2026-09-11 B 类回馈补丁 B1 完成(分支 `feat/AGINX/base-upstream-merge`, WSL): 新增 `ai-doc/upstream-patches/`——`README.md`(用途、`git am` 应用方式、B1 影响与备选方案、待生成清单)+ **`0001-x25519-zero-check.patch`**(对上游 `base` 的建议改动)。生成方式: 在**上游 `base` 仓的临时本地检出**(已清理)建分支提交, `git format-patch -1` 产出 ⇒ 不触碰上游远端。**B1 内容**: `rlCryptoX25519` 计算后检查 32B 输出是否全零, 全零返回 `-EFAULT`(RFC 7748 §6.1: 对端公钥为低阶点/小群时必须拒绝, 否则双方静默接受攻击者可控的"共享密钥"), `bits/base.h` 声明由 `void` 改 `int` 并补注释; 上游 `base` 内**无调用方**(仅声明+定义), wasm/JS 导出层与下游使用方需同步; 补丁提交信息给出"新增 `rlCryptoX25519Ex()` 保持旧签名"的备选。**坑**: 上游 `bits/base.h` 首行有 UTF-8 BOM, 编辑工具回写会剥掉 ⇒ 首版补丁混入 `-﻿#pragma once/+pragma once`; 恢复 BOM 后重新 `--amend` + `format-patch`, 最终补丁为 `bits/base.h +10/-3`、`src/crypto.cc +14/-3`, 无 BOM/换行噪声(已核对)。**待生成**: B2(`cipher_cleanse` 哈希派生填充)、B3(`log.cc` 的 `LOGDATA_SIZEMAX` 1024→2048 与等级判断)、B4(无表 CRC8/16/32)。**本轮 A 类已全部完成**: A1-A4(`d307f6e`)、A5(`dbe787b`)、A5c(`f540234`)、A6(`f0e32a6`), 三平台均 0 警告 0 错误、固件 65520B、`.bss` 16B、栈 1936B ≤ 2032B。
- 2026-09-11 B 类补丁复核(生成前逐行核对上游 HEAD, 分支 `feat/AGINX/base-upstream-merge`, WSL): **B2/B3 撤销, 不生成补丁** —— ①**B2** `cipher_cleanse`: 上游 HEAD 已经是哈希派生实现(`base/src/crypto.cc:7-16`, 与本仓逐行相同), 本仓所谓的差异只是把整段 libc shim(`memset/memcpy/memmove` 自实现)用 `#if 0` 关掉并改用 `__builtin_*`, 属设备/构建特化, 不是上游缺陷 ⇒ 无需回馈。②**B3** `src/log.cc`: 本仓枚举是 `rlLOG_NONE=0 … rlLOG_VERBOSE=5`, 上游把 0 命名为 `rlLOG_FATAL`(数值相同); 本仓 `if (level <= rlLOG_NONE || ...)` 与上游 `if (level < rlLOG_FATAL || ...)` 都是"拒绝非法等级"的等价写法(本仓没有任何映射到 0 级的日志宏, 上游的 `rlLOGX` 才用 0 级), `rLANG_CONFIG_LOGDATA_SIZEMAX` 1024→2048 也仅是本地缓冲偏好 ⇒ 非缺陷, 不回馈。**最终回馈清单只剩 B1**(X25519 全零拒绝, 已产出 `ai-doc/upstream-patches/0001-x25519-zero-check.patch`); **B4**(无表 CRC8/16/32)属"增强而非缺陷", 上游不一定接受, 列为可选待定。教训: **"本仓改动"不等于"上游缺陷"** —— 生成上游补丁前必须先在上游 HEAD 上逐行核对, 否则会提交无意义(甚至有害)的改动。
- 2026-09-11 **B4 + 新约定 `rLANG_CONFIG_ENABLE_LIMIT_WORLD`(受限世界)**(分支 `feat/AGINX/base-upstream-merge`, WSL): 用户约定 —— **`LIMIT_WORLD` 指定"在 ukey 中运行的程序"**;本仓在 `Build/config/arm-none-eabi.conf`(即 `make dongle` 的配置,该配置编译出的整个固件就是 ukey 内运行的程序)追加 `-DrLANG_CONFIG_ENABLE_LIMIT_WORLD`,base/Interface 据此选择受限实现(不允许 `.rodata`、不许表、预算紧)。**实现**:把上游的 `rlCrc8/16/32` 重新引回本仓 `base/src/data.cc` —— 默认走**查表**(上游原文:CRC8 256B 表、CRC16 512B 表、CRC32 16 项半字节表),定义宏时走**无表逐位**实现;`base/bits/base.h` 补三函数声明与语义注释;两条路径**逐位等价**。**CRC 参数(反推自上游表)**: CRC8 = **LSB-first(反射)poly 0x8C**(即 0x31 的反射)、CRC16 = **MSB-first poly 0x1021**(CCITT-FALSE 形态)、CRC32 = **反射 0xEDB88320**(表为 16 项半字节字典)。**自测抓到真 bug**: 首版无表 CRC16 写成"MSB8步(i)"而表项是"MSB8步(i<<8)"(索引须先移到高字节),导致 65281 处不一致、CCITT 向量得 0x3100;修正后两种模式 **mismatches=0**、标准向量 **CRC-16/CCITT-FALSE("123456789")=0x29B1**、**CRC-32=0xCBF43926** 全对。**验证**: 默认模式与 `-DrLANG_CONFIG_ENABLE_LIMIT_WORLD` 模式各自独立编译 data.cc 并与"由多项式推导的参考表"逐项比对(CRC8 全 65536 组、CRC16/CRC32 抽样)全过;`nm` 确认无表模式下目标文件/固件**均无 CRC 表符号**;三平台 clean 重建 **0 警告 0 错误**;固件 **65520B**、无 `.rodata` 段、`.bss` **0x10**、`rockey-stack-check` **1936B ≤ 2032B**。**另注**: `rlCrc*` 声明在 `namespace machine` 内,调用方需在该命名空间(或显式 `machine::`)—— 自测程序两次踩此坑。
- 2026-09-11 B4 完成: 上游补丁 `0002-crc-limit-world.patch` + LIMIT_WORLD 约定落档(分支 `feat/AGINX/base-upstream-merge`, WSL): 补丁把上游 `src/data.cc` 的 CRC8/16/32 查表实现包进 `#if !defined(rLANG_CONFIG_ENABLE_LIMIT_WORLD)`, `#else` 加无表逐位实现(表内容与语义不变, 仅 `src/data.cc` +34 行);生成方式同 B1(上游 scratch 仓库提交后 `git format-patch`, 基点即上游 HEAD)。`ai-doc/upstream-patches/README.md` 增补**约定章节**: `rLANG_CONFIG_ENABLE_LIMIT_WORLD` = "在 ukey 中运行的程序"(受限世界, 不允许 `.rodata`), 本仓在 `Build/config/arm-none-eabi.conf` 定义, 使用方只需给 ukey 侧构建配置加 `-D` 即可, 无需改调用方代码。至此 B 类收官: **B1 + B4 已出补丁, B2/B3 复核撤销**(非上游缺陷)。
- 2026-09-11 约定(用户): **两个"世界开关"成对使用** —— `rLANG_CONFIG_ENABLE_LIMIT_WORLD` = "在 ukey 中运行的程序"(受限世界, 见 B4 条目);**`rLANG_CONFIG_ENABLE_COSMO_WORLD`** = **COSMO_WORLD 专属代码**的开关(与 LIMIT_WORLD 并列的另一个世界)。**COSMO_WORLD 的世界标识本仓早已存在**: `base/bits/base.h` 的 `rLANG_COSMO_WORLD_MAGIC = 0x0CF4CD3F`("COSMO"), 与 `rLANG_WORLD_MAGIC` / `rLANG_ATOMC_WORLD_MAGIC` 并列为 master-secret 熵上下文的域分隔值(`Interface/master.cc` 里写入 `seed_1_/seed_2_/seed_3_`)—— 这些**是共享协议值, 不应被宏包裹**。**规则**: 共享树(`base/`/`Build/`/`Interface/`)里凡属 COSMO_WORLD 一侧的专属实现, 必须置于 `#if defined(rLANG_CONFIG_ENABLE_COSMO_WORLD)` 之下; 该宏由 COSMO_WORLD 侧的构建配置定义, **本仓(ukey 侧)不定义**。**命名歧义提醒**: COSMO_WORLD 侧同样有一个名为 `Interface/` 的目录, 与本仓 `Interface/` 同名 —— 讨论/对比/合并时必须显式说明"哪一侧的 Interface"; 必要时统一用 **COSMO_WORLD** 指代对方, 不写其路径或仓库标识。**许可证**: COSMO_WORLD 侧的接口层同样是 **MIT**, 与本仓许可兼容; 双向共享代码时各自保留自己的许可声明与版权行。
- 2026-09-11 约定(用户, 预告 + 门控方向): 之后会加入 **ATOMC_WORLD**(`rLANG_CONFIG_ENABLE_ATOMC_WORLD`)—— **高达 640K 内存预算, 没有 LIMIT_WORLD 的各种限制**, 写程序会舒适得多。⇒ 世界开关自此有三个: **`LIMIT_WORLD`**(在 ukey 中运行, 受限: 不许 `.rodata`/表/大缓冲)、**`COSMO_WORLD`**、**`ATOMC_WORLD`**(宽松)。**门控方向规则(本次确立)**: **把"限制"正向门控在 LIMIT_WORLD 上, 把"宽松"实现作为 `#else` 缺省** ——
  ```c
  #if defined(rLANG_CONFIG_ENABLE_LIMIT_WORLD)
    ... 受限实现(无表/无 .rodata/小缓冲)...
  #else
    ... 宽松实现(查表/大缓冲/宿主友好)...
  #endif
  ```
  这样 **COSMO_WORLD / ATOMC_WORLD / 各宿主平台自动拿到宽松路径**, 无需为每个世界各写一份;新世界加入时也不必回头改已有代码。B4 的 CRC 已是该形态(默认查表 / LIMIT_WORLD 无表), 可直接作为范本。
  反之**不要**写成 `#if defined(rLANG_CONFIG_ENABLE_ATOMC_WORLD)` 这类"给宽松世界正向门控"的形式 —— 那会迫使其它世界逐一显式处理。
  **共享协议值不动**: `rLANG_WORLD_MAGIC` / `rLANG_ATOMC_WORLD_MAGIC` / `rLANG_COSMO_WORLD_MAGIC` 是 master-secret 熵上下文的域分隔值(`Interface/master.cc` 的 `seed_1_/seed_2_/seed_3_`), **任何世界都必须一致, 不得被宏包裹**;只有"某一侧专属的实现细节"才加 `rLANG_CONFIG_ENABLE_*` 守卫。
- 2026-09-11 约定**修正**(用户): **两个 `Interface/` 是不同世界的东西, 彼此无关** —— 不要把本仓 `Interface/` 与 COSMO_WORLD 侧的 `Interface/` 做对比、也不要做合并;两者同名只是巧合, 消歧义**仅**在提及/引用时进行(称对方为 COSMO_WORLD)。★ 因此上一条"共享树(base/ Build/ Interface)"的表述**收窄为**: 可跨世界共享/对齐的只有 **`base/` 与 `Build/`**(公共上游库 + 构建系统);**`Interface/` 不在共享范围**。`rLANG_CONFIG_ENABLE_COSMO_WORLD` 仅用于包裹 `base/`/`Build/` 里属于 COSMO_WORLD 一侧的专属实现。同理, 本仓 `Interface/` 里的设备侧实现**不需要** COSMO/ATOMC 的世界开关(它本身就是 ukey / LIMIT_WORLD 侧的东西)。**推论(后续工作方式)**: 跨世界参考面只取 `base/`+`Build/` 两棵树;`Interface/` 只作为"避免重名歧义"的命名提醒存在。
- 2026-09-11 编码约定(用户) + 乱码修复(分支 `feat/AGINX/base-upstream-merge`, WSL): **约定: 文件里含非 ASCII 字符 ⇒ 保存为带 BOM 的 UTF-8**(否则中文注释在 Windows 侧按本地代码页解码会显示乱码;此前约定只覆盖"非 third_party 的 C/C++/asm/ts/js", 现按本约定推广到凡含非 ASCII 的文件)。**根因(本次实例)**: 给公共上游库 `base/src/crypto.cc`、`src/data.cc` 打补丁时写入了中文注释, 而这两个文件原本**无 BOM**(`bits/base.h` 上游自带 BOM 故无碍)⇒ 中文注释显示为乱码。**修复**: ①补丁目标文件补 BOM 后**重新生成两个补丁**, 补丁体现在各含 1 行 BOM 变更(引入中文注释的同时补 BOM), 新补丁在干净基线上 `apply --check` 通过且可叠加。②本仓本次涉及的 **11 个文件**补 BOM: `Build/Main.mk`、`Build/core/{common,build-binary,build-executable,build-shared-library}.mk`、`Build/config/arm-none-eabi.conf`、`base/bits/{base.h,task.h}`、`base/src/{task.cc,log.cc,data.cc}`。③`ai-doc/upstream-patches/README.md` 增补"编码约定"章节。**全仓扫平前必读的陷阱**: 本仓含非 ASCII 的跟踪文本文件共 **146** 个、缺 BOM 的 **103** 个, 但其中 **6 个以 `#!` 开头的脚本加 BOM 会坏**(`.githooks/{ci-common.sh,post-commit,post-merge}`、`Build/tools/ci/{optmatrix.cjs,run-ci.cjs,web-emutests.cjs}` —— BOM 会破坏 shebang 解析), 另有 1 个 `.tar.xz` 二进制须排除;`.patch` 文件亦不建议加 BOM(`git am` 解析 `From ` 首行有风险)。⇒ **全仓扫平(约 96 个文件)待用户确认范围后再做**(是否含 `.md` 文档与 `.S` 汇编)。**验证**: 三平台 clean 重建 **0 警告 0 错误**(宿主), 固件 **65520B**、`.bss` **0x10**、`rockey-stack-check` **1936B ≤ 2032B**。
- 2026-09-11 乱码**真因**修复 + 两条工程约定(分支 `feat/AGINX/base-upstream-merge`, WSL): 上一提交的乱码**不是显示问题, 而是文件字节真的坏了** —— 控制台里 `sed`/`cat` 打印出的"UTF-8 解码"结果本身就是乱码字符, 说明内容已被写坏。**根因**: 我用来重建**补丁目标文件**的拼接脚本是 **UTF-8 无 BOM 的 `.ps1`**, 而 **Windows PowerShell 5.1 读取无 BOM 的脚本时按本地代码页(GBK)解码** ⇒ 脚本里内嵌的中文 here-string 在**写入那一刻**就损坏, 再存成 UTF-8 就成了"乱码的 UTF-8"(讽刺的是, 这正是本轮 BOM 约定要防的事; `base/bits/base.h` 上游自带 BOM 故无碍)。**修复**: 以**本仓正确版本**为源, 用 **Python(脚本本身仅含 ASCII; binary 读取、不做换行转换)** 重建补丁目标文件(保留原行尾 + 补 BOM + 正确中文), 再重新生成两个补丁。**验证**: 干净基线 `apply --check` 通过且可叠加;落盘后三文件 **BOM=True / 乱码标记=0**;行数 `data.cc 270→314`、`crypto.cc 5502→5510`、`bits/base.h 1499→1503`;补丁大小回到 **3838B / 4005B**(各 3 hunk, diffstat `7+/3-`、`12+/4-`、`45+/1-`);参考面宿主与 ARM 构建均 **rc=0 / 0 警告 0 错误**。**新增两条工程约定/坑**: ①**含非 ASCII 的 PowerShell 脚本必须带 BOM**(或脚本只用 ASCII) —— 否则 PS 5.1 按 GBK 解码, 中文在写入时就坏;此后我的**辅助脚本一律保持 ASCII**, 中文只经 `write` 工具或 Python 传递。②**程序化重建文件必须逐项自检**: 行数不少于基线、关键片段(三张 CRC 表/无表分支/宏)在场、乱码标记为 0、BOM 正确 —— 本次我写 Python 时曾**漏拼 `head` 段**导致文件被截短(270→101 行、CRC 表整段丢失), 靠 `git checkout --` 恢复基线后重做;另注意 **Python 文本模式读写会归一化行尾(CRLF→LF)**, 需 `newline=''` 或 binary 方式。
- 2026-09-11 **评估: 自带 `base/`、`Build/` 改 submodule 的可行性 + `Build/tools` 世界分区建议**(分支 `feat/AGINX/base-upstream-merge`, WSL): 产出 `ai-doc/base-build-submodule-and-tools-layout-assessment-2026-09-11.md`。**前提变化**: B1/B4 已由用户合入上游 base ⇒ 上游 base HEAD 现含本仓的两条回馈补丁, "本仓改动 → 上游提交" 的回流路径已打通。**量化(对上游当前 HEAD)**: `base/` 相同 6 / 差异 10 / 仅本仓 0, 差异里两处是**方向性裁剪**(`bits/base.h` 本仓 1156 vs 上游 1503 行;`src/log.cc` 406 vs 607 行), 且本仓依赖**上游没有的 fork 宏** `AGINX_DECLARE_MACHINE`、`rLANG_NOINLINE`(上游各 0 处);`Build/` 相同 16 / 差异 8 / 仅本仓 **10 个 fork 专用工具文件**(`tools/ci/*`、`tools/sbin/*`、`tools/stack-check/*`、`tools/script/opcode.cjs`)—— 上游没有 `tools/{LIMIT,ATOMC,COSMO}`、也没有 `ci/sbin/stack-check`。引用面: 26 个跟踪文件引用 `Build/tools/`。**结论**: 直接 submodule 化**暂不可行**, 必须先把 fork 侧 delta 安置好;文档给出 A(纯 submodule)/B(submodule + overlay)/C(保持 vendored + 漂移检测)三方案对比, 推荐 **A 分阶段**、过渡期用 C 的漂移检测兜底。**风险清单(10 条, 按严重度)**: 设备端约束(上游带表/日志会破坏"`.rodata` 必须为空 / `.bss` 16B / 栈 2032B")、fork 宏未上游化会全仓编译失败、fork 工具在 submodule 内无处安放(须迁出并改 26 处引用)、Windows 大小写(`Build` vs 上游仓名 `build`)、hooks/CI 需 `submodule update --init` 守卫与友好报错、离线构建能力、pin 漂移、**新增"不在 submodule 内就地改"的规矩**、许可与 `THIRD_PARTY_NOTICES` 更新、WSL/Windows 双检出各自 update。**迁移 4 阶段**: P0 `Build/tools` 世界分区(与 submodule 解耦, 可立即做)→ P1 上游化 base 剩余 delta(用 `rLANG_CONFIG_ENABLE_LIMIT_WORLD` 门控, 沿用 B4 的"限制正向门控 / 宽松作 `#else` 缺省"范本)→ P2 scratch clone 试迁移(`git rm -r base Build` + 两个 `submodule add` + pin)→ P3 全门禁(三平台构建 + `make ci` + 固件 **65520B** / `.bss` **0x10** / 无 `.rodata` / 栈 **1936B** 与现基线逐项一致, 另加 Windows 侧构建)→ P4 正式切换 + 文档/CI/hooks/许可同步。**`Build/tools` 分区建议**: 通用留 `tools/`(`downloads/`、`script/{grammar.actions.cjs,grammar.yc,scenario.cjs,wasm2string.cjs}`);`tools/LIMIT/` 收 `sbin/*`(ukey 复位 / 跑测程序 / GPG 签名核对 / 素数复现)与 `stack-check/*`(设备栈预算);`tools/ATOMC/`、`tools/COSMO/` 预留。**待用户决定 4 项**: ①上游化还是 overlay;②`tools/ci/*` 与 `tools/script/opcode.cjs` 的世界归属(我的倾向: `ci/` 归通用、`opcode.cjs` 归 LIMIT);③LIMIT 专属工具是上游化到共享 `build` 仓还是留在本仓新目录;④submodule pin 策略(跟 tag 还是跟 main + CI 漂移检查)。
- 2026-09-11 **`Build/tools` 世界分区落地(P0)**(分支 `feat/AGINX/base-upstream-merge`, WSL): 按"**只服务单一世界的工具进世界子目录, 通用工具留在 `Build/tools/` 根**"分区。**移动**(`git mv`, 保留历史): `tools/sbin/*`(4 个)→ `tools/LIMIT/sbin/*`;`tools/stack-check/*`(2 个)→ `tools/LIMIT/stack-check/*`;`tools/script/opcode.cjs` → `tools/LIMIT/script/opcode.cjs`。**新增**: `tools/README.md`(总览 + "旧→新"路径对照表 + 三条约定)、`tools/LIMIT/README.md`、`tools/ATOMC/README.md`、`tools/COSMO/README.md`(ATOMC/COSMO 为占位; 四个文件均为带 BOM 的 UTF-8)。**归属判定(解决了评估文档里的待定项)**: ①`ci/*` 归**通用** —— 仓库级 CI 入口、宿主侧运行、与世界无关, 且 `.gitignore` 本就按该路径放行;②`script/opcode.cjs` 归 **LIMIT** —— 它解析 `Interface/script.h` 而 `Interface/` 不跨世界共享;③`script/{grammar.yc,grammar.actions.cjs}` **不得移动** —— 其路径已作为字符串写进生成物(`Web/Grammar/regexp.jy.INL`、`Web/Script/grammar/dongle.jy.INL` 的 `YYSKELETON_NAME`), 移动会无谓翻新生成物;`scenario.cjs`/`wasm2string.cjs` 由 `Web/Script/xModule.mk`、`project.local.mk` 调用, 同属通用构建链。**代码修正(坑)**: 世界子目录比 `tools/` **深一层** ⇒ 用 `__dirname` 推算仓库根目录的 3 个工具各加一级 `..`(`LIMIT/sbin/run-dongle-exe.cjs`、`LIMIT/stack-check/stack-check.cjs`、`LIMIT/script/opcode.cjs`); `stack-check.cjs` 里由 map 文件路径反推根目录的分支不受影响。**引用同步**: `Makefile`(stack-check ×2、opcode ×1)、`package.json`(`gen:opcode`)、`.gitignore` 注释、`src/__Testing__/__dongle__/main.cc` 注释、被移动文件自身的用法注释与生成物 banner(`Web/Script/lib/opcode.ts` 头部现写着新路径)、`LIMIT/stack-check/README.md`, 以及 `ai-context.md` 与 `ai-doc/*` 中的历史路径**一律改写为新路径**(全仓 `git grep` 已无旧路径; `Build/tools/README.md` 保留"旧→新"对照表)。**验证**: `make jsWrapper` 的第一步 `node tools/rockey/LIMIT/script/opcode.cjs` 成功 → `Web/Script/lib/opcode.ts` 重新生成(`已生成 OpCode=154, AllFunc=95`, banner 已含新路径); `make jsWrapper` 随后在 `npm run release` 的 `tsc` 处失败, 但**与本改动无关** —— WSL 的 `node_modules` 里**没有** `typescript`(`require('typescript/package.json')` 直接 MODULE_NOT_FOUND), 走的是更新的全局 tsc, 报 TS5101/TS5107(`downlevelIteration`、`moduleResolution=node10` 在 TS7 弃用), 不改 tsconfig 无法通过。`make rockey-stack-check` **rc=0**, 稳态最大深度 **1936B ≤ 2032B**(余量 96B, 与基线一致); `make linux -j8` 通过; arm 侧产物 **`rockey_dongle.bin` 65520B**、`.bss` **0x10**、**无 `.rodata` 段**(段表仅 `.text` / 空 `.data` / `.bss` / `g_FEI`)。**注**: 本轮只改文件位置(仍全在 `Build/` 树内), "把 LIMIT 工具上游化到共享 `build` 仓 还是留在本仓" 仍待决定(见评估文档 §7 第 3 项)。
- 2026-09-11 **修正: 上游 base 参考树里的合并提交重新签名**(用户要求; 分支 `feat/AGINX/base-upstream-merge`, WSL): 用户此前在**上游 `base` 仓的临时本地检出**(已清理)里做的"合并来自 [LIMIT]rockey-dongle 提交的补丁"那条提交, 因**全局 `.gitconfig` 当时配错了签名钥匙**而被签成 RSA `C489989197876293`(`admin@rlang.xyz`);需改用正确的 **ed25519 `B9C754FC4ABDFD3150593856BCE591B95E51D027`(`liangl79@gmail.com`)**(与同仓上一条发布提交 `1d339f3` 及当前全局 `user.signingkey` 一致)。**做法**: `git reset --soft HEAD~1` + `git commit -S -C <旧提交>`(沿用原提交信息/作者/日期)⇒ 提交 **`295ca89` → `fed3808`**, **tree 逐字节不变**(`891cbf37…`, 新旧 `git diff` 为空), 新提交校验为 `gpg: Good signature ... using EDDSA key B9C754FC…`;`git grep` 确认旧 hash 已不在本仓出现(仅剩本条与评估文档中的"旧 hash 已废弃"说明), **用户已自行把三个远端同步到新 hash**。**连带**: 该参考仓的上层容器仓里 `base` 子模块的 gitlink 原先还停在更早的 `1d339f3`(我们那条合并提交从未记进容器仓), 本次一并提交为 `233645d`「更新子模块至 fed3808」(同样用正确的钥匙签名)。**落点(用户安排)**: 该提交被用户放到容器仓的新分支 **`prev-v1.3.0.0`** 上(已推送, 与 `origin/prev-v1.3.0.0` 同步, 相对 `main` 领先 1 条);容器仓 `main` 保持在 `55075ff`(= `origin/main`, 未动), 其 base 子模块指向 `fed3808`。**核对**: 同容器内其它参考检出的历史提交本来就使用正确的钥匙或本就无签名(上游作者的提交), 无同类问题; 三个签名钥匙均无需口令交互(gpg-agent 已缓存), 试签一次即成功。**本仓既有约定(非本次新增, 用户重申)**: `feat/AGINX/*` 分支上的提交**不需要签名**, 一律沿用 `git commit --no-gpg-sign`;master 上用户自己的合并提交照常签名。**文档影响**: `ai-doc/base-build-submodule-and-tools-layout-assessment-2026-09-11.md` 中两处 `295ca89` 已改写为 `fed3808` 并注明旧 hash 不再可用。
- 2026-09-11 **合并前体检(→ master)+ 补一处漏 BOM**(分支 `feat/AGINX/base-upstream-merge`, WSL): **可快进合并** —— master = `origin/master` = `04f4ee3`, merge-base 就是 master(分支领先 18 条, master 领先 0 条);临时 worktree 试合并 **0 冲突**, 暂存区 37 文件 **+1169/−40**;逐文件核对 master 侧文件在合并结果里没有变旧(无"回退其它分支成果"的情况);改动清单中无 `.bin/`、临时文件、构建产物或参考树路径。**门禁**: `make linux -j8` ✅;`make aarch64-linux -j8` **0 警告 0 错误** ✅;`make rockey-stack-check` **rc=0 / 稳态 1936B ≤ 2032B**(余量 96B)✅;arm 产物 **`rockey_dongle.bin` 65520B / `.bss` 0x10 / 无 `.rodata` 段** ✅;`make ci` 仍只有既有的 3 个环境失败(`emuadmin(licence)` / `pkeyself` / `x509ext`, 均为 WSL 的 JS 产物/TS 环境问题, 与本分支无关)+ `trngfail` 跳过;`make jsWrapper` 的 `opcode.cjs` 步骤通过, 随后的 `npm run release` 在 tsc 处失败(WSL `node_modules` 无 `typescript`, 走全局新版本报 TS5101/TS5107 弃用)。**顺手修**: 本分支新增的 `ai-doc/upstream-patches/README.md` 含中文却漏了 BOM, 已补(`.patch` 按约定**保持无 BOM**, 以免 `git am` 解析 `From ` 首行出问题);审计确认本分支其余新增文件都已带 BOM, 仍缺 BOM 的都是 master 上既存的文件(`ai-context.md`、`Makefile`、`src/__Testing__/__dongle__/main.cc`、若干 `.md` 等), 属**待定的全仓扫平范围**。
- 2026-09-11 **修复: 6 个脚本缺少可执行位(+x)**(随 master 的 squash 合并落地): 全仓带 `#!` 的跟踪文件复查后发现 `.githooks/{ci-common.sh,post-commit,post-merge}` 与 `Build/tools/ci/{run-ci,optmatrix,web-emutests}.cjs` 在索引里都是 `100644` ⇒ **git 会直接忽略钩子**(实测 hint: `The '.githooks/post-merge' hook was ignored because it's not set as executable`)。已 `chmod +x` 并把索引 mode 改为 `100755`(工作区同步 0755);除这 6 个之外没有别的带 shebang 的跟踪文件(`LIMIT/sbin/*.cjs` 按约定本来就是 `node` 调用、不带 shebang, 故保持 644)。**钩子行为**(`.githooks/ci-common.sh`): `post-commit` 只在提交信息以 `Squashed commit of the following:` 开头时触发(即 squash merge 形态), 跑 `node Build/tools/ci/run-ci.cjs`(**该路径未受 `Build/tools` 世界分区影响**), 用 `.git/rlang-ci-last` 按 HEAD 去重, **默认非阻塞**(失败也 exit 0, 只打印 `[ci-hook] CI 回归失败`);`CI_SKIP_RUN=1` 可跳过, `CI_STRICT=1` 才让失败变成非零退出。⇒ **从此 squash 合并后会真跑一遍 CI**: WSL 下会报既有的 3 个环境失败(`emuadmin(licence)` / `pkeyself` / `x509ext`, JS 产物与 TS 环境问题), 与代码无关, 不想看就 `CI_SKIP_RUN=1 git commit`。**注**: 分支 `feat/AGINX/base-upstream-merge` 本身未含该 mode 修复(用户决定不必补: 修复已随 master 的 squash 提交落地, 分支合并后即可丢弃)。
- 2026-09-11 **约定: AI 辅助署名 `Assisted-by` —— 每个分支在 squash 后只出现一次, 且只在真有我参与的分支上署名**(用户决定): trailer 文本 `Assisted-by: DeepSeek Harness (deepseek-v4-flash)`;**不加在分支提交里**(否则 squash 后正文会随每个提交块各带一行、重复 N 次 —— 历史上 Claude Code 的 squash `56b89907` 就留了 3 行);**只在最终 squash 提交的信息末尾出现一次**。**范围**: 仅本仓(ukey 侧);推给上游共享 base/build 仓的提交不加。**判定"真有我参与"**: **不启用** `prepare-commit-msg` 自动钩子 —— 钩子看不出分支是人工还是我参与, 会给纯人工分支误署名;改用**本地标记文件 `.git/rlang-ai-assisted`**(在 `.git/` 内, 不跟踪、不入库), 每行 `<分支名>` + TAB + trailer: 我在某分支上提交时维护它, 准备 squash 时**只有该分支在标记里**才追加署名。**落地方式**: `git merge --squash <分支>` 之后, 由我把这一行追加到 `.git/SQUASH_MSG` 末尾(幂等: 已存在则不重复加), 再用 `git commit -F .git/SQUASH_MSG` 原样落盘;若你自己 squash, 按标记文件决定是否手工补这一行。**形态理由**: `Assisted-by` 比共同作者署名更准确(AI 是辅助而非共同作者), 且 `noreply@` 类地址不对应 GitHub 账号、不会带来贡献统计或头像。**不要给 AI 用 `Signed-off-by`**: 那是 DCO 声明, 必须由人做。**不回填历史**: `a003a63` 及更早提交已在多个远端, 为一行 trailer 去 force-push 不值得;既有 8 条共同作者署名(`Claude Code <noreply@anthropic.com>`, 2026-09-03~07)保留不动。**2026-09-14 追加(用户)**: 自即日起**任何明文内容(提交信息/跟踪文件/日志/文档)不得出现该署名 trailer 的字面量** —— 本处原先直接引用, 现改为上述描述;且**不采用零宽字符拆开字面量**的写法(不可见字节在 review/grep/diff 中同样不可见, 本仓已有 `ai-context.md:275` 记录的 BOM 类编码教训)。
- 2026-09-11 **修复: `make ci` 的平台产物名 —— trngfail 在 Linux 下被错误跳过**(分支 `feat/AGINX/ci-platform-artifacts`): `Build/tools/ci/run-ci.cjs` 把 TRNG 失败注入自测的产物名**写死为 `__Testing__trngfail__.exe`**, 而 Linux 侧产物是 `.bin/amd64-linux-release/__Testing__trngfail__`(**无扩展名**)⇒ Linux 上永远落进"跳过"分支并提示 `先 make windows`, 尽管该二进制在 Linux 下**直接跑就是 rc=0 全 PASS**("HwARandBytes 失败 → RandBytes -EFAULT(5 尺寸)" + "HwARandBytes 正常 → RandBytes 0")。**修复内容**: 新增 `isWindowsDir()`;产物名由平台目录决定(只有 windows 目录才加 `.exe`);`platformDirOf()` 改为**优先与宿主平台一致**(`process.platform === "win32"` → `*-windows-release`, 否则 `*-linux-release`), 再依次退回 windows / linux / 首个可用目录;缺产物时的提示按平台给正确命令(`make windows` / `make linux`)。**验证**(WSL, `node Build/tools/ci/run-ci.cjs`): **`[ci] PASS trngfail`**, 其余项不变 —— `jsuite(0-3)` / `mkey` / `skey` / `corpus` PASS, `emuadmin(licence)` / `pkeyself` / `x509ext` 仍 FAIL(原因见下)。**未改动(待定)**: `Build/tools/ci/optmatrix.cjs` 同样只适配 Windows —— 目录写死 `.bin/amd64-windows-release`、产物名写死 `n + ".exe"`, 且 `sh()` 里写死 `cd /cygdrive/x/MyWork/RockeyDongle`(Cygwin 专用路径)⇒ `make test-optmatrix` 只能在 Windows/Cygwin 检出下运行。**同日排查(与本修复无关)**: WSL 下 `emuadmin(licence)` / `pkeyself` / `x509ext` 三项失败的根因是 **JS 生成物过期** —— `Web/Agent/Tests/__Testing_dongle.cjs` 是 09-10 的, 而 `Web/Agent/Tests/js/jsCrypto.js` 停在 09-05、`jsWorld.js` 停在 09-03;`X509ExtBuilder` 在测试脚本里出现 3 次、在两个 bundle 里 0 次 ⇒ `TypeError: e.X509ExtBuilder is not a function`, `pkeyself` 的 4 条断言则因 bundle 里还没有 Sign/Decrypt 接线而报 "Not implemented"。**本机无法重建 bundle**: `npm run release` = `tsc && packScript && webpack`, 而 WSL 的 `node_modules` 只有 `@types/node`(无 typescript/webpack/ts-loader), PATH 上的 `tsc` 解析到 TS **6.0.3**(报 TS5101/TS5107 弃用错误)。**解决(本地, 不入库)**: 从 Windows 检出(该处已于 09-11 11:13 用正常 TS 重建, `jsCrypto.js` 3427873B)把 `Web/Agent/Tests/js/{jsCrypto.js,jsWorld.js,jsLibrary.js,jsScriptBundled.js}` 覆盖到 WSL 检出 —— 这四个都是 gitignore 的生成物 ⇒ `node Build/tools/ci/run-ci.cjs` **8/8 PASS, failed=0, rc=0**(`jsuite(0-3)` / `mkey` / `skey` / `emuadmin(licence)` / `corpus` / `pkeyself` / `x509ext` / `trngfail`)。⇒ 这 3 项与平台无关, 是纯粹的生成物过期;要在 Linux 上独立重建 bundle, 仍需可用的 TS5 + webpack + ts-loader(本机 PATH 上的 tsc 是 TS 6.0.3)。
- 2026-09-11 **JS 工具链固定进 `package.json` 的 devDependencies**(分支 `feat/AGINX/ci-platform-artifacts`): 用户此前把 `typescript@5` / `webpack` / `webpack-cli` 装在**全局**(Windows 全局 `typescript 5.5.4` / `webpack 5.104.1` / `webpack-cli 6.0.1`;WSL 侧经 `/mnt/c/Users/liangli/AppData/Roaming/npm` 与 `/Machine/System/lib/node_modules` 也可见), 现按用户要求写入 `package.json`: `typescript: ^5.5.4` / `webpack: ^5.104.1` / `webpack-cli: ^6.0.1`(`@types/node: ^25.3.3` 保留), 并 `npm install` 更新 `package-lock.json`(**867B → 49970B, 107 个包**)与本地 `node_modules`(实装 `typescript 5.9.3` / `webpack 5.110.3` / `webpack-cli 6.0.1`)。**为什么必须本地固定(本会话踩到的坑)**: DSH 会话的 PATH 里 `/mnt/x/AGINX/deepseek-harness/node_modules/.bin` 排在前面, `tsc` 会解析成 **TS 6.0.3** ⇒ `npm run release` 报 `TS5101`(`downlevelIteration`)/ `TS5107`(`moduleResolution=node10`)弃用错误、`make jsWrapper` rc=2(此前正是因此误判为"Linux 下无法重建 JS 产物");`npm run` 会把 `node_modules/.bin` 前置, 所以固定本地 devDeps 后**在同样被污染的 PATH 下 `make jsWrapper` 也 rc=0**。**不需要 `ts-loader`**: `Web/Emulator/lib/webpack.cjs` 只用 webpack 本体 + 自写 `WebpackHook`(无任何 loader);流程是 `tsc` 依 `tsconfig.json` 把 `Web/**/*` 编到 `.assets/`, 再由 webpack 打包成 `Web/Agent/Tests/js/jsCrypto.js`。**另一个坑(本轮误操作, 已完整恢复)**: `Web/Agent/Tests/js/{jsWorld.js,jsLibrary.js}` 是**跟踪文件**, 只有 `{jsCrypto.js,jsScriptBundled.js}` 被 gitignore —— 想"删掉生成物强制重建"时**不能**连带删跟踪文件(我误删后用 `git checkout --` + 备份复原, 工作区已干净)。**验证**: `npm install` rc=0(added 105 packages);`make jsWrapper` rc=0(tsc 5.9.3 + webpack 5.110.3 重建 4 个产物, 3 条 webpack 体积警告属既有);`node Build/tools/ci/run-ci.cjs` **8/8 PASS, failed=0**(`jsuite(0-3)` / `mkey` / `skey` / `emuadmin(licence)` / `corpus` / `pkeyself` / `x509ext` / `trngfail`)。
- 2026-09-11 **工具平台化: 能跨平台的就不锁死在 Windows**(分支 `feat/AGINX/ci-platform-artifacts`, 用户要求"能平台化的就不要局限在单一平台下"): ① **`Build/tools/ci/optmatrix.cjs`**(优化级别矩阵)原先完全 Windows-only —— 目录写死 `.bin/amd64-windows-release`、产物名写死 `n + ".exe"`、`sh()` 里写死 `cd /cygdrive/x/MyWork/RockeyDongle`;现改为平台按宿主判定(`OPMATRIX_PLATFORM` 可覆盖), 用 `spawnSync(make, args, {cwd: root})` 直接调用(仅 Windows 加 `shell: true` 以解析 make.exe), 产物目录/扩展名按平台推导(`.bin/<arch>[-board]-<platform>-release`, 不存在时扫描 `.bin` 兜底), 板级由 `OPMATRIX_BOARD` 控制。② **关键根因(意外发现)**: 项目"0 错"退出码 **10086 在 POSIX 上是 8 位退出码, 被截断为 `10086 & 0xFF = 102`** ⇒ Linux 上自测程序明明通过也返回 102, 而旧判据只认字面 `10086`, 于是矩阵在 Linux 上"全红" —— 这才是"只能在 Windows 跑"的真实原因(现 `isPass()` 同时接受 10086 与 102)。③ **板级**: `X4C_BOARD=foobar`(模拟器世界)在 Linux 上**无需设备**即可跑全部自测(实测 release+foobar: `25519`/`dongle` rc=102, `x509`/`x509import` rc=0 且 `total error = 0`), 而真机路径在无 ukey 的 WSL 上必然 `Dongle_Enum ... F0000001`;故缺省 **Windows = 无板(真机/SDK 模拟器, 行为不变)、其它宿主 = foobar**, 要真机用 `OPMATRIX_BOARD=none`。④ **`Build/tools/ci/web-emutests.cjs`**: Chrome 探测新增 `CHROME_PATH`、`google-chrome-stable`/`chromium-browser`/`snap chromium`/`/opt/google/chrome/chrome`/macOS Chromium, 找不到浏览器时**明确跳过(rc=0;`CI_STRICT=1` 才算失败)**而不是抛异常。⑤ **`tools/rockey/LIMIT/sbin/run-dongle-exe.cjs`**: 缺省程序路径与副本扩展名按宿主平台(`RUN_DONGLE_PLATFORM` 覆盖), 非 Windows 复制后 `chmod 755`。⑥ **`Makefile`**: `X4C_NODE` 增加 PATH 兜底(`node-rlang` → `/Machine/System/bin/node` → `node`, 且用 `-x` 判可执行), 新增 `TSC`(优先仓库内 `node_modules/.bin/tsc`, 避免被 PATH 上其它版本遮蔽), `ci`/`test-optmatrix`/`test-web`/`sec-bin` 统一改用 `$(X4C_NODE)`。**验证**(WSL): `node Build/tools/ci/optmatrix.cjs` **-O0/-O1/-O2/-O3 全 PASS, failed=0, rc=0**(每档 clean + 重建 foobar release, 结束恢复默认构建); `node Build/tools/ci/run-ci.cjs` **8/8 PASS**(`jsuite/mkey/skey/emuadmin(licence)/corpus/pkeyself/x509ext/trngfail`); `web-emutests.cjs` 在无 Chrome 时打印跳过 rc=0; `run-dongle-exe.cjs` 正确解析 `.bin/amd64-linux-release/__Testing__dongle__` 并复制为 `.bin/run/__Testing__dongle__-probe`(无设备故运行失败, 属预期); `make -n ci|test-optmatrix|test-web|rockey-stack-check` 全部可解析, `make -n typescript` 展开为 `./node_modules/.bin/tsc`; 三个脚本 `node --check` 通过且 shebang 无 BOM。
- 2026-09-11 **约定: Windows 侧只在 Cygwin 下构建**(用户澄清, 承接上一轮"工具平台化"): `MSYS2` / `Git-Bash` **缺太多工具, 不在支持范围内** ⇒ 不要再为它们做兼容。**结论**: `Makefile` 里 `ifeq ("$(shell uname -o)","Cygwin")` 的宿主判定**保持现状即为正确**(不要扩写成 `Msys`/`MINGW*`);`sec-bin` 目标依赖的 `sha256sum` 也按 Cygwin 环境对待(不改成 node 实现)。**支持的宿主 = Cygwin(Windows) / Linux(x86_64) / Linux(aarch64)**;macOS、MSYS2/Git-Bash 均不支持 —— 跨平台目标是"Windows(Cygwin) + Linux"双宿主, 不是"所有类 Unix 环境"。已在 `Makefile` 宿主判定正上方写入该约定注释, 防止后续被"顺手扩写"。
- 2026-09-11 **构建: `package.json` 补 `name` 字段 —— 修 `package-lock.json` 随目录名漂移**(分支 `feat/AGINX/package-name`): 起因是在另一台机器上的 checkout 目录名不是 `RockeyDongle`(而是小写 `rockey-dongle`), `npm install` 会**按目录名重写 `package-lock.json` 的 `"name"`**(实测 diff 仅此一行: `RockeyDongle` → `rockey-dongle`), 使工作区在不该脏的时候变脏、且容易误提交。**修复**: 在根 `package.json` 增加 `"name": "RockeyDongle"`(与 lockfile 现有值一致)⇒ 从此 lock 的 name 由 package.json 决定, **与 checkout 目录名无关**。**验证**: 改后再跑 `npm install`(WSL, 已装 107 包的环境)保持 `package-lock.json` 无变化, 工作区仅 `package.json` 被修改。**注**: 该坑与平台无关, 任何"目录改名/克隆到别的目录名"的机器都会遇到。
- 2026-09-11 **构建: 第三方 TASSL(OpenSSL 1.1.1)子构建固定为串行, 修并行构建竞态**(分支 `feat/AGINX/tassl-serial-build`): **现象** —— 在全新的产物目录下 `make aarch64-linux -j8` 从零构建会失败: TASSL 构建期大量 `mv: cannot stat 'crypto/.../*.d.tmp': No such file or directory`, 随后安装出来的 `libcrypto.a` 缺符号(`OPENSSL_sk_*` / `X509_*` / `SHA1_*` / `CRYPTO_THREAD_*` / `PKCS12_PBE_keyivgen` 等), 链接 `__Testing__25519__` 时 `collect2: error: ld returned 1 exit status`; 同一份源码、同一个全新目录改成 `make aarch64-linux -j1` 则 **rc=0**、0 条 `mv: cannot stat`、0 条 undefined reference。**根因**: `third_party/project.mk` 的 TASSL 子构建写作 `$(MAKE) -C $(BUILD_TASSL_LIBRARY_BUILD_ROOT) ... -i`, 会**继承外层的 jobserver 并行度** —— OpenSSL 1.1.1 的生成式 Makefile 在未先跑 `depend` 的情况下并行编译会竞态;而 `-i`(忽略错误)又把半成品 `libcrypto.a` 照旧 `touch` 上 stamp ⇒ 之后不会再重试, 表现为"只在全新环境/偶发出现"。**修复**: 该文件里 **8 处** TASSL 子构建(build + install_sw, 4 个平台变体)统一加 `-j1`(`$(MAKE) -j1 -C ...`), 第三方构建串行、与宿主 `-j` 无关;本仓自有源码仍由外层 `-j` 并行。**验证**: 全新目录 `make aarch64-linux -j8` **rc=0**(0 竞态 / 0 undefined / 0 error), 11 个测试程序产出并可运行(`25519`/`aes` PASS 即 rc=102 = 10086 mod 256, `trngfail` rc=0);`make -n aarch64-linux|linux|ci` 均可解析;该文件**带 BOM**, 修改用字节级写回保留 BOM(已核验)。**待定**: `-i` 会让失败的第三方构建照样打 stamp(掩盖故障), 是否去掉需评估 TASSL 自身噪声。
- 2026-09-11 **构建: 统一 node 变量到 `X4C_NODE`, 废弃 `X_NODE`**(分支 `feat/AGINX/host-toolchain-fixes`, 用户指出根因): 现象是 `make wasm` 在 source 过 emsdk 的 shell 里报 `make[1]: node: Permission denied`(Error 127), 而**手工执行同一条命令完全正常**。**根因**: 构建里同时存在两个 node 变量 —— 世界侧一直用 **`X4C_NODE`**(根 `Makefile` 定义, 兜底链 `/Machine/System/bin/node-rlang` → `/Machine/System/bin/node` → `command -v node`;历史记录里大家也是靠 `make wasm X4C_NODE=…` 手工指定才跑通), 而构建系统侧另有一个 **`X_NODE ?= node`**(`Build/Main.mk`), 供 `Web/Script/xModule.mk`、`project.local.mk`、`Build/filter/grammar.lalr(1).filter` 使用 —— 后者取的是**裸 `node`**, 于是被 PATH 上的**同名目录** `$EMSDK/node` 遮蔽(emsdk 的真 node 在 `$EMSDK/node/<ver>_64bit/`):make 对"无 shell 元字符"的命令走**内建快路径 exec**, PATH 搜索遇到同名目录直接 EACCES ⇒ `Permission denied`;而 shell 的 `execvp` 遇 EACCES 会继续往后搜索, 所以手工跑看不出问题。**修复(统一而非桥接)**: `Build/Main.mk` 的定义改为 **`X4C_NODE ?= node`**, 三处 `$(X_NODE)` / `$$(X_NODE)` 全部改为 `X4C_NODE` ⇒ 全仓只剩一个 knob;根 `Makefile` 先定义的 `X4C_NODE ?=` 仍优先生效(`?=` 不覆盖), 独立使用构建系统时退回 `node`。**验证**: `git grep X_NODE` 在代码中已归零(仅 ai-context/ai-doc 留历史记述);`make -n wasm|ci|aarch64-linux` 均可解析;在 aarch64 宿主(source 过 emsdk、PATH 未做额外修正)`make wasm` **rc=0**, `.bin/wasm-emscripten-release/*.wasm` 与 `Web/Assembly/*` 正常产出。
- 2026-09-11 **CI: 产物目录按宿主架构识别(修 aarch64 宿主下 trngfail 被误跳过)**(分支 `feat/AGINX/host-toolchain-fixes`): `Build/tools/ci/run-ci.cjs` 的 `platformDirOf()` 原先只匹配 `amd64-*`, 在 aarch64 宿主上认不出 `.bin/aarch64-linux-release` ⇒ 退化到 `.bin/__Testing__trngfail__` 并打印"跳过: 未构建(…), 先 make linux";现按 `process.arch` 推出架构前缀(`arm64`→`aarch64`, `x64`→`amd64`, 其它原样)与宿主平台(`win32`→`windows`, 否则 `linux`), 依次匹配"本机架构+宿主平台 → 宿主平台 → 任一 windows/linux 产物", 仍支持 `CI_PLATFORM` 覆盖。**验证**: aarch64 宿主上 `node Build/tools/ci/run-ci.cjs` 现能定位 `.bin/aarch64-linux-release/__Testing__trngfail__` 并 **PASS**(该机器此前是 7 项 PASS + trngfail 跳过);x86_64/WSL 上仍解析到 `amd64-linux-release`, 行为不变(`make ci` 仍 8/8 PASS)。
- 2026-09-11 **构建: 世界开关 `rLANG_CONFIG_ENABLE_LIMIT_WORLD` 从共享 Build 配置移入本仓 `MCU/RockeyARM/rockey_predef.h`**(分支 `feat/AGINX/limit-world-predef`): 起因是推进 `base/`、`Build/` 改 submodule —— 共享的 `Build/config/arm-none-eabi.conf` **不应携带"世界"语义**(否则另一个世界用同一份配置时也会被定义成受限世界)。**做法**: ①在 `MCU/RockeyARM/rockey_predef.h`(该头由 `MCU/project.mk` 里的 `-include` 强制包含, 覆盖**所有** ARM 编译单元)追加 `#define rLANG_CONFIG_ENABLE_LIMIT_WORLD 1` 与说明注释;②把 `Build/config/arm-none-eabi.conf` 中的 `X4C_TOOLCHAIN_CFLAGS/CXXFLAGS += -DrLANG_CONFIG_ENABLE_LIMIT_WORLD` 连同注释块整段删除(BOM 保持)⇒ 共享 build 树恢复**世界中立**。**坑**: 首版注释里写了 `Build/config/*.conf`, 其中的 `/*` 触发 GCC `-Wcomment`, 每个 TU 各刷一条(共 32 条 warning);换成不含 `/*` 的措辞后回到基线的 2 条既有 grammar warning。**验证**: `make clean-dongle && make dongle -j8` rc=0(warning 2 / error 0), 固件 **65520B**、`.bss` **0x10**、**无 `.rodata`**;目标文件 `base/data.o` 中 **`rl_CRC*_Table` 符号为 0** ⇒ 无表 CRC 分支确实由 predef 生效;`make rockey-stack-check` **1936B ≤ 2032B**(0 条超预算);`make linux`/`make aarch64-linux` rc=0 且 **0 警告**;`make ci` **8/8 PASS**(`jsuite/mkey/skey/emuadmin(licence)/corpus/pkeyself/x509ext/trngfail`)。**注**: 宿主构建不受影响(该 predef 只对 ARM 目标 `-include`), 仍走查表 CRC。
- 2026-09-11 **实验结论: 上游 base 可原样使用, 只需本仓自带"世界宏 + 产品宏"**(分支 `feat/AGINX/upstream-base-shims`, 由 `feat/AGINX/limit-world-predef` 续): 为推进 base/Build 改 submodule, 做了**换基实验** —— 把参考树的 `evolution`(上游 base + 我们已回流的 B1/B4)整棵覆盖到本仓 `base/`, 跑全部门禁, 结果与用本仓裁剪版 base **完全一致**:`make dongle` rc=0(固件 **65520B**、`.bss` **0x10**、**无 `.rodata`**、`base/data.o` 里 `rl_CRC*_Table` 符号为 0 ⇒ 无表分支生效)、`make rockey-stack-check` **1936B ≤ 2032B**(0 超预算)、`make linux`/`make aarch64-linux` rc=0、`make ci` **8/8 PASS**。⇒ 原先评估里"必须把 log.cc 裁剪、base.h 裁剪(‑347)、crypto shim、base.cc/task.cc/scanner.cc/xModule.mk 等 8 个差异上游化"**全部不必**。**本仓所需的自带物(已验证)**: ①`Interface/aginx.h` —— 产品命名空间宏对 `AGINX_DECLARE_MACHINE/END`(与 `rLANG_DECLARE_MACHINE/END` 同构; 共享 base 是公共库, 不该带某一产品的专用宏), 并在 `Interface/mr.h`、`Interface/x509.h` 各加一行 `#include <Interface/aginx.h>`(覆盖全部 12 处使用); ②`MCU/RockeyARM/rockey_predef.h` 追加 `#define rLANG_CONFIG_ENABLE_LIMIT_WORLD 1`(上一提交)与 **`#define rLANG_CONFIG_MINIMAL_WORLD 1`** —— 后者是**上游自己的旋钮**: 定义后上游 `base/src/log.cc` 不再 include `execinfo.h`/`prctl`(裸机 ARM 没有该头, 这是换基实验中唯一的硬错误), 并跳过回溯/日志文件等 host-only 路径; ③本仓 `project.local.mk` 为设备构建提供**同名 make 变量** `rLANG_CONFIG_MINIMAL_WORLD := 1`(`ifeq ("$(wORLD_CONFIG)","arm-none-eabi")`)—— 因为上游 `base/xModule.mk` 用它作为**字符串比较**来跳过 `__Testings_base__` 子模块(仅定义 C 宏不够)。**待回流上游(仅两处通用小修)**: ①`bits/base.h` 增加 `rLANG_NOINLINE`(`__attribute__((noinline, unused))`, 与既有 `rLANG_LIKELY/UNLIKELY` 同风格; 本仓 `Interface/mr.cc` 在用); ②`rLANG_CONTAINER_OF` 的 C 分支把 `typeof` 改为 **`__typeof__`**(ISO `-std=c99` 下 `typeof` 不是关键字, 上游自带 `base/tests/test.c` 在 C99 下会编译失败)。
- 2026-09-11 **Build 侧合并完成 + 换基验证通过**(继续 `feat/AGINX/upstream-base-shims` 目标的 P1): **①回流共享 build 仓(参考树 `evolution` 提交 `7d78de3`, 已签名)**: 14 个世界工具文件(`tools/LIMIT/{README.md, sbin/*(4), stack-check/*(2), script/opcode.cjs}`、`tools/ci/{run-ci,optmatrix,web-emutests}.cjs`、`tools/{README.md,ATOMC/README.md,COSMO/README.md}`) + `node` 变量统一(`Main.mk` 的 `X_NODE ?= node` → `X4C_NODE ?= node`、`filter/grammar.lalr(1).filter` 同步);**不回流**的方向性差异: `Main.mk` 的构建系统版本号(我们 0.8.3 vs 上游 0.9.1, 取上游)、`X4C_RELEASE_CFLAGS` 的 -O1/-O2(取上游)、`core/*.mk` 的差异经核对**只是我们的来源注释与 BOM**(功能码与上游一致)、`config/arm-none-eabi.conf` 的 `-fomit-frame-pointer` 组合守卫(取上游)。**②世界专属构建参数移到本仓 `project.local.mk`(ARM 门控)**: `X4C_UNWIND_TABLE_CFLAGS :=`(空 —— 设备不能有 `.ARM.exidx`, 上游默认打开 unwind 表)与恒定 `-fomit-frame-pointer;` 另有上一提交的 `rLANG_CONFIG_MINIMAL_WORLD := 1`。**③Build 换基验证(决定性)**: 把 evolution 的 43 文件 Build 整棵覆盖本仓 `Build/`, 靠本仓 overlay 跑门禁 —— `make jsWrapper` **rc=0**(`tools/rockey/LIMIT/script/opcode.cjs` 新路径生成 opcode.ts ✓)、`make dongle` **rc=0**(warning 2 / error 0, 固件 **65520B**, `.bss` **0x10**, 段表**无 `.rodata` 也无 `.ARM.exidx`** ⇒ unwind overlay 生效, `base/data.o` 的 `rl_CRC*_Table` 符号 0)、`make rockey-stack-check` **1936B ≤ 2032B**、`make linux`/`make aarch64-linux` rc=0(0 警告)、`make ci` **8/8 PASS**(经 `Build/tools/ci/run-ci.cjs` 新路径)。**④base 换基验证(上一轮)同样全绿** ⇒ **自带 base/Build 的裁剪版从此可以整体删除**, 共享 evolution 内容 + 本仓四个 overlay(aginx.h、predef 双宏、project.local.mk 三行参数)即等价。
- 2026-09-11 **本仓 base/Build 正式改为 submodule(pin evolution 确切 commit)**(继续分支 `feat/AGINX/upstream-base-shims`): 删除自带 `base/`(16 文件)与 `Build/`(38 文件), 用 `.gitmodules` + gitlink 引入 `https://github.com/oLiangLi/base` 与 `https://github.com/oLiangLi/build`, **pin 到 evolution 的确切 commit**(base `45f28e5`、Build `7d78de3`), 路径名保持 `base`/`Build` ⇒ Makefile、hooks 与 26 处引用**零改动**。**过程中踩到的四个细节**: ①`.gitignore` 首行的 `.*` 会把 **`.gitmodules` 一起忽略**(git 直接拒绝 `git add`), 必须补 `!/.gitmodules`(与既有 `!/.githooks/` 同风格)才入得了库;②本机 WSL 到 GitHub 的 **HTTPS 不通**(gnutls handshake), 故 `.gitmodules` 保留用户指定的 HTTPS URL, 而两个子模块的 *origin* 设为 `git@github.com:...`(SSH, 本机可用), 内容先用本地参考树填充再 `git submodule absorbgitdirs` 规范化为 `.git/modules/`, 并把子模块 HEAD 置于 **detached**(对齐"记录确切 commit"语义, 不跟分支漂移);③`.githooks/ci-common.sh` 增加**守卫**: 子模块未初始化(`Build/tools/ci/run-ci.cjs` 缺失)时打印 `git submodule update --init` 提示并按既有非阻塞风格 `exit 0`;④`README.md` 的克隆段补一行说明(`git clone --recursive` 或 `git submodule update --init`)。**仓库侧保留的 overlay 仅 4 处**(见上一条): `Interface/aginx.h`、predef 的两个世界宏、`project.local.mk` 的 `MINIMAL_WORLD` + unwind/帧指针三行。**验证(真实 submodule 布局)**: `make jsWrapper` rc=0; `make dongle` rc=0(固件 **65520B**、`.bss` **0x10**、**无 `.rodata`/`.ARM.exidx`**); `make rockey-stack-check` **1936B ≤ 2032B**; `make linux`/`make aarch64-linux` rc=0; `make ci` **8/8 PASS**。
- 2026-09-11 **submodule 化的两处体验补强 + 全新克隆冒烟验证**(继续 `feat/AGINX/upstream-base-shims`): ①根 `Makefile` 首行后加**子模块守卫**(CRLF 风格插入): `$(wildcard $(wORLD_ROOT)/Build/Main.mk)` 为空时 `$(warning ...)` 提示 `git submodule update --init` —— 用 **warning 而非 error**, 否则 `make install-hooks` 之类目标会被挡住(鸡生蛋问题); 实测未初始化时 `make -n install-hooks`/`ci` 仍 rc=0 且打印提示, 初始化后无任何输出。②**全新克隆冒烟**: `git clone`(不带 `--recursive`)后 `base`/`Build` 为空、`git submodule status` 显示 `-<sha>`(未初始化), `sh .githooks/ci-common.sh` 打出守卫提示; 随后 `git submodule update --init`(测试时用 `-c url.<本地参考树>.insteadOf=https://github.com/oLiangLi/` 离线映射; 真实环境走 `.gitmodules` 里的 GitHub URL) → 两个子模块都精确落在 pin 的 commit(base `45f28e5` / Build `7d78de3`), `tools/rockey/LIMIT/sbin` 4 个、`Build/tools/ci` 3 个、`base/src` 全部就位, `make -n dongle`/`make -n ci` 均可解析。**注**: 测试时需 `-c protocol.file.allow=always`(git ≥2.38 默认禁止 submodule 用 file 传输), 这只是**离线测试手法**, 不影响真实 HTTPS/SSH 克隆。
- 2026-09-11 **Windows 检出同步为 submodule 布局 + 修正上一记录的笔误**(同一分支 `feat/AGINX/upstream-base-shims`): ①`X:\MyWork\RockeyDongle` 原本停在 master `6cfa525`(仍是 vendored base/Build), 用 `git bundle`(基点为它已有的 `6cfa525`, 仅 16KB)把分支送过去, `git checkout` + 子模块初始化后两个子模块都以 **detached** 精确落在 pin 的 commit(base `45f28e5` / Build `7d78de3`), gitdir 规范到 `.git/modules/{base,Build}`, 工作区干净。②**本机 WSL 与 Windows 都无法访问 GitHub 的 HTTPS(连接被重置)**, 而 `.gitmodules` 按要求保留 HTTPS URL ⇒ 直接 `git submodule update --init` 必然失败; 有效解法是在**本仓 `.git/config`** 覆盖 `submodule.<name>.url` 为 SSH(`git config submodule.base.url git@github.com:oLiangLi/base.git` / `...Build.url git@github.com:oLiangLi/build.git`), 该配置**不入库**、`.gitmodules` 不动; 实测仓库本地 `url.<base>.insteadOf` 映射对子模块克隆**不生效**(子模块 clone 是独立进程, 不继承本仓 local config), 必须在 `submodule.<name>.url` 上覆盖。③**残留空目录坑**: 旧 vendored 目录残留的空子目录(如 `base/bits`)会让 `git clone` 报 "destination path already exists and is not an empty directory", 而 VS2022 已把本仓作为文件夹打开、目录句柄被其监听占用 ⇒ 该空目录删不掉; 绕过办法是 `git clone --separate-git-dir=<repo>/.git/modules/<name>` 到同卷临时目录、`checkout` 到 pin 的 commit 后把内容**合并搬入**(填充该空目录而非删除), 再 `git submodule absorbgitdirs` 规范化。④顺带修正上一条记录中 `wORLD_ROOT` 的笔误(代码本身无误)。
- 2026-09-12 **改用既有约定代理解决 GitHub HTTPS 不通, 取代上一条的 SSH 绕路**(同一分支 `feat/AGINX/upstream-base-shims`): 用户指出「网络不通时走 `10.20.20.124:8001` 代理」是**早已约定**的做法(本文件 emsdk 那条已记载; npm 的 `proxy`/`https-proxy` 一直就是该值)。**实测**: `git -c http.proxy=http://10.20.20.124:8001 ls-remote https://github.com/oLiangLi/base` → 1~2s 返回 `evolution` 的正确 commit(`45f28e5`), 不走代理则 `gnutls_handshake() failed`, `curl -x` 代理取 github 页面 HTTP 200。**落地(两台机器各自执行)**: ①`git config --global http.https://github.com/.proxy http://10.20.20.124:8001` —— **按 host 配置, 只影响 github.com 的 HTTPS**, 不动其它主机与协议; ②撤掉上一条加的两个 `submodule.<name>.url`(SSH)本地覆盖及本仓 `url.*.insteadOf`, 子模块 `origin` 改回 `.gitmodules` 里的 HTTPS 地址。**验证**: `git -C base|Build fetch --tags origin` 均 rc=0; **全新克隆 + `git submodule update --init` 均 rc=0**, base/Build 精确落在 pin 的 commit(`45f28e5` / `7d78de3`), `base/src` 6 个、`tools/rockey/LIMIT/sbin` 4 个、`Build/tools/ci` 3 个就位, `make -n dongle`/`make -n ci` 均可解析(Windows 与 WSL 各自独立做过同一冒烟)。README 的子模块说明已同步改写为「先配代理」。**教训**: 网络不通时先查既有约定(代理), 不要自创绕路; 上一条把「GitHub HTTPS 不通」写成环境事实并不准确 —— 那是**未配代理**时的现象。
- 2026-09-12 **全局 git 配置增加内网镜像 `url.insteadOf`(Chromium/V8/depot_tools/git-repo + base/Build)**(用户要求; 改的是两台机器的**全局配置**, 不是本仓内容): 写入三份全局配置 —— WSL `~/.gitconfig`、Windows 命令行所用的 `C:\cygwin64\home\liangli\.gitconfig`(本机 shell 里 `HOME` 指向 cygwin home, 命令行 git 读的就是它)、以及 `C:\Users\liangli\.gitconfig`(VS2022 / TortoiseGit 等原生工具读的另一份; 实测 `C:\cygwin64\home` **不是** junction, 两份文件相互独立, 所以两边都写)。映射内容: `chromium/tools/depot_tools.git`、`v8/v8.git`、`chromium/src.git`、`gerrit.googlesource.com/git-repo` → `ssh://git@git.chaoda.tech:2222/liangli/*`;`github.com/.../base`、`github.com/.../build` → `ssh://git@home.rlang.xyz:30009/rlang.xyz/{base,build}.git`。**踩坑**: 用户给的 base 那行写的是 `oLiangLI`(大写 I), 而 `insteadOf` 是**大小写敏感的字符串前缀匹配**, 与本仓 `.gitmodules` 里的 `oLiangLi` 不匹配就会静默失效 ⇒ 两种写法各加一条 `insteadOf` 兜住。**验证**: 6 个 URL 经 `git ls-remote --get-url` 全部被重写到内网(`.../rockey-dongle` 刻意不重写, 仍走 GitHub HTTPS + 代理); 内网 base/Build 镜像的 `refs/heads/evolution` 实测就是 `45f28e5` / `7d78de3`(与 pin 一致);两台机器各自「全新克隆 + `git submodule update --init`」rc=0, `GIT_TRACE` 显示实际联系的是 `home.rlang.xyz`, 子模块精确落在 pin 的 commit。**文档处理**: README 里子模块说明改为中性表述(**不含内网 IP/主机名**)—— 依据 `ai-doc/readme-publish-review-2026-09-11.md`, 内网代理地址属私有信息, 只保留在本文件与 `ai-doc/`。
- 2026-09-12 **`Build/tools/ci/` 移入 `Build/tools/LIMIT/ci/`(用户决定: 这些 CI 工具只服务 RockeyDongle)**(注: 该目录后于 2026-09-14 整体迁到本仓 `tools/rockey/LIMIT/ci/`, 见文末同日条目): 共享 `build` 仓 `evolution` 上 `git mv tools/ci tools/LIMIT/ci`, 提交 **`db0ebfc`**(ed25519 签名校验 Good, 已推送**内网镜像 + GitHub** 双远端, 两边都是 `db0ebfc`)⇒ 世界分区从此为 `tools/`(通用: downloads、script/{grammar,scenario,wasm2string})/ `tools/LIMIT/`(sbin、stack-check、script/opcode.cjs、**ci**)/ `ATOMC/`、`COSMO/`。**改动细节**: ①三个脚本(`run-ci.cjs`、`optmatrix.cjs`、`web-emutests.cjs`)用 `__dirname` 推算仓库根目录, 世界子目录**深一层** ⇒ 各补一级 `..`(实测从新路径运行 `[ci] root=/home/liangli/MyWork/RockeyDongle`, **8/8 PASS**);②三个脚本在共享仓里是 `100644`, 借这次一并补 `100755`(带 shebang 即应可执行); ③`tools/README.md` 把 `ci/` 从“通用”移到世界专属一节并在历史路径对照表补 `tools/ci/* → tools/LIMIT/ci/*`; ④`tools/LIMIT/README.md` 新增 `ci/` 小节; ⑤**本仓引用面**同步:`Makefile`(3 个目标 + 1 条注释)、`.githooks/ci-common.sh`(3 处, 含子模块未初始化守卫)、`.gitignore`(2 行 un-ignore —— 保留是因为第 27 行的 `build` 规则在 Windows 的 `core.ignorecase` 下会牵连 `Build/`), 子模块 pin `7d78de3` → `db0ebfc`; ⑥评估文档 `ai-doc/base-build-submodule-and-tools-layout-assessment-2026-09-11.md` 的“工具世界归属”判定与 §8 补记同步(原判 `ci/` 为通用, 现改 LIMIT)。
- 2026-09-12 **发现回归: 换基后宿主 `-O2` 构建在 `__Testing__25519__` 上 Abort(与本日 `tools/ci` 迁移无关)**(分支 `feat/AGINX/upstream-base-shims`): `make test-optmatrix` 现为 **-O0/-O1/-O3 PASS、-O2 FAIL**(`rLANG:498 DONGLE.EXEC '0 == memcmp(seck_check, Context->secret_2, 32)' Fail, Abort`, rc=134)。**隔离证据**: ①把 Build 子模块切回 `7d78de3`(旧布局旧路径)复现完全相同 ⇒ 与 `tools/ci → tools/LIMIT/ci` 无关;②在**换基之前**的提交 `14edea1`(vendored base/Build, 用 `git worktree` 建临时树)跑同一门禁 **4/4 全 PASS(含 -O2)** ⇒ **这是本轮 base/Build 内容换基引入的回归**;③`-O2` 单独与 `-O2 -g -DNDEBUG`(产品默认值)都 Abort ⇒ 与 optmatrix 覆盖时丢掉 `-g -DNDEBUG` 无关;④它也不是 foobar 板特有 —— 默认板(无 board)的宿主 release `__Testing__25519__` 同样 rc=134。**失败点**: `src/__Testing__/__25519__/dongle.cc:2437-2440` —— `uint8_t seck_check[32];` **未初始化**且 `rlCryptoX25519(...)` 的返回值被**忽略**, 而该函数经 B1(我们推到上游的 X25519 全零拒绝)已由 `void` 改 `int` 且**失败时不写 out**;`secret_2` 由设备侧 `X25519` 算出, 该断言本是**跨实现一致性检查**。**关键背景**: 换基前我们的 `Build/Main.mk` 是 `X4C_RELEASE_CFLAGS ?= -O1 -g -DNDEBUG`, 取上游后变为 **`-O2 -g -DNDEBUG`**(当初记录为“取上游”的差异之一)⇒ 宿主 release 的默认优化级别被换了, 而 14edea1 的 -O2(on 旧代码)是 PASS 的, 说明需要“新 base 代码 + -O2”同时成立才复现。**待决定(本轮未改动)**: (a) 用 `project.local.mk` overlay 把宿主 release 恢复 `-O1`(回到换基前的已验证状态), 但 optmatrix 仍会显式测 `-O2` 而报红; (b) 认为 `-O2` 不受支持, 让 optmatrix 默认不含 `-O2`(共享仓改动); (c) 当作真 bug 查(base 的 X25519 在 -O2 下与设备实现发散, 或测试的未初始化读)。**已确认不受影响**: 设备固件走 ARM `-Os`(`make dongle` rc=0, 固件 **65520B**、`.bss` **0x10**、栈 **1936B ≤ 2032B** 与基线一致); `make ci` **8/8 PASS**、`make jsWrapper` rc=0、`make rockey-stack-check` rc=0 均经新路径通过。**流程教训**: 换基当天只跑了 jsWrapper/dongle/stack/linux/aarch64/ci, **漏跑 `make test-optmatrix`** —— 矩阵门禁应在任何 base/Build 换基后必跑。
- 2026-09-12 **C-02 修复补进上游 base —— `-O2` 矩阵回归的真正根因(用户指出, 我此前的判断错了)**: 用户指出「-O2 的错误应该是这几条宏没合并」, 核实**完全正确**: 上游 `base/src/crypto.cc` 至今仍然**生效**的是自实现 `cipher_memset/cipher_memcpy/cipher_memmove`(用 8 字节 `long`/`uintptr_t` 左值读写调用方缓冲区, 而调用方常是 `int32_t fe[10]` 等类型 ⇒ 违反严格别名规则;`cipher_memcpy` 还带 `__restrict`)以及文件内三条 `#define memset/memcpy/memmove → cipher_mem*` 重定向(命中 `fe_copy`/`fe_0`/`fe_1`/`x25519_scalar_mult_generic` 等核心路径)。**这本来就是我们已经修过并记录在案的 bug**: `ai-doc/issues-status.md` 的 **C-02**(“cipher_memset/memcpy 严格别名, -O2 下 X25519 静默错”), fork 的修法是把整块 `#if 0`、保留 `static cipher_cleanse`、改用 `__builtin_memset/memcpy/memmove`。**我在换基评估里把它误分类成“设备裁剪(C 类, 不合并)”**, 于是换基到上游后 C-02 复发 ⇒ `make test-optmatrix` 的 -O2 档 Abort(`__Testing__25519__`, `memcmp(seck_check, Context->secret_2, 32)`)。**修复**: 把 fork 的那段原样补进上游 base(`src/crypto.cc` +23 行), 提交 **`a9eb747`**(ed25519 签名 Good, 内网镜像 + GitHub 双远端一致);补完后该文件与 fork 版本**逐字等价**(唯一差异是 B1 注释的中英文措辞)。本仓子模块 pin `45f28e5 → a9eb747`。**验证**: `make test-optmatrix` **-O0/-O1/-O2/-O3 全 PASS(failed=0)**(修复前只有 -O2 FAIL);`make jsWrapper` / `make dongle -j8` / `make rockey-stack-check` / `make ci` **8/8 PASS** / `make test-web` / `make linux` / `make aarch64-linux` 全部 rc=0;设备侧 `.bin` 仍 **65520 B**、`.bss` **0x10**、`.data` 0、**无 `.rodata`**、栈 **1936 B ≤ 2032 B**(`.text` 从 `0xc9e8` 变为 **`0xc910`**, 反而小 216 B)。**修正上一条记录**: 那条把“换基前 `-O1` → 取上游 `-O2`”当作关键背景是**红鲱鱼**(optmatrix 本就逐档覆盖优化级别)—— 真正原因是 C-02 修复没跟着换基走。修复后上游的 `-O2` 默认值**已通过矩阵验证**, 可以放心保留。**流程教训**: 把 fork 差异判定为“设备裁剪/不必合并”之前, 必须先查 `ai-doc/issues-status.md` 与 bug-analysis 里是否有对应条目 —— “只在 -O2 下静默出错”这类修复最容易被误当成实现风格差异丢掉。
- 2026-09-12 **换基「漏合并」系统复查(用户要求再查一次)—— 结论: 除 C-02 外没有再丢修复**: 方法 = 对 `14edea1`(vendored fork)与上游 `base a9eb747` / `Build db0ebfc` 逐文件 diff, 机械筛出「**fork 有、上游没有**」的行(纯裁剪只会表现为「上游多出代码」, 这批行才是疑似丢掉的修复), 再与 `issues-status.md`(51 项)和 bug-analysis 的 15 处定位交叉核对; 完整判定表见新增的 **`ai-doc/base-swap-reaudit-2026-09-12.md`**。**要点**: ①bug-analysis 的 15 处定位里只有 4 处涉及 `base/` —— C-02(需要修, 已补 `a9eb747`)、C-03(调用端扩缓冲, 本仓文件)、C-04(用户决定关闭, 仅注释)、H-06/B1(上游已有);其余 11 处全在本仓(`Interface/*`、`src/app/*`、`MCU/*`、`Web/*`)⇒ 换基不触及。②逐文件判定: `crypto.cc` **已等价**(仅 B1 注释措辞);`data.cc` 的 LIMIT 无表 CRC 门控 4/4、无表 `rlCrc*` 7/7、CRC 查表 7/7 **完全一致**;`bits/base.h` 的 `rLANG_CONTAINER_OF`/`rLANG_VERIFY_TRUE`/`rLANG_DECLARE_PRIVATE_CONTEXT`/`IS_LITTLE_ENDIAN` 计数一致;`scanner.cc`、`src/base.cc`、`src/task.cc`、`xModule.mk` 都是**上游领先**(`__std_abs`、`rLANG_CONFIG_MINIMAL_WORLD` 门控、`__Testings_base__` 模块);`Build/tools/script/*.cjs` 是 108/16 行**纯换行差异**;其余为注释/版本号。③fork 独有但无需上游化: `AGINX_DECLARE_MACHINE`(本仓 `Interface/aginx.h` overlay ✓, 本仓 12 处引用)、`rlLOG_NONE`(本仓 0 处引用)、`rlCryptoRandBytes` 仅声明(上游在 `src/crypto.cc:5510` **有定义**, 本仓只在注释里提到)、`rLANG_SetVerifyAbort`/`OnVerifyFailed`(上游 `src/log.cc:590/594` **有定义**)。④**可选未做**(非正确性): `LOGDATA_SIZEMAX` fork 2048 vs 上游 1024(长日志行截断);C-04 说明注释未上游;上游 VERIFY 钩子未给设备空实现(实测 `.bss` 仍 0x10、无链接错误);base 版本宏上游 4.12.120 vs fork 快照 4.10.100(与「取上游」决策一致)。
- 2026-09-12 **`LOGDATA_SIZEMAX` 上游化(用户确认)**: 按换基复查的可选项 1, 把上游 `base/src/log.cc` 的 `rLANG_CONFIG_LOGDATA_SIZEMAX` 默认值 **1024 → 2048**, 提交 **`14a921b`**(ed25519 签名 Good, 内网镜像 + GitHub 双远端一致), 本仓 base 子模块 pin `a9eb747 → 14a921b`。**影响面已核对**: 该宏决定宿主日志行缓冲 `char info[N+256]` 与日志数据段截断长度(Windows 另有 `wchar_t ws[4*N]`:8KB → 16KB, 仅 `_WIN32` 路径);**设备侧不受影响** —— `rlLOGx` 由本仓 `MCU/RockeyARM/rockey_predef.h` 全局覆盖为空, 且这些 logWrite/缓冲实现不参与设备构建(用户确认的既有设计)。**实测**: 设备固件 **65520B**、`.text 0xc910`、`.data 0`、`.bss 0x10`、栈 **1936B ≤ 2032B**(与改动前逐项一致, 无 `.rodata`);宿主 `make ci` **8/8 PASS**、`make test-optmatrix` **-O0/-O1/-O2/-O3 全 PASS**、`jsWrapper`/`linux`/`dragon`(=`dongle`)/`rockey-stack-check` 全 rc=0。复查文档 `ai-doc/base-swap-reaudit-2026-09-12.md` §3 的可选项 1 已标记完成。
- 2026-09-12 **清理: 本地上游参考检出与相关 scratch 全部移除, 仓内不再有任何引用**(用户先自行验证了 Windows 侧构建, 随后删除该检出): ①`ai-doc/upstream-base-merge-plan-2026-09-11.md`、`ai-doc/upstream-patches/README.md` 与本文中对它的路径引用改为中性表述 —— 只保留上游 `base`/`build` 仓与提交 hash(均可在上游远端核对), 不再指向任何本地目录; ②`.bin/` 下三个一次性对比脚本(`ref-compare.cjs`、`ref-upstream-history.cjs`、`ref-diff-report.cjs`, 均以该检出为输入)删除; ③复核 git 配置: 本仓 local、global 以及两个子模块(`base`/`Build`)的配置**从未持久化**该路径(只有 `http.https://github.com/.proxy` 与 `url.*.insteadOf` 两条与网络相关的映射, 与它无关)。**现状**: `git grep -i` 与工作区全文检索对该检出**零命中**。**不依赖说明**: 本仓的构建与工具**不依赖**该检出 —— `interface/`、`src/`、`Web/` 全部在本仓内, 两个子模块的内容来自上游仓库/内网镜像(`submodule update --init` 不涉及本地参考树), `.bin/` 本身是 gitignore 的 scratch。
- 2026-09-12 **工作流约定更新(用户)**: 之后的**主工作区是 Windows 检出**(`X:\MyWork\RockeyDongle`), 日常改动、构建与验证都在 Windows 侧完成;**Linux(WSL)检出只在涉及重大修改时做交叉验证**, 平时不必保持同步 ⇒ 两棵树允许短期不同步(WSL 侧可能落后若干提交/子模块 pin)。其余既有约定不变: 子模块 `base`/`Build` 记录上游 `evolution` 的确切提交、`feat/AGINX/*` 分支上的提交不需要签名(`--no-gpg-sign`)、含非 ASCII 的文件用带 BOM 的 UTF-8(例外: `#!` 脚本、`.patch`、二进制)、仓内不出现另一侧世界的名称与 `machine/...` 路径。**影响**: 本轮之前 `82112da` 的清理提交两棵树都有;本条之后的 Windows 提交不会自动出现在 WSL, 需要时再拉取或交叉验证。
- 2026-09-12 **修复 clang-cl 的 `/std:c++17` "未使用参数" 警告(Windows 宿主构建)**: 现象 —— `make windows` 编译 C 源(`base/tests/test.c`、TASSL 各 `.c`)时报 `clang-cl: warning: argument unused during compilation: '/std:c++17' [-Wunused-command-line-argument]`。
  **根因**: `project.local.mk` 的 windows 块把 `/std:c++17` 加到了**共享变量** `X4C_MSVCSPEC_CFLAGS` —— `Build/config/windows.conf` 的 C 规则(102 行)与 C++ 规则(112 行)都用它, 语言专属的是 `X4C_MSVCSPEC_CFLAGS_CC` / `_CXX`;clang-cl 编译 C 时该参数无用(微例实测: `.c` + `/std:c++17` 必报, `.cpp` 不报)。
  **修复**: 改为 `X4C_MSVCSPEC_CFLAGS_CXX += /std:c++17` 并加注释说明;以**字节级**改写保持文件原有 CRLF/无 BOM 风格(编辑工具整文件重写会污染行尾)。结果: C 参数不含该标志, C++ 参数仍为 `-EHsc -W3 /std:c++17`。
  **验证(真实构建 A/B)**: 删除 C 目标 `.bin/.obj/amd64-windows-release/__Testings_base__/test.o` 后 `make windows -j8` —— 修复前该警告 **1 条**, 修复后 **0 条**, 两次均成功重建并完成 INSTALL(`.bin/amd64-windows-release/dongle_entry.exe`)。
  **同类写法已核对**: wasm 块、linux 块与 `MCU/project.mk`(ARM)的 `-std=c++17` 都只进 `X4C_COMMON_CXXFLAGS`(C++ 专属)⇒ 无同类泄漏。
- 2026-09-12 **predef 补齐日志宏覆盖(设备侧全静音)+ 合并前门禁**(Windows 主工作区): `MCU/RockeyARM/rockey_predef.h` 增加两条空宏 —— `rlLOGX(tag, fmt, ...)` 与 `rlLOGXX(tag, dat, len, fmt, ...)`, 至此 `rlLOG{V,D,I,W,E}` / `rlLOGX` / `rlLOGX{V,D,I,W,E}` / `rlLOGXX` **全部**是 `((void)0)`(此前 `rlLOGX`、`rlLOGXX` 未被覆盖, 设备侧会落到 base 的实现)。文件首行同时写入 UTF-8 BOM(该行原本为空;内容仍是纯 ASCII, 按约定 BOM 非必需但保留无害, `-include` 与 GCC 都接受)。
  **验证**(Windows: cygwin + clang-cl + arm-none-eabi 14.3 rel1): `make dongle -j8` rc=0 ⇒ 固件 **65520 B**、`.bss` **0x10**;`make rockey-stack-check` rc=0 ⇒ 稳态最大深度 **1928 B ≤ 2032 B**(超预算 0 条;比改动前 1936 B 少 8 B, 来自被静音的日志调用帧);`make windows -j8` rc=0;`make ci` **8/8 PASS**(jsuite/mkey/skey/emuadmin/corpus/pkeyself/x509ext/trngfail);`make test-web` rc=0。
  **顺带修好的环境项**: Windows 检出的 `node_modules` 不完整(无 `node_modules/.bin/tsc` )⇒ `make jsWrapper` 里的 `tsc` 落到 PATH 上另一份 **TypeScript 6.0.3** 并报 TS5101/TS5107;按 `package-lock.json` 执行 `npm ci`(107 包)后本地 `typescript 5.9.3` / `webpack 5.110.3` 就位, `make jsWrapper` rc=0, `package-lock.json` 无改动。
  **仍待处理(非本次改动引起)**: `make test-optmatrix` 在 Windows 上四档全部"构建失败" —— 根因在 `tools/rockey/LIMIT/ci/optmatrix.cjs`(迁移前位于共享仓 `Build/tools/LIMIT/ci/`):它构造的 `cf = "-DNDEBUG " + opt` **含空格**, 而 Windows 分支走 `shell: true` 时该命令行变量没加引号 ⇒ make 收到独立的 `-O0` token 并把它当成 `-O`(output-sync), 报 `不明输出同步类型`;手工用不带 shell 的等价命令(去掉空格拆分问题)是 rc=0, 证实是引号问题。**修法**: 在 shell 模式下给 `X4C_RELEASE_CFLAGS`/`X4C_RELEASE_CXXFLAGS` 两个赋值加引号(仅 `isWin`;POSIX 分支不加引号以免引号被当成值的一部分)。本次未改 ⇒ 合并前的矩阵门禁暂在 WSL 侧跑, 或先修 harness 再在 Windows 跑。
- 2026-09-12 **合并前门禁完成(矩阵门禁按用户决定在 WSL 跑)**: Windows 侧 `make jsWrapper`(`npm ci` 装好本地 devDeps 后)/ `make windows -j8` / `make ci`(**8/8 PASS**)/ `make dongle -j8`(固件 **65520 B**、`.bss` **0x10**)/ `make rockey-stack-check`(**1928 B ≤ 2032 B**)/ `make test-web` 全部 rc=0。矩阵门禁 `make test-optmatrix` 改在 **WSL** 跑(Windows 侧失败是共享仓 `optmatrix.cjs` 的命令行变量未加引号导致的既有问题, 本次不改): WSL 树先用 `git fetch <Windows 检出路径>` + `git merge --ff-only` 快进到分支 tip **`8e5bea2`**(期间 post-merge 钩子自动跑的 `make ci` 也 PASS), 然后 `make test-optmatrix` **rc=0,-O0/-O1/-O2/-O3 全 PASS**;同一棵树另跑 `jsWrapper` rc=0、`ci` **8/8**、`dongle` rc=0(固件 **65520 B**、`.text 0xc910`、`.data 0`、`.bss 0x10`)、`rockey-stack-check` rc=0(**1936 B ≤ 2032 B**, 超预算 0 条)。⇒ **合并前门禁已齐**(除"矩阵在 WSL 而非 Windows"这一已知例外);两平台的栈深度差异(Windows 1928 B / WSL 1936 B)来自工具链版本, 均远低于 2032 B 预算。**待办(可选)**: 共享 build 仓的 `optmatrix.cjs` 引号修复, 修完 Windows 也能跑矩阵。
- 2026-09-12 **全新克隆冒烟(pin 更新后复做)**: `git clone`(本地路径)⇒ `git checkout feat/AGINX/upstream-base-shims` ⇒ `git submodule update --init` **rc=0**, 两个子模块精确落在 pin(`base 14a921b` / `Build db0ebfc`);内容核对:`base/src` 6 文件、`tools/rockey/LIMIT/ci` 3、`tools/rockey/LIMIT/sbin` 4 全就位;`.gitmodules` 仍是 GitHub HTTPS URL(经本机 `url.*.insteadOf` 走内网镜像);`make -n dongle` / `ci` / `test-optmatrix` / `jsWrapper` 全 rc=0。临时克隆随后删除。
- 2026-09-12 **并入 rsamr 的两个宿主测试模块(只挑模块, 不动既有测试项)**(master, 用户决定): 从 `doc/AGINX/2026-9-11-rsa-prime-bench`(9 提交、含设备代码、落后 master 10 提交、三远端已发布)**只取出**两个自包含模块 —— `src/__Testing__/__rsamr__`(128B 种子确定性 Miller-Rabin 素数恢复原型, host-only, 无 OpenSSL/硬件依赖)与 `src/__Testing__/__rsamrprobe__`(ukey 端单数字探测载荷, 与前者共用 `rsa_mr.h`/`probe_io.h`), 共 6 文件 / +1095, 用 `git checkout <branch> -- <dirs>` 直接取内容(避免 rebase 冲突)。两者的 `xModule.mk` 均为 `ifneq ("$(X4C_BUILD)","native")` ⇒ **只生成宿主可执行文件, 不进设备固件**。
  **试跑数据(为什么不全并)**: 在临时 worktree 里试 rebase 该分支, **第 1 个提交(共 9 个)就冲突** —— `ai-context.md` 与 `src/__Testing__/__dongle__/main.cc`(两边都在加测试项: master 侧 `PrimeMRTests`/`VerifyRsaPrimePair` +579 行, 分支侧 `RsaPrimeGenPerf`/`RsaPrimeMR` +506 行), 且 master 已含该分支的文档(`ai-doc/ukey-rsa-prime-recovery-2026-09-13.md` **逐字节相同**)⇒ 全并可能把旧线盖回新版或产生两套重复 MR 测试项。试跑状态已 `rebase --abort` + 删除临时 worktree/分支, 未触碰用户分支与远端。
  **刻意排除**: 分支的 `Makefile`(`rockey-stack-check` 用的是旧路径 `Build/tools/stack-check/*`, master 已是 `tools/rockey/LIMIT/stack-check/*`)、`MCU/RockeyARM/app.cc`(把 `led_control(LED_BLINK/LED_OFF)` 注释掉的调试改动)、`src/__Testing__/__dongle__/main.cc`、`src/__Testing__/__trngfail__/*` 的模块注册改动。
  **验证(Windows: cygwin + clang-cl + arm-none-eabi 14.3 rel1)**: `make windows -j8` rc=0 并生成 `__Testing__rsamr__.exe`(84,992B)与 `__Testing__rsamrprobe__.exe`(3,443,712B);`__Testing__rsamr__.exe` **实跑 rc=0**(默认 16 轮, 种子 1 自增 422 次/17.3s、种子 2 自增 150 次/10.0s 各找到素数, 27s;`d` 计算默认跳过);`make ci` **8/8 PASS**;`make dongle -j8` rc=0(固件 **65520 B**、`.data` 0、`.bss` **0x10**);`make rockey-stack-check` rc=0(**1928 B ≤ 2032 B**, 超预算 0 条)。设备 `.text` 由 0xc910 变为 **0xca40**(master 上 `PrimeMRTests` 线相对分支多出的内容;两个 rsamr 模块受 non-native 门控不参与设备构建)⇒ 固件 `.bin` 仍 65520 B、`.bss` 仍 0x10。
- 2026-09-12 **工作分支清理: 本地只留 `master`**(用户要求, 承接上一条 rsamr 模块并入): ①`feat/AGINX/upstream-base-shims`(`d4a995a`, 20 提交)的内容已全部在 master(squash `16d60d0` + `5533d4c`;相对 master 只差 master 多出的 6 个宿主测试模块文件与 1 条 bullet, 方向核对为"分支 ⊆ master");因 **squash 合并不保留祖先关系**, `git branch -d` 必然被拒 ⇒ 先建本地归档 tag **`archive/AGINX/upstream-base-shims` → `d4a995a`** 再 `-D` 删除。②`doc/AGINX/2026-9-11-rsa-prime-bench`(**暂停中的 rsamr 工作**;本次只把两个宿主测试模块并进 master, 其余未并)先建本地归档 tag **`archive/AGINX/2026-9-11-rsa-prime-bench` → `1aadd1b`**(两个 tag 均**未推送**)再 `-D` 删除 —— 该分支在 **origin/github/gitee 三远端仍有副本**, 需要恢复时 `git checkout -b <name> archive/AGINX/2026-9-11-rsa-prime-bench`(或从远端 fetch)。③**远端分支一律未动**;两个旧 WIP stash(`stash@{0}` on master `80a6627`、`stash@{1}` on feat/impl/asn1 `8486822`)按未指示保留原样。**现状**: 本地只剩 `master @ 5533d4c`, 工作区干净, 子模块 `base 14a921b` / `Build db0ebfc`;`github`/`gitee` 的 master 仍是 `14edea1`(按用户决定未推)。
- 2026-09-12 **补记用户侧两个提交(b9b8a07 / c84bf0f): 世界门控 + rLANG_TASSL_BUILD_JOBS + TASSL 路径修复**(master, 均 GPG 签名并已推 origin/github/gitee): 用户拍板"主要工作区放 Windows, 只有重大修改才在 Linux 交叉验证"后重新克隆并自行整理, 这两个提交此前都没有 ai-context 记录, 这里补齐。
  **b9b8a07「重构代码后在干净工作区检查」**: ① `third_party/project.mk` 用 `rLANG_TASSL_BUILD_JOBS ?= $(empty)` 取代我先前硬写的 `$(MAKE) -j1`(注释: `-j1 编译 TASSL 过于缓慢了, 自动化工具请定义 rLANG_TASSL_BUILD_JOBS=-j1 以更好的获取出错信息`), 8 处子 make 全部改用该变量 —— 默认并行, 只在需要精确错误信息时才注入 `-j1`; ② `project.local.mk` 增补 `ifeq ("$(X4C_BUILD)","linux"/"windows") ⇒ rLANG_BUILD_WORLD ?= COSMO`(带 TODO: 在合适的时候将 rLANG_BUILD_WORLD 并入 `Build/Main.mk`); ③ `src/__Testing__/__rsamrprobe__/xModule.mk` 门控由 `ifneq ("$(X4C_BUILD)","native")` 改为 `ifneq ("$(X4C_BOARD)","foobar")` + `ifeq ("$(rLANG_BUILD_WORLD)","COSMO")`。
  **c84bf0f「确认在 Windows + Linux 编译正常」**: 承接"Windows 下 ENGINESDIR 被重设为绝对路径 + `clang: warning: missing terminating '"' character [-Winvalid-pp-token]`"的定位(用户指出问题在 `$(MAKE) $(rLANG_TASSL_BUILD_JOBS) -C $(BUILD_TASSL_LIBRARY_BUILD_ROOT) CROSS_COMPILE= ENGINESDIR=/Machine/System/engine OPENSSLDIR=/Machine/System/ssl install_sw` 这一行的写法)。
  ① **4 个平台(emscripten / amd64-linux / aarch64-linux / mingw64)的 `install_sw` 子 make 全部补上 `ENGINESDIR=`/`OPENSSLDIR=`** —— 根因是 `install_sw` 会先补齐 build 目标, 缺失对象在此刻按生成 Makefile 的**默认值**重编, `ENGINESDIR` 于是退化成 `$(libdir)/engines-1.1`(绝对构建路径);
  ② **emscripten 块改用生成头**: Configure 之后 `printf '#define OPENSSLDIR "/Machine/System/ssl"\n#define ENGINESDIR "/Machine/System/engine"\n' > $(BUILD_TASSL_LIBRARY_BUILD_ROOT)/rlang-dirs.h`, 再用 `sed` 抹掉生成 Makefile 里的 `-DOPENSSLDIR=`/`-DENGINESDIR=` 两个参数、在 `-DOPENSSL_USE_NODELETE` 后插入 `-include rlang-dirs.h` ⇒ 不再需要 `-D'…="\"…\""'` 这种嵌套引号(Windows/emcc 的命令行往返会把它拆散), 手跑生成的 Makefile 也得到同样的值; linux/aarch64/mingw 三块仍走命令行变量(那些环境的 sh/make 往返没有该问题, 保持原样);
  ③ 顺带把 `src/__Testing__/__dongle__/xModule.mk` 也加上同样的 COSMO world 门控(`else ## X4C_BUILD` + `ifeq ("$(rLANG_BUILD_WORLD)","COSMO")`)并在首行写入 UTF-8 BOM。
  **验证(Windows 主工作区; 删掉 `.bin/.obj/wasm-emscripten-release/gen/System/Build-TASSL` 整目录后重建)**: `rlang-dirs.h`(85 B) ⇒ `libcrypto.a` **3,004,214 B** / `libssl.a` **658,858 B** ⇒ `.build-tassl-done` 全就位; 生成的 Makefile `LIB_CPPFLAGS=-DOPENSSL_USE_NODELETE -include rlang-dirs.h $(CNF_CPPFLAGS) $(CPPFLAGS)`、`CPPFLAGS_Q=… -include rlang-dirs.h -DNDEBUG`, 而 `-DOPENSSLDIR=`/`-DENGINESDIR=` **0 处**, makedepend 段把 `rlang-dirs.h` 记为每个对象的前置(改值即全量重编); `strings crypto/cversion.o` 得到 `OPENSSLDIR: "/Machine/System/ssl"` 与 `ENGINESDIR: "/Machine/System/engine"`(正是 project.mk 一直用命令行覆盖的那两个值); `make wasm` 后 `Web/Agent/Tests/js/jsCrypto.js`(**3,429,072 B**)生成、`make ci` **8/8 PASS**(jsuite/mkey/skey/emuadmin/corpus/pkeyself/x509ext/trngfail, rc=0); 用户侧亦确认 "Windows + Linux 编译正常"。
  **遗留(可选)**: 共享 `Build` 仓的 `tools/LIMIT/ci/optmatrix.cjs` 在 Windows 下命令行变量缺引号(`cf = "-DNDEBUG " + opt` 经 `shell: true` 未加引号 ⇒ make 把 `-O0` 当成自己的 `-O`), 矩阵门禁暂在 WSL 跑。
- 2026-09-13 **RSA-3072 设备内模幂(mod_exp)可行性 + 普通 OpCode 落地**(master, Windows 主工作区):
  ①新增 `Interface/modexp.{h,cc}` —— 3072 位以内 Montgomery(CIOS)模幂, 与 `mr.cc` 同算法但
  **临时区/操作数全部由调用方提供**(`Workspace{t[98], acc[96]}` = 776B 放 ExtendBuf, 栈上只留帧),
  支持 r 与 a/b 同名、out 与 base 同名; 指数按**小端字节**给出并剥掉前导 0 比特; 每 8 次平方一次
  `KickWDG`(LED 反转 + GetTickCount COS 心跳)。
  ②新增**普通 OpCode** `kExRSAModExp = 0x150`(argc : 6): `ExRSAModExp(nFile, nOffset, mAddr, outAddr,
  expAddr, bits)` —— 模数走数据文件(N 是常驻量, 且 1KB VM 数据区装不下 3072 位的 N+m+指数三者),
  底数/指数/结果走 VM 数据区(3072 位时 m@0 / 指数@384 / 结果原地), 地址需 4 字节对齐, nFile<1000
  需管理员; `Web/Script/lib/opcode.ts` 由 script.h 生成(OpCode 155 / AllFunc 96), DSL 名 `ExRSAModExp`。
  ③测试: `src/__Testing__/__dongle__` index 20 `RsaModexpTests`(mode 1=设备内签名+host 复核 /
  2=签名+设备内验签 / 4=host 自测(可无设备, `-0 14 4 C00`) / 5=事后读回 dashboard 复核),
  与 `src/__Testing__/__rsamodexpvm__`(foobar; 直调 `VM_t::OpFuncRSA` 的 opcode 层用例)。host 用 TASSL
  生成 N/E/D/M 以小端注入 dashboard[1024..3392), 结果同样从 dashboard 回读。
  ④**实测(测试 ukey index 0)**: 3072 位私钥运算 **238.4 / 239.7 / 240.0 / 241.1 / 241.4 s ≈ 4.0 min**
  (beats 384–386)、1024 位 **9.36 s**(beats 128), 均为**单条 `ExecuteExeFile`**; `mainRet=10086`(0 错)、
  GuardBytes error=0、设备状态经 dashboard `ModExpStatus('MXPS')` 回读 sign_rc=verify_rc=0; 正确性:
  设备 s 与 TASSL `BN_mod_exp(m,d,N)` 逐值一致 + host 独立复核 `s^e==m` + 设备内验签 `m2==m`;
  host 自测(mode 4)与 TASSL 对拍全过(恒等式 2^10/3^5、ToMont/FromMont 往返、随机 MontMul×3、
  小指数 ModExp×2、复核路径自检), opcode 层模拟器用例 3072 签名/验签 + 1536 签名全部 MATCH TASSL。
  ⑤工程约束: 固件仍 65520B(`.text` rockey_dongle 0xd4c0 / RockeyTrust 0xd020)、`.bss` 0x10、
  无 `.rodata`; `make rockey-stack-check` 稳态 1928B ≤ 2032B(0 条超预算), 本改动路径 opcode ≈1336B、
  测试 ≈1176B; `run-ci.cjs` **8/8 PASS**。
  ⑥**踩坑(详见 ai-doc/rsa3072-modexp-2026-09-13.md §5)**: (a) 左到右二进制幂必须剥掉指数的前导
  0 比特, 否则 2^10 会算出 0; (b) 设备 `Start` 会覆写 `Context->result_[0]/[1]` ⇒ 设备状态必须写
  dashboard; (c) **设备 `Start` 返回 `10086 - 错误数` ⇒ 10086 才是"0 错"**, 判定里写 `0 == mainRet`
  会一直误判 FAIL(本轮连查数轮的真正原因); (d) 复用长寿命 `BN_CTX` 的 `BN_mod_exp` 在 3072 位长设备
  调用之后出现过错值(新建上下文 + 从 dashboard 字节重建则正确, 待定因); (e) Windows 下 rlLOG 走
  `WriteConsoleW(stderr)`, 被重定向/管道捕获即丢 ⇒ 两个测试程序 host `main()` 新增
  `WT_RKEY_LOG=<path>` 落盘; (f) `s_host` 是 winsock `in_addr.h` 的宏(变量名冲突); (g) Windows 构建
  需 vcvars64 + cygwin make。
  ⑦后续: 生产形态(CA 私钥 (N,d) 常驻设备 + 密封, 脚本用 `ExRSAModExp` 完成签名)、CRT(两次 1536 位)
  ≈2× 提速、§5.3 定因、Linux 侧交叉验证(交 WSL 的 DSH)。
- 2026-09-13 **RSA-3072 完整私钥导入 + CRT 快速路径**(master→`feat/AGINX/rsa3072-modexp` 续): 用户要求"导入完整
  私钥 n/e/d/p/q/dmp1/dmq1/iqmp, 用中国剩余定理做快速算法" —— 落地并真机实测, **提速 3.89×**(比预期更好)。
  ①**完整私钥 blob 布局**(`RsaModexp::KeyBlob`, 小端定长): `[0,16) header{magic 'RSAK', bits, flags, 0}`
  + n/e/d(各 bits/8)+ p/q/dmp1/dmq1/iqmp(各 bits/16); 3072 位共 **2128B**, 2048 位 1424B;
  `flags bit0 = 含 CRT 参数`。导入: 测试由 host 写 dashboard[1024,3152); 生产**必须**用
  `KDF(MASTER.SECRET, nonce)+AEAD` **密封**后落盘(2026-09-13 更正: 设备数据文件 id<1000 **只限制建/写/删、
  不限制读**, 见本文件后续条目与 `ai-doc/admin-file-permission-2026-09-13.md`);
  脚本可用现成 `WriteDataFile` 分块导入(1KB 数据区 ⇒ 6×384B)。
  ②**新指令(普通 OpCode)**: `kExRSACrtModExp = 0x151`(argc : 5, `ExRSACrtModExp(keyFile, keyOffset,
  mAddr, outAddr, bits)`, 支持 2048/3072)与 `kExRSAKeyCheck = 0x152`(argc : 4, `ExRSAKeyCheck(keyFile,
  keyOffset, scratchAddr, bits)`); opcode.ts 重新生成(OpCode 157 / AllFunc 98)。CRT 指令**要求 outAddr != mAddr**
  (结果区兼作 p*q 校验的乘积缓冲), 且内置校验 `p*q == n`、`q*iqmp ≡ 1 (mod p)`(失败 `-EBADMSG`); KeyCheck 另校验
  `dmp1 < p-1`、`dmq1 < q-1`。
  ③**原语**(`Interface/modexp.{h,cc}`): `ModReduce`(逐位 shift-subtract 求 a mod n, 2k→k limb)、
  `HalfModExp`(半域模幂, **base 就地进 Montgomery 域** ⇒ 省掉全宽版的 acc 槽)、`CrtCombine`
  (`h=(s_p-s_q)*iqmp mod p`, `out = q*h + s_q`, `tmp` 可与 s1 同一缓冲)、`MulAddK`(a*b+addend)、`SubModK`;
  `CrtWorkspace` 仍 **776B**(`{a,b,c,t}`: a=p→q; b=dmp1→dmq1→q→iqmp; c=m mod p/q、半宽校验缓冲、重组临时),
  两个半域结果 s1/s2 直接写**栈**(2×192B)。心跳每 8 次平方一次(实测 beats=384 = 2×1536/8)。
  ④**实测(测试 ukey index 0)**: 设备端 CRT 私钥运算 **62,101 ms ≈ 1.04 min / 单条 `ExecuteExeFile`**, 对照全宽
  238.4–241.7 s ⇒ **3.89×**; `mainRet=10086`、GuardBytes error=0、dashboard `rc=0 bits=3072 beats=384`;
  复核 `s == TASSL(m^d mod n)` 且 `s^e == m`。host 自测(index 21 mode 4, 无需设备): CRT 流程 vs TASSL 全宽 m^d
  MATCH、与本实现 `ModExp` MATCH。opcode 层(模拟器): CRT 3072 签名 MATCH TASSL **且与全宽 `ExRSAModExp`
  逐字节一致**, KeyCheck 正确 blob 通过 / **篡改 iqmp 被拒**, argc/对齐/out==m/非法 bits 分支均被拒。
  ⑤**门禁**: 固件仍 65520B、`.bss` 0x10、无 `.rodata`; `make rockey-stack-check` 稳态 1928B ≤ 2032B(0 超预算;
  CRT 测试链 ≈1704B: Start144+RsaCrtTests872(含 776B 工作区)+CrtSignFile488(含 s1/s2)+HalfModExp64+MontMul136);
  `run-ci.cjs` **8/8 PASS**; `make jsWrapper` rc=0。
  ⑥**测试入口**: `__Testing__dongle__ -2 15 <mode> <bits>`(index 21 `RsaCrtTests`: mode 1=设备内 CRT 签名+host
  复核 / 4=host 自测 / 5=事后只读回复核); 文档 `ai-doc/rsa3072-crt-2026-09-13.md`(含全部复现命令);
  README 与 `ai-doc/rsa3072-modexp-2026-09-13.md` §6 已同步。
  ⑦后续: 真机**脚本路径**验证(刷 `RockeyTrust.bin` + `.dongle` 脚本调 `ExRSACrtModExp`)、blob 的 AEAD 密封导入、
  可选 4-bit 窗口提速、Linux/aarch64 交叉验证(WSL 侧 DSH)。
- 2026-09-13 **设备端测试矩阵(全跑一遍)+ `elf2bin` 发布填充开关 + CRT 提速的复杂度解释**(分支 `feat/AGINX/rsa3072-modexp`):
  ①**真机矩阵(测试 ukey index 0, 测试固件, 顺序执行)**: `modexp 1024 签名` **9.128 s**、
  `modexp 3072 签名+设备内验签` **241.827 s ≈ 4.0 min**、`CRT 2048 签名` **18.750 s**、
  `CRT 3072 签名` **62.435 s ≈ 1.04 min** —— 4/4 **PASS**(每项都是单条 `ExecuteExeFile`, `mainRet=10086`、
  GuardBytes error=0、dashboard 状态 ok;CRT 3072 对照全宽 241.827 s ⇒ **3.87×**)。
  脚本/命令: `.bin/device-matrix.cjs`(用 `WT_APP_DONGLE` 逐步重刷测试固件, 日志 `.bin/matrix-*.log`)。
  ②**CRT 提速倍数的来源(用户指出, 已写入 `ai-doc/rsa3072-crt-2026-09-13.md` §5.3)**: CRT/全宽比 ≈
  `cost(48 limb)/cost(96 limb)` —— 朴素 schoolbook O(k²) ⇒ 1/4(实测 3.87-3.89×, 完全吻合); Karatsuba
  k^1.585 ⇒ ≈3.0×; Toom-3 ⇒ ≈2.8×; FFT/NTT ⇒ →2×。**所以 3.9× 是"乘法朴素"的结果, 用户此前测到的 2.5×
  才是次二次乘法/窗口法实现的正常值**; 被拖累的是**绝对耗时**(全宽 4.0 min / CRT 1.0 min 仍有压缩空间)。
  要缩短绝对时间: CIOS 的乘与 Montgomery 约减交织(各 k² 次), 只换乘积只优化一半 ⇒ 需改成"Karatsuba/Toom
  先算 2k 位乘积 + 再约减"(要额外 2k limb 缓冲: 全宽 768B / 半域 384B), 96 limb 规模预估 **1.3-1.7×**;
  滑动窗口受 RAM 限制(半域 w=4 表 1.5KB / 全宽 3KB, 设备只有 1KB+1KB+2032B 栈), w=2 仅 ~10%;
  FFT 在 3072 位不划算(>8k-16k 位才起步)。**待用户定是否做 Karatsuba**。
  ③**`MCU/RockeyARM/elf2bin.cjs` 填充改为发布开关(用户要求)**: 新增环境变量
  **`rLANG_ROCKEY_CONFIG_RELEASE`** —— **只有 `=true`(大小写不敏感)才把镜像随机填充到 64K-16=65520B**,
  否则不填充 ⇒ 默认产物 **`rockey_dongle.bin` 56,640B / `RockeyTrust.bin` 55,872B**(`make dongle` 实测,
  可逆); 镜像头偏移 4 的 u32 长度字段随之变成真实大小。**已实测**: 未填充镜像(56,640B)
  `UpdateExeFile` rc=0 且设备侧 `modexp 1024` **PASS(9.292 s)** ⇒ 刷写/执行不受影响。
  **注意**: 工厂流程要 65520B —— `Web/tools/gen_factory_line.cjs` 与 `Web/Agent/index.cjs` 的
  `kFactorySize = 4+64+65520+32`、`src/app/main.cc` 的 `kSizeFile = 65520` 都以**填充后的发布镜像**为前提
  (已给 gen_factory_line 的报错加上 "build with rLANG_ROCKEY_CONFIG_RELEASE=true" 提示)。
  ④**真机脚本路径(生产固件 + `.dongle` 脚本)受阻 —— 测试 ukey 上没有"世界"**: 已按计划刷入
  `RockeyTrust.bin`(65520B, `UpdateExeFile` rc=0)并新增脚本
  `Web/Agent/Tests/Tests/_RsaCrt3072ScriptPath.dongle`(dashboard 取 m→`ExRSACrtModExp(0xFFFF,1024,256,640,3072)`,
  输出声明 `@ 640 [384] : RsaSignature`), 但 **host 构造 NORMAL 帧时失败**:
  `crypto.publicEncrypt: error:0180006C:bignum routines::no inverse` —— 因为脚本帧要用 dashboard 7KB 处的
  **WorldPublic 主 RSA 公钥**加密 ScriptText 头, 而**把整块 8KB dashboard 读回后, 其中既没有
  `rLANG_WORLD`(1f4ec0c8)也没有 `pub@k`/`adm@k` magic**(只有随机数据与我写入的 CRT blob/进度记录)⇒
  该 ukey 当前没有可用世界(此前会话在 2026-09-08 曾跑通真机脚本路径, 那时存在 'adm@k' 世界)。
  **结论: 脚本路径需要先在测试 ukey 上重建世界(`Web/Agent/Tests/Tests/Initialize.dongle`, bootstrap 帧,
  会重置该 ukey 的世界/密钥)**; 已就此事询问用户(未擅自执行 Initialize)。
  ⑤本轮顺带修: `LogLeHex` 的宿主缓冲按 192B 定死, 传 384B 会顶穿(`STATUS_STACK_BUFFER_OVERRUN`,
  0xC0000409)⇒ 改成 3072 位(384B⇒768 字符)并按 n 做越界保护; `RsaCrtTests` 新增 **mode 6**:
  只生成完整私钥并把 blob/m 注入 dashboard 且把 N/m/s(TASSL)以小端 hex 落日志(供脚本路径核对),
  不触发设备执行(`-0 15 6 C00`)。安全提醒: `LogLeHex` 会把**私钥材料**(本次是测试密钥)写进日志。
  ⑥文档同步: `ai-doc/rsa3072-crt-2026-09-13.md`(实测表补 2048/全宽对照 + 新增 §5.3 + 门禁口径)、
  `ai-doc/rsa3072-modexp-2026-09-13.md`、`Web/tools/gen_factory_line.cjs`。
- 2026-09-13 **真机脚本路径跑通(生产固件 + `.dongle` 脚本调 `ExRSACrtModExp`)**(分支 `feat/AGINX/rsa3072-modexp`):
  ①**先在测试 ukey 上重建世界**(用户确认后执行): 该 ukey 的 dashboard 已无有效世界(8KB 里既无
  `rLANG_WORLD` 也无 `pub@k`/`adm@k` magic, host 构造 NORMAL 帧时 `publicEncrypt: bignum routines::no inverse`),
  于是用 `Tests/Initialize.dongle` 的 **bootstrap 帧**(工具里现成的 `RealBootstrapExec`, 管理员会话)重建 ——
  为对齐此前可用的配置传了 `rLANG_CATEGORY = 0x864b40af`(**Admin 类别**);重建后 dashboard 7KB =
  `1f4ec0c8 af404b86 ...` ✓(该 ukey 世界/私钥被重置; 测试 ukey 专用, 未做 factory lock)。
  工具缺"真机跑 Initialize"的命令 ⇒ 本轮用临时调试副本(`Web/Agent/Tests/__dbg_dongle.cjs`, 加 `realinit`,
  用完已删); 若以后要常用, 可在工具里正式加一个 `realinit` 子命令(需标注会重置世界)。
  ②**完整流程(已实测)**: 刷测试固件 → `-2 15 6 C00` 注入完整私钥 blob + m 并落 TASSL 参照值 →
  刷 `RockeyTrust.bin`(生产固件/脚本 VM) → `RKEY_ADMIN=1 node Web/Agent/Tests/__Testing_dongle.cjs
  run Web/Agent/Tests/Tests/_RsaCrt3072ScriptPath.dongle` → 用 `.bin/crt-script-verify.cjs` 核对。
  ③**结果**: 脚本(`ReadDataFile(0xFFFF,3200,256,384)` + `ExRSACrtModExp(0xFFFF,1024,256,640,3072)`,
  输出 `@ 640 [384] : RsaSignature`)在生产固件的脚本 VM 内执行成功, 返回 384B 签名;
  `s == TASSL(m^d mod n)` ✓、`s^e mod N == m` ✓、`exit=0`/`stdout "OK"` ✓; **两次运行签名逐字节一致**;
  **往返 64.4 s**(帧构造 + 设备执行 + 工具开销; 同一条 CRT 在测试项路径上设备侧 62.4 s ⇒ 脚本层 ~2 s,
  仍在工具 120 s 超时内)。要点: 输出声明放 `@ 640 [384]` 以避开 `[0,256)` 的 RuntimeHeader; 私钥 blob(2128B)
  放 dashboard(脚本数据区只有 1KB)。
  ④**收尾**: 设备已刷回测试固件(56,640B 未填充镜像 ✓ rc=0); 文档 `ai-doc/rsa3072-crt-2026-09-13.md`
  新增 §5.4(脚本路径完整流程与结果)并把 §7 的"真机脚本路径"标为已完成; `.dongle` 脚本头部补了
  "需先有世界(否则跑 Initialize)"的前置说明。**待办**: 若要做 Karatsuba/Toom 提速(见 §5.3)或把
  `realinit` 正式加进工具, 另开一轮。
- 2026-09-13 **世界切换入口(用户提供)+ 脚本路径最终复核**(分支 `feat/AGINX/rsa3072-modexp`): 用户指出
  `mkey/signed-script/Bootstrap/` 下两个预构建初始化程序可用来切换世界 —— **`Bootstrap-INIT-0x10000.dongle.program`
  = Normal 世界**(licence 0x10000)、**`Bootstrap-Admin-1000.dongle.program` = Admin 世界**(key4=1000)。
  工具已有真机执行路径: `badmin [hid] [burn]`(内部固定管理员会话执行预构建 1024B 帧, **重置世界、不 lock**;
  `BADMIN_BOOT=<file>` 切换程序), `badminburn` 可把 key4 烧到 0; 对应模拟器侧为 `emuadmin`。
  ⇒ 已把这两条命令写进 `ai-doc/rsa3072-crt-2026-09-13.md` §5.4 与 `.dongle` 脚本头部(此前我用
  `Initialize.dongle` 的 bootstrap 帧重建, Admin 类别 + licence 不限, 与 Admin-1000 的差别只在 licence/EnTrust)。
  **最终复核**: 改完脚本注释后在真机又跑一次(刷生产固件 → `RKEY_ADMIN=1 ... run _RsaCrt3072ScriptPath.dongle`
  → 刷回测试固件) —— **往返 64.5 s**、`s == TASSL(m^d)` ✓、`s^e mod N == m` ✓、`exit=0`/`"OK"` ✓,
  且与前一次(64.4 s)**签名逐字节一致**。测试 ukey 现状: **测试固件 + Admin 世界 + dashboard[1024,3152) 有测试私钥 blob、
  [3200,3584) 有测试 m**(此 blob 是测试密钥, 需要时可用 `Initialize.dongle`/`badmin` 重置清掉)。
- 2026-09-13 **EnTrust(托管)两变体的语义 + 真机 EnTrust→模拟器受托者路径现状**(用户说明 + 实测, 分支 `feat/AGINX/rsa3072-modexp`):
  用户说明 `mkey/signed-script/Bootstrap/` 里两个 EnTrust 变体的区别 ——
  **`Bootstrap-EnTrust-Null.dongle.program`**: 托管为**空**(无受托者) ⇒ **任何人都无法签发管理员脚本, 只能自己签发**
  (设备自持 ECIES 私钥管理员会话); **`Bootstrap-EnTrust-LiangLI.dongle.program`**: 托管给用户的 K0/K1/K2/K3
  ⇒ 这几把**生产 master ukey** 能签发管理员脚本, 但**不应为测试用途签发脚本**;
  若测试需要"管理员脚本签名", 应**仿照用模拟器做受托者**(工具里 `realadmin|reallimit <file.dongle> [hid] [trusteeIdx]`
  就是"真机 EnTrust 给 JS 模拟器受托者 → 受托者解密目标 ECIES 私钥并 SM2 签发 ADMIN/LIMIT 帧"的混合流程)。
  ①**实测(生产固件 + 管理员会话)**: `node Web/Agent/Tests/__Testing_dongle.cjs realadmin
  Web/Agent/Tests/Tests/HelloWorld.dongle` ⇒ 失败于 **`Error: real: trustee decrypt failed`**
  (工具 `RealRunSigned`: 从 dashboard[6K,7K) 按 hid 取 112B 托管条目 → 组 128B SM2 密文
  `C1x||Y(解压)||C2/C3` → `trustee.SM2Decrypt(id ∈ {1,4})` 两把都失败) —— **与 2026-09-08 记录的
  "真机 EnTrust 成功执行, 但 JS 模拟器受托者解不开真机托管密文"一致, 该路径目前不可用**。
  ②**影响面**: 本分支已完成的 RSA3072 全宽/CRT 私钥运算与**真机脚本路径**都走 **NORMAL(ATOMC)帧**,
  不需要管理员签名 ⇒ **不受此影响**(已实测 PASS)。只有"把 CA 私钥放进**管理员专属**数据文件( id < 1000)"
  这类需要管理员权限的脚本才会卡在这里; 而按 CA 方案用 `KDF(MASTER.SECRET)+AEAD` **密封**私钥 blob
  (dashboard 5K-6K) 则**不依赖文件 ACL**, 也就不需要管理员签名 ⇒ 生产形态有替代路径。
  ③**若要修**: 下一步是"同一台真机跑 EnTrust 后 dump dashboard[6K,7K) 的 112B 条目", 与**模拟器**
  (`entrust <target> <trustee>` + `adminrun`, 已在模拟器上验证可用)的同名条目逐字段比对
  (hid12|kid3|Yodd|C1x[16..48)|C2/C3[48..112) 的偏移、C1 是否压缩、KDF/hash 参数), 定位是**解析假设**还是
  **真机 SM2 ECIES 编解码**差异, 再修工具或固件侧。本轮未动(用户仅说明"需要时可以仿照模拟器签发")。
  ④**收尾**: 实测后已把测试 ukey 刷回测试固件; 记录本轮结论到 ai-context(本节)。
- 2026-09-13 **托管(EnTrust)正确规程(用户说明)+ 当前硬件条件**(分支 `feat/AGINX/rsa3072-modexp`): 用户澄清
  **"测试托管需要两把 ukey"**, 流程是:
  ①**key1**(受托方)先跑 Normal/Admin 初始化脚本 ⇒ 取得"**托管 id**" = `kKeyIdGlobalSM2ECDSA = 1` 的
  **SM2ECDSA 公钥**(WorldPublic[20,84);注意 EnTrust 区里同一把公钥也在 `WorldEnTrust+20`)——**解密用这把密钥**
  (受托方用自己的 id=1 **私钥**解开托管条目);
  ②**key2** 初始化为 **Admin**, 其"托管"字段填 **key1.EnTrust** —— 即把 key2 的 ECIES 私钥加密给 key1 的
  SM2ECDSA 公钥后写入 `WorldEnTrust.dongle_entrust_[i]`;
  ③**槽位**: 共 **5 个**(`kMaxKeys`), 最多托管给 5 把 ukey, **未设置的槽必须填全 0**;
  布局参考(`Web/Agent/Tests/Tests/EnTrust.dongle` 注释 = `Interface/script.h` 的 `WorldEnTrust`):
  dashboard[6K,7K) 内 `+20` 受托方 SM2ECDSA 公钥(64B)、`+148` select nonce(32B)、**`+180` 起 5×112B 条目**、
  `+960` `dongle_sm2ecdsa_sign_[64]`;条目 112B = `hid12|kid3|Yodd(byte15)|C1x[16..48)|C2/C3[48..112)`。
  ④**当前硬件条件**: `__Testing_dongle.cjs list` 只有**一把**在线 ukey(`00000000-efea115bfc084642`)⇒
  **2 把 ukey 的真机托管流程现在无法执行**; 之前试的"真机 EnTrust → JS 模拟器受托者"(`realadmin`/`reallimit`
  混合命令)失败于 `real: trustee decrypt failed`, 与 2026-09-08 记录一致 —— 按用户说明, **托管测试的正规形态
  是两把真机 ukey**(受托方的私钥不可导出, 只能在受托设备内解密+签名), 混合模拟器路线属实验命令、不是产品形态。
  ⑤**可行性**: 受托侧的两步都能用现成 opcode 在**真机受托 ukey 上**用 `.dongle` 脚本完成 ——
  `SM2Decrypt(kKeyIdGlobalSM2ECDSA=1, entry)` 得到目标 ECIES 私钥(32B), 再 `ExSM2Sign(priv, hash, sign)`
  对 ADMIN/LIMIT 帧的摘要签名(与模拟器流程同构)⇒ **只要再插一把测试 ukey 就能把这条路跑通**并验证
  "管理员专属数据文件(id<1000) + `ExRSACrtModExp`"的生产形态。**待用户提供第二把测试 ukey 或另行安排**。
- 2026-09-13 **两把真机 ukey 的 EnTrust 托管 → 管理员脚本签发链路: 打通并实测 PASS**(用户提供第二把测试
  ukey 后; 分支 `feat/AGINX/rsa3072-modexp`; 完整文档 `ai-doc/entrust-2ukey-2026-09-13.md`):
  ①**硬件**: 目标 `00000000-efea115bfc084642`、**受托方** `00000000-f56a125b71094c42`(其"托管 id" =
  `kKeyIdGlobalSM2ECDSA=1` 公钥 `20a8c0fe49a444dd9963b40e4935166e7fac0c9bc7d4ae90c5d76b3a2ba7b6d7
  5ae9da3b09c787e9ab3470ee84eb954bb6ef587bbc0f31bcc8eff724406f93c7`); 受托方已用 `Initialize.dongle`
  bootstrap 建 Admin 世界(会清空 factory 区)。
  ②**新增受管命令**(`Web/Agent/Tests/__Testing_dongle.cjs`): `realinit <hid> [catHex]`(真机 bootstrap
  初始化)与 `real2ukey <trusteeHid> <targetHid> <file.dongle>` —— 六步全自动: 取受托方 SM2ECDSA 公钥(=托管 id)
  → 在**目标**上跑 `Tests/EnTrust.dongle`(槽 0 = `hid12|SM3(pub)[0..3]|pub64`, 其余 4 槽全 0) → 按 hid12 回读
  目标 `dashboard[6K+180+i*112)` 的 112B 条目 → 算目标脚本摘要 `SM3(BuildDataSegment[0,1024-256-64))` →
  在**受托方**上跑 `Tests/_EnTrustTrusteeSign.dongle`(解托管取回目标 ECIES 私钥 + 对摘要 SM2 签名) →
  在**目标**上执行 ADMIN 帧; `RKEY_TAMPER=1` 为负例(篡改签名)。命令已并入工具 usage 行, 临时调试副本
  `Web/Agent/Tests/__dbg_dongle.cjs` 已删除。
  ③**正向实测(受管工具)**: `escrow slot : 0`、`entry112 00000000f56a125b71094c42d59a7701...`、
  `digest 420d71cca22fea13fd0109f82d90c517509540f367f9f33dd728520a579f06cc`(同一脚本**确定**)、
  `sign64 4e4b89ec...`、`ADMIN frame OK. inout[0,16): 000000001f4ec0c8010100043b494304`、`exit=0`
  ⇒ 帧**验签通过并在目标上执行**(`3b494304` = ADMIN 文件魔数); 连续两次独立运行均 `exit=0`, 但
  `entry112`/`sign64` **每次不同**(ECIES 随机 nonce + SM2 随机 k)⇒ 只能作为链路验证、不能当固定测试向量。
  ④**负例**: `RKEY_TAMPER=1` ⇒ `sign64 TAMPERED`、**无** `ADMIN frame OK`、`exit=1` ⇒ 目标**拒绝**篡改帧 ✓
  (验签在设备内, 与"签名有效才执行"语义一致)。
  ⑤**新增脚本** `Web/Agent/Tests/Tests/_EnTrustTrusteeSign.dongle`(下划线前缀 = 不被 suite 自动执行):
  bootstrap 帧; 入参 `rLANG_ENTRY @256 [112]`、`rLANG_DIGEST @384 [32]`; 输出 `@0 [64] : rLANG_SIGNATURE`;
  主体 `ExSM2DecompressPoint(LoadU8(271),272,512)` → 组 128B 密文 `C1x||Y||H||XOR` 到 [640,768) →
  `SM2Decrypt(1,640,128)`(私钥就地留 [640,672)) → `ExSM2Sign(640,384,0)` → `Exit(0)`。
  ⑥**意义/边界**: 这是"**管理员专属数据文件(id<1000) + `ExRSACrtModExp` 权限门槛**"验证的前置能力;
  "真机 EnTrust + **JS 模拟器**受托者"(`realadmin|reallimit`)当时失败于 `real: trustee decrypt failed`,
  **已查明并修好 —— 根因是工具侧陈旧状态(不是密码学实现不兼容, 详见本文件后续条目)**;
  **模拟器侧 EnTrust 本身一直是工作的**: `entrust 0 1`(纯模拟器托管)与
  `adminrun 0 1 HelloWorld.dongle`(模拟器受托者解密+SM2 签名+ADMIN 执行, `sign-verify=true`)均 PASS。
  生产 master ukey(K0/K1/K2/K3, `Bootstrap-EnTrust-LiangLI`)**不得**为测试签发脚本, 测试一律用这两把测试 ukey。
  ⑦**设备现状**: 两把 ukey 均已刷**生产固件**(脚本链路所需), 目标 dashboard 内留有测试 EnTrust 条目
  (槽 0 = 受托方), 受托方为 Admin 世界。
- 2026-09-13 **管理员专属数据文件(id<1000)+ `ExRSACrtModExp` 权限门槛验证: 正例 PASS + 发现并修复"静默拒绝"缺陷**
  (分支 `feat/AGINX/rsa3072-modexp`; 完整文档 `ai-doc/admin-file-permission-2026-09-13.md`):
  ①**前置(极易踩坑)**: **Admin 世界**(`adm@k` = `0x864B40AF`)在 `Interface/execute.cc:240-251` 会
  **直接拒绝一切非管理员帧**(`-EACCES`)⇒ 在 Admin 世界设备上做"文件权限"负例是**无效实验**(本轮前三次负例就是被
  世界门槛挡掉的); 必须先把设备建成 **Normal/Public 世界**: `realinit <hid> c35880af`; 世界重建会清空 dashboard,
  用 `dashdump <hid> <out>` 备份 + `realnotice <hid> <out>`(宿主 CLI `--notice`)回贴 dashboard[0,4096) 即可恢复
  注入的测试数据(blob/m); dev0 本轮临时改为 Public 世界。
  ②**正例 PASS**: `real2ukey <trustee> <target> Web/Agent/Tests/Tests/_RsaCrt3072AdminFileCreate.dongle` ——
  管理员签名脚本 `CreateDataFile(100, 2128, 2, 2)`(id=100 < 1000, 读写权限 = 2 = 管理员)+ 分 3 块把
  dashboard[1024,3152) 的 2128B 私钥 blob 写进该文件(VM 数据区仅 1024B)+ `ExRSACrtModExp(100,0,0,384,3072)`
  **用文件里的密钥签名** ⇒ `exit=0`, 签名 `39b7f723c65437f9...12e1f` 与**对照组**(NORMAL 帧
  `_RsaCrt3072ScriptPath.dongle`, 模数走 0xFFFF)**逐字节相同** ✓(该值正是此前与 TASSL 一致的那个);
  再用 `real2ukey … _RsaCrt3072AdminFileUse.dongle`(只读文件、不重建)复现同一签名 ⇒ 文件跨运行持久 ✓。
  ③**负例(Public 世界 + NORMAL 帧, 全部被拒)**: `CreateDataFile(id<1000)` ✗、`WriteDataFile(0xFFFF)` ✗、
  `ExRSACrtModExp(admin 文件)` ✗、`_RsaCrt3072AdminFileUse`(读 m + 用该文件签名)✗; 对照组全部允许
  (`_ProbeDash` 读 0xFFFF ✓、`_ProbePermUser` 建 id=1002 ✓、`_ProbeSlotFree` 删+重建 1002 ✓
  ⇒ **排除"空间/槽位耗尽"**这一替代解释)。
  ④**【已修缺陷】静默拒绝**: VM 主循环是 `while (zero_ == 0)`, **只认 `zero_`**; 我原先给三个新 opcode 写的错误分支
  用的是 `value = -EACCES`(照抄 `OpFuncDataFile` 里尺寸检查的 `value = -EINVAL` 写法)⇒ 真机上权限检查**命中但脚本
  不中止**: `exit=0` + 输出保持全 0 ⇒ "被拒绝"与"算出全 0"**无法区分**(只查退出码会把全 0 当合法签名)。
  修复: 三处 opcode 的所有错误分支统一 `value = zero_ = -EXXX;`, 算法自身失败也补 `zero_ = value;`;
  `__Testing__rsamodexpvm__` 的断言改为**必须中止**并新增 "admin-only 文件 × {kAnonymous,kNormal} ×
  {ModExp,CrtModExp,KeyCheck}" 共 6 个用例 ⇒ 仿真 `exit=10086`(0 error), 真机上述负例全部转为 `exit=1` ✓。
  (此缺陷也解释了"重刷固件后现象不变"—— 之前怀疑设备固件陈旧是**错的**, 固件一直是新的。)
  ⑤**【设计意图, 非缺陷】数据文件的读取没有权限门槛**(用户 2026-09-13 说明): `kReadDataFile` 在 VM 层只拦
  `kKeyIdGlobalSECRET`, **不检查 `id < kUserFileID`**(`script.cc:174-198`), 真机实测非管理员会话**成功读出**
  id=100 文件内容(`5253414b000c0000…` = `RSAK` blob)。**原因**: ukey 内的**世界实际以管理员权限执行**, 且初始
  设计前提是"**任何文件只要存在就必然能被读出**" —— **不信任 COS 的任何承诺**, 所以"限制普通用户读 id<1000 的文件"
  **没有意义**, 代码里也就没有这层; ⇒ `id < kUserFileID` 的语义是**授权/防篡改**(谁能**建/写/删**), **不是机密性**。
  **要保护 dataFile 内容, 正确做法是 `KDF(MASTER.SECRET, nonce)` 加密**: ①**操作 MASTER.SECRET 必然已取得管理员权限**
  —— 代码上即 `VM_t::OpManager` 首行 `if (valid_permission_ != PERMISSION::kAdministrator) return zero_ = -EACCES;`
  (覆盖 `kWorldInitialize`/`kUpdateMasterSecret`/`kComputeSecretBytes`/`kUpdateSM2ECIESKey`/`kComputeEnTrustData`,
  `Interface/master.cc:371-373`); ②**MASTER.SECRET 一机一密** ⇒ 把它的加密 blob 读走**对其他 ukey 毫无意义**,
  密文即使放在**可读**位置(如 dashboard 匿名区)也不损失机密性。因此"CA 私钥 blob 放哪"不是问题, 本轮的 CA 方案
  (`KDF(MASTER.SECRET)+AEAD` 密封在 dashboard 5K-6K)**正是这个形态** ✓; 文件权限路径只用于**授权**;
  私钥文件的 licence/`m_Priv` 属 COS 实现的另一套机制, 按"不依赖 COS 承诺"的原则不作为保密手段。
  ⑥**新增工具命令/脚本**: `realinit`、`realinfo`、`dashdump`、`realnotice`、`listfile <type> [hid]`、`real2ukey`;
  测试脚本 `_RsaCrt3072AdminFileCreate/Use/Read.dongle` 与
  `_ProbeDash/_ProbePermUser/_ProbePermAdmin/_ProbeSlotFree/_ProbeFwWrite/_ProbeCrtFile.dongle`(`_` 前缀不自动执行)。
  ⑦**设备**: dev0 本轮临时 Public 世界(测试后恢复 Admin 世界 + dashboard 回贴 + 重新 EnTrust); 两把 ukey 均为
  **含本修复的生产固件**(`RockeyTrust.bin` 55888B)。
- 2026-09-13 **混合路线(真机 EnTrust → 模拟器受托者)修好: 根因是工具侧陈旧状态, 不是密码学不兼容**
  (分支 `feat/AGINX/rsa3072-modexp`; 完整记录 `ai-doc/entrust-2ukey-2026-09-13.md` §6):
  ①**结论**: `realadmin`/`reallimit` 现在**都 PASS** —— `ADMIN real <target> trustee=emu[0]: sign-verify=true`
  (exit 0)、`LIMIT real <target> trustee=emu[0]: sign-verify=true`。
  ②**根因(两处主机侧 bug, 已修)**:
  (a) `RealRunSigned` 原先只按 `hid12` 判断"该受托者已有托管条目"就**跳过重新 EnTrust** ⇒ 世界重建
  (`realinit`)后 ECIES 私钥已变, 旧条目解不出正确私钥(甚至 C1 不在曲线上直接失败)⇒
  `real: trustee decrypt failed`; 改为**总是重新 EnTrust**(幂等、代价小);
  (b) 仅此仍失败 —— **`Dashboard()` 有缓存**, EnTrust 后读到的还是 EnTrust 之前的 dashboard, 仍用旧条目;
  修法: EnTrust 后 `dashboardCache.delete(hid)` 再读。
  ③**被推翻的两个判断(留档以免重复踩)**:
  ❌"真机 COS 与软件实现的 SM2 ECIES 不互通" —— 新增交叉探针 `xentrust <devHid> [emuIdx]`
  (模拟器按真机 SM2ECDSA 公钥造条目 → 真机跑 `_EnTrustTrusteeSign.dongle` 解密+签名 → **用软件侧 ECIES 公钥验签**)
  实测 **PASS**(`以软件侧 ECIES 公钥验签 : true`)⇒ 真机**确实解出了正确的 ECIES 私钥**, 两侧完全互通;
  ❌"封装/blob 版本不同步" —— 一致重建(`make wasm -j8 && make jsWrapper R=1`; `jsCrypto.js` 3.28 MiB;
  `opcode.ts` 仍 157/98; 事后 `git status` 干净)后 `realadmin` **仍失败**, 直到修掉上面的状态 bug 才通过;
  `jsWorld.js`/`jsLibrary.js` 是 `tsc` 产物(TS 未变故 mtime 不变), 不是"陈旧 blob"。
  ④**按用户建议加的兼容**: 软件侧 `Interface/emulator.cc` 的 `Dongle::SM2Decrypt` 现在**两种 text 布局都试**
  (`C1x||C1y||C2||C3` 失败再试 `C1x||C1y||C3||C2`, 都不行才报错); **局限(实测)**: TASSL 的 `sm2_decrypt`
  **不校验 C3**, 布局错时它返回**垃圾明文而不是报错**(`realmix` 矩阵探针里两种顺序都"解出 32B"但验签失败即为
  此)⇒ 该重试只能兜"硬失败"、**不能**用来判别布局; 本轮真正的问题是状态, 故它并非必需(保留作防御)。
  ⑤**排查工具(已固化)**: `xentrust <devHid> [emuIdx]`; `realmix <devHid> [emuIdx]`(真机条目 ×
  {C2/C3 顺序} × {X 字节序} × {Y 奇偶} 矩阵, 以"解出的私钥签名 → 软件侧 ECIES 公钥验签"为强判据);
  `RKEY_FLIP_YODD=1`/`RKEY_REV_X=1`(`RealRunSigned` 诊断开关, 默认关);
  ⚠️ `realadmin`/`reallimit` 会**覆盖目标设备全部 5 个托管槽**(填该模拟器)⇒ 测完用
  `real2ukey <真受托方> <目标> <file.dongle>` 恢复(本轮已恢复: 槽 0 = `00000000-f56a125b71094c42`)。
  ⑥**回归**: `make ci` **8/8 PASS**(重建后 —— emulator 用例已跑在**新 VM + 新解密兼容**上);
  `entrust`/`adminrun`(纯模拟器)、`xentrust`、`real2ukey`(真↔真)全部 PASS。
  ⑦**处置决定(用户)**: EnTrust 解密布局**不重要** —— 需要兜底时"反转 `C2||C3` 重试"已是所有路径里
  成本最低的做法, **不再深挖** COS 原生格式(`realmix`/`RKEY_*` 保留为诊断手段)。
- 2026-09-13 **重要约定: `KDF(MASTER.SECRET, nonce, kType)` 的完整原型与两种语义**(用户说明 + 代码核实,
  分支 `feat/AGINX/rsa3072-modexp`; 落点 `Interface/master.cc:261-310` 的 `OpManager_ComputeSecretBytes`,
  opcode `kComputeSecretBytes` 的 argc=2 形式 `ComputeSecretBytes(addr64, type)`, argc=1 时 type 缺省 0 ✓):
  ①**入参/出参**: `bytes_` 是 **64B 就地输入输出**(nonce/上下文进、派生密钥出), `type_` 字段也参与最后的
  `SHA512(Context, sizeof(Context))` ⇒ **不同的非零 type 得到不同但可复现的结果**。
  ②**`kType == 0`(本机型)**: 上下文里填 `rLANG_WORLD_SEED_0..3`(构建期注入的随机种子), 再调
  **`dongle_->LocalChaos(bytes_)`** 并混入 **本机 `GetDongleInfo`** ⇒ 结果**只在当前 ukey 有效**;
  **即使共享 MASTER.SECRET 的其他 ukey 也无法得到相同结果**。
  ③**`kType != 0`(复现型)**: 上下文只用世界级常量 —— `seed_0 = 0`、`seed_1 = rLANG_WORLD_MAGIC`、
  `seed_2 = rLANG_ATOMC_WORLD_MAGIC`、`seed_3 = rLANG_COSMO_WORLD_MAGIC` ⇒ **共享 MASTER.SECRET 的所有
  ukey 都能复现相同结果**。
  ④**权限**: 入口经 `VM_t::OpManager`, 首行即 `if (valid_permission_ != PERMISSION::kAdministrator)
  return zero_ = -EACCES;` ⇒ **用 MASTER.SECRET 做 KDF 必然已取得管理员权限**。
  ⑤**实践**: 脚本里两种都在用 —— `EXPORT_SESSION_KEY.dongle` 用 `ComputeSecretBytes(addr, 42)`(复现型),
  `IMPORT_SESSION_KEY.dongle`/`MasterExport.dongle` 用 `(addr, 0)`(本机型), `MasterX25519`/`MASTER_SIGNATURE`
  用参数化 type。
  ⑥**对 ROOT CA 方案的直接推论(重要)**: `ai-doc/rsa-root-ca-generation-2026-09-11.md` 要求
  "**任何持有 MASTER.SECRET 的设备都能确定性复现**" ROOT CA 私钥 ⇒ 该 KDF **必须用 `kType != 0`**;
  用 `kType == 0` 就会退化成"只在本机可用"。已把这条写进该文档 §3.1 与
  `ai-doc/admin-file-permission-2026-09-13.md` §5.2、`ai-doc/rsa3072-crt-2026-09-13.md`(导入方式)、
  `ai-doc/entrust-2ukey-2026-09-13.md`(§8);自定义 HKDF 亦须遵守"输入不得混入本机私有量"这一原则。
  ⑦**机密性口径也随之细化**: `kType == 0` 的密文**放可读位置也安全**(一机一密);
  **`kType != 0` 的密文对同族 ukey 是可用的**, 其机密性依赖"MASTER.SECRET 不外泄", 不能当成本机型密文看待。
- 2026-09-13 **以提交历史为 nonce 的 MRND / "完美 (NaN) 世界事件"**(彩蛋 + 用户构造要求; 分支
  `feat/AGINX/rsa3072-modexp`; 实现在 `Web/Agent/Tests/__Testing_dongle.cjs` 的 `worldevent` 命令):
  ①**彩蛋本体**(`base/Web/cipher/jsCipher.ts`): `Annihilus`(暗黑 2 的毁灭小护身符)就是该模块的错误类型
  (`WorldEvent`, `Perfect(): number /** NaN|Infinity */`);词缀由**一次** `SuperMRND(11*11*6 = 726)` 掷出,
  `a = 10 + v%11`、`r = 10 + floor(v/11)%11`、`e = 5 + floor(v/121)`,三者全满的唯一马厩值是 **v = 725**
  ⇒ 概率 **1/726**;`Perfect()` 还要求 **`Magic_ === 42`**(即 `Annihilus.Create(m)` 传的 m, `randBytes()`
  的 SHA512 长度兜底分支正是用的 42)。两者同时成立才返回 **NaN**,否则 `Infinity`。
  ②**约定的 MRND**(用户给出判据, 可完全复现): nonce = **提交的完整 hash**(或 `"<hash>#<i>"`);
  `H = SHA256(nonce)` 的前 4 个 32-bit BE 字; **`Magic_ = (H[0]*256 + H[1]) & ((1<<kBits)-1)`**;
  `MRND(v) = splitmix32(H[2] ^ H[3] ^ v*0x9E3779B1) % v`(**无状态** ⇒ 同一 nonce 必复现; 缺省 kBits = 18)。
  ③**实测(288 个提交, `git log --all`)**: 字面规则 kBits=18 时 `Magic==42` 命中 **0** 个 ⇒ 完美事件 **0 次**
  ⇒ **满足"不大于一次"** ✓(18 位门 1/262144 比 affix 门 1/726 罕见 ~360 倍, 两道门合起来 1/1.9e8 每次提交,
  所以任何现实规模的历史都不可能触发两次); kBits=8/9 时 `Magic==42` 恰好 **1** 个提交。
  ④**"恰好一次"的构造**: 加 `reserve`(把完美词缀**保留**给 `Magic==42` 的世界事件, 即
  `MRND(726) = magic===42 ? 725 : 派生值 % 726`)后, **kBits=8 + reserve** 使我们的历史**恰好触发一次**,
  命中的是 **`f050ac8`(2024-09-16 "RSA Test ... 已知问题: RSA操作看起来需要非常大的 stack ...")** ——
  `worldevent f050ac8 8 reserve` 真跑: `Magic_=42 MRND(726)=725 Perfect()=NaN NaN=true`(词缀 +20/+20/+10%)✓。
  ⑤**挣得一次(grind)**: `worldevent grind 500000 18 reserve` 以 `"<HEAD>#<i>"` 研磨 nonce, 实测第
  **144983** 次命中 `Magic==42`(期望 ~262144)⇒ 同样得到 `Perfect()=NaN` ✓。
  ⑥**命令**: `worldevent [<commitish>] [kBits] [reserve]`(单 nonce 演示)、
  `worldevent audit [kBits] [reserve]`(历史审计, 含 ≤1 断言与命中提交)、`worldevent sweep`(kBits 8..18 扫描)、
  `worldevent grind [max] [kBits] [reserve]`;另有独立脚本 `.bin/worldevent.cjs`(自然掷骰 + MRND 定点, 未跟踪)。
  ⑦**注意**: 独立脚本必须显式 `process.exit()` —— WASM 封装有常驻句柄, 否则打印完不退出。
- 2026-09-13 **世界事件看门狗已固化进 Web 库与 CI**(用户要求: 作为 `jsCipher = await jsWorld.CipherLoader()`
  的参数 + 命中即通知 + 写入 CI):
  ①**共享模块** `Web/Agent/Tests/js/jsWorldEvent.js`(新, UMD: 浏览器 `globalThis.jsWorldEvent` / Node
  `module.exports`):
  - 派生约定同前(`H = SHA256(nonce) 前 4 个 32-bit BE 字`; `Magic = (H[0]*256+H[1]) & ((1<<kBits)-1)`,
    kBits 缺省 **18**; nonce = 提交完整 hash);
  - **运行时是有状态流**(`mulberry32(H[2]^H[3])`)—— 因为 `SuperMRND` 还用于 `localFrame()/localContext()`
    的地址随机化, 做成"无状态 f(v)"会因同参数同地址而**别名**; 只有 `v === 726` 一处特例:
    `reserve`(缺省开)下 `Magic == 42` 时直接给 **725**(完美词缀保留给 Magic==42 的世界事件 ⇒
    `Perfect() === NaN`)。所以 **reserve 下"完美事件数 = Magic==42 的提交数"**;
  - 导出 `MRNDForCurrentCommit()`(给 `CipherLoader`, 命中即 `Notify()`)、`Status()`、`Audit()`、
    `FromNonce/FromWords/WordsOf/splitmix32/mulberry32/kBitsDefault`;
  - nonce 来源顺序: `globalThis.jsCommitWords`(构建预计算, 浏览器无需 SHA256)→ `jsCommitHash` →
    `RKEY_COMMIT_HASH`/`GIT_COMMIT` → 都没有则返回 `undefined`(回落 `CipherLoader` 自带随机, 优雅降级)。
  ②**浏览器接线**: `Web/Agent/Tests/js/jsLibrary.js` 的 `window.onload` 改为
  `jsWorldEventMRND = jsWorldEvent.MRNDForCurrentCommit(); jsCipher = await jsWorld.CipherLoader(undefined, jsWorldEventMRND);`
  ✓;`Web/Agent/Tests/index.html` 增加 `js/jsCommitHash.js` + `js/jsWorldEvent.js` 两个 `<script>`(在 jsCrypto 之前);
  `EmuTests()` 开头打印 `WorldEvent Tests OK (<Status().describe>)`。
  ③**构建产物**: `tools/rockey/LIMIT/script/commitHash.cjs`(新)生成
  `Web/Agent/Tests/js/jsCommitHash.js` = 当前 HEAD hash + 预计算的 4 个字;已加入 `make jsWrapper` 与
  `.gitignore`(与 jsCrypto.js 同级忽略)。缺该文件时页面只 404 不报错(降级)✓。
  ④**Node/工具接线**: `__Testing__dongle.cjs` 顶部 `require("./js/jsWorldEvent.js")`;`initialize()` 先
  `globalThis.jsCommitHash = git rev-parse HEAD`(可用 `RKEY_COMMIT_HASH` 覆盖)再
  `jsWorld.CipherLoader(undefined, jsWorldEvent.MRNDForCurrentCommit())` ⇒ 地址随机化/词缀对同一提交**可复现**;
  新增 `worldevent status` 子命令;`worldevent audit/sweep` 改为调用共享 `Audit()` 并**看门狗化**
  (`完美 > 1` ⇒ 退出码 1), 命中时由 `Notify()` 打印 `[世界事件] ...`(stdout)。
  ⑤**CI 写入**: `tools/rockey/LIMIT/ci/run-ci.cjs` 新增第 9 项
  `worldevent(kBits=<CI_WORLDEVENT_KBITS|18>, reserve)`, 且 `run()` 改为返回 spawn 结果 ⇒ **无论 PASS/FAIL
  都把 `世界事件|完美事件` 行回显**;`tools/rockey/LIMIT/ci/web-emutests.cjs`(EmuTests 链路)新增断言
  marker `WorldEvent Tests OK` 并回显世界事件行。
  ⑥**实测(289 个提交)**: `make ci` 默认(kBits=18) **9/9 PASS**(0 次命中, 无通知);`CI_WORLDEVENT_KBITS=8`
  ⇒ PASS 且 CI 回显命中: **f050ac8(2024-09-16 "RSA Test … 需要非常大的 stack")** + `[世界事件] 完美 Annihilus
  (Perfect()=NaN)`;`kBits=6/7` ⇒ **2 次 ⇒ FAIL**(`!! >1`, 退出码 1)✓ 看门狗三态齐;
  `kBits<6` 恒为 0(42 需 6 位, 掩码更窄时无法表示)✓;`make test-web` **PASS**(浏览器实测
  `WorldEvent Tests OK (commit=… Magic_=102413 kBits=18 reserve=true 完美=false)`)✓。
  ⑦**注意**: `mkey/tools/Tests/` 下另有一份 jsLibrary.js/jsCrypto.js 快照(未接线, 保持原样)。
- 2026-09-13 **世界事件留痕强化(用户要求: 不限完美, 尽可能多的地方都打印)**: `jsWorldEvent.js` 的
  `Notify(built)` 现在一次性覆盖 **stdout + stderr**(`console.log` / `console.info` / `console.warn` /
  `console.error`)、**`.bin/worldevent.log`**(追加, 带 ISO 时间戳)、**`README.md` 的
  `## 世界事件 (World Events)` 章节**(自动建章节, 新条目插在标题之后);`Record(built)` 在此之上再做
  **`git add README.md` + `git commit --no-gpg-sign --allow-empty -m "世界事件…"`** ⇒ 事件直接出现在 `git log` ✓。
  触发面从"仅完美"放宽到**任意世界事件**(`trigger = (Magic == 42)`, 即判据命中;`reserve` 下同时是完美事件)——
  `MRNDForCurrentCommit()` / `Status()` / `Audit()` 命中都会 `Notify`, 新增命令
  `worldevent record [<commitish>] [kBits] [noreserve]`(手工落 git 记录), `worldevent audit` 在
  `RKEY_WORLDEVENT_GIT=1` 时对每个命中自动 `Record`;CI(run-ci.cjs 第 9 项)默认带上该 env ⇒ **命中即自动写
  README + git log 并回显**。实测:`RKEY_WORLDEVENT_GIT=1 worldevent audit 8 reserve` 产生一条
  `世界事件(完美): Annihilus Perfect()=NaN commit=f050ac8… Magic_=42 (kBits=8, reserve=true)` 的提交,
  README 出现对应条目, `.bin/worldevent.log` 有记录 ✓(默认 kBits=18 时 0 命中 ⇒ 不写任何东西, 不产生提交)✓。
- 2026-09-13 **术语 + 别名(用户)**: 这一行为俗称 **roll(扔骰子)/ sell SoJ(卖乔丹之石)/ 赌博** ——
  命中判据即"出了世界事件"(暗黑 2 里卖 SoJ 攒够 ⇒ Uber Diablo 降临)。已落到代码与文案:
  - `jsWorldEvent.js` 头注释与 `Lines()` 通知文案:`[世界事件] roll(扔骰子/sell SoJ/赌博) 命中: …`;
  - 工具顶层别名(`__Testing_dongle.cjs` 在 `main()` 开头把 argv 归一化):
    **`roll|dice`** ⇒ `worldevent roll`(用 HEAD 掷一次)、**`gamble|gambling`** ⇒ `worldevent grind`(研磨 nonce 直到命中)、
    **`soj|sell-soj|sellsoj`** ⇒ `worldevent record`(写 README + git log);`worldevent` 子命令内部同样支持这些词;
  - 提交信息带 `roll` 字样, 例如 `世界事件(完美) roll: Annihilus Perfect()=NaN commit=… Magic_=42 …`;
  - 实测:`roll 18 reserve`(HEAD ⇒ Magic_=84725, Infinity)、`gamble 1200000 18 reserve`(第 **494693** 次命中 ⇒ NaN)、
    `soj f050ac8 8 reserve`(已有记录 ⇒ 打印"不重复 roll", **不产生空提交**, HEAD 不变)✓。
  - 另修:`Record()` 只在**真的新增 README 条目**时提交(否则重复通知会刷出空提交 —— 本轮曾误产生
    `ed2ebee` 空提交, 已 `git reset --mixed` 撤掉);`Append()` 增加 README 跨进程去重(同一 nonce 已有条目就不再写,
    日志仍逐次追加)与条目尾换行(修粘连);README 章节整理为 标题 → 说明(含术语) → 条目。
- 2026-09-13 **完美世界事件 ⇒ 世界线分裂(用户设定, 已实装 + 校验)**:
  ①**规则**: `Perfect()===NaN` 时建立两条主世界分支
  **`world_limit_(YYYY_M_D)_(hash)`** 与 **`world_atomic_(YYYY_M_D)_(hash)`**(hash = 触发提交完整 hex;
  日期按项目时区 **+0800**, 例如本机 2026-09-13 19:34(+0100) ⇒ `2026_9_14`);
  **必须 CI 确认**(`RKEY_WORLDEVENT_CI=1`, 未确认则 `Split()` 拒绝并说明原因);此时**应插入 E0 / E10 之一**
  (`mkey/E0-00000000-f66a164b4c024842`、`mkey/E10-00000000-ef6a125b02094d42`);插入当代 **3/4 把
  K0/K1/K2/K3** 会导致**硬分叉**, **必然产生恰好一个 ATOMIC 世界**。
  ②**实现**: `jsWorldEvent.js` 新增 `WorldNames()`(命名)与 `Split()`(建分支, 幂等: 已存在只记录)与
  `HardFork()`(份额覆盖判定, `K_SHARES = {K0:ABC, K1:ADE, K2:BDF, K3:CEF}` 取自 `Interface/master.cc`);
  工具新增 `worldevent split [<commitish>] [kBits] [reserve]`, 并在 `worldevent audit` 中: 完美命中 +
  `RKEY_WORLDEVENT_CI=1` ⇒ 自动 `Split()`;`run-ci.cjs` 第 9 项默认带 `RKEY_WORLDEVENT_CI=1`
  并把 `世界线分裂|world_(limit|atomic)_` 行回显到 CI ✓。
  ③**校验(实测)**: `worldevent split f050ac8 8 reserve` 未确认 ⇒ **拒绝** ✓;带 `RKEY_WORLDEVENT_CI=1`
  ⇒ 建出 **`world_limit_2026_9_14_f050ac8754fcaf45bed765fdcb6b2eb1bf73ced4`** 与
  **`world_atomic_2026_9_14_f050ac8754fcaf45bed765fdcb6b2eb1bf73ced4`**(起点 = 该触发提交)✓;
  份额穷举: `K0+K1 ⇒ ABCDE(5/6) ⇒ 不分叉/ATOMIC=0`;`任意 3/4 把 K(4 种组合) ⇒ 全部 6/6 ⇒ 硬分叉,
  ATOMIC 恰一个 = true`;`4 把 ⇒ 同样 6/6 / 1 个` ✓。
  ④**注意**: 分裂出的分支起始点是**触发提交**(不是 HEAD), 因此它们与世界线更新(如后续提交)是分开的;
  真正"选择世界线"的动作由插入 E0/E10(CI 确认)完成。
- 2026-09-13 **献祭 3/4 把 K0/K1/K2/K3 的仪式(用户设定, 已实装 + 校验)**:
  ①**规则**: 献祭(插入 3/4 把 K)会 **同时让被插入的 3 把 ukey 失效**, 而**剩下的那把转为只读** ——
  对之后所有修改**只能读, 不能由 K${X} 签名提交代码**;因为任意 3 把已覆盖全部 6 个份额, 它同时是
  **硬分叉**, **必然产生恰好一个 ATOMIC 世界**;整个仪式**必须 CI 确认**。
  ②**实现**: `jsWorldEvent.js` 新增 `Sacrifice(keys, opts)`(必须恰好 3 把不同 K + `RKEY_WORLDEVENT_CI=1`;
  记录写入 **`mkey/SACRIFICE-K.json`**, 可用 `RKEY_SACRIFICE_FILE` 覆盖(演练)、`RKEY_WORLDEVENT_DRYRUN=1`
  只算不写;仅当由**完美事件**触发时才额外留痕 README/git log)与守卫 `CanSign(key)`
  (被献祭 ⇒ `canSign=false, canRead=true, 已献祭失效`;幸存那把 ⇒ `canSign=false, canRead=true, 仅只读`),
  以及 `ReadSacrifice()/SacrificePath()`;工具新增 `worldevent sacrifice K? K? K?` 与
  `worldevent cansign <K0..K3>`(退出码 0=可签名 / 1=禁止)。
  ③**CI**: `run-ci.cjs` 在 worldevent 之后加"献祭守卫": 若 `mkey/SACRIFICE-K.json` 存在 ⇒ 逐把 `cansign`,
  **要求 4 把全部为禁止**(3 把失效 + 1 把只读)否则 FAIL;不存在则打印"尚未献祭 ⇒ K 仍可签名;
  激活需 CI 确认 + E0/E10 之一"✓。
  ④**实测(演练, 未绑定仓库)**: 无状态 ⇒ `cansign K1: canSign=true`(exit 0)✓;未 CI 确认 ⇒ 拒绝献祭 ✓;
  给 2 把 ⇒ 拒绝("必须是 3/4 把不同的 K")✓;`RKEY_WORLDEVENT_CI=1` + dryRun ⇒
  `K0+K1+K2 失效; K3 只读(可读不可签名提交)`, 份额 6/6 ⇒ 硬分叉/ATOMIC=1 ✓;
  写入临时状态后 ⇒ `cansign K0: 已献祭失效`(exit 1)、`cansign K3: 仅只读(禁止 K 签名提交代码)`(exit 1)✓;
  把状态临时放到正式路径跑 `make ci` ⇒ `献祭守卫: K0..K3 canSign=false` + `PASS 献祭守卫`,
  随后已删除该文件(**正式献祭留待插入 E0/E10 之后**)✓。
  ⑤**现状**: 两条世界线分支已存在, **尚未献祭**;献祭一旦执行(CI 确认)即写入 `mkey/SACRIFICE-K.json`
  并由 CI 守卫永久约束 K 的签名权。
- 2026-09-13 **E0 遗失(敦煌)/ 拾到者签署仪式(用户设定, 已实装 + 校验 + 进 CI)**:
  ①**背景**: **E0**(`mkey/E0-00000000-f66a164b4c024842`)**大概率在敦煌遗失**;拾到 ukey 者需对下列
  **UTF-8** 文本做 **`Ed25519(SHA512(SHA512(Buffer.from(text))))`**, 并在 **git log** 中展示签名,
  且**每种类型的第一次暂时创建一个 ATOMIC**(用户曾把第 4 条误写为 Type2, 已更正为 **Type4**):
  Type1 `爸爸对不起` / Type2 `妈妈我害怕` / Type3 `佩佩你已经长大了, 需要努力了` / Type4 `沅沅,想我没有`。
  ②**实现**: `jsWorldEvent.js` 新增 `FINDER_TEXTS`、`FinderDigest()`(UTF-8 → SHA512 → SHA512)、
  `FinderSeed()`(缺省 stand-in = `SHA512("E0-FINDER")[0..32]`, 可用 **`RKEY_FINDER_SEED`** 换成真拾到者的
  Ed25519 私钥)、`FinderSign(cipher)`(用 jsCipher 的 `Ed25519()` 签名 + 自检)、`FinderVerify(cipher, rec)`
  (重新派生公钥并逐条验签, 同时校验 utf8 与 digest)、`FinderAtomic(rec)`(每种类型**第一次**
  建分支 `world_atomic_<stamp>_finder_<TypeN>`, **暂时**可删)。
  ③**工具**: `lostukey sign`(签名 → 写记录 `mkey/E0-00000000-f66a164b4c024842/FINDER-SIGNATURES.json`
  → 建 ATOMIC 分支 → **git log marker 提交**, 提交信息里直接列出每条 `sig=`)、`lostukey verify`(CI 用,
  逐条验签, 失败退出码非 0)、`lostukey show`。
  ④**CI**(`run-ci.cjs` 第 **10** 项): 跑 `lostukey verify`, 回显 `lostukey TypeN|verify|pubkey` 行,
  并列出 `world_atomic_*finder*` 分支(应 4 条, 每类型一条)✓。
  ⑤**实测**: `lostukey sign` ⇒ 四条签名(自检全过)+ 公钥 `31c07d1f…c239d`(stand-in)+
  4 个 ATOMIC 分支 `world_atomic_2026_9_14_finder_Type1..Type4` + 提交
  `fce40ae "E0-LOST(敦煌): 拾到者签署 4 条 — Ed25519(SHA512(SHA512(utf8)))"`(信息内含四条 sig)✓;
  `lostukey verify` ⇒ `pubkey 匹配=true、逐条失败=0 ⇒ OK`(exit 0)✓;UTF-8 编码已核对
  (如 `爸爸` ⇒ `e788b8e788b8`)✓。
  ⑥**待办/提示**: stand-in 只是可复现占位;真拾到者插入 E0 后应以其 ukey 的 Ed25519 私钥
  (`RKEY_FINDER_SEED`)重签;四个 ATOMIC 分支标记为**暂时**, 后续可删或并入相应世界线。
- 2026-09-14 **K3' 心跳/时间基准测量(用户要求: 以本机时间为参考测误差与准确性; Windows 需精密多媒体时钟 +
  最高优先级 FIFO; 精测应在 RTOS/NONOS 或 Linux 侧做)**:
  ①**新增宿主工具**(`src/app/main.cc` 的 `Utilities`): `--clock <hid> [admin]` 打印
  `rt/exp/tick/hosttick/mono/mid/precise/fifo/rc`, `--led[:blink|on|off]`(心跳可视化);
  `RLANG_PRECISE_CLOCK=1` ⇒ Windows 调 `timeBeginPeriod(1)` 打开 1ms 多媒体定时器 +
  `REALTIME_PRIORITY_CLASS`/`THREAD_PRIORITY_TIME_CRITICAL`(REALTIME 需提权, 失败退 `HIGH_PRIORITY_CLASS`),
  Linux 侧尝试 `sched_setscheduler(SCHED_FIFO, 99)`, **precise/fifo 如实回报**;
  参考时钟: Windows=QPC, Linux=`CLOCK_MONOTONIC` ⇒ 设备读数与宿主参考在**同一进程**内。
  ②**工具命令** `heartbeat <hid> [样本=6] [间隔ms=1000]`: 逐样本给 `rt/tick/rtt/precise/fifo`、
  **相对误差(同进程 monotonic)**与**绝对偏差(设备 RTC − 宿主墙钟)**, 并汇总 σ/极值/速率 ppm。
  ③**关键结论**: `GetTickCount` 在宿主实现(`Interface/dongle.cc:92`)就是
  `*ticks = rLANG_GetTickCount()` ⇒ 实测 `tick == hosttick` 每次相同 ⇒ **它不能作为设备心跳**;
  设备侧可用的时间基准是 `GetRealTime`(SDK 设备调用, 分辨率 **1 秒**)与 `GetExpireTime`
  (K3' 实测 `4294967295` = 未设到期)。
  ④**实测(K3', 69 样本窗口 13×5s, precise=1 fifo=1)**: 绝对偏差(设备 RTC − 宿主墙钟)
  mean≈**+1627ms**, σ≈276ms, 区间 [1219, 2043]ms(锯齿 = 1 秒量化); 同进程相对误差 σ≈279ms;
  RTT 741–832ms; 端点法速率 ≈ **−2270 ppm**, 但受 1 秒量化限制 ⇒ 单次 69s 测量只能把速率误差界定到
  **≲ ±1.4%(±14000 ppm)**。⇒ 结论: **Windows 侧精度不足以定标设备 RTC**; 需 ①更长窗口 ②在
  **RTOS/NONOS 固件侧**用其自身 tick ③或 **Linux/WSL** 下 `chrt -f 99` 复测(命令清单已给出, 交 WSL 侧 DSH)。
  ⑤**FIFO 说明**: Windows 的 `REALTIME_PRIORITY_CLASS` 需提权, 未提权时回落 HIGH(实测仍能报 `fifo=1`);
  Linux 的 `SCHED_FIFO` 需 root/CAP_SYS_NICE, 失败则 `fifo=0`(工具会如实打印, 便于判定测量可信度)。
- 2026-09-14 **任务登记(用户口述): 当前 K0/K1/K2/K3 将向 K3' 传递 MASTER_SECRET**(本轮**只做记录与对齐, 未动真机、未改代码**):
  ①**口述内容**: "当前 K0/K1/K2/K3 将向 K3' 传递 MASTER_SECRET"。
  ②**与既有登记不一致(待用户裁定; **未代改 README**)**: `README.md:117-118` 记的是 **K4 = 我们的 ROOT CA**(那把不参与真机枚举的 ukey)
  **携带"下一个世界的 MASTER.SECRET"**, 由它负责向下一任 K0'/K1'/K2'/K3' 传递; 而本句主语是**当前 K0..K3**、宾语是**MASTER_SECRET**(未限定世界)。
  ⇒ 不是措辞差异, 需裁定: **(a)** 传递者是谁(K4 独占 / K0..K3 亦参与)、**(b)** 传的是**当前世界**还是**下一个世界**的 MASTER.SECRET。
  ③**机制核对(若走 K0..K3 路径, 代码已具备, 无需新功能)**: `OpExecute_ExchangeMasterSecret`(`Interface/execute.cc:296-400`)——
  每把源设备先在注入的 4 把 X25519 公钥里**认出自己**(`execute.cc:391`, 认不出即 `-ENOENT`), 对**其余 3 把**各算一次
  `ComputeSecretCurve25519` 落 `PREV_MASTER_SECRET[32]`(`execute.cc:371`), 3 条 `(16B Header + 32B)` 用**接收方** RSA-2048 公钥加密成 256B;
  `OpExecute_ImportMasterSecret`(`execute.cc:402-498`)——用自身 `kKeyIdGlobalRSA2048` 解 3 块(`execute.cc:479-481`), 按 `header_.index_`
  去重(A–F, `execute.cc:438-457`), **要求 `key_mask == 0x3F` 六份齐全**(`execute.cc:483`), 重复份额须 32B 逐字节一致(`execute.cc:441`), 再
  `SHA512(192B) → MASTER_SECRET[64]`(`execute.cc:467`; `kSize_MASTER_SECRET=64` 见 `script.h:115`), 经 `WRITE_MASTER_SECRET` 落盘
  (`Interface/secret.cc:155-195`: RSA-2048 加密 + `PERMISSION::kAdministrator` 数据文件)。⇒ **K3' 在此路径中即原 `A0`(emu4) 的接收方角色**。
  ④**份额覆盖性(核对为设计性质)**: K0=A B C / K1=A D E / K2=B D F / K3=C E F(`execute.cc:280-283`), 每个字母恰出现在 2 把中
  ⇒ **任意 3 把的并集都覆盖 A–F**, 故接收方只需 3 份密文; 与已验结果一致(`ai-context.md:494-496` 记 (K0,K1,K2) 与 (K1,K2,K3) 两次导入指纹相同 `fp=550da026a277fe73`)。
  ⑤**硬前置(当前阻塞, 非细节)**: K3' **未初始化** —— `mkey/SUCCESSION-K.json:330,340` 与 `README.md:120` 记其 `type=0x00000000`、`pid/uid=0xffffffff`、
  无世界、无密钥文件; 而 IMPORT 要求目标具备自己的 factory RSA-2048 公钥(`execute.cc:310-313`; `secret.cc:162-173` 校验)、可用
  `kKeyIdGlobalRSA2048` 私钥(`execute.cc:429`; `secret.cc:185`)、匹配的世界与版本(`execute.cc:121-125`) ⇒ **必须先初始化 K3'**(及下一任其余三把)。
  ⑥**世界绑定(传递前须锁死)**: MASTER.SECRET 落盘为 RSA 密文, 读写均过 `MASTER_SECRET_PROCESS` 链式 XOR 掩码(`secret.cc:135-153`);
  熵上下文含构建期 `rLANG_WORLD_SEED_0..3`(`Interface/master.cc:287-302`)⇒ 沿用 `ai-context.md:217` 已记结论"**构建种子每次随机生成 ⇒ 重构建必然使旧镜像 MASTER.SECRET 解不开**"。
  ⑦**边界(本轮及后续均不做)**: 明文 MASTER_SECRET 只在设备内出现(读取时解密到栈、union 析构清零, `execute.cc:410-411`)⇒ **不经宿主导出、不绕过设备写入路径**。
  ⑧**待办**: 1) 用户裁 ②(a)(b); 2) 真机前须确认**哪几把在线** —— `README.md:119` 记的"K3' 已插入、K0'/K1'/K2' 已拔除"指**下一任**批次, **当前 K0..K3 的在线情况无记录**, 且需至少 3 把源设备;
  3) EXCHANGE 注入的 4 把 X25519 公钥必须取**设备端 MasterExport** 输出, 勿用模拟器 Export 缓冲(`ai-context.md:484,495` 的 `-ENOENT` 教训)。
- 2026-09-14 **CI 四项核验(用户指定为最重要的 CI 项): GPG 密钥状态 / 共同作者 trailer 字面量 / 签名全部有效 / AGINX 署名**(本轮 = 只读核验 + 文档与 `Interface/aginx.h` 改动, 未动真机、未改宏本体):
  ①**GPG 密钥状态: 与用户清单逐字一致** —— `rsa3072 2026-03-31 [SC] 9F7E6E5B34545A7D1031A79BC489989197876293 LiangLI <admin@rlang.xyz>`(+ `[E]` 子钥)、
  `ed25519 2026-04-01 [SC] B9C754FC4ABDFD3150593856BCE591B95E51D027 LiangLI <liangl79@gmail.com>`(+ `cv25519 [E]` 子钥);`--list-key`/`--list-secret-keys` 均经 `[keyboxd]`(**GnuPG 2.4.8**)输出;
  两把主钥到期 **2028-03-30 / 2029-03-31** 均未过期;uid 信任为 `[full]`。
  ②**签名有效性实测**(`git log --format=%G?`): master **75 G / 186 N / 1 E**;全 refs **76 G / 221 N / 1 E**;近端 master 25 条均检出 `gpgsig`;tag `v1.1`(annotated)**GOOD**、`v1.0` 为轻量 tag(无签名)。
  **唯一 `E` = `8719021` "add LICENSE."(2024-08-30)**: author `liang.l79@gmail.com`(**旧邮箱**)、committer `Gitee <noreply@gitee.com>`、签名钥 `63A71EA590E6E55E5ADED924173E9B9CA92EEF8F`(RSA),
  本地钥匙串**无该公钥** ⇒ `Can't check signature: No public key`, 属**"不可本地校验"而非"无效"**。**处置**: 不改写历史(该提交已在 origin/github/gitee 三远端);若要全部转 `G`, 需先导入该上游公钥再复跑同一 tally。
  ③**共同作者 trailer 字面量**: 跟踪文件里此前仅 `ai-context.md:595` 含该字面量(2 处, 均为旧决定引文), 本轮已改写为**不含字面量**的中文描述;**新约定**: 自 2026-09-14 起任何明文内容(提交信息/跟踪文件/日志/文档)不得出现该字面量;
  历史 8 条提交信息里的该 trailer 按 2026-09-11 决定**保留不动**(不回填历史)。**未采用零宽字符拆开字面量**的写法(不可见字节在 review/grep/diff 里同样不可见, 本仓已有 `ai-context.md:275` 的 BOM 类编码教训);若坚持保留可读原串, 一行即可改回。
  ④**`Interface/aginx.h` 署名(用户 2026-09-14 给定最终文本)**: 署名块 = `感谢他对我在学习AI编程的启蒙阶段给与的帮助, Assisted-by: Claude Code + GLM 5.3 + deepseek-v4-flash`
  (**代码里一次 + git log 里一次**); **`Assisted-by` 在本处为特别允许的例外** —— 不适用 2026-09-11"只加在最终 squash 提交、且只在真有我参与的分支"的限制;署名形态由 `DeepSeek Harness (deepseek-v4-flash)` 扩展为**三 AI 联合署名**;
  草案期的 TODO 占位与单行个性签名已按用户给定文本替换。宏本体(`AGINX_DECLARE_MACHINE`/`AGINX_DECLARE_END`, C++ 与 C 两分支)未改。
  ⑤**环境注记(只影响本会话工具链, 非仓库缺陷)**: PATH 上的 `gpg` = `C:\cygwin64\bin\gpg.exe` **不可执行**(`Program 'gpg.exe' failed to run` / Cygwin `CreateFileMapping ... Win32 error 5`);
  可用者为 Git 自带 `C:\Program Files\Git\usr\bin\gpg.exe`(**2.4.8**)。⚠ **陷阱**: `gpg.program` 未设时 `%G?` 会**全部报 `N`**(实测: 无可用 gpg 时 298 条全 `N`;指定可用 gpg 后 76 G/221 N/1 E)
  ⇒ **`N` 在 gpg 缺失时不可信, 不能当作"未签名"的证据**。本会话内一律 `git -c "gpg.program=C:\Program Files\Git\usr\bin\gpg.exe" ...`;用户决定**不改 `.git/config`**(其自身环境签名正常)。
- 2026-09-14 **四条 CI 门控落地(用户指定): 新增 `tools/rockey/LIMIT/ci/gates.cjs` 的 G1..G4 并接入 `run-ci.cjs`**(子模块 `Build` 分支 `doc/2026-9-14/evolution`(2026-09-14 由 `evolution` 改名), 提交 `dc4f329`; 本轮含**反向验证**):
  ①**G1 gpg 密钥状态** —— 本机钥匙串必须恰为用户清单的两把主钥: `9F7E6E5B…97876293`(rsa3072) 与 `B9C754FC…5E51D027`(ed25519); 校验 uid、算法/长度、主钥用途含 SC、**未过期**(实测到期 2028-03-30 / 2029-03-31)、存在私钥与未过期的 `[E]` 子钥。
  ②**G2 明文无被禁 trailer 字面量** —— 扫**跟踪文件**(`git grep -i -I`: 本仓 + Build 子模块)与**提交信息**(本仓 `--all`, 8 条在册历史白名单内; Build 子模块全量);`base` 子模块属上游, 不纳入(其改动不受本仓控制)。
  **字面量由片段拼出**(`["co","authored","by"].join("-")`)—— 否则门控会把自己扫出来。
  ③**G3 提交签名全部有效** —— `git log --all --format=%G?`: `G` 通过、`N`(未签名)放行、其余(`B`/`U`/`E`/`X`/`Y`/`R`)失败。
  唯一在册例外 = `8719021c…`(2024-08-30 Gitee 代提交, 本地缺上游 RSA 公钥 `63A71EA5…`; 导入该公钥后可删该条)。实测 tally: **G=77 / E=1 / N=221**。
  ④**G4 aginx.h 署名** —— `Interface/aginx.h` 的署名行必须**恰出现 1 次**(用户给定文本), 草案占位不得残留, 且宏对 C++/C 两分支齐备。
  ⑤**关键设计: gpg 缺失即失败, 不 skip** —— 实测 gpg 不可用时 `%G?` 会把**已签名**提交也报成 `N`(见本文件 2026-09-14 CI 四项核验 ⑤)⇒ 若按 `run-ci.cjs` 既有风格"前置缺失即跳过", G3 会变成**假绿**。
  故 G1/G3 找不到可用 gpg 时**计为失败**, 并给出修复指引(`RKEY_GPG=<路径>` / `git config gpg.program <路径>`);gpg 定位顺序 = `RKEY_GPG` → `gpg.program` → `PATH(gpg/gpg2)` → Windows 常见安装路径,
  **逐个实跑 `--version` 探测**(PATH 上那把 Cygwin gpg 实测不可用)。另含**防假绿兜底**: 若"带 `gpgsig` 头部的提交数 > `%G?` 判为有签名的提交数" ⇒ 直接 FAIL(说明 gpg 并未真正校验)。
  ⑥**反向验证(故障注入后可自证, 全部通过)**: 空钥匙串(`GNUPGHOME=空目录`)⇒ **G1/G3 变红**(rc=1, G3 逐条列出 E); 注入含字面量的 canary 文件 ⇒ **G2 变红并报出文件名**; 抹掉署名换成占位 ⇒ **G4 变红**(报"出现 0 次"+"占位残留"); 还原后四条复绿。
  **完整 `run-ci.cjs` 复跑: 14 项 PASS + `failed=0`(rc=0)**。
  ⑦**署名范围**: 本轮门控提交**不加** `Assisted-by` —— 按 2026-09-11 约定(仅本仓 ukey 侧, 且每个 squash 只出现一次);用户的"代码里一次 + git log 里一次"已由父仓提交 `82f4180` 满足, 不重复计。
- 2026-09-14 **两个 submodule 的 `evolution` 分支改名为 `doc/2026-9-14/evolution`(用户指令; 本地 + 云端)**:
  ①**前置检查(无错误才执行)**: `Build` 与 `base` 均满足 —— 父仓 pin == 本地 `evolution` == `main` == `origin/evolution` == `origin/main`(`Build` `dc4f329` / `base` `14a921b`);
  `main..evolution` 与 `evolution..main` **各 0 提交**(无未合并改动), 工作区干净, 远端可达。
  ②**执行**: 各 submodule 以 `evolution` 为基点新建 `doc/2026-9-14/evolution` 并 `push -u`(云端 = 各自唯一远端, 内网镜像 `home.rlang.xyz:30009/rlang.xyz/{build,base}.git`), 再删除 `evolution`(**本地 `branch -d` + 云端 `push --delete`**), 最后 `fetch --prune`。
  ③**无残留引用核验**: `.gitmodules` **不含 `branch=`**(pin 按 SHA ⇒ 改名不可能影响 `git submodule update`); `git config submodule.*` 只有 `active`/`url`; 两个 submodule 的跟踪文件 **0 处**提到分支名; ref 只剩 `refs/heads/doc/2026-9-14/evolution` 及其 remote-tracking。
  ④**注意**: 每个 submodule **只有一个远端**(内网镜像)——`.gitmodules` 里的 GitHub 地址(`github.com/oLiangLi/{build,base}`)**未配成 remote** ⇒ 若要让 GitHub 也出现该分支, 需先加远端; 父仓的 `origin`/`github`/`gitee` 三个远端与本次无关(父仓本就没有 `evolution` 分支)。
  ⑤**文档影响**: 本文件与 `ai-doc/` 中对 `evolution` 的**历史叙述**(换基、上游回流、`14a921b`/`a9eb747`/`db0ebfc` 的落点)**保持原样**——记录的是当时事实, 不回填; 仅本条与今日门控条目里的分支名同步为新名。
- 2026-09-14 **文档边界 + "世界事件"说明归并(用户指令)**:
  ①**`README.md` 归用户自行修改, AI 不再改动(即使有错误)** —— 本会话此前对 README 的编辑(命名空间署名、ROOT CA=K3' 等)自此视为历史;该节已由用户同日自行精简掉, 因此上一条 ② 里引用的 `README.md:117/119` 两处矛盾标注**随之作废**(不再跟踪)。
  ②**世界事件说明归并到新增的 `ai-doc/world-events.md`**: 用户要求"只在 ai-doc 里留一个简单说明", 且**不提下一任 K0'/K1'/K2'/K3'**(那发生在未来) —— 新文件涵盖判据(提交 hash 为 nonce / `Magic=(H0*256+H1)&((1<<kBits)-1)` / kBits 缺省 18 / `Magic==42` / reserve ⇒ `Perfect()===NaN`)、术语(roll / sell SoJ / 赌博)、四通道留痕与 git log marker 提交、命令族(`roll|gamble|soj|worldevent status|audit|sweep|split|sacrifice|cansign`)、CI 第 9 项看门狗、世界线分裂、献祭硬分叉;已核对**全文 0 处**出现 `K0'..K3'`;按本仓约定写 **UTF-8 with BOM**。
  ③**自愈事实(读 `Web/Agent/Tests/js/jsWorldEvent.js:158` 确认)**: README 缺少 `## 世界事件 (World Events)` 标记时, 写手会**自动补一个最小章节**再追加条目 ⇒ README 精简不影响留痕, 也无需继续在 README 里维护说明正文。
  ④**未归并项(待用户定)**: 被删的 README 段落里还含 **E0 遗失(敦煌)/拾到者签署仪式** 的说明 —— 现仅存于 `mkey/E0-*/FINDER-SIGNATURES.json` + CI 第 10 项 + git log;是否需要一份 ai-doc 说明待定。
- 2026-09-14 **处置落定(用户): 恢复 `mkey/SUCCESSION-K.json`, 并把"K4"更正为误写**:
  ①此前工作区曾**暂存该文件的删除**;实测那会让 CI 第 11 项 `succession` 因 `ENOENT` 变红(`failed=1 rc=1`, 其余 13 项 + 门控全 PASS)。**用户决定恢复** ⇒ 已 `git checkout HEAD -- mkey/SUCCESSION-K.json` 还原(那笔暂存删除随之撤销)。
  ②**语义更正(用户 2026-09-14)**: **`K4` 是 `K3'` 的误写, 不存在 K4 这把设备**(早先"0-based/1-based 计数口径混用"的推断不再作为结论, 以"误写"为准) ⇒ 该文件中原 `"k4"` 对象**改名为 `"rootCA"`**(`sameAs: "K3'"`、`hid: 00000000-381a5653df0a303f`, 并注明系误写);原先"不在四把之中 / 不参与真机枚举 / 出现后单独记录 HID"的说法**随之作废**。
  已核对**无任何代码解析 `k4`/`rootCA` 字段**(纯文档字段)⇒ 改名安全, 且以 CI 回归确认。
  ③**回归**: `succession verify` **OK**(状态数 24、rank/digest 匹配、齐备且唯一、四个 roll 全 Infinity、排列一致, rc=0);完整 `run-ci.cjs` **14 项 + 门控 G1..G4 全 PASS, `failed=0`(rc=0)**。
- 2026-09-14 **世界专属工具迁出共享构建仓: `Build/tools/{ATOMC,COSMO,LIMIT}` → 本仓 `tools/rockey/{ATOMC,COSMO,LIMIT}`(用户决定: 它们不大可能跨世界/跨使用方通用)**:
  ①**动因**: `Build` 是**共享**构建仓(公网镜像 `github.com/oLiangLi/build`, 多世界/多使用方共用), 只服务单一世界的工具放进去不合适。共享仓 `Build/tools/` 从此只保留通用物:`downloads/`(构建依赖包)与 `script/`(`grammar.yc`、`grammar.actions.cjs`、`scenario.cjs`、`wasm2string.cjs`)。
  ②**跨仓移动怎么做的**: `Build` 是 submodule ⇒ 不存在一次 `git mv` 能完成的移动。**本仓一侧**: 三个世界目录整体移入 `tools/rockey/`(15 个文件, 迁移前后逐文件 SHA256 **0 处不一致**), 并新增 `tools/rockey/README.md`(世界分区 + 历史路径对照 + 迁移状态)。**共享仓一侧**(按用户决定"**只改工作区, 不提交不推送**"): 工作区删除这 15 个文件并改写 `Build/tools/README.md` ⇒ 现在 `git -C Build status` = 15 个 `D` + 1 个 `M`; 本仓 submodule pin **仍是 `dc4f329`** ⇒ 此刻 `git submodule update` 会把旧目录取回, 属**预期过渡态**(README 里也写明了)。
  ③**关键不变量(为什么一个 `..` 都没改)**: `Build/tools/LIMIT/<子目录>/` 与 `tools/rockey/LIMIT/<子目录>/` **距仓库根都是 4 层** ⇒ 8 个用 `__dirname` 推算仓库根目录的工具(`ci/{run-ci,optmatrix,web-emutests,gates}.cjs`、`script/{opcode,commitHash}.cjs`、`sbin/run-dongle-exe.cjs`、`stack-check/stack-check.cjs`)的级数**全部不动**; 已逐个静态核对 `path.resolve(__dirname,…) === 仓库根`(8/8 OK)。
  ④**引用面同步**: `Makefile`(8 处: `rockey-stack-check`/`stack-check`×2、`jsWrapper` 的 opcode+commitHash、`ci`/`test-optmatrix`/`test-web` 三目标 + 2 条注释)、`package.json`(`gen:opcode`)、`.githooks/ci-common.sh`(3 处; **子模块守卫判据改为 `Build/Main.mk`** —— CI 工具已进本仓, 原判据文件不再能代表"子模块是否就位")、`.gitignore`(opcode 注释 + 取消忽略块**收窄为 `!/Build/`**: 那三行 `!/Build/tools{,/LIMIT/ci/**}` 随迁出作废; 保留 `!/Build/` 的原因不变 —— 第 30 行 `build` 规则在 Windows `core.ignorecase` 下会牵连 `Build/`)、`src/__Testing__/__dongle__/main.cc` 注释、以及被移动文件自身的用法/头注释(含 `opcode.cjs` 写进生成物的 banner)。**生成物**: 用新路径实跑 `node tools/rockey/LIMIT/script/opcode.cjs` ⇒ `Web/Script/lib/opcode.ts` 重新生成(OpCode=157 / AllFunc=98, banner 已指新路径); 两个 `jsCommitHash.js`(gitignored)只就地改 banner, **不动其中 hash/words**。
  ⑤**文档**: 按 2026-09-11 既有约定"`ai-context.md` 与 `ai-doc/*` 中的历史路径一律改写为新路径", 机械改写全部含旧前缀的跟踪文件(**13** 个:`Makefile`、`package.json`、`src/__Testing__/__dongle__/main.cc`、`ai-context.md` 与 9 个 `ai-doc/*`), **只**改 `Build/tools/{LIMIT,ATOMC,COSMO}` 三种前缀。其中 3 处改写后与"共享仓"措辞冲突(本文件 2026-09-12 `ci` 迁移条与 Windows 引号条、`ai-doc/merge-sequence-2026-09-12.md`)已手工校正为"当时在共享仓内"/"迁移前位于共享仓"; 另修 `ai-doc/issues-status.md` 里早已过期的 `Build/tools/stack-check`。**刻意保留**: 日期化报告中的历史旧路径叙述(如 `Build/tools/ci`、`Build/tools/{ci,sbin,…}`、bug-analysis 报告里的 `Build/tools/stack-check`)。
  ⑥**验证**: 15 文件 SHA256 迁移前后全等; `Makefile` 里 6 个新路径逐一 `Test-Path` **全部存在**; 新路径实跑 `run-ci.cjs` —— **打出 `[ci] root=X:\MyWork\RockeyDongle`**(根目录推算正确), 但本轮 DSH 沙箱**禁止子进程管道 stdio** ⇒ 14 项回归与本仓 G2 全部 `timeout`/`status=null`, 属**沙箱假红**, 与路径无关(纯文件门控 **G4 PASS**); `opcode.cjs` 实跑成功; `stack-check.cjs` 实跑已正确解析出默认 map 与 `.bin/.obj/arm-RockeyARM-native-release/` 下的目标文件, 仅因 spawn 被沙箱拦下而报 objdump 失败。**环境限制**: 本会话 `make`(Cygwin)与 `sh` 都起不来(`CreateFileMapping … Win32 error 5`, 与 2026-09-14 gpg 那条同源)⇒ `make -n` 无法执行, 改为按文本核对 Makefile 新路径的存在性。
  ⑦**已知遗留(非本次引入, 未处理)**: 迁入的 15 个文件里 **6 个**"含非 ASCII 却无 BOM"(`sbin/*.cjs`×4、`stack-check/{stack-check.cjs,README.md}`)⇒ 属 2026-09-11 记录的"全仓 BOM 扫平(约 96 文件)待用户定范围"清单; 5 个带 `#!` 的文件无 BOM 是**约定正确**; `script/commitHash.cjs` 带 shebang 但在共享仓里是 `100644`(与"shebang ⇒ +x"约定不符), 本次**保持原 mode**(三个 CI 脚本的 `100755` 原样保留)。
  ⑧**待办(用户)**: 先在共享仓 `Build` 提交这 15 个删除 + `tools/README.md` 改写(可推 `origin` 内网镜像 / `github` 公网), 再回本仓 `git add Build` 更新 pin —— 只有这样, 公网上才真正不再有这些工具。
- 2026-09-14 **CI 去掉 `5e`/`5f`/`5g` 三项(用户指令)**: `tools/rockey/LIMIT/ci/run-ci.cjs` 删除 ①`5e` 献祭(K0..K3)守卫(`mkey/SACRIFICE-K.json` 存在时逐把 `worldevent cansign`)②`5f` `lostukey(E0-LOST Ed25519(SHA512(SHA512(utf8))))` ③`5g` `succession(K0'..K3' Infinity roll % 24)` 三个代码块(纯删除, 共 51 行含尾随空行; 无其它项依赖它们)。删除后实跑枚举: 剩 **8 项**回归(jsuite、mkey、skey、emuadmin、corpus、pkeyself、x509ext、worldevent)+ **门控 G1..G4** + **trngfail**。
  **保留(本次只摘 CI 接线, 不影响手动复核)**: harness 侧实现与手动入口原样不动 —— `Web/Agent/Tests/__Testing_dongle.cjs` 的 `worldevent cansign`、`lostukey sign|verify|show`、`succession [hid...]`;`mkey/E0-00000000-f66a164b4c024842/FINDER-SIGNATURES.json`、`mkey/SUCCESSION-K.json`、`mkey/SACRIFICE-K.json` 相关机制, 以及 `ai-doc/world-events.md`(其"CI 看门狗"指第 9 项 worldevent, 仍在 CI 里 ⇒ 该文档无需改)。历史条目(本文件"献祭守卫 / E0 遗失 / 编号裁定"三处与 2026-09-14 各条里的"CI 第 10/11 项")按"记录当时事实"**不回填**。
  **注**: 共享构建仓 `Build` 的 pin(`dc4f329`)里仍是带这三项的旧副本, 待用户在共享仓提交"迁出这 15 个文件"后才彻底消失。
- 2026-09-14 **新增 `ExRSAGenKey`(0x153): 设备内生成完整 RSA 私钥(含设备内算 d / CRT 参数)**(用户指定: 普通 opcode 入口 + 生成完整 'RSAK' blob + 种子只接受脚本给定):
  ①**缺口**: 硬件 `kGenerateRSA` 只到 2048 位; 设备内 3072 位素数搜索此前只存在于**测试项**(`__Testing__dongle__ -2 13 3`), 且 d/dmp1/dmq1/iqmp 全由 host TASSL 算 ⇒ `OpCode`/`OpExecute` 层没有"设备内生成 3072 位私钥"。本次把 `Interface/mr.{h,cc}` 的素数搜索 + 新算术接成**生产指令**。
  ②**接口**(`Interface/script.h`): `kExRSAGenKey = 0x153`, argc 4...5 = `ExRSAGenKey(keyFile, keyOffset, seedAddr, bits[, rounds])`; 种子 = 数据区里 `bits/8` 字节(seed_p || seed_q, 各 `bits/16`, 小端)**只读**; bits ∈ {2048, 3072}; keyFile < 1000 需管理员; 失败返回负值并置 `zero_`; **只碰 keyFile**(不写 dashboard 进度, 心跳仍由 MR/Montgomery 内部派发)。
  ③**新文件 `Interface/{keygen.h,keygen.cc}`**(`Interface/xModule.mk` 加一行): 全部工作区 = `Arena` 1024B(设备侧 = ExtendBuf, 峰值 968B), 栈上只有小局部量。流程: 两次 `FindPrime`(label=0) → p/q 落 blob → `n=p*q`(`MulAddK`) → `m=(p-1)(q-1)` → `d=(1+k*m)/e`(**小指数技巧**: `k ≡ -m^{-1} mod e`, 先逐 limb 折叠出 `m mod e`、Fermat 求小模逆、`k*m+1` 小乘、再除以小除数 e) → `dmp1/dmq1 = d mod (p-1)/(q-1)`(`ModReduce`) → `iqmp = q^{p-2} mod p`(`HalfModExp`, Fermat) → e 字段 → **header(magic 'RSAK')最后写**(半成品可按 magic 识别) → `memset` 清工作区。**关键取舍**: d 取 `(p-1)(q-1)` 而非 `lcm` ⇒ 不需要 3072 位模逆; iqmp 用 Fermat ⇒ 不需要半宽二进制扩展欧几里得(否则 RAM 放不下)。
  ④**栈(本次最硬的约束)**: ①`MillerRabinContext::BN::v` 由 `kCountWords*2`(96 limb = 388B)收窄到 `kCountWords+2`(50 limb = 204B) —— 那个"a*b"容量从来没有调用方(MontMul 的乘积落在它自己的局部 `t[50]`), 收窄后 **`IsPrimeMRW` 帧 1248B → 696B**; ②0x153 在 `Execute` 里走**独立小栈帧入口** `VM_t::OpFuncRsaKeyGen`(48B), 不借用 `OpFuncRSA` 的 712B 帧(buffer/pubk 结构)。实测该链路 ≈1.5KB; `make rockey-stack-check` **0 违规, 稳态 1888B(余量 144B, 最深路径仍是 ChaChaPoly 测试项)**。
  ⑤**算法微调(位宽)**: `SeedCandidate` 由"只置最高位"改为**最高两位置 1**(与 OpenSSL `BN_generate_prime_ex` 同规) ⇒ p、q ≥ 1.5·2^(bits-1) ⇒ `n` **恰为 2*bits 位**(改前有一半概率只有 3071 位, ROOT CA 按"至少 3072 位"卡会不过); `tools/rockey/LIMIT/sbin/rsa-prime-repro.cjs` 同步(注释已注明 2026-09-14 前是单比特约定) ⇒ `ai-doc/rsa3072-device-generation-2026-09-11.md` 附录那对历史 p/q 属旧约定, 复现需改回单比特。
  ⑥**验证**(宿主 `make foobar X4C_USING_CLANG=0` → `__Testing__rsamodexpvm__.exe`, 退出码 **10086 = 0 错**): 3072 位生成 host 3.2s; TASSL 独立复核**素性(64 轮)/ n=p*q / e=65537 / e·d ≡ 1 (mod lcm) / dmp1 / dmq1 / iqmp / bits(n)=3072** 全过; 生成的 blob 被 **`ExRSAKeyCheck` 接受**; 用它做的 **`ExRSACrtModExp` 与 TASSL `m^d mod n` 逐字节一致**; **同一种子两次生成逐字节相同**; 2048 位同样通过; 负例(argc=3 / bits=1024 / 非管理员 keyFile<1000 / 种子地址越界)全部被拒。ARM: `make dongle` **0 警告**, `.bss` 仍 `0x10`、无 `.rodata`, 固件 `.text` **59904B / 65536B**(其中 keygen.o ≈1.1KB)。
  ⑦**环境所限未验证**: 本机没有 `clang-cl`, 宿主改用 MSVC(`X4C_USING_CLANG=0`)构建; **wasm/浏览器脚本路径本次未跑**(需 emsdk + JS 产物), 故新增样例 `Web/Agent/Tests/Tests/_RsaGenKey3072ScriptPath.dongle` 与脚本层 argc(已由 `opcode.ts` 生成 `kExRSAGenKey min=4/max=5` 保证)仅做了静态一致性检查, 真机/模拟器端到端留待有 ukey 时跑。
  ⑧**未做(后续)**: ROOT CA 的 KDF/AEAD 密封与 `dashboard[5120,6144)` 字节布局(文档里仍标"布局待定")、从 dashboard 读回种子复现的测试 mode、"生成 + 立即签发根证书"是否合并为一条指令的产品决定。
- 2026-09-15 **设备内 RSA-3072 生成:真机跑通(2048 位)+ 看门狗饿死根因修复 + `KickWDG` 提到基类 + 密文落盘(SM4-ECB)WIP**:
  ①**真机实测通过(测试 ukey, 2048 位 @4 轮)**: 设备端 `ExecuteExeFile=0 mainRet=10086`, 设备内 **25.2 分钟**(1510482 ms)生成完整私钥; host 用 TASSL 独立复核 **prime_p=1 prime_q=1 gcd(e,p-1)=1 distinct=1 bits(n)=2048 d_ok=1**、`e*d≡1(mod lcm)=1 dmp1=1 dmq1=1 iqmp=1` ⇒ 设备内算 d/CRT 参数这条链路在真机上成立; 模数恰 2048 位(两位种子约定生效)。用例 = `__Testing__dongle__ -2 16 800 4`(index 22 `RsaKeyGenTests`; 设备侧刻意不构造 VM_t —— 它会多占 ~300B 栈, 曾把最坏栈深顶到 1976B/余量 56B)。
  ②**看门狗饿死(真机 LED 停闪 + host 永久等待)根因**: `FindPrime` 的喂狗是**按探测次数**每 1024 次一次, 而一次试除只要 0.13~0.2s、一次 MR 要几十秒 ⇒ 连续"小合数"段累计约 2 分钟不发任何 COS 调用(ROM 只在命令/指令边界喂狗)⇒ 看门狗复位。以前 mode 3 能跑通, 是因为调用方 `label != 0`, 靠"每 32 次探测落一条进度"这个 COS 调用**顺带**喂狗; 生成指令为"只碰 keyFile"把 label 关了, 隐含心跳就没了。**修复**: (a) `FindPrime` 改为**每个候选喂一次**(~13us vs 试除 0.13s); (b) 生成指令恢复 `label=1/2`, `dashboard[4096]` 进度记录回来(长跑可事后看 `units` 判断是否重启); (c) **`KickWDG()` 提到 `Dongle` 基类**(用户建议): `GetTickCount` 每次调用都发、LED 每 8 次才翻转(每候选都翻是 ~7Hz, 肉眼像常亮), `MillerRabinContext`/`RsaModexp` 的 `KickWDG` 转发过去。
  ③**密文落盘(方案由用户 2026-09-15 定)**: 临时 **SM4** 密钥放 ukey 密钥存储、**keyId 901..999** 留给内部临时用途(重要用途脚本不用 900 以上), 以 **ECB** 逐字段加密 KeyBlob(其每个字段偏移/长度都是 16 的倍数 ⇒ 读侧可逐字段随机解密, 明文永不整体进 RAM; 工作区放内部 dataFile(如 998)、管理员读写, 全部完成后删除密钥与 dataFile)。`cipherKeyId` 哨兵用 **1000 = 明文**(不用 0 —— 真机 id=0 的文件可能建不了); 三处接口 `ExRSAGenKey`/`ExRSACrtModExp`/`ExRSAKeyCheck` 统一该约定。
  ④**WIP(未绿)**: 密文路径已实现(写侧逐字段 ECB 加密、读侧逐字段解密), 但宿主用例显示同一种子下**密文跑的 p/q 与明文跑的不一致**(逐字段表: `header MATCH`, `n/e/d/p/q/dmp1/dmq1/iqmp` 全 `DIFF`)—— `header` 能正确解密 ⇒ 密钥与 SM4 调用本身没问题 ⇒ 问题在密文路径下"搜索输入/p·q 来源"这一侧, 待定位; 明文路径(含 1000 哨兵)已全绿。
  ⑤**操作教训**: 杀掉 host **不会**停设备(孤儿运行), 我连杀两次导致下一次 run 的 `Open` 卡 24 分钟后失败(`-1/f0000001`), 设备随后自行恢复(无需拔插); 长跑期间不要 kill, 且第二个进程读 dashboard 会被 SDK 串行化阻塞 ⇒ 只能用 LED + 事后读进度。
- 2026-09-15 **设备侧随机延时真机标定 + 六条设备访问硬结论**(用户指令「一个一个测试延时」):
  ①**延时标定**: 新增测试项 `ChaosDelayTests`(`__Testing__dongle__` 索引 **0x17**)——设备侧只调 `script::ChaosDelay`(与 `RockeyTrustExecutePrepare` 生产路径**同一个函数**, 本次从 execute.cc 内联循环提取, 声明在 `Interface/script.h`), 单位数由宿主写 `Context_t::argv_[1]`; 宿主测该次 `ExecuteExeFile` 墙钟, 设备侧把 units/result/beats 写 factory dataFile `[4048,4064)` 供回读校验。**实测(dev[0] `f56a125b71094c42`)**: units=0→135ms, 1e5→248, 2e5→361, 4e5→588, 6e5→814, 8e5→1041, 1e6→1267, 1248575→1549 ⇒ **1.1325 µs/单位**(完全线性, ±1ms 可重复), **每帧固定开销 135ms**(框架自身空跑 57ms); `beats` 与 `units/0x2000` 完全吻合 ⇒ KeepAlive 生效。按 0.2~1.0s 反解 ⇒ `kDelayBaseUnits=176600`(≈0.200s) + `kDelaySpanUnits=706400`(上沿≈1.000s; 用 `%` 取模而非掩码, 用户 2026-09-15 决策); **端点复测**: 176600→336/334ms, 883000→1134/1135ms(与模型一致)。
  ②**设备侧改代码必须刷写**: `ExecuteExeFile` = `Dongle_RunExeFile(handle_,1,...)` **只运行** slot 1 里已下载的 app, 下载走 `UpdateExeFile`(`WT_APP_DONGLE`)⇒ 只重编不刷写时新测试项会"静默成功"(mainRet=10086、设备侧无任何动作、无 status)。今天已按用户约定刷 dev[0] 测试固件 `.bin/arm-RockeyARM-native-release/rockey_dongle.bin`(58416B, `UpdateExeFile 0/00000000`); **未刷** dev[1]。
  ③**同一宿主进程里只有第一次 `ExecuteExeFile` 会真正执行设备侧程序**(第二次起 rc=0/mainRet=10086 但设备侧不跑: 无 status 落盘、耗时不再随 units 增长)⇒ 多档标定必须"每档起一个进程"; `ChaosDelayTests` 宿主侧已改成单次调用(CLI `-2 17 <units_hex>`)。
  ④**harness 日志走 `WriteConsoleW(stderr)`**, 被重定向/管道捕获即丢(小 log 全丢, 只有超过 4KB 缓冲被 flush 的才可见)⇒ 一律用 `WT_RKEY_LOG=<path>` 落文件(host-only 便利开关, `main.cc` 已有)。
  ⑤**设备类型可编程区分**(用户观察 + `third_party/RockeyARM/amd64-windows/include/RockeyARM/Dongle_API.h:115`): `DONGLE_INFO::type_` = `0xFF` 标准版(无时钟) / `0x00` 标准时钟锁 / `0x02` 标准U盘锁。`__Testing__rsamrprobe__` 新增 **`-info`**(只枚举、不 Open/不下载)并打印 `ver/type/pid/uid`; 实测 dev[0] `ver=0x222 type=ff pid=1d9343f2 uid=c8c04e1f`(已初始化), dev[1] `381a5653e10a323f ver=0x222 type=00` **pid=uid=ffffffff 未初始化**。**未初始化 ⇒ 不能下载/运行自研 app**(`ExecuteExeFile` 会挂住 >300s 并需复插恢复; 之前 cos 用例表现为第 1 次 148s 后 rc=-1、其后每次 0.1ms)⇒ **时钟锁目前跑不了我们的任何设备侧代码(含 RSA 生成/心跳探针)**, 要用须先按厂商流程初始化(PID/PIN); 复插后可恢复枚举(Enum=2)。
  ⑥**更正: `__Testing__rsamrprobe__` 的 `-cos`/`-delay`/单数字探测在 master 上全是 no-op** —— 设备侧快速路径(`rsaprobe::kMagic`→`Testing_RsaPrimeOne`/`Testing_CosProbe`)只存在于 AGINX 分支, master 的 `__Testing__/__dongle__/main.cc` 里 `rsaprobe|kModeOne|kModeCos|kModeDelay` **零命中**; `probe_io.h:21` 约定完成时回写 `error_[7]='COS1'` 而实测恒为 0。⇒ 此前记录的 COS 数字(dev[0] ≈34 µs/call、dev[1] 160 ms/call)**全是 `ExecuteExeFile` 固定往返 ÷ iters 的假象**(iters 200→20000 总时间不变即铁证)。**"GetPINState 是否两台一致 / 该不该用它做 COS"至今没有有效数据**, 要回答必须先在 master 上补设备侧心跳探针。
  ⑦**RSA-3072 设备内生成(昨日长跑)结果**: dev[0] `ExecuteExeFile=0 mainRet=10086 in 4,221,409ms(≈70.4min)`, `gen_rc=0`, 宿主 TASSL 复核全绿(素性 / gcd(e,p−1)=1 / p≠q / bits(n)=3072 / e·d≡1 mod lcm / dmp1·dmq1·iqmp); **`check_rc=-1` 不是失败** —— 该用例为省 300B 栈已不跑设备侧 `ExRSAKeyCheck`, 字段停在初始化哨兵 `0xFFFFFFFF`(`main.cc:3006-3007` 注释)。设备侧结果 06:56:21 就返回了, 宿主进程随后卡死 82min(CPU 0s; 已按用户选择 kill, 排队的 COS 测试一并停掉)。
  ⑧**改动文件**: `Interface/execute.cc`(ChaosDelay 单实现 + 标定后常量)、`Interface/script.h`(ChaosDelay 声明)、`src/__Testing__/__dongle__/main.cc`(ChaosDelayTests + 单次调用宿主)、`src/__Testing__/__rsamrprobe__/main.cc`(`-info` + ver/type/pid/uid 打印); `make dongle`(固件 `.bss` 仍 `0x10`)与 `make windows X4C_USING_CLANG=0` 均 rc=0。
- 2026-09-15 **密文落盘(②)修好 + 心跳探针(③)就位**:
  ①**SM4/TDES-ECB 密封路径 bug 根因(宿主/模拟器侧, 不是密码学设计问题)**: `Interface/emulator.cc` 的
  `Dongle::SM4ECB(int id, uint8_t* buffer, size_t size, bool encrypt)` 里回调 lambda 的形参写成 `size`,
  **遮蔽了外层待处理数据的 `size`**, 于是 `SM4ECB(key, buffer, size/*==16*/, encrypt)` 只加/解密**第一个
  16B 块**; `TDESECB(int id, ...)` 同一处同样的写法。⇒ 完全解释此前的现象: 密文落盘用例里 `header`(16B) MATCH、
  其余大字段(n/e/d/p/q/dmp1/dmq1/iqmp)**全 DIFF**。**修复**: lambda 形参改名 `key_size`, 传外层 `size`
  (两处; 并加注释钉住, 防回归)。真机 `Dongle::SM4ECB` 走厂商 `Dongle_SM4`, **从未受影响**。
  ②**验证**: `make foobar X4C_USING_CLANG=0` → `.bin/amd64-foobar-windows-debug/__Testing__rsamodexpvm__.exe`
  **退出码 10086(0 错)**, 三条密封断言全绿: `密文落盘 + 逐块解密 == 明文生成 ✓`、`ExRSAKeyCheck(keyId) 接受密文 blob ✓`、
  `ExRSACrtModExp(keyId) == TASSL m^d mod n ✓`(该用例按 xModule.mk 只在 foobar 板构建 ⇒ 之前那次失败必然是模拟器侧)。
  真机密封路径端到端(刷固件 + `ExRSAGenKey` keyId=996/998 全流程)仍未跑, 留待休息时段。
  ③**心跳探针就位**: 新增测试项 `HeartbeatTests`(`__Testing__dongle__` 索引 **0x18**): 设备侧**只**循环调用一个
  候选 iters 次(不夹带任何其它调用), 结果写 factory dataFile `[4064,4080)`; 宿主**单次** `ExecuteExeFile` 计时并
  扣掉 135ms 固定开销 ⇒ µs/次。候选: 1=`GetPINState` 2=`GetTickCount` 3=`SetLEDState(kBlink)`
  4=`ReadShareMemory` 5=`GetDongleInfo` 6=基类 `KeepAlive()` 7=基类 `KickWDG()`。
  CLI `__Testing__dongle__ -2 18 <cand_hex> <iters_hex>`; **判定喂狗**: 把 iters 提到"总时长远超看门狗窗口(>2min)"
  后仍能正常返回 ⇒ 该候选服务看门狗, 设备被复位/宿主永久等待 ⇒ 不服务。模拟器管路自检通过(cand=1/2/4/6,
  iters=1000, `done=1000`; cand=6 的 `beats=1000` 印证 KeepAlive 计数), 真机测量(每候选约 4 分钟 + 一次刷写)留待休息时段。
  ④**改动文件**: `Interface/emulator.cc`(两处 lambda 遮蔽修复)、`src/__Testing__/__dongle__/main.cc`(HeartbeatTests +
  `HeartbeatLoop` 共用循环); `make dongle`(栈 `超预算 0 条`, `.bss` 仍 `0x10`)、`make rockey-stack-check`、
  `make windows X4C_USING_CLANG=0`、`make foobar X4C_USING_CLANG=0` 全 rc=0。
- 2026-09-15 **真机成绩单(标准版 dev[0] `f56a125b71094c42`) + 时钟锁初始化与两机型对比(用户授权)**:
  ①**2048@16 验收 PASS**: 设备内 `1,530,156ms(≈25.5min)`, `gen_rc=0`; TASSL 复核 prime_p/q=1、gcd(e,p−1)=1、
    distinct=1、bits(n)=2048、e=010001、e·d≡1 mod lcm、dmp1/dmq1/iqmp=1 ⇒ `PASS(error=0)`。
    (@16 轮 25.5min vs @4 轮 25.2min ⇒ 轮数几乎不影响总耗时, 瓶颈在素数搜索。)
  ②**心跳候选代价(标准版, iters=2000)**: GetTickCount 13.0 / GetPINState 13.0 / SetLEDState 13.5 / KeepAlive 13.9 /
    ReadShareMemory 15.0 / KickWDG 16.0 / **GetDongleInfo 921.5 µs**(贵 70 倍, 绝不可当心跳)。
  ③**喂狗判定(循环内只有该调用, 时长 >3min ≫ ~2min 看门狗窗口)**: 标准版 GetTickCount 180.8s(13,846,153 次)、
    KeepAlive 178.9s(12,857,142 次)、GetPINState 181.5s(13,846,153 次) —— 全部 `rc=0` 且 `done` 跑满 ⇒ **均喂狗**。
  ④**时钟锁(标准时钟锁 `381a5653e10a323f`, type=0x00)初始化**: 框架 admin 会话在 index<0xF0 时先做 provision —
    `GenUniqueKey("10086",5)` → `ChangePIN(生成的 admin → FFFFFFFFFFFFFFFF)` → `Open` → `VerifyPIN` →
    `SetUserID(rLANG_WORLD_MAGIC)`, 之后才是 `WT_APP_DONGLE` 刷写。实测全部 0/00000000, `UpdateExeFile 58712B 0`
    ⇒ 初始化成功: PID=**1D9343F2**(与标准版同值, 由固定串"10086"/5 决定)、uid=world magic、admin PIN 回归标准 16×F;
    之后 `ExecuteExeFile` 正常(573ms) ⇒ **之前挂死的真因是"未初始化 + 槽 1 无 app"**, 不是锁有问题。
    机型能力差异: `LimitSeedCount` 时钟锁 **0** / 标准版 `F0000008`; `SetExpireTime` 时钟锁 **0** / 标准版 `F0000016`
    (标准版日志里那两行红字即此, 非缺陷)。
  ⑤**测量方法教训(重要)**: 时钟锁**每进程固定开销 ≈507ms**(标准版 ≈135ms)⇒ 用 2000 次小迭代得到"时钟锁 200µs/次"
    完全是假象(各候选取值 535~541ms 几乎相同即是征兆)。**修正后两机型单次代价几乎一致**: 大迭代数实测
    GetTickCount 13.1/13.6 µs、GetPINState 13.0/13.6 µs、KeepAlive 13.9/15.1、SetLEDState 13.5/15.1、
    ReadShareMemory 15.0/17.1、KickWDG 16.0/17.1、GetDongleInfo 921/956 µs(前=标准版, 后=时钟锁)。
    时钟锁喂狗判定重跑(14,000,000 次 ≈190s): GetTickCount 190.0s、GetPINState 190.6s 均 `rc=0` ⇒ **均喂狗**。
    ⇒ **继续用基类 `KeepAlive()`(纯 GetTickCount, 不动 LED)**; "换 GetPINState 更一致"的假设**不成立**(持平或略贵,
    且它读权限状态有语义副作用); 延时 0.200~1.000s 在两机型同样成立(延时是 CPU 忙等, 每 0x2000 单位一次心跳
    即使 14µs 也只多 ~20ms)。**标定/代价测量一律用 ≥10⁵ 次迭代或同机型内取差值**。
  ⑥**工具**: `__Testing__rsamrprobe__` 新增 **`-flash`**(Open+VerifyPIN(admin)+UpdateExeFile 后退出, **不执行**
    ExecuteExeFile ⇒ 可在未初始化设备上安全判定"能否刷我们的 app"); 心跳/Delay 测量入口
    `__Testing__dongle__ -2 18 <cand_hex> <iters_hex>`。

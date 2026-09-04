# Rockey-Dongle 项目审查上下文记录

> 本文件是 2026-09-01 ~ 2026-09-02 一次完整代码审查会话的工作上下文,并持续维护至 2026-09-04(§9 复核、§10 后续提交),供后续会话/接手人直接续接工作,避免重复分析。
> 配套交付物:`bug-analysis-report.html`(完整带样式报告,含图表)。

---

## 1. 任务背景

- **用户请求**:① 分析项目有没有 bug;② 评估项目难易程度;③ 生成 HTML 报告;④ **重点检查设备端随机数发生器**。
- **审查方式**:4 路并行深度审查代理 + 主会话独立 RNG/基础库分析 + 可执行验证。
- **审查对象**:master@8555281,自研代码约 33,000 行(不含 `third_party/TASSL`),测试约 5,600 行。
- **结论**:确认 **51 项问题**(Critical 4 / High 11 / Medium 12 / Low 24),难度评级 **专家级 9/10**。

## 2. 项目关键事实(审查中核实,勿重复推导)

### 2.1 构建与模块结构
- 平台:MCU 固件(arm-none-eabi,RockeyARM)/ Linux / Windows / Cygwin / aarch64-linux / WASM / wasmjs,自研 x4c 构建系统(`Build/`)。
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
- 不可消除:glibc 静态链接 dlopen/getaddrinfo/gethostbyname 警告(来自 glibc .gnu.warning 桩,TASSL 依赖这些符号);设备固件 readelf "bogus end-of-sibling" 提示。
- 既有问题(未修):wasmjs 配置链接失败(Web/Emulator pki.cc 的 RockeyPKEY_Sign/Decrypt 为 rLANGIMPORT,宿主无 JS 实现)。

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
- **严格 DER 解析**:≤1KB 证书就地零拷贝;拒绝 indefinite/非规范编码/尾随字节/负 INTEGER。
- API:`X509Parse / X509VerifySignature / X509VerifySelfSigned / X509ExtNext / X509CheckTime / X509GetPublicKey` + 9 个 `X509OID_*` 判断。
- **验签全走硬件/宿主库**:RSA2048-SHA256(FTRX rsa_pub / TASSL RSA_verify)、P256-SHA256(FTRX ecc_verify / TASSL)、SM2-SM3(FTRX sm2_verify / TASSL EVP_SM2 别名路径,e = SM3(Z_A||tbs) 标准语义)。
- 设计要点:时间检查只置警告位(设备 RTC 不可靠);遵守固件无 rodata/无除法约束(OID 立即数比对、拆包/日期解析无 / 与 %)。
- 新增 `src/__Testing__/__x509__/`(320 行):TASSL 生成 RSA/P256/SM2 CA+叶证书,正反例与 OpenSSL X509_verify 对照 0 错误;stack-check 0 违规。
- **⏳ 待办:脚本层 OpCode 尚未接入(用户后续接入)**;接入后固件 text 增量约 3.5–4KB,余量充足。

### 10.4 2026-09-04 X509 摘要扩展 SHA384/512 + cLAUD 代码签名宏(未提交,本会话)

- **RSA/P256 支持 SHA384/512**:`X509SigType` 新增 4 值(RSA_SHA384/512、P256_SHA384/512,值 4-7),classify_sigalg 与 OID 谓词补齐 4 个 OID;SM2 仍固定 SM3。
- 摘要计算全部移入 work 区(布局 `[Sha*Ctx 240B][md 64B]`,work 下限 752→**304B**);三种 Sha*Ctx 同尺寸(240B,同一 `rlCryptoShaCtx`)。
- **P256+SHA384/512 按 FIPS 186-4 §6.4 截取左 256 位**作 e(P256Verify 接口固定 32B 摘要,设备 FTRX 与宿主 TASSL 一致;摘要已与 OpenSSL 实测一致)。
- `RSAVerifyPkcs1` 签名加 md_type 参数(`Dongle::X509Digest` 枚举,值即摘要字节数 32/48/64):设备端 DigestInfo 前缀立即数比对参数化([1]=19+len、[14]=(len>>4)−1、[18]=len);宿主/模拟器映射 NID_sha256/384/512。真机检查点扩展:SHA384/512 的 COS 解填充行为本机无法验证。
- **X509GetPublicKey 改按证书自身 SPKI OID 分派**(原按 sig_type:叶证书密钥类型与签发者签名算法不同时错路由;混合链测试覆盖此修复)。
- 测试 __x509__:**8 条链**(RSA/P256×SHA256/384/512、SM2×SM3、P256-CA 签 RSA-叶混合链)+ EC 公钥提取断言,与 OpenSSL X509_verify 对照 **0 错误**;aarch64-linux/foobar/`make dongle` 构建全过;stack-check 0 违规(稳态 1784B 不变,X509 链未接 VM 不计入);固件 text 仍 49024B(X509 函数无调用方被 gc-sections 裁掉,OpCode 接入时才计入)。
- **代码签名宏(用户 2026-09-04 决定,2026-09-05 修订)**:Claude 编写的代码用专属命名空间宏;昵称 Claude(克劳德),前缀原为 `cLAUD`。2026-09-05 用户决定前缀改为 **`AGINX`**(取产品名而非作者代号,避免每位协作者各占一对宏使 base.h 膨胀)。base/bits/base.h 已定义 `AGINX_DECLARE_MACHINE`/`AGINX_DECLARE_END`(与 rLANG 同构),x509.cc 与 __x509__ 测试已采用。

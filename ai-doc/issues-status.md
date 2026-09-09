# Rockey-Dongle 审查问题状态清单(issues-status, 2026-09-09)

> 来源:ai-doc/bug-analysis-report-2026-09-01.html(2026-09-01/02 审查, 51 项)+ ai-context §9/§10 修复复核记录。
> 状态标记:✅ 已修复并验证 · 🔒 关闭(用户/设计决策) · ⚠️ 机制不同但效果达标 · ❌ 未落地(仍开放)。
> CI/评审引用:每次改动后由 `make ci`(hooks 自动)跑模拟器回归;本清单用于人审核对。

## 状态汇总

- Critical 4/4 ✅ · High 11:10 解决(H-08 ❌)· Medium 12:11 解决(M-01 ❌)· Low 24:13 解决(11 开放, 多设计取舍/低收益)
- 合计 51:**38 已解决/关闭,13 开放**

## 逐条清单

### Critical(4)

| ID | 简述 | 状态 | 验证/备注 |
|---|---|---|---|
| C-01 | digest handler md=nullptr 未检(设备 DoS) | ✅ | script.cc 五处补 `if(md)`;构建通过 |
| C-02 | cipher_memset/memcpy 严格别名,-O2 下 X25519 静默错 | ✅ | 删除自实现改 libc;**-O1/-O2/-O3 RFC 7748/8032 全过**;进入优化矩阵门禁建议 |
| C-03 | --list base64 无界写 2048 | ✅ | 缓冲 2048→4096(最坏 64 只狗 3462) |
| C-04 | rl_BASE64_Read(len=-1) 越界读/无界写 | 🔒 | 用户决策:strlen 模式与现状退出条件一致,调用端保证 NUL/容量,不修 |

### High(11)

| ID | 简述 | 状态 | 验证/备注 |
|---|---|---|---|
| H-01 | DRBG 熵反馈用余数 size(64 倍数→SHA512("")) | ✅ | 三处统一共享 `Interface/TRNG.cc`,`SHA512(size_total)`;NIST 8.45MB 10/10 PASS(统计面) |
| H-02 | >128B 无硬件熵注入 | ✅ | TRNG.cc 按 64B 块逐块 HwARandBytes⊕ChaCha |
| H-03 | 栈预算 2032B 逼近/超限 | ✅ | 方案1(W16)+2(Helper ctx)+3(noinline)实施,违规路径 32→0,稳态 1784/2032B;`Build/tools/stack-check` 入库 |
| H-04 | 启动桩无 BX/BLX 跳转 | 🔒 | 用户确认:MCU 环境 .text 不可读,Cortex-M0 无 BLX 寄存器指令,依赖 app_entry 位置成立 |
| H-05 | ChaChaPoly Open 先解密后认证 | ✅ | 常量时间 tag 比较 + 失败清零 + *size_ 成功才更新 |
| H-06 | X25519 全零输出未检/非规范 u | ✅ | 返回 int + 常量时间全零检查;u=0 返回 -EFAULT;RFC 向量过 |
| H-07 | 负立即数[-0x100000,-0x1001]编码错(减作加) | ✅ | kLoadMNI|M + kAddUI(0x1000-L);**10,987 样本零失配**;corpus 复测(见 __Testing corpus) |
| H-08 | 编译器不建模栈深(运行时 18>16) | ❌ | 未实现;建议 codegen 静态建模 + 门禁;现仅有运行时 stack-check |
| H-09 | OpWriteSecretFile 失败仍提交(回归) | ✅ | c72d21c 引入回归;2026-09-03 重做(读改写修复),基线对照 i2 两轮 0 错 |
| H-10 | 模拟器 Open 失败即 Create+"wb" | 🔒 | 用户决策:仅测试用途镜像,每次重新生成,保留 |
| H-11 | elf2bin 丢弃多 PT_LOAD 段 | ✅ | 恢复 phnum 校验,允许空 g_FEI 段 |

### Medium(12)

| ID | 简述 | 状态 | 验证/备注 |
|---|---|---|---|
| M-01 | Interface ge_scalarmult 秘密依赖分支 | ❌ | 未实施;建议评估接入常量时间版本 |
| M-02 | 私钥清零被 DSE 删除 | ✅ | volatile 逐字节清零(curve25519.cc:2292/dongle.h HashBase) |
| M-03 | 前导零十进制按八进制截断("09"→0) | ✅(⚠️机制) | 词法层(dongle.sc DEC 正则排除前导零),"09" 不再静默八进制;行为目标达成 |
| M-04 | Load/Store 常量地址不对齐检查 | ✅ | grammar 编译期对齐校验(memoryAccessSize) |
| M-05 | public>256 输出覆盖输入 | 🔒 | 用户设计决策:public 上界恢复 0..1024(布局 TEXT256+DATA768,整体输出) |
| M-06 | Exit(非0)清空输出 | 🔒 | 用户决策:非零即异常,不分辨错误,保留 |
| M-07 | 主机 GetPINState 恒失败(逗号表达式) | ✅ | 诚实 `-ENOSYS` 存根(SDK 无查询 API) |
| M-08 | ComputeSecretSecp256k1 返回约定相反 | ✅ | 改 `?0:-EFAULT` |
| M-09 | 私钥材料残留/BN_free | ✅ | BN_clear_free + 全局 `-DBN_free=BN_clear_free`;emulator.cc 三处修正 |
| M-10 | PIN 入日志 | 🔒 | 设计哲学("ukey 之外信息众所周之")+ FINAL_LOCK 宏门控 |
| M-11 | ExecutePrepare 校验顺序颠倒 | ✅ | 先校验 vm.data_/vm.buffer_ 再 memcpy |
| M-12 | HwARandBytes 失败不查/无重播 | ✅ | 构造重试3次+清零;RandBytes 检查返回值返回 -EFAULT;TRNG.cc 持续熵注入;失败注入测试见 `__Testing__trngfail__` |

### Low(24)

| ID | 简述 | 状态 | 验证/备注 |
|---|---|---|---|
| L-01 | 移位量≥32 静默截断 | ✅ | grammar 编译期 RangeError(立即数+常量折叠 6 处) |
| L-02 | 逻辑运算结果不对称 | ❌(保留) | 改语义可能破坏既有脚本;建议测试锁定当前语义 |
| L-03 | WASM 解析栈 256 层报错误导 | ❌ | wasm 侧改动,暂缓 |
| L-04 | SM2Cipher ASN1 API 无长度参数 | ❌ | 接口变更待产品决策 |
| L-05 | CreateDataFile 负尺寸 | ✅ | 负/零/超限返回 -EINVAL(统一) |
| L-06 | 读取失败仍哈希 | ✅ | 仅两读成功后才哈希 |
| L-07 | Enum 不钳制 count | ✅ | `DONGLE_VERIFY(count<=64)` 契约断言 |
| L-08 | TDES 长度校验 %16 应 %8 | ✅ | script.cc 改 %8(SM4 保留 %16) |
| L-09 | ScopeRNG 全局指针竞态 | ❌(潜伏) | 单线程;注释标记非线程安全 |
| L-10 | pki RAND_seed 未初始化缓冲 | ✅ | 缓冲零初始化(wasm 构建已随 emsdk 就位后验证) |
| L-11 | 模拟器权限/计数不落实 | ⚠️部分 | 2026-09-09 已实现 licence 计数递减(会话内);文件权限仍不强制;真机为准 |
| L-12 | 模拟器默认弱主密钥 | ❌(保留) | 仅测试;文档标注 |
| L-13 | READ_MASTER_SECRET 失败仍覆写输出 | ✅ | 失败立即清零并返回 -EFAULT |
| L-14 | READ_MASTER_SECRET 错误路径不清零 | ✅ | 两错误路径补 memset |
| L-15 | isxdigit 负 char UB | ✅ | cast unsigned char |
| L-16 | DONGLE_VERIFY abort | ❌ | 畸形镜像可 DoS 宿主;评估收益后定 |
| L-17 | rand() 未播种 | ✅ | 删除无意义 rand() |
| L-18 | sha256 size_t→int 截断 | ✅(⚠️机制) | internal len int→size_t 加宽 + 去 (int) 强转;sha256 套件 0 错 |
| L-19 | ChaCha 32 位回绕 | ❌(不可达) | 保留注释,不做 |
| L-20 | Ed25519 非规范公钥(设计取舍) | ❌(取舍) | ref10 行为;文档标注 |
| L-21 | Ed25519 PubkeyEx 无 clamp(#if0) | ❌(取舍) | 调用方保证;文档标注 |
| L-22 | ge_scalarmult 读未初始化 T | ✅ | dummy T 单位点初始化;25519 套件 0 错 |
| L-23 | rlCryptoRandBytes 熵池无播种 | ❌ | 接主 RNG 或删除该函数 |
| L-24 | 日志颜色复位码被覆盖 | ✅ | efmt sprintf 返回值累加 |

## 引用与更新约定

- 本清单随 bug-analysis 报告复查/修复同步更新(报告 + 本文件 + ai-context 三处一致)。
- CI(`make ci`)不直接解析本表;人审与提交信息引用之。

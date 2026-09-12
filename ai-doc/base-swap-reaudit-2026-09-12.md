# base/Build 换基后的「漏合并」复查(2026-09-12)

> 触发:换基后 `make test-optmatrix` 的 `-O2` 档失败,根因是 fork 的 **C-02** 修复没随换基走(已修,见 `ai-context.md` 2026-09-12 两条记录)。
> 本文件是对「还有没有第二个 C-02」的系统复查。
>
> **方法**:把 `14edea1`(vendored fork)与上游 `base a9eb747` / `Build db0ebfc` 逐文件 diff,
> 先机械筛出「**fork 有、上游没有**」的行(纯裁剪只会表现为「上游多出代码」,所以这批行才是疑似被丢掉的修复),
> 再逐条判定,并与 `ai-doc/issues-status.md`(51 项)与 `bug-analysis-report-2026-09-01.html`(15 处定位)交叉核对。

## 1. 逐文件判定

| 文件 | fork 独有行 | 上游独有行 | 判定 |
| --- | --- | --- | --- |
| `base/base.h` | 1 | 0 | 空行,无关 |
| `base/bits/base.h` | 95 | 448 | fork 独有 = 产品宏 `AGINX_DECLARE_MACHINE`(本仓由 `Interface/aginx.h` overlay 提供 ✓)、`rlLOG_NONE`(本仓 0 处引用 ✓)、版本宏(4.10.100 vs 上游 4.12.120)、旧 `typeof` 写法(上游已改 `__typeof__`);关键符号计数一致:`rLANG_CONTAINER_OF` 7/7、`rLANG_VERIFY_TRUE` 3/3、`rLANG_DECLARE_PRIVATE_CONTEXT` 7/7、`IS_LITTLE_ENDIAN` 8/8、`rLANG_VERSION_RELEASE` 2/2 |
| `base/bits/task.h` | 5 | 2 | 注释 + 空格 |
| `base/scanner/scanner.cc` | 3 | 14 | **上游领先**:上游新增 `__std_abs` 模板替代 `std::abs`、INL 路径改 `base/Web/...` |
| `base/src/base.cc` | 7 | 21 | **上游领先**:上游新增 `rLANG_CONFIG_MINIMAL_WORLD` 门控与 wasm 时间戳分支(换基正需要) |
| `base/src/crypto.cc` | 2 | 4 | **等价**:C-02 已补(上游 `a9eb747`)✓;仅 B1 注释中英文措辞不同 |
| `base/src/data.cc` | 37 | 31 | LIMIT 无表 CRC:`rLANG_CONFIG_ENABLE_LIMIT_WORLD` 门控 4/4、无表 `rlCrc*` 7/7、CRC 查表 7/7 —— **完全一致** ✓;fork 独有 = C-04 说明注释 |
| `base/src/log.cc` | 65 | 266 | 设备日志裁剪;VERIFY 钩子上游**有定义**(`src/log.cc:590/594`)✓;`!tag` 空指针守卫两边都有 ✓(fork 写 `level <= rlLOG_NONE`、上游写 `level < rlLOG_FATAL`,等价);仅 `LOGDATA_SIZEMAX` 默认值不同(§3) |
| `base/src/task.cc` | 14 | 12 | **上游领先**:平台装配被 `#ifndef rLANG_CONFIG_MINIMAL_WORLD` 包裹 + 用 `Magic::Xs` |
| `base/xModule.mk` | 2 | 13 | **上游领先**:改为显式列源目录,并新增 `__Testings_base__` 模块(用 `rLANG_CONFIG_MINIMAL_WORLD` **make 变量**门控;本仓 `project.local.mk` 已设 1) |
| `Build/Main.mk` | 6 | 5 | 构建系统版本号与 `-O1/-O2`(已决定取上游;`-O2` 在 C-02 修复后通过矩阵验证 ✓) |
| `Build/config/arm-none-eabi.conf` | 9 | 3 | fork 独有 = **我们故意移走**的 `-DrLANG_CONFIG_ENABLE_LIMIT_WORLD`(现由 `MCU/RockeyARM/rockey_predef.h` 提供 ✓) |
| `Build/core/{common,build-binary,build-executable,build-shared-library}.mk` | 17/4/2/2 | 7/1/1/1 | 注释 + `rLANG_COMMON_STRICT_*` / `X4C_UNWIND_TABLE_CFLAGS` 空缺省(设备由 `project.local.mk` 覆盖为「无 unwind 表」✓) |
| `Build/tools/README.md`、`Build/tools/LIMIT/README.md` | 2 / 0 | 3 / 10 | 文档差异,即本轮 `tools/ci → tools/LIMIT/ci` 迁移的产物 ✓ |
| `Build/tools/script/{grammar.actions,wasm2string}.cjs` | 108 / 16 | 108 / 16 | **两侧行数相同 ⇒ 纯换行(CRLF/LF)差异** ✓(无逻辑改动) |

## 2. 清单级交叉核对

`bug-analysis-report-2026-09-01.html` 的 15 处定位里,**只有 4 处涉及 `base/`**:

| 条目 | 定位 | base 侧是否需修 | 现状 |
| --- | --- | --- | --- |
| **C-02** | `base/src/crypto.cc:24-151` | **需要** | ✅ 已补(上游 `a9eb747`,签名并推双远端) |
| C-03 | `src/app/main.cc:652` → `base/src/data.cc:89` | 否(调用端把缓冲 2048→4096) | ✅ 本仓文件,未受换基影响 |
| C-04 | `base/src/data.cc:49-87` | 否(用户决定关闭,仅注释) | 🔒 关闭 |
| H-06 | `base/src/crypto.cc:5449-5453` + `Interface/curve25519.cc` | 是(B1) | ✅ 上游已有(`fed3808`) |

其余 11 处定位全在本仓(`Interface/*`、`src/app/*`、`MCU/*`、`Web/*`)⇒ **换基不触及**。
`issues-status.md` 里 13 项开放条目(❌/🔒)本就未实现或按设计关闭,与换基无关。

## 3. 结论与可选跟进

**结论:除 C-02 外,换基没有再丢掉任何修复。** base/Build 的剩余差异全部落在三类:①上游领先(fork 是旧快照);
②我们有意保留的 overlay(`AGINX_DECLARE_MACHINE`、`LIMIT_WORLD` 位置、unwind 表为空、`MINIMAL_WORLD` make 变量);
③注释/版本号/换行。

**可选(均非正确性;第 1 项经用户确认后已完成,其余保持现状)**:

1. ✅ **已完成(用户确认)**:`rLANG_CONFIG_LOGDATA_SIZEMAX` 默认值 1024 → **2048**(上游 base `evolution` `14a921b`,已签名并推内网 + GitHub)。该宏只影响**宿主**日志行缓冲(`char info[N+256]`,Windows 另有 `wchar_t ws[4*N]`:8KB→16KB);设备侧 `rlLOGx` 由本仓 `MCU/RockeyARM/rockey_predef.h` 全局覆盖为空,相关实现也不参与设备构建 ⇒ 设备指标实测不变(固件 65520B、`.text 0xc910`、`.bss 0x10`、栈 1936B ≤ 2032B)。宿主门禁:`make ci` 8/8、`make test-optmatrix` 4/4、`jsWrapper`/`linux`/`dongle`/`rockey-stack-check` 全 rc=0。
2. C-04 的说明注释未上游(纯文档)。
3. 上游 `log.cc` 的 VERIFY 钩子未按设备(`__RockeyARM__`)给空实现;实测设备 `.bss` 仍 **0x10**、无链接错误 ⇒ 无影响。
4. base 版本宏上游为 4.12.120(fork 快照是 4.10.100);固件随之报上游版本,与「取上游」的既定决策一致。

**方法沉淀**:把 fork 差异判为「设备裁剪/不必合并」之前,先查 `issues-status.md` 与 bug-analysis 是否有对应条目,
并用「fork 独有行」筛选法过一遍 —— C-02 这类「只在 `-O2` 下静默出错」的修复最容易被误当成实现风格差异丢掉。

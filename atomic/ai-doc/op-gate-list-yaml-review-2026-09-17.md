# `atomic/op_GATE/list` + 生成器 `gen.cjs`: 格式评审 (2026-09-17, 第七版)

> ✅ **生成器已实现并全部实测** —— `atomic/op_GATE/tools/gen.cjs` (+ `tools/README.md`)。
> 第二版的 `named_args` 建议已撤回 (变参由桩内部造 `va_list`); 第三/四/五版围绕"手写 uuid + 锁定"的建议已作废 (见 §3)。

## 1. 用户的八条裁定

1. **YAML 不描述原型** ⇒ host 直接从 `VM_t::hart_t` 读 `a0..a7`/栈。
2. **门号两级**: pc 给"导出槽位" (`jalr x0, op_GATE_<lib>__kIndex*4(zero)`), `t0` 给"组内条目号" (`li t0, N`)。
3. **变参由桩内部消化**: "我实现一个**内部产生 `va_list` 的桩**, 之后就是普通的函数调用了"。
4. 号位重新分配: **`[64, 511]` 完全归我们**; **`[-512, -65]` 留给用户私有实现**。
5. **每次编译都重新生成这组导出函数** ⇒ "**完全不用考虑兼容性问题**"; Makefile 每次编译**先删掉 `gen/`**, 所以每次都是空目录里全新建。
6. **槽位由洗牌分配**: "使用一个简单的洗牌算法让列表里的 `op_GATE_kIndex` 使用**这四个随机数**对 `kIndex` 进行分配" (四个随机数 = Makefile 里的 `rLANG_WORLD_SEED_0..3`)。
7. **文件名必须稳定**: "文件名不要发生变化, 就用 `op_GATE_libgcc.h` 这样的就可以, **不然编写封装函数将比较麻烦, 包含头文件都不知道是谁**"。
8. **内容摘要保留**: "**按导出函数算出 uuid 的功能需要保留**" (即 `SHA1(库名 + 导出函数列表)`)。

## 2. 摘要 (保留) 与锁定 (移除)

- **保留** `__kIdSha1` = `SHA1("op-gate-export/1\n" + 库名 + "\n" + 函数列表… + "\n")` ⇒ 40 hex; 并新增 **`op_GATE__kWorldId`** = `SHA1("op-gate-world/1\n" + 4 个随机数 + "\n" + 每个导出的 (库名:kIndex) …)` —— 它的用途是让 **host 与 guest 核对"是不是同一组随机数、同一份分配"**。
- **移除** 上一版的 `op_GATE.lock.json` 与"就地修改已发布导出 ⇒ 报错"的检查: 既然每次编译都在空目录里全新建、且不追求跨编译兼容, 锁定就没有意义 (留着反而会让"改函数列表"这种事**挡住构建**)。

## 3. 洗牌分配 (裁定 4/5/6 的落地)

```
seed  = 4 个 32 位随机数 (Makefile 的 rLANG_WORLD_SEED_0..3)
rng   = xorshift128 (四个数全部作为状态; 全 0 时退化为固定常量)
slots = [64 … 511]  (448 个)
洗牌  = Fisher-Yates (rng() % (i+1) 逐个交换)
取槽  = 按**库名字典序**排好的导出, 依次取 slots[0], slots[1], …
```

- **与我们自己的窗口对应**: `kIndex` 就是 `pc/4`; 而 JALR 的 12 位立即数把 `kIndex` 限在 `[-512, 511]` ⇒ `[64,511]` 是我们的、`[-512,-65]` 是用户的, 中间 `[-64,-1]`/`[0,63]` 不用于普通导出。
- **按库名排序取槽** (而不是命令行顺序) ⇒ 同一个 Makefile 换文件顺序不会改变分配 ⇒ 更不容易出现 host/guest 不一致。
- 允许在 YAML 里写 `kIndex: <N>` **钉死**某个导出的槽位 (校验必须落在两个区间内), 供用户私有实现使用。

## 4. 产物 (文件名稳定, 裁定 7)

| 产物 | 内容 |
| --- | --- |
| `gen/op_GATE_<lib>.S` | `#define op_GATE_<lib>__kIndex <N>` + 窗口断言 + 每条 `li t0,N` / `jalr x0, <kIndex*4>(zero)` / `.size`; 每个桩单独一个 `.text.<name>.<hash12>` 段 |
| `gen/op_GATE_<lib>.h` | `__kIndex` / `__kCount` / `__kLibrary` / `__kIdSha1` + 条目 enum + `__kEntryNames[]` |
| `gen/op_GATE_manifest.h` | `op_GATE_export_t { library, kIndex, count, sha1, names }` 表 + `op_GATE__kWorldId` |

## 5. ✅ 实测 (2026-09-17)

用用户的命令与随机数 (`--world-seed="0xf4ee5b4e,0x3e7a96da,0x58c6800a,0x4ffbbf43"`):

```
libmusl  kIndex 163   libbase  kIndex 229   libgcc  kIndex 330
world id: d7786707c832b99a70537ad25eb2a511dc0974a5
```

| 验证 | 结果 |
| --- | --- |
| 同一组随机数重跑 | 分配与 world id **逐位相同** ✓ |
| 换一组随机数 (`0x11111111,…`) | 分配变成 `libmusl 79 / libgcc 105 / libbase 477` ✓ (每次编译不同) |
| 三个 `.S` 用真工具链汇编 (不再需要 `-D`) | **rc=0** ✓; `libgcc` 反汇编 `li t0,0/1` + `jr 1320(zero)` (= 330×4 ✓) |
| 头文件在**严格档**下 | guest C (`-Wall -Werror -Wunused -Wextra` + musl 头) rc=0 ✓; host g++ 两个 TU rc=0 ✓; clang++ rc=0 ✓; **只 include 不使用**的 TU 也 rc=0 (靠 `__attribute__((unused))`) |
| `gen/` 先删再生成 | ✓ (每次都从空目录重建) |

**顺手修掉一个 bug**: 上一版里 `\t.text.<name>.<hash12>` 这种段名写法**汇编器不认** (`Error: unknown pseudo-op: '.text.foo.bar'`) —— 带名字的段必须写成
```asm
	.section	.text.__addsf3.ae7ddeed3f59,"ax",@progbits
```

### 5.1 ⭐ 为什么每个桩要独立 section (用户目的: 链接时丢掉"没被真正调用"的)

用户原话: "**让每个函数都在独立的 `section.name` 里, 这样链接时容易去掉没真正调用的**"。
实测 (真工具链 + 我们 `varargs.ld` 的布局; guest 只调用 `__adddf3`、完全不碰 `__addsf3`):

| 链接方式 | 结果 |
| --- | --- |
| 不带 `--gc-sections` (对照) | `nm` 里 **两个桩都在** (`__addsf3` + `__adddf3`); 5004 字节 |
| 带 `-Wl,--gc-sections` | ld 打印 **`removing unused section '.text.__addsf3.ae7ddeed3f59'`**; `nm` 只剩 `__adddf3`; **4952 字节** ✓ |
| 保留下来的那个桩 | `jr 1320(zero)` = `kIndex 330 × 4` ✓ 仍指向门槽位 |

⇒ 独立 section 的写法是对的 (也正因此 `.text.<name>.<hash12>` 必须写成 `.section …, "ax", @progbits`, 见上面那个 bug)。
⇒ ⚠ **但目前构建里没有任何地方传 `--gc-sections`** (全仓 `Build/` 里搜不到; `rv32im-atomic-rockey.conf` 有 `-ffunction-sections` 却没有 gc)。
   等接 **world 链接**那一步时记得加 `-Wl,--gc-sections`, 并且**链接脚本里不要 `KEEP(.text.*)`** (KEEP 会把它们钉住, 与这个目的冲突); 入口/向量等真正的根单独用 `KEEP` 列。

## 6. 仍然缺什么

1. ⚠ **`t0` 是 guest 可控的 ⇒ host 三重校验**: 上界 (`__kCount` 已生成 ✓)、**导入位图**、函数表兜底 —— 后两项要等 **app 规格**定下来才能生成。
2. **app 规格 (唯一还没定的一环)**: 每个 app 导入哪些导出、各自 `kIndex` 是否沿用洗牌结果 (还是 app 单独指定)、是否允许子集导入。定了我就把 app 头 (`kIndex` 表 + 位图 + 函数表 + 世界指纹) 接进 `gen.cjs`。
3. **用户私有实现** (`[-512,-65]`) 的书写方式: 目前只是"工具不分配", 是否要在 `manifest` 里留出位置/校验, 待定。
4. 符号遮蔽与链接顺序 (`.globl` 遮蔽真 libgcc 是**目的**; 两个导出同名 ⇒ 链接期 duplicate 早失败)。
5. 可挂起 / 非确定性标记 (`async` / `deterministic`), 以及变参桩的"命名参数个数" (只需**写桩的人**知道, 建议写在手写桩的注释里)。

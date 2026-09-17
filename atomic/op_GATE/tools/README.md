## 目录下的文件自动生成, 亲不要手动的修改它

`gen.cjs` 由 `list/*.yaml` 生成 `op_GATE/gen/` 下的 guest 桩与头文件。

### 用法 (Makefile 里每次编译都跑一次)

```bash
node ./../atomic/op_GATE/tools/gen.cjs \
     ./../atomic/op_GATE/list/libbase.yaml ./../atomic/op_GATE/list/libgcc.yaml ./../atomic/op_GATE/list/libmusl.yaml \
     --world-seed="0xf4ee5b4e,0x3e7a96da,0x58c6800a,0x4ffbbf43"
```

- `--world-seed` 必须是 **4 个 32 位随机数** (逗号分隔, 支持 `0x` 前缀) —— 直接用 Makefile 里已经算好的 `rLANG_WORLD_SEED_0..3`。
- 产物目录默认 `../gen`, 可用 `--out` 覆盖; **Makefile 每次编译前会删掉 `gen/`, 每次都是全新建**。

### 产物 (文件名**稳定**, 不含 sha1 —— 手写封装函数要 include 它们)

| 产物 | 内容 |
| --- | --- |
| `gen/op_GATE_<lib>.S` | guest 桩: `#define op_GATE_<lib>__kIndex <N>` + 每条 `li t0,N` + `jalr x0, <kIndex*4>(zero)`; **每个函数一个独立 `.text.<name>.<hash12>` 段** ⇒ 链接时可以用 `-Wl,--gc-sections` **丢掉没被真正调用的桩** (实测: 只调用 `__adddf3` 时 ld 会打印 `removing unused section '.text.__addsf3.…'`) |
| `gen/op_GATE_<lib>.h` | `__kIndex` / `__kCount` / `__kLibrary` / `__kIdSha1` + 条目 enum + 名字表 |
| `gen/op_GATE_manifest.h` | 汇总表 `op_GATE_export_t { library, kIndex, count, sha1, names }` + `op_GATE__kWorldId` |

### 号位规则

- **`kIndex` 由洗牌分配**: 用 4 个随机数做 xorshift128, 再对 **[64, 511]** 做 Fisher-Yates 洗牌, 按**库名字典序**给每个导出取一个槽位 ⇒ 与命令行里文件的先后顺序无关, 同一组随机数**逐位可复现**。
- **[64, 511] 归我们** (系统/库导出); **[-512, -65] 留给用户私有实现**, 本工具**不分配** (用户自己 `#define` 即可)。
- 若某个导出想钉死槽位, 可在 YAML 里写 `kIndex: <N>` (会被校验必须落在上面两个区间内)。
- `lib*.yaml` 里 `list:` 的**顺序就是组内 `t0`**; `- { name: xxx, stub: hand }` 表示该条由**手写桩**实现 (例如变参门: 桩内部造 `va_list` 后再普通调用), 生成器只留占位注释。
- 每次编译都重新生成 + 重新洗牌 ⇒ **不追求跨编译兼容** (这正是"每次编译不兼容"的机制); `__kIdSha1` 与 `op_GATE__kWorldId` 只作记录与 host/guest 一致性核对。

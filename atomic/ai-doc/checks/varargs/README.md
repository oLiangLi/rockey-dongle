# 用真 toolchain 验证 RV32IM 可变参数约定 (在 VM_t 上端到端跑)

**2026-09-16 实测通过**: 真 toolchain 编出来的变参程序在我们的解释器上运行, 结果与"同一份源码在宿主编译"逐个相同 (唯一差异是 `long double` 的**目标相关**位模式 —— 见下)。

## 文件

| 文件 | 作用 |
| --- | --- |
| `varargs-test.c` | guest 程序: 覆盖 8 个变参分支 (全寄存器 / 溢出到栈 / `long long` 偶数对 / 凑不出偶数对 / 跳空 / 指针 / `double` 位模式 / `long double` 按引用)。加 `-DHOST_TEST` 可编成宿主程序打印同一张结果表 |
| `varargs.ld` | 链接脚本: 按 ATOMC 最终内存映射把映像放在 `0x10000` (576K), 定义 `__global_pointer$` |
| `run-varargs.cc` | 宿主 runner: 极简 ELF32 装载器 (PT_LOAD→`p_paddr`、bss 清零、从 `.symtab` 找 `g`)、**按最终内存映射实现**的 IMPL、断言 `g[]` 与宿主结果一致 |
| `build-and-run.ps1` | 一条命令跑完全流程 (编 guest → objdump → 编宿主 → 跑解释器) |
| `foobar-sret.c` | **用户 2026-09-16 的提问样例** (原样保留): 返回 `long double` 的函数 ⇒ **sret 隐式第一参数占 `a0`**, 于是 `fmt` 在 `a1`、`1` 在 `a2`…… 只用来**看调用约定** (`vfoobar` 未定义, 不链接): `riscv32-unknown-elf-gcc -march=rv32im -mabi=ilp32 -O2 -S foobar-sret.c`。分析见文档 §7 |
| `foobar-ret-double.c` | **用户的第二版** (返回类型改成 `double`): 8 字节 ⇒ 用 `a0a1` 返回值 ⇒ **没有 sret**, `fmt` 回到 `a0`, 参数分配整体回移一格 (且 `a5` 不再跳空); 内部调用还变成了尾调用。对照表见文档 §7.4 |
| `guest-fmt.c` | **printf 家族跨门**的证明 (文档 §8): guest 只发**一次**门调用 (7 个参数塞满 `a0–a6`, 与 `rlLoggingWriteEx`/`platformLoggingWrite` 的形参表一一对应), 宿主用**原生 snprintf** 格式化。⚠ **门 id 用 `0` 作占位, 宿主侧取参器/格式化器待接线** (等 `atomic` 侧定下门编号与宿主落地位置, 见文档 §8.7) |

## 跑

```powershell
# 工具链默认在 X:\Machine\ATOMIC\rv32im-atomic-rockey\bin (WSL 侧是 /Machine/ATOMIC/...)
# 也可以用 $env:RV32IM_TOOLCHAIN 指定
pwsh -File build-and-run.ps1
```

## 关键前提 (实测)

- `riscv32-unknown-elf-gcc` **16.1.0** / binutils **2.46**, 单 multilib (`--print-multi-lib` = `.;`), 目标 `riscv32-unknown-elf`;
- `-march=rv32im -mabi=ilp32` ⇒ 宏: `__riscv_float_abi_soft=1`、`__riscv_muldiv=1`(M 扩展在)、
  `__LDBL_MANT_DIG__=113`、`__SIZEOF_LONG_DOUBLE__=16` ⇒ **`long double` = binary128**;
- guest 的 `_start` 自己设 `sp = 0x10FFE0` 与 `gp`; 程序结尾用 `ecall` 停机
  (VM 的 `op_ECALL` 默认返回 `SIGILL`)。

## 结果 (2026-09-16)

```
  PT_LOAD vaddr=0x10000 filesz=1184 memsz=1280 flags=7
  entry=0x10460  g=0x104A0
rc=4 (SIGILL, 来自结尾的 ecall)  pc=0x10478  sp=0x10FFE0  cycles=0+646
  PASS  程序以 ecall 结束
  PASS  g[0..7] 与宿主编译同一份源码的结果逐个相同 (21/45/6/15/21/300/0x4000A000)
```

- `g[0]=21` 变参全在寄存器 (被调方造了 28 字节 varargs save area)
- `g[1]=45` 变参溢出到栈 (7 个寄存器 + 2 个栈槽)
- `g[2]=6` / `g[3]=15` `long long` 变参走**偶数起始寄存器对** (a1 被跳空), 多出来的走栈且按 8 对齐
- `g[4]=21` 命名参数占满 a0..a4 后, 8 字节变参**跳空 a5** 用 a6a7, 后续 int 落到栈
- `g[5]=300` 指针变参
- `g[6]=4294705152` `double` 变参 (位模式; 软浮点 ILP32 下同样走整数寄存器对)
- `g[7]=0x4000A000` `long double` 变参 —— **按引用**传 (调用方把 16 字节放进栈、把地址放进槽), `va_arg` 取出指针再读 16 字节; 该值与宿主 (x86 80 位扩展) **不可比**, 是目标 binary128 的属性
- `cycles = 0 + 646` —— 顺带验证了周期计价的"**总代价 = `cycles_` + `cyc_`**"(折叠在 `Execv` 入口)

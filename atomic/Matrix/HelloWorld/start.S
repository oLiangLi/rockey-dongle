	.section .text.crt0,"ax",@progbits
	.align	2
	.globl	_MatrixStart
	.type	_MatrixStart, @function
_MatrixStart:
	lla   gp, __global_pointer$        /* 小数据区 (链接脚本定义 __global_pointer$) */
	lla   sp, _estack                  /* sp = 0x10FFE0; **sp 由 crt 写**, 宿主对其它寄存器不做保证 */
	call  rLANG_op_GATE_Initialize     /* 世界核对: 门数/世界魔数不符 => 宿主拒绝 (高窗 hyper 门) */
	call  MatrixExecv                  /* a0 = 应用入口的返回值 (rLANGEXPORT int MatrixExecv(), 像 main 一样) */
	tail  MatrixExit                   /* = MatrixExit(a0): noreturn 且 a0 原样传下去 => tail 安全 */
	.size	_MatrixStart, .-_MatrixStart

/*
 * 两条"没写下来就会被误解"的契约:
 *  1) `call MatrixExecv` + `tail MatrixExit` 就是 **`MatrixExit(MatrixExecv())`**:
 *     - `MatrixExecv` 是**应用侧入口** (应用用 `rLANGEXPORT int MatrixExecv()` 定义, 自己 return 状态);
 *       库侧在 op_GATE/hyper/hyper.h 里以 `rLANGIMPORT int MatrixExecv();` 引用它;
 *     - `MatrixExit` 是 **noreturn** (内部 for(;;) 只反复调 exit 门) ⇒ 这里 `tail` 不设 ra 是安全的,
 *       而且 a0 一路原样传下去 (状态不经任何寄存器中转)。
 *     ⇒ 若哪天 MatrixExit 变成会返回, 或 MatrixExecv 改了调用约定, 这一段必须跟着改。
 *  2) `.bss` **由加载器初始化** (ELF 语义: p_memsz > p_filesz 的那部分补零), 用户 2026-09-18 定。
 *     所以 crt **不做**清零循环 (别在这里加) —— 这是加载器的契约, 见 ldscript/default.ld 头注释。
 */

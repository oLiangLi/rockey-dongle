/*
 * atomic/Matrix/ldscript/default.ld —— Matrix (ATOMC 应用侧) 的默认链接脚本
 *
 * 内存映射 (与 atomic/ai-doc 里最终确定的布局一致):
 *   0x00000 - 0x0FFFF   不映射         (低 64K; 调用门窗口 0x000-0x7FF 在其中, 靠 pc 拦截, 不需要取指)
 *   0x10000 - 0x9FFFF   程序映像 576K  <= **本脚本管这一段** (ROM+RAM)
 *   0xA0000 - 0xEFFFF   可写设备区     (不存在则写忽略 / 读 0x55AAFF00)
 *   0xF0000 - 0xFFFFF   只读区/ROM     (写必 SIGSEGV => 兼作栈下护栏; ROM 最大 64K-16)
 *   0x100000- 0x10FFFF  用户栈 64K     (sp = 0x10FFE0, 整个栈落在经典 HMA 内)
 *
 * 权限按 **64K 页** 切段 (给宿主/MPU/PMP 用: 每一页只承载一种权限):
 *   .text   RX   /  .rodata R  /  .data + .bss RW(ZI)
 *   => 三个 PT_LOAD 段, 各自从 64K 边界开始, 不会与相邻权限共页
 *
 * 约定 (与 op_GATE 生成器 / rv32im-atomic.hpp 对齐):
 *   - 入口 `_MatrixStart` 在 `.text.crt0` (start.S), 必须 KEEP (否则 --gc-sections 会丢掉)
 *   - `__global_pointer$` 指向小数据区, 供 `lla gp, ...` 使用
 *   - `__bss_start`/`__bss_end` 供工具/调试使用; **`.bss` 由加载器初始化** (ELF 语义: `p_memsz > p_filesz`
 *     的那部分补零) —— `start.S` **不做**清零 (用户 2026-09-18 定)  ⇒ 这是**加载器的契约**
 *   - `__Matrix_*` 符号给宿主划分权限页
 */

_estack = (0x100000 + 0x010000 - 32) & -16;   /* 0x10FFE0: 16 字节对齐 (psABI 过程入口要求) */

MEMORY {
	IMAGE (rwx) : ORIGIN = 0x00010000, LENGTH = 576K
}

ENTRY(_MatrixStart)

PHDRS {
	text   PT_LOAD FLAGS(5);   /* R + X */
	rodata PT_LOAD FLAGS(4);   /* R     */
	data   PT_LOAD FLAGS(6);   /* R + W (含 .bss: ZI) */
}

SECTIONS
{
	/* ---- RX: 代码 ---- */
	.text : ALIGN(64K)
	{
		__Matrix_text_start = .;
		KEEP(*(.text.crt0))          /* start.S: 入口必须留 */
		*(.text .text.*)
		*(.plt .plt.*)
		KEEP(*(.init))
		KEEP(*(.fini))
		. = ALIGN(16);
		__Matrix_text_end = .;
	} > IMAGE : text

	/* ---- R: 只读数据 (从 64K 边界开始, 不与 .text 共页) ---- */
	.rodata : ALIGN(64K)
	{
		__Matrix_rodata_start = .;
		*(.srodata .srodata.*)
		*(.rodata .rodata.*)
		*(.eh_frame)                 /* 只读 */
		*(.gcc_except_table .gcc_except_table.*)

		__preinit_array_start = .;
		KEEP(*(.preinit_array*))
		__preinit_array_end = .;

		__init_array_start = .;
		KEEP(*(SORT(.init_array.*)))
		KEEP(*(.init_array*))
		__init_array_end = .;

		__fini_array_start = .;
		KEEP(*(SORT(.fini_array.*)))
		KEEP(*(.fini_array*))
		__fini_array_end = .;

		. = ALIGN(16);
		__Matrix_rodata_end = .;
	} > IMAGE : rodata

	/* ---- RW: 已初始化数据 (从 64K 边界开始) ---- */
	.data : ALIGN(64K)
	{
		__Matrix_data_start = .;
		__global_pointer$ = . + 0x800;   /* 小数据区中间 (gp 相对寻址 ±2KB) */
		LONG(0);                         /* 保证 .data **非空**: 否则 ld 在 .data 被回收成空段时
		                                    会把 .bss 放回 .text 那一页 (实测) => RW 与 RX 共页 */
		*(.sdata .sdata.*)
		*(.data .data.*)
		*(.data.rel.ro .data.rel.ro.*)   /* 静态非 PIC 下就是普通 RW 数据 */
		*(.got .got.*)
		*(.tdata .tdata.*)               /* 静态 TLS 块 (见计划文档 §10) */
		. = ALIGN(16);
		__Matrix_data_end = .;
	} > IMAGE : data

	/* ---- RW + ZI: 零初始化数据 (与 .data 同权限, 不必再对齐到页) ---- */
	.bss (NOLOAD) : ALIGN(16)
	{
		__bss_start = .;
		*(.sbss .sbss.*)
		*(.bss .bss.*)
		*(.tbss .tbss.*)
		*(COMMON)
		. = ALIGN(16);
		__bss_end = .;
		__Matrix_bss_end = .;
	} > IMAGE : data

	__Matrix_image_end = .;

	/* ---- 结构性断言 (越界/失配要在链接期就炸, 而不是运行期诡异) ---- */
	ASSERT((__Matrix_text_start   & (64K - 1)) == 0, "Matrix: .text 未对齐到 64K 页")
	ASSERT((__Matrix_rodata_start & (64K - 1)) == 0, "Matrix: .rodata 未对齐到 64K 页")
	ASSERT((__Matrix_data_start   & (64K - 1)) == 0, "Matrix: .data 未对齐到 64K 页")
	ASSERT((_estack & 15) == 0,                      "Matrix: _estack 未 16 字节对齐")
	ASSERT(__Matrix_image_end <= 0x000A0000,         "Matrix: 映像超出 576K (0x10000-0x9FFFF)")
	ASSERT(__Matrix_rodata_start >= __Matrix_text_end,   "Matrix: .rodata 与 .text 重叠 (权限页会混)")
	ASSERT(__Matrix_data_start   >= __Matrix_rodata_end, "Matrix: .data 与 .rodata 重叠 (权限页会混)")
	ASSERT((__bss_start >> 16)   >= (__Matrix_data_start >> 16),
	       "Matrix: .bss 落在 .data 之前的页 (RW 与 RX/RO 共页); 检查 .data 是否为空")
	ASSERT(__bss_end <= 0x000A0000,                  "Matrix: .bss 超出映像区")
}

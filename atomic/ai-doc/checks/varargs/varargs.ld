/* varargs.ld —— 按 ATOMC 的最终内存映射放置映像:
     0x00000-0x0FFFF 不映射           (低 64K: 门窗口 + 哨兵, 见文档)
     0x10000-0x9FFFF 程序映像 576K    <= 我们放 .text/.rodata/.data/.bss
     0xA0000-0xEFFFF 可写设备区
     0xF0000-0xFFFFF 只读区/ROM
     0x100000-0x10FFFF 用户栈 (sp = 0x10FFE0)
   注意: __global_pointer$ 供 gp 相对寻址 (musl 的 crt_arch.h 也这么干)。  */
ENTRY(_start)

MEMORY
{
  IMAGE (rwx) : ORIGIN = 0x00010000, LENGTH = 0x00090000   /* 576K */
}

SECTIONS
{
  .text : {
    *(.text._start)          /* 入口放最前 */
    *(.text .text.*)
    . = ALIGN(4);
  } > IMAGE

  .rodata : {
    *(.rodata .rodata.*)
    *(.srodata .srodata.*)
    . = ALIGN(4);
  } > IMAGE

  .data : {
    __global_pointer$ = . + 0x800;   /* gp 指到小数据区中间 */
    *(.sdata .sdata.*)
    *(.data .data.*)
    . = ALIGN(8);
  } > IMAGE

  .bss : {
    __bss_start = .;
    *(.sbss .sbss.*)
    *(.bss .bss.*)
    *(COMMON)
    . = ALIGN(8);
    __bss_end = .;
  } > IMAGE

  /DISCARD/ : { *(.comment) *(.riscv.attributes) *(.note*) }
}

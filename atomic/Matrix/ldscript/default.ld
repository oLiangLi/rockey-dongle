
_estack = (0x100000 + 0x010000 - 32) & -16;

MEMORY {
	RAM (RWX) : ORIGIN = 0x010000, LENGTH = ((640 - 64) * 1024)
}

/* Entry Point */
ENTRY(_MatrixStart);



SECTIONS
{
	.text :
	{
		__Matrix_text_start = .;
		. = ALIGN(64*1024);
		KEEP(*(.text.crt0))      /* start.S */
		*(.text .text.*)
        KEEP (*(.init))
        KEEP (*(.fini))
		. = ALIGN(64);
		__Matrix_text_end = .;
	} > RAM

	.rodata :
	{
		. = ALIGN(64);
		*(.rodata .rodata.*)
		*(.eh_frame)

        __preinit_array_start = .;
        KEEP (*(.preinit_array*))
        __preinit_array_end = .;

        __init_array_start = .;
        KEEP (*(SORT(.init_array.*)))
        KEEP (*(.init_array*))
        __init_array_end = .;

        __fini_array_start = .;
        KEEP (*(SORT(.fini_array.*)))
        KEEP (*(.fini_array*))
        __fini_array_end = .;

		. = ALIGN(64*1024);
	} > RAM

	.data :
	{
		__global_pointer$ = . + 0x800;
		. = ALIGN(64*1024);
		*(.data .data.*)
		. = ALIGN(64);
	}

	.bss (NOLOAD) :
	{
		. = ALIGN(64);
		__bss_start = .;
		*(.bss .bss.*)
		__bss_end = .;
	}
}

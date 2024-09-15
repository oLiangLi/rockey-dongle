SECTIONS {
	.text 0x00000000 : {
		KEEP(*(.world.start));
		KEEP(*(.world.pubkey));
		*(.text .text.*);
		*(.rodata.CSWTCH .rodata.CSWTCH.*);
		
		. = ALIGN(8); PROVIDE(__rodata_begin = .);
		*(.rodata .rodata.*);
		. = ALIGN(8); PROVIDE(__rodata_end = .);
	}

	.data 0x68000A00 : {
        . = ALIGN(8); PROVIDE(__data_begin = .);
        *(.data .data.*);
        . = ALIGN(8); PROVIDE(__data_end = .);
        . = ALIGN(8); PROVIDE(__bss_begin = .);
        *(.bss .bss.*);
        . = ALIGN(8); PROVIDE(__bss_end = .);
	}

	g_FEI 0x68001400 : {
		*(.ARM.__AT_0x68001400);
	}
}

ASSERT((_world_start == 0x40), "_world_start != 0x40");
ASSERT((__rodata_begin == __rodata_end), "__rodata_begin != __rodata_end");

ASSERT((__data_begin == __data_end), "__data_begin != __data_end");
ASSERT((__bss_end - __bss_begin <= 0x200), "__bss_end - __bss_begin > 0x200");

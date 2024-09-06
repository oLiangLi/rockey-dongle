SECTIONS {
	.text 0x00000000 : {
		KEEP(*(.world.start));
		KEEP(*(.world.pubkey));
		*(.text .text.*);
		
		. = ALIGN(8); PROVIDE(__rodata_begin = .);
		*(.rodata .rodata.*);
		. = ALIGN(8); PROVIDE(__rodata_end = .);
	}

	.data 0xC8C00000 : {
	    *(.data .data.* .bss .bss.*);
	}

	g_FEI 0x68001400 : {
		*(.ARM.__AT_0x68001400);
	}
}

ASSERT((_world_start == 0x40), "_world_start != 0x40");
ASSERT((__rodata_begin == __rodata_end), "__rodata_begin != __rodata_end");


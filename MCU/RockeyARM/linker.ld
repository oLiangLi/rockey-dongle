SECTIONS {
	.text 0x00000000 : {
		KEEP(*(.world.start))
		KEEP(*(.world.pubkey))
		*(.text .text.*)
		*(.rodata .rodata.*)
	}

	.data 0xC8C00000 : {
	    *(.data .data.* .bss .bss.*)
	}

	g_FEI 0x68001400 : {
		*(.ARM.__AT_0x68001400)
	}
}

ASSERT((_world_start == 0x40), "_world_start != 0x40");
ASSERT((g_master_pubkey == 0x50), "g_master_pubkey != 0x50");
ASSERT((g_master_pubkey_end - g_master_pubkey_start == 260), "sizeof(g_master_pubkey) != 260")

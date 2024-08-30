	.section .world.start
	.align	2
	.thumb
	
Vector:
	.long 0x68000C00
	.long 0 /* size_image  */	

	/**
	 *! RandFill 60 bytes ...
	 */
	.long 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0

_world_start:
    .global _world_start
	LDR R0, =0x68000c00
	MOV SP, R0
	LDR R0,=app_entry
	BX  R0

	.section .world.pubkey
	.align 2
g_master_pubkey:
g_master_pubkey_start:
	.global g_master_pubkey
	.global g_master_pubkey_end
	.global g_master_pubkey_start
	.long 0
	.long 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.long 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.long 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.long 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
g_master_pubkey_end:
	.long 0xC8C04E1F

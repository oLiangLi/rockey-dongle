	.section .world.start
	.align	2
	.thumb
	
Vector:
	.long 0x68000BE0
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
	#LDR R0, =0x68000c00
	#MOV SP, R0
	#LDR R0,=app_entry
	#BX  R0
	.long 0xC8C04E1F
	LDR R0,=app_entry
	.short 0xC8C0
	.long 0xC8C04E1F

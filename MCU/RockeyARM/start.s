	.section .world.start
	.align	2
	.thumb
	
Vector:
	.long 0x68000BF0
	.long 0 /* size_image  */	

	/**
	 *! RandFill 60 bytes ...
	 */
	.long 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0
	.long 0, 0, 0, 0

   .thumb_func
   .global _start
   .global _world_start
_start:
_world_start:
	#LDR R0, =0x68000c00
	#MOV SP, R0
	#LDR R0,=app_entry
	#BX  R0
	.long 0xC8C04E1F
	LDR R0,=app_entry
	.short 0xC8C0
	.long 0xC8C04E1F

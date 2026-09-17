	.section .text.crt0,"ax",@progbits
	.align	2
	.globl	_MatrixStart
	.type	_MatrixStart, @function
_MatrixStart:
	lla   gp, __global_pointer$
	lla   sp, _estack
	call  rLANG_op_GATE_Initialize	
	tail  MatrixExecv
	.size	_MatrixStart, .-_MatrixStart

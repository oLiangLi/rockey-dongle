/* foobar-sret.c —— 用户 2026-09-16 的测试, 原样保留。
 *
 * 观察: call_foobar 里 fmt 落在 a1 (而不是 a0), 1 在 a2, 0x12345678 在 a3 ...
 * 原因: **foobar 返回 long double (16 字节 > 2*XLEN) ⇒ 按引用返回**:
 *   psABI: "Values are returned in the same manner as a first named argument of the same type
 *           would be passed. If such an argument would have been passed by reference, the caller
 *           allocates memory for the return value, and passes the address as an **implicit first
 *           parameter**."
 *   ⇒ 隐式第一参数 (返回缓冲区的地址) 占 **a0**, 因此显式参数全部右移一格。
 * 编译: riscv32-unknown-elf-gcc -march=rv32im -mabi=ilp32 -O2 -S foobar-sret.c
 * (本文件只用来**看调用约定**; vfoobar 未定义, 不参与链接。) */
#include <stdarg.h>

long double foobar(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
long double vfoobar(const char* fmt, va_list ap);

long double foobar(const char* fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	long double result = vfoobar(fmt, ap);
	va_end(ap);

	return result;
}

void call_foobar() {
	foobar("%d %d %ld %lld %.3f %.3lf %.3LF\n", 1,
		0x12345678, 0x56789123l, 0xAABBCCDD11223344ll, 2.718f, 3.1415926, 0.618L
	);
}

/* foobar-ret-double.c —— 用户 2026-09-16 的第二版 (返回类型从 long double 改成 double), 原样保留。
 *
 * 对照结论: **`double` = 2*XLEN ⇒ 用 `a0a1` 返回值, 不需要 sret** ⇒ 显式参数回到 a0 起:
 *   a0 = fmt, a1 = 1, a2 = 0x12345678, a3 = 0x56789123l,
 *   a4a5 = 0xAABBCCDD11223344ll (偶数起始对, **不再跳空**), a6a7 = (double)2.718f,
 *   栈: 3.1415926 (double) + 指向 0.618L 的指针。
 * 注意函数**内部**仍然看得见 sret: 对 `vfoobar` 的调用 (它返回 long double) 依旧要在 a0 里传返回缓冲区。
 * 编译: riscv32-unknown-elf-gcc -march=rv32im -mabi=ilp32 -O2 -S foobar-ret-double.c */
#include <stdarg.h>

double foobar(const char* fmt, ...) __attribute__((format(printf, 1, 2)));;
double vfoobar(const char* fmt, va_list ap);

double foobar(const char* fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	long double result = vfoobar(fmt, ap);
	va_end(ap);

	return (double)result;
}

void call_foobar() {
	foobar("%d %d %ld %lld %.3f %.3lf %.3LF\n", 1,
		0x12345678, 0x56789123l, 0xAABBCCDD11223344ll, 2.718f, 3.1415926, 0.618L
	);
}

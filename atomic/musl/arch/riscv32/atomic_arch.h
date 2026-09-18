#ifndef __WTINC_ATOMIC_MUSL_ATOMIC_ARCH_H__
#define __WTINC_ATOMIC_MUSL_ATOMIC_ARCH_H__

/**
 *! ATOMC 对 musl `arch/riscv32/atomic_arch.h` 的**本地覆盖** ...
 *! - 我们只实现 RV32IM: 解释器不实现 A 扩展 (`lr.w`/`sc.w`/`amo*`), 也不实现 C ...
 *! - 而 ATOMC 是**单线程、不可重入**的 (明确的取舍): 异步只在**指令边界/门返回**处恢复,
 *!   不可能在 a_cas 中间重入, 也不存在并发访问同一地址 ...
 *!   ⇒ `a_cas` 用普通 load/store 即可, 不需要 LL/SC ...
 *! - `a_barrier` 保持 `fence rw,rw` —— 这条指令 VM 本来就支持 (判据 0x0F == (op & 0xF00FFFFF)) ...
 *! - ⚠ 生效前提: 本目录的 -I 必须排在 third_party/musl/arch/riscv32 **之前** (见 atomic/project.mk) ...
 */

#define a_barrier a_barrier
static inline void a_barrier(void)
{
	__asm__ __volatile__ ("fence rw,rw" : : : "memory");
}

#define a_cas a_cas
static inline int a_cas(volatile int *p, int t, int s)
{
	int old = *p;
	if (old == t)
		*p = s;
	return old;
}

#endif /* __WTINC_ATOMIC_MUSL_ATOMIC_ARCH_H__ */

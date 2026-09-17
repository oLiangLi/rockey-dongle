/* varargs-test.c —— 用真 toolchain (riscv32-unknown-elf-gcc 16.1.0, -march=rv32im -mabi=ilp32) 编译,
   再在我们的 VM_t 解释器上运行, 用来验证 psABI 可变参数约定的**每一个分支**:

   (1) 变参全部落在寄存器        => 被调方必须构造 varargs save area
   (2) 变参溢出到栈              => save area + "上栈后全上栈" 的连续性
   (3) long long 变参            => 8 字节变参必须落在**偶数起始**的寄存器对
   (4) 8 字节变参凑不出偶数对    => 提前溢出到栈
   (5) 命名 long long (不必偶数) 之后的 8 字节变参 => **跳空**一个寄存器
   (6) 指针变参                  => 按指针大小/对齐前进
   (7) double 变参               => 软浮点 ILP32 下同样走整数寄存器对 (只搬位模式, 不做浮点运算)
   (8) long double 变参          => 16B > 2*XLEN => **按引用**传, va_arg 内部解引用

   结果写进 g[] (volatile, 防止被优化掉); 同一份源码也能在宿主上编译 (-DHOST_TEST) 打印同样的表,
   两边逐个比对 => "同源两目标" 的对照实验。 */
#include <stdarg.h>
#include <stdint.h>

#ifdef HOST_TEST
#include <stdio.h>
#define NOINLINE
#else
#define NOINLINE __attribute__((noinline))
#endif

volatile uint32_t g[24];

/* (1)(2): 整数变参 ---------------------------------------------------- */
NOINLINE uint32_t sum_i(int n, ...) {
  va_list ap;
  uint32_t s = 0;
  va_start(ap, n);
  for (int i = 0; i < n; ++i) s += (uint32_t)va_arg(ap, int);
  va_end(ap);
  return s;
}

/* (3)(4): unsigned long long 变参 (每个 8 字节, 必须偶数起始对) -------- */
NOINLINE uint64_t sum_ll(int n, ...) {
  va_list ap;
  uint64_t s = 0;
  va_start(ap, n);
  for (int i = 0; i < n; ++i) s += va_arg(ap, unsigned long long);
  va_end(ap);
  return s;
}

/* (5): 命名参数用掉 a0 + (a1a2) + a3 -> 下一个空位是 a4; 再吃掉 a4,
   则 8 字节变参必须**跳空 a5** 去用 a6a7 --------------------------------- */
NOINLINE uint64_t skip_pair(int a, unsigned long long b, int c, int d, ...) {
  va_list ap;
  uint64_t s = (uint64_t)(uint32_t)a + b + (uint64_t)(uint32_t)c + (uint64_t)(uint32_t)d;
  va_start(ap, d);
  s += va_arg(ap, unsigned long long); /* 期望: a6a7 (跳过 a5) */
  s += (uint32_t)va_arg(ap, int);      /* 期望: 紧随其后的栈槽 (寄存器已用光) */
  va_end(ap);
  return s;
}

/* (6): 指针变参 ------------------------------------------------------- */
NOINLINE uint32_t sum_p(int n, ...) {
  va_list ap;
  uint32_t s = 0;
  va_start(ap, n);
  for (int i = 0; i < n; ++i) s += *va_arg(ap, const uint32_t *);
  va_end(ap);
  return s;
}

/* (7): double 变参 —— 只看位模式 (不做浮点运算 => 不拉 libgcc 的软浮点) */
NOINLINE uint32_t sum_d_bits(int n, ...) {
  va_list ap;
  uint32_t s = 0;
  va_start(ap, n);
  for (int i = 0; i < n; ++i) {
    union { double d; uint32_t u[2]; } v;
    v.d = va_arg(ap, double);
    s += v.u[0] ^ v.u[1];
  }
  va_end(ap);
  return s;
}

/* (8): long double 变参 (16 字节, 按引用) ------------------------------ */
NOINLINE uint32_t sum_ld_bits(int n, ...) {
  va_list ap;
  uint32_t s = 0;
  va_start(ap, n);
  for (int i = 0; i < n; ++i) {
    union { long double ld; uint32_t u[4]; } v;
    v.ld = va_arg(ap, long double); /* 编译成: 从 va_list 取指针, 再从该地址读 16 字节 */
    s += v.u[0] ^ v.u[1] ^ v.u[2] ^ v.u[3];
  }
  va_end(ap);
  return s;
}

NOINLINE void run_all(void) {
  g[0] = sum_i(6, 1, 2, 3, 4, 5, 6);                     /* 全在寄存器 */
  g[1] = sum_i(9, 1, 2, 3, 4, 5, 6, 7, 8, 9);            /* 溢出到栈 */
  g[2] = (uint32_t)sum_ll(3, 1ull, 2ull, 3ull);          /* 三对: a2a3, a4a5, a6a7 */
  g[3] = (uint32_t)sum_ll(5, 1ull, 2ull, 3ull, 4ull, 5ull); /* 前三对 + 后两个上栈 */
  g[4] = (uint32_t)skip_pair(1, 2ull, 3, 4, 5ull, 6);    /* 跳空 a5, 再取栈上的 int */
  g[10] = 100; g[11] = 200;
  g[5] = sum_p(2, &g[10], &g[11]);
  g[6] = sum_d_bits(2, 1.5, -2.5);
  g[7] = sum_ld_bits(1, 3.25L);
}

#ifndef HOST_TEST

/* 裸机入口: 设 sp (我们的内存映射: 栈 = 0x100000-0x10FFFF, 栈顶 16 字节对齐),
   设 gp, 跑完用 ecall 停机 (VM 的 op_ECALL 默认返回 SIGILL => Execv 结束) */
extern void run_all(void);
extern char __global_pointer$[];

__attribute__((naked, noreturn)) void _start(void) {
  __asm__ volatile(
      "lla   gp, __global_pointer$\n"
      "lui   sp, 0x110\n"          /* sp = 0x110000 */
      "addi  sp, sp, -32\n"        /* sp = 0x10FFE0 (16 字节对齐, 与内存布局一致) */
      "call  run_all\n"
      "ecall\n"                    /* VM: op_ECALL 默认返回 SIGILL, 程序结束 */
      "1: j 1b\n");
}

#else /* ---------------- 宿主侧: 打印同一张表 ---------------- */

int main(void) {
  run_all();
  for (int i = 0; i < 24; ++i)
    if (g[i]) printf("g[%d] = %u\n", i, (unsigned)g[i]);
  return 0;
}

#endif

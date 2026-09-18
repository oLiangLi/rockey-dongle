/* guest-fmt.c —— **printf 家族跨门**的最小证明 (2026-09-16)
 *
 * 背景: 在解释器里跑 musl 的 vsnprintf/vsprintf (即 guest 自己做格式化) 慢得不可接受;
 *       正确做法是让 guest 只**发一次门调用**, 把 (fmt, va_list) 交给宿主, 由宿主用**原生 snprintf** 格式化。
 *
 * 为什么可行: `va_list` 在 RISC-V 上就是 `void*`(见 psABI), 它指向**guest 内存**里的一段
 *   "按 ILP32 变参规则排布"的连续区 (寄存器保存区 + 栈参数区) ⇒ 宿主只要按同一套规则自己取参即可。
 *
 * 门的 7 个参数**与 base/bits/base.h:727 的 `rlLoggingWriteEx(level, tag, line, data, len, fmt, ...)`
 *   (以及 base/src/log.cc 的 `platformLoggingWrite(..., va_list ap)`) 一一对应** ⇒ 天然落在 a0..a6。
 */
#include <stdarg.h>
#include <stdint.h>

volatile uint32_t g[4];

/* 门桩: 7 个形参按 psABI 落在 a0..a6; `jalr x1,0(x0)` 落到地址 0 —— 被 VM 拦成 op_GATE(0),
 * 且 VM 会先把 pc_ 设成 x1(ra) = 下一条指令 ⇒ 门返回后 `ret` 回到调用者。宿主把结果写在 a0。 */
__attribute__((naked)) void gate_log(int level, uint32_t tag, int line, const void* data, int len,
                                    const char* fmt, va_list ap) {
  __asm__ volatile("jalr x1, 0(x0)\n\t"
                   "ret\n\t");
}

__attribute__((noinline)) void guest_log(int level, uint32_t tag, int line, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  gate_log(level, tag, line, 0, 0, fmt, ap); /* 只有**这一条**跨门调用; guest 侧不解析格式串 */
  va_end(ap);
}

extern void run_all(void);
extern char __global_pointer$[];

__attribute__((naked, noreturn)) void _start(void) {
  __asm__ volatile("lla   gp, __global_pointer$\n"
                   "lui   sp, 0x110\n"
                   "addi  sp, sp, -32\n"
                   "call  run_all\n"
                   "ecall\n"
                   "1: j 1b\n");
}

__attribute__((noinline)) void run_all(void) {
  /* ① 正常格式化: int / string / long long / double / unsigned / char / 百分号
        (guest 侧的格式串与参数都按 psABI 摆好, 宿主负责取参与格式化) */
  guest_log(3, 0x1234u, 42, "lvl=%d tag=%04X s=%s ll=%lld d=%.3f u=%u c=%c p=%d%%",
            7, 0x1234u, "hello", -1234567890123LL, 2.5, 4294967295u, 'Z', 99);

  /* ② 不支持的指令: 长双精度 (guest 是 binary128, 宿主 x86 是 80 位扩展 ⇒ 不能直接搬) + %n
        ⇒ 宿主应当**fail-closed** (写标记并置错误标志), 而不是把 guest 内存当宿主内存读 */
  guest_log(5, 0x0BADu, 43, "ld=%.3LF n=%n", 0.618L, (int*)0);

  g[0] = 1u;
}

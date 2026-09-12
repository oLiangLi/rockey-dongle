

#define rlLOGV(tag, fmt, ...) ((void)0)
#define rlLOGD(tag, fmt, ...) ((void)0)
#define rlLOGI(tag, fmt, ...) ((void)0)
#define rlLOGW(tag, fmt, ...) ((void)0)
#define rlLOGE(tag, fmt, ...) ((void)0)
#define rlLOGX(tag, fmt, ...) ((void)0)

#define rlLOGXV(tag, dat, len, fmt, ...) ((void)0)
#define rlLOGXD(tag, dat, len, fmt, ...) ((void)0)
#define rlLOGXI(tag, dat, len, fmt, ...) ((void)0)
#define rlLOGXW(tag, dat, len, fmt, ...) ((void)0)
#define rlLOGXE(tag, dat, len, fmt, ...) ((void)0)
#define rlLOGXX(tag, dat, len, fmt, ...) ((void)0)

/*
 * World switches for the device (ukey-resident) build live here, not in the shared
 * Build config files, so that the shared build system stays world-neutral.
 *
 * rLANG_CONFIG_ENABLE_LIMIT_WORLD: this artifact is a program running INSIDE the ukey
 * (restricted world): no .rodata, no lookup tables, tight .bss/stack budgets.
 * base/ code selects restricted implementations accordingly (e.g. table-less CRC).
 */
#define rLANG_CONFIG_ENABLE_LIMIT_WORLD 1

/*
 * rLANG_CONFIG_MINIMAL_WORLD: upstream base/Build knob meaning "no host facilities":
 * skips dbghelp/execinfo/backtrace, log files, prctl/signal handlers and other
 * desktop-only paths (see base/src/log.cc, base/src/base.cc, base/src/task.cc).
 * The bare-metal ARM target has no execinfo.h, so this must be on here.
 */
#define rLANG_CONFIG_MINIMAL_WORLD 1

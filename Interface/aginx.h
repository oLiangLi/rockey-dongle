/*!
 *! Interface/aginx.h —— 本产品的"命名空间声明"宏对(与 base 的 rLANG_DECLARE_MACHINE/END 同构)。
 *!
 *! 为什么不放在共享 base 里: 前缀取**产品名**而非作者/工具代号, 避免每位协作者各占一对宏使
 *! base/bits/base.h 持续膨胀; 共享 base 是公共库, 不应携带某一产品的专用宏。
 *! 因此本仓自带该头, 凡使用 AGINX_DECLARE_MACHINE/END 的文件显式 `#include <Interface/aginx.h>`。
 *! (C++ 下展开为 namespace machine { ... }, C 下为空, 与 rLANG_* 行为一致。)
 */
#ifndef AGINX_DECLARE_MACHINE
#if defined(__cplusplus)
#define AGINX_DECLARE_MACHINE namespace machine {
#define AGINX_DECLARE_END }
#else /* __cplusplus */
#define AGINX_DECLARE_MACHINE
#define AGINX_DECLARE_END
#endif /* __cplusplus */
#endif /* AGINX_DECLARE_MACHINE */

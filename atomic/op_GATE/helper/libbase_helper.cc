#include <base/base.h>

rLANG_DECLARE_MACHINE

/**
 *! 将不定参数转化为 va_list 方便在 host 侧实现 ...
 */
rLANGIMPORT void
rlLoggingWriteEx_op_GATE_ap(int level, uint32_t tag, int line, const void* data, int len, const char* fmt, va_list ap);
rLANGEXPORT void rlLoggingWriteEx(int level, uint32_t tag, int line, const void* data, int len, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  rlLoggingWriteEx_op_GATE_ap(level, tag, line, data, len, fmt, ap);
  va_end(ap);
}
rLANGEXPORT void rlLoggingWrite(int level, uint32_t tag, int line, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  rlLoggingWriteEx_op_GATE_ap(level, tag, line, nullptr, 0, fmt, ap);
  va_end(ap);
}

rLANG_DECLARE_END

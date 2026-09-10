#include <base/base.h>
extern "C" {
#include <FTRX.h>
} /* extern "C" */

rLANG_DECLARE_MACHINE
namespace dongle {
int Start(void* InOutBuf, void* ExtendBuf);
}  // namespace dongle
rLANG_DECLARE_END

rLANGIMPORT char __bss_begin[];  /// linker.ld ...
rLANGIMPORT char __bss_end[];
rLANGEXPORT int rLANGAPI app_entry() {
  //led_control(LED_BLINK);
  memset(__bss_begin, 0, __bss_end - __bss_begin);
  int result = machine::dongle::Start(reinterpret_cast<void*>(0x68000000), reinterpret_cast<void*>(0x68000C00));
  //led_control(LED_OFF);

  return result;
}

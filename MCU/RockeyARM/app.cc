#include <base/base.h>
extern "C" {
#include <FTRX.h>
} /* extern "C" */

rLANG_DECLARE_MACHINE
namespace dongle {
int Start(void* InOutBuf, void* ExtendBuf);
}  // namespace dongle
rLANG_DECLARE_END

rLANGEXPORT int rLANGAPI app_entry() {
  led_control(LED_BLINK);
  machine::dongle::Start(reinterpret_cast<void*>(0x68000000), reinterpret_cast<void*>(0x68000C00));
  led_control(LED_OFF);
}

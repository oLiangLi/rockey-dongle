#include <base/base.h>
#include <FTRX.h>

rLANG_DECLARE_MACHINE

rLANGEXPORT int rLANGAPI app_entry() {
  led_control(LED_BLINK);

  return 10086;
}

rLANG_DECLARE_END

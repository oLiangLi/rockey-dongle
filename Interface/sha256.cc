#include <Interface/dongle.h>
#include <base/base.h>

rLANG_DECLARE_MACHINE

namespace dongle {

int Dongle::SHA256(const void* input, size_t size, uint8_t md[32]) {
  return -ENOSYS;
}

} // namespace dongle

rLANG_DECLARE_END

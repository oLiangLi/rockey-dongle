#include "script.h"

rLANG_DECLARE_MACHINE

namespace dongle {
namespace script {

int VM_t::OpManager(uint16_t op, int argc, int32_t argv[]) {
  if(valid_permission_ != PERMISSION::kAdministrator)
    return zero_ = -EACCES;

  return zero_ = -ENOSYS;
}

}
}  // namespace dongle

rLANG_DECLARE_END

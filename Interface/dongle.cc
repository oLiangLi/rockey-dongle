#include <base/base.h>
#include <Interface/dongle.h>
#include "RockeyARM/Dongle_API.h"

rLANG_DECLARE_MACHINE

namespace dongle {

RockeyARM::~RockeyARM() {
  Close();
}

int RockeyARM::EnumDongle(DONGLE_INFO* info, size_t size, uint32_t* error) {
  DWORD result;
  int count = -1;

  if (!info || !size) {
    result = Dongle_Enum(nullptr, &count);
  } else {
    constexpr size_t kDongleMaxCount = 64;
    ::DONGLE_INFO all[kDongleMaxCount];
    result = Dongle_Enum(all, &count);
    if (result == DONGLE_SUCCESS && count > 0) {
      if (size > static_cast<size_t>(count))
        size = count;
      for (size_t i = 0; i < size; ++i)
        GetDongleInfo(&info[i], all[i]);
    }
  }
  if (error)
    *error = result;
  return count;
}

int RockeyARM::CheckError(uint32_t error) {
  if (DONGLE_SUCCESS == error)
    return 0;
  last_error_ = error;
  return -1;
}

int RockeyARM::Close() {
  Handle h = nullptr;
  std::swap(h, handle_);
  return CheckError(Dongle_Close(h));
}

int RockeyARM::Open(int index) {
  Close();

  DONGLE_HANDLE handle = nullptr;
  if (0 != CheckError(Dongle_Open(&handle, index)))
    return -1;
  handle_ = static_cast<Handle>(handle);
  return 0;
}


} // namespace dongle

rLANG_DECLARE_END

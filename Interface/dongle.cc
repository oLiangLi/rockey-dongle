#include <base/base.h>
#include <Interface/dongle.h>
#include "RockeyARM/Dongle_API.h"

rLANG_DECLARE_MACHINE

namespace {
constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("DONGLE");
}

namespace dongle {

RockeyARM::~RockeyARM() {
  Close();
}

int Dongle::RandBytes(uint8_t* buffer, size_t size) {
  return CheckError(Dongle_GenRandom(handle_, static_cast<int>(size), buffer));
}

int Dongle::CheckError(DWORD error) {
  if (DONGLE_SUCCESS == error)
    return 0;
  last_error_ = error;
  return -1;
}

int RockeyARM::Enum(DONGLE_INFO info[64]) {
  int count = 0;
  ::DONGLE_INFO all[64];  
  int result = CheckError(Dongle_Enum(all, &count));
  rlLOGE(TAG, "%d) Dongle_Enum %d, %08X", result, count, GetLastError());
  if (result < 0)
    return -1;

  if (info) {
    // TODO: ...
  }

  return count;
}

int RockeyARM::Open(int index) {
  ::DONGLE_HANDLE handle = nullptr;

  Close();


  if (0 != CheckError(Dongle_Open(&handle, index)))
    return -1;

  int remain = 0;
  int result = CheckError(Dongle_VerifyPIN(handle, FLAG_ADMINPIN, CONST_ADMINPIN, &remain));
  rlLOGI(TAG, "Dongle_VerifyPIN %d, %d, %08X", result, remain, GetLastError());

  handle_ = static_cast<ROCKEY_HANDLE>(handle);
  return 0;
}

int RockeyARM::Close(){
  ROCKEY_HANDLE handle = nullptr;
  std::swap(handle, handle_);
  return CheckError(Dongle_Close(handle));
}


#if 0

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
#endif


} // namespace dongle

rLANG_DECLARE_END

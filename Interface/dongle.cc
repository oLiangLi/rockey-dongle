#include <base/base.h>
#include <Interface/dongle.h>
#include "RockeyARM/Dongle_API.h"

rLANG_DECLARE_MACHINE

namespace {
constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("DONGLE");
}

namespace dongle {
    
int Dongle::RandBytes(uint8_t* buffer, size_t size) {
  return DONGLE_CHECK(Dongle_GenRandom(handle_, static_cast<int>(size), buffer));
}
int Dongle::GetRealTime(DWORD* time) {
  return DONGLE_CHECK(Dongle_GetUTCTime(handle_, time));
}
int Dongle::GetExpireTime(DWORD* time) {
  return DONGLE_CHECK(Dongle_GetDeadline(handle_, time));
}
int Dongle::GetTickCount(DWORD* ticks) {
  *ticks = static_cast<DWORD>(rLANG_GetTickCount());
  return 0;
}

int Dongle::GetDongleInfo(DONGLE_INFO* info) {
  if (!handle_)
    return -EBADF;
  *info = dongle_info_;
  return 0;
}
int Dongle::GetPINState(PERMISSION* state) {
  *state = PERMISSION::kAnonymous;
  return DONGLE_CHECK(("Dongle_GetPINState(state)", DONGLE_FAILED));
}

rLANG_ABIREQUIRE(static_cast<int>(LED_STATE::kOff) == LED_OFF && static_cast<int>(LED_STATE::kOn) == LED_ON &&
                 static_cast<int>(LED_STATE::kBlink) == LED_BLINK);
int Dongle::SetLEDState(LED_STATE state) {
  return DONGLE_CHECK(Dongle_LEDControl(handle_, static_cast<int>(state)));
}







int Dongle::CheckError(DWORD error) {
  if (DONGLE_SUCCESS == error)
    return 0;
  last_error_ = error;
  return -1;
}

RockeyARM::~RockeyARM() {
  Close();
}

int RockeyARM::Enum(DONGLE_INFO info[64]) {
  int count = 0;
  ::DONGLE_INFO all[64];
  int result = DONGLE_CHECK(Dongle_Enum(all, &count));
  if (result < 0)
    return -1;

  for (int i = 0; info && i < count; ++i)
    GetRockeyDongleInfo(&info[i], all[i]);
  return count;
}


int RockeyARM::VerifyPIN(PERMISSION perm, const char* pin, int* remain) {
  int flags = FLAG_USERPIN;

  if (perm == PERMISSION::kAdminstrator) {
    flags = FLAG_ADMINPIN;
    if (!pin)
      pin = CONST_ADMINPIN;
  }    
  else if (perm == PERMISSION::kNormal) {
    flags = FLAG_USERPIN;
    if (!pin)
      pin = CONST_USERPIN;
  } else {
    return -EINVAL;
  }

  return DONGLE_CHECK(Dongle_VerifyPIN(handle_, flags, const_cast<char*>(pin), remain));
}

int RockeyARM::Open(int index) {
  if (index < 0 || index >= 64)
    return -EINVAL;

  int count = 0;
  ::DONGLE_INFO dongle_info_all_[64];
  ::DONGLE_HANDLE handle = nullptr;

  Close();
  if (DONGLE_CHECK(Dongle_Enum(dongle_info_all_, &count)) < 0)
    return -1;

  if (index >= count)
    return -ERANGE;

  GetRockeyDongleInfo(&dongle_info_, dongle_info_all_[index]);
  if (0 != DONGLE_CHECK(Dongle_Open(&handle, index)))
    return -1;

  handle_ = static_cast<ROCKEY_HANDLE>(handle);
  return 0;
}

int RockeyARM::Close(){
  if (!handle_)
    return 0;

  ROCKEY_HANDLE handle = nullptr;
  std::swap(handle, handle_);
  return DONGLE_CHECK(Dongle_Close(handle));
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

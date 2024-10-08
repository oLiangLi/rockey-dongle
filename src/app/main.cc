#include <base/base.h>
#include <Interface/dongle.h>
#include <tuple>

rLANG_DECLARE_MACHINE

namespace {
constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("App@K");
}

namespace dongle {

using DWORD = Dongle::DWORD;

int Start(void* InOutBuf, void* ExtendBuf) {
  int result = 0;
  struct Context_t {
    PERMISSION permission_;
    DWORD realTime_, expireTime_, ticks_;

    uint8_t share_memory_1_[32];
    uint8_t share_memory_2_[32];

    DONGLE_INFO dongle_info_;
    uint8_t bytes[64];
  } *Context = (Context_t*)InOutBuf;


#if defined(__EMULATOR__)
  const char* const kTestingDongleFile = ".foobar-dongle.bin";
  const char* const kTestingDongleSecret = "1234567812345678";
  Emulator rockey;

  if (rockey.Open(kTestingDongleFile, kTestingDongleSecret) < 0)
    rockey.Create(kTestingDongleSecret);

#elif !defined(__RockeyARM__)
  RockeyARM rockey;
  DONGLE_INFO dongle_info[64];

  result = rockey.Enum(dongle_info);
  rlLOGI(TAG, "rockey.Enum return %d/%08x", result, rockey.GetLastError());

  for (int i = 0; i < result; ++i) {
    rlLOGXI(TAG, &dongle_info[i], sizeof(DONGLE_INFO), "rockey.Enum %d/%d", i + 1, result);
  }

  result = rockey.Open(0);
  rlLOGI(TAG, "rockey.Open return %d/%08x", result, rockey.GetLastError());

  result = rockey.RandBytes(Context->bytes, sizeof(Context->bytes));
  rlLOGI(TAG, "rockey.RandBytes return %d/%08X", result, rockey.GetLastError());

  result = rockey.VerifyPIN(PERMISSION::kAdminstrator, nullptr, nullptr);
  rlLOGI(TAG, "rockey.VerifyPIN %d/%08X", result, rockey.GetLastError());
#else

  Dongle rockey;

#endif

  result = rockey.RandBytes(Context->bytes, sizeof(Context->bytes));

  rockey.SetLEDState(LED_STATE::kBlink);

  rockey.GetRealTime(&Context->realTime_);
  rockey.GetExpireTime(&Context->expireTime_);
  rockey.GetTickCount(&Context->ticks_);
  rockey.GetDongleInfo(&Context->dongle_info_);
  rockey.GetPINState(&Context->permission_);

  rockey.ReadShareMemory(Context->share_memory_2_);
  rockey.WriteShareMemory(&Context->bytes[32]);
  rockey.ReadShareMemory(Context->share_memory_1_);

  rlLOGXI(TAG, Context, sizeof(Context_t), "rockey.RandBytes return %d/%08x", result, rockey.GetLastError());

#if defined(__EMULATOR__)
  rockey.Write(kTestingDongleFile);
#endif /* __EMULATOR__ */
  
  std::ignore = TAG;
  return 10086 - result;
}

} // namespace dongle

rLANG_DECLARE_END

int main() {
  uint64_t InOutBuf[(3 << 10) / 8] = {0};
  uint64_t ExtendBuf[(1 << 10) / 8] = {0};

  return machine::dongle::Start(InOutBuf, ExtendBuf);
}


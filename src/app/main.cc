#include <base/base.h>
#include <Interface/dongle.h>
#include <tuple>

rLANG_DECLARE_MACHINE

namespace {
constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("App@K");
}

namespace dongle {

int Start(void* InOutBuf, void* ExtendBuf) {
  int result = 0;
  struct Context_t {
    uint8_t bytes[64];
  } *Context = (Context_t*)InOutBuf;


#if !defined(__RockeyARM__)
  RockeyARM rockey;

  result = rockey.Enum(nullptr);
  rlLOGI(TAG, "rockey.Enum return %d/%08x", result, rockey.GetLastError());

  result = rockey.Open(0);
  rlLOGI(TAG, "rockey.Open return %d/%08x", result, rockey.GetLastError());
#else

  Dongle rockey;

#endif

  result = rockey.RandBytes(Context->bytes, sizeof(Context->bytes));
  rlLOGXI(TAG, Context->bytes, sizeof(Context->bytes), "rockey.RandBytes return %d/%08x", result, rockey.GetLastError());

  
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


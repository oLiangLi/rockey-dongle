#include <Interface/dongle.h>

rLANG_DECLARE_MACHINE

namespace dongle {

namespace {
constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("Foobar");
}

struct InOutBuffer {
  uint8_t rand_[16];

  uint32_t tag;
};

class Application {
 public:
  Application(Dongle* dongle, void* iobuf, void* extbuf)
      : dongle_(dongle), iobuf_(static_cast<InOutBuffer*>(iobuf)), extbuf_(extbuf) {}
  ~Application() = default;
  
 public:
  int Run() {
    int result = dongle_->RandBytes(iobuf_->rand_, sizeof(iobuf_->rand_));   
    
    rlLOGXI(TAG, iobuf_, sizeof(*iobuf_), "%d) Exec: %08X", result, dongle_->GetLastError());

    iobuf_->tag = TAG;
    return result;
  }

 protected:
  Dongle* const dongle_;
  InOutBuffer* const iobuf_;
  void* const extbuf_;
};

int Start(void* InOutBuf, void* ExtendBuf) {
#ifdef __RockeyARM__
  Dongle dongle;
#else /* */
  RockeyARM dongle;
  dongle.Enum(nullptr);
  dongle.Open(0);
#endif
  Application instance{&dongle, InOutBuf, ExtendBuf};
  return instance.Run();
}

} // namespace dongle 

rLANG_DECLARE_END

int main() {
  uint64_t InOutBuf[(3 << 10) / 8] = {0};
  uint64_t ExtendBuf[(1 << 10) / 8] = {0};
  return machine::dongle::Start(InOutBuf, ExtendBuf);
}


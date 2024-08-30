#include <base/base.h>
#include <tuple>

rLANG_DECLARE_MACHINE

namespace Curve25519 {

struct Curve25519Context {
  uint8_t private_ed25519_az_[32];
  uint8_t private_x25519_[32];
  uint8_t public_ed25519_[32];
  uint8_t public_x25519__[32];

  uint32_t TAG_;
};

int Check(void* InOutBuf, void* ExtendBuf) {
  constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("25519");

  Curve25519Context* const Context = static_cast<Curve25519Context*>(InOutBuf);
  for (int i = 0; i < 32; ++i) {
    Context->private_ed25519_az_[i] = Context->private_x25519_[i] = static_cast<uint8_t>(i);
  }
  // Context->result_[0] = get_random(Context->private_ed25519_az_, sizeof(Context->private_ed25519_az_));
  // Context->result_[1] = get_random(Context->private_x25519_, sizeof(Context->private_x25519_));

  rlCryptoEd25519PubkeyEx(Context->public_ed25519_, Context->private_ed25519_az_);
  rlCryptoX25519Pubkey(Context->public_x25519__, Context->private_x25519_);
  std::ignore = Context->TAG_ = TAG;

#ifndef X_BUILD_native
  rlLOGXI(TAG, Context->public_ed25519_, sizeof(Context->public_ed25519_), "Context->public_ed25519_:");
  rlLOGXI(TAG, Context->public_x25519__, sizeof(Context->public_x25519__), "Context->public_x25519__:");
#endif /* X_BUILD_native */

  return 0;
}

}  // namespace Curve25519

namespace dongle {

int Start(void* InOutBuf, void* ExtendBuf) {
  return Curve25519::Check(InOutBuf, ExtendBuf);
}

}  // namespace dongle

rLANG_DECLARE_END

int main(int argc, char* argv[]) {
  uint64_t InOutBuf[(3 << 10) / 8];
  uint64_t ExtendBuf[(1 << 10) / 8];
  return machine::dongle::Start(InOutBuf, ExtendBuf);
}

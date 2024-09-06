#include <base/base.h>
#include <tuple>

rLANG_DECLARE_MACHINE

namespace Curve25519 {

struct Curve25519Context {
  uint8_t public_ed25519_[32];
  uint8_t public_x25519__[32];
  uint8_t pubkey_exchang_[32];
  uint8_t shared_secret__[32];

  uint32_t TAG_;
};

int Check(void* InOutBuf, void* ExtendBuf) {
  constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("25519");
  uint8_t private_[32];

  Curve25519Context* const Context = static_cast<Curve25519Context*>(InOutBuf);
  for (int i = 0; i < 32; ++i)
    private_[i] = static_cast<uint8_t>(i);

  rlCryptoEd25519PubkeyEx(Context->public_ed25519_, private_);
  rlCryptoX25519Pubkey(Context->public_x25519__, private_);

  /**! */
  rlCryptoX25519Pubkey(Context->pubkey_exchang_, Context->public_ed25519_);
  rlCryptoX25519(Context->shared_secret__, private_, Context->pubkey_exchang_);

  rlLOGXI(TAG, Context->public_ed25519_, sizeof(Context->public_ed25519_), "Context->public_ed25519_:");
  rlLOGXI(TAG, Context->public_x25519__, sizeof(Context->public_x25519__), "Context->public_x25519__:");
  rlLOGXI(TAG, Context->pubkey_exchang_, sizeof(Context->pubkey_exchang_), "Context->pubkey_exchang_:");
  rlLOGXI(TAG, Context->shared_secret__, sizeof(Context->shared_secret__), "Context->shared_secret__:");

  std::ignore = Context->TAG_ = TAG;

  return 10086;
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

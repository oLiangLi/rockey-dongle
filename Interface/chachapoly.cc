#include <Interface/dongle.h>
#include <base/base.h>

rLANG_DECLARE_MACHINE

namespace dongle {

int Dongle::CHACHAPOLY_Seal(const uint8_t key[32], const uint8_t nonce[12], void* buffer, size_t* size_) {
  size_t size = *size_;

  rlCryptoChaChaPolyCtx ctx;
  rlCryptoChaChaPolyInit(&ctx);
  rlCryptoChaChaPolySetKey(&ctx, key);
  rlCryptoChaChaPolyStarts(&ctx, nonce, 1);
  rlCryptoChaChaPolyUpdate(&ctx, buffer, buffer, size);
  rlCryptoChaChaPolyFinish(&ctx, static_cast<uint8_t*>(buffer) + size);

  *size_ = size + 16;
  return 0;
}

int Dongle::CHACHAPOLY_Open(const uint8_t key[32], const uint8_t nonce[12], void* buffer, size_t* size_) {
  size_t size = *size_;
  uint8_t mac[16];
  if (size < 16)
    return last_error_ = -EINVAL;
  size -= 16;

  rlCryptoChaChaPolyCtx ctx;
  rlCryptoChaChaPolyInit(&ctx);
  rlCryptoChaChaPolySetKey(&ctx, key);
  rlCryptoChaChaPolyStarts(&ctx, nonce, 0);
  rlCryptoChaChaPolyUpdate(&ctx, buffer, buffer, size);
  rlCryptoChaChaPolyFinish(&ctx, mac);

  *size_ = size;
  if (0 == memcmp(mac, static_cast<uint8_t*>(buffer) + size, 16))
    return 0;
  return last_error_ = -EFAULT;
}

} // namespace dongle

rLANG_DECLARE_END

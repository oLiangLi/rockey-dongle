#include <Interface/dongle.h>
#include <base/base.h>

rLANG_DECLARE_MACHINE

namespace dongle {

int Dongle::CHACHAPOLY_Seal(const uint8_t key[32],
                            const uint8_t nonce[12],
                            void* buffer,
                            size_t* size_,
                            const void* aad,
                            size_t aad_len) {
  size_t size = *size_;

  rlCryptoChaChaPolyCtx ctx;
  rlCryptoChaChaPolyInit(&ctx);
  rlCryptoChaChaPolySetKey(&ctx, key);
  rlCryptoChaChaPolyStarts(&ctx, nonce, 1);
  /* RFC 8439: AAD 必须在密文之前喂入, 否则 Poly1305 的输入顺序错、tag 不一致 */
  if (aad && aad_len)
    rlCryptoChaChaPolyUpdateAAd(&ctx, aad, aad_len);
  rlCryptoChaChaPolyUpdate(&ctx, buffer, buffer, size);
  rlCryptoChaChaPolyFinish(&ctx, static_cast<uint8_t*>(buffer) + size);

  *size_ = size + 16;
  return 0;
}

int Dongle::CHACHAPOLY_Open(const uint8_t key[32],
                            const uint8_t nonce[12],
                            void* buffer,
                            size_t* size_,
                            const void* aad,
                            size_t aad_len) {
  size_t size = *size_;
  uint8_t mac[16], diff = 0;
  if (size < 16)
    return last_error_ = -EINVAL;
  size -= 16;

  rlCryptoChaChaPolyCtx ctx;
  rlCryptoChaChaPolyInit(&ctx);
  rlCryptoChaChaPolySetKey(&ctx, key);
  rlCryptoChaChaPolyStarts(&ctx, nonce, 0);
  if (aad && aad_len)
    rlCryptoChaChaPolyUpdateAAd(&ctx, aad, aad_len);
  rlCryptoChaChaPolyUpdate(&ctx, buffer, buffer, size);
  rlCryptoChaChaPolyFinish(&ctx, mac);

  /* constant-time tag compare */
  const uint8_t* tag = static_cast<const uint8_t*>(buffer) + size;
  for (int i = 0; i < 16; ++i)
    diff |= (uint8_t)(mac[i] ^ tag[i]);

  if (0 == diff) {
    *size_ = size;
    return 0;
  }

  /* authentication failed: wipe the (unauthenticated) plaintext */
  memset(buffer, 0, size + 16);
  return last_error_ = -EFAULT;
}

}  // namespace dongle

rLANG_DECLARE_END

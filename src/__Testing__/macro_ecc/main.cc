#include <base/base.h>

#if defined(__RockeyARM__)
#define uECC_PLATFORM uECC_arm_thumb
#endif /* __RockeyARM__ */

/**
 *!
 */
// #define uECC_VLI_NATIVE_LITTLE_ENDIAN 1

/**
 *!
 */
#define uECC_SUPPORTS_secp160r1 0
#define uECC_SUPPORTS_secp192r1 0
#define uECC_SUPPORTS_secp224r1 0
#define uECC_SUPPORTS_secp256r1 1
#define uECC_SUPPORTS_secp256k1 1

#include <third_party/micro-ecc/uECC.h>
#include <third_party/micro-ecc/uECC.c>

rLANG_DECLARE_MACHINE

namespace {
constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("$ECC@");

static uint32_t state[16];
void InitRNG() {
  memset(state, 0, sizeof(state));
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;
}

int TestingRNG(uint8_t* dest, unsigned size) {
  uint8_t last[64];  

  while (size >= 64) {
    rlCryptoChaCha20Block(state, dest);
    ++state[12];
    dest += 64;
    size -= 64;
  }

  if (size > 0) {
    rlCryptoChaCha20Block(state, last);
    memcpy(dest, last, size);
    ++state[12];
  }

  return 1;
}

}

namespace dongle {

int Start(void* InOutBuf, void* ExtendBuf) {
  struct Context_t {
    uint8_t prikey1[32], pubkey1[64];
    uint8_t prikey2[32], pubkey2[64];
    uint8_t secret1[32], secret2[32];
    uint8_t sign1[64], sign2[64];

    int Exec() {
      int err = 0;
      uint8_t check_pubkey[64], compress_pubkey[33];      

      auto secp256r1 = uECC_secp256r1();
      auto secp256k1 = uECC_secp256k1();

      if (32 != uECC_curve_private_key_size(secp256r1))
        ++err;

      if (32 != uECC_curve_private_key_size(secp256k1))
        ++err;

      if (64 != uECC_curve_public_key_size(secp256r1))
        ++err;

      if (64 != uECC_curve_public_key_size(secp256k1))
        ++err;

      if (!uECC_make_key(pubkey1, prikey1, secp256r1))
        ++err;

      if (!uECC_make_key(pubkey2, prikey2, secp256r1))
        ++err;

      compress_pubkey[0] = 2 | pubkey1[63] % 2;
      memcpy(&compress_pubkey[1], pubkey1, 32);
      uECC_decompress(compress_pubkey, check_pubkey, secp256r1);
      if (0 != memcmp(check_pubkey, pubkey1, 32))
        ++err;

      compress_pubkey[0] = 2 | pubkey2[63] % 2;
      memcpy(&compress_pubkey[1], pubkey2, 32);
      uECC_decompress(compress_pubkey, check_pubkey, secp256r1);
      if (0 != memcmp(check_pubkey, pubkey2, 32))
        ++err;

      if (!uECC_shared_secret(pubkey1, prikey2, secret1, secp256r1))
        ++err;

      if (!uECC_shared_secret(pubkey2, prikey1, secret2, secp256r1))
        ++err;

      if (0 != memcmp(secret1, secret2, 32))
        ++err;

      if (!uECC_sign(prikey1, secret1, 32, sign1, secp256r1))
        ++err;

      if (!uECC_verify(pubkey1, secret1, 32, sign1, secp256r1))
        ++err;

      if (!uECC_make_key(pubkey1, prikey1, secp256k1))
        ++err;

      if (!uECC_make_key(pubkey2, prikey2, secp256k1))
        ++err;

      compress_pubkey[0] = 2 | pubkey1[63] % 2;
      memcpy(&compress_pubkey[1], pubkey1, 32);
      uECC_decompress(compress_pubkey, check_pubkey, secp256k1);
      if (0 != memcmp(check_pubkey, pubkey1, 32))
        ++err;

      compress_pubkey[0] = 2 | pubkey2[63] % 2;
      memcpy(&compress_pubkey[1], pubkey2, 32);
      uECC_decompress(compress_pubkey, check_pubkey, secp256k1);
      if (0 != memcmp(check_pubkey, pubkey2, 32))
        ++err;

      if (!uECC_shared_secret(pubkey1, prikey2, secret1, secp256k1))
        ++err;

      if (!uECC_shared_secret(pubkey2, prikey1, secret2, secp256k1))
        ++err;

      if (0 != memcmp(secret1, secret2, 32))
        ++err;

      if (!uECC_sign(prikey1, secret1, 32, sign2, secp256k1))
        ++err;

      if (!uECC_verify(pubkey1, secret1, 32, sign2, secp256k1))
        ++err;

      return 10086 - err;
    }
  }* Context = (struct Context_t*)InOutBuf;

  rLANG_ABIREQUIRE(sizeof(Context_t) <= 0x400);

  int result;
#ifndef X_BUILD_native
  for (int loop = 0; loop < 100; ++loop) {
    result = Context->Exec();
    rlLOGXI(TAG, Context, sizeof(*Context), "%d Context: %d", loop, result);
    if (result != 10086)
      abort();
  }
#endif /* X_BUILD_native */

  InitRNG();
  uECC_set_rng(TestingRNG);
  result = Context->Exec();
#ifndef X_BUILD_native
  rlLOGXI(TAG, Context, sizeof(*Context), "Context: %d", result);
  for (int loop = 0; loop < 10; ++loop) {
    Context_t copy_context;
    memcpy(&copy_context, Context, sizeof(Context_t));

    InitRNG();
    result = Context->Exec();
    rlLOGXI(TAG, Context, sizeof(*Context), "%d Context: %d", loop, result);
    if (result != 10086 || 0 != memcmp(&copy_context, Context, sizeof(Context_t)))
      abort();
  }
#endif /* X_BUILD_native */

  return result;
}

}  // namespace dongle

rLANG_DECLARE_END

int main() {
  uint64_t InOutBuf[(3 << 10) / 8] = {0};
  uint64_t ExtendBuf[(1 << 10) / 8] = {0};
  return machine::dongle::Start(InOutBuf, ExtendBuf);
}

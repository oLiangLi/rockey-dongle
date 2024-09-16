#include <base/base.h>

#ifdef _MSC_VER
#pragma warning(disable: 4244)
#endif /* _MSC_VER*/

#if defined(__RockeyARM__)
#endif /* __RockeyARM__ */

#define uECC_SUPPORTS_secp160r1 0
#define uECC_SUPPORTS_secp192r1 0
#define uECC_SUPPORTS_secp224r1 0
#define uECC_WORD_SIZE 4


#if defined(__RockeyARM__)  // uECC_arm_thumb
#define uECC_PLATFORM 4
#endif /* __RockeyARM__ */

#include <third_party/micro-ecc/uECC.h>
#include <third_party/micro-ecc/uECC.c>

rLANG_DECLARE_MACHINE

namespace {
constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("$ECC@");

struct RNG_STATE_t {
  uint32_t state[16];
};
static RNG_STATE_t* RNG_STATE;

void InitRNG(RNG_STATE_t* state) {
  RNG_STATE = state;

  memset(RNG_STATE->state, 0, sizeof(RNG_STATE->state));

  RNG_STATE->state[0] = 0x61707865;
  RNG_STATE->state[1] = 0x3320646e;
  RNG_STATE->state[2] = 0x79622d32;
  RNG_STATE->state[3] = 0x6b206574;
}

}

namespace dongle {
    
int TestingRNG(uint8_t* dest, unsigned size) {
  uint8_t last[64];

  while (size >= 64) {
    rlCryptoChaCha20Block(RNG_STATE->state, dest);
    ++RNG_STATE->state[12];
    dest += 64;
    size -= 64;
  }

  if (size > 0) {
    rlCryptoChaCha20Block(RNG_STATE->state, last);
    memcpy(dest, last, size);
    ++RNG_STATE->state[12];
  }

  return 1;
}

void InitCurve(uECC_Curve_t* r1, uECC_Curve_t* k1) {
  zp__curve_secp256r1 = r1;
  zp__curve_secp256k1 = k1;

#undef BYTES_TO_WORDS_8_V
#define BYTES_TO_WORDS_8_V(pp, ii, a, b, c, d, e, f, g, h) \
  do {                                                     \
    curve_secp256r1.pp[ii + 0] = 0x##d##c##b##a;           \
    curve_secp256r1.pp[ii + 1] = 0x##h##g##f##e;           \
  } while (0)

  curve_secp256r1.num_words = curve_secp256k1.num_words = 8;
  curve_secp256r1.num_bytes = curve_secp256k1.num_bytes = 32;
  curve_secp256r1.num_n_bits = curve_secp256k1.num_n_bits = 256;

  BYTES_TO_WORDS_8_V(p, 0, FF, FF, FF, FF, FF, FF, FF, FF);
  BYTES_TO_WORDS_8_V(p, 2, FF, FF, FF, FF, 00, 00, 00, 00);
  BYTES_TO_WORDS_8_V(p, 4, 00, 00, 00, 00, 00, 00, 00, 00);
  BYTES_TO_WORDS_8_V(p, 6, 01, 00, 00, 00, FF, FF, FF, FF);

  BYTES_TO_WORDS_8_V(n, 0, 51, 25, 63, FC, C2, CA, B9, F3);
  BYTES_TO_WORDS_8_V(n, 2, 84, 9E, 17, A7, AD, FA, E6, BC);
  BYTES_TO_WORDS_8_V(n, 4, FF, FF, FF, FF, FF, FF, FF, FF);
  BYTES_TO_WORDS_8_V(n, 6, 00, 00, 00, 00, FF, FF, FF, FF);

  BYTES_TO_WORDS_8_V(G, 0, 96, C2, 98, D8, 45, 39, A1, F4);
  BYTES_TO_WORDS_8_V(G, 2, A0, 33, EB, 2D, 81, 7D, 03, 77);
  BYTES_TO_WORDS_8_V(G, 4, F2, 40, A4, 63, E5, E6, BC, F8);
  BYTES_TO_WORDS_8_V(G, 6, 47, 42, 2C, E1, F2, D1, 17, 6B);

  BYTES_TO_WORDS_8_V(G, 8, F5, 51, BF, 37, 68, 40, B6, CB);
  BYTES_TO_WORDS_8_V(G, 10, CE, 5E, 31, 6B, 57, 33, CE, 2B);
  BYTES_TO_WORDS_8_V(G, 12, 16, 9E, 0F, 7C, 4A, EB, E7, 8E);
  BYTES_TO_WORDS_8_V(G, 14, 9B, 7F, 1A, FE, E2, 42, E3, 4F);

  BYTES_TO_WORDS_8_V(b, 0, 4B, 60, D2, 27, 3E, 3C, CE, 3B);
  BYTES_TO_WORDS_8_V(b, 2, F6, B0, 53, CC, B0, 06, 1D, 65);
  BYTES_TO_WORDS_8_V(b, 4, BC, 86, 98, 76, 55, BD, EB, B3);
  BYTES_TO_WORDS_8_V(b, 6, E7, 93, 3A, AA, D8, 35, C6, 5A);

#undef BYTES_TO_WORDS_8_V
#define BYTES_TO_WORDS_8_V(pp, ii, a, b, c, d, e, f, g, h) \
  do {                                                     \
    curve_secp256k1.pp[ii + 0] = 0x##d##c##b##a;           \
    curve_secp256k1.pp[ii + 1] = 0x##h##g##f##e;           \
  } while (0)

  BYTES_TO_WORDS_8_V(p, 0, 2F, FC, FF, FF, FE, FF, FF, FF);
  BYTES_TO_WORDS_8_V(p, 2, FF, FF, FF, FF, FF, FF, FF, FF);
  BYTES_TO_WORDS_8_V(p, 4, FF, FF, FF, FF, FF, FF, FF, FF);
  BYTES_TO_WORDS_8_V(p, 6, FF, FF, FF, FF, FF, FF, FF, FF);

  BYTES_TO_WORDS_8_V(n, 0, 41, 41, 36, D0, 8C, 5E, D2, BF);
  BYTES_TO_WORDS_8_V(n, 2, 3B, A0, 48, AF, E6, DC, AE, BA);
  BYTES_TO_WORDS_8_V(n, 4, FE, FF, FF, FF, FF, FF, FF, FF);
  BYTES_TO_WORDS_8_V(n, 6, FF, FF, FF, FF, FF, FF, FF, FF);

  BYTES_TO_WORDS_8_V(G, 0, 98, 17, F8, 16, 5B, 81, F2, 59);
  BYTES_TO_WORDS_8_V(G, 2, D9, 28, CE, 2D, DB, FC, 9B, 02);
  BYTES_TO_WORDS_8_V(G, 4, 07, 0B, 87, CE, 95, 62, A0, 55);
  BYTES_TO_WORDS_8_V(G, 6, AC, BB, DC, F9, 7E, 66, BE, 79);

  BYTES_TO_WORDS_8_V(G, 8, B8, D4, 10, FB, 8F, D0, 47, 9C);
  BYTES_TO_WORDS_8_V(G, 10, 19, 54, 85, A6, 48, B4, 17, FD);
  BYTES_TO_WORDS_8_V(G, 12, A8, 08, 11, 0E, FC, FB, A4, 5D);
  BYTES_TO_WORDS_8_V(G, 14, 65, C4, A3, 26, 77, DA, 3A, 48);

  curve_secp256k1.b[0] = 7;
}


int Start(void* InOutBuf, void* ExtendBuf) {
  uECC_Curve_t r1, k1;
  machine::dongle::InitCurve(&r1, &k1);

  struct Context_t {
    uint8_t prikey1[32], pubkey1[64];
    uint8_t prikey2[32], pubkey2[64];
    uint8_t secret1[32], secret2[32];
    uint8_t sign1[64], sign2[64];

    int Exec() {
      int err = 0;
      uint8_t check_pubkey[64], compress_pubkey[33];


      auto secp256r1 = &curve_secp256r1;
      auto secp256k1 = &curve_secp256k1;

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
  RNG_STATE_t state;

  InitRNG(&state);
  //uECC_set_rng(TestingRNG);
  result = Context->Exec();
  rlLOGXI(TAG, Context, sizeof(*Context), "Context: %d", result);

  return result;
}

}  // namespace dongle

rLANG_DECLARE_END

int Micro_ECC_RNG_t::operator()(uint8_t* dest, unsigned int size) {
  return machine::dongle::TestingRNG(dest, size);
}

int main() {
  uint64_t InOutBuf[(3 << 10) / 8] = {0};
  uint64_t ExtendBuf[(1 << 10) / 8] = {0};  
  return machine::dongle::Start(InOutBuf, ExtendBuf);
}

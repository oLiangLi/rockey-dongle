#include <Interface/dongle.h>
#include <base/base.h>

#ifdef _MSC_VER
#pragma warning(disable : 4244)
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

namespace dongle {

struct ScopeRNG {
  ScopeRNG(Dongle* dongle_) { g_rng_function.dongle_ = dongle_; }
  ~ScopeRNG() { g_rng_function.dongle_ = nullptr; }
};

namespace {

constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("CURVE");

struct CurveSM2_t {
  static constexpr int num_words = 8;
  uECC_word_t p[8];
  uECC_word_t b[8];
};
  
void GFpCurveSM2(CurveSM2_t* sm2) {
#define BYTES_TO_WORDS_8_V(pp, ii, a, b, c, d, e, f, g, h) \
  do {                                                     \
    sm2->pp[ii + 0] = 0x##d##c##b##a;                      \
    sm2->pp[ii + 1] = 0x##h##g##f##e;                      \
  } while (0)

  BYTES_TO_WORDS_8_V(p, 0, ff, ff, ff, ff, ff, ff, ff, ff);
  BYTES_TO_WORDS_8_V(p, 2, 00, 00, 00, 00, ff, ff, ff, ff);
  BYTES_TO_WORDS_8_V(p, 4, ff, ff, ff, ff, ff, ff, ff, ff);
  BYTES_TO_WORDS_8_V(p, 6, ff, ff, ff, ff, fe, ff, ff, ff);

  BYTES_TO_WORDS_8_V(b, 0, 93, 0e, 94, 4d, 41, bd, bc, dd);
  BYTES_TO_WORDS_8_V(b, 2, 92, 8f, ab, 15, f5, 89, 97, f3);
  BYTES_TO_WORDS_8_V(b, 4, a7, 09, 65, cf, 4b, 9e, 5a, 4d);
  BYTES_TO_WORDS_8_V(b, 6, 34, 5e, 9f, 9d, 9e, fa, e9, 28);
}

void uECC_vli_modMult_sm2(uECC_word_t* result,
  const uECC_word_t* left,
  const uECC_word_t* right,
  const CurveSM2_t* curve) {
  //TODO: LiangLI, implements modMult_sm2 ...
  uECC_vli_modMult(result, left, right, curve->p, 8);
}

void x_side_sm2(uECC_word_t* result, const uECC_word_t* x, const CurveSM2_t* curve) {
  uECC_word_t _3[8] = {3}; /* -a = 3 */

  uECC_vli_modMult_sm2(result, x, x, curve);              /* r = x^2 */
  uECC_vli_modSub(result, result, _3, curve->p, 8);       /* r = x^2 - 3 */
  uECC_vli_modMult_sm2(result, result, x, curve);         /* r = x^3 - 3x */
  uECC_vli_modAdd(result, result, curve->b, curve->p, 8); /* r = x^3 - 3x + b */
}

/* Compute a = sqrt(a) (mod curve_p). */
void mod_sqrt_sm2(uECC_word_t* a, const CurveSM2_t* curve) {
  bitcount_t i;
  uECC_word_t p1[8] = {1};
  uECC_word_t l_result[8] = {1};

  /* When curve->p == 3 (mod 4), we can compute
     sqrt(a) = a^((curve->p + 1) / 4) (mod curve->p). */
  uECC_vli_add(p1, curve->p, p1, 8); /* p1 = curve_p + 1 */
  for (i = uECC_vli_numBits(p1, 8) - 1; i > 1; --i) {
    uECC_vli_modMult_sm2(l_result, l_result, l_result, curve);
    if (uECC_vli_testBit(p1, i)) {
      uECC_vli_modMult_sm2(l_result, l_result, a, curve);
    }
  }
  uECC_vli_set(a, l_result, 8);
}

}


/**
 *! ... SM2 ...
 */
int Dongle::CheckPointOnCurveSM2(const uint8_t X[32], const uint8_t Y[32]) {
  uECC_word_t tmp1[8];
  uECC_word_t tmp2[8];
  uECC_word_t point[8 * 2];
  uECC_vli_bytesToNative(point, X, 32);
  uECC_vli_bytesToNative(point + 8, Y, 32);

  CurveSM2_t sm2;
  GFpCurveSM2(&sm2);

  if (EccPoint_isZero(point, &sm2))
    return -EINVAL;

  /* x and y must be smaller than p. */
  if (uECC_vli_cmp_unsafe(sm2.p, point, 8) != 1 || uECC_vli_cmp_unsafe(sm2.p, point + 8, 8) != 1)
    return -EINVAL;

  uECC_vli_modMult_sm2(tmp1, point + 8, point + 8, &sm2);  // y*y
  x_side_sm2(tmp2, point, &sm2);                           // x*x*x + a*x + b ...

  return uECC_vli_equal(tmp1, tmp2, 8) ? 0 : -EINVAL;
}

int Dongle::DecompressPointSM2(uint8_t Y[32], const uint8_t X[32], bool Yodd) {
  uECC_word_t pointX[8];
  uECC_word_t pointY[8];
  uECC_vli_bytesToNative(pointX, X, 32);

  CurveSM2_t sm2;
  GFpCurveSM2(&sm2);

  x_side_sm2(pointY, pointX, &sm2);
  mod_sqrt_sm2(pointY, &sm2);

  if ((pointY[0] & 1) != (Yodd ? 1 : 0))
    uECC_vli_sub(pointY, sm2.p, pointY, 8);
  uECC_vli_nativeToBytes(Y, 32, pointY);  
  return 0;
}

/**
 *! ... P256 ...
 */
int Dongle::CheckPointOnCurvePrime256v1(const uint8_t X[32], const uint8_t Y[32]) {
  return -ENOSYS;
}
int Dongle::DecompressPointPrime256v1(uint8_t Y[32], const uint8_t X[32], bool Yodd) {
  return -ENOSYS;
}
int Dongle::GenerateKeyPairPrime256v1(uint8_t X[32], uint8_t Y[32], uint8_t K[32]) {
  return -ENOSYS;
}
int Dongle::ComputeSecretPrime256v1(uint8_t secret[32], const uint8_t X[32], const uint8_t Y[32], const uint8_t K[32]) {
  return -ENOSYS;
}
int Dongle::SignMessagePrime256v1(const uint8_t K[32], const uint8_t H[32], uint8_t R[32], uint8_t S[32]) {
  return -ENOSYS;
}
int Dongle::VerifySignPrime256v1(const uint8_t X[32],
                                 const uint8_t Y[32],
                                 const uint8_t H[32],
                                 const uint8_t R[32],
                                 const uint8_t S[32]) {
  return -ENOSYS;
}

/**
 *! ... Secp256k1 ...
 */
int Dongle::CheckPointOnCurveSecp256k1(const uint8_t X[32], const uint8_t Y[32]) {
  return -ENOSYS;
}
int Dongle::DecompressPointSecp256k1(uint8_t Y[32], const uint8_t X[32], bool Yodd) {
  return -ENOSYS;
}
int Dongle::GenerateKeyPairSecp256k1(uint8_t X[32], uint8_t Y[32], uint8_t K[32]) {
  return -ENOSYS;
}
int Dongle::ComputeSecretSecp256k1(uint8_t secret[32], const uint8_t X[32], const uint8_t Y[32], const uint8_t K[32]) {
  return -ENOSYS;
}
int Dongle::SignMessageSecp256k1(const uint8_t K[32], const uint8_t H[32], uint8_t R[32], uint8_t S[32]) {
  return -ENOSYS;
}
int Dongle::VerifySignSecp256k1(const uint8_t X[32],
                                const uint8_t Y[32],
                                const uint8_t H[32],
                                const uint8_t R[32],
                                const uint8_t S[32]) {
  return -ENOSYS;
}

} // namespace dongle 

rLANG_DECLARE_END

int Micro_ECC_RNG_t::operator()(uint8_t* dest, unsigned int size) {
  auto* dongle = static_cast<machine::dongle::Dongle*>(dongle_);
  return dongle->RandBytes(dest, size) >= 0 ? 1 : 0;
}


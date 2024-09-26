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

struct ScopeSecp256r1 {
  ScopeSecp256r1() {
    zp__curve_secp256r1 = &curve_;

#undef BYTES_TO_WORDS_8_V
#define BYTES_TO_WORDS_8_V(pp, ii, a, b, c, d, e, f, g, h) \
  do {                                                     \
    curve_secp256r1.pp[ii + 0] = 0x##d##c##b##a;           \
    curve_secp256r1.pp[ii + 1] = 0x##h##g##f##e;           \
  } while (0)

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
  }
  ~ScopeSecp256r1() { zp__curve_secp256r1 = nullptr; }

 private:
  uECC_Curve_t curve_{8, 32, 256};
};

struct ScopeSecp256k1 {
  ScopeSecp256k1() {
    zp__curve_secp256k1 = &curve_;

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
  ~ScopeSecp256k1() { zp__curve_secp256k1 = nullptr; }

 private:
  uECC_Curve_t curve_{8, 32, 256};
};


namespace {

constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("CURVE");

struct CurveSM2_t {
  static constexpr int num_words = 8;
  uECC_word_t p[8];
  uECC_word_t b[8];
};
  
void GFpCurveSM2(CurveSM2_t* sm2) {
#undef BYTES_TO_WORDS_8_V
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
  uECC_word_t product[16];

  uECC_vli_mult(product, left, right, 8);

  ///
  /// see: https://tongsuo.net/docs/features/sm2/overview/
  /// 
#if 0  
  uECC_vli_mmod(result, product, curve->p, 8);
#else
  int carry = 0;
  uECC_word_t T[8];
  uECC_word_t* const P = product;

  uECC_vli_set(result, product, 8);  // s1

  T[0] = P[8];
  T[1] = P[9];
  T[2] = 0;
  T[3] = P[11];
  T[4] = P[12];
  T[5] = P[13];
  T[6] = P[14];
  T[7] = P[15];
  carry += uECC_vli_add(result, result, T, 8);  // s2

  T[0] = P[13];
  T[1] = P[14];
  T[2] = 0;
  T[3] = P[13];
  T[4] = P[14];
  T[5] = P[15];
  T[6] = 0;
  T[7] = P[14];
  carry += uECC_vli_add(T, T, T, 8);  // 2*s3
  carry += uECC_vli_add(result, result, T, 8);

  T[0] = P[14];
  T[1] = P[15];
  T[2] = 0;
  T[3] = 0;
  T[4] = 0;
  T[5] = 0;
  T[6] = 0;
  T[7] = P[13];
  carry += uECC_vli_add(T, T, T, 8);  // 2*s4
  carry += uECC_vli_add(result, result, T, 8);

  T[0] = P[15];
  T[1] = 0;
  T[2] = 0;
  T[3] = 0;
  T[4] = 0;
  T[5] = 0;
  T[6] = 0;
  T[7] = P[12];
  carry += uECC_vli_add(T, T, T, 8);  // 2*s5
  carry += uECC_vli_add(result, result, T, 8);

  T[0] = P[12];
  T[1] = P[13];
  T[2] = 0;
  T[3] = P[14];
  T[4] = P[15];
  T[5] = P[10];
  T[6] = P[11];
  T[7] = P[11];
  carry += uECC_vli_add(result, result, T, 8);  // s6

  T[0] = P[10];
  T[1] = P[11];
  T[2] = 0;
  T[3] = P[12];
  T[4] = P[13];
  T[5] = P[14];
  T[6] = P[15];
  T[7] = P[10];
  carry += uECC_vli_add(result, result, T, 8);  // s7

  T[0] = P[9];
  T[1] = P[10];
  T[2] = 0;
  T[3] = P[8];
  T[4] = P[9];
  T[5] = 0;
  T[6] = 0;
  T[7] = P[9];
  carry += uECC_vli_add(result, result, T, 8);  // s8

  T[0] = P[11];
  T[1] = P[12];
  T[2] = 0;
  T[3] = P[15];
  T[4] = 0;
  T[5] = 0;
  T[6] = 0;
  T[7] = P[8];
  carry += uECC_vli_add(result, result, T, 8);  // s9

  T[0] = 0;
  T[1] = 0;
  T[2] = 0;
  T[3] = 0;
  T[4] = 0;
  T[5] = 0;
  T[6] = 0;
  T[7] = P[15];
  carry += uECC_vli_add(T, T, T, 8);  // 2*s10
  carry += uECC_vli_add(result, result, T, 8);

  T[0] = 0;
  T[1] = 0;
  T[2] = P[14];
  T[3] = 0;
  T[4] = 0;
  T[5] = 0;
  T[6] = 0;
  T[7] = 0;
  carry -= uECC_vli_sub(result, result, T, 8);

  T[0] = 0;
  T[1] = 0;
  T[2] = P[13];
  T[3] = 0;
  T[4] = 0;
  T[5] = 0;
  T[6] = 0;
  T[7] = 0;
  carry -= uECC_vli_sub(result, result, T, 8);

  T[0] = 0;
  T[1] = 0;
  T[2] = P[9];
  T[3] = 0;
  T[4] = 0;
  T[5] = 0;
  T[6] = 0;
  T[7] = 0;
  carry -= uECC_vli_sub(result, result, T, 8);

  T[0] = 0;
  T[1] = 0;
  T[2] = P[8];
  T[3] = 0;
  T[4] = 0;
  T[5] = 0;
  T[6] = 0;
  T[7] = 0;
  carry -= uECC_vli_sub(result, result, T, 8);
  
  if (carry < 0) {
    do {
      carry += uECC_vli_add(result, result, curve->p, 8);
    } while (carry < 0);
  } else {
    while (carry || uECC_vli_cmp_unsafe(curve->p, result, 8) != 1) {
      carry -= uECC_vli_sub(result, result, curve->p, 8);
    }
  }
#endif
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
    return last_error_ = -EFAULT;

  /* x and y must be smaller than p. */
  if (uECC_vli_cmp_unsafe(sm2.p, point, 8) != 1 || uECC_vli_cmp_unsafe(sm2.p, point + 8, 8) != 1)
    return last_error_ = -EFAULT;

  uECC_vli_modMult_sm2(tmp1, point + 8, point + 8, &sm2);  // y*y
  x_side_sm2(tmp2, point, &sm2);                           // x*x*x + a*x + b ...

  return uECC_vli_equal(tmp1, tmp2, 8) ? 0 : last_error_ = -EFAULT;
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
  uint8_t pubkey[64];
  memcpy(&pubkey[0], X, 32);
  memcpy(&pubkey[32], Y, 32);
  ScopeSecp256r1 __secp256r1;
  return uECC_valid_public_key(pubkey, &curve_secp256r1) ? 0 : last_error_ = -EFAULT;
}
int Dongle::DecompressPointPrime256v1(uint8_t Y[32], const uint8_t X[32], bool Yodd) {
  uint8_t pubkey[64];
  pubkey[0] = Yodd ? 3 : 2;
  memcpy(&pubkey[1], X, 32);

  ScopeSecp256r1 __secp256r1;
  uECC_decompress(pubkey, pubkey, &curve_secp256r1);
  memcpy(Y, &pubkey[32], 32);
  return 0;
}
int Dongle::ComputePubkeyPrime256v1(uint8_t X[32], uint8_t Y[32], const uint8_t K[32]) {
  uint8_t pubkey[64];

  ScopeRNG __rng(this);
  ScopeSecp256r1 __secp256r1;
  if (!uECC_compute_public_key(K, pubkey, &curve_secp256r1))
    return last_error_ = -EFAULT;
  memcpy(X, &pubkey[0], 32);
  memcpy(Y, &pubkey[32], 32);
  return 0;
}
int Dongle::GenerateKeyPairPrime256v1(uint8_t X[32], uint8_t Y[32], uint8_t K[32]) {
  uint8_t pubkey[64];

  ScopeRNG __rng(this);
  ScopeSecp256r1 __secp256r1;
  if (!uECC_make_key(pubkey, K, &curve_secp256r1))
    return last_error_ = -EFAULT;
  memcpy(X, &pubkey[0], 32);
  memcpy(Y, &pubkey[32], 32);
  return 0;
}
int Dongle::ComputeSecretPrime256v1(uint8_t secret[32], const uint8_t X[32], const uint8_t Y[32], const uint8_t K[32]) {
  uint8_t pubkey[64];
  memcpy(&pubkey[0], X, 32);
  memcpy(&pubkey[32], Y, 32);

  ScopeRNG __rng(this);
  ScopeSecp256r1 __secp256r1;
  return uECC_shared_secret(pubkey, K, secret, &curve_secp256r1) ? 0 : last_error_ = -EFAULT;
}
int Dongle::SignMessagePrime256v1(const uint8_t K[32], const uint8_t H[32], uint8_t R[32], uint8_t S[32]) {
  uint8_t sign[64];

  ScopeRNG __rng(this);
  ScopeSecp256r1 __secp256r1;
  if (!uECC_sign(K, H, 32, sign, &curve_secp256r1))
    return last_error_ = -EFAULT;

  memcpy(R, &sign[0], 32);
  memcpy(S, &sign[32], 32);
  return 0;
}
int Dongle::VerifySignPrime256v1(const uint8_t X[32],
                                 const uint8_t Y[32],
                                 const uint8_t H[32],
                                 const uint8_t R[32],
                                 const uint8_t S[32]) {  
  uint8_t sign[64];
  uint8_t pubkey[64];
  memcpy(&sign[0], R, 32);
  memcpy(&sign[32], S, 32);
  memcpy(&pubkey[0], X, 32);
  memcpy(&pubkey[32], Y, 32);

  ScopeSecp256r1 __secp256r1;
  return uECC_verify(pubkey, H, 32, sign, &curve_secp256r1) ? 0 : last_error_ = -EFAULT;
}

/**
 *! ... Secp256k1 ...
 */
int Dongle::CheckPointOnCurveSecp256k1(const uint8_t X[32], const uint8_t Y[32]) {
  uint8_t pubkey[64];
  memcpy(&pubkey[0], X, 32);
  memcpy(&pubkey[32], Y, 32);
  ScopeSecp256k1 __secp256k1;
  return uECC_valid_public_key(pubkey, &curve_secp256k1) ? 0 : last_error_ = -EFAULT;
}
int Dongle::DecompressPointSecp256k1(uint8_t Y[32], const uint8_t X[32], bool Yodd) {
  uint8_t pubkey[64];
  pubkey[0] = Yodd ? 3 : 2;
  memcpy(&pubkey[1], X, 32);

  ScopeSecp256k1 __secp256k1;
  uECC_decompress(pubkey, pubkey, &curve_secp256k1);
  memcpy(Y, &pubkey[32], 32);
  return 0;
}
int Dongle::ComputePubkeySecp256k1(uint8_t X[32], uint8_t Y[32], const uint8_t K[32]) {
  uint8_t pubkey[64];

  ScopeRNG __rng(this);
  ScopeSecp256k1 __secp256k1;
  if (!uECC_compute_public_key(K, pubkey, &curve_secp256k1))
    return last_error_ = -EFAULT;
  memcpy(X, &pubkey[0], 32);
  memcpy(Y, &pubkey[32], 32);
  return 0;
}
int Dongle::GenerateKeyPairSecp256k1(uint8_t X[32], uint8_t Y[32], uint8_t K[32]) {
  uint8_t pubkey[64];

  ScopeRNG __rng(this);
  ScopeSecp256k1 __secp256k1;
  if (!uECC_make_key(pubkey, K, &curve_secp256k1))
    return last_error_ = -EFAULT;
  memcpy(X, &pubkey[0], 32);
  memcpy(Y, &pubkey[32], 32);
  return 0;
}
int Dongle::ComputeSecretSecp256k1(uint8_t secret[32], const uint8_t X[32], const uint8_t Y[32], const uint8_t K[32]) {
  uint8_t pubkey[64];
  memcpy(&pubkey[0], X, 32);
  memcpy(&pubkey[32], Y, 32);

  ScopeRNG __rng(this);
  ScopeSecp256k1 __secp256k1;
  return uECC_shared_secret(pubkey, K, secret, &curve_secp256k1);
}
int Dongle::SignMessageSecp256k1(const uint8_t K[32], const uint8_t H[32], uint8_t R[32], uint8_t S[32]) {
  uint8_t sign[64];

  ScopeRNG __rng(this);
  ScopeSecp256k1 __secp256k1;
  if (!uECC_sign(K, H, 32, sign, &curve_secp256k1))
    return last_error_ = -EFAULT;

  memcpy(R, &sign[0], 32);
  memcpy(S, &sign[32], 32);
  return 0;
}
int Dongle::VerifySignSecp256k1(const uint8_t X[32],
                                const uint8_t Y[32],
                                const uint8_t H[32],
                                const uint8_t R[32],
                                const uint8_t S[32]) {
  uint8_t sign[64];
  uint8_t pubkey[64];
  memcpy(&sign[0], R, 32);
  memcpy(&sign[32], S, 32);
  memcpy(&pubkey[0], X, 32);
  memcpy(&pubkey[32], Y, 32);

  ScopeSecp256k1 __secp256k1;
  return uECC_verify(pubkey, H, 32, sign, &curve_secp256k1) ? 0 : last_error_ = -EFAULT;
}

} // namespace dongle 

rLANG_DECLARE_END

int Micro_ECC_RNG_t::operator()(uint8_t* dest, unsigned int size) {
  auto* dongle = static_cast<machine::dongle::Dongle*>(dongle_);
  return dongle->RandBytes(dest, size) >= 0 ? 1 : 0;
}


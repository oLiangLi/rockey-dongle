#include <Interface/dongle.h>
#include <base/base.h>

rLANG_DECLARE_MACHINE

namespace {
constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("25519");
}

namespace dongle {
  
// Curve25519 ...
namespace {
/*
 * Reference base 2^25.5 implementation.
 */
/*
 * This code is mostly taken from the ref10 version of Ed25519 in SUPERCOP
 * 20141124 (http://bench.cr.yp.to/supercop.html).
 *
 * The field functions are shared by Ed25519 and X25519 where possible.
 */

/* fe means field element. Here the field is \Z/(2^255-19). An element t,
 * entries t[0]...t[9], represents the integer t[0]+2^26 t[1]+2^51 t[2]+2^77
 * t[3]+2^102 t[4]+...+2^230 t[9]. Bounds on each t[i] vary depending on
 * context.  */
typedef int32_t fe[10];

static const int64_t kBottom25Bits = 0x1ffffffLL;
static const int64_t kBottom26Bits = 0x3ffffffLL;
static const int64_t kTop39Bits = 0xfffffffffe000000LL;
static const int64_t kTop38Bits = 0xfffffffffc000000LL;

static uint64_t load_3(const uint8_t* in) {
  uint64_t result;
  result = (uint64_t)in[0];
  result |= ((uint64_t)in[1]) << 8;
  result |= ((uint64_t)in[2]) << 16;
  return result;
}

static uint64_t load_4(const uint8_t* in) {
  uint64_t result;
  result = (uint64_t)in[0];
  result |= ((uint64_t)in[1]) << 8;
  result |= ((uint64_t)in[2]) << 16;
  result |= ((uint64_t)in[3]) << 24;
  return result;
}

static void fe_frombytes(fe h, const uint8_t* s) {
  /* Ignores top bit of h. */
  int64_t h0 = load_4(s);
  int64_t h1 = load_3(s + 4) << 6;
  int64_t h2 = load_3(s + 7) << 5;
  int64_t h3 = load_3(s + 10) << 3;
  int64_t h4 = load_3(s + 13) << 2;
  int64_t h5 = load_4(s + 16);
  int64_t h6 = load_3(s + 20) << 7;
  int64_t h7 = load_3(s + 23) << 5;
  int64_t h8 = load_3(s + 26) << 4;
  int64_t h9 = (load_3(s + 29) & 8388607) << 2;
  int64_t carry0;
  int64_t carry1;
  int64_t carry2;
  int64_t carry3;
  int64_t carry4;
  int64_t carry5;
  int64_t carry6;
  int64_t carry7;
  int64_t carry8;
  int64_t carry9;

  carry9 = h9 + (1 << 24);
  h0 += (carry9 >> 25) * 19;
  h9 -= carry9 & kTop39Bits;
  carry1 = h1 + (1 << 24);
  h2 += carry1 >> 25;
  h1 -= carry1 & kTop39Bits;
  carry3 = h3 + (1 << 24);
  h4 += carry3 >> 25;
  h3 -= carry3 & kTop39Bits;
  carry5 = h5 + (1 << 24);
  h6 += carry5 >> 25;
  h5 -= carry5 & kTop39Bits;
  carry7 = h7 + (1 << 24);
  h8 += carry7 >> 25;
  h7 -= carry7 & kTop39Bits;

  carry0 = h0 + (1 << 25);
  h1 += carry0 >> 26;
  h0 -= carry0 & kTop38Bits;
  carry2 = h2 + (1 << 25);
  h3 += carry2 >> 26;
  h2 -= carry2 & kTop38Bits;
  carry4 = h4 + (1 << 25);
  h5 += carry4 >> 26;
  h4 -= carry4 & kTop38Bits;
  carry6 = h6 + (1 << 25);
  h7 += carry6 >> 26;
  h6 -= carry6 & kTop38Bits;
  carry8 = h8 + (1 << 25);
  h9 += carry8 >> 26;
  h8 -= carry8 & kTop38Bits;

  h[0] = (int32_t)h0;
  h[1] = (int32_t)h1;
  h[2] = (int32_t)h2;
  h[3] = (int32_t)h3;
  h[4] = (int32_t)h4;
  h[5] = (int32_t)h5;
  h[6] = (int32_t)h6;
  h[7] = (int32_t)h7;
  h[8] = (int32_t)h8;
  h[9] = (int32_t)h9;
}

/* Preconditions:
 *  |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
 *
 * Write p=2^255-19; q=floor(h/p).
 * Basic claim: q = floor(2^(-255)(h + 19 2^(-25)h9 + 2^(-1))).
 *
 * Proof:
 *   Have |h|<=p so |q|<=1 so |19^2 2^(-255) q|<1/4.
 *   Also have |h-2^230 h9|<2^231 so |19 2^(-255)(h-2^230 h9)|<1/4.
 *
 *   Write y=2^(-1)-19^2 2^(-255)q-19 2^(-255)(h-2^230 h9).
 *   Then 0<y<1.
 *
 *   Write r=h-pq.
 *   Have 0<=r<=p-1=2^255-20.
 *   Thus 0<=r+19(2^-255)r<r+19(2^-255)2^255<=2^255-1.
 *
 *   Write x=r+19(2^-255)r+y.
 *   Then 0<x<2^255 so floor(2^(-255)x) = 0 so floor(q+2^(-255)x) = q.
 *
 *   Have q+2^(-255)x = 2^(-255)(h + 19 2^(-25) h9 + 2^(-1))
 *   so floor(2^(-255)(h + 19 2^(-25) h9 + 2^(-1))) = q. */
static void fe_tobytes(uint8_t* s, const fe h) {
  int32_t h0 = h[0];
  int32_t h1 = h[1];
  int32_t h2 = h[2];
  int32_t h3 = h[3];
  int32_t h4 = h[4];
  int32_t h5 = h[5];
  int32_t h6 = h[6];
  int32_t h7 = h[7];
  int32_t h8 = h[8];
  int32_t h9 = h[9];
  int32_t q;

  q = (19 * h9 + (((int32_t)1) << 24)) >> 25;
  q = (h0 + q) >> 26;
  q = (h1 + q) >> 25;
  q = (h2 + q) >> 26;
  q = (h3 + q) >> 25;
  q = (h4 + q) >> 26;
  q = (h5 + q) >> 25;
  q = (h6 + q) >> 26;
  q = (h7 + q) >> 25;
  q = (h8 + q) >> 26;
  q = (h9 + q) >> 25;

  /* Goal: Output h-(2^255-19)q, which is between 0 and 2^255-20. */
  h0 += 19 * q;
  /* Goal: Output h-2^255 q, which is between 0 and 2^255-20. */

  h1 += h0 >> 26;
  h0 &= kBottom26Bits;
  h2 += h1 >> 25;
  h1 &= kBottom25Bits;
  h3 += h2 >> 26;
  h2 &= kBottom26Bits;
  h4 += h3 >> 25;
  h3 &= kBottom25Bits;
  h5 += h4 >> 26;
  h4 &= kBottom26Bits;
  h6 += h5 >> 25;
  h5 &= kBottom25Bits;
  h7 += h6 >> 26;
  h6 &= kBottom26Bits;
  h8 += h7 >> 25;
  h7 &= kBottom25Bits;
  h9 += h8 >> 26;
  h8 &= kBottom26Bits;
  h9 &= kBottom25Bits;
  /* h10 = carry9 */

  /* Goal: Output h0+...+2^255 h10-2^255 q, which is between 0 and 2^255-20.
   * Have h0+...+2^230 h9 between 0 and 2^255-1;
   * evidently 2^255 h10-2^255 q = 0.
   * Goal: Output h0+...+2^230 h9.  */

  s[0] = (uint8_t)(h0 >> 0);
  s[1] = (uint8_t)(h0 >> 8);
  s[2] = (uint8_t)(h0 >> 16);
  s[3] = (uint8_t)((h0 >> 24) | ((uint32_t)(h1) << 2));
  s[4] = (uint8_t)(h1 >> 6);
  s[5] = (uint8_t)(h1 >> 14);
  s[6] = (uint8_t)((h1 >> 22) | ((uint32_t)(h2) << 3));
  s[7] = (uint8_t)(h2 >> 5);
  s[8] = (uint8_t)(h2 >> 13);
  s[9] = (uint8_t)((h2 >> 21) | ((uint32_t)(h3) << 5));
  s[10] = (uint8_t)(h3 >> 3);
  s[11] = (uint8_t)(h3 >> 11);
  s[12] = (uint8_t)((h3 >> 19) | ((uint32_t)(h4) << 6));
  s[13] = (uint8_t)(h4 >> 2);
  s[14] = (uint8_t)(h4 >> 10);
  s[15] = (uint8_t)(h4 >> 18);
  s[16] = (uint8_t)(h5 >> 0);
  s[17] = (uint8_t)(h5 >> 8);
  s[18] = (uint8_t)(h5 >> 16);
  s[19] = (uint8_t)((h5 >> 24) | ((uint32_t)(h6) << 1));
  s[20] = (uint8_t)(h6 >> 7);
  s[21] = (uint8_t)(h6 >> 15);
  s[22] = (uint8_t)((h6 >> 23) | ((uint32_t)(h7) << 3));
  s[23] = (uint8_t)(h7 >> 5);
  s[24] = (uint8_t)(h7 >> 13);
  s[25] = (uint8_t)((h7 >> 21) | ((uint32_t)(h8) << 4));
  s[26] = (uint8_t)(h8 >> 4);
  s[27] = (uint8_t)(h8 >> 12);
  s[28] = (uint8_t)((h8 >> 20) | ((uint32_t)(h9) << 6));
  s[29] = (uint8_t)(h9 >> 2);
  s[30] = (uint8_t)(h9 >> 10);
  s[31] = (uint8_t)(h9 >> 18);
}

/* h = f */
static void fe_copy(fe h, const fe f) {
  memmove(h, f, sizeof(int32_t) * 10);
}

/* h = 0 */
static void fe_0(fe h) {
  memset(h, 0, sizeof(int32_t) * 10);
}

/* h = 1 */
static void fe_1(fe h) {
  memset(h, 0, sizeof(int32_t) * 10);
  h[0] = 1;
}

/* h = f + g
 * Can overlap h with f or g.
 *
 * Preconditions:
 *    |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
 *    |g| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
 *
 * Postconditions:
 *    |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc. */
static void fe_add(fe h, const fe f, const fe g) {
  unsigned i;
  for (i = 0; i < 10; i++) {
    h[i] = f[i] + g[i];
  }
}

/* h = f - g
 * Can overlap h with f or g.
 *
 * Preconditions:
 *    |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
 *    |g| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
 *
 * Postconditions:
 *    |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc. */
static void fe_sub(fe h, const fe f, const fe g) {
  unsigned i;
  for (i = 0; i < 10; i++) {
    h[i] = f[i] - g[i];
  }
}

/* h = f * g
 * Can overlap h with f or g.
 *
 * Preconditions:
 *    |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
 *    |g| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
 *
 * Postconditions:
 *    |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
 *
 * Notes on implementation strategy:
 *
 * Using schoolbook multiplication.
 * Karatsuba would save a little in some cost models.
 *
 * Most multiplications by 2 and 19 are 32-bit precomputations;
 * cheaper than 64-bit postcomputations.
 *
 * There is one remaining multiplication by 19 in the carry chain;
 * one *19 precomputation can be merged into this,
 * but the resulting data flow is considerably less clean.
 *
 * There are 12 carries below.
 * 10 of them are 2-way parallelizable and vectorizable.
 * Can get away with 11 carries, but then data flow is much deeper.
 *
 * With tighter constraints on inputs can squeeze carries into int32. */
static void fe_mul(fe h, const fe f, const fe g) {
  int32_t f0 = f[0];
  int32_t f1 = f[1];
  int32_t f2 = f[2];
  int32_t f3 = f[3];
  int32_t f4 = f[4];
  int32_t f5 = f[5];
  int32_t f6 = f[6];
  int32_t f7 = f[7];
  int32_t f8 = f[8];
  int32_t f9 = f[9];
  int32_t g0 = g[0];
  int32_t g1 = g[1];
  int32_t g2 = g[2];
  int32_t g3 = g[3];
  int32_t g4 = g[4];
  int32_t g5 = g[5];
  int32_t g6 = g[6];
  int32_t g7 = g[7];
  int32_t g8 = g[8];
  int32_t g9 = g[9];
  int32_t g1_19 = 19 * g1; /* 1.959375*2^29 */
  int32_t g2_19 = 19 * g2; /* 1.959375*2^30; still ok */
  int32_t g3_19 = 19 * g3;
  int32_t g4_19 = 19 * g4;
  int32_t g5_19 = 19 * g5;
  int32_t g6_19 = 19 * g6;
  int32_t g7_19 = 19 * g7;
  int32_t g8_19 = 19 * g8;
  int32_t g9_19 = 19 * g9;
  int32_t f1_2 = 2 * f1;
  int32_t f3_2 = 2 * f3;
  int32_t f5_2 = 2 * f5;
  int32_t f7_2 = 2 * f7;
  int32_t f9_2 = 2 * f9;
  int64_t f0g0 = f0 * (int64_t)g0;
  int64_t f0g1 = f0 * (int64_t)g1;
  int64_t f0g2 = f0 * (int64_t)g2;
  int64_t f0g3 = f0 * (int64_t)g3;
  int64_t f0g4 = f0 * (int64_t)g4;
  int64_t f0g5 = f0 * (int64_t)g5;
  int64_t f0g6 = f0 * (int64_t)g6;
  int64_t f0g7 = f0 * (int64_t)g7;
  int64_t f0g8 = f0 * (int64_t)g8;
  int64_t f0g9 = f0 * (int64_t)g9;
  int64_t f1g0 = f1 * (int64_t)g0;
  int64_t f1g1_2 = f1_2 * (int64_t)g1;
  int64_t f1g2 = f1 * (int64_t)g2;
  int64_t f1g3_2 = f1_2 * (int64_t)g3;
  int64_t f1g4 = f1 * (int64_t)g4;
  int64_t f1g5_2 = f1_2 * (int64_t)g5;
  int64_t f1g6 = f1 * (int64_t)g6;
  int64_t f1g7_2 = f1_2 * (int64_t)g7;
  int64_t f1g8 = f1 * (int64_t)g8;
  int64_t f1g9_38 = f1_2 * (int64_t)g9_19;
  int64_t f2g0 = f2 * (int64_t)g0;
  int64_t f2g1 = f2 * (int64_t)g1;
  int64_t f2g2 = f2 * (int64_t)g2;
  int64_t f2g3 = f2 * (int64_t)g3;
  int64_t f2g4 = f2 * (int64_t)g4;
  int64_t f2g5 = f2 * (int64_t)g5;
  int64_t f2g6 = f2 * (int64_t)g6;
  int64_t f2g7 = f2 * (int64_t)g7;
  int64_t f2g8_19 = f2 * (int64_t)g8_19;
  int64_t f2g9_19 = f2 * (int64_t)g9_19;
  int64_t f3g0 = f3 * (int64_t)g0;
  int64_t f3g1_2 = f3_2 * (int64_t)g1;
  int64_t f3g2 = f3 * (int64_t)g2;
  int64_t f3g3_2 = f3_2 * (int64_t)g3;
  int64_t f3g4 = f3 * (int64_t)g4;
  int64_t f3g5_2 = f3_2 * (int64_t)g5;
  int64_t f3g6 = f3 * (int64_t)g6;
  int64_t f3g7_38 = f3_2 * (int64_t)g7_19;
  int64_t f3g8_19 = f3 * (int64_t)g8_19;
  int64_t f3g9_38 = f3_2 * (int64_t)g9_19;
  int64_t f4g0 = f4 * (int64_t)g0;
  int64_t f4g1 = f4 * (int64_t)g1;
  int64_t f4g2 = f4 * (int64_t)g2;
  int64_t f4g3 = f4 * (int64_t)g3;
  int64_t f4g4 = f4 * (int64_t)g4;
  int64_t f4g5 = f4 * (int64_t)g5;
  int64_t f4g6_19 = f4 * (int64_t)g6_19;
  int64_t f4g7_19 = f4 * (int64_t)g7_19;
  int64_t f4g8_19 = f4 * (int64_t)g8_19;
  int64_t f4g9_19 = f4 * (int64_t)g9_19;
  int64_t f5g0 = f5 * (int64_t)g0;
  int64_t f5g1_2 = f5_2 * (int64_t)g1;
  int64_t f5g2 = f5 * (int64_t)g2;
  int64_t f5g3_2 = f5_2 * (int64_t)g3;
  int64_t f5g4 = f5 * (int64_t)g4;
  int64_t f5g5_38 = f5_2 * (int64_t)g5_19;
  int64_t f5g6_19 = f5 * (int64_t)g6_19;
  int64_t f5g7_38 = f5_2 * (int64_t)g7_19;
  int64_t f5g8_19 = f5 * (int64_t)g8_19;
  int64_t f5g9_38 = f5_2 * (int64_t)g9_19;
  int64_t f6g0 = f6 * (int64_t)g0;
  int64_t f6g1 = f6 * (int64_t)g1;
  int64_t f6g2 = f6 * (int64_t)g2;
  int64_t f6g3 = f6 * (int64_t)g3;
  int64_t f6g4_19 = f6 * (int64_t)g4_19;
  int64_t f6g5_19 = f6 * (int64_t)g5_19;
  int64_t f6g6_19 = f6 * (int64_t)g6_19;
  int64_t f6g7_19 = f6 * (int64_t)g7_19;
  int64_t f6g8_19 = f6 * (int64_t)g8_19;
  int64_t f6g9_19 = f6 * (int64_t)g9_19;
  int64_t f7g0 = f7 * (int64_t)g0;
  int64_t f7g1_2 = f7_2 * (int64_t)g1;
  int64_t f7g2 = f7 * (int64_t)g2;
  int64_t f7g3_38 = f7_2 * (int64_t)g3_19;
  int64_t f7g4_19 = f7 * (int64_t)g4_19;
  int64_t f7g5_38 = f7_2 * (int64_t)g5_19;
  int64_t f7g6_19 = f7 * (int64_t)g6_19;
  int64_t f7g7_38 = f7_2 * (int64_t)g7_19;
  int64_t f7g8_19 = f7 * (int64_t)g8_19;
  int64_t f7g9_38 = f7_2 * (int64_t)g9_19;
  int64_t f8g0 = f8 * (int64_t)g0;
  int64_t f8g1 = f8 * (int64_t)g1;
  int64_t f8g2_19 = f8 * (int64_t)g2_19;
  int64_t f8g3_19 = f8 * (int64_t)g3_19;
  int64_t f8g4_19 = f8 * (int64_t)g4_19;
  int64_t f8g5_19 = f8 * (int64_t)g5_19;
  int64_t f8g6_19 = f8 * (int64_t)g6_19;
  int64_t f8g7_19 = f8 * (int64_t)g7_19;
  int64_t f8g8_19 = f8 * (int64_t)g8_19;
  int64_t f8g9_19 = f8 * (int64_t)g9_19;
  int64_t f9g0 = f9 * (int64_t)g0;
  int64_t f9g1_38 = f9_2 * (int64_t)g1_19;
  int64_t f9g2_19 = f9 * (int64_t)g2_19;
  int64_t f9g3_38 = f9_2 * (int64_t)g3_19;
  int64_t f9g4_19 = f9 * (int64_t)g4_19;
  int64_t f9g5_38 = f9_2 * (int64_t)g5_19;
  int64_t f9g6_19 = f9 * (int64_t)g6_19;
  int64_t f9g7_38 = f9_2 * (int64_t)g7_19;
  int64_t f9g8_19 = f9 * (int64_t)g8_19;
  int64_t f9g9_38 = f9_2 * (int64_t)g9_19;
  int64_t h0 = f0g0 + f1g9_38 + f2g8_19 + f3g7_38 + f4g6_19 + f5g5_38 + f6g4_19 + f7g3_38 + f8g2_19 + f9g1_38;
  int64_t h1 = f0g1 + f1g0 + f2g9_19 + f3g8_19 + f4g7_19 + f5g6_19 + f6g5_19 + f7g4_19 + f8g3_19 + f9g2_19;
  int64_t h2 = f0g2 + f1g1_2 + f2g0 + f3g9_38 + f4g8_19 + f5g7_38 + f6g6_19 + f7g5_38 + f8g4_19 + f9g3_38;
  int64_t h3 = f0g3 + f1g2 + f2g1 + f3g0 + f4g9_19 + f5g8_19 + f6g7_19 + f7g6_19 + f8g5_19 + f9g4_19;
  int64_t h4 = f0g4 + f1g3_2 + f2g2 + f3g1_2 + f4g0 + f5g9_38 + f6g8_19 + f7g7_38 + f8g6_19 + f9g5_38;
  int64_t h5 = f0g5 + f1g4 + f2g3 + f3g2 + f4g1 + f5g0 + f6g9_19 + f7g8_19 + f8g7_19 + f9g6_19;
  int64_t h6 = f0g6 + f1g5_2 + f2g4 + f3g3_2 + f4g2 + f5g1_2 + f6g0 + f7g9_38 + f8g8_19 + f9g7_38;
  int64_t h7 = f0g7 + f1g6 + f2g5 + f3g4 + f4g3 + f5g2 + f6g1 + f7g0 + f8g9_19 + f9g8_19;
  int64_t h8 = f0g8 + f1g7_2 + f2g6 + f3g5_2 + f4g4 + f5g3_2 + f6g2 + f7g1_2 + f8g0 + f9g9_38;
  int64_t h9 = f0g9 + f1g8 + f2g7 + f3g6 + f4g5 + f5g4 + f6g3 + f7g2 + f8g1 + f9g0;
  int64_t carry0;
  int64_t carry1;
  int64_t carry2;
  int64_t carry3;
  int64_t carry4;
  int64_t carry5;
  int64_t carry6;
  int64_t carry7;
  int64_t carry8;
  int64_t carry9;

  /* |h0| <= (1.65*1.65*2^52*(1+19+19+19+19)+1.65*1.65*2^50*(38+38+38+38+38))
   *   i.e. |h0| <= 1.4*2^60; narrower ranges for h2, h4, h6, h8
   * |h1| <= (1.65*1.65*2^51*(1+1+19+19+19+19+19+19+19+19))
   *   i.e. |h1| <= 1.7*2^59; narrower ranges for h3, h5, h7, h9 */

  carry0 = h0 + (1 << 25);
  h1 += carry0 >> 26;
  h0 -= carry0 & kTop38Bits;
  carry4 = h4 + (1 << 25);
  h5 += carry4 >> 26;
  h4 -= carry4 & kTop38Bits;
  /* |h0| <= 2^25 */
  /* |h4| <= 2^25 */
  /* |h1| <= 1.71*2^59 */
  /* |h5| <= 1.71*2^59 */

  carry1 = h1 + (1 << 24);
  h2 += carry1 >> 25;
  h1 -= carry1 & kTop39Bits;
  carry5 = h5 + (1 << 24);
  h6 += carry5 >> 25;
  h5 -= carry5 & kTop39Bits;
  /* |h1| <= 2^24; from now on fits into int32 */
  /* |h5| <= 2^24; from now on fits into int32 */
  /* |h2| <= 1.41*2^60 */
  /* |h6| <= 1.41*2^60 */

  carry2 = h2 + (1 << 25);
  h3 += carry2 >> 26;
  h2 -= carry2 & kTop38Bits;
  carry6 = h6 + (1 << 25);
  h7 += carry6 >> 26;
  h6 -= carry6 & kTop38Bits;
  /* |h2| <= 2^25; from now on fits into int32 unchanged */
  /* |h6| <= 2^25; from now on fits into int32 unchanged */
  /* |h3| <= 1.71*2^59 */
  /* |h7| <= 1.71*2^59 */

  carry3 = h3 + (1 << 24);
  h4 += carry3 >> 25;
  h3 -= carry3 & kTop39Bits;
  carry7 = h7 + (1 << 24);
  h8 += carry7 >> 25;
  h7 -= carry7 & kTop39Bits;
  /* |h3| <= 2^24; from now on fits into int32 unchanged */
  /* |h7| <= 2^24; from now on fits into int32 unchanged */
  /* |h4| <= 1.72*2^34 */
  /* |h8| <= 1.41*2^60 */

  carry4 = h4 + (1 << 25);
  h5 += carry4 >> 26;
  h4 -= carry4 & kTop38Bits;
  carry8 = h8 + (1 << 25);
  h9 += carry8 >> 26;
  h8 -= carry8 & kTop38Bits;
  /* |h4| <= 2^25; from now on fits into int32 unchanged */
  /* |h8| <= 2^25; from now on fits into int32 unchanged */
  /* |h5| <= 1.01*2^24 */
  /* |h9| <= 1.71*2^59 */

  carry9 = h9 + (1 << 24);
  h0 += (carry9 >> 25) * 19;
  h9 -= carry9 & kTop39Bits;
  /* |h9| <= 2^24; from now on fits into int32 unchanged */
  /* |h0| <= 1.1*2^39 */

  carry0 = h0 + (1 << 25);
  h1 += carry0 >> 26;
  h0 -= carry0 & kTop38Bits;
  /* |h0| <= 2^25; from now on fits into int32 unchanged */
  /* |h1| <= 1.01*2^24 */

  h[0] = (int32_t)h0;
  h[1] = (int32_t)h1;
  h[2] = (int32_t)h2;
  h[3] = (int32_t)h3;
  h[4] = (int32_t)h4;
  h[5] = (int32_t)h5;
  h[6] = (int32_t)h6;
  h[7] = (int32_t)h7;
  h[8] = (int32_t)h8;
  h[9] = (int32_t)h9;
}

/* h = f * f
 * Can overlap h with f.
 *
 * Preconditions:
 *    |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
 *
 * Postconditions:
 *    |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
 *
 * See fe_mul.c for discussion of implementation strategy. */
static void fe_sq(fe h, const fe f) {
  int32_t f0 = f[0];
  int32_t f1 = f[1];
  int32_t f2 = f[2];
  int32_t f3 = f[3];
  int32_t f4 = f[4];
  int32_t f5 = f[5];
  int32_t f6 = f[6];
  int32_t f7 = f[7];
  int32_t f8 = f[8];
  int32_t f9 = f[9];
  int32_t f0_2 = 2 * f0;
  int32_t f1_2 = 2 * f1;
  int32_t f2_2 = 2 * f2;
  int32_t f3_2 = 2 * f3;
  int32_t f4_2 = 2 * f4;
  int32_t f5_2 = 2 * f5;
  int32_t f6_2 = 2 * f6;
  int32_t f7_2 = 2 * f7;
  int32_t f5_38 = 38 * f5; /* 1.959375*2^30 */
  int32_t f6_19 = 19 * f6; /* 1.959375*2^30 */
  int32_t f7_38 = 38 * f7; /* 1.959375*2^30 */
  int32_t f8_19 = 19 * f8; /* 1.959375*2^30 */
  int32_t f9_38 = 38 * f9; /* 1.959375*2^30 */
  int64_t f0f0 = f0 * (int64_t)f0;
  int64_t f0f1_2 = f0_2 * (int64_t)f1;
  int64_t f0f2_2 = f0_2 * (int64_t)f2;
  int64_t f0f3_2 = f0_2 * (int64_t)f3;
  int64_t f0f4_2 = f0_2 * (int64_t)f4;
  int64_t f0f5_2 = f0_2 * (int64_t)f5;
  int64_t f0f6_2 = f0_2 * (int64_t)f6;
  int64_t f0f7_2 = f0_2 * (int64_t)f7;
  int64_t f0f8_2 = f0_2 * (int64_t)f8;
  int64_t f0f9_2 = f0_2 * (int64_t)f9;
  int64_t f1f1_2 = f1_2 * (int64_t)f1;
  int64_t f1f2_2 = f1_2 * (int64_t)f2;
  int64_t f1f3_4 = f1_2 * (int64_t)f3_2;
  int64_t f1f4_2 = f1_2 * (int64_t)f4;
  int64_t f1f5_4 = f1_2 * (int64_t)f5_2;
  int64_t f1f6_2 = f1_2 * (int64_t)f6;
  int64_t f1f7_4 = f1_2 * (int64_t)f7_2;
  int64_t f1f8_2 = f1_2 * (int64_t)f8;
  int64_t f1f9_76 = f1_2 * (int64_t)f9_38;
  int64_t f2f2 = f2 * (int64_t)f2;
  int64_t f2f3_2 = f2_2 * (int64_t)f3;
  int64_t f2f4_2 = f2_2 * (int64_t)f4;
  int64_t f2f5_2 = f2_2 * (int64_t)f5;
  int64_t f2f6_2 = f2_2 * (int64_t)f6;
  int64_t f2f7_2 = f2_2 * (int64_t)f7;
  int64_t f2f8_38 = f2_2 * (int64_t)f8_19;
  int64_t f2f9_38 = f2 * (int64_t)f9_38;
  int64_t f3f3_2 = f3_2 * (int64_t)f3;
  int64_t f3f4_2 = f3_2 * (int64_t)f4;
  int64_t f3f5_4 = f3_2 * (int64_t)f5_2;
  int64_t f3f6_2 = f3_2 * (int64_t)f6;
  int64_t f3f7_76 = f3_2 * (int64_t)f7_38;
  int64_t f3f8_38 = f3_2 * (int64_t)f8_19;
  int64_t f3f9_76 = f3_2 * (int64_t)f9_38;
  int64_t f4f4 = f4 * (int64_t)f4;
  int64_t f4f5_2 = f4_2 * (int64_t)f5;
  int64_t f4f6_38 = f4_2 * (int64_t)f6_19;
  int64_t f4f7_38 = f4 * (int64_t)f7_38;
  int64_t f4f8_38 = f4_2 * (int64_t)f8_19;
  int64_t f4f9_38 = f4 * (int64_t)f9_38;
  int64_t f5f5_38 = f5 * (int64_t)f5_38;
  int64_t f5f6_38 = f5_2 * (int64_t)f6_19;
  int64_t f5f7_76 = f5_2 * (int64_t)f7_38;
  int64_t f5f8_38 = f5_2 * (int64_t)f8_19;
  int64_t f5f9_76 = f5_2 * (int64_t)f9_38;
  int64_t f6f6_19 = f6 * (int64_t)f6_19;
  int64_t f6f7_38 = f6 * (int64_t)f7_38;
  int64_t f6f8_38 = f6_2 * (int64_t)f8_19;
  int64_t f6f9_38 = f6 * (int64_t)f9_38;
  int64_t f7f7_38 = f7 * (int64_t)f7_38;
  int64_t f7f8_38 = f7_2 * (int64_t)f8_19;
  int64_t f7f9_76 = f7_2 * (int64_t)f9_38;
  int64_t f8f8_19 = f8 * (int64_t)f8_19;
  int64_t f8f9_38 = f8 * (int64_t)f9_38;
  int64_t f9f9_38 = f9 * (int64_t)f9_38;
  int64_t h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
  int64_t h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
  int64_t h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
  int64_t h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
  int64_t h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
  int64_t h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
  int64_t h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
  int64_t h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
  int64_t h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
  int64_t h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;
  int64_t carry0;
  int64_t carry1;
  int64_t carry2;
  int64_t carry3;
  int64_t carry4;
  int64_t carry5;
  int64_t carry6;
  int64_t carry7;
  int64_t carry8;
  int64_t carry9;

  carry0 = h0 + (1 << 25);
  h1 += carry0 >> 26;
  h0 -= carry0 & kTop38Bits;
  carry4 = h4 + (1 << 25);
  h5 += carry4 >> 26;
  h4 -= carry4 & kTop38Bits;

  carry1 = h1 + (1 << 24);
  h2 += carry1 >> 25;
  h1 -= carry1 & kTop39Bits;
  carry5 = h5 + (1 << 24);
  h6 += carry5 >> 25;
  h5 -= carry5 & kTop39Bits;

  carry2 = h2 + (1 << 25);
  h3 += carry2 >> 26;
  h2 -= carry2 & kTop38Bits;
  carry6 = h6 + (1 << 25);
  h7 += carry6 >> 26;
  h6 -= carry6 & kTop38Bits;

  carry3 = h3 + (1 << 24);
  h4 += carry3 >> 25;
  h3 -= carry3 & kTop39Bits;
  carry7 = h7 + (1 << 24);
  h8 += carry7 >> 25;
  h7 -= carry7 & kTop39Bits;

  carry4 = h4 + (1 << 25);
  h5 += carry4 >> 26;
  h4 -= carry4 & kTop38Bits;
  carry8 = h8 + (1 << 25);
  h9 += carry8 >> 26;
  h8 -= carry8 & kTop38Bits;

  carry9 = h9 + (1 << 24);
  h0 += (carry9 >> 25) * 19;
  h9 -= carry9 & kTop39Bits;

  carry0 = h0 + (1 << 25);
  h1 += carry0 >> 26;
  h0 -= carry0 & kTop38Bits;

  h[0] = (int32_t)h0;
  h[1] = (int32_t)h1;
  h[2] = (int32_t)h2;
  h[3] = (int32_t)h3;
  h[4] = (int32_t)h4;
  h[5] = (int32_t)h5;
  h[6] = (int32_t)h6;
  h[7] = (int32_t)h7;
  h[8] = (int32_t)h8;
  h[9] = (int32_t)h9;
}

static void fe_invert(fe out, const fe z) {
  fe t0;
  fe t1;
  fe t2;
  fe t3;
  int i;

  /*
   * Compute z ** -1 = z ** (2 ** 255 - 19 - 2) with the exponent as
   * 2 ** 255 - 21 = (2 ** 5) * (2 ** 250 - 1) + 11.
   */

  /* t0 = z ** 2 */
  fe_sq(t0, z);

  /* t1 = t0 ** (2 ** 2) = z ** 8 */
  fe_sq(t1, t0);
  fe_sq(t1, t1);

  /* t1 = z * t1 = z ** 9 */
  fe_mul(t1, z, t1);
  /* t0 = t0 * t1 = z ** 11 -- stash t0 away for the end. */
  fe_mul(t0, t0, t1);

  /* t2 = t0 ** 2 = z ** 22 */
  fe_sq(t2, t0);

  /* t1 = t1 * t2 = z ** (2 ** 5 - 1) */
  fe_mul(t1, t1, t2);

  /* t2 = t1 ** (2 ** 5) = z ** ((2 ** 5) * (2 ** 5 - 1)) */
  fe_sq(t2, t1);
  for (i = 1; i < 5; ++i) {
    fe_sq(t2, t2);
  }

  /* t1 = t1 * t2 = z ** ((2 ** 5 + 1) * (2 ** 5 - 1)) = z ** (2 ** 10 - 1) */
  fe_mul(t1, t2, t1);

  /* Continuing similarly... */

  /* t2 = z ** (2 ** 20 - 1) */
  fe_sq(t2, t1);
  for (i = 1; i < 10; ++i) {
    fe_sq(t2, t2);
  }
  fe_mul(t2, t2, t1);

  /* t2 = z ** (2 ** 40 - 1) */
  fe_sq(t3, t2);
  for (i = 1; i < 20; ++i) {
    fe_sq(t3, t3);
  }
  fe_mul(t2, t3, t2);

  /* t2 = z ** (2 ** 10) * (2 ** 40 - 1) */
  for (i = 0; i < 10; ++i) {
    fe_sq(t2, t2);
  }
  /* t1 = z ** (2 ** 50 - 1) */
  fe_mul(t1, t2, t1);

  /* t2 = z ** (2 ** 100 - 1) */
  fe_sq(t2, t1);
  for (i = 1; i < 50; ++i) {
    fe_sq(t2, t2);
  }
  fe_mul(t2, t2, t1);

  /* t2 = z ** (2 ** 200 - 1) */
  fe_sq(t3, t2);
  for (i = 1; i < 100; ++i) {
    fe_sq(t3, t3);
  }
  fe_mul(t2, t3, t2);

  /* t2 = z ** ((2 ** 50) * (2 ** 200 - 1) */
  fe_sq(t2, t2);
  for (i = 1; i < 50; ++i) {
    fe_sq(t2, t2);
  }

  /* t1 = z ** (2 ** 250 - 1) */
  fe_mul(t1, t2, t1);

  /* t1 = z ** ((2 ** 5) * (2 ** 250 - 1)) */
  fe_sq(t1, t1);
  for (i = 1; i < 5; ++i) {
    fe_sq(t1, t1);
  }

  /* Recall t0 = z ** 11; out = z ** (2 ** 255 - 21) */
  fe_mul(out, t1, t0);
}

/* h = -f
 *
 * Preconditions:
 *    |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
 *
 * Postconditions:
 *    |h| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc. */
static void fe_neg(fe h, const fe f) {
  unsigned i;
  for (i = 0; i < 10; i++) {
    h[i] = -f[i];
  }
}

/* return 0 if f == 0
 * return 1 if f != 0
 *
 * Preconditions:
 *    |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc. */
static int fe_isnonzero(const fe f) {
  int r = 0;
  uint8_t s[32];

  fe_tobytes(s, f);

  for (int i = 0; i < 32; ++i) {
    r |= s[i];
  }
  return r;
}

/* return 1 if f is in {1,3,5,...,q-2}
 * return 0 if f is in {0,2,4,...,q-1}
 *
 * Preconditions:
 *    |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc. */
static int fe_isnegative(const fe f) {
  uint8_t s[32];
  fe_tobytes(s, f);
  return s[0] & 1;
}

/* h = 2 * f * f
 * Can overlap h with f.
 *
 * Preconditions:
 *    |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
 *
 * Postconditions:
 *    |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
 *
 * See fe_mul.c for discussion of implementation strategy. */
static void fe_sq2(fe h, const fe f) {
  int32_t f0 = f[0];
  int32_t f1 = f[1];
  int32_t f2 = f[2];
  int32_t f3 = f[3];
  int32_t f4 = f[4];
  int32_t f5 = f[5];
  int32_t f6 = f[6];
  int32_t f7 = f[7];
  int32_t f8 = f[8];
  int32_t f9 = f[9];
  int32_t f0_2 = 2 * f0;
  int32_t f1_2 = 2 * f1;
  int32_t f2_2 = 2 * f2;
  int32_t f3_2 = 2 * f3;
  int32_t f4_2 = 2 * f4;
  int32_t f5_2 = 2 * f5;
  int32_t f6_2 = 2 * f6;
  int32_t f7_2 = 2 * f7;
  int32_t f5_38 = 38 * f5; /* 1.959375*2^30 */
  int32_t f6_19 = 19 * f6; /* 1.959375*2^30 */
  int32_t f7_38 = 38 * f7; /* 1.959375*2^30 */
  int32_t f8_19 = 19 * f8; /* 1.959375*2^30 */
  int32_t f9_38 = 38 * f9; /* 1.959375*2^30 */
  int64_t f0f0 = f0 * (int64_t)f0;
  int64_t f0f1_2 = f0_2 * (int64_t)f1;
  int64_t f0f2_2 = f0_2 * (int64_t)f2;
  int64_t f0f3_2 = f0_2 * (int64_t)f3;
  int64_t f0f4_2 = f0_2 * (int64_t)f4;
  int64_t f0f5_2 = f0_2 * (int64_t)f5;
  int64_t f0f6_2 = f0_2 * (int64_t)f6;
  int64_t f0f7_2 = f0_2 * (int64_t)f7;
  int64_t f0f8_2 = f0_2 * (int64_t)f8;
  int64_t f0f9_2 = f0_2 * (int64_t)f9;
  int64_t f1f1_2 = f1_2 * (int64_t)f1;
  int64_t f1f2_2 = f1_2 * (int64_t)f2;
  int64_t f1f3_4 = f1_2 * (int64_t)f3_2;
  int64_t f1f4_2 = f1_2 * (int64_t)f4;
  int64_t f1f5_4 = f1_2 * (int64_t)f5_2;
  int64_t f1f6_2 = f1_2 * (int64_t)f6;
  int64_t f1f7_4 = f1_2 * (int64_t)f7_2;
  int64_t f1f8_2 = f1_2 * (int64_t)f8;
  int64_t f1f9_76 = f1_2 * (int64_t)f9_38;
  int64_t f2f2 = f2 * (int64_t)f2;
  int64_t f2f3_2 = f2_2 * (int64_t)f3;
  int64_t f2f4_2 = f2_2 * (int64_t)f4;
  int64_t f2f5_2 = f2_2 * (int64_t)f5;
  int64_t f2f6_2 = f2_2 * (int64_t)f6;
  int64_t f2f7_2 = f2_2 * (int64_t)f7;
  int64_t f2f8_38 = f2_2 * (int64_t)f8_19;
  int64_t f2f9_38 = f2 * (int64_t)f9_38;
  int64_t f3f3_2 = f3_2 * (int64_t)f3;
  int64_t f3f4_2 = f3_2 * (int64_t)f4;
  int64_t f3f5_4 = f3_2 * (int64_t)f5_2;
  int64_t f3f6_2 = f3_2 * (int64_t)f6;
  int64_t f3f7_76 = f3_2 * (int64_t)f7_38;
  int64_t f3f8_38 = f3_2 * (int64_t)f8_19;
  int64_t f3f9_76 = f3_2 * (int64_t)f9_38;
  int64_t f4f4 = f4 * (int64_t)f4;
  int64_t f4f5_2 = f4_2 * (int64_t)f5;
  int64_t f4f6_38 = f4_2 * (int64_t)f6_19;
  int64_t f4f7_38 = f4 * (int64_t)f7_38;
  int64_t f4f8_38 = f4_2 * (int64_t)f8_19;
  int64_t f4f9_38 = f4 * (int64_t)f9_38;
  int64_t f5f5_38 = f5 * (int64_t)f5_38;
  int64_t f5f6_38 = f5_2 * (int64_t)f6_19;
  int64_t f5f7_76 = f5_2 * (int64_t)f7_38;
  int64_t f5f8_38 = f5_2 * (int64_t)f8_19;
  int64_t f5f9_76 = f5_2 * (int64_t)f9_38;
  int64_t f6f6_19 = f6 * (int64_t)f6_19;
  int64_t f6f7_38 = f6 * (int64_t)f7_38;
  int64_t f6f8_38 = f6_2 * (int64_t)f8_19;
  int64_t f6f9_38 = f6 * (int64_t)f9_38;
  int64_t f7f7_38 = f7 * (int64_t)f7_38;
  int64_t f7f8_38 = f7_2 * (int64_t)f8_19;
  int64_t f7f9_76 = f7_2 * (int64_t)f9_38;
  int64_t f8f8_19 = f8 * (int64_t)f8_19;
  int64_t f8f9_38 = f8 * (int64_t)f9_38;
  int64_t f9f9_38 = f9 * (int64_t)f9_38;
  int64_t h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
  int64_t h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
  int64_t h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
  int64_t h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
  int64_t h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
  int64_t h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
  int64_t h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
  int64_t h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
  int64_t h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
  int64_t h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;
  int64_t carry0;
  int64_t carry1;
  int64_t carry2;
  int64_t carry3;
  int64_t carry4;
  int64_t carry5;
  int64_t carry6;
  int64_t carry7;
  int64_t carry8;
  int64_t carry9;

  h0 += h0;
  h1 += h1;
  h2 += h2;
  h3 += h3;
  h4 += h4;
  h5 += h5;
  h6 += h6;
  h7 += h7;
  h8 += h8;
  h9 += h9;

  carry0 = h0 + (1 << 25);
  h1 += carry0 >> 26;
  h0 -= carry0 & kTop38Bits;
  carry4 = h4 + (1 << 25);
  h5 += carry4 >> 26;
  h4 -= carry4 & kTop38Bits;

  carry1 = h1 + (1 << 24);
  h2 += carry1 >> 25;
  h1 -= carry1 & kTop39Bits;
  carry5 = h5 + (1 << 24);
  h6 += carry5 >> 25;
  h5 -= carry5 & kTop39Bits;

  carry2 = h2 + (1 << 25);
  h3 += carry2 >> 26;
  h2 -= carry2 & kTop38Bits;
  carry6 = h6 + (1 << 25);
  h7 += carry6 >> 26;
  h6 -= carry6 & kTop38Bits;

  carry3 = h3 + (1 << 24);
  h4 += carry3 >> 25;
  h3 -= carry3 & kTop39Bits;
  carry7 = h7 + (1 << 24);
  h8 += carry7 >> 25;
  h7 -= carry7 & kTop39Bits;

  carry4 = h4 + (1 << 25);
  h5 += carry4 >> 26;
  h4 -= carry4 & kTop38Bits;
  carry8 = h8 + (1 << 25);
  h9 += carry8 >> 26;
  h8 -= carry8 & kTop38Bits;

  carry9 = h9 + (1 << 24);
  h0 += (carry9 >> 25) * 19;
  h9 -= carry9 & kTop39Bits;

  carry0 = h0 + (1 << 25);
  h1 += carry0 >> 26;
  h0 -= carry0 & kTop38Bits;

  h[0] = (int32_t)h0;
  h[1] = (int32_t)h1;
  h[2] = (int32_t)h2;
  h[3] = (int32_t)h3;
  h[4] = (int32_t)h4;
  h[5] = (int32_t)h5;
  h[6] = (int32_t)h6;
  h[7] = (int32_t)h7;
  h[8] = (int32_t)h8;
  h[9] = (int32_t)h9;
}

static void fe_pow22523(fe out, const fe z) {
  fe t0;
  fe t1;
  fe t2;
  int i;

  fe_sq(t0, z);
  fe_sq(t1, t0);
  for (i = 1; i < 2; ++i) {
    fe_sq(t1, t1);
  }
  fe_mul(t1, z, t1);
  fe_mul(t0, t0, t1);
  fe_sq(t0, t0);
  fe_mul(t0, t1, t0);
  fe_sq(t1, t0);
  for (i = 1; i < 5; ++i) {
    fe_sq(t1, t1);
  }
  fe_mul(t0, t1, t0);
  fe_sq(t1, t0);
  for (i = 1; i < 10; ++i) {
    fe_sq(t1, t1);
  }
  fe_mul(t1, t1, t0);
  fe_sq(t2, t1);
  for (i = 1; i < 20; ++i) {
    fe_sq(t2, t2);
  }
  fe_mul(t1, t2, t1);
  fe_sq(t1, t1);
  for (i = 1; i < 10; ++i) {
    fe_sq(t1, t1);
  }
  fe_mul(t0, t1, t0);
  fe_sq(t1, t0);
  for (i = 1; i < 50; ++i) {
    fe_sq(t1, t1);
  }
  fe_mul(t1, t1, t0);
  fe_sq(t2, t1);
  for (i = 1; i < 100; ++i) {
    fe_sq(t2, t2);
  }
  fe_mul(t1, t2, t1);
  fe_sq(t1, t1);
  for (i = 1; i < 50; ++i) {
    fe_sq(t1, t1);
  }
  fe_mul(t0, t1, t0);
  fe_sq(t0, t0);
  for (i = 1; i < 2; ++i) {
    fe_sq(t0, t0);
  }
  fe_mul(out, t0, z);
}

/* Replace (f,g) with (g,f) if b == 1;
 * replace (f,g) with (f,g) if b == 0.
 *
 * Preconditions: b in {0,1}. */
static void fe_cswap(fe f, fe g, unsigned int b) {
  size_t i;
  b = 0 - b;
  for (i = 0; i < 10; i++) {
    int32_t x = f[i] ^ g[i];
    x &= b;
    f[i] ^= x;
    g[i] ^= x;
  }
}

/* Replace f with g if b == 1;
 * leave f unchanged if b == 0.
 *
 * Preconditions: b in {0,1}.
 *
 * 与 fe_cswap 同一写法(全按位运算, 无秘密相关分支/访存), 供常数时间标量乘做点位条件搬运。 */
static void fe_cmov(fe f, const fe g, unsigned int b) {
  size_t i;
  b = 0 - b;
  for (i = 0; i < 10; i++) {
    f[i] ^= b & (f[i] ^ g[i]);
  }
}

/* h = f * 121666
 * Can overlap h with f.
 *
 * Preconditions:
 *    |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
 *
 * Postconditions:
 *    |h| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc. */
static void fe_mul121666(fe h, fe f) {
  int32_t f0 = f[0];
  int32_t f1 = f[1];
  int32_t f2 = f[2];
  int32_t f3 = f[3];
  int32_t f4 = f[4];
  int32_t f5 = f[5];
  int32_t f6 = f[6];
  int32_t f7 = f[7];
  int32_t f8 = f[8];
  int32_t f9 = f[9];
  int64_t h0 = f0 * (int64_t)121666;
  int64_t h1 = f1 * (int64_t)121666;
  int64_t h2 = f2 * (int64_t)121666;
  int64_t h3 = f3 * (int64_t)121666;
  int64_t h4 = f4 * (int64_t)121666;
  int64_t h5 = f5 * (int64_t)121666;
  int64_t h6 = f6 * (int64_t)121666;
  int64_t h7 = f7 * (int64_t)121666;
  int64_t h8 = f8 * (int64_t)121666;
  int64_t h9 = f9 * (int64_t)121666;
  int64_t carry0;
  int64_t carry1;
  int64_t carry2;
  int64_t carry3;
  int64_t carry4;
  int64_t carry5;
  int64_t carry6;
  int64_t carry7;
  int64_t carry8;
  int64_t carry9;

  carry9 = h9 + (1 << 24);
  h0 += (carry9 >> 25) * 19;
  h9 -= carry9 & kTop39Bits;
  carry1 = h1 + (1 << 24);
  h2 += carry1 >> 25;
  h1 -= carry1 & kTop39Bits;
  carry3 = h3 + (1 << 24);
  h4 += carry3 >> 25;
  h3 -= carry3 & kTop39Bits;
  carry5 = h5 + (1 << 24);
  h6 += carry5 >> 25;
  h5 -= carry5 & kTop39Bits;
  carry7 = h7 + (1 << 24);
  h8 += carry7 >> 25;
  h7 -= carry7 & kTop39Bits;

  carry0 = h0 + (1 << 25);
  h1 += carry0 >> 26;
  h0 -= carry0 & kTop38Bits;
  carry2 = h2 + (1 << 25);
  h3 += carry2 >> 26;
  h2 -= carry2 & kTop38Bits;
  carry4 = h4 + (1 << 25);
  h5 += carry4 >> 26;
  h4 -= carry4 & kTop38Bits;
  carry6 = h6 + (1 << 25);
  h7 += carry6 >> 26;
  h6 -= carry6 & kTop38Bits;
  carry8 = h8 + (1 << 25);
  h9 += carry8 >> 26;
  h8 -= carry8 & kTop38Bits;

  h[0] = (int32_t)h0;
  h[1] = (int32_t)h1;
  h[2] = (int32_t)h2;
  h[3] = (int32_t)h3;
  h[4] = (int32_t)h4;
  h[5] = (int32_t)h5;
  h[6] = (int32_t)h6;
  h[7] = (int32_t)h7;
  h[8] = (int32_t)h8;
  h[9] = (int32_t)h9;
}

/* ge_p2 (projective): (X:Y:Z) satisfying x=X/Z, y=Y/Z */
struct ge_p2 {
  fe X;
  fe Y;
  fe Z;
};

/* ge_p3 (extended): (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT */
struct ge_p3 : public ge_p2 {
  fe T;
};

/* ge_p1p1 (completed): ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T */
struct ge_p1p1 {
  fe X;
  fe Y;
  fe Z;
  fe T;
};

struct ge_cached {
  fe YplusX;
  fe YminusX;
  fe Z;
  fe T2d;
};

static void ge_tobytes(uint8_t* s, const ge_p2* h) {
  fe recip;
  fe x;
  fe y;

  fe_invert(recip, h->Z);
  fe_mul(x, h->X, recip);
  fe_mul(y, h->Y, recip);
  fe_tobytes(s, y);
  s[31] ^= fe_isnegative(x) << 7;
}

static void ge_p3_tobytes(uint8_t* s, const ge_p3* h) {
  fe recip;
  fe x;
  fe y;

  fe_invert(recip, h->Z);
  fe_mul(x, h->X, recip);
  fe_mul(y, h->Y, recip);
  fe_tobytes(s, y);
  s[31] ^= fe_isnegative(x) << 7;
}


#undef FE_INIT
#define FE_INIT(v, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9) \
  do {                                                     \
    v[0] = a0;                                             \
    v[1] = a1;                                             \
    v[2] = a2;                                             \
    v[3] = a3;                                             \
    v[4] = a4;                                             \
    v[5] = a5;                                             \
    v[6] = a6;                                             \
    v[7] = a7;                                             \
    v[8] = a8;                                             \
    v[9] = a9;                                             \
  } while (0)

/**
 *! noinline: 本函数的 7 个 fe 局部量(~280B)若内联将撑大 Verify 帧;
 *! 它在 Verify 开头执行, 与其后的 ge_scalarmult 链时序不重叠, 独立成帧即可
 */
static int __attribute__((noinline)) ge_frombytes_vartime(ge_p3* h, const uint8_t* s) {
  fe u;
  fe v;
  fe v3;
  fe vxx;
  fe check;

  fe d;  // = {-10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448, -12055116};
  fe sqrtm1;  //= {-32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482};
  FE_INIT(d, -10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448, -12055116);
  FE_INIT(sqrtm1, -32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482);

  fe_frombytes(h->Y, s);
  fe_1(h->Z);
  fe_sq(u, h->Y);
  fe_mul(v, u, d);
  fe_sub(u, u, h->Z); /* u = y^2-1 */
  fe_add(v, v, h->Z); /* v = dy^2+1 */

  fe_sq(v3, v);
  fe_mul(v3, v3, v); /* v3 = v^3 */
  fe_sq(h->X, v3);
  fe_mul(h->X, h->X, v);
  fe_mul(h->X, h->X, u); /* x = uv^7 */

  fe_pow22523(h->X, h->X); /* x = (uv^7)^((q-5)/8) */
  fe_mul(h->X, h->X, v3);
  fe_mul(h->X, h->X, u); /* x = uv^3(uv^7)^((q-5)/8) */

  fe_sq(vxx, h->X);
  fe_mul(vxx, vxx, v);
  fe_sub(check, vxx, u); /* vx^2-u */
  if (fe_isnonzero(check)) {
    fe_add(check, vxx, u); /* vx^2+u */
    if (fe_isnonzero(check)) {
      return -1;
    }
    fe_mul(h->X, h->X, sqrtm1);
  }

  if (fe_isnegative(h->X) != (s[31] >> 7)) {
    fe_neg(h->X, h->X);
  }

  fe_mul(h->T, h->X, h->Y);
  return 0;
}


/* The set of scalars is \Z/l
 * where l = 2^252 + 27742317777372353535851937790883648493.
 *
 * 紧凑版(2026-09-04):原 ref10 64 位全展开实现在 Cortex-M0(Thumb-1 无 64 位硬件)
 * 上 ~9.5KB, 按 21 位肢体循环化后与 ref10 逐字节等价, 体积 ~1KB。
 * 折叠常数即 L 的低 126 位在 radix-2^21 下的有符号肢。
 */

/* x[j]*2^(21j) 折叠进 x[j-12..j-7](x*2^252 ≡ -x*l0 mod L) */
static void sc_fold(int64_t* x, int j) {
  x[j - 12] += x[j] * 666643;
  x[j - 11] += x[j] * 470296;
  x[j - 10] += x[j] * 654183;
  x[j - 9] -= x[j] * 997805;
  x[j - 8] += x[j] * 136657;
  x[j - 7] -= x[j] * 683901;
  x[j] = 0;
}

/* ref10 进位链:带偏置 (s+bias)>>21, 不带偏置 s>>21; 肢体可能为负, 必须 int64 */
static void sc_carry(int64_t* x, int from, int to, int64_t bias, int step) {
  int i;
  for (i = from; i <= to; i += step) {
    int64_t c = (x[i] + bias) >> 21;
    x[i + 1] += c;
    x[i] -= c << 21;
  }
}

/* 按 radix-2^21 逐肢读取:位偏移 21*i mod 8 循环(21 ≡ 5 mod 8, 故 shift 序列
 * 0,5,2,7,4,1,6,3), 每步前进 2 字节、shift>=4 时再进 1 字节。
 * 增量递进是为了避免 / 与 % 运算(Cortex-M0 无硬件除法, 除法会引入
 * __aeabi_idiv 依赖)。shift<=3 读 3 字节, 否则读 4 字节。 */
static void sc_unpack_64(int64_t* x, const uint8_t* s) {
  const uint8_t* p = s;
  int sh = 0;
  int i;
  for (i = 0; i < 23; ++i) {
    uint32_t w = (sh <= 3) ? (uint32_t)load_3(p) : (uint32_t)load_4(p);
    x[i] = (w >> sh) & 0x1FFFFF;
    p += (sh >= 3) ? 3 : 2; /* bit 前进 21 位 = 2 字节 + 5 位, sh+5>=8 时再多进 1 字节 */
    sh = (sh + 5) & 7;
  }
  x[23] = load_4(s + 60) >> 3; /* 最高肢不截断, 交给折叠 */
}

/* 32 字节按 radix-2^21 拆 12 肢;第 11 肢不截断 */
static void sc_unpack_32(int32_t* x, const uint8_t* s) {
  const uint8_t* p = s;
  int sh = 0;
  int i;
  for (i = 0; i < 11; ++i) {
    uint32_t w = (sh <= 3) ? (uint32_t)load_3(p) : (uint32_t)load_4(p);
    x[i] = (int32_t)((w >> sh) & 0x1FFFFF);
    p += (sh >= 3) ? 3 : 2; /* bit 前进 21 位 = 2 字节 + 5 位, sh+5>=8 时再多进 1 字节 */
    sh = (sh + 5) & 7;
  }
  x[11] = (int32_t)(load_4(s + 28) >> 7);
}

/* 12 肢(radix-2^21)打包回 32 字节小端;跨肢拼接仅当移位后余位不足且下一肢存在
 * (最高字节只取 s11 的 4 位, 与 ref10 一致, 不读被丢弃的 s12)。
 * 肢索引/移位同样增量递进, 避免除法。 */
static void sc_pack_32(uint8_t* s, const int64_t* x) {
  int limb = 0;
  int sh = 0;
  int j;
  for (j = 0; j < 32; ++j) {
    uint32_t v = (uint32_t)(x[limb] >> sh);
    if (sh > 13 && limb + 1 <= 11) {
      v |= (uint32_t)(x[limb + 1] << (21 - sh));
    }
    s[j] = (uint8_t)v;
    sh += 8;
    if (sh >= 21) {
      sh -= 21;
      ++limb;
    }
  }
}

/* Input:
 *   s[0]+256*s[1]+...+256^63*s[63] = s
 *
 * Output:
 *   s[0]+256*s[1]+...+256^31*s[31] = s mod l
 *   Overwrites s in place. */
static void x25519_sc_reduce(uint8_t* s) {
  int64_t x[24];
  int j;

  sc_unpack_64(x, s);

  for (j = 23; j >= 18; --j) {
    sc_fold(x, j);
  }
  sc_carry(x, 6, 16, 1 << 20, 2);
  sc_carry(x, 7, 15, 1 << 20, 2);
  for (j = 17; j >= 12; --j) {
    sc_fold(x, j);
  }
  sc_carry(x, 0, 10, 1 << 20, 2);
  sc_carry(x, 1, 11, 1 << 20, 2);

  sc_fold(x, 12);
  sc_carry(x, 0, 11, 0, 1);
  sc_fold(x, 12);
  sc_carry(x, 0, 11, 0, 1);

  sc_pack_32(s, x);
}

/* Input:
 *   a[0]+256*a[1]+...+256^31*a[31] = a
 *   b[0]+256*b[1]+...+256^31*b[31] = b
 *   c[0]+256*c[1]+...+256^31*c[31] = c
 *
 * Output:
 *   s[0]+256*s[1]+...+256^31*s[31] = (ab+c) mod l
 *   where l = 2^252 + 27742317777372353535851937790883648493. */
/**
 *! noinline: sc_muladd 只在 Sign 末尾执行, 与 ge 运算时序不重叠 ——
 *! 独立成帧后, Sign 帧不再包含其局部量, 与 ExtendBuf 上的 Helper 时序分离
 *! (紧凑版栈帧 M0 实测 400B:al/bl/cl 12x3x4B + x[24] 8B = 336B + 循环/搬运)
 */
static void __attribute__((noinline)) sc_muladd(uint8_t* s, const uint8_t* a, const uint8_t* b, const uint8_t* c) {
  int32_t al[12];
  int32_t bl[12];
  int32_t cl[12];
  int64_t x[24];
  int i;
  int k;

  sc_unpack_32(al, a);
  sc_unpack_32(bl, b);
  sc_unpack_32(cl, c);

  /* 12x12 schoolbook: x[k] = cl[k] + Σ_{i+j=k} al[i]*bl[j] (k<12 加 c) */
  for (k = 0; k < 23; ++k) {
    int lo = (k > 11) ? (k - 11) : 0;
    int hi = (k < 12) ? k : 11;
    int64_t acc = (k < 12) ? cl[k] : 0;
    for (i = lo; i <= hi; ++i) {
      acc += (int64_t)al[i] * bl[k - i];
    }
    x[k] = acc;
  }
  x[23] = 0;

  sc_carry(x, 0, 22, 1 << 20, 2);
  sc_carry(x, 1, 21, 1 << 20, 2);
  for (k = 23; k >= 18; --k) {
    sc_fold(x, k);
  }
  sc_carry(x, 6, 16, 1 << 20, 2);
  sc_carry(x, 7, 15, 1 << 20, 2);
  for (k = 17; k >= 12; --k) {
    sc_fold(x, k);
  }
  sc_carry(x, 0, 10, 1 << 20, 2);
  sc_carry(x, 1, 11, 1 << 20, 2);

  sc_fold(x, 12);
  sc_carry(x, 0, 11, 0, 1);
  sc_fold(x, 12);
  sc_carry(x, 0, 11, 0, 1);

  sc_pack_32(s, x);
}

struct Helper {
  /* r = p */
  void ge_p3_to_cached(ge_cached* r, const ge_p3* p) {
    fe d2;
    FE_INIT(d2, -21827239, -5839606, -30745221, 13898782, 229458, 15978800, -12551817, -6495438, 29715968, 9444199);
    fe_add(r->YplusX, p->Y, p->X);
    fe_sub(r->YminusX, p->Y, p->X);
    fe_copy(r->Z, p->Z);
    fe_mul(r->T2d, p->T, d2);
  }

  /* r = p */
  void ge_p1p1_to_p3(ge_p3* r, const ge_p1p1* p) {
    fe_mul(r->X, p->X, p->T);
    fe_mul(r->Y, p->Y, p->Z);
    fe_mul(r->Z, p->Z, p->T);
    fe_mul(r->T, p->X, p->Y);
  }

  /* r = 2 * p */
  void ge_p2_dbl(ge_p1p1* r, const ge_p2* p) {
    fe t0;

    fe_sq(r->X, p->X);
    fe_sq(r->Z, p->Y);
    fe_sq2(r->T, p->Z);
    fe_add(r->Y, p->X, p->Y);
    fe_sq(t0, r->Y);
    fe_add(r->Y, r->Z, r->X);
    fe_sub(r->Z, r->Z, r->X);
    fe_sub(r->X, t0, r->Y);
    fe_sub(r->T, r->T, r->Z);
  }

  /* r = 2 * p */
  void ge_dbl(ge_p3* r, const ge_p3* p) {
    ge_p2_dbl(&q, p);
    ge_p1p1_to_p3(r, &q);
  }

  /* r = p + q */
  void ge_add_p1p1(ge_p1p1* r, const ge_p3* p, const ge_cached* q) {
    fe t0;

    fe_add(r->X, p->Y, p->X);
    fe_sub(r->Y, p->Y, p->X);
    fe_mul(r->Z, r->X, q->YplusX);
    fe_mul(r->Y, r->Y, q->YminusX);
    fe_mul(r->T, q->T2d, p->T);
    fe_mul(r->X, p->Z, q->Z);
    fe_add(t0, r->X, r->X);
    fe_sub(r->X, r->Z, r->Y);
    fe_add(r->Y, r->Z, r->Y);
    fe_add(r->Z, t0, r->T);
    fe_sub(r->T, t0, r->T);
  }

  /* r = p + q */
  void ge_add(ge_p3* r, const ge_p3* p, const ge_p3* q) {
    ge_p3_to_cached(&qc, q);
    ge_add_p1p1(&p1p1, p, &qc);
    ge_p1p1_to_p3(r, &p1p1);
  }

  /* r = (b == 1) ? p : r  (常数时间; r 与 p 可同一)
   * Preconditions: b in {0,1} */
  void ge_cmov(ge_p3* r, const ge_p3* p, unsigned int b) {
    fe_cmov(r->X, p->X, b);
    fe_cmov(r->Y, p->Y, b);
    fe_cmov(r->Z, p->Z, b);
    fe_cmov(r->T, p->T, b);
  }

  /* G */
  void ge_1(ge_p3* r) {
    FE_INIT(r->X, -14297830, -7645148, 16144683, -16471763, 27570974, -2696100, -26142465, 8378389, 20764389, 8758491);
    FE_INIT(r->Y, -26843541, -6710886, 13421773, -13421773, 26843546, 6710886, -13421773, 13421773, -26843546,
            -6710886);
    fe_1(r->Z);
    FE_INIT(r->T, 28827062, -6116119, -27349572, 244363, 8635006, 11264893, 19351346, 13413597, 16611511, -6414980);
  }

  /**
   *! 常数时间标量乘(M-01, 2026-10-12): 旧实现逐位 `if (bit)` 分支, 且 `if (!init)` 的空转次数
   *! 恰等于 k 的前导零个数 ⇒ **泄露最高置位位位置**。Sign 的 nonce 与 ComputePubkey 的 az 都走
   *! 这条 base 点路径, nonce 的任意位泄露都可经格攻击恢复私钥 ⇒ 必须消掉秘密相关分支。
   *! 现改为"恒算 R+A 到 T, 再按 0/1 掩码条件搬运": 每步仍 1 次 ge_add、共 255 步(旧实现零位走
   *! dummy 累加器也是 1 次 ge_add ⇒ 运算量一致), 分支与访存都不再依赖秘密; 旧 dummy 累加器 T
   *! 改作真和的暂存, 于是不再需要 init 标志。附带修正: k == 0 时旧实现返回**未初始化**的 R,
   *! 现正确返回中性元。
   *! R 与 point 允许同一(Verify 的 ge_scalarmult(&A, h, &A) 用法) ⇒ 先把 point 快照进成员 A。
   *! 栈: 不新增局部量(T/A 均为 Helper 成员), 帧与改前一致。
   *! 未直接采用 base/src/crypto.cc 的常量时间 ge_scalarmult_base: 它依赖 ~30KB 的 k25519Precomp
   *! 表(设备 64KB 固件装不下)且只支持 base 点, 而 Verify 需要变基。
   */
  void ge_scalarmult(ge_p3* R, const uint8_t k[32], const ge_p3* point) {
    A = *point; /* 先快照: R 可能与 point 相同 */

    /* R 起点 = 中性元(合法点, 不读未初始化内存: X=0, Y=1, Z=1, T=0) */
    fe_0(R->X);
    fe_1(R->Y);
    fe_1(R->Z);
    fe_0(R->T);

    for (int i = 0;; ++i) {
      const unsigned int bit = (unsigned int)((k[i >> 3] >> (i & 7)) & 1);
      ge_add(&T, R, &A); /* 每一位都算, 不走秘密分支 */
      ge_cmov(R, &T, bit);

      if (i == 254)
        break;
      ge_dbl(&A, &A);
    }
  }

  /* h = a * G */
  void ge_scalarmult_base(ge_p3* h, const uint8_t* a) { /* slow ... */
    ge_1(h);
    ge_scalarmult(h, a, h);
  }

  /**
   *! Sha512Ctx 借用 q/qc/p1p1 的联合体空间: 两者时序不重叠 ——
   *! q/qc/p1p1 仅在 ge_add/ge_dbl 调用内作为临时量存活, 不跨哈希;
   *! 三个入口(ComputePubkey/Sign/Verify)的所有哈希都发生在 ge 运算之前/之后。
   *! 借此消除 Sign/Verify/ComputePubkey 各自 240B 的 Sha512Ctx 栈临时。
   */
  Sha512Ctx& sha512_ctx() {
    return *reinterpret_cast<Sha512Ctx*>(sha512_ctx_);
  }

  union {
    ge_p1p1 q;  // ge_dbl
    struct {
      ge_cached qc;  // ge_add
      ge_p1p1 p1p1;  // ge_add
    };
    alignas(Sha512Ctx) uint8_t sha512_ctx_[sizeof(Sha512Ctx)];  // 哈希期专用
  };

  ge_p3 T, A;    // ge_scalarmult
  ge_p3 AR;      // pubkey/sign/verify ...
  uint8_t sha512[SHA512_DIGEST_LENGTH];

  union {
    ge_p3 VA;     // verify ...
    struct {      // sign ...
      uint8_t sha512_az[SHA512_DIGEST_LENGTH];
      uint8_t sha512_nonce[SHA512_DIGEST_LENGTH];
    };
  };
};

rLANG_ABIREQUIRE(sizeof(Helper) <= 1024);

} // namespace ...

int Curve25519::X25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
  uint8_t e[32];
  fe x1, x2, z2, x3, z3, tmp0, tmp1;
  unsigned swap = 0;
  int pos;

  memcpy(e, scalar, 32);
  e[0] &= 248;
  e[31] &= 127;
  e[31] |= 64;
  fe_frombytes(x1, point);
  fe_1(x2);
  fe_0(z2);
  fe_copy(x3, x1);
  fe_1(z3);

  for (pos = 254; pos >= 0; --pos) {
    unsigned b = 1 & (e[pos / 8] >> (pos & 7));
    swap ^= b;
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);
    swap = b;
    fe_sub(tmp0, x3, z3);
    fe_sub(tmp1, x2, z2);
    fe_add(x2, x2, z2);
    fe_add(z2, x3, z3);
    fe_mul(z3, tmp0, x2);
    fe_mul(z2, z2, tmp1);
    fe_sq(tmp0, tmp1);
    fe_sq(tmp1, x2);
    fe_add(x3, z3, z2);
    fe_sub(z2, z3, z2);
    fe_mul(x2, tmp1, tmp0);
    fe_sub(tmp1, tmp1, tmp0);
    fe_sq(z2, z2);
    fe_mul121666(z3, tmp1);
    fe_sq(x3, x3);
    fe_add(tmp0, tmp0, z3);
    fe_mul(z3, x1, z2);
    fe_mul(z2, tmp1, tmp0);
  }

  fe_invert(z2, z2);
  fe_mul(x2, x2, z2);
  fe_tobytes(out, x2);

  /* wipe the clamped private scalar with a non-eliminable cleanse (plain memset
   * is removed by the compiler's dead-store elimination) */
  {
    volatile uint8_t* ve = e;
    for (size_t i = 0; i < sizeof(e); ++i)
      ve[i] = 0;
  }

  /* RFC 7748 §6.1: reject the all-zero output (low-order point / small subgroup) */
  {
    uint8_t zero = 0;
    for (int i = 0; i < 32; ++i)
      zero |= out[i];
    if (0 == zero)
      return -EFAULT;
  }
  return 0;
}

void Ed25519::ComputePubkey(void* vExtBuffer, uint8_t pubkey[32], const uint8_t prikey[32]) {
  Helper* helper = static_cast<Helper*>(vExtBuffer);

  uint8_t* const az = helper->sha512;
  helper->sha512_ctx().Init().Update(prikey, 32).Final(az).Clear();

  az[0] &= 248;
  az[31] &= 63;
  az[31] |= 64;

  helper->ge_scalarmult_base(&helper->AR, az);
  ge_p3_tobytes(pubkey, &helper->AR);
  memset(az, 0, SHA512_DIGEST_LENGTH);
}

int Ed25519::Verify(void* vExtBuffer,
                    const void* message,
                    int message_len,
                    const uint8_t signature[64],
                    const uint8_t public_key[32]) {
  Helper* helper = static_cast<Helper*>(vExtBuffer);

  /* rcopy/scopy 已删除: Verify 全程只读 signature(哈希/标量乘/比较均不写它), 无需 64B 栈拷贝 */
  uint8_t rcheck[32];
  uint8_t* const h = helper->sha512;
  ge_p3& A = helper->VA;
  ge_p3& R = helper->AR;

  if ((signature[63] & 224) != 0 || ge_frombytes_vartime(&A, public_key) != 0) {
    return -1;
  }

  fe_neg(A.X, A.X);
  fe_neg(A.T, A.T);

  helper->sha512_ctx().Init().Update(signature, 32).Update(public_key, 32).Update(message, message_len).Final(h).Clear();

  x25519_sc_reduce(h);
  helper->ge_scalarmult_base(&R, signature + 32);
  helper->ge_scalarmult(&A, h, &A);
  helper->ge_add(&R, &R, &A);
  ge_tobytes(rcheck, &R);

  int r = 0, i;
  for (i = 0; i < 32; ++i) {
    r += rcheck[i] ^ signature[i];
  }
  return r;
}

void Ed25519::Sign(void* vExtBuffer,
                   uint8_t out_sig[64],
                   const void* message,
                   int message_len,
                   const uint8_t public_key[32],
                   const uint8_t private_key[32]) {
  Helper* helper = static_cast<Helper*>(vExtBuffer);

  ge_p3& R = helper->AR;
  uint8_t* const az = helper->sha512_az;
  uint8_t* const nonce = helper->sha512_nonce;
  uint8_t* const hram = helper->sha512;

  helper->sha512_ctx().Init().Update(private_key, 32).Final(az).Clear();

  az[0] &= 248;
  az[31] &= 63;
  az[31] |= 64;

  helper->sha512_ctx().Init().Update(&az[32], 32).Update(message, message_len).Final(nonce).Clear();

  x25519_sc_reduce(nonce);
  helper->ge_scalarmult_base(&R, nonce);
  ge_p3_tobytes(out_sig, &R);

  helper->sha512_ctx().Init().Update(out_sig, 32).Update(public_key, 32).Update(message, message_len).Final(hram).Clear();

  x25519_sc_reduce(hram);
  sc_muladd(out_sig + 32, hram, az, nonce);

  memset(nonce, 0, SHA512_DIGEST_LENGTH);
  memset(az, 0, SHA512_DIGEST_LENGTH);
}

int Dongle::GenerateKeyPairCurve25519(uint8_t pubkey[32], uint8_t prikey[32]) {
  std::ignore = TAG;
  if (RandBytes(prikey, 32) < 0)
    return -1;
  ComputePubkeyCurve25519(pubkey, prikey);
  return 0;
}
int Dongle::ComputePubkeyCurve25519(uint8_t pubkey[32], const uint8_t prikey[32]) {
  Curve25519().ComputePubkey(pubkey, prikey);
  return 0;
}
int Dongle::ComputeSecretCurve25519(uint8_t secret[32], const uint8_t prikey[32], const uint8_t pubkey[32]) {
  return Curve25519().X25519(secret, prikey, pubkey);
}

int Dongle::GenerateKeyPairEd25519(void* vExtBuffer, uint8_t pubkey[32], uint8_t prikey[32]) {
  if (RandBytes(prikey, 32) < 0)
    return -1;
  Ed25519().ComputePubkey(vExtBuffer, pubkey, prikey);
  return 0;
}
int Dongle::ComputePubkeyEd25519(void* vExtBuffer, uint8_t pubkey[32], const uint8_t prikey[32]) {
  Ed25519().ComputePubkey(vExtBuffer, pubkey, prikey);
  return 0;
}
int Dongle::SignMessageEd25519(void* vExtBuffer, /* Stack Overflow, [X]InOutBuffer ... */
                               uint8_t out_sig[64],
                               const void* message,
                               int message_len,
                               const uint8_t public_key[32],
                               const uint8_t private_key[32]) {
  Ed25519().Sign(vExtBuffer, out_sig, message, message_len, public_key, private_key);
  return 0;
}
int Dongle::VerifySignEd25519(void* vExtBuffer, /* Stack Overflow, [X]InOutBuffer ... */
                              const void* message,
                              int message_len,
                              const uint8_t signature[64],
                              const uint8_t public_key[32]) {
  return 0 == Ed25519().Verify(vExtBuffer, message, message_len, signature, public_key) ? 0 : last_error_ = -EFAULT;
}


} // namespace dongle ...

rLANG_DECLARE_END

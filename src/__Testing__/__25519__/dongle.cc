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

static int ge_frombytes_vartime(ge_p3* h, const uint8_t* s) {
  fe u;
  fe v;
  fe v3;
  fe vxx;
  fe check;

  fe d;      // = {-10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448, -12055116};
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

/* r = p */
static void ge_p3_to_cached(ge_cached* r, const ge_p3* p) {
  fe d2; // = {-21827239, -5839606, -30745221, 13898782, 229458, 15978800, -12551817, -6495438, 29715968, 9444199};
  FE_INIT(d2, -21827239, -5839606, -30745221, 13898782, 229458, 15978800, -12551817, -6495438, 29715968, 9444199);

  fe_add(r->YplusX, p->Y, p->X);
  fe_sub(r->YminusX, p->Y, p->X);
  fe_copy(r->Z, p->Z);
  fe_mul(r->T2d, p->T, d2);
}

/* r = p */
static void ge_p1p1_to_p3(ge_p3* r, const ge_p1p1* p) {
  fe_mul(r->X, p->X, p->T);
  fe_mul(r->Y, p->Y, p->Z);
  fe_mul(r->Z, p->Z, p->T);
  fe_mul(r->T, p->X, p->Y);
}

/* r = 2 * p */
static void ge_dbl(ge_p3* r, const ge_p3* p) {
  auto ge_p2_dbl = [](ge_p1p1* r, const ge_p2* p) {
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
  };

  ge_p1p1 q;
  ge_p2_dbl(&q, p);
  ge_p1p1_to_p3(r, &q);
}

/* r = p + q */
static void ge_add(ge_p3* r, const ge_p3* p, const ge_p3* q) {
  auto ge_add_p1p1 = [](ge_p1p1* r, const ge_p3* p, const ge_cached* q) {
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
  };

  ge_cached qc;
  ge_p1p1 p1p1;
  ge_p3_to_cached(&qc, q);
  ge_add_p1p1(&p1p1, p, &qc);
  ge_p1p1_to_p3(r, &p1p1);
}

/* G */
static void ge_1(ge_p3* r) {
  FE_INIT(r->X, -14297830, -7645148, 16144683, -16471763, 27570974, -2696100, -26142465, 8378389, 20764389, 8758491);
  FE_INIT(r->Y, -26843541, -6710886, 13421773, -13421773, 26843546, 6710886, -13421773, 13421773, -26843546, -6710886);
  fe_1(r->Z);
  FE_INIT(r->T, 28827062, -6116119, -27349572, 244363, 8635006, 11264893, 19351346, 13413597, 16611511, -6414980);
}

static void ge_scalarmult(ge_p3* R, const uint8_t k[32], const ge_p3* point) {
  bool init = false;
  ge_p3 T = *point, A = *point;

  for (int i = 0;; ++i) {
    const bool bit = k[i / 8] & (1 << (i % 8));
    if (bit) {
      if (!init) {
        *R = A;
        init = true;
      } else {
        ge_add(R, R, &A);
      }
    } else {
      ge_add(&T, &T, &A);
    }

    if (i == 254)
      break;
    ge_dbl(&A, &A);
  }  
}

/* h = a * B
 * where a = a[0]+256*a[1]+...+256^31 a[31]
 * B is the Ed25519 base point (x,4/5) with x positive.
 *
 * Preconditions:
 *   a[31] <= 127 */
static void ge_scalarmult_base(ge_p3* h, const uint8_t* a) {   /* slow ... */
  ge_1(h);
  ge_scalarmult(h, a, h);
}

/* The set of scalars is \Z/l
 * where l = 2^252 + 27742317777372353535851937790883648493. */

/* Input:
 *   s[0]+256*s[1]+...+256^63*s[63] = s
 *
 * Output:
 *   s[0]+256*s[1]+...+256^31*s[31] = s mod l
 *   where l = 2^252 + 27742317777372353535851937790883648493.
 *   Overwrites s in place. */
static void x25519_sc_reduce(uint8_t* s) {
  int64_t s0 = 2097151 & load_3(s);
  int64_t s1 = 2097151 & (load_4(s + 2) >> 5);
  int64_t s2 = 2097151 & (load_3(s + 5) >> 2);
  int64_t s3 = 2097151 & (load_4(s + 7) >> 7);
  int64_t s4 = 2097151 & (load_4(s + 10) >> 4);
  int64_t s5 = 2097151 & (load_3(s + 13) >> 1);
  int64_t s6 = 2097151 & (load_4(s + 15) >> 6);
  int64_t s7 = 2097151 & (load_3(s + 18) >> 3);
  int64_t s8 = 2097151 & load_3(s + 21);
  int64_t s9 = 2097151 & (load_4(s + 23) >> 5);
  int64_t s10 = 2097151 & (load_3(s + 26) >> 2);
  int64_t s11 = 2097151 & (load_4(s + 28) >> 7);
  int64_t s12 = 2097151 & (load_4(s + 31) >> 4);
  int64_t s13 = 2097151 & (load_3(s + 34) >> 1);
  int64_t s14 = 2097151 & (load_4(s + 36) >> 6);
  int64_t s15 = 2097151 & (load_3(s + 39) >> 3);
  int64_t s16 = 2097151 & load_3(s + 42);
  int64_t s17 = 2097151 & (load_4(s + 44) >> 5);
  int64_t s18 = 2097151 & (load_3(s + 47) >> 2);
  int64_t s19 = 2097151 & (load_4(s + 49) >> 7);
  int64_t s20 = 2097151 & (load_4(s + 52) >> 4);
  int64_t s21 = 2097151 & (load_3(s + 55) >> 1);
  int64_t s22 = 2097151 & (load_4(s + 57) >> 6);
  int64_t s23 = (load_4(s + 60) >> 3);
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
  int64_t carry10;
  int64_t carry11;
  int64_t carry12;
  int64_t carry13;
  int64_t carry14;
  int64_t carry15;
  int64_t carry16;

  s11 += s23 * 666643;
  s12 += s23 * 470296;
  s13 += s23 * 654183;
  s14 -= s23 * 997805;
  s15 += s23 * 136657;
  s16 -= s23 * 683901;
  s23 = 0;

  s10 += s22 * 666643;
  s11 += s22 * 470296;
  s12 += s22 * 654183;
  s13 -= s22 * 997805;
  s14 += s22 * 136657;
  s15 -= s22 * 683901;
  s22 = 0;

  s9 += s21 * 666643;
  s10 += s21 * 470296;
  s11 += s21 * 654183;
  s12 -= s21 * 997805;
  s13 += s21 * 136657;
  s14 -= s21 * 683901;
  s21 = 0;

  s8 += s20 * 666643;
  s9 += s20 * 470296;
  s10 += s20 * 654183;
  s11 -= s20 * 997805;
  s12 += s20 * 136657;
  s13 -= s20 * 683901;
  s20 = 0;

  s7 += s19 * 666643;
  s8 += s19 * 470296;
  s9 += s19 * 654183;
  s10 -= s19 * 997805;
  s11 += s19 * 136657;
  s12 -= s19 * 683901;
  s19 = 0;

  s6 += s18 * 666643;
  s7 += s18 * 470296;
  s8 += s18 * 654183;
  s9 -= s18 * 997805;
  s10 += s18 * 136657;
  s11 -= s18 * 683901;
  s18 = 0;

  carry6 = (s6 + (1 << 20)) >> 21;
  s7 += carry6;
  s6 -= carry6 * (1 << 21);
  carry8 = (s8 + (1 << 20)) >> 21;
  s9 += carry8;
  s8 -= carry8 * (1 << 21);
  carry10 = (s10 + (1 << 20)) >> 21;
  s11 += carry10;
  s10 -= carry10 * (1 << 21);
  carry12 = (s12 + (1 << 20)) >> 21;
  s13 += carry12;
  s12 -= carry12 * (1 << 21);
  carry14 = (s14 + (1 << 20)) >> 21;
  s15 += carry14;
  s14 -= carry14 * (1 << 21);
  carry16 = (s16 + (1 << 20)) >> 21;
  s17 += carry16;
  s16 -= carry16 * (1 << 21);

  carry7 = (s7 + (1 << 20)) >> 21;
  s8 += carry7;
  s7 -= carry7 * (1 << 21);
  carry9 = (s9 + (1 << 20)) >> 21;
  s10 += carry9;
  s9 -= carry9 * (1 << 21);
  carry11 = (s11 + (1 << 20)) >> 21;
  s12 += carry11;
  s11 -= carry11 * (1 << 21);
  carry13 = (s13 + (1 << 20)) >> 21;
  s14 += carry13;
  s13 -= carry13 * (1 << 21);
  carry15 = (s15 + (1 << 20)) >> 21;
  s16 += carry15;
  s15 -= carry15 * (1 << 21);

  s5 += s17 * 666643;
  s6 += s17 * 470296;
  s7 += s17 * 654183;
  s8 -= s17 * 997805;
  s9 += s17 * 136657;
  s10 -= s17 * 683901;
  s17 = 0;

  s4 += s16 * 666643;
  s5 += s16 * 470296;
  s6 += s16 * 654183;
  s7 -= s16 * 997805;
  s8 += s16 * 136657;
  s9 -= s16 * 683901;
  s16 = 0;

  s3 += s15 * 666643;
  s4 += s15 * 470296;
  s5 += s15 * 654183;
  s6 -= s15 * 997805;
  s7 += s15 * 136657;
  s8 -= s15 * 683901;
  s15 = 0;

  s2 += s14 * 666643;
  s3 += s14 * 470296;
  s4 += s14 * 654183;
  s5 -= s14 * 997805;
  s6 += s14 * 136657;
  s7 -= s14 * 683901;
  s14 = 0;

  s1 += s13 * 666643;
  s2 += s13 * 470296;
  s3 += s13 * 654183;
  s4 -= s13 * 997805;
  s5 += s13 * 136657;
  s6 -= s13 * 683901;
  s13 = 0;

  s0 += s12 * 666643;
  s1 += s12 * 470296;
  s2 += s12 * 654183;
  s3 -= s12 * 997805;
  s4 += s12 * 136657;
  s5 -= s12 * 683901;
  s12 = 0;

  carry0 = (s0 + (1 << 20)) >> 21;
  s1 += carry0;
  s0 -= carry0 * (1 << 21);
  carry2 = (s2 + (1 << 20)) >> 21;
  s3 += carry2;
  s2 -= carry2 * (1 << 21);
  carry4 = (s4 + (1 << 20)) >> 21;
  s5 += carry4;
  s4 -= carry4 * (1 << 21);
  carry6 = (s6 + (1 << 20)) >> 21;
  s7 += carry6;
  s6 -= carry6 * (1 << 21);
  carry8 = (s8 + (1 << 20)) >> 21;
  s9 += carry8;
  s8 -= carry8 * (1 << 21);
  carry10 = (s10 + (1 << 20)) >> 21;
  s11 += carry10;
  s10 -= carry10 * (1 << 21);

  carry1 = (s1 + (1 << 20)) >> 21;
  s2 += carry1;
  s1 -= carry1 * (1 << 21);
  carry3 = (s3 + (1 << 20)) >> 21;
  s4 += carry3;
  s3 -= carry3 * (1 << 21);
  carry5 = (s5 + (1 << 20)) >> 21;
  s6 += carry5;
  s5 -= carry5 * (1 << 21);
  carry7 = (s7 + (1 << 20)) >> 21;
  s8 += carry7;
  s7 -= carry7 * (1 << 21);
  carry9 = (s9 + (1 << 20)) >> 21;
  s10 += carry9;
  s9 -= carry9 * (1 << 21);
  carry11 = (s11 + (1 << 20)) >> 21;
  s12 += carry11;
  s11 -= carry11 * (1 << 21);

  s0 += s12 * 666643;
  s1 += s12 * 470296;
  s2 += s12 * 654183;
  s3 -= s12 * 997805;
  s4 += s12 * 136657;
  s5 -= s12 * 683901;
  s12 = 0;

  carry0 = s0 >> 21;
  s1 += carry0;
  s0 -= carry0 * (1 << 21);
  carry1 = s1 >> 21;
  s2 += carry1;
  s1 -= carry1 * (1 << 21);
  carry2 = s2 >> 21;
  s3 += carry2;
  s2 -= carry2 * (1 << 21);
  carry3 = s3 >> 21;
  s4 += carry3;
  s3 -= carry3 * (1 << 21);
  carry4 = s4 >> 21;
  s5 += carry4;
  s4 -= carry4 * (1 << 21);
  carry5 = s5 >> 21;
  s6 += carry5;
  s5 -= carry5 * (1 << 21);
  carry6 = s6 >> 21;
  s7 += carry6;
  s6 -= carry6 * (1 << 21);
  carry7 = s7 >> 21;
  s8 += carry7;
  s7 -= carry7 * (1 << 21);
  carry8 = s8 >> 21;
  s9 += carry8;
  s8 -= carry8 * (1 << 21);
  carry9 = s9 >> 21;
  s10 += carry9;
  s9 -= carry9 * (1 << 21);
  carry10 = s10 >> 21;
  s11 += carry10;
  s10 -= carry10 * (1 << 21);
  carry11 = s11 >> 21;
  s12 += carry11;
  s11 -= carry11 * (1 << 21);

  s0 += s12 * 666643;
  s1 += s12 * 470296;
  s2 += s12 * 654183;
  s3 -= s12 * 997805;
  s4 += s12 * 136657;
  s5 -= s12 * 683901;
  s12 = 0;

  carry0 = s0 >> 21;
  s1 += carry0;
  s0 -= carry0 * (1 << 21);
  carry1 = s1 >> 21;
  s2 += carry1;
  s1 -= carry1 * (1 << 21);
  carry2 = s2 >> 21;
  s3 += carry2;
  s2 -= carry2 * (1 << 21);
  carry3 = s3 >> 21;
  s4 += carry3;
  s3 -= carry3 * (1 << 21);
  carry4 = s4 >> 21;
  s5 += carry4;
  s4 -= carry4 * (1 << 21);
  carry5 = s5 >> 21;
  s6 += carry5;
  s5 -= carry5 * (1 << 21);
  carry6 = s6 >> 21;
  s7 += carry6;
  s6 -= carry6 * (1 << 21);
  carry7 = s7 >> 21;
  s8 += carry7;
  s7 -= carry7 * (1 << 21);
  carry8 = s8 >> 21;
  s9 += carry8;
  s8 -= carry8 * (1 << 21);
  carry9 = s9 >> 21;
  s10 += carry9;
  s9 -= carry9 * (1 << 21);
  carry10 = s10 >> 21;
  s11 += carry10;
  s10 -= carry10 * (1 << 21);

  s[0] = (uint8_t)(s0 >> 0);
  s[1] = (uint8_t)(s0 >> 8);
  s[2] = (uint8_t)((s0 >> 16) | (s1 << 5));
  s[3] = (uint8_t)(s1 >> 3);
  s[4] = (uint8_t)(s1 >> 11);
  s[5] = (uint8_t)((s1 >> 19) | (s2 << 2));
  s[6] = (uint8_t)(s2 >> 6);
  s[7] = (uint8_t)((s2 >> 14) | (s3 << 7));
  s[8] = (uint8_t)(s3 >> 1);
  s[9] = (uint8_t)(s3 >> 9);
  s[10] = (uint8_t)((s3 >> 17) | (s4 << 4));
  s[11] = (uint8_t)(s4 >> 4);
  s[12] = (uint8_t)(s4 >> 12);
  s[13] = (uint8_t)((s4 >> 20) | (s5 << 1));
  s[14] = (uint8_t)(s5 >> 7);
  s[15] = (uint8_t)((s5 >> 15) | (s6 << 6));
  s[16] = (uint8_t)(s6 >> 2);
  s[17] = (uint8_t)(s6 >> 10);
  s[18] = (uint8_t)((s6 >> 18) | (s7 << 3));
  s[19] = (uint8_t)(s7 >> 5);
  s[20] = (uint8_t)(s7 >> 13);
  s[21] = (uint8_t)(s8 >> 0);
  s[22] = (uint8_t)(s8 >> 8);
  s[23] = (uint8_t)((s8 >> 16) | (s9 << 5));
  s[24] = (uint8_t)(s9 >> 3);
  s[25] = (uint8_t)(s9 >> 11);
  s[26] = (uint8_t)((s9 >> 19) | (s10 << 2));
  s[27] = (uint8_t)(s10 >> 6);
  s[28] = (uint8_t)((s10 >> 14) | (s11 << 7));
  s[29] = (uint8_t)(s11 >> 1);
  s[30] = (uint8_t)(s11 >> 9);
  s[31] = (uint8_t)(s11 >> 17);
}

/* Input:
 *   a[0]+256*a[1]+...+256^31*a[31] = a
 *   b[0]+256*b[1]+...+256^31*b[31] = b
 *   c[0]+256*c[1]+...+256^31*c[31] = c
 *
 * Output:
 *   s[0]+256*s[1]+...+256^31*s[31] = (ab+c) mod l
 *   where l = 2^252 + 27742317777372353535851937790883648493. */
static void sc_muladd(uint8_t* s, const uint8_t* a, const uint8_t* b, const uint8_t* c) {
  int64_t a0 = 2097151 & load_3(a);
  int64_t a1 = 2097151 & (load_4(a + 2) >> 5);
  int64_t a2 = 2097151 & (load_3(a + 5) >> 2);
  int64_t a3 = 2097151 & (load_4(a + 7) >> 7);
  int64_t a4 = 2097151 & (load_4(a + 10) >> 4);
  int64_t a5 = 2097151 & (load_3(a + 13) >> 1);
  int64_t a6 = 2097151 & (load_4(a + 15) >> 6);
  int64_t a7 = 2097151 & (load_3(a + 18) >> 3);
  int64_t a8 = 2097151 & load_3(a + 21);
  int64_t a9 = 2097151 & (load_4(a + 23) >> 5);
  int64_t a10 = 2097151 & (load_3(a + 26) >> 2);
  int64_t a11 = (load_4(a + 28) >> 7);
  int64_t b0 = 2097151 & load_3(b);
  int64_t b1 = 2097151 & (load_4(b + 2) >> 5);
  int64_t b2 = 2097151 & (load_3(b + 5) >> 2);
  int64_t b3 = 2097151 & (load_4(b + 7) >> 7);
  int64_t b4 = 2097151 & (load_4(b + 10) >> 4);
  int64_t b5 = 2097151 & (load_3(b + 13) >> 1);
  int64_t b6 = 2097151 & (load_4(b + 15) >> 6);
  int64_t b7 = 2097151 & (load_3(b + 18) >> 3);
  int64_t b8 = 2097151 & load_3(b + 21);
  int64_t b9 = 2097151 & (load_4(b + 23) >> 5);
  int64_t b10 = 2097151 & (load_3(b + 26) >> 2);
  int64_t b11 = (load_4(b + 28) >> 7);
  int64_t c0 = 2097151 & load_3(c);
  int64_t c1 = 2097151 & (load_4(c + 2) >> 5);
  int64_t c2 = 2097151 & (load_3(c + 5) >> 2);
  int64_t c3 = 2097151 & (load_4(c + 7) >> 7);
  int64_t c4 = 2097151 & (load_4(c + 10) >> 4);
  int64_t c5 = 2097151 & (load_3(c + 13) >> 1);
  int64_t c6 = 2097151 & (load_4(c + 15) >> 6);
  int64_t c7 = 2097151 & (load_3(c + 18) >> 3);
  int64_t c8 = 2097151 & load_3(c + 21);
  int64_t c9 = 2097151 & (load_4(c + 23) >> 5);
  int64_t c10 = 2097151 & (load_3(c + 26) >> 2);
  int64_t c11 = (load_4(c + 28) >> 7);
  int64_t s0;
  int64_t s1;
  int64_t s2;
  int64_t s3;
  int64_t s4;
  int64_t s5;
  int64_t s6;
  int64_t s7;
  int64_t s8;
  int64_t s9;
  int64_t s10;
  int64_t s11;
  int64_t s12;
  int64_t s13;
  int64_t s14;
  int64_t s15;
  int64_t s16;
  int64_t s17;
  int64_t s18;
  int64_t s19;
  int64_t s20;
  int64_t s21;
  int64_t s22;
  int64_t s23;
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
  int64_t carry10;
  int64_t carry11;
  int64_t carry12;
  int64_t carry13;
  int64_t carry14;
  int64_t carry15;
  int64_t carry16;
  int64_t carry17;
  int64_t carry18;
  int64_t carry19;
  int64_t carry20;
  int64_t carry21;
  int64_t carry22;

  s0 = c0 + a0 * b0;
  s1 = c1 + a0 * b1 + a1 * b0;
  s2 = c2 + a0 * b2 + a1 * b1 + a2 * b0;
  s3 = c3 + a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
  s4 = c4 + a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
  s5 = c5 + a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0;
  s6 = c6 + a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0;
  s7 = c7 + a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1 + a7 * b0;
  s8 = c8 + a0 * b8 + a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 + a6 * b2 + a7 * b1 + a8 * b0;
  s9 = c9 + a0 * b9 + a1 * b8 + a2 * b7 + a3 * b6 + a4 * b5 + a5 * b4 + a6 * b3 + a7 * b2 + a8 * b1 + a9 * b0;
  s10 = c10 + a0 * b10 + a1 * b9 + a2 * b8 + a3 * b7 + a4 * b6 + a5 * b5 + a6 * b4 + a7 * b3 + a8 * b2 + a9 * b1 +
        a10 * b0;
  s11 = c11 + a0 * b11 + a1 * b10 + a2 * b9 + a3 * b8 + a4 * b7 + a5 * b6 + a6 * b5 + a7 * b4 + a8 * b3 + a9 * b2 +
        a10 * b1 + a11 * b0;
  s12 = a1 * b11 + a2 * b10 + a3 * b9 + a4 * b8 + a5 * b7 + a6 * b6 + a7 * b5 + a8 * b4 + a9 * b3 + a10 * b2 + a11 * b1;
  s13 = a2 * b11 + a3 * b10 + a4 * b9 + a5 * b8 + a6 * b7 + a7 * b6 + a8 * b5 + a9 * b4 + a10 * b3 + a11 * b2;
  s14 = a3 * b11 + a4 * b10 + a5 * b9 + a6 * b8 + a7 * b7 + a8 * b6 + a9 * b5 + a10 * b4 + a11 * b3;
  s15 = a4 * b11 + a5 * b10 + a6 * b9 + a7 * b8 + a8 * b7 + a9 * b6 + a10 * b5 + a11 * b4;
  s16 = a5 * b11 + a6 * b10 + a7 * b9 + a8 * b8 + a9 * b7 + a10 * b6 + a11 * b5;
  s17 = a6 * b11 + a7 * b10 + a8 * b9 + a9 * b8 + a10 * b7 + a11 * b6;
  s18 = a7 * b11 + a8 * b10 + a9 * b9 + a10 * b8 + a11 * b7;
  s19 = a8 * b11 + a9 * b10 + a10 * b9 + a11 * b8;
  s20 = a9 * b11 + a10 * b10 + a11 * b9;
  s21 = a10 * b11 + a11 * b10;
  s22 = a11 * b11;
  s23 = 0;

  carry0 = (s0 + (1 << 20)) >> 21;
  s1 += carry0;
  s0 -= carry0 * (1 << 21);
  carry2 = (s2 + (1 << 20)) >> 21;
  s3 += carry2;
  s2 -= carry2 * (1 << 21);
  carry4 = (s4 + (1 << 20)) >> 21;
  s5 += carry4;
  s4 -= carry4 * (1 << 21);
  carry6 = (s6 + (1 << 20)) >> 21;
  s7 += carry6;
  s6 -= carry6 * (1 << 21);
  carry8 = (s8 + (1 << 20)) >> 21;
  s9 += carry8;
  s8 -= carry8 * (1 << 21);
  carry10 = (s10 + (1 << 20)) >> 21;
  s11 += carry10;
  s10 -= carry10 * (1 << 21);
  carry12 = (s12 + (1 << 20)) >> 21;
  s13 += carry12;
  s12 -= carry12 * (1 << 21);
  carry14 = (s14 + (1 << 20)) >> 21;
  s15 += carry14;
  s14 -= carry14 * (1 << 21);
  carry16 = (s16 + (1 << 20)) >> 21;
  s17 += carry16;
  s16 -= carry16 * (1 << 21);
  carry18 = (s18 + (1 << 20)) >> 21;
  s19 += carry18;
  s18 -= carry18 * (1 << 21);
  carry20 = (s20 + (1 << 20)) >> 21;
  s21 += carry20;
  s20 -= carry20 * (1 << 21);
  carry22 = (s22 + (1 << 20)) >> 21;
  s23 += carry22;
  s22 -= carry22 * (1 << 21);

  carry1 = (s1 + (1 << 20)) >> 21;
  s2 += carry1;
  s1 -= carry1 * (1 << 21);
  carry3 = (s3 + (1 << 20)) >> 21;
  s4 += carry3;
  s3 -= carry3 * (1 << 21);
  carry5 = (s5 + (1 << 20)) >> 21;
  s6 += carry5;
  s5 -= carry5 * (1 << 21);
  carry7 = (s7 + (1 << 20)) >> 21;
  s8 += carry7;
  s7 -= carry7 * (1 << 21);
  carry9 = (s9 + (1 << 20)) >> 21;
  s10 += carry9;
  s9 -= carry9 * (1 << 21);
  carry11 = (s11 + (1 << 20)) >> 21;
  s12 += carry11;
  s11 -= carry11 * (1 << 21);
  carry13 = (s13 + (1 << 20)) >> 21;
  s14 += carry13;
  s13 -= carry13 * (1 << 21);
  carry15 = (s15 + (1 << 20)) >> 21;
  s16 += carry15;
  s15 -= carry15 * (1 << 21);
  carry17 = (s17 + (1 << 20)) >> 21;
  s18 += carry17;
  s17 -= carry17 * (1 << 21);
  carry19 = (s19 + (1 << 20)) >> 21;
  s20 += carry19;
  s19 -= carry19 * (1 << 21);
  carry21 = (s21 + (1 << 20)) >> 21;
  s22 += carry21;
  s21 -= carry21 * (1 << 21);

  s11 += s23 * 666643;
  s12 += s23 * 470296;
  s13 += s23 * 654183;
  s14 -= s23 * 997805;
  s15 += s23 * 136657;
  s16 -= s23 * 683901;
  s23 = 0;

  s10 += s22 * 666643;
  s11 += s22 * 470296;
  s12 += s22 * 654183;
  s13 -= s22 * 997805;
  s14 += s22 * 136657;
  s15 -= s22 * 683901;
  s22 = 0;

  s9 += s21 * 666643;
  s10 += s21 * 470296;
  s11 += s21 * 654183;
  s12 -= s21 * 997805;
  s13 += s21 * 136657;
  s14 -= s21 * 683901;
  s21 = 0;

  s8 += s20 * 666643;
  s9 += s20 * 470296;
  s10 += s20 * 654183;
  s11 -= s20 * 997805;
  s12 += s20 * 136657;
  s13 -= s20 * 683901;
  s20 = 0;

  s7 += s19 * 666643;
  s8 += s19 * 470296;
  s9 += s19 * 654183;
  s10 -= s19 * 997805;
  s11 += s19 * 136657;
  s12 -= s19 * 683901;
  s19 = 0;

  s6 += s18 * 666643;
  s7 += s18 * 470296;
  s8 += s18 * 654183;
  s9 -= s18 * 997805;
  s10 += s18 * 136657;
  s11 -= s18 * 683901;
  s18 = 0;

  carry6 = (s6 + (1 << 20)) >> 21;
  s7 += carry6;
  s6 -= carry6 * (1 << 21);
  carry8 = (s8 + (1 << 20)) >> 21;
  s9 += carry8;
  s8 -= carry8 * (1 << 21);
  carry10 = (s10 + (1 << 20)) >> 21;
  s11 += carry10;
  s10 -= carry10 * (1 << 21);
  carry12 = (s12 + (1 << 20)) >> 21;
  s13 += carry12;
  s12 -= carry12 * (1 << 21);
  carry14 = (s14 + (1 << 20)) >> 21;
  s15 += carry14;
  s14 -= carry14 * (1 << 21);
  carry16 = (s16 + (1 << 20)) >> 21;
  s17 += carry16;
  s16 -= carry16 * (1 << 21);

  carry7 = (s7 + (1 << 20)) >> 21;
  s8 += carry7;
  s7 -= carry7 * (1 << 21);
  carry9 = (s9 + (1 << 20)) >> 21;
  s10 += carry9;
  s9 -= carry9 * (1 << 21);
  carry11 = (s11 + (1 << 20)) >> 21;
  s12 += carry11;
  s11 -= carry11 * (1 << 21);
  carry13 = (s13 + (1 << 20)) >> 21;
  s14 += carry13;
  s13 -= carry13 * (1 << 21);
  carry15 = (s15 + (1 << 20)) >> 21;
  s16 += carry15;
  s15 -= carry15 * (1 << 21);

  s5 += s17 * 666643;
  s6 += s17 * 470296;
  s7 += s17 * 654183;
  s8 -= s17 * 997805;
  s9 += s17 * 136657;
  s10 -= s17 * 683901;
  s17 = 0;

  s4 += s16 * 666643;
  s5 += s16 * 470296;
  s6 += s16 * 654183;
  s7 -= s16 * 997805;
  s8 += s16 * 136657;
  s9 -= s16 * 683901;
  s16 = 0;

  s3 += s15 * 666643;
  s4 += s15 * 470296;
  s5 += s15 * 654183;
  s6 -= s15 * 997805;
  s7 += s15 * 136657;
  s8 -= s15 * 683901;
  s15 = 0;

  s2 += s14 * 666643;
  s3 += s14 * 470296;
  s4 += s14 * 654183;
  s5 -= s14 * 997805;
  s6 += s14 * 136657;
  s7 -= s14 * 683901;
  s14 = 0;

  s1 += s13 * 666643;
  s2 += s13 * 470296;
  s3 += s13 * 654183;
  s4 -= s13 * 997805;
  s5 += s13 * 136657;
  s6 -= s13 * 683901;
  s13 = 0;

  s0 += s12 * 666643;
  s1 += s12 * 470296;
  s2 += s12 * 654183;
  s3 -= s12 * 997805;
  s4 += s12 * 136657;
  s5 -= s12 * 683901;
  s12 = 0;

  carry0 = (s0 + (1 << 20)) >> 21;
  s1 += carry0;
  s0 -= carry0 * (1 << 21);
  carry2 = (s2 + (1 << 20)) >> 21;
  s3 += carry2;
  s2 -= carry2 * (1 << 21);
  carry4 = (s4 + (1 << 20)) >> 21;
  s5 += carry4;
  s4 -= carry4 * (1 << 21);
  carry6 = (s6 + (1 << 20)) >> 21;
  s7 += carry6;
  s6 -= carry6 * (1 << 21);
  carry8 = (s8 + (1 << 20)) >> 21;
  s9 += carry8;
  s8 -= carry8 * (1 << 21);
  carry10 = (s10 + (1 << 20)) >> 21;
  s11 += carry10;
  s10 -= carry10 * (1 << 21);

  carry1 = (s1 + (1 << 20)) >> 21;
  s2 += carry1;
  s1 -= carry1 * (1 << 21);
  carry3 = (s3 + (1 << 20)) >> 21;
  s4 += carry3;
  s3 -= carry3 * (1 << 21);
  carry5 = (s5 + (1 << 20)) >> 21;
  s6 += carry5;
  s5 -= carry5 * (1 << 21);
  carry7 = (s7 + (1 << 20)) >> 21;
  s8 += carry7;
  s7 -= carry7 * (1 << 21);
  carry9 = (s9 + (1 << 20)) >> 21;
  s10 += carry9;
  s9 -= carry9 * (1 << 21);
  carry11 = (s11 + (1 << 20)) >> 21;
  s12 += carry11;
  s11 -= carry11 * (1 << 21);

  s0 += s12 * 666643;
  s1 += s12 * 470296;
  s2 += s12 * 654183;
  s3 -= s12 * 997805;
  s4 += s12 * 136657;
  s5 -= s12 * 683901;
  s12 = 0;

  carry0 = s0 >> 21;
  s1 += carry0;
  s0 -= carry0 * (1 << 21);
  carry1 = s1 >> 21;
  s2 += carry1;
  s1 -= carry1 * (1 << 21);
  carry2 = s2 >> 21;
  s3 += carry2;
  s2 -= carry2 * (1 << 21);
  carry3 = s3 >> 21;
  s4 += carry3;
  s3 -= carry3 * (1 << 21);
  carry4 = s4 >> 21;
  s5 += carry4;
  s4 -= carry4 * (1 << 21);
  carry5 = s5 >> 21;
  s6 += carry5;
  s5 -= carry5 * (1 << 21);
  carry6 = s6 >> 21;
  s7 += carry6;
  s6 -= carry6 * (1 << 21);
  carry7 = s7 >> 21;
  s8 += carry7;
  s7 -= carry7 * (1 << 21);
  carry8 = s8 >> 21;
  s9 += carry8;
  s8 -= carry8 * (1 << 21);
  carry9 = s9 >> 21;
  s10 += carry9;
  s9 -= carry9 * (1 << 21);
  carry10 = s10 >> 21;
  s11 += carry10;
  s10 -= carry10 * (1 << 21);
  carry11 = s11 >> 21;
  s12 += carry11;
  s11 -= carry11 * (1 << 21);

  s0 += s12 * 666643;
  s1 += s12 * 470296;
  s2 += s12 * 654183;
  s3 -= s12 * 997805;
  s4 += s12 * 136657;
  s5 -= s12 * 683901;
  s12 = 0;

  carry0 = s0 >> 21;
  s1 += carry0;
  s0 -= carry0 * (1 << 21);
  carry1 = s1 >> 21;
  s2 += carry1;
  s1 -= carry1 * (1 << 21);
  carry2 = s2 >> 21;
  s3 += carry2;
  s2 -= carry2 * (1 << 21);
  carry3 = s3 >> 21;
  s4 += carry3;
  s3 -= carry3 * (1 << 21);
  carry4 = s4 >> 21;
  s5 += carry4;
  s4 -= carry4 * (1 << 21);
  carry5 = s5 >> 21;
  s6 += carry5;
  s5 -= carry5 * (1 << 21);
  carry6 = s6 >> 21;
  s7 += carry6;
  s6 -= carry6 * (1 << 21);
  carry7 = s7 >> 21;
  s8 += carry7;
  s7 -= carry7 * (1 << 21);
  carry8 = s8 >> 21;
  s9 += carry8;
  s8 -= carry8 * (1 << 21);
  carry9 = s9 >> 21;
  s10 += carry9;
  s9 -= carry9 * (1 << 21);
  carry10 = s10 >> 21;
  s11 += carry10;
  s10 -= carry10 * (1 << 21);

  s[0] = (uint8_t)(s0 >> 0);
  s[1] = (uint8_t)(s0 >> 8);
  s[2] = (uint8_t)((s0 >> 16) | (s1 << 5));
  s[3] = (uint8_t)(s1 >> 3);
  s[4] = (uint8_t)(s1 >> 11);
  s[5] = (uint8_t)((s1 >> 19) | (s2 << 2));
  s[6] = (uint8_t)(s2 >> 6);
  s[7] = (uint8_t)((s2 >> 14) | (s3 << 7));
  s[8] = (uint8_t)(s3 >> 1);
  s[9] = (uint8_t)(s3 >> 9);
  s[10] = (uint8_t)((s3 >> 17) | (s4 << 4));
  s[11] = (uint8_t)(s4 >> 4);
  s[12] = (uint8_t)(s4 >> 12);
  s[13] = (uint8_t)((s4 >> 20) | (s5 << 1));
  s[14] = (uint8_t)(s5 >> 7);
  s[15] = (uint8_t)((s5 >> 15) | (s6 << 6));
  s[16] = (uint8_t)(s6 >> 2);
  s[17] = (uint8_t)(s6 >> 10);
  s[18] = (uint8_t)((s6 >> 18) | (s7 << 3));
  s[19] = (uint8_t)(s7 >> 5);
  s[20] = (uint8_t)(s7 >> 13);
  s[21] = (uint8_t)(s8 >> 0);
  s[22] = (uint8_t)(s8 >> 8);
  s[23] = (uint8_t)((s8 >> 16) | (s9 << 5));
  s[24] = (uint8_t)(s9 >> 3);
  s[25] = (uint8_t)(s9 >> 11);
  s[26] = (uint8_t)((s9 >> 19) | (s10 << 2));
  s[27] = (uint8_t)(s10 >> 6);
  s[28] = (uint8_t)((s10 >> 14) | (s11 << 7));
  s[29] = (uint8_t)(s11 >> 1);
  s[30] = (uint8_t)(s11 >> 9);
  s[31] = (uint8_t)(s11 >> 17);
}


}

void X25519(uint8_t out[32], uint8_t scalar[32], uint8_t point[32]) {
  fe x1, x2, z2, x3, z3, tmp0, tmp1;
  uint8_t e[32];
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

  memset(e, 0, sizeof(e));
}

void X25519Pubkey(uint8_t pubkey[32], const uint8_t prikey[32]) {
  uint8_t e[32];
  ge_p3 A;
  fe zplusy, zminusy, zminusy_inv;

  memcpy(e, prikey, 32);
  e[0] &= 248;
  e[31] &= 127;
  e[31] |= 64;

  ge_scalarmult_base(&A, e);

  /* We only need the u-coordinate of the curve25519 point. The map is
   * u=(y+1)/(1-y). Since y=Y/Z, this gives u=(Z+Y)/(Z-Y). */
  fe_add(zplusy, A.Z, A.Y);
  fe_sub(zminusy, A.Z, A.Y);
  fe_invert(zminusy_inv, zminusy);
  fe_mul(zplusy, zplusy, zminusy_inv);
  fe_tobytes(pubkey, zplusy);

  memset(e, 0, sizeof(e));
}

void Ed25519Pubkey(uint8_t pubkey[32], const uint8_t prikey[32]) {
  uint8_t az[SHA512_DIGEST_LENGTH];
  ge_p3 A;

  Sha512Ctx().Init().Update(prikey, 32).Final(az);

  az[0] &= 248;
  az[31] &= 63;
  az[31] |= 64;

  ge_scalarmult_base(&A, az);
  ge_p3_tobytes(pubkey, &A);
  memset(az, 0, sizeof(az));
}

void Ed25519Sign(uint8_t out_sig[64],
  const void* message,
  int message_len,
  const uint8_t public_key[32],
  const uint8_t private_key[32]) {
  ge_p3 R;
  uint8_t az[SHA512_DIGEST_LENGTH];
  uint8_t nonce[SHA512_DIGEST_LENGTH];
  uint8_t hram[SHA512_DIGEST_LENGTH];

  Sha512Ctx().Init().Update(private_key, 32).Final(az);

  az[0] &= 248;
  az[31] &= 63;
  az[31] |= 64;

  Sha512Ctx().Init().Update(&az[32], 32).Update(message, message_len).Final(nonce);

  x25519_sc_reduce(nonce);
  ge_scalarmult_base(&R, nonce);
  ge_p3_tobytes(out_sig, &R);

  Sha512Ctx().Init().Update(out_sig, 32).Update(public_key, 32).Update(message, message_len).Final(hram);

  x25519_sc_reduce(hram);
  sc_muladd(out_sig + 32, hram, az, nonce);

  memset(nonce, 0, sizeof(nonce));
  memset(az, 0, sizeof(az));
}

int Ed25519Verify(const void* message, int message_len, const uint8_t signature[64], const uint8_t public_key[32]) {
  ge_p3 A;
  uint8_t rcopy[32];
  uint8_t scopy[32];
  uint8_t rcheck[32];
  uint8_t h[SHA512_DIGEST_LENGTH];
  ge_p3 R;

  if ((signature[63] & 224) != 0 || ge_frombytes_vartime(&A, public_key) != 0) {
    return -1;
  }

  fe_neg(A.X, A.X);
  fe_neg(A.T, A.T);

  memcpy(rcopy, signature, 32);
  memcpy(scopy, signature + 32, 32);

  Sha512Ctx().Init().Update(signature, 32).Update(public_key, 32).Update(message, message_len).Final(h);

  x25519_sc_reduce(h);
  ge_scalarmult_base(&R, scopy);
  ge_scalarmult(&A, h, &A);
  ge_add(&R, &R, &A);
  ge_tobytes(rcheck, &R);

  int r = 0, i;
  for (i = 0; i < 32; ++i) {
    r += rcheck[i] ^ rcopy[i];
  }
  return r;
}

struct Context_t {
  uint32_t argv_[4];

  uint8_t secret_1[32];
  uint8_t secret_2[32];

  uint8_t pubkey_1[32];
  uint8_t pubkey_2[32];
  uint8_t prikey_[64];

  uint8_t edpubkey[32];
  uint8_t sign[64];
};

int Start(void* InOutBuf, void* ExtendBuf) {
  int error = 0;
  Context_t* Context = (Context_t*)InOutBuf;

  uint32_t state[16];
  uint8_t base[32 /* + 512 + 192 */] = {9};
  uint8_t pubk_check[32];
  
  memset(state, 0, sizeof(state));
  memcpy(state, Context->argv_, sizeof(Context->argv_));

  for (int i = 0; i < 2; ++i) {
    ++state[12];
    rlCryptoChaCha20Block(state, Context->prikey_);
    ++state[12];
    rlCryptoChaCha20Block(state, Context->pubkey_1);
    ++state[12];
    rlCryptoChaCha20Block(state, Context->secret_1);

    X25519(Context->pubkey_1, &Context->prikey_[0], base);
    X25519(Context->pubkey_2, &Context->prikey_[32], base);

    X25519(Context->secret_1, &Context->prikey_[0], Context->pubkey_2);
    X25519(Context->secret_2, &Context->prikey_[32], Context->pubkey_1);

    int result = memcmp(Context->secret_1, Context->secret_2, 32);
    if (result)
      ++error;
    DONGLE_VERIFY(0 == result);

    if (0 != result) {
      X25519Pubkey(pubk_check, &Context->prikey_[32]);
      DONGLE_VERIFY(0 == memcmp(pubk_check, Context->pubkey_2, 32));

      Ed25519Pubkey(Context->edpubkey, Context->prikey_);
      Ed25519Sign(Context->sign, Context->prikey_, 64, Context->edpubkey, Context->prikey_);
      DONGLE_VERIFY(0 == Ed25519Verify(Context->prikey_, 64, Context->sign, Context->edpubkey));
    }

#if !defined(X_BUILD_native)
    ge_p3 ge_base;
    const uint8_t one_[32] = {1};
    uint8_t base_pubkey[32];
    uint8_t sign_check[64];
    uint8_t seck_check[32];

    rlCryptoX25519(seck_check, &Context->prikey_[32], Context->pubkey_1);
    DONGLE_VERIFY(0 == memcmp(seck_check, Context->secret_2, 32));

    X25519Pubkey(pubk_check, &Context->prikey_[32]);
    DONGLE_VERIFY(0 == memcmp(pubk_check, Context->pubkey_2, 32));

    Ed25519Pubkey(Context->edpubkey, Context->prikey_);
    Ed25519Sign(Context->sign, Context->prikey_, 64, Context->edpubkey, Context->prikey_);
    DONGLE_VERIFY(0 == Ed25519Verify(Context->prikey_, 64, Context->sign, Context->edpubkey));

    auto fe_log = [](const fe& A, const char* prefix) {
      char line[2048], *p = line;
      for (int i = 0; i < 10; ++i)
        p += sprintf(p, "%d,", A[i]);
      rlLOGI(TAG, "\t%s: [ %s ]", prefix, line);
    };

    rlCryptoEd25519PubkeyEx(base_pubkey, one_);
    ge_frombytes_vartime(&ge_base, base_pubkey);
    rlLOGI(TAG, "BASE.Point:");
    fe_log(ge_base.X, "X");
    fe_log(ge_base.Y, "Y");
    fe_log(ge_base.Z, "Z");
    fe_log(ge_base.T, "T");

    uint8_t pub1[32], pub2[32];
    rlCryptoX25519Pubkey(pub1, &Context->prikey_[0]);
    rlCryptoX25519Pubkey(pub2, &Context->prikey_[32]);
    DONGLE_VERIFY(0 == memcmp(pub1, Context->pubkey_1, 32));
    DONGLE_VERIFY(0 == memcmp(pub2, Context->pubkey_2, 32));

    rlCryptoEd25519Pubkey(pub1, Context->prikey_);
    DONGLE_VERIFY(0 == memcmp(pub1, Context->edpubkey, 32));

    rlCryptoEd25519Sign(sign_check, Context->prikey_, 64, Context->edpubkey, Context->prikey_);
    DONGLE_VERIFY(0 == memcmp(sign_check, Context->sign, 64));
#endif /* */

    rlLOGXI(TAG, Context, sizeof(Context_t), "25519 test return %d", result);
  }

  return 10086 - error;
}

}  // namespace dongle

rLANG_DECLARE_END


int main(int argc, char* argv[]) {
  using namespace machine;
  using namespace machine::dongle;
#ifdef _MSC_VER
  if (argc >= 2 && 0 == strcmp("-d", argv[1])) {
    while (!::IsDebuggerPresent()) {
      rlLOGI(TAG, "Wait debugger ...");
      Sleep(1000);
    }
    ::DebugBreak();
    --argc;
    ++argv;
  }
#endif /* _MSC_VER */

  rLANG_ABIREQUIRE(sizeof(Context_t) <= 1024);
  Context_t* Context = (Context_t*)calloc(1, 3 << 10);
  uint64_t ExtendBuf[(1 << 10) / 8] = {0};

   for (int i = 1; i <= 4 && i < argc; ++i) {
    Context->argv_[i - 1] = strtoul(argv[i], nullptr, 16);
  }

  return Start(Context, ExtendBuf);
}

/*! rsa_mr.h — MCU/设备约束版 1024 位 Miller–Rabin 素数搜索(定长数组, 无堆/无 .rodata 表)
 *! 配合 __Testing__dongle__ 的 RsaPrimeMR 测试项在 ukey 内执行, 以测得"找 1024 位素数"时间。
 *! 约束: 无动态分配; 常量(小素数基)以立即数/局部常量形式内联, 不建 .rodata 表;
 *!       数字=uint32[64] 小端, n=有效 limb 数(≤32 参与运算, 乘/取模临时 ≤64)。
 *! 说明: 这是"可行性"版(平方乘+二进制除法, 无 Montgomery); 正确性先在 host 测试项验证。
 */
#ifndef AGINX_RSA_MR_H
#define AGINX_RSA_MR_H

#include <cstdint>
#include <cstring>

namespace rsa_mr {

struct BN {
  uint32_t v[64];
  int n; /* 有效 limb 数, >=1 */
  BN() { clear(); }
  explicit BN(uint32_t one) {
    clear();
    v[0] = one;
    n = 1;
  }
  void clear() {
    memset(v, 0, sizeof(v));
    n = 1;
  }
};

static inline void trim(BN& a) {
  while (a.n > 1 && a.v[a.n - 1] == 0) --a.n;
}
static inline int cmp(const BN& a, const BN& b) {
  if (a.n != b.n) return a.n < b.n ? -1 : 1;
  for (int i = a.n; i-- > 0;)
    if (a.v[i] != b.v[i]) return a.v[i] < b.v[i] ? -1 : 1;
  return 0;
}
static inline int clz32(uint32_t x) {
  int c = 0;
  for (int b = 31; b >= 0; --b)
    if (x & (1u << b)) return 31 - b;
  return 32;
}
static inline int bitlen(const BN& a) {
  if (a.n == 1 && a.v[0] == 0) return 0;
  return (a.n - 1) * 32 + (32 - clz32(a.v[a.n - 1]));
}
static inline void add(BN& r, const BN& a, const BN& b) {
  r = a;
  uint64_t carry = 0;
  const int N = a.n > b.n ? a.n : b.n;
  for (int i = 0; i < N; ++i) {
    uint64_t s = carry + r.v[i];
    if (i < b.n) s += b.v[i];
    r.v[i] = (uint32_t)s;
    carry = s >> 32;
  }
  if (carry) r.v[N] = (uint32_t)carry;
  r.n = N + (carry ? 1 : 0);
  trim(r);
}
static inline void sub(BN& r, const BN& a, const BN& b) { /* a>=b */
  r = a;
  int64_t borrow = 0;
  for (int i = 0; i < r.n; ++i) {
    int64_t s = (int64_t)r.v[i] - (i < b.n ? (int64_t)b.v[i] : 0) - borrow;
    if (s < 0) {
      s += (int64_t)1 << 32;
      borrow = 1;
    } else {
      borrow = 0;
    }
    r.v[i] = (uint32_t)s;
  }
  trim(r);
}
static inline void addSmall(BN& a, uint32_t x) {
  uint64_t carry = x;
  for (int i = 0; i < a.n && carry; ++i) {
    uint64_t s = (uint64_t)a.v[i] + carry;
    a.v[i] = (uint32_t)s;
    carry = s >> 32;
  }
  if (carry) a.v[a.n++] = (uint32_t)carry;
  trim(a);
}
static inline void subSmall(BN& a, uint32_t x) {
  int64_t borrow = x;
  for (int i = 0; i < a.n && borrow; ++i) {
    int64_t s = (int64_t)a.v[i] - borrow;
    if (s < 0) {
      s += (int64_t)1 << 32;
      borrow = 1;
    } else {
      borrow = 0;
    }
    a.v[i] = (uint32_t)s;
  }
  trim(a);
}
static inline void shlK(BN& r, const BN& a, int k) { /* k>=0 */
  if (k <= 0) {
    r = a;
    return;
  }
  const int words = k / 32, bits = k % 32;
  BN z;
  z.n = a.n + words + (bits ? 1 : 0);
  for (int i = 0; i < a.n; ++i) {
    uint64_t x = (uint64_t)a.v[i] << bits;
    z.v[i + words] |= (uint32_t)x;
    if (bits) z.v[i + words + 1] |= (uint32_t)(x >> 32);
  }
  trim(z);
  r = z;
}
static inline void shr1(BN& a) {
  uint32_t carry = 0;
  for (int i = a.n - 1; i >= 0; --i) {
    uint32_t nv = (a.v[i] >> 1) | (carry << 31);
    carry = a.v[i] & 1;
    a.v[i] = nv;
  }
  trim(a);
}
static inline bool isEven(const BN& a) {
  return a.n > 0 && (a.v[0] & 1) == 0;
}
static inline void pow2Set(BN& a, int bit) {
  const int limb = bit / 32, off = bit % 32;
  if (limb < 0 || limb >= 64) return;
  if (limb >= a.n) {
    for (int i = a.n; i <= limb; ++i) a.v[i] = 0;
    a.n = limb + 1;
  }
  uint64_t carry = (uint64_t)a.v[limb] + (1u << off);
  a.v[limb] = (uint32_t)carry;
  int j = limb;
  while (carry >>= 32) {
    ++j;
    if (j >= a.n) {
      a.v[j] = 0;
      ++a.n;
    }
    carry += a.v[j];
    a.v[j] = (uint32_t)carry;
  }
  trim(a);
}
static inline void mul(BN& r, const BN& a, const BN& b) {
  BN z;
  for (int i = 0; i < a.n; ++i) {
    uint64_t carry = 0;
    for (int j = 0; j < b.n; ++j) {
      uint64_t s = (uint64_t)a.v[i] * b.v[j] + z.v[i + j] + carry;
      z.v[i + j] = (uint32_t)s;
      carry = s >> 32;
    }
    int j = b.n;
    while (carry) {
      uint64_t s = (uint64_t)z.v[i + j] + carry;
      z.v[i + j] = (uint32_t)s;
      carry = s >> 32;
      ++j;
    }
  }
  z.n = a.n + b.n;
  trim(z);
  r = z;
}
static inline void divmod(BN& q, BN& rem, const BN& a, const BN& b) {
  BN r = a;
  q.clear();
  while (cmp(r, b) >= 0) {
    int s = bitlen(r) - bitlen(b);
    BN bs;
    shlK(bs, b, s);
    while (cmp(r, bs) < 0) {
      --s;
      if (s < 0) break;
      shlK(bs, b, s);
    }
    if (s < 0) break;
    BN rr;
    sub(rr, r, bs);
    r = rr;
    pow2Set(q, s);
  }
  rem = r;
}
static inline void mulmod(BN& r, const BN& a, const BN& b, const BN& m) {
  BN p, q, rem;
  mul(p, a, b);
  divmod(q, rem, p, m);
  r = rem;
}
static inline void powmod(BN& r, const BN& base, const BN& e, const BN& m) {
  BN b = base;
  BN q, rem;
  divmod(q, rem, b, m);
  b = rem;
  BN acc(1);
  for (int i = bitlen(e) - 1; i >= 0; --i) {
    BN t;
    mulmod(t, acc, acc, m);
    acc = t;
    if ((e.v[i / 32] >> (i % 32)) & 1) {
      mulmod(t, acc, b, m);
      acc = t;
    }
  }
  r = acc;
}
/* 小候选表: n<=smallMax 直接查(表为 32 位栈数组, 体积小、运行期构建, 不入 .rodata) */
static inline bool isSmall(const BN& n) {
  const uint32_t sm[16] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53};
  if (cmp(n, BN{sm[15] + 2}) > 0) return false;
  for (int i = 0; i < 16; ++i)
    if (cmp(n, BN{sm[i]}) == 0) return true;
  return false;
}
static inline bool isPrimeMR(const BN& n, int rounds) {
  if (n.n == 1 && n.v[0] < 2) return false;
  if (isSmall(n)) return true; /* 2/3/5/... 直接命中 */
  if (isEven(n)) return false;
  if (rounds < 1) rounds = 1;
  if (rounds > 16) rounds = 16;
  const uint32_t bases[16] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53};
  BN nm1 = n;
  subSmall(nm1, 1);
  BN d = nm1;
  int s = 0;
  while (isEven(d)) {
    shr1(d);
    ++s;
  }
  for (int r = 0; r < rounds; ++r) {
    BN a = n;
    BN aa(bases[r]);
    if (cmp(aa, nm1) >= 0) continue;
    BN x;
    powmod(x, aa, d, n);
    if (cmp(x, BN{1}) == 0 || cmp(x, nm1) == 0) continue;
    bool witness = false;
    for (int j = 1; j < s; ++j) {
      BN t;
      mulmod(t, x, x, n);
      x = t;
      if (cmp(x, nm1) == 0) {
        witness = true;
        break;
      }
      if (cmp(x, BN{1}) == 0) break;
    }
    if (!witness) return false;
    (void)a;
  }
  return true;
}
/* 从 128B 种子小端构造 1024 位奇候选(置第 1023 位) */
static inline void seedToOdd(BN& out, const uint8_t seed[128]) {
  out.clear();
  for (int i = 0; i < 128; ++i) out.v[i / 4] |= (uint32_t)seed[i] << ((i % 4) * 8);
  out.n = 32;
  trim(out);
  /* 不足 1024 位则整体抬高 */
  if (bitlen(out) < 1023) {
    BN t;
    shlK(t, out, 1023 - bitlen(out));
    out = t;
  }
  if (bitlen(out) < 1024) pow2Set(out, 1023);
  if (isEven(out)) addSmall(out, 1);
  trim(out);
}
/* 递增搜索: 返回找到后 true 并把素数放入 out; 记录探测次数 */
static inline bool findPrime(BN& out, const uint8_t seed[128], int rounds, long long& probes) {
  BN cand;
  seedToOdd(cand, seed);
  probes = 0;
  for (;;) {
    if (isPrimeMR(cand, rounds)) {
      out = cand;
      return true;
    }
    addSmall(cand, 2);
    ++probes;
  }
}

} /* namespace rsa_mr */

#endif /* AGINX_RSA_MR_H */

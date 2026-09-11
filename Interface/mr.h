#include <Interface/dongle.h>

AGINX_DECLARE_MACHINE

namespace dongle {

/**
 *! 用于 ukey 在设备内执行 1024 位 Miller-Rabin 测试, 运行也许非常的缓慢
 */
class MillerRabinContext {
 public:
  static constexpr int kCountWords = 32; /* 1024 bits */
  using limb_t = uint32_t;
  using DWORD = Dongle::DWORD;
  struct BN {
    void clear() {
      memset(v, 0, sizeof(v));
      n = 0;
    }
    limb_t v[kCountWords * 2]{}; /* a*b */
    int n = 0;
  };

  /**
   *! 我们ukey每轮只执行单独一轮RM测试, 每次测试的结果加密保存在 InOutBuffer, 由HOST推进
   */
  int IsPrimeMRW(const BN& v, int rounds = kMaxRounds);
  void KickWDG();
  void InitSmallBases();

  /** 可用基上限(与 smallBases_ 容量一致); 测试时可只跑前几轮以缩短设备端耗时 */
  static constexpr int kMaxRounds = 16;

  /**
   *! 小素数试除(廉价前置过滤): 用 3..kTrialLimit 的所有奇数对 n 流式求余,
   *! 命中因子即判定合数 —— 绝大多数合数无需进入昂贵的 Miller-Rabin 幂模。
   *! 不用素数表(运行时按奇数递推, 不产生 .rodata); 1024 位仅 ~32 limb/除数。
   */
  static constexpr uint32_t kTrialLimit = 1000;
  bool TrialDivide(const BN& n) {
    for (uint32_t d = 3; d <= kTrialLimit; d += 2) {
      uint32_t r = 0;
      for (int i = n.n; i-- > 0;) {
        const uint64_t t = ((uint64_t)r << 32) | n.v[i];
        r = static_cast<uint32_t>(t % d);
      }
      if (r == 0)
        return true; /* 有小于等于 kTrialLimit 的奇因子 → 合数 */
    }
    return false;
  }

  /* ---- Montgomery(无 R² 版本): R = 2^{32k}, k = n.n ----
   *! 进域用 k*32 次倍增(mod n), 出域用 k*32 次半减(奇数补 n); 因此不需要
   *! 64-limb 乘积与逐位长除, CIOS 仅需 uint32_t t[k+2] 的栈(≤136B)。 */
  static uint32_t N0Inv(uint32_t n0) { /* -n^{-1} mod 2^32(牛顿迭代 5 轮) */
    uint32_t x = 1;
    for (int i = 0; i < 5; ++i)
      x *= 2u - n0 * x;
    return 0u - x;
  }
  void MontMul(BN& r, const BN& a, const BN& b, const BN& n, uint32_t n0inv);
  void ToMont(BN& r, const BN& a, const BN& n);   /* r = a*R mod n(要求 a < n) */
  void FromMont(BN& r, const BN& a, const BN& n); /* r = a*R^{-1} mod n */

 protected:
  void trim(BN& a) {
    while (a.n > 1 && a.v[a.n - 1] == 0)
      --a.n;
  }
  int cmp(const BN& a, const BN& b) {
    if (a.n != b.n)
      return a.n < b.n ? -1 : 1;
    for (int i = a.n; i-- > 0;)
      if (a.v[i] != b.v[i])
        return a.v[i] < b.v[i] ? -1 : 1;
    return 0;
  }
  int clz32(uint32_t x) {
    for (int b = 31; b >= 0; --b)
      if (x & (1u << b))
        return 31 - b;
    return 32;
  }
  int bitlen(const BN& a) {
    if (a.n == 1 && a.v[0] == 0)
      return 0;
    return (a.n - 1) * 32 + (32 - clz32(a.v[a.n - 1]));
  }
  bool isEven(const BN& a) { return a.n > 0 && (a.v[0] & 1) == 0; }
  bool isOne(const BN& a) { return a.n == 1 && a.v[0] == 1; }

  void addSmall(BN& a, uint32_t x) {
    uint64_t carry = x;
    for (int i = 0; i < a.n && carry; ++i) {
      uint64_t s = (uint64_t)a.v[i] + carry;
      a.v[i] = (uint32_t)s;
      carry = s >> 32;
    }
    if (carry)
      a.v[a.n++] = (uint32_t)carry;
    trim(a);
  }
  void subSmall(BN& a, uint32_t x) {
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
  void shr1(BN& a) {
    uint32_t carry = 0;
    for (int i = a.n - 1; i >= 0; --i) {
      uint32_t nv = (a.v[i] >> 1) | (carry << 31);
      carry = a.v[i] & 1;
      a.v[i] = nv;
    }
    trim(a);
  }
  void pow2Set(BN& a, int bit) { /* a += 2^bit */
    const int limb = bit / 32, off = bit % 32;
    if (limb < 0 || limb >= 64)
      return;
    if (limb >= a.n) {
      for (int i = a.n; i <= limb; ++i)
        a.v[i] = 0;
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

 protected:
  void mulTo(BN& r, const BN& a, const BN& b);
  void remTo(BN& rr, const BN& a, const BN& b);
  void mulmodW(BN& r, const BN& a, const BN& b, const BN& m, BN& prod, BN& rem);
  void powmodMRW(BN& r, uint32_t base, const BN& e, const BN& m, BN& bs, BN& prod, BN& rem);


 protected:
  BN prod_; /* 乘积 2n limb */
  BN rem_;  /* 取模余数 */
  BN bs_;   /* pow mod 小基 */

  limb_t smallBases_[16]{}; /* !rodata: 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53 */
  Dongle* dongle_ = nullptr;
  uint32_t counter_ = 0;
};

/**
 *! 所有成员缺省都初始化为0, 因此我们可以安全的 reinterpret_cast 使用 ...
 */
rLANG_ABIREQUIRE(sizeof(MillerRabinContext) <= 1024);
}  // namespace dongle

AGINX_DECLARE_END

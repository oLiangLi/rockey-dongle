#include "mr.h"

AGINX_DECLARE_MACHINE

namespace dongle {

#if defined(__RockeyARM__)
#define rLANG_ROCKEY_NOOPTIMIZE __attribute__((optimize("O0")))
#else
#define rLANG_ROCKEY_NOOPTIMIZE
#endif

#if 0
/**
 *! 调试时允许一些小一些的数字参加测试
 */
static constexpr int kSizeDebuggerLimit = 4;
#else
/**
 *! 必须传入 1024 位的整数进行素数测试
 */
static constexpr int kSizeDebuggerLimit = MillerRabinContext::kCountWords;
#endif

static constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("kRMPT");

/* r = a*b*R^{-1} mod n (CIOS, R=2^{32k}, k=n.n); r 可与 a/b 别名(结果经局部 t 回写) */
rLANG_NOINLINE void MillerRabinContext::MontMul(BN& r, const BN& a, const BN& b, const BN& n,
                                                uint32_t n0inv) {
  const int k = n.n;
  uint32_t t[34];
  for (int i = 0; i < k + 2; ++i)
    t[i] = 0;
  for (int i = 0; i < k; ++i) {
    const uint32_t bi = (i < b.n) ? b.v[i] : 0;
    uint64_t c = 0;
    for (int j = 0; j < k; ++j) {
      const uint32_t aj = (j < a.n) ? a.v[j] : 0;
      const uint64_t s = (uint64_t)aj * bi + t[j] + c;
      t[j] = (uint32_t)s;
      c = s >> 32;
    }
    uint64_t s2 = (uint64_t)t[k] + c;
    t[k] = (uint32_t)s2;
    t[k + 1] = (uint32_t)(s2 >> 32);

    const uint32_t m = t[0] * n0inv; /* m = t0 * (-n^{-1}) mod 2^32 */
    c = ((uint64_t)t[0] + (uint64_t)m * n.v[0]) >> 32;
    for (int j = 1; j < k; ++j) {
      const uint64_t s = (uint64_t)m * n.v[j] + t[j] + c;
      t[j - 1] = (uint32_t)s;
      c = s >> 32;
    }
    const uint64_t s3 = (uint64_t)t[k] + c;
    t[k - 1] = (uint32_t)s3;
    t[k] = t[k + 1] + (uint32_t)(s3 >> 32);
  }
  /* 结果 < 2n → 条件减一次 n */
  bool ge = (t[k] != 0);
  if (!ge) {
    int j = k - 1;
    for (; j >= 0; --j) {
      if (t[j] != n.v[j]) {
        ge = (t[j] > n.v[j]);
        break;
      }
    }
    if (j < 0)
      ge = true; /* 相等 */
  }
  if (ge) {
    int64_t borrow = 0;
    for (int j = 0; j < k; ++j) {
      int64_t d = (int64_t)t[j] - (int64_t)n.v[j] - borrow;
      if (d < 0) {
        d += (int64_t)1 << 32;
        borrow = 1;
      } else {
        borrow = 0;
      }
      t[j] = (uint32_t)d;
    }
  }
  r.clear();
  r.n = k;
  for (int j = 0; j < k; ++j)
    r.v[j] = t[j];
  trim(r);
}

/* r = a*R mod n(要求 a < n): k*32 次倍增 + 条件减; r 可与 a 别名 */
rLANG_NOINLINE void MillerRabinContext::ToMont(BN& r, const BN& a, const BN& n) {
  if (&r != &a) {
    r.clear();
    r.n = a.n;
    for (int i = 0; i < a.n; ++i)
      r.v[i] = a.v[i];
  }
  trim(r);
  const int bits = 32 * n.n;
  for (int i = 0; i < bits; ++i) {
    uint32_t carry = 0;
    for (int j = 0; j < r.n; ++j) {
      const uint64_t s = ((uint64_t)r.v[j] << 1) | carry;
      r.v[j] = (uint32_t)s;
      carry = (uint32_t)(s >> 32);
    }
    if (carry)
      r.v[r.n++] = carry;
    /* 注意: 进位≠超过 n(小数值时进位只是越过 32 位边界), 必须按比较决定是否减 n */
    if (cmp(r, n) >= 0) {
      int64_t borrow = 0;
      for (int j = 0; j < r.n; ++j) {
        int64_t d = (int64_t)r.v[j] - (j < n.n ? (int64_t)n.v[j] : 0) - borrow;
        if (d < 0) {
          d += (int64_t)1 << 32;
          borrow = 1;
        } else {
          borrow = 0;
        }
        r.v[j] = (uint32_t)d;
      }
      trim(r);
    }
  }
}

/* r = a*R^{-1} mod n: k*32 次半减(奇数先补 n); r 可与 a 别名 */
rLANG_NOINLINE void MillerRabinContext::FromMont(BN& r, const BN& a, const BN& n) {
  if (&r != &a) {
    r.clear();
    r.n = a.n;
    for (int i = 0; i < a.n; ++i)
      r.v[i] = a.v[i];
  }
  trim(r);
  const int bits = 32 * n.n;
  for (int i = 0; i < bits; ++i) {
    if (r.v[0] & 1u) { /* r += n(n 为奇数 → 偶) */
      uint64_t c = 0;
      for (int j = 0; j < r.n; ++j) {
        const uint64_t s = (uint64_t)r.v[j] + (j < n.n ? (uint64_t)n.v[j] : 0) + c;
        r.v[j] = (uint32_t)s;
        c = s >> 32;
      }
      if (c)
        r.v[r.n++] = (uint32_t)c;
    }
    uint32_t carry = 0;
    for (int j = r.n; j-- > 0;) {
      const uint32_t nv = (r.v[j] >> 1) | (carry << 31);
      carry = r.v[j] & 1u;
      r.v[j] = nv;
    }
    trim(r);
  }
}

rLANG_NOINLINE int MillerRabinContext::IsPrimeMRW(const BN& n, int rounds) {
  if (n.n < kSizeDebuggerLimit || n.n > kCountWords)
    return -1; /* */

  if (isEven(n))
    return 0;

  /* 廉价前置: 小素数试除, 大多数合数在此被拒(无需昂贵幂模) */
  if (TrialDivide(n))
    return 0;

  /* Montgomery 域: R = 2^{32k}; 全程在域内比较(one_m/nm1_m 只转换一次) */
  const uint32_t n0inv = N0Inv(n.v[0]);
  BN d = n;
  subSmall(d, 1);
  int s = 0;
  while (isEven(d)) {
    shr1(d);
    ++s;
  }

  BN one_m, nm1_m, base_m, x;
  /* 原地构造, 省两个 BN 栈槽(设备栈预算紧张): one_m = 1*R, nm1_m = (n-1)*R */
  one_m.clear();
  one_m.v[0] = 1;
  one_m.n = 1;
  ToMont(one_m, one_m, n);
  nm1_m = n;
  subSmall(nm1_m, 1);
  ToMont(nm1_m, nm1_m, n);

  if (rounds < 1 || rounds > (int)(sizeof(smallBases_) / sizeof(smallBases_[0])))
    rounds = (int)(sizeof(smallBases_) / sizeof(smallBases_[0]));
  for (int r = 0; r < rounds; ++r) {
    const uint32_t base = smallBases_[r];
    if (n.n == 1 && (uint64_t)base + 1 >= (uint64_t)n.v[0])
      continue; /* n-1 <= base 时该基无意义 */
    base_m.clear();
    base_m.v[0] = base;
    base_m.n = 1;
    ToMont(base_m, base_m, n); /* 原地把小基转进 Montgomery 域 */
    x.clear();
    x.n = one_m.n;
    for (int j = 0; j < one_m.n; ++j)
      x.v[j] = one_m.v[j];
    for (int i = bitlen(d) - 1; i >= 0; --i) {
      MontMul(x, x, x, n, n0inv);
      if ((d.v[i >> 5] >> (i & 31)) & 1u)
        MontMul(x, x, base_m, n, n0inv);
      if ((i & 31) == 0)
        KickWDG(); /* 每 32 次平方: LED 反转 + COS 心跳 */
    }
    if (cmp(x, one_m) == 0 || cmp(x, nm1_m) == 0)
      continue;
    bool witness = false;
    for (int j = 1; j < s; ++j) {
      MontMul(x, x, x, n, n0inv);
      if (cmp(x, nm1_m) == 0) {
        witness = true;
        break;
      }
      if (cmp(x, one_m) == 0)
        break;
      if ((j & 31) == 0)
        KickWDG();
    }
    if (!witness)
      return 0;
  }
  return 1;
}

rLANG_NOINLINE void MillerRabinContext::mulTo(BN& r, const BN& a, const BN& b) {
  r.clear();
  for (int i = 0; i < a.n; ++i) {
    uint64_t carry = 0;
    for (int j = 0; j < b.n; ++j) {
      uint64_t s = (uint64_t)a.v[i] * b.v[j] + r.v[i + j] + carry;
      r.v[i + j] = (uint32_t)s;
      carry = s >> 32;
    }
    int j = b.n;
    while (carry) {
      uint64_t s = (uint64_t)r.v[i + j] + carry;
      r.v[i + j] = (uint32_t)s;
      carry = s >> 32;
      ++j;
    }
  }
  r.n = a.n + b.n;
  trim(r);
}

rLANG_NOINLINE void MillerRabinContext::remTo(BN& rr, const BN& a, const BN& b) {
  if (cmp(a, b) < 0) {
    rr = a;
    return;
  }
  rr.n = 1;
  rr.v[0] = 0;
  for (int i = bitlen(a) - 1; i >= 0; --i) {
    uint32_t carry = (a.v[i >> 5] >> (i & 31)) & 1u;
    for (int j = 0; j < rr.n; ++j) {
      uint64_t t = ((uint64_t)rr.v[j] << 1) | carry;
      rr.v[j] = (uint32_t)t;
      carry = (uint32_t)(t >> 32);
    }
    if (carry)
      rr.v[rr.n++] = carry;
    if (cmp(rr, b) >= 0) { /* rr -= b */
      int64_t borrow = 0;
      for (int j = 0; j < rr.n; ++j) {
        int64_t s = (int64_t)rr.v[j] - (j < b.n ? (int64_t)b.v[j] : 0) - borrow;
        if (s < 0) {
          s += (int64_t)1 << 32;
          borrow = 1;
        } else {
          borrow = 0;
        }
        rr.v[j] = (uint32_t)s;
      }
      trim(rr);
    }
  }
}

rLANG_NOINLINE void MillerRabinContext::mulmodW(BN& r, const BN& a, const BN& b, const BN& m, BN& prod, BN& rem) {
  KickWDG();
  mulTo(prod, a, b);
  remTo(rem, prod, m);
  r = rem;
}

rLANG_NOINLINE void
MillerRabinContext::powmodMRW(BN& r, uint32_t base, const BN& e, const BN& m, BN& bs, BN& prod, BN& rem) {
  bs.v[0] = base; /* base < m(MR 路径已保证), 单 limb, 其余槽位不读 */
  bs.n = 1;
  r.clear();
  r.v[0] = 1;
  r.n = 1; /* 注意: BN::clear() 置 n=0, 必须显式置 1, 否则 mulTo 空转 → 恒判合数 */
  for (int i = bitlen(e) - 1; i >= 0; --i) {
    mulmodW(r, r, r, m, prod, rem);
    if ((e.v[i >> 5] >> (i & 31)) & 1u)
      mulmodW(r, r, bs, m, prod, rem);
  }
}

void MillerRabinContext::KickWDG() {
#if defined(__RockeyARM__)
  ++counter_;

  dongle_->SetLEDState(counter_ & 1 ? LED_STATE::kOn : LED_STATE::kOff);

  /**
   *! 仅仅设置LED状态并不生效, 需要一次有效的 COS 调用 ...
   */
#if 1
  DWORD ticks = 0;
  std::ignore = dongle_->GetTickCount(&ticks);
#endif
#else  /* __RockeyARM__ */
  rlLOGV(TAG, "MR.KickWDG %d ...", (int)++counter_);
#endif /* __RockeyARM__ */

  std::ignore = TAG;
}

rLANG_ROCKEY_NOOPTIMIZE void MillerRabinContext::InitSmallBases() {
  smallBases_[0] = 2;
  smallBases_[1] = 3;
  smallBases_[2] = 5;
  smallBases_[3] = 7;

  smallBases_[4] = 11;
  smallBases_[5] = 13;
  smallBases_[6] = 17;
  smallBases_[7] = 19;

  smallBases_[8] = 23;
  smallBases_[9] = 29;
  smallBases_[10] = 31;
  smallBases_[11] = 37;

  smallBases_[12] = 41;
  smallBases_[13] = 43;
  smallBases_[14] = 47;
  smallBases_[15] = 53;
}

}  // namespace dongle

AGINX_DECLARE_END

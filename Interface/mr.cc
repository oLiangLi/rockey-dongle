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
 *! 允许的最小测试宽度: 1024 位(kMinCountWords); 上限为 kCountWords=1536 位
 */
static constexpr int kSizeDebuggerLimit = MillerRabinContext::kMinCountWords;
#endif

static constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("kRMPT");

/* r = a*b*R^{-1} mod n (CIOS, R=2^{32k}, k=n.n); r 可与 a/b 别名(结果经局部 t 回写) */
rLANG_NOINLINE void MillerRabinContext::MontMul(BN& r, const BN& a, const BN& b, const BN& n, uint32_t n0inv) {
  const int k = n.n;
  uint32_t t[kCountWords + 2];
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

  /* Montgomery 域: R = 2^{32k}; 全程在域内比较(one_m_/nm1_m_ 只转换一次)
   *! one_m_/nm1_m_ 放类成员而非栈: k=48 时单个 BN 388B, 与 d/base_m/x 一起放栈会顶穿 */
  const uint32_t n0inv = N0Inv(n.v[0]);
  BN d = n;
  subSmall(d, 1);
  int s = 0;
  while (isEven(d)) {
    shr1(d);
    ++s;
  }

  BN base_m, x;
  /* 原地构造: one_m_ = 1*R, nm1_m_ = (n-1)*R = n - R mod n(域内减法, 省一次 ToMont) */
  one_m_.clear();
  one_m_.v[0] = 1;
  one_m_.n = 1;
  ToMont(one_m_, one_m_, n);
  nm1_m_ = n;
  subEq(nm1_m_, one_m_);

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
    x.n = one_m_.n;
    for (int j = 0; j < one_m_.n; ++j)
      x.v[j] = one_m_.v[j];
    for (int i = bitlen(d) - 1; i >= 0; --i) {
      MontMul(x, x, x, n, n0inv);
      if ((d.v[i >> 5] >> (i & 31)) & 1u)
        MontMul(x, x, base_m, n, n0inv);
      if ((i & 31) == 0)
        KickWDG(); /* 每 32 次平方: LED 反转 + COS 心跳 */
    }
    if (cmp(x, one_m_) == 0 || cmp(x, nm1_m_) == 0)
      continue;
    bool witness = false;
    for (int j = 1; j < s; ++j) {
      MontMul(x, x, x, n, n0inv);
      if (cmp(x, nm1_m_) == 0) {
        witness = true;
        break;
      }
      if (cmp(x, one_m_) == 0)
        break;
      if ((j & 31) == 0)
        KickWDG();
    }
    if (!witness)
      return 0;
  }
  return 1;
}

/*! a -= b(要求 a >= b): 在 Montgomery 域内由 one_m_ 直接得到 nm1_m_ = n - R mod n */
rLANG_NOINLINE void MillerRabinContext::subEq(BN& a, const BN& b) {
  int64_t borrow = 0;
  for (int j = 0; j < a.n; ++j) {
    const int64_t bj = (j < b.n) ? (int64_t)b.v[j] : 0;
    int64_t d = (int64_t)a.v[j] - bj - borrow;
    if (d < 0) {
      d += (int64_t)1 << 32;
      borrow = 1;
    } else {
      borrow = 0;
    }
    a.v[j] = (uint32_t)d;
  }
  trim(a);
}

/*! 候选定型: c.v 已由调用方用种子/TRNG 填满 bits/8 字节, 这里保证它是严格 bits 位的奇数 */
rLANG_NOINLINE void MillerRabinContext::SeedCandidate(BN& c, int bits) {
  const int words = bits / 32;
  c.n = words;
  c.v[0] |= 1u;               /* 最低位: 奇数 */
  c.v[words - 1] |= 1u << 31; /* 最高位: 恰 bits 位 */
  trim(c);
}

/*! 从候选起点 +2 搜索素数; 幂模内部已有周期心跳, 这里只为试除密集的长尾补一次喂狗 */
rLANG_NOINLINE int MillerRabinContext::FindPrime(BN& out,
                                                 int bits,
                                                 int rounds,
                                                 uint64_t maxProbes,
                                                 uint64_t& probes,
                                                 uint32_t label) {
  const int words = bits / 32;
  probes = 0;
  SeedCandidate(out, bits);
  for (uint64_t i = 0; i <= maxProbes; ++i) {
    probes = i;
    if (IsPrimeMRW(out, rounds) > 0)
      return 1;
    addSmall(out, 2);
    /* 边界防御: 进位越过最高位就不再是 bits 位候选(预算内不可能发生, 仅防呆) */
    if (out.n != words || 0 == (out.v[words - 1] >> 31))
      return 0;
    if ((i & 0x3ffu) == 0)
      KickWDG();
    /* 每 32 次探测落一次进度(带 MR 的候选每次约几十秒 ⇒ ≈3 分钟一次):
     * 即使中途被看门狗复位, dashboard 上也能看到搜到第几个候选、在找 p 还是 q。
     * ! 该记录会被最终 GenResult 覆盖(magic 不同)。*/
    if (label && (i & 0x1fu) == 0)
      ReportProgress(kMagicAlive, label, i, 0);
  }
  return 0;
}

/*! 长跑进度落盘: dashboard[kProgressOffset, +64)(factory dataFile 0xFFFF) */
rLANG_NOINLINE void MillerRabinContext::ReportProgress(uint32_t magic,
                                                       uint32_t seq,
                                                       uint64_t units,
                                                       uint32_t checksum) {
  Progress p{};
  p.magic = magic;
  p.seq = seq;
  p.units_lo = (uint32_t)units;
  p.units_hi = (uint32_t)(units >> 32);
  p.beats = counter_;
  p.checksum = checksum;
  p.result = 0xFFFFFFFFu; /* 未调用; 写入失败时保留返回码 */
  if (dongle_) {
    const int rc = dongle_->WriteDataFile(Dongle::kFactoryDataFileId, kProgressOffset, &p, sizeof(p));
    p.result = (uint32_t)rc;
    if (0 != rc) /* 失败重试一次并把返回码留在 dashboard 上 */
      std::ignore = dongle_->WriteDataFile(Dongle::kFactoryDataFileId, kProgressOffset, &p, sizeof(p));
  }
  std::ignore = TAG;
}

/**
 *! 长跑/看门狗耐久测试(设备内执行): 定工作量(LCG 依赖链, 不会被优化掉)+ 周期性 KickWDG,
 *! 并按 kReportBeats 节奏把进度写到 dashboard —— 即使被看门狗复位, 最后一次进度也留在
 *! dashboard 上, host 据此算出"程序连续执行的最大时间"。
 */
rLANG_NOINLINE uint32_t MillerRabinContext::Endurance(uint64_t iters) {
  uint32_t checksum = 0x9e3779b9u;
  uint32_t seq = 0;
  uint64_t units = 0;

  ReportProgress(kMagicStart, seq++, 0, checksum); /* 起始记录: 区分"从未启动"与"刚启动即死" */
  for (uint64_t i = 0; i < iters; ++i) {
    checksum = checksum * 1664525u + 1013904223u;
    ++units;
    if (0 == (units % kBeatUnits)) {
      KickWDG();
      if (0 == (counter_ % kReportBeats))
        ReportProgress(kMagicAlive, seq++, units, checksum);
    }
  }
  ReportProgress(kMagicDone, seq, units, checksum); /* 正常结束记录 */
  return checksum;
}
void MillerRabinContext::KickWDG() {
#if defined(__RockeyARM__)
  ++counter_;

  if (nullptr == dongle_)
    return; /* 未注入 COS 句柄: 只能计数, 无法真正喂狗 */

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

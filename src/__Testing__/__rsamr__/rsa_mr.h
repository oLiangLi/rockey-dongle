/*! rsa_mr.h — MCU/设备约束版 1024 位 Miller–Rabin 素数搜索(定长数组, 无堆/无 .rodata 表)
 *! 配合 __Testing__dongle__ 的 RsaPrimeMR 测试项在 ukey 内执行, 以测得"找 1024 位素数"时间。
 *! 约束: 无动态分配; 常量(小素数基)以立即数/局部常量形式内联, 不建 .rodata 表;
 *!       数字=uint32[64] 小端, n=有效 limb 数(≤32 参与运算, 乘/取模临时 ≤64)。
 *!
 *! 栈优化(2026-09-13): 目标全链静态栈深 ≤2KB(不搬 SP 也可行)。
 *!   旧版所有函数 static inline, mulmod/divmod/powmod 每层各持多个 260B BN 临时,
 *!   内联进调用方叠加成 6248B(isPrimeMR 单帧 2456B)。
 *!   新版:
 *!     - MR 热路径函数全部 noinline, 各自只留小帧, 栈深按调用链相加;
 *!     - mulmod 的 product/remainder、powmodMR 的小基 bs 放进调用方传入的
 *!       MRWork(占用 ExtendBuf[1KB] 辅助区, 非栈)——测试项把 ExtendBuf 传进来即可;
 *!     - divmod 由"每步复制+移位"改为二进制逐位取模 remTo(余数原地左移+减);
 *!     - findPrime 直接在 out 上原地 +2/自检(候选即 out, 无 cand 副本);
 *!   栈上残留的最深链: Start→Testing_RsaPrimeMR→findPrimeW→isPrimeMRW(nm1/d/x
 *!   三个 BN≈0.8KB)→powmodMRW→mulmodW→remTo, 估算 ≤2KB(以 rockey-stack-check
 *!   实测为准)。MRWork 恒 ≤1KB: 每 BN=260B×3=780B, 用 static_assert 兜底。
 */
#ifndef AGINX_RSA_MR_H
#define AGINX_RSA_MR_H

#include <cstdint>
#include <cstring>

#if defined(__GNUC__) || defined(__clang__)
#define RSA_MR_NOINLINE __attribute__((noinline))
#else
#define RSA_MR_NOINLINE
#endif

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

/*! MR 工作区: product/remainder/small-base 三槽, 建议放入 ExtendBuf(≥1024B)。
 *! 三个槽的函数均在使用前完整写入(见 mulTo/remTo/powmodMRW), 故可对裸内存
 *! reinterpret_cast 使用; 也可 placement-new 以先清零。 */
struct MRWork {
  BN prod; /* 乘积 2n limb */
  BN rem;  /* 取模余数 */
  BN bs;   /* powmod 小基 */
};
static_assert(sizeof(MRWork) <= 1024, "MRWork must fit 1KB ExtendBuf");

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
  for (int b = 31; b >= 0; --b)
    if (x & (1u << b)) return 31 - b;
  return 32;
}
static inline int bitlen(const BN& a) {
  if (a.n == 1 && a.v[0] == 0) return 0;
  return (a.n - 1) * 32 + (32 - clz32(a.v[a.n - 1]));
}
static inline bool isEven(const BN& a) {
  return a.n > 0 && (a.v[0] & 1) == 0;
}
static inline bool isOne(const BN& a) {
  return a.n == 1 && a.v[0] == 1;
}
static inline bool isMax1024(const BN& a) { /* == 2^1024-1 (32 limb 全 1) */
  if (a.n != 32) return false;
  for (int i = 0; i < 32; ++i)
    if (a.v[i] != 0xFFFFFFFFu) return false;
  return true;
}
/* 原地 +x / -x (小值, 进位/借位传播) */
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
static inline void shr1(BN& a) {
  uint32_t carry = 0;
  for (int i = a.n - 1; i >= 0; --i) {
    uint32_t nv = (a.v[i] >> 1) | (carry << 31);
    carry = a.v[i] & 1;
    a.v[i] = nv;
  }
  trim(a);
}
static inline void pow2Set(BN& a, int bit) { /* a += 2^bit */
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
/* 保留(供 seedToOdd 抬高候选用; 单次调用, 不在 MR 热路径上) */
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

/* ===================== MR 热路径核心(noinline, 小帧) ===================== */

/* r = a*b (r 必须与 a/b 不同对象; 直接写 r, 无乘积累加临时) */
static RSA_MR_NOINLINE void mulTo(BN& r, const BN& a, const BN& b) {
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

/* rr = a mod b (b>0, a 可到 64 limb 乘积; 二进制逐位: 余数原地左移+注入位+可减则减,
 * 无需被除数/除数副本, 无商) */
static RSA_MR_NOINLINE void remTo(BN& rr, const BN& a, const BN& b) {
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
    if (carry) rr.v[rr.n++] = carry;
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

/* r = a*b mod m; 允许 r 与 a/b 别名(结果最后回写). prod/rem 用工作区槽, 栈仅留小帧 */
static RSA_MR_NOINLINE void mulmodW(BN& r, const BN& a, const BN& b, const BN& m, BN& prod,
                                    BN& rem) {
  mulTo(prod, a, b);
  remTo(rem, prod, m);
  r = rem;
}

/* r = base^e mod m (MR 用, base 为小 u32 基; r 与 e/m 不同对象). bs 用工作区槽 */
static RSA_MR_NOINLINE void powmodMRW(BN& r, uint32_t base, const BN& e, const BN& m, BN& bs,
                                      BN& prod, BN& rem) {
  bs.v[0] = base; /* base < m(MR 路径已保证), 单 limb, 其余槽位不读 */
  bs.n = 1;
  r.clear();
  r.v[0] = 1;
  for (int i = bitlen(e) - 1; i >= 0; --i) {
    mulmodW(r, r, r, m, prod, rem);
    if ((e.v[i >> 5] >> (i & 31)) & 1u) mulmodW(r, r, bs, m, prod, rem);
  }
}

/* 单 limb 小整数试除素性(u32; 仅用于小值/快速路径, 无 .rodata 表) */
static inline bool smallPrimeU32(uint32_t v) {
  if (v < 2) return false;
  for (uint32_t d = 2; d <= v / d; ++d)
    if (v % d == 0) return false;
  return true;
}
/* 在栈上运行时生成前 rounds 个小素数(无 const 表 → 不进 .rodata) */
static inline int smallBases(uint32_t b[], int rounds) {
  if (rounds < 1) rounds = 1;
  if (rounds > 16) rounds = 16;
  int n = 0;
  uint32_t x = 2;
  while (n < rounds && x < 4096) {
    bool prime = true;
    for (int j = 0; j < n; ++j)
      if (x % b[j] == 0) {
        prime = false;
        break;
      }
    if (prime) b[n++] = x;
    ++x;
  }
  return n;
}

/* Miller–Rabin(n 只读; 栈上 nm1/d/x 三个 BN≈0.8KB, 其余临时用 MRWork 槽) */
static RSA_MR_NOINLINE bool isPrimeMRW(const BN& n, int rounds, MRWork& w) {
  if (n.n == 1) {
    const uint32_t v = n.v[0];
    if (v < 2) return false;
    if (v <= 0xffffffu) return smallPrimeU32(v);
  }
  if (isEven(n)) return false;

  BN nm1 = n;
  subSmall(nm1, 1);
  BN d = nm1;
  int s = 0;
  while (isEven(d)) {
    shr1(d);
    ++s;
  }
  uint32_t bases[16];
  const int cnt = smallBases(bases, rounds);
  BN x;
  for (int r = 0; r < cnt; ++r) {
    const uint32_t base = bases[r];
    if (nm1.n == 1 && base >= nm1.v[0]) continue; /* nm1≥2^32 时基必 < nm1 */
    powmodMRW(x, base, d, n, w.bs, w.prod, w.rem);
    if (isOne(x) || cmp(x, nm1) == 0) continue;
    bool witness = false;
    for (int j = 1; j < s; ++j) {
      mulmodW(x, x, x, n, w.prod, w.rem);
      if (cmp(x, nm1) == 0) {
        witness = true;
        break;
      }
      if (isOne(x)) break;
    }
    if (!witness) return false;
  }
  return true;
}

/* 从 128B 种子小端构造 1024 位奇候选(置第 1023 位); 独立帧(不在 MR 热路径上) */
static RSA_MR_NOINLINE void seedToOdd(BN& out, const uint8_t seed[128]) {
  out.clear();
  for (int i = 0; i < 128; ++i) out.v[i / 4] |= (uint32_t)seed[i] << ((i % 4) * 8);
  out.n = 32;
  trim(out);
  if (bitlen(out) < 1023) {
    BN t;
    shlK(t, out, 1023 - bitlen(out));
    out = t;
  }
  if (bitlen(out) < 1024) pow2Set(out, 1023);
  if (isEven(out)) addSmall(out, 1);
  trim(out);
}

/* 递增搜索(+2): 找到返回 true 并把素数放入 out(原地); 记录探测次数。
 * 候选在 out 上直接演化 → findPrime 帧极小。w 需调用方提供(建议 ExtendBuf 1KB)。
 * 保护: 候选到 2^1024-1 仍非素数时回绕到最小 1024 位奇候选(2^1023+1)继续,
 *       避免 +2 溢出成 1025 位(乘积会超出 64 limb 临时)。 */
static RSA_MR_NOINLINE bool findPrimeW(BN& out, const uint8_t seed[128], int rounds,
                                       long long& probes, MRWork& w,
                                       void (*progress)(long long, void*) = nullptr,
                                       void* progress_ctx = nullptr) {
  seedToOdd(out, seed);
  probes = 0;
  for (;;) {
    if (isPrimeMRW(out, rounds, w)) return true;
    if (isMax1024(out)) {
      out.clear();
      pow2Set(out, 1023); /* 2^1023 */
      addSmall(out, 1);   /* +1 → 最小 1024 位奇数 */
    }
    addSmall(out, 2);
    ++probes;
    /* 每 4 探测回报一次(WDOG 实验: 回报里调设备 GetTickCount 试探是否喂狗) */
    if (progress && (probes & 0x3) == 0) progress(probes, progress_ctx);
  }
}

} /* namespace rsa_mr */

#endif /* AGINX_RSA_MR_H */

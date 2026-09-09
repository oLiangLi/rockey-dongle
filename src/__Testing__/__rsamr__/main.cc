/*! __Testing__rsamr__: 从 128 字节种子确定性恢复 RSA 素数 p/q 的自研 Miller–Rabin 原型。
 *! 目的: 回答"在 ukey 上从随机数开始找 1024 位素数大概多久"(恢复 RSA 私钥前置于硬件
 *! RSA 生成不可用, 只能注入 2×128B 随机数后由代码自行做素性测试)。
 *! 自研部分: 32 位小端 limb 大数(加/减/乘/移/除模)、Miller–Rabin、小素数试除;
 *! 不做任何硬件 RSA / OpenSSL 依赖。e=65537; d 计算(扩展欧几里得)默认关闭(argv 传 full 打开)。
 *! 用法: __Testing__rsamr__ [rounds] [seedhex_256] [full]
 *!   rounds   MR 轮数(每候选用小素数表前 N 个作基, 默认 16)
 *!   seedhex  两段 128B(=1024 位起点)十六进制拼接, 缺省用确定性模式
 *! 输出: p/q 十六进制、命中候选序号、墙钟耗时。
 */
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <chrono>

typedef std::vector<uint32_t> BN; /* little-endian limbs */

static void trim(BN& a) {
  while (a.size() > 1 && a.back() == 0) a.pop_back();
}
static int cmp(const BN& a, const BN& b) {
  if (a.size() != b.size()) return a.size() < b.size() ? -1 : 1;
  for (size_t i = a.size(); i-- > 0;)
    if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
  return 0;
}
static int clz32(uint32_t v) {
  int n = 0;
  for (int b = 31; b >= 0; --b) {
    if (v & (1u << b)) return 31 - b;
    ++n;
  }
  return n;
}
static int bitlen(const BN& a) {
  if (a.size() == 1 && a[0] == 0) return 0;
  return (int)(a.size() - 1) * 32 + (32 - clz32(a.back()));
}
static BN add(const BN& a, const BN& b) {
  BN r(std::max(a.size(), b.size()) + 1, 0);
  uint64_t carry = 0;
  for (size_t i = 0; i < r.size(); ++i) {
    uint64_t s = carry;
    if (i < a.size()) s += a[i];
    if (i < b.size()) s += b[i];
    r[i] = (uint32_t)s;
    carry = s >> 32;
  }
  trim(r);
  return r;
}
static BN sub(const BN& a, const BN& b) { /* a>=b */
  BN r(a);
  int64_t borrow = 0;
  for (size_t i = 0; i < r.size(); ++i) {
    int64_t s = (int64_t)r[i] - (i < b.size() ? (int64_t)b[i] : 0) - borrow;
    if (s < 0) {
      s += (int64_t)1 << 32;
      borrow = 1;
    } else {
      borrow = 0;
    }
    r[i] = (uint32_t)s;
  }
  trim(r);
  return r;
}
static BN addSmall(BN a, uint32_t v) {
  uint64_t carry = v;
  for (size_t i = 0; i < a.size() && carry; ++i) {
    uint64_t s = (uint64_t)a[i] + carry;
    a[i] = (uint32_t)s;
    carry = s >> 32;
  }
  if (carry) a.push_back((uint32_t)carry);
  return a;
}
static BN subSmall(const BN& a, uint32_t v) {
  BN r = a;
  int64_t borrow = v;
  for (size_t i = 0; i < r.size() && borrow; ++i) {
    int64_t s = (int64_t)r[i] - borrow;
    if (s < 0) {
      s += (int64_t)1 << 32;
      borrow = 1;
    } else {
      borrow = 0;
    }
    r[i] = (uint32_t)s;
  }
  trim(r);
  return r;
}
static BN shlK(const BN& a, int k) { /* k>=0 bits */
  if (k == 0) return a;
  int words = k / 32, bits = k % 32;
  BN r(a.size() + words + 1, 0);
  for (size_t i = 0; i < a.size(); ++i) {
    uint64_t v = (uint64_t)a[i] << bits;
    r[i + words] |= (uint32_t)v;
    if (bits && i + words + 1 < r.size()) r[i + words + 1] |= (uint32_t)(v >> 32);
  }
  trim(r);
  return r;
}
static BN shr1(BN a) {
  uint32_t carry = 0;
  for (size_t i = a.size(); i-- > 0;) {
    uint32_t nv = (a[i] >> 1) | (carry << 31);
    carry = a[i] & 1;
    a[i] = nv;
  }
  trim(a);
  return a;
}
static bool isEven(const BN& a) {
  return a.size() > 0 && (a[0] & 1) == 0;
}
static void pow2Set(BN& a, int bit) {
  size_t limb = (size_t)(bit / 32), off = (size_t)(bit % 32);
  if (limb >= a.size()) a.resize(limb + 1, 0);
  uint64_t carry = 1ull << off;
  for (size_t i = limb; carry && i < a.size(); ++i) {
    uint64_t s = (uint64_t)a[i] + carry;
    a[i] = (uint32_t)s;
    carry = s >> 32;
  }
  if (carry) a.push_back((uint32_t)carry);
  trim(a);
}
static BN mul(const BN& a, const BN& b) {
  BN r(a.size() + b.size(), 0);
  for (size_t i = 0; i < a.size(); ++i) {
    uint64_t carry = 0;
    for (size_t j = 0; j < b.size(); ++j) {
      uint64_t s = (uint64_t)a[i] * b[j] + r[i + j] + carry;
      r[i + j] = (uint32_t)s;
      carry = s >> 32;
    }
    size_t j = b.size();
    while (carry) {
      uint64_t s = (uint64_t)r[i + j] + carry;
      r[i + j] = (uint32_t)s;
      carry = s >> 32;
      ++j;
    }
  }
  trim(r);
  return r;
}
static std::pair<BN, BN> divmod(const BN& a, const BN& b) {
  BN r = a, q(1, 0);
  while (cmp(r, b) >= 0) {
    int s = bitlen(r) - bitlen(b);
    BN bs = shlK(b, s);
    while (cmp(r, bs) < 0) {
      --s;
      if (s < 0) break;
      bs = shlK(b, s);
    }
    if (s < 0) break;
    r = sub(r, bs);
    pow2Set(q, s);
  }
  return {q, r};
}
static BN mulmod(const BN& a, const BN& b, const BN& m) {
  return divmod(mul(a, b), m).second;
}
static BN powmod(BN base, const BN& e, const BN& m) {
  base = divmod(base, m).second;
  BN r(1, 1);
  for (int i = bitlen(e) - 1; i >= 0; --i) {
    r = mulmod(r, r, m);
    if ((e[(size_t)(i / 32)] >> (i % 32)) & 1) r = mulmod(r, base, m);
  }
  return r;
}
static std::vector<uint32_t> smallPrimes(int limit) {
  std::vector<bool> comp((size_t)limit + 1, false);
  std::vector<uint32_t> out;
  for (int i = 2; i <= limit; ++i) {
    if (!comp[(size_t)i]) {
      out.push_back((uint32_t)i);
      for (long long j = (long long)i * i; j <= limit; j += i) comp[(size_t)j] = true;
    }
  }
  return out;
}
static uint32_t modU32(const BN& a, uint32_t m) {
  uint64_t r = 0;
  for (size_t i = a.size(); i-- > 0;) {
    r = ((r << 32) + a[i]) % m;
  }
  return (uint32_t)r;
}
static bool isPrimeMR(const BN& n, const std::vector<uint32_t>& primes, int rounds, std::vector<uint32_t>* used = nullptr) {
  if (isEven(n)) return false;
  for (size_t i = 0; i < primes.size() && primes[i] * (uint64_t)primes[i] <= (uint32_t)1e9; ++i) {
    /* 小候选快速路径: n 本身就是小素数表成员 */
  }
  if (cmp(n, BN{ (uint32_t)primes.back() + 2 }) <= 0) {
    for (uint32_t p : primes)
      if (cmp(n, BN{ p }) == 0) return true;
    return false;
  }
  BN d = subSmall(n, 1);
  int s = 0;
  while (isEven(d)) {
    d = shr1(d);
    ++s;
  }
  const uint32_t smalls[16] = {2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53};
  int nbase = rounds < 1 ? 1 : (rounds > 16 ? 16 : rounds);
  for (int i = 0; i < nbase; ++i) {
    uint32_t a = smalls[i];
    BN ba{ a };
    if (cmp(ba, subSmall(n, 1)) >= 0) continue;
    if (used) used->push_back(a);
    BN x = powmod(ba, d, n);
    if (cmp(x, BN{ 1 }) == 0 || cmp(x, subSmall(n, 1)) == 0) continue;
    bool witness = false;
    for (int r = 1; r < s; ++r) {
      x = mulmod(x, x, n);
      if (cmp(x, subSmall(n, 1)) == 0) {
        witness = true;
        break;
      }
      if (cmp(x, BN{ 1 }) == 0) break;
    }
    if (!witness) return false;
  }
  return true;
}

static BN fromHex(const char* h) {
  BN a;
  for (size_t i = 0; i < strlen(h); ++i) {
    int v = 0;
    char c = h[i];
    if (c >= '0' && c <= '9') v = c - '0';
    else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
    a = addSmall(shlK(a, 4), (uint32_t)v);
  }
  if (a.empty()) a.push_back(0);
  return a;
}
static void toHex(const BN& a, char* out, size_t cap) {
  char tmp[4096];
  size_t n = 0;
  BN v = a;
  while (!(v.size() == 1 && v[0] == 0) && n + 8 < sizeof(tmp) - 8) {
    uint32_t rem = modU32(v, 16);
    tmp[n++] = "0123456789abcdef"[rem];
    /* 简易除以 16: 用 divmod */
    v = divmod(v, BN{ 16 }).first;
  }
  if (n == 0) tmp[n++] = '0';
  tmp[n] = 0;
  size_t L = n;
  for (size_t i = 0; i < L; ++i) out[i] = tmp[L - 1 - i];
  out[L] = 0;
  (void)cap;
}

int main(int argc, char* argv[]) {
  int rounds = argc > 1 ? atoi(argv[1]) : 16;
  const char* seedhex = argc > 2 ? argv[2] : nullptr;
  bool do_d = argc > 3 && 0 == strcmp(argv[3], "full");

  auto primes = smallPrimes(2048);
  BN p, q;
  long long hitP = -1, hitQ = -1;

  auto search = [&](const BN& seed, BN& out, long long* hit, const char* tag) {
    BN cand = seed;
    /* 目标 1024 位: 若长度不足则把最高可用位置 1; 已满足则置第 1024 位(索引 1023) */
    if (bitlen(cand) < 1023) {
      /* 让候选中包含种子全部字节并抬高至 ~1024 位 */
      cand = shlK(cand, 1023 - bitlen(cand));
    }
    if (bitlen(cand) < 1024) pow2Set(cand, 1023);
    cand = addSmall(cand, 0);
    if (isEven(cand)) cand = addSmall(cand, 1);
    long long i = 0;
    auto t0 = std::chrono::steady_clock::now();
    std::vector<uint32_t> used;
    while (true) {
      bool trial = true;
      for (size_t k = 0; k < primes.size() && trial; ++k) {
        uint32_t pp = primes[k];
        if ((uint64_t)pp * pp > (uint64_t)1e9) break;
        if (modU32(cand, pp) == 0 && cmp(cand, BN{ pp }) != 0) trial = false;
      }
      if (trial && isPrimeMR(cand, primes, rounds, &used)) {
        out = cand;
        *hit = i;
        break;
      }
      cand = addSmall(cand, 2);
      ++i;
    }
    auto t1 = std::chrono::steady_clock::now();
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    char hex[4096];
    toHex(out, hex, sizeof(hex));
    std::printf("%s: found after %lld increments, %.0f ms, prime=%s...\n", tag, *hit, ms, hex + (strlen(hex) > 48 ? strlen(hex) - 48 : 0));
  };

  if (seedhex) {
    size_t L = strlen(seedhex);
    char buf[512];
    size_t half = L / 2;
    memcpy(buf, seedhex, half);
    buf[half] = 0;
    BN sp = fromHex(buf);
    memcpy(buf, seedhex + half, L - half);
    buf[L - half] = 0;
    BN sq = fromHex(buf);
    if (bitlen(sp) < 1023) sp = shlK(sp, 1023 - bitlen(sp));
    if (bitlen(sq) < 1023) sq = shlK(sq, 1023 - bitlen(sq));
    pow2Set(sp, 1023);
    pow2Set(sq, 1023);
    if (isEven(sp)) sp = addSmall(sp, 1);
    if (isEven(sq)) sq = addSmall(sq, 1);
    search(sp, p, &hitP, "p(seed1)");
    search(sq, q, &hitQ, "q(seed2)");
  } else {
    BN sp(4, 0), sq(4, 0);
    for (int i = 0; i < 16; ++i) {
      sp[(size_t)i % sp.size()] = (uint32_t)(i * 0x9e37 + 0x1234567u);
      sq[(size_t)i % sq.size()] = (uint32_t)(i * 0x7f4a7c15u + 0x0badc0deu);
    }
    sp = shlK(sp, 1023 - bitlen(sp));
    sq = shlK(sq, 1023 - bitlen(sq));
    pow2Set(sp, 1023);
    pow2Set(sq, 1023);
    if (isEven(sp)) sp = addSmall(sp, 1);
    if (isEven(sq)) sq = addSmall(sq, 1);
    search(sp, p, &hitP, "p(seed1)");
    search(sq, q, &hitQ, "q(seed2)");
  }

  char hp[4096], hq[4096];
  toHex(p, hp, sizeof(hp));
  toHex(q, hq, sizeof(hq));
  std::printf("p(hex)=%s\nq(hex)=%s\n", hp, hq);

  if (do_d) {
    /* e=65537; d = e^{-1} mod (p-1)(q-1); 扩展欧几里得 */
    BN phi = mul(subSmall(p, 1), subSmall(q, 1));
    BN e{ 65537 };
    BN a0 = e, a1 = phi, x0{1}, x1{0};
    while (!(a1.size() == 1 && a1[0] == 0)) {
      auto qr = divmod(a0, a1);
      BN a2 = a1, r2 = qr.second;
      /* x2 = x0 - q*x1 */
      BN x2 = sub(x0, mul(qr.first, x1));
      a0 = a2; a1 = r2; x0 = x1; x1 = x2;
    }
    /* d = x0 mod phi */
    BN d = divmod(x0, phi).second;
    char hd[4096];
    toHex(d, hd, sizeof(hd));
    std::printf("d(hex)=%s\n", hd);
  } else {
    std::printf("(d 计算默认跳过; 传 argv[3]=full 开启)\n");
  }
  return 0;
}

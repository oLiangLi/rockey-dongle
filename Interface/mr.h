#include <Interface/aginx.h>
#include <Interface/dongle.h>

AGINX_DECLARE_MACHINE

namespace dongle {

/**
 *! 用于 ukey 在设备内执行 1024/1536 位 Miller-Rabin 测试与 RSA 素数搜索, 运行也许非常的缓慢
 *
 *! 容量按 RSA-3072 的 1536 位素因子设计(kCountWords=48), 1024 位测试仍然完全可用;
 *! 这是单指令内完成整个 RSA 密钥生成(见 ai-doc/rsa-root-ca-generation-2026-09-11.md)的前提。
 */
class MillerRabinContext {
 public:
  static constexpr int kCountWords = 48;    /* 1536 bits —— RSA-3072 素因子上限 */
  static constexpr int kMinCountWords = 32; /* 允许的最小测试宽度: 1024 位 */
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

  /**
   *! RSA 素数搜索(设备内单指令完成整个密钥生成的基础): 调用方已把 bits/8 字节的
   *! 种子(设备 TRNG 或由 MASTER.SECRET 派生的字节)填进 c.v; 这里只保证候选是
   *! 严格 bits 位的奇数(最高位、最低位置 1), 之后每次 +2 直到通过 Miller-Rabin。
   *! 返回 1 = 命中素数, 0 = 超过 maxProbes 或候选越界(调用方按失败处理);
   *! probes 回传实际探测次数(期望值 ≈ ln(2^bits)/2)。
   */
  void SeedCandidate(BN& c, int bits);
  /** label: 生成进度记录里的"阶段"标记(1=p, 2=q), 便于中途失败时定位死在哪一步 */
  int FindPrime(BN& out, int bits, int rounds, uint64_t maxProbes, uint64_t& probes, uint32_t label = 0);

  /**
   *! 长跑/看门狗耐久测试(设备内执行): 定工作量循环 + 周期性 KickWDG, 用来验证
   *! "只要定时喂狗, 单次执行可以跑几小时"这一前提(设备内 GetTickCount 不自走,
   *! 时长只能由 host 侧墙钟测量)。返回迭代校验和, Heartbeats() 回传喂狗次数。
   */
  uint32_t Endurance(uint64_t iters);
  uint32_t Heartbeats() const { return counter_; }

  /**
   *! 长跑进度记录: 设备端按周期写入 dashboard[kProgressOffset], 即使被看门狗复位,
   *! 最后一次进度也在 dashboard 上 —— host 读回即可算出"程序连续执行的最大时间"。
   */
  struct Progress {
    uint32_t magic;    /* kMagicStart / kMagicAlive / kMagicDone */
    uint32_t seq;      /* 写入序号(单调递增, 判断进度是否还在推进) */
    uint32_t units_lo; /* 已完成迭代数 */
    uint32_t units_hi;
    uint32_t beats; /* KickWDG 次数(= COS 心跳次数) */
    uint32_t checksum;
    uint32_t result; /* 最近一次 WriteDataFile 返回(0xFFFFFFFF = 未调用) */
    uint32_t spare;
  };
  static constexpr uint32_t kProgressOffset = 4096;   /* 测试用进度区: 避开 [0,4096) 证书与 [5120,6144) CA blob */
  static constexpr uint32_t kMagicStart = 0x7473524d; /* 'MRst' */
  static constexpr uint32_t kMagicAlive = 0x6e75524d; /* 'MRun' */
  static constexpr uint32_t kMagicDone = 0x6e64524d;  /* 'MRdn' */
  static constexpr uint64_t kBeatUnits = 1u << 16;    /* 每 2^16 个单位喂一次狗(≈10-60ms, 实测单位耗时后校准) */
  static constexpr uint32_t kReportBeats = 2048;      /* 每 2048 次喂狗写一次 dashboard(≈30s) */
  void ReportProgress(uint32_t magic, uint32_t seq, uint64_t units, uint32_t checksum);

  /**
   *! RSA 素数生成(设备内单指令)的结果落盘布局 —— 全部在 dashboard 的测试区:
   *!   [kProgressOffset, +64)  = 长跑进度记录 Progress(mode 4 用)
   *!   [kGenStatusOffset, +64) = 生成状态 GenResult(生成结束时最后写, 作为完成标志)
   *!   [kGenPOffset, +192)     = p(小端, ≤1536 位); [kGenQOffset, +192) = q
   *!   [kGenSeedPOffset,+192)  = p 的搜索起点种子; [kGenSeedQOffset,+192) = q 的
   *! 前两者在 4K..5K(未分配测试区), 种子在 0..4K 匿名用户区 —— 不碰 5K 起的 CA blob。
   */
  struct GenResult {
    uint32_t magic;       /* kMagicGenDone */
    uint32_t bits;        /* 实际位宽 1024/1536 */
    uint32_t rounds;      /* MR 轮数 */
    uint32_t ok;          /* bit0 = p 命中素数并已落盘, bit1 = q */
    uint32_t probes_p_lo; /* p 的探测次数 */
    uint32_t probes_p_hi;
    uint32_t probes_q_lo;
    uint32_t probes_q_hi;
  };
  static constexpr uint32_t kGenStatusOffset = 4096; /* 与 kProgressOffset 同一测试区(同一时刻只用其一) */
  static constexpr uint32_t kGenPOffset = 4160;
  static constexpr uint32_t kGenQOffset = 4544;
  static constexpr uint32_t kGenSeedPOffset = 2048; /* 匿名用户区(0..4K) */
  static constexpr uint32_t kGenSeedQOffset = 2304;
  static constexpr uint32_t kMagicGenDone = 0x6e65474d; /* 'MGen' */

  void KickWDG();
  void InitSmallBases();

  /**
   *! 设备侧 KickWDG 需要 COS 句柄(SetLEDState/GetTickCount); host 侧可缺省
   */
  void SetDongle(Dongle* dongle) { dongle_ = dongle; }

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
    if (limb < 0 || limb >= kCountWords * 2)
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
  /*! a -= b(要求 a >= b); 用于在 Montgomery 域内由 one_m_ 直接得到 nm1_m_ = n - one_m_ */
  void subEq(BN& a, const BN& b);

 protected:
  /**
   *! one_m_/nm1_m_ 放类成员而不是栈: k=48 时单个 BN 已是 388B, 若与 d/base_m/x
   *! 一起放栈会顶穿 2032B 的设备栈; 代价是每个候选重新转换一次(可忽略)。
   */
  BN one_m_; /* R mod n */
  BN nm1_m_; /* -R mod n (= Montgomery 域的 n-1) */

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

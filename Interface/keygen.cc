#include "keygen.h"

AGINX_DECLARE_MACHINE

namespace dongle {

static constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("KEYGN");

namespace {

using limb_t = RsaModexp::limb_t;

/*! 定长 k limb 减 1(要求 a > 0) */
void SubOneK(limb_t* a, int k) {
  for (int i = 0; i < k; ++i) {
    if (0 != a[i]) {
      --a[i];
      return;
    }
    a[i] = 0xFFFFFFFFu; /* 借位继续 */
  }
}

/*! out(wk limb) = a(wk limb) * m + add, 返回最高进位(out 装不下的部分) */
limb_t MulSmallAdd(limb_t* out, const limb_t* a, int wk, uint32_t m, uint32_t add) {
  uint64_t carry = add;
  for (int i = 0; i < wk; ++i) {
    const uint64_t s = static_cast<uint64_t>(a[i]) * m + carry;
    out[i] = static_cast<uint32_t>(s);
    carry = s >> 32;
  }
  return static_cast<limb_t>(carry);
}

/*! out(wk limb) = a(wk limb) / d, 返回余数; hi 为 a 之上那一个 limb(小除数长除的入口余数)。
 *! out 可与 a 别名: 自高位向低位逐 limb 原地写入。 */
limb_t DivSmall(limb_t* out, const limb_t* a, int wk, uint32_t d, limb_t hi) {
  uint64_t rem = hi;
  for (int i = wk; i-- > 0;) {
    const uint64_t cur = (rem << 32) | a[i];
    out[i] = static_cast<limb_t>(cur / d);
    rem = cur % d;
  }
  return static_cast<limb_t>(rem);
}

/*! a mod m(m 小到可以逐 limb 折叠): 不需要长除 */
limb_t ModSmall(const limb_t* a, int wk, uint32_t m) {
  uint64_t r = 0;
  for (int i = wk; i-- > 0;)
    r = ((r << 32) | a[i]) % m;
  return static_cast<limb_t>(r);
}

/*! 小模数模逆(模 m 为素数 ⇒ Fermat: a^{m-2} mod m) */
limb_t ModInvSmallPrime(limb_t a, uint32_t m) {
  uint64_t base = static_cast<uint64_t>(a) % m;
  uint64_t result = 1;
  uint32_t e = m - 2;
  while (e) {
    if (e & 1u)
      result = (result * base) % m;
    base = (base * base) % m;
    e >>= 1;
  }
  return static_cast<limb_t>(result);
}

/*! 读字段: cipherKeyId != 0 时读出后**逐字段 ECB 解密**(KeyBlob 各字段偏移/长度都是 16 的倍数,
 *! 所以可以按块随机解密, 明文永不整体进 RAM)。 */
int ReadField(Dongle& dongle, int keyFile, uint32_t off, void* buf, size_t size, int cipherKeyId) {
  if (0 != dongle.ReadDataFile(keyFile, off, buf, size))
    return -EIO;
  if (cipherKeyId) {
    if (0 != (size % 16))
      return -EINVAL;
    if (0 != dongle.SM4ECB(cipherKeyId, static_cast<uint8_t*>(buf), size, false))
      return -EIO;
  }
  return 0;
}

/*! 写字段: cipherKeyId != 0 时**就地** ECB 加密后再写 —— 调用方必须保证该缓冲此后不再当明文用 */
int WriteField(Dongle& dongle, int keyFile, uint32_t off, uint8_t* buf, size_t size, int cipherKeyId) {
  if (cipherKeyId) {
    if (0 != (size % 16))
      return -EINVAL;
    if (0 != dongle.SM4ECB(cipherKeyId, buf, size, true))
      return -EIO;
  }
  return dongle.WriteDataFile(keyFile, off, buf, size);
}

}  // namespace

/**
 *! 内存布局(1KB arena, 峰值 968B; 全部 4 字节对齐):
 *!   阶段 1(搜索):[0, 512) MillerRabinContext,[512, 512+sizeof(BN)) 候选(= 就地演化的 p / q)
 *!   阶段 2(组装):P = [0, hk)  p / p-1、Q = [hk, 2hk) q / q-1 / dmp1/dmq1 输出、
 *!                W = [wk, 2wk) n / m / d(与 P/Q 不重叠)、
 *!                iqmp 阶段重新排: base=q@0、mod=p@hk、exp=p-2@2hk、t@3hk、out@3hk+(hk+2)
 *! 之所以能这么省: d 用 (p-1)(q-1) 而不是 lcm(p-1,q-1)(见 keygen.h), 于是不需要 3072 位模逆;
 *! iqmp 用 Fermat(p 是素数)调 HalfModExp, 于是也不需要一半宽的二进制扩展欧几里得。
 */
int RsaKeyGen::Generate(Dongle& dongle,
                        int keyFile,
                        uint32_t keyOffset,
                        const uint8_t* seed,
                        int bits,
                        int rounds,
                        int cipherKeyId,
                        Arena& arena) {
  if (nullptr == seed)
    return -EINVAL;
  if (bits != kMinBits && bits != kMaxBits)
    return -EINVAL;
  if (rounds < 1 || rounds > MillerRabinContext::kMaxRounds)
    rounds = MillerRabinContext::kMaxRounds;

  const int hk = bits / 64; /* 素因子 limb: 2048→32 / 3072→48 */
  const int wk = bits / 32; /* 全宽 limb:   2048→64 / 3072→96 */
  const int hb = bits / 16; /* 素因子字节 */
  const int wb = bits / 8;  /* 全宽字节 */

  uint8_t* const A = reinterpret_cast<uint8_t*>(&arena.limb[0]);
  memset(A, 0, sizeof(Arena));

  int rc = 0;
  do {
    /* ---------------- 阶段 1: 搜 p / q(设备内, 与 rsa-prime-repro.cjs 逐位对齐) ---------------- */
    {
      constexpr int kCandOffset = 512;
      rLANG_ABIREQUIRE(sizeof(MillerRabinContext) <= kCandOffset);
      rLANG_ABIREQUIRE(kCandOffset + sizeof(MillerRabinContext::BN) <= sizeof(Arena));

      MillerRabinContext* const mr = reinterpret_cast<MillerRabinContext*>(A);
      MillerRabinContext::BN* const cand = reinterpret_cast<MillerRabinContext::BN*>(A + kCandOffset);
      mr->SetDongle(&dongle);
      mr->InitSmallBases();

      for (int i = 0; i < 2; ++i) {
        cand->clear(); /* 不用 memset: BN 有默认成员初始化, memset 会触发 -Wclass-memaccess */
        memcpy(&cand->v[0], seed + static_cast<size_t>(i) * static_cast<size_t>(hb), static_cast<size_t>(hb));
        cand->n = hk; /* 候选宽度 = 种子宽度(FindPrime 只保证最高位/最低位) */
        uint64_t probes = 0;
        /* label = 1(p) / 2(q): 与测试口径一致 —— 每 32 次探测往 dashboard 落一条进度记录
         * (magic 'MRun', seq=label, units=已探测数), 长跑期间 host 可用 `-2 19 5` 只读观察
         * "到底还在推进还是在某处卡住"; 该记录同时是一次 COS 调用(额外的喂狗)。
         * 注意: 不要把 label 设成 0 —— 那会同时去掉这条可观测性与隐含心跳(见 mr.cc 注释)。 */
        if (mr->FindPrime(*cand, bits / 2, rounds, kMaxProbes, probes, static_cast<uint32_t>(i + 1)) <= 0) {
          rc = -ERANGE; /* 探测超限/候选越界: 按失败处理, 绝不无限搜索 */
          break;
        }
        const uint32_t off = (0 == i) ? RsaModexp::KeyBlob::POffset(bits) : RsaModexp::KeyBlob::QOffset(bits);
        /* cipherKeyId != 0 时就地加密候选: p 之后候选会被 q 的种子完全重写, 不影响后续 ✓ */
        if (0 != WriteField(dongle, keyFile, keyOffset + off, reinterpret_cast<uint8_t*>(&cand->v[0]),
                            static_cast<size_t>(hb), cipherKeyId)) {
          rc = -EIO;
          break;
        }
      }
      if (0 != rc)
        break;
    }

    limb_t* const P = reinterpret_cast<limb_t*>(A);
    limb_t* const Q = reinterpret_cast<limb_t*>(A + hk * 4);
    limb_t* const W = reinterpret_cast<limb_t*>(A + wk * 4);
    dongle.KickWDG(); /* 组装阶段的显式心跳: 基类方法, 任何长循环都可以直接调(见 Dongle::KickWDG) */

    /* (a) n = p*q */
    if (0 != ReadField(dongle, keyFile, keyOffset + RsaModexp::KeyBlob::POffset(bits), P, static_cast<size_t>(hb), cipherKeyId) ||
        0 != ReadField(dongle, keyFile, keyOffset + RsaModexp::KeyBlob::QOffset(bits), Q, static_cast<size_t>(hb), cipherKeyId)) {
      rc = -EIO;
      break;
    }
    RsaModexp::MulAddK(W, P, Q, hk, nullptr); /* 2*hk = wk limb */
    if (0 != WriteField(dongle, keyFile, keyOffset + RsaModexp::KeyBlob::NOffset(bits), reinterpret_cast<uint8_t*>(W),
                        static_cast<size_t>(wb), cipherKeyId)) {
      rc = -EIO;
      break;
    }

    /* (b) m = (p-1)*(q-1) */
    SubOneK(P, hk);
    SubOneK(Q, hk);
    RsaModexp::MulAddK(W, P, Q, hk, nullptr);

    /* (c) d = (1 + k*m) / e, 其中 k ≡ -m^{-1} (mod e) ⇒ e*d ≡ 1 (mod m) 且 d < m < n */
    {
      const limb_t rem = ModSmall(W, wk, kE);
      if (0 == rem) {
        rc = -EINVAL; /* 不可能: e 为素数且不整除 p-1 / q-1 */
        break;
      }
      const uint32_t kk = kE - ModInvSmallPrime(rem, kE); /* ∈ [1, e-1] */
      limb_t* const prod = reinterpret_cast<limb_t*>(A); /* wk limb: 覆盖 P/Q(p、q 已无用) */
      const limb_t hi = MulSmallAdd(prod, W, wk, kk, 1u);
      if (0 != DivSmall(W, prod, wk, kE, hi)) { /* 商原地写回 W: m 已无用 */
        rc = -EINVAL;
        break;
      }
    }
    /* W = d 到此为止; **先不写盘**: 下面的 dmp1/dmq1 还要用 W 里的明文 d(就地加密会毁掉它),
     * 因此 d 的写盘挪到 dmp1/dmq1 之后 —— 那时 d 已不再被使用。 */

    /* (d)(e) dmp1 = d mod (p-1)、dmq1 = d mod (q-1) */
    for (int i = 0; i < 2; ++i) {
      const uint32_t in_off = (0 == i) ? RsaModexp::KeyBlob::POffset(bits) : RsaModexp::KeyBlob::QOffset(bits);
      const uint32_t out_off = (0 == i) ? RsaModexp::KeyBlob::Dmp1Offset(bits) : RsaModexp::KeyBlob::Dmq1Offset(bits);
      if (0 != ReadField(dongle, keyFile, keyOffset + in_off, P, static_cast<size_t>(hb), cipherKeyId)) {
        rc = -EIO;
        break;
      }
      SubOneK(P, hk);                          /* P = p-1 / q-1 */
      RsaModexp::ModReduce(Q, W, wk, P, hk);    /* Q(输出)不得与 W(被除数)别名 */
      if (0 != WriteField(dongle, keyFile, keyOffset + out_off, reinterpret_cast<uint8_t*>(Q),
                          static_cast<size_t>(hb), cipherKeyId)) {
        rc = -EIO;
        break;
      }
    }
    if (0 != rc)
      break;

    /* d 已不再被使用 ⇒ 现在就地加密写盘 */
    if (0 != WriteField(dongle, keyFile, keyOffset + RsaModexp::KeyBlob::DOffset(bits),
                        reinterpret_cast<uint8_t*>(W), static_cast<size_t>(wb), cipherKeyId)) {
      rc = -EIO;
      break;
    }

    /* (f) iqmp = q^{p-2} mod p(Fermat: p 为素数 ⇒ q^{p-1} ≡ 1) */
    {
      limb_t* const base = reinterpret_cast<limb_t*>(A);
      limb_t* const mod = reinterpret_cast<limb_t*>(A + hk * 4);
      uint8_t* const exp = A + 2 * hk * 4;
      limb_t* const t = reinterpret_cast<limb_t*>(A + 3 * hk * 4);
      limb_t* const out = reinterpret_cast<limb_t*>(A + (4 * hk + 2) * 4);
      rLANG_ABIREQUIRE((5 * 48 + 2) * 4 <= sizeof(Arena));

      /* exp 区容量恰 hk limb: 先当 limb 数组读入 p 并减 2 ⇒ 指数 = p-2(小端字节序与 limb 同) */
      limb_t* const exp_limbs = reinterpret_cast<limb_t*>(exp);
      if (0 != ReadField(dongle, keyFile, keyOffset + RsaModexp::KeyBlob::POffset(bits), exp_limbs, static_cast<size_t>(hb), cipherKeyId) ||
          0 != ReadField(dongle, keyFile, keyOffset + RsaModexp::KeyBlob::QOffset(bits), base, static_cast<size_t>(hb), cipherKeyId) ||
          0 != ReadField(dongle, keyFile, keyOffset + RsaModexp::KeyBlob::POffset(bits), mod, static_cast<size_t>(hb), cipherKeyId)) {
        rc = -EIO;
        break;
      }
      SubOneK(exp_limbs, hk);
      SubOneK(exp_limbs, hk);

      RsaModexp rsa;
      rsa.SetDongle(&dongle);
      dongle.KickWDG(); /* iqmp 是 2*k 位指数的模幂(1024/1536 位指数), 入口先喂一次 */
      rc = rsa.HalfModExp(out, base, exp, hb, mod, hk, t);
      if (0 != rc)
        break;
      if (0 != WriteField(dongle, keyFile, keyOffset + RsaModexp::KeyBlob::IqmpOffset(bits),
                          reinterpret_cast<uint8_t*>(out), static_cast<size_t>(hb), cipherKeyId)) {
        rc = -EIO;
        break;
      }
    }

    /* (g) e 字段: 小端定长, 65537 = 0x010001 */
    {
      memset(A, 0, static_cast<size_t>(wb));
      A[0] = 0x01;
      A[2] = 0x01;
      if (0 != WriteField(dongle, keyFile, keyOffset + RsaModexp::KeyBlob::EOffset(bits), A,
                          static_cast<size_t>(wb), cipherKeyId)) {
        rc = -EIO;
        break;
      }
    }

    /* (h) header 最后写: magic 'RSAK' 出现即表示整套字段已就绪(半成品可按 magic 识别) */
    {
      RsaModexp::KeyBlobHeader hdr{};
      hdr.magic = RsaModexp::KeyBlob::kMagic;
      hdr.bits = static_cast<uint32_t>(bits);
      hdr.flags = RsaModexp::KeyBlob::kFlagCrt;
      hdr.reserved = 0;
      if (0 != WriteField(dongle, keyFile, keyOffset, reinterpret_cast<uint8_t*>(&hdr), sizeof(hdr), cipherKeyId)) {
        rc = -EIO;
        break;
      }
    }
  } while (0);

  memset(A, 0, sizeof(Arena)); /* 私钥材料不留在内存(设备侧 ExtendBuf 会被后续指令复用) */
  rlLOGI(TAG, "RsaKeyGen bits=%d rc=%d", bits, rc);
  return rc;
}

}  // namespace dongle

AGINX_DECLARE_END

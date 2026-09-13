#include "modexp.h"

AGINX_DECLARE_MACHINE

namespace dongle {

static constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("MODXP");

/*! 定长 k limb 比较(小端): <0 / 0 / >0 */
static int CmpK(const RsaModexp::limb_t* a, const RsaModexp::limb_t* b, int k) {
  for (int i = k; i-- > 0;) {
    if (a[i] != b[i])
      return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}

/*! a -= b(定长 k limb, 要求 a >= b) */
static void SubEqK(RsaModexp::limb_t* a, const RsaModexp::limb_t* b, int k) {
  int64_t borrow = 0;
  for (int i = 0; i < k; ++i) {
    int64_t d = static_cast<int64_t>(a[i]) - static_cast<int64_t>(b[i]) - borrow;
    if (d < 0) {
      d += static_cast<int64_t>(1) << 32;
      borrow = 1;
    } else {
      borrow = 0;
    }
    a[i] = static_cast<uint32_t>(d);
  }
}

/*! 指数的有效位长: 跳过前导零字节, 再剥掉最高字节内的前导 0 比特(左到右二进制幂以 r = base
 *! 起步, 它对应**最高有效位 1**; 不剥就会多算若干平方, 得到 base 的错误幂次)。 */
static int ExpBitLength(const uint8_t* exp, int expBytes) {
  int top = expBytes;
  while (top > 0 && 0 == exp[top - 1])
    --top;
  if (0 == top)
    return 0;
  int bits = top * 8;
  while (bits > 1 && 0 == ((exp[(bits - 1) >> 3] >> ((bits - 1) & 7)) & 1u))
    --bits;
  return bits;
}

uint32_t RsaModexp::N0Inv(uint32_t n0) {
  uint32_t x = 1;
  for (int i = 0; i < 5; ++i)
    x *= 2u - n0 * x;
  return 0u - x;
}

/*! CIOS: r = a*b*R^{-1} mod n(与 Interface/mr.cc 同算法, 但临时区由调用方给出) */
void RsaModexp::MontMul(limb_t* r,
                        const limb_t* a,
                        const limb_t* b,
                        const limb_t* n,
                        int k,
                        uint32_t n0inv,
                        limb_t* t) {
  for (int i = 0; i < k + 2; ++i)
    t[i] = 0;

  for (int i = 0; i < k; ++i) {
    const uint32_t bi = b[i];
    uint64_t c = 0;
    for (int j = 0; j < k; ++j) {
      const uint64_t s = static_cast<uint64_t>(a[j]) * bi + t[j] + c;
      t[j] = static_cast<uint32_t>(s);
      c = s >> 32;
    }
    const uint64_t s2 = static_cast<uint64_t>(t[k]) + c;
    t[k] = static_cast<uint32_t>(s2);
    t[k + 1] = static_cast<uint32_t>(s2 >> 32);

    const uint32_t m = t[0] * n0inv; /* m = t0 * (-n^{-1}) mod 2^32 */
    c = (static_cast<uint64_t>(t[0]) + static_cast<uint64_t>(m) * n[0]) >> 32;
    for (int j = 1; j < k; ++j) {
      const uint64_t s = static_cast<uint64_t>(m) * n[j] + t[j] + c;
      t[j - 1] = static_cast<uint32_t>(s);
      c = s >> 32;
    }
    const uint64_t s3 = static_cast<uint64_t>(t[k]) + c;
    t[k - 1] = static_cast<uint32_t>(s3);
    t[k] = t[k + 1] + static_cast<uint32_t>(s3 >> 32);
  }

  /* 结果 < 2n → 条件减一次 n */
  bool ge = (t[k] != 0);
  if (!ge) {
    int j = k - 1;
    for (; j >= 0; --j) {
      if (t[j] != n[j]) {
        ge = (t[j] > n[j]);
        break;
      }
    }
    if (j < 0)
      ge = true; /* 相等 */
  }
  if (ge) {
    int64_t borrow = 0;
    for (int j = 0; j < k; ++j) {
      int64_t d = static_cast<int64_t>(t[j]) - static_cast<int64_t>(n[j]) - borrow;
      if (d < 0) {
        d += static_cast<int64_t>(1) << 32;
        borrow = 1;
      } else {
        borrow = 0;
      }
      t[j] = static_cast<uint32_t>(d);
    }
  }

  for (int j = 0; j < k; ++j)
    r[j] = t[j];
}

/*! 原地 a = a*R mod n(k*32 次倍增 + 条件减); 要求 a < n */
void RsaModexp::ToMont(limb_t* a, const limb_t* n, int k) {
  const int bits = 32 * k;
  for (int i = 0; i < bits; ++i) {
    uint32_t carry = 0;
    for (int j = 0; j < k; ++j) {
      const uint64_t s = (static_cast<uint64_t>(a[j]) << 1) | carry;
      a[j] = static_cast<uint32_t>(s);
      carry = static_cast<uint32_t>(s >> 32);
    }
    /* 定长 k limb: 越出最高 limb 即 a >= 2^{32k} > n, 必减 n; 且 a < 2n ⇒ 一次足够 */
    if (carry || CmpK(a, n, k) >= 0)
      SubEqK(a, n, k);
  }
}

/*! 原地 a = a*R^{-1} mod n(k*32 次半减, 奇数先补 n); 要求 a < n */
void RsaModexp::FromMont(limb_t* a, const limb_t* n, int k) {
  const int bits = 32 * k;
  for (int i = 0; i < bits; ++i) {
    uint32_t top = 0;
    if (a[0] & 1u) { /* a += n(a < n ⇒ a+n < 2n, 最多越出 1 位) */
      uint64_t c = 0;
      for (int j = 0; j < k; ++j) {
        const uint64_t s = static_cast<uint64_t>(a[j]) + n[j] + c;
        a[j] = static_cast<uint32_t>(s);
        c = s >> 32;
      }
      top = static_cast<uint32_t>(c);
    }
    for (int j = 0; j < k - 1; ++j)
      a[j] = (a[j] >> 1) | (a[j + 1] << 31);
    a[k - 1] = (a[k - 1] >> 1) | (top << 31);
  }
}

/*! r = (a - b) mod n(定长 k limb) */
void RsaModexp::SubModK(limb_t* r, const limb_t* a, const limb_t* b, const limb_t* n, int k) {
  int64_t borrow = 0;
  for (int i = 0; i < k; ++i) {
    int64_t d = static_cast<int64_t>(a[i]) - static_cast<int64_t>(b[i]) - borrow;
    if (d < 0) {
      d += static_cast<int64_t>(1) << 32;
      borrow = 1;
    } else {
      borrow = 0;
    }
    r[i] = static_cast<uint32_t>(d);
  }
  if (borrow) { /* a < b ⇒ 结果加回 n */
    uint64_t c = 0;
    for (int i = 0; i < k; ++i) {
      const uint64_t s = static_cast<uint64_t>(r[i]) + n[i] + c;
      r[i] = static_cast<uint32_t>(s);
      c = s >> 32;
    }
  }
}

/*! r = a mod n: 逐位 shift-subtract(r 不得与 a 别名) */
void RsaModexp::ModReduce(limb_t* r, const limb_t* a, int aWords, const limb_t* n, int k) {
  for (int i = 0; i < k; ++i)
    r[i] = 0;
  for (int bit = aWords * 32 - 1; bit >= 0; --bit) {
    uint32_t carry = (a[bit >> 5] >> (bit & 31)) & 1u;
    for (int j = 0; j < k; ++j) {
      const uint64_t s = (static_cast<uint64_t>(r[j]) << 1) | carry;
      r[j] = static_cast<uint32_t>(s);
      carry = static_cast<uint32_t>(s >> 32);
    }
    if (carry || CmpK(r, n, k) >= 0)
      SubEqK(r, n, k);
  }
}

/*! out(2k) = a*b + addend */
void RsaModexp::MulAddK(limb_t* out, const limb_t* a, const limb_t* b, int k, const limb_t* addend) {
  for (int i = 0; i < 2 * k; ++i)
    out[i] = 0;

  for (int i = 0; i < k; ++i) {
    uint64_t c = 0;
    for (int j = 0; j < k; ++j) {
      const uint64_t s = static_cast<uint64_t>(a[i]) * b[j] + out[i + j] + c;
      out[i + j] = static_cast<uint32_t>(s);
      c = s >> 32;
    }
    int idx = i + k;
    while (c) { /* 进位向后传播(乘积恰好落在 2k 个 limb 内) */
      const uint64_t s = static_cast<uint64_t>(out[idx]) + c;
      out[idx] = static_cast<uint32_t>(s);
      c = s >> 32;
      ++idx;
    }
  }

  if (addend) {
    uint64_t c = 0;
    for (int i = 0; i < k; ++i) {
      const uint64_t s = static_cast<uint64_t>(out[i]) + addend[i] + c;
      out[i] = static_cast<uint32_t>(s);
      c = s >> 32;
    }
    for (int i = k; c && i < 2 * k; ++i) {
      const uint64_t s = static_cast<uint64_t>(out[i]) + c;
      out[i] = static_cast<uint32_t>(s);
      c = s >> 32;
    }
  }
}

void RsaModexp::KickWDG() {
#if defined(__RockeyARM__)
  ++counter_;

  if (nullptr == dongle_)
    return; /* 未注入 COS 句柄: 只能计数, 无法真正喂狗 */

  dongle_->SetLEDState(counter_ & 1 ? LED_STATE::kOn : LED_STATE::kOff);

  /*! 仅设置 LED 状态并不生效, 需要一次有效的 COS 调用 */
#if 1
  DWORD ticks = 0;
  std::ignore = dongle_->GetTickCount(&ticks);
#endif
#else  /* __RockeyARM__ */
  ++counter_;
  std::ignore = TAG;
#endif /* __RockeyARM__ */
}

/*! 平方乘核心: r = base_m^exp mod n(base_m 已在 Montgomery 域且只读; r 与 base_m 不同缓冲) */
void RsaModexp::ModexpCore(limb_t* r,
                           const limb_t* base_m,
                           const uint8_t* exp,
                           int expBits,
                           const limb_t* n,
                           int k,
                           uint32_t n0inv,
                           limb_t* t) {
  memcpy(r, base_m, sizeof(limb_t) * static_cast<size_t>(k));
  for (int i = expBits - 2; i >= 0; --i) {
    MontMul(r, r, r, n, k, n0inv, t);
    if ((exp[i >> 3] >> (i & 7)) & 1u)
      MontMul(r, r, base_m, n, k, n0inv, t);
    if ((i % kKickSquarings) == 0)
      KickWDG(); /* 周期性 COS 心跳: 长计算必须被服务, 否则设备会被挂起 */
  }
}

int RsaModexp::ModExp(limb_t* out,
                      const limb_t* base,
                      const uint8_t* exp,
                      int expBytes,
                      const limb_t* n,
                      int k,
                      Workspace& ws) {
  if (!out || !base || !exp || !n)
    return -EINVAL;
  if (k < kMinWords || k > kMaxWords || expBytes < 0)
    return -EINVAL;
  if (0 == n[k - 1])
    return -EINVAL; /* 模数必须恰 k limb */
  if (0 == (n[0] & 1u))
    return -EINVAL; /* Montgomery 要求奇模数 */

  const int expBits = ExpBitLength(exp, expBytes);
  if (0 == expBits) { /* exp == 0 ⇒ out = 1(mod n), n > 1 */
    memset(out, 0, sizeof(limb_t) * static_cast<size_t>(k));
    out[0] = 1;
    return 0;
  }

  /* 底数复制到工作区并归约到 [0, n): 允许 base < 9n, 超出即报错 */
  memcpy(ws.acc, base, sizeof(limb_t) * static_cast<size_t>(k));
  for (int guard = 0; CmpK(ws.acc, n, k) >= 0; ++guard) {
    if (guard >= 8)
      return -ERANGE;
    SubEqK(ws.acc, n, k);
  }

  const uint32_t n0inv = N0Inv(n[0]);
  ToMont(ws.acc, n, k); /* acc = base*R mod n */
  ModexpCore(out, ws.acc, exp, expBits, n, k, n0inv, ws.t);
  FromMont(out, n, k); /* out = out*R^{-1} mod n */
  return 0;
}

int RsaModexp::HalfModExp(limb_t* out,
                          limb_t* base,
                          const uint8_t* exp,
                          int expBytes,
                          const limb_t* n,
                          int k,
                          limb_t* t) {
  if (!out || !base || !exp || !n || !t || out == base)
    return -EINVAL;
  if (k < 1 || k > kHalfWords || expBytes < 0)
    return -EINVAL;
  if (0 == n[k - 1] || 0 == (n[0] & 1u))
    return -EINVAL;

  const int expBits = ExpBitLength(exp, expBytes);
  if (0 == expBits) {
    memset(out, 0, sizeof(limb_t) * static_cast<size_t>(k));
    out[0] = 1;
    return 0;
  }

  /* base 就地归约到 [0, n)(允许 base < 9n) */
  for (int guard = 0; CmpK(base, n, k) >= 0; ++guard) {
    if (guard >= 8)
      return -ERANGE;
    SubEqK(base, n, k);
  }

  const uint32_t n0inv = N0Inv(n[0]);
  ToMont(base, n, k);
  ModexpCore(out, base, exp, expBits, n, k, n0inv, t);
  FromMont(out, n, k);
  return 0;
}

void RsaModexp::CrtCombine(limb_t* out,
                           const limb_t* s1,
                           const limb_t* s2,
                           const limb_t* p,
                           const limb_t* q,
                           limb_t* iqmp,
                           int k,
                           limb_t* tmp,
                           limb_t* t) {
  SubModK(tmp, s1, s2, p, k); /* tmp = (s1 - s2) mod p */
  ToMont(tmp, p, k);
  ToMont(iqmp, p, k);
  MontMul(tmp, iqmp, tmp, p, k, N0Inv(p[0]), t); /* tmp = (s1-s2)*iqmp*R */
  FromMont(tmp, p, k);                           /* tmp = h */
  MulAddK(out, q, tmp, k, s2);                   /* out = q*h + s2 = base^d mod n, 且 < n */
}

/*! 读 blob 头并做基本校验 */
static int ReadKeyHeader(Dongle& dongle, int keyFile, uint32_t keyOffset, int bits, RsaModexp::KeyBlobHeader& hdr) {
  if (0 != dongle.ReadDataFile(keyFile, keyOffset, &hdr, sizeof(hdr)))
    return -EIO;
  if (hdr.magic != RsaModexp::KeyBlob::kMagic || hdr.bits != static_cast<uint32_t>(bits) ||
      0 == (hdr.flags & RsaModexp::KeyBlob::kFlagCrt))
    return -EBADMSG;
  return 0;
}

/*! 校验 q*iqmp ≡ 1 (mod p): 进入时 ws.a=p、ws.b=q; 出口 ws.b=iqmp(已被转换过, 需重读) */
static int CheckIqmp(Dongle& dongle, int keyFile, uint32_t keyOffset, int bits, RsaModexp::CrtWorkspace& ws, int hw) {
  const int hb = bits / 16;
  RsaModexp::ModReduce(ws.c, ws.b, hw, ws.a, hw); /* c = q mod p */
  if (0 != dongle.ReadDataFile(keyFile, keyOffset + RsaModexp::KeyBlob::IqmpOffset(bits), ws.b, hb))
    return -EIO;
  RsaModexp::ToMont(ws.c, ws.a, hw);
  RsaModexp::ToMont(ws.b, ws.a, hw);
  RsaModexp::MontMul(ws.b, ws.c, ws.b, ws.a, hw, RsaModexp::N0Inv(ws.a[0]), ws.t);
  RsaModexp::FromMont(ws.b, ws.a, hw);
  for (int i = 0; i < hw; ++i) {
    if (ws.b[i] != (0 == i ? 1u : 0u))
      return -EBADMSG;
  }
  return 0;
}

/*! 校验 p*q == n: ws.a=p、ws.b=q; prod 为 2*hw limb(通常借用 out 或 scratch) */
static int CheckModulus(Dongle& dongle,
                        int keyFile,
                        uint32_t keyOffset,
                        int bits,
                        RsaModexp::CrtWorkspace& ws,
                        RsaModexp::limb_t* prod,
                        int hw) {
  const int hb = bits / 16;
  RsaModexp::MulAddK(prod, ws.a, ws.b, hw, nullptr);
  if (0 != dongle.ReadDataFile(keyFile, keyOffset + RsaModexp::KeyBlob::NOffset(bits), ws.c, hb))
    return -EIO;
  if (0 != memcmp(ws.c, prod, static_cast<size_t>(hb)))
    return -EBADMSG;
  if (0 != dongle.ReadDataFile(keyFile, keyOffset + RsaModexp::KeyBlob::NOffset(bits) + hb, ws.c, hb))
    return -EIO;
  if (0 != memcmp(ws.c, reinterpret_cast<const uint8_t*>(prod) + hb, static_cast<size_t>(hb)))
    return -EBADMSG;
  return 0;
}

int RsaModexp::CrtSignFile(Dongle& dongle,
                           int keyFile,
                           uint32_t keyOffset,
                           const limb_t* base,
                           limb_t* out,
                           int bits,
                           CrtWorkspace& ws) {
  if (!base || !out)
    return -EINVAL;
  if (bits < kCrtMinBits || bits > kMaxBits || (bits % 64) != 0)
    return -EINVAL; /* 半域 k=bits/64 必须为整数且 >= kMinWords */
  if (base == out)
    return -EINVAL; /* 校验阶段要用 out 当 p*q 的乘积缓冲, 不能覆盖输入 */

  const int k = bits / 32;  /* 全宽 limb(3072 位 ⇒ 96) */
  const int hw = k / 2;     /* 半域 limb(⇒ 48) */
  const int hb = bits / 16; /* 半域字节(⇒ 192) */
  if (hw > kHalfWords)
    return -EINVAL;

  KeyBlobHeader hdr{};
  int rc = ReadKeyHeader(dongle, keyFile, keyOffset, bits, hdr);
  if (0 != rc)
    return rc;

  if (0 != dongle.ReadDataFile(keyFile, keyOffset + KeyBlob::POffset(bits), ws.a, hb))
    return -EIO;
  if (0 != dongle.ReadDataFile(keyFile, keyOffset + KeyBlob::QOffset(bits), ws.b, hb))
    return -EIO;

  rc = CheckModulus(dongle, keyFile, keyOffset, bits, ws, out, hw); /* out 兼作乘积缓冲 */
  if (0 != rc)
    return rc;
  rc = CheckIqmp(dongle, keyFile, keyOffset, bits, ws, hw);
  if (0 != rc)
    return rc;

  /* 半域 1: s_p = (base mod p)^dmp1 mod p(结果直接写栈上的 s1) */
  limb_t s1[kHalfWords], s2[kHalfWords];
  if (0 != dongle.ReadDataFile(keyFile, keyOffset + KeyBlob::Dmp1Offset(bits), ws.b, hb))
    return -EIO;
  ModReduce(ws.c, base, k, ws.a, hw);
  if (0 != HalfModExp(s1, ws.c, reinterpret_cast<const uint8_t*>(ws.b), hb, ws.a, hw, ws.t))
    return -EFAULT;

  /* 半域 2: s_q = (base mod q)^dmq1 mod q */
  if (0 != dongle.ReadDataFile(keyFile, keyOffset + KeyBlob::QOffset(bits), ws.a, hb))
    return -EIO;
  if (0 != dongle.ReadDataFile(keyFile, keyOffset + KeyBlob::Dmq1Offset(bits), ws.b, hb))
    return -EIO;
  ModReduce(ws.c, base, k, ws.a, hw);
  if (0 != HalfModExp(s2, ws.c, reinterpret_cast<const uint8_t*>(ws.b), hb, ws.a, hw, ws.t))
    return -EFAULT;

  /* 重组: out = s_q + q * ((s_p - s_q) * iqmp mod p); 临时区借用 s1(其原值仍作为 SubModK 的入参) */
  if (0 != dongle.ReadDataFile(keyFile, keyOffset + KeyBlob::POffset(bits), ws.a, hb))
    return -EIO;
  if (0 != dongle.ReadDataFile(keyFile, keyOffset + KeyBlob::QOffset(bits), ws.b, hb))
    return -EIO;
  if (0 != dongle.ReadDataFile(keyFile, keyOffset + KeyBlob::IqmpOffset(bits), ws.c, hb))
    return -EIO;
  CrtCombine(out, s1, s2, ws.a, ws.b, ws.c, hw, s1, ws.t);
  std::ignore = TAG;
  return 0;
}

int RsaModexp::KeyCheckFile(Dongle& dongle,
                            int keyFile,
                            uint32_t keyOffset,
                            int bits,
                            CrtWorkspace& ws,
                            limb_t* scratch) {
  if (!scratch)
    return -EINVAL;
  if (bits < kCrtMinBits || bits > kMaxBits || (bits % 64) != 0)
    return -EINVAL;

  const int k = bits / 32;
  const int hw = k / 2;
  const int hb = bits / 16;
  if (hw > kHalfWords)
    return -EINVAL;

  KeyBlobHeader hdr{};
  int rc = ReadKeyHeader(dongle, keyFile, keyOffset, bits, hdr);
  if (0 != rc)
    return rc;

  if (0 != dongle.ReadDataFile(keyFile, keyOffset + KeyBlob::POffset(bits), ws.a, hb))
    return -EIO;
  if (0 != dongle.ReadDataFile(keyFile, keyOffset + KeyBlob::QOffset(bits), ws.b, hb))
    return -EIO;

  rc = CheckModulus(dongle, keyFile, keyOffset, bits, ws, scratch, hw);
  if (0 != rc)
    return rc;
  rc = CheckIqmp(dongle, keyFile, keyOffset, bits, ws, hw);
  if (0 != rc)
    return rc;

  /* dmp1 < p-1、dmq1 < q-1(指数必须落在合法区间) */
  const limb_t one[1] = {1};
  memcpy(ws.c, ws.a, static_cast<size_t>(hb)); /* c = p */
  SubEqK(ws.c, one, 1);                        /* c = p-1 */
  if (0 != dongle.ReadDataFile(keyFile, keyOffset + KeyBlob::Dmp1Offset(bits), ws.b, hb))
    return -EIO;
  if (CmpK(ws.b, ws.c, hw) >= 0)
    return -EBADMSG;

  if (0 != dongle.ReadDataFile(keyFile, keyOffset + KeyBlob::QOffset(bits), ws.a, hb))
    return -EIO;
  memcpy(ws.c, ws.a, static_cast<size_t>(hb)); /* c = q */
  SubEqK(ws.c, one, 1);                        /* c = q-1 */
  if (0 != dongle.ReadDataFile(keyFile, keyOffset + KeyBlob::Dmq1Offset(bits), ws.b, hb))
    return -EIO;
  if (CmpK(ws.b, ws.c, hw) >= 0)
    return -EBADMSG;

  std::ignore = TAG;
  return 0;
}

}  // namespace dongle

AGINX_DECLARE_END

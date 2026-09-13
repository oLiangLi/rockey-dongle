#pragma once

#include <Interface/aginx.h>
#include <Interface/dongle.h>

AGINX_DECLARE_MACHINE

namespace dongle {

/**
 *! 设备内 3072 位以内的 Montgomery 模幂(RSA-3072 的签名/验签原语)。
 *!
 *! 为什么单独一份实现: `Interface/mr.cc` 的 Montgomery 只服务 ≤1536 位素因子(k≤48),
 *! 其 CIOS 临时区 `t[kCountWords+2]` 与 BN 缓冲都按该宽度定死; 3072 位模数(k=96)时
 *! BN 的 `v[kCountWords*2]`(96 limb)已没有进位余量, 且 3 个大数放不进 InOutBuf /
 *! ExtendBuf 任何单独一块(各 1KB)。
 *! 因此这里改成"缓冲区全部由调用方提供"的形式: 设备侧把 `Workspace` 放 ExtendBuf、
 *! 操作数放 InOutBuf 的数据段, 栈上只留模数与帧 —— 栈与 RAM 占用都可由调用方核算。
 *!
 *! 约定: 大数一律为**小端 32 位 limb**(与 BN::v、dashboard 落盘顺序一致);
 *! 指数以**小端字节数组**给出(与 dashboard 读回的种子/密钥同序), 允许前导零字节,
 *! 内部按最高非零字节定位(如 e=65537 只有 3 字节 ⇒ 只算 17 位)。
 *
 *! CRT 快速路径: 3072 位私钥运算可拆成两次 1536 位(k=48)模幂 —— MontMul 代价 ∝ k²,
 *! 于是两次半域幂只有全宽一次的 2×(48/96)²×(1536/3072)=1/4 左右, 且半域缓冲只要 192B。
 *! 见 `CrtSignFile()` 与 `KeyBlob`(完整私钥 n/e/d/p/q/dmp1/dmq1/iqmp 的落盘布局)。
 */
class RsaModexp {
 public:
  using limb_t = uint32_t;
  using DWORD = Dongle::DWORD;
  static constexpr int kMaxWords = 96;              /* 3072 bits */
  static constexpr int kMaxBits = kMaxWords * 32;   /* 3072 */
  static constexpr int kMinWords = 32;              /* 1024 bits */
  static constexpr int kHalfWords = kMaxWords / 2;  /* 48 limb = 1536 位(3072 位 RSA 的素因子) */

  /** 工作区: 由调用方提供(设备侧 = ExtendBuf 切片, 因此不占栈) */
  struct Workspace {
    limb_t t[kMaxWords + 2]; /* CIOS 临时区(t 不得与 r/a/b/n 别名) */
    limb_t acc[kMaxWords];   /* Montgomery 域的底数 */
  };
  rLANG_ABIREQUIRE(sizeof(Workspace) == (kMaxWords + 2 + kMaxWords) * 4);

  /**
   *! CRT 私钥运算的工作区(776B, 与全宽 Workspace 同尺寸, 设备侧放 ExtendBuf):
   *!   槽 a: p → q(半域模数)
   *!   槽 b: dmp1 → dmq1 → q → iqmp(可变)
   *!   槽 c: m mod p/q → 半宽校验缓冲 → 重组临时 h
   *!   t   : Montgomery 临时(k+2)
   *! 两个半域结果 s_p/s_q 由调用方另给缓冲(CrtSignFile 用栈上的 2×kHalfWords = 384B)。
   */
  struct CrtWorkspace {
    limb_t a[kHalfWords];
    limb_t b[kHalfWords];
    limb_t c[kHalfWords];
    limb_t t[kHalfWords + 2];
  };
  rLANG_ABIREQUIRE(sizeof(CrtWorkspace) == (3 * kHalfWords + kHalfWords + 2) * 4);

  /**
   *! RSA 私钥 blob(小端字节, 定长) —— 设备数据文件里的"完整私钥", 供 CRT 运算/校验读取。
   *!   偏移                 字段                     长度
   *!   [0,  16)             header{magic 'RSAK', bits, flags, 0}
   *!   [16, +w)             n                         w = bits/8
   *!   [.., +w)             e(小端, 高位补 0)         w
   *!   [.., +w)             d                         w
   *!   [.., +h) ×5          p, q, dmp1, dmq1, iqmp    h = w/2
   *! flags bit0 = 含 CRT 参数(p/q/dmp1/dmq1/iqmp 可用)。
   *! 3072 位: w=384, h=192 ⇒ 总长 16 + 3*384 + 5*192 = 2128B。
   */
  struct KeyBlob {
    static constexpr uint32_t kMagic = 0x4B415352; /* 'RSAK' */
    static constexpr int kHeaderSize = 16;
    static constexpr uint32_t kFlagCrt = 1;
    static constexpr int FieldSize(int bits) { return bits / 8; }  /* n/e/d */
    static constexpr int HalfSize(int bits) { return bits / 16; }  /* p/q/dmp1/dmq1/iqmp */
    static constexpr int NOffset(int bits) { return kHeaderSize; }
    static constexpr int EOffset(int bits) { return NOffset(bits) + FieldSize(bits); }
    static constexpr int DOffset(int bits) { return EOffset(bits) + FieldSize(bits); }
    static constexpr int POffset(int bits) { return DOffset(bits) + FieldSize(bits); }
    static constexpr int QOffset(int bits) { return POffset(bits) + HalfSize(bits); }
    static constexpr int Dmp1Offset(int bits) { return QOffset(bits) + HalfSize(bits); }
    static constexpr int Dmq1Offset(int bits) { return Dmp1Offset(bits) + HalfSize(bits); }
    static constexpr int IqmpOffset(int bits) { return Dmq1Offset(bits) + HalfSize(bits); }
    static constexpr int TotalSize(int bits) { return IqmpOffset(bits) + HalfSize(bits); }
  };
  struct KeyBlobHeader {
    uint32_t magic;
    uint32_t bits;
    uint32_t flags;
    uint32_t reserved;
  };
  rLANG_ABIREQUIRE(sizeof(KeyBlobHeader) == KeyBlob::kHeaderSize);

  /** CRT 支持的位宽: 半域 k=bits/32/2 必须 >= kMinWords ⇒ bits >= 2048 */
  static constexpr int kCrtMinBits = kMinWords * 64; /* 2048 */

  /** -n^{-1} mod 2^32(牛顿迭代 5 轮) */
  static uint32_t N0Inv(uint32_t n0);

  /** r = a*b*R^{-1} mod n(CIOS, R=2^{32k}); r 可与 a/b 别名, 但不得与 t/n 别名 */
  static void MontMul(limb_t* r,
                      const limb_t* a,
                      const limb_t* b,
                      const limb_t* n,
                      int k,
                      uint32_t n0inv,
                      limb_t* t);

  /** 原地进/出 Montgomery 域; 要求 n 为奇数, 进入前 a < n */
  static void ToMont(limb_t* a, const limb_t* n, int k);
  static void FromMont(limb_t* a, const limb_t* n, int k);

  /** r = (a - b) mod n(定长 k limb; 要求 a,b < n) */
  static void SubModK(limb_t* r, const limb_t* a, const limb_t* b, const limb_t* n, int k);

  /** r = a mod n: a 为 aWords 个 limb(>= k), 逐位 shift-subtract(约 32·aWords·k 次操作) */
  static void ModReduce(limb_t* r, const limb_t* a, int aWords, const limb_t* n, int k);

  /** out(2k limb) = a*b + addend(a/b/addend 各 k limb; addend 可为 nullptr) */
  static void MulAddK(limb_t* out, const limb_t* a, const limb_t* b, int k, const limb_t* addend);

  /** 设备侧周期心跳(LED/看门狗由 COS 调用派发); host 侧只计数 */
  void SetDongle(Dongle* dongle) { dongle_ = dongle; }
  uint32_t Heartbeats() const { return counter_; }
  void KickWDG();

  /**
   *! out = base^exp mod n。
   *! 约束: kMinWords <= k <= kMaxWords; n 为奇数且恰 k limb(n[k-1] != 0);
   *!       base < 9n(超出返回 -ERANGE); out 不得与 exp 重叠(可与 base 别名)。
   *! 返回 0 成功, 负值为错误码。
   */
  int ModExp(limb_t* out, const limb_t* base, const uint8_t* exp, int expBytes, const limb_t* n, int k, Workspace& ws);

  /**
   *! 单半域模幂(CRT 用): out = base^exp mod n, `base` **可变**(就地进 Montgomery 域),
   *! 因此不需要 Workspace 里的 acc 槽(省 k 个 limb)。要求 out != base。
   *! k 取 kHalfWords(3072 位 RSA 的 p/q)。
   */
  int HalfModExp(limb_t* out, limb_t* base, const uint8_t* exp, int expBytes, const limb_t* n, int k, limb_t* t);

  /**
   *! CRT 重组: out(2k limb) = s2 + q * ((s1 - s2) * iqmp mod p)。
   *! iqmp **可变**(会被转进 Montgomery 域); tmp 为 k limb 临时区(**可与 s1 同一缓冲**)。
   */
  static void CrtCombine(limb_t* out,
                         const limb_t* s1,
                         const limb_t* s2,
                         const limb_t* p,
                         const limb_t* q,
                         limb_t* iqmp,
                         int k,
                         limb_t* tmp,
                         limb_t* t);

  /**
   *! 从设备数据文件读取 RSA 私钥 blob, 做 **CRT 私钥运算**(签名/解密):
   *!   s_p = (base mod p)^dmp1 mod p;  s_q = (base mod q)^dmq1 mod q;
   *!   h = (s_p - s_q) * iqmp mod p;   out = s_q + q*h   (= base^d mod n, 且 < n)
   *! 校验(全部失败返回 -EBADMSG): blob magic/bits/flags、p*q == n、q*iqmp ≡ 1 (mod p)。
   *! 约束: bits ∈ {2048, 3072}; base/out 各 bits/8 字节且 **out != base**
   *!       (校验阶段把 out 当 p*q 的乘积缓冲用, 因此不能覆盖输入)。
   */
  int CrtSignFile(Dongle& dongle,
                  int keyFile,
                  uint32_t keyOffset,
                  const limb_t* base,
                  limb_t* out,
                  int bits,
                  CrtWorkspace& ws);

  /**
   *! 只校验数据文件里的私钥 blob(不改动 base/out):
   *!   magic/bits/flags、p*q == n、q*iqmp ≡ 1 (mod p)、dmp1 < p-1、dmq1 < q-1。
   *! scratch 需 bits/8 字节(2*halfWords 个 limb, 用于 p*q 乘积)。返回 0 = 通过。
   */
  int KeyCheckFile(Dongle& dongle, int keyFile, uint32_t keyOffset, int bits, CrtWorkspace& ws, limb_t* scratch);

  /** 每 kKickSquarings 次平方喂一次狗(设备侧 k=96 单次 MontMul ≈ 40ms、k=48 ≈ 10ms) */
  static constexpr int kKickSquarings = 8;

 private:
  /** 平方乘核心: r = base_m^exp mod n(base_m 已在 Montgomery 域, 只读) */
  void ModexpCore(limb_t* r, const limb_t* base_m, const uint8_t* exp, int expBits, const limb_t* n, int k, uint32_t n0inv,
                  limb_t* t);

  Dongle* dongle_ = nullptr;
  uint32_t counter_ = 0;
};

}  // namespace dongle

AGINX_DECLARE_END

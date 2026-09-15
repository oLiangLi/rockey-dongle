#include <Interface/dongle.h>
#include <Interface/keygen.h>
#include <Interface/modexp.h>
#include <Interface/script.h>
#include <base/base.h>
#include <time.h>

rLANG_DECLARE_MACHINE

namespace {
constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("MEXPV");
}

namespace dongle {

/**
 *! `kExRSAModExp` 的 **opcode 层**用例(模拟器, 直调 `VM_t::OpFuncRSA`):
 *!   1) 3072 位签名 m^d mod n —— 与 TASSL BN_mod_exp 逐字节一致(模数走数据文件,
 *!      底数/指数/结果在 VM 数据区, 结果原地覆盖底数);
 *!   2) 3072 位验签 s^e mod n(e = 65537, 只 17 位 → 走小指数/前导零路径)还原 m;
 *!   3) 1536 位(k=48)样例, 证明同一实现覆盖 1024..3072 全宽度;
 *!   4) 参数错误: argc=5 → SIGILL; 非 4 字节对齐地址 → SIGSEGV; bits 非 32 倍数 → -EINVAL;
 *!      模数数据文件不存在 → -EIO。算法本身的正确性由 __Testing__dongle__ mode 4(host 随机
 *!      对拍 + 真机)覆盖, 这里只验证 opcode 胶水层(address/file/alignment/bits 解析)。
 */
namespace {

using script::OpCode;

constexpr uint16_t kOpModExp = static_cast<uint16_t>(OpCode::kExRSAModExp);
constexpr uint16_t kOpCrtModExp = static_cast<uint16_t>(OpCode::kExRSACrtModExp);
constexpr uint16_t kOpKeyCheck = static_cast<uint16_t>(OpCode::kExRSAKeyCheck);
constexpr uint32_t kFileId = Dongle::kFactoryDataFileId; /* 0xFFFF: 匿名可读, 测试用 */
constexpr uint32_t kNOffset = 0;                         /* 模数在数据文件里的偏移 */
constexpr int32_t kMAddr = 0;                            /* 底数/结果在 VM 数据区的偏移 */
constexpr int32_t kEAddr = 384;                          /* 指数在 VM 数据区的偏移 */
/* CRT: 完整私钥 blob 与结果/临时区(数据文件 8KB、VM 数据区 1KB 之内) */
constexpr uint32_t kCrtKeyOffset = 0;      /* 完整私钥 blob */
constexpr uint32_t kCrtBadKeyOffset = 4096; /* 篡改过的 blob(负例) */
constexpr int32_t kCrtOutAddr = 384;       /* CRT 结果(与底数 kMAddr 分开: 校验要用结果区作乘积缓冲) */
constexpr int32_t kChkScratchAddr = 0;     /* KeyCheck 的 p*q 乘积缓冲(签名之后可复用底数区) */

struct Buffers {
  alignas(8) uint8_t data[1024];   /* VM 数据段(地址空间 0..1023) */
  alignas(8) uint8_t buffer[1024]; /* VM buffer 段(= 设备侧 ExtendBuf, 模幂工作区) */
};

/*! 生成一对 RSA 素因子, 返回 N/e/d/私钥指数的 bits 分解 */
struct RsaKey {
  BIGNUM* N = nullptr;
  BIGNUM* e = nullptr;
  BIGNUM* d = nullptr;
  BIGNUM* p = nullptr;
  BIGNUM* q = nullptr;
  BIGNUM* dmp1 = nullptr;
  BIGNUM* dmq1 = nullptr;
  BIGNUM* iqmp = nullptr;
  ~RsaKey() {
    BN_free(N);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(q);
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
  }
};

bool GenerateKey(int bits, RsaKey& key) {
  BN_CTX* bc = BN_CTX_new();
  key.p = BN_new();
  key.q = BN_new();
  BIGNUM* pm1 = BN_new();
  BIGNUM* qm1 = BN_new();
  BIGNUM* g = BN_new();
  BIGNUM* lcm = BN_new();
  key.N = BN_new();
  key.e = BN_new();
  key.d = BN_new();
  key.dmp1 = BN_new();
  key.dmq1 = BN_new();
  key.iqmp = BN_new();

  bool ok = false;
  if (BN_generate_prime_ex(key.p, bits / 2, 0, nullptr, nullptr, nullptr) &&
      BN_generate_prime_ex(key.q, bits / 2, 0, nullptr, nullptr, nullptr) && BN_mul(key.N, key.p, key.q, bc) &&
      BN_set_word(key.e, 65537) && BN_sub_word(BN_copy(pm1, key.p), 1) && BN_sub_word(BN_copy(qm1, key.q), 1) &&
      BN_gcd(g, pm1, qm1, bc) && BN_mul(lcm, pm1, qm1, bc) && BN_div(lcm, nullptr, lcm, g, bc) &&
      nullptr != BN_mod_inverse(key.d, key.e, lcm, bc) && nullptr != BN_mod_inverse(key.iqmp, key.q, key.p, bc) &&
      1 == BN_mod(key.dmp1, key.d, pm1, bc) && 1 == BN_mod(key.dmq1, key.d, qm1, bc)) {
    ok = true;
  }

  BN_free(pm1);
  BN_free(qm1);
  BN_free(g);
  BN_free(lcm);
  BN_CTX_free(bc);
  return ok;
}

/*! 组装完整私钥 blob(布局见 RsaModexp::KeyBlob); 返回字节数 */
int BuildKeyBlob(uint8_t* blob, int bits, const RsaKey& key) {
  RsaModexp::KeyBlobHeader hdr{};
  hdr.magic = RsaModexp::KeyBlob::kMagic;
  hdr.bits = static_cast<uint32_t>(bits);
  hdr.flags = RsaModexp::KeyBlob::kFlagCrt;
  memcpy(blob, &hdr, sizeof(hdr));
  const int w = RsaModexp::KeyBlob::FieldSize(bits);
  const int h = RsaModexp::KeyBlob::HalfSize(bits);
  std::ignore = BN_bn2lebinpad(key.N, blob + RsaModexp::KeyBlob::NOffset(bits), w);
  std::ignore = BN_bn2lebinpad(key.e, blob + RsaModexp::KeyBlob::EOffset(bits), w);
  std::ignore = BN_bn2lebinpad(key.d, blob + RsaModexp::KeyBlob::DOffset(bits), w);
  std::ignore = BN_bn2lebinpad(key.p, blob + RsaModexp::KeyBlob::POffset(bits), h);
  std::ignore = BN_bn2lebinpad(key.q, blob + RsaModexp::KeyBlob::QOffset(bits), h);
  std::ignore = BN_bn2lebinpad(key.dmp1, blob + RsaModexp::KeyBlob::Dmp1Offset(bits), h);
  std::ignore = BN_bn2lebinpad(key.dmq1, blob + RsaModexp::KeyBlob::Dmq1Offset(bits), h);
  std::ignore = BN_bn2lebinpad(key.iqmp, blob + RsaModexp::KeyBlob::IqmpOffset(bits), h);
  return RsaModexp::KeyBlob::TotalSize(bits);
}

/*! 用 opcode 算 base^exp mod n, 并与 TASSL 对拍; 返回 0 = 一致 */
int CheckModExp(Dongle& rockey,
                script::VM_t& vm,
                Buffers& b,
                const RsaKey& key,
                int bits,
                const uint8_t* base_le,
                const uint8_t* exp_le,
                const char* what) {
  const int k = bits / 32;
  const size_t nbytes = static_cast<size_t>(k) * 4;
  int error = 0;

  uint8_t n_le[RsaModexp::kMaxWords * 4];
  std::ignore = BN_bn2lebinpad(key.N, n_le, static_cast<int>(nbytes));
  if (0 != rockey.WriteDataFile(kFileId, kNOffset, n_le, nbytes)) {
    rlLOGE(TAG, "%s: WriteDataFile(N) 失败", what);
    return 1;
  }

  memcpy(b.data + kMAddr, base_le, nbytes);
  memcpy(b.data + kEAddr, exp_le, nbytes);
  int32_t argv[6] = {static_cast<int32_t>(kFileId), static_cast<int32_t>(kNOffset), kMAddr, kMAddr, kEAddr, bits};
  vm.zero_ = 0;
  const int rc = vm.OpFuncRSA(kOpModExp, 6, argv);
  if (0 != rc || 0 != vm.zero_) {
    rlLOGE(TAG, "%s: opcode 返回 %d(zero_=%d)", what, rc, vm.zero_);
    return 1;
  }

  /* TASSL 参照: base^exp mod N */
  BIGNUM* bv = BN_lebin2bn(base_le, static_cast<int>(nbytes), nullptr);
  BIGNUM* ev = BN_lebin2bn(exp_le, static_cast<int>(nbytes), nullptr);
  BIGNUM* ref = BN_new();
  BIGNUM* got = BN_lebin2bn(b.data + kMAddr, static_cast<int>(nbytes), nullptr);
  BN_CTX* bc = BN_CTX_new();
  std::ignore = BN_mod_exp(ref, bv, ev, key.N, bc);
  const int cmp = BN_cmp(got, ref);
  if (0 != cmp) {
    rlLOGE(TAG, "%s: 结果与 TASSL 不一致", what);
    ++error;
  }
  rlLOGI(TAG, "%s: opcode ok (bits=%d, %s)", what, bits, 0 == cmp ? "MATCH TASSL" : "MISMATCH");

  BN_free(bv);
  BN_free(ev);
  BN_free(ref);
  BN_free(got);
  BN_CTX_free(bc);
  return error;
}

/*! CRT 用例: 完整私钥 blob 写进数据文件 → ExRSACrtModExp → 与 TASSL m^d 对拍;
 *! 顺带校验 ExRSAKeyCheck(正确 blob 通过 / 篡改 iqmp 必须被拒)与 CRT 的参数错误分支。 */
int CheckCrt(Dongle& rockey, script::VM_t& vm, Buffers& b, const RsaKey& key, int bits, const uint8_t* m_le,
             uint8_t* s_crt_out) {
  const size_t nbytes = static_cast<size_t>(bits) / 8;
  int error = 0;

  uint8_t blob[RsaModexp::KeyBlob::TotalSize(RsaModexp::kMaxBits)];
  const int blob_len = BuildKeyBlob(blob, bits, key);
  if (0 != rockey.WriteDataFile(kFileId, kCrtKeyOffset, blob, static_cast<size_t>(blob_len))) {
    rlLOGE(TAG, "CRT: WriteDataFile(blob) 失败");
    return 1;
  }

  /* 1) CRT 签名 */
  memcpy(b.data + kMAddr, m_le, nbytes);
  memset(b.data + kCrtOutAddr, 0, nbytes);
  int32_t argv[5] = {static_cast<int32_t>(kFileId), static_cast<int32_t>(kCrtKeyOffset), kMAddr, kCrtOutAddr, bits};
  vm.zero_ = 0;
  int rc = vm.OpFuncRSA(kOpCrtModExp, 5, argv);
  if (0 != rc || 0 != vm.zero_) {
    rlLOGE(TAG, "CRT: opcode 返回 %d(zero_=%d)", rc, vm.zero_);
    return 1;
  }
  BIGNUM* got = BN_lebin2bn(b.data + kCrtOutAddr, static_cast<int>(nbytes), nullptr);
  BIGNUM* ref = BN_new();
  BIGNUM* mv = BN_lebin2bn(m_le, static_cast<int>(nbytes), nullptr);
  BN_CTX* bc = BN_CTX_new();
  std::ignore = BN_mod_exp(ref, mv, key.d, key.N, bc);
  const int cmp = BN_cmp(got, ref);
  rlLOGI(TAG, "CRT %d sign m^d: opcode ok (%s)", bits, 0 == cmp ? "MATCH TASSL" : "MISMATCH");
  if (0 != cmp)
    ++error;
  if (s_crt_out)
    memcpy(s_crt_out, b.data + kCrtOutAddr, nbytes);

  /* 2) 密钥校验: 正确 blob */
  int32_t argv_chk[4] = {static_cast<int32_t>(kFileId), static_cast<int32_t>(kCrtKeyOffset), kChkScratchAddr, bits};
  vm.zero_ = 0;
  rc = vm.OpFuncRSA(kOpKeyCheck, 4, argv_chk);
  if (0 != rc || 0 != vm.zero_) {
    rlLOGE(TAG, "KeyCheck(正确 blob) 返回 %d(zero_=%d)", rc, vm.zero_);
    ++error;
  }

  /* 3) 密钥校验: 篡改 iqmp 必须被拒 */
  uint8_t bad[RsaModexp::KeyBlob::TotalSize(RsaModexp::kMaxBits)];
  memcpy(bad, blob, static_cast<size_t>(blob_len));
  bad[RsaModexp::KeyBlob::IqmpOffset(bits)] ^= 0x01;
  std::ignore = rockey.WriteDataFile(kFileId, kCrtBadKeyOffset, bad, static_cast<size_t>(blob_len));
  int32_t argv_bad[4] = {static_cast<int32_t>(kFileId), static_cast<int32_t>(kCrtBadKeyOffset), kChkScratchAddr, bits};
  vm.zero_ = 0;
  rc = vm.OpFuncRSA(kOpKeyCheck, 4, argv_bad);
  if (rc >= 0 || 0 == vm.zero_) {
    rlLOGE(TAG, "KeyCheck(篡改 iqmp) 未被中止(rc=%d, zero_=%d)", rc, vm.zero_);
    ++error;
  }

  /* 4) CRT 参数错误分支 */
  vm.zero_ = 0;
  std::ignore = vm.OpFuncRSA(kOpCrtModExp, 4, argv);
  if (0 == vm.zero_) {
    rlLOGE(TAG, "CRT argc=4 未被拒绝");
    ++error;
  }

  vm.zero_ = 0;
  int32_t argv_same[5] = {static_cast<int32_t>(kFileId), static_cast<int32_t>(kCrtKeyOffset), kMAddr, kMAddr, bits};
  rc = vm.OpFuncRSA(kOpCrtModExp, 5, argv_same);
  if (rc >= 0 || 0 == vm.zero_) { /* out == m: 校验阶段会覆盖输入 ⇒ 必须中止 */
    rlLOGE(TAG, "CRT out==m 未被中止(rc=%d, zero_=%d)", rc, vm.zero_);
    ++error;
  }

  vm.zero_ = 0;
  int32_t argv_bits[5] = {static_cast<int32_t>(kFileId), static_cast<int32_t>(kCrtKeyOffset), kMAddr, kCrtOutAddr, 1000};
  rc = vm.OpFuncRSA(kOpCrtModExp, 5, argv_bits);
  if (rc >= 0 || 0 == vm.zero_) {
    rlLOGE(TAG, "CRT 非法 bits 未被中止(rc=%d, zero_=%d)", rc, vm.zero_);
    ++error;
  }

  /* 5) 权限门槛: admin-only 文件(id < kUserFileID=1000)在 NORMAL/ANONYMOUS 会话下必须被拒绝,
   *    且必须**置 zero_ 中止脚本** —— 只返回负 value 会让调用方看到 exit 0 + 全 0 结果
   *    (真机上曾出现该静默拒绝, 见 ai-doc/rsa3072-crt-2026-09-13.md §7)。 */
  const PERMISSION saved_permission = vm.valid_permission_;
  constexpr int32_t kAdminFile = 100;
  for (const PERMISSION perm : {PERMISSION::kAnonymous, PERMISSION::kNormal}) {
    vm.valid_permission_ = perm;

    vm.zero_ = 0;
    int32_t a_mod[6] = {kAdminFile, static_cast<int32_t>(kNOffset), kMAddr, kCrtOutAddr, kEAddr, bits};
    rc = vm.OpFuncRSA(kOpModExp, 6, a_mod);
    if (rc >= 0 || 0 == vm.zero_) {
      rlLOGE(TAG, "ModExp(admin 文件, perm=%d) 未被中止(rc=%d, zero_=%d)", static_cast<int>(perm), rc, vm.zero_);
      ++error;
    }

    vm.zero_ = 0;
    int32_t a_crt[5] = {kAdminFile, static_cast<int32_t>(kCrtKeyOffset), kMAddr, kCrtOutAddr, bits};
    rc = vm.OpFuncRSA(kOpCrtModExp, 5, a_crt);
    if (rc >= 0 || 0 == vm.zero_) {
      rlLOGE(TAG, "CRT(admin 文件, perm=%d) 未被中止(rc=%d, zero_=%d)", static_cast<int>(perm), rc, vm.zero_);
      ++error;
    }

    vm.zero_ = 0;
    int32_t a_chk[4] = {kAdminFile, static_cast<int32_t>(kCrtKeyOffset), kChkScratchAddr, bits};
    rc = vm.OpFuncRSA(kOpKeyCheck, 4, a_chk);
    if (rc >= 0 || 0 == vm.zero_) {
      rlLOGE(TAG, "KeyCheck(admin 文件, perm=%d) 未被中止(rc=%d, zero_=%d)", static_cast<int>(perm), rc, vm.zero_);
      ++error;
    }
  }
  vm.valid_permission_ = saved_permission;

  BN_free(got);
  BN_free(ref);
  BN_free(mv);
  BN_CTX_free(bc);
  return error;
}

/* ============================ ExRSAGenKey(设备内生成 RSA 私钥) ============================ */

constexpr uint16_t kOpGenKey = static_cast<uint16_t>(OpCode::kExRSAGenKey);
constexpr uint32_t kGenKeyOffset = 1024; /* 生成结果 blob(与 CRT 用例的 0 / 4096 错开, 且本用例在其后跑) */
constexpr int32_t kGenSeedAddr = 0;      /* 种子块 = VM 数据区 [0, bits/8) */

/*! 数据文件里读回的完整私钥(各字段各自成 BIGNUM) */
struct GenKeyBlob {
  BIGNUM* n = nullptr;
  BIGNUM* e = nullptr;
  BIGNUM* d = nullptr;
  BIGNUM* p = nullptr;
  BIGNUM* q = nullptr;
  BIGNUM* dmp1 = nullptr;
  BIGNUM* dmq1 = nullptr;
  BIGNUM* iqmp = nullptr;
  ~GenKeyBlob() {
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(q);
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
  }
};

/*! 读回 KeyBlob: 校验 header(magic/bits/flags)后按布局切字段; raw 需 TotalSize(bits) 字节 */
bool LoadGenBlob(Dongle& rockey, uint32_t offset, int bits, GenKeyBlob& key, uint8_t* raw) {
  if (0 != rockey.ReadDataFile(kFileId, offset, raw, static_cast<size_t>(RsaModexp::KeyBlob::TotalSize(bits))))
    return false;
  const RsaModexp::KeyBlobHeader* hdr = reinterpret_cast<const RsaModexp::KeyBlobHeader*>(raw);
  if (hdr->magic != RsaModexp::KeyBlob::kMagic || hdr->bits != static_cast<uint32_t>(bits) ||
      0 == (hdr->flags & RsaModexp::KeyBlob::kFlagCrt)) {
    rlLOGE(TAG, "GenKey: blob header 非法(magic=%08x bits=%u flags=%u)", hdr->magic, hdr->bits, hdr->flags);
    return false;
  }
  const int w = RsaModexp::KeyBlob::FieldSize(bits);
  const int h = RsaModexp::KeyBlob::HalfSize(bits);
  key.n = BN_lebin2bn(raw + RsaModexp::KeyBlob::NOffset(bits), w, nullptr);
  key.e = BN_lebin2bn(raw + RsaModexp::KeyBlob::EOffset(bits), w, nullptr);
  key.d = BN_lebin2bn(raw + RsaModexp::KeyBlob::DOffset(bits), w, nullptr);
  key.p = BN_lebin2bn(raw + RsaModexp::KeyBlob::POffset(bits), h, nullptr);
  key.q = BN_lebin2bn(raw + RsaModexp::KeyBlob::QOffset(bits), h, nullptr);
  key.dmp1 = BN_lebin2bn(raw + RsaModexp::KeyBlob::Dmp1Offset(bits), h, nullptr);
  key.dmq1 = BN_lebin2bn(raw + RsaModexp::KeyBlob::Dmq1Offset(bits), h, nullptr);
  key.iqmp = BN_lebin2bn(raw + RsaModexp::KeyBlob::IqmpOffset(bits), h, nullptr);
  return nullptr != key.n && nullptr != key.e && nullptr != key.d && nullptr != key.p && nullptr != key.q &&
         nullptr != key.dmp1 && nullptr != key.dmq1 && nullptr != key.iqmp;
}

/*! 用 TASSL 独立复核设备内生成的私钥: 素数性 / n=p*q / e*d≡1 (mod lcm) / CRT 参数 / iqmp */
int VerifyGenBlob(const GenKeyBlob& k, int bits, const char* what) {
  int error = 0;
  BN_CTX* const bc = BN_CTX_new();
  BIGNUM* const t = BN_new();
  BIGNUM* const pm1 = BN_new();
  BIGNUM* const qm1 = BN_new();
  BIGNUM* const g = BN_new();
  BIGNUM* const lcm = BN_new();

  if (BN_num_bits(k.n) != bits) {
    rlLOGE(TAG, "%s: bits(n)=%d != %d", what, BN_num_bits(k.n), bits);
    ++error;
  }
  if (1 != BN_is_prime_ex(k.p, 64, bc, nullptr) || 1 != BN_is_prime_ex(k.q, 64, bc, nullptr)) {
    rlLOGE(TAG, "%s: p/q 未通过 64 轮素性检验", what);
    ++error;
  }
  if (0 == BN_cmp(k.p, k.q)) {
    rlLOGE(TAG, "%s: p == q", what);
    ++error;
  }
  BN_mul(t, k.p, k.q, bc); /* n == p*q */
  if (0 != BN_cmp(t, k.n)) {
    rlLOGE(TAG, "%s: n != p*q", what);
    ++error;
  }
  BN_set_word(t, RsaKeyGen::kE); /* e == 65537 */
  if (0 != BN_cmp(t, k.e)) {
    rlLOGE(TAG, "%s: e != 65537", what);
    ++error;
  }
  BN_sub_word(BN_copy(pm1, k.p), 1);
  BN_sub_word(BN_copy(qm1, k.q), 1);
  BN_gcd(g, pm1, qm1, bc);
  BN_mul(lcm, pm1, qm1, bc);
  BN_div(lcm, nullptr, lcm, g, bc);
  BN_mod_mul(t, k.e, k.d, lcm, bc); /* e*d ≡ 1 (mod lcm(p-1,q-1)) */
  if (!BN_is_one(t)) {
    rlLOGE(TAG, "%s: e*d != 1 (mod lcm)", what);
    ++error;
  }
  BN_mod(t, k.d, pm1, bc); /* dmp1 == d mod (p-1) */
  if (0 != BN_cmp(t, k.dmp1)) {
    rlLOGE(TAG, "%s: dmp1 != d mod (p-1)", what);
    ++error;
  }
  BN_mod(t, k.d, qm1, bc); /* dmq1 == d mod (q-1) */
  if (0 != BN_cmp(t, k.dmq1)) {
    rlLOGE(TAG, "%s: dmq1 != d mod (q-1)", what);
    ++error;
  }
  BN_mod_inverse(t, k.q, k.p, bc); /* iqmp == q^{-1} mod p */
  if (0 != BN_cmp(t, k.iqmp)) {
    rlLOGE(TAG, "%s: iqmp != q^{-1} mod p", what);
    ++error;
  }

  BN_free(lcm);
  BN_free(g);
  BN_free(qm1);
  BN_free(pm1);
  BN_free(t);
  BN_CTX_free(bc);
  return error;
}

/*! 调一次 ExRSAGenKey(种子已在 b.data[0, bits/8)) */
int RunGenKey(script::VM_t& vm, int bits, int rounds, bool expect_ok) {
  int32_t argv[5] = {static_cast<int32_t>(kFileId), static_cast<int32_t>(kGenKeyOffset), kGenSeedAddr, bits, rounds};
  vm.zero_ = 0;
  const int rc = vm.OpFuncRsaKeyGen(5, argv);
  const bool ok = (0 == rc && 0 == vm.zero_);
  if (ok != expect_ok) {
    rlLOGE(TAG, "GenKey(bits=%d): rc=%d zero_=%d, 期望 %s", bits, rc, vm.zero_, expect_ok ? "成功" : "失败");
    return 1;
  }
  return 0;
}

/*! 生成 + 复核 + 确定性 + 与 ExRSAKeyCheck / ExRSACrtModExp 串联; 返回错误数 */
int CheckGenKey(Dongle& rockey, script::VM_t& vm, Buffers& b) {
  int error = 0;
  const int bits = 3072;
  const int hb = bits / 16; /* 每个素数的种子字节数 */
  const PERMISSION saved_perm = vm.valid_permission_;
  vm.valid_permission_ = PERMISSION::kAdministrator; /* ExRSAGenKey 一律要求管理员权限 */

  /* 固定种子(device 侧算法与 rsa-prime-repro.cjs 逐位对齐 ⇒ 同种子必得同一 p/q) */
  for (int i = 0; i < hb; ++i) {
    b.data[i] = static_cast<uint8_t>(0x11 + i * 7);
    b.data[hb + i] = static_cast<uint8_t>(0x51 + i * 5);
  }
  uint8_t seed_copy[384]; /* 后面的 CRT 用例会往数据区写 m/结果(与种子区重叠), 比对前要还原 */
  memcpy(seed_copy, b.data, sizeof(seed_copy));

  const clock_t t0 = clock();
  error += RunGenKey(vm, bits, MillerRabinContext::kMaxRounds, true);
  const double secs = static_cast<double>(clock() - t0) / CLOCKS_PER_SEC;
  rlLOGI(TAG, "GenKey(3072, %d 轮): %.1fs", MillerRabinContext::kMaxRounds, secs);
  if (0 != error)
    return error;

  uint8_t raw1[RsaModexp::KeyBlob::TotalSize(RsaModexp::kMaxBits)];
  GenKeyBlob key;
  if (!LoadGenBlob(rockey, kGenKeyOffset, bits, key, raw1)) {
    rlLOGE(TAG, "GenKey: blob 读回失败");
    return error + 1;
  }
  error += VerifyGenBlob(key, bits, "GenKey(3072)");

  /* 生成出来的 blob 必须能被 ExRSAKeyCheck 接受 */
  {
    int32_t argv[4] = {static_cast<int32_t>(kFileId), static_cast<int32_t>(kGenKeyOffset), kChkScratchAddr, bits};
    vm.zero_ = 0;
    const int rc = vm.OpFuncRSA(kOpKeyCheck, 4, argv);
    if (0 != rc || 0 != vm.zero_) {
      rlLOGE(TAG, "GenKey: ExRSAKeyCheck(生成的 blob) 返回 %d(zero_=%d)", rc, vm.zero_);
      ++error;
    } else {
      rlLOGI(TAG, "GenKey: ExRSAKeyCheck 接受生成的 blob ✓");
    }
  }

  /* 用生成的私钥做一次 CRT 私钥运算, 与 TASSL 全宽 m^d mod n 对拍 */
  {
    const size_t nbytes = static_cast<size_t>(bits) / 8;
    BIGNUM* mv = BN_new();
    BN_CTX* bc = BN_CTX_new();
    RAND_bytes(b.data + kMAddr, static_cast<int>(nbytes));
    BN_lebin2bn(b.data + kMAddr, static_cast<int>(nbytes), mv);
    BN_mod(mv, mv, key.n, bc);
    std::ignore = BN_bn2lebinpad(mv, b.data + kMAddr, static_cast<int>(nbytes));

    memset(b.data + kCrtOutAddr, 0, nbytes);
    int32_t argv[5] = {static_cast<int32_t>(kFileId), static_cast<int32_t>(kGenKeyOffset), kMAddr, kCrtOutAddr, bits};
    vm.zero_ = 0;
    const int rc = vm.OpFuncRSA(kOpCrtModExp, 5, argv);
    BIGNUM* got = BN_lebin2bn(b.data + kCrtOutAddr, static_cast<int>(nbytes), nullptr);
    BIGNUM* ref = BN_new();
    std::ignore = BN_mod_exp(ref, mv, key.d, key.n, bc);
    if (0 != rc || 0 != vm.zero_ || 0 != BN_cmp(got, ref)) {
      rlLOGE(TAG, "GenKey: 生成的私钥 CRT 签名与 TASSL 不一致(rc=%d zero_=%d cmp=%d)", rc, vm.zero_, BN_cmp(got, ref));
      ++error;
    } else {
      rlLOGI(TAG, "GenKey: CRT 签名 == TASSL m^d mod n ✓");
    }
    BN_free(ref);
    BN_free(got);
    BN_free(mv);
    BN_CTX_free(bc);
  }

  /* 确定性: 同一种子再生成一次(同一偏移覆盖), 整块 blob 必须逐字节相同 */
  {
    uint8_t raw2[RsaModexp::KeyBlob::TotalSize(RsaModexp::kMaxBits)];
    memcpy(b.data, seed_copy, sizeof(seed_copy)); /* 还原上一次 CRT 用例覆盖掉的种子 */
    error += RunGenKey(vm, bits, MillerRabinContext::kMaxRounds, true);
    if (0 != rockey.ReadDataFile(kFileId, kGenKeyOffset, raw2, sizeof(raw2))) {
      rlLOGE(TAG, "GenKey: 第二次生成读回失败");
      ++error;
    } else if (0 != memcmp(raw1, raw2, sizeof(raw2))) {
      rlLOGE(TAG, "GenKey: 同一种子两次生成结果不一致(!)");
      ++error;
    } else {
      rlLOGI(TAG, "GenKey: 同一种子 ⇒ 逐字节相同的私钥 ✓");
    }
  }

  /* 2048 位(1024 位素因子): 更短的路径也要能生成 + 复核 */
  {
    const int bits2 = 2048;
    const int hb2 = bits2 / 16;
    for (int i = 0; i < hb2; ++i) {
      b.data[i] = static_cast<uint8_t>(0x21 + i * 3);
      b.data[hb2 + i] = static_cast<uint8_t>(0x91 + i * 11);
    }
    error += RunGenKey(vm, bits2, MillerRabinContext::kMaxRounds, true);
    uint8_t raw[RsaModexp::KeyBlob::TotalSize(RsaModexp::kMaxBits)];
    GenKeyBlob key2;
    if (LoadGenBlob(rockey, kGenKeyOffset, bits2, key2, raw))
      error += VerifyGenBlob(key2, bits2, "GenKey(2048)");
    else
      ++error;
  }

  /* 密文落盘: SM4-ECB 临时密钥(keyId 996)+ 逐字段随机解密(生成/KeyCheck/CRT 三条路径都必须照常工作) */
  {
    const int kKeyId = 996; /* 约定: >900 只作内部临时密钥 */
    uint8_t sm4key[16];
    for (int i = 0; i < 16; ++i)
      sm4key[i] = static_cast<uint8_t>(0xA0 + i);
    if (0 != rockey.CreateKeyFile(kKeyId, PERMISSION::kAdministrator, SECRET_STORAGE_TYPE::kSM4) ||
        0 != rockey.WriteKeyFile(kKeyId, sm4key, sizeof(sm4key), SECRET_STORAGE_TYPE::kSM4)) {
      rlLOGE(TAG, "GenKey(sealed): 创建/写入 SM4 临时密钥失败");
      ++error;
    } else {
      memcpy(b.data, seed_copy, sizeof(seed_copy)); /* 前面的 CRT 用例覆盖过数据区 */
      int32_t argv[6] = {static_cast<int32_t>(kFileId), static_cast<int32_t>(kGenKeyOffset), kGenSeedAddr, bits,
                         MillerRabinContext::kMaxRounds, kKeyId};
      vm.zero_ = 0;
      const int rc = vm.OpFuncRsaKeyGen(6, argv);
      if (0 != rc || 0 != vm.zero_) {
        rlLOGE(TAG, "GenKey(sealed): ExRSAGenKey(keyId=%d) 返回 %d(zero_=%d)", kKeyId, rc, vm.zero_);
        ++error;
      }

      /* 落盘必须是密文: header 魔数不该还是 'RSAK' */
      uint8_t sealed_raw[RsaModexp::KeyBlob::TotalSize(RsaModexp::kMaxBits)];
      uint8_t unsealed[RsaModexp::KeyBlob::TotalSize(RsaModexp::kMaxBits)];
      const size_t blob_len = static_cast<size_t>(RsaModexp::KeyBlob::TotalSize(bits));
      if (0 != rockey.ReadDataFile(kFileId, kGenKeyOffset, sealed_raw, blob_len)) {
        rlLOGE(TAG, "GenKey(sealed): 读回失败");
        ++error;
      } else if (reinterpret_cast<const RsaModexp::KeyBlobHeader*>(sealed_raw)->magic == RsaModexp::KeyBlob::kMagic) {
        rlLOGE(TAG, "GenKey(sealed): 落盘竟是明文(!)");
        ++error;
      } else {
        /* 逐块解密后必须与刚才那把明文 blob 逐字节相同(同一粒种子 ⇒ 同一把私钥) */
        memcpy(unsealed, sealed_raw, blob_len);
        int dec_rc = 0;
        for (size_t off = 0; off < blob_len && 0 == dec_rc; off += 256) {
          const size_t n = (blob_len - off < 256) ? (blob_len - off) : 256;
          dec_rc = rockey.SM4ECB(kKeyId, unsealed + off, n, false); /* 256/16 对齐 ⇒ 块内可独立解 */
        }
        if (0 != dec_rc)
          ++error;
        else if (0 != memcmp(unsealed, raw1, blob_len)) {
          const int wd = RsaModexp::KeyBlob::FieldSize(bits), hd2 = RsaModexp::KeyBlob::HalfSize(bits);
          const struct { const char* name; int off; int len; } fld[] = {
              {"header", 0, 16},
              {"n", RsaModexp::KeyBlob::NOffset(bits), wd},
              {"e", RsaModexp::KeyBlob::EOffset(bits), wd},
              {"d", RsaModexp::KeyBlob::DOffset(bits), wd},
              {"p", RsaModexp::KeyBlob::POffset(bits), hd2},
              {"q", RsaModexp::KeyBlob::QOffset(bits), hd2},
              {"dmp1", RsaModexp::KeyBlob::Dmp1Offset(bits), hd2},
              {"dmq1", RsaModexp::KeyBlob::Dmq1Offset(bits), hd2},
              {"iqmp", RsaModexp::KeyBlob::IqmpOffset(bits), hd2}};
          for (const auto& x : fld)
            rlLOGE(TAG, "GenKey(sealed) 字段 %-6s %s", x.name,
                   (0 == memcmp(unsealed + x.off, raw1 + x.off, static_cast<size_t>(x.len))) ? "MATCH" : "DIFF");
          ++error;
        } else {
          rlLOGI(TAG, "GenKey(sealed): 密文落盘 + 逐块解密 == 明文生成 ✓");
        }
      }

      /* 带 keyId 的 ExRSAKeyCheck: 必须接受(证明读侧逐字段解密正确) */
      {
        int32_t argv_chk[5] = {static_cast<int32_t>(kFileId), static_cast<int32_t>(kGenKeyOffset), kChkScratchAddr, bits,
                               kKeyId};
        vm.zero_ = 0;
        const int rc_chk = vm.OpFuncRSA(kOpKeyCheck, 5, argv_chk);
        if (0 != rc_chk || 0 != vm.zero_) {
          rlLOGE(TAG, "GenKey(sealed): ExRSAKeyCheck(keyId) 返回 %d(zero_=%d)", rc_chk, vm.zero_);
          ++error;
        } else {
          rlLOGI(TAG, "GenKey(sealed): ExRSAKeyCheck(keyId) 接受密文 blob ✓");
        }
      }

      /* 带 keyId 的 CRT 签名: 与 TASSL m^d mod n 对拍 */
      {
        const size_t nbytes = static_cast<size_t>(bits) / 8;
        BIGNUM* mv = BN_lebin2bn(b.data + kMAddr, static_cast<int>(nbytes), nullptr);
        BN_CTX* bc = BN_CTX_new();
        BN_mod(mv, mv, key.n, bc);
        std::ignore = BN_bn2lebinpad(mv, b.data + kMAddr, static_cast<int>(nbytes));
        int32_t argv_crt[6] = {static_cast<int32_t>(kFileId), static_cast<int32_t>(kGenKeyOffset), kMAddr, kCrtOutAddr,
                               bits, kKeyId};
        memset(b.data + kCrtOutAddr, 0, nbytes);
        vm.zero_ = 0;
        const int rc_crt = vm.OpFuncRSA(kOpCrtModExp, 6, argv_crt);
        BIGNUM* got = BN_lebin2bn(b.data + kCrtOutAddr, static_cast<int>(nbytes), nullptr);
        BIGNUM* ref = BN_new();
        std::ignore = BN_mod_exp(ref, mv, key.d, key.n, bc);
        if (0 != rc_crt || 0 != vm.zero_ || 0 != BN_cmp(got, ref)) {
          rlLOGE(TAG, "GenKey(sealed): ExRSACrtModExp(keyId) 与 TASSL 不一致(rc=%d zero_=%d)", rc_crt, vm.zero_);
          ++error;
        } else {
          rlLOGI(TAG, "GenKey(sealed): ExRSACrtModExp(keyId) == TASSL m^d mod n ✓");
        }
        BN_free(ref);
        BN_free(got);
        BN_free(mv);
        BN_CTX_free(bc);
      }

      /* 负例: 1..900 的 keyId 必须被拒(避免误用业务 keyId) */
      {
        int32_t argv_bad[6] = {static_cast<int32_t>(kFileId), static_cast<int32_t>(kGenKeyOffset), kGenSeedAddr, bits,
                               MillerRabinContext::kMaxRounds, 100};
        vm.zero_ = 0;
        std::ignore = vm.OpFuncRsaKeyGen(6, argv_bad);
        if (0 == vm.zero_) {
          rlLOGE(TAG, "GenKey(sealed): cipherKeyId=100 未被拒绝");
          ++error;
        }
      }
    }
  }

  /* 参数/权限/越界分支 */
  {
    int32_t argv_argc[3] = {static_cast<int32_t>(kFileId), static_cast<int32_t>(kGenKeyOffset), kGenSeedAddr};
    vm.zero_ = 0;
    std::ignore = vm.OpFuncRsaKeyGen(3, argv_argc);
    if (0 == vm.zero_) {
      rlLOGE(TAG, "GenKey: argc=3 未被拒绝");
      ++error;
    }

    error += RunGenKey(vm, 1024, 16, false); /* 素因子 512 位 < 能力下限 */

    const PERMISSION saved = vm.valid_permission_;
    vm.valid_permission_ = PERMISSION::kAnonymous;
    int32_t argv_perm[4] = {100, static_cast<int32_t>(kGenKeyOffset), kGenSeedAddr, bits};
    vm.zero_ = 0;
    std::ignore = vm.OpFuncRsaKeyGen(4, argv_perm);
    if (0 == vm.zero_) {
      rlLOGE(TAG, "GenKey: 非管理员写 keyFile<1000 未被拒绝");
      ++error;
    }
    vm.valid_permission_ = saved;

    int32_t argv_oor[4] = {static_cast<int32_t>(kFileId), static_cast<int32_t>(kGenKeyOffset), 700, bits}; /* 700+384 > 1024 */
    vm.zero_ = 0;
    std::ignore = vm.OpFuncRsaKeyGen(4, argv_oor);
    if (0 == vm.zero_) {
      rlLOGE(TAG, "GenKey: 越界种子地址未被拒绝");
      ++error;
    }
  }

  vm.valid_permission_ = saved_perm;
  return error;
}

int RunCase(Dongle& rockey, bool& ok_out) {
  int error = 0;
  ok_out = true;

  Buffers b;
  memset(&b, 0, sizeof(b));
  script::VM_t vm(&rockey, b.data, b.buffer);
  vm.valid_permission_ = PERMISSION::kAnonymous;

  RsaKey key;
  if (!GenerateKey(3072, key)) {
    rlLOGE(TAG, "GenerateKey(3072) 失败");
    return 1;
  }

  uint8_t m_le[RsaModexp::kMaxWords * 4];
  uint8_t d_le[RsaModexp::kMaxWords * 4];
  uint8_t e_le[RsaModexp::kMaxWords * 4];
  uint8_t s_le[RsaModexp::kMaxWords * 4];
  std::ignore = BN_bn2lebinpad(key.d, d_le, 384);
  std::ignore = BN_bn2lebinpad(key.e, e_le, 384);
  RAND_bytes(m_le, 384);
  {
    /* m < N */
    BIGNUM* mv = BN_lebin2bn(m_le, 384, nullptr);
    BN_CTX* bc = BN_CTX_new();
    std::ignore = BN_mod(mv, mv, key.N, bc);
    std::ignore = BN_bn2lebinpad(mv, m_le, 384);
    BN_free(mv);
    BN_CTX_free(bc);
  }

  /* 1) 3072 位签名 m^d mod n */
  error += CheckModExp(rockey, vm, b, key, 3072, m_le, d_le, "3072 sign m^d");
  memcpy(s_le, b.data + kMAddr, 384);

  /* 2) 3072 位验签 s^e mod n == m */
  error += CheckModExp(rockey, vm, b, key, 3072, s_le, e_le, "3072 verify s^e");
  if (0 != memcmp(b.data + kMAddr, m_le, 384)) {
    rlLOGE(TAG, "3072 verify: 还原出的 m 不一致");
    ++error;
  }

  /* 3) 1536 位样例(同一实现覆盖更小宽度) */
  {
    RsaKey key2;
    if (!GenerateKey(1536, key2)) {
      rlLOGE(TAG, "GenerateKey(1536) 失败");
      ++error;
    } else {
      uint8_t m2[RsaModexp::kMaxWords * 4], d2[RsaModexp::kMaxWords * 4];
      std::ignore = BN_bn2lebinpad(key2.d, d2, 192);
      RAND_bytes(m2, 192);
      BIGNUM* mv = BN_lebin2bn(m2, 192, nullptr);
      BN_CTX* bc = BN_CTX_new();
      std::ignore = BN_mod(mv, mv, key2.N, bc);
      std::ignore = BN_bn2lebinpad(mv, m2, 192);
      BN_free(mv);
      BN_CTX_free(bc);
      error += CheckModExp(rockey, vm, b, key2, 1536, m2, d2, "1536 sign m^d");
    }
  }

  /* 4) 参数错误分支 */
  {
    int32_t argv[6] = {static_cast<int32_t>(kFileId), 0, kMAddr, kMAddr, kEAddr, 3072};

    vm.zero_ = 0;
    std::ignore = vm.OpFuncRSA(kOpModExp, 5, argv);
    if (0 == vm.zero_) {
      rlLOGE(TAG, "argc=5 未被拒绝");
      ++error;
    }

    vm.zero_ = 0;
    int32_t argv_unaligned[6] = {static_cast<int32_t>(kFileId), 0, kMAddr + 1, kMAddr, kEAddr, 3072};
    std::ignore = vm.OpFuncRSA(kOpModExp, 6, argv_unaligned);
    if (0 == vm.zero_) {
      rlLOGE(TAG, "非对齐地址未被拒绝");
      ++error;
    }

    vm.zero_ = 0;
    int32_t argv_bits[6] = {static_cast<int32_t>(kFileId), 0, kMAddr, kMAddr, kEAddr, 1000};
    const int rc_bits = vm.OpFuncRSA(kOpModExp, 6, argv_bits);
    if (rc_bits >= 0 || 0 == vm.zero_) { /* 必须中止(zero_ != 0), 否则调用方看到 exit 0 + 全 0 结果 */
      rlLOGE(TAG, "非法 bits 未被中止(rc=%d, zero_=%d)", rc_bits, vm.zero_);
      ++error;
    }

    vm.zero_ = 0;
    int32_t argv_file[6] = {0x1234, 0, kMAddr, kMAddr, kEAddr, 3072};
    const int rc_file = vm.OpFuncRSA(kOpModExp, 6, argv_file);
    if (rc_file >= 0 || 0 == vm.zero_) {
      rlLOGE(TAG, "不存在的模数文件未被中止(rc=%d, zero_=%d)", rc_file, vm.zero_);
      ++error;
    }
  }

  /* 5) CRT(完整私钥 + 中国剩余定理)与密钥校验 */
  {
    uint8_t s_crt[RsaModexp::kMaxWords * 4];
    memset(s_crt, 0, sizeof(s_crt));
    error += CheckCrt(rockey, vm, b, key, 3072, m_le, s_crt);
    if (0 != memcmp(s_crt, s_le, 384)) { /* CRT 结果必须与全宽模幂逐字节一致 */
      rlLOGE(TAG, "CRT 与全宽 ExRSAModExp 结果不一致");
      ++error;
    } else {
      rlLOGI(TAG, "CRT 结果 == 全宽 ExRSAModExp 结果");
    }
  }

  /* 6) ExRSAGenKey: 设备内生成 RSA 私钥(n/e/d/p/q/dmp1/dmq1/iqmp)并与 TASSL 对拍 */
  {
    rlLOGI(TAG, "=== ExRSAGenKey 用例(设备内生成完整私钥) ===");
    error += CheckGenKey(rockey, vm, b);
  }

  ok_out = (0 == error);
  return error;
}

}  // namespace

int Start(void* InOutBuf, void* ExtendBuf) {
  memset(InOutBuf, 0, 1024); /* 本用例不需要 Context_t 布局 */
  std::ignore = ExtendBuf;
  std::ignore = TAG;

  int error = 0;
#if !defined(__RockeyARM__)
  Emulator rockey(PERMISSION::kAdministrator);
  if (0 != rockey.Create("__rsamodexpvm__")) {
    rlLOGE(TAG, "Emulator::Create 失败");
    return 10086 - 1;
  }
  bool ok = false;
  error = RunCase(rockey, ok);
  rlLOGI(TAG, "RsaModexpVM opcode 用例: %s (error=%d)", ok ? "PASS" : "FAIL", error);
#endif /* !__RockeyARM__ */

  return 10086 - error;
}

}  // namespace dongle

rLANG_DECLARE_END

#if !defined(__RockeyARM__)
int main() {
  /*! Windows 下日志经 WriteConsoleW(stderr) 输出, 被重定向/管道捕获时会丢失
   *! ⇒ 允许 WT_RKEY_LOG=<path> 落盘(与 __Testing__dongle__ 同一约定)。 */
  if (const char* log_path = getenv("WT_RKEY_LOG")) {
    if (FILE* fp = fopen(log_path, "w"))
      machine::rlLoggingOutputFile(fp);
  }
  uint64_t InOutBuf[(3 << 10) / 8] = {0};
  uint64_t ExtendBuf[(1 << 10) / 8] = {0};
  return machine::dongle::Start(InOutBuf, ExtendBuf);
}
#endif /* !__RockeyARM__ */

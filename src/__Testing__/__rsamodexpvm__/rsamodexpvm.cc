#include <Interface/dongle.h>
#include <Interface/modexp.h>
#include <Interface/script.h>
#include <base/base.h>

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

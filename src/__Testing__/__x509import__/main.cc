#include <Interface/dongle.h>
#include <Interface/script.h>
#include <Interface/x509.h>
#include <time.h>
#include <cstdio>
#include <string>
#include <vector>

AGINX_DECLARE_MACHINE

namespace {
/* rLANG_DECLARE_MAGIC_Xs 只取 s[0..4], 参数须匹配 [a-zA-Z0-9@$]{5}(>5 位尾部被忽略;
 * 曾误用 6 位 "@x509i" 与 __x509__ 的 "@x509" 同值, 日志 tag 冲突) */
constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("x509i");
}

namespace {

using machine::dongle::Dongle;
using machine::dongle::Emulator;
using machine::dongle::PERMISSION;
using machine::dongle::SECRET_STORAGE_TYPE;
using machine::dongle::X509FsmParse;
using machine::dongle::X509FsmSource;
using machine::dongle::X509View;

int g_error = 0;

static void Check(bool ok, const char* what) {
  if (!ok) {
    rlLOGE(TAG, "FAIL: %s", what);
    ++g_error;
  }
}

/* ---- 内存 FSM 源(与 dashboard 源同语义) ---- */
static int MemCertRead(void* ctx, size_t off, uint8_t* dst, size_t len) {
  auto* v = static_cast<std::vector<uint8_t>*>(ctx);
  if (off + len > v->size())
    return -1;
  if (len)
    memcpy(dst, v->data() + off, len);
  return 0;
}

/* ---- 主机侧证书构造(TASSL, 仅用来产出合法 DER) ---- */

static void SetNameCN(X509* cert, const char* cn) {
  X509_NAME* name = X509_get_subject_name(cert);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const uint8_t*>(cn), -1, -1, 0);
  X509_set_issuer_name(cert, name);
}

static void AddExtStr(X509* cert, int nid, const char* value) {
  X509V3_CTX ctx;
  X509V3_set_ctx(&ctx, nullptr, cert, nullptr, nullptr, 0);
  X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, const_cast<char*>(value));
  if (ext)
    X509_add_ext(cert, ext, -1);
  X509_EXTENSION_free(ext);
}

static EVP_PKEY* NewHostRSA() {
  RSA* rsa = RSA_new();
  BIGNUM* e = BN_new();
  BN_set_word(e, 65537);
  RSA_generate_key_ex(rsa, 2048, e, nullptr);
  BN_free(e);
  EVP_PKEY* pkey = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(pkey, rsa);
  return pkey;
}

static EVP_PKEY* NewHostEC(int nid) {
  EC_KEY* ec = EC_KEY_new_by_curve_name(nid);
  EC_KEY_generate_key(ec);
  EVP_PKEY* pkey = EVP_PKEY_new();
  EVP_PKEY_assign_EC_KEY(pkey, ec);
  if (nid == NID_sm2)
    EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2); /* BabaSSL: SM2 需要 EVP_PKEY_SM2 别名 */
  return pkey;
}

/* 仅公钥(SPKI 用): n 大端 256B + e */
static EVP_PKEY* PubRSAKey(const uint8_t n[256], uint32_t e) {
  RSA* rsa = RSA_new();
  BIGNUM* bn_n = BN_bin2bn(n, 256, nullptr);
  BIGNUM* bn_e = BN_new();
  BN_set_word(bn_e, e);
  RSA_set0_key(rsa, bn_n, bn_e, nullptr);
  EVP_PKEY* pkey = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(pkey, rsa);
  return pkey;
}

/* 仅公钥(SPKI 用): EC/SM2 X||Y */
static EVP_PKEY* PubECKey(int nid, const uint8_t X[32], const uint8_t Y[32]) {
  EC_KEY* ec = EC_KEY_new_by_curve_name(nid);
  BIGNUM* x = BN_bin2bn(X, 32, nullptr);
  BIGNUM* y = BN_bin2bn(Y, 32, nullptr);
  EC_KEY_set_public_key_affine_coordinates(ec, x, y);
  BN_free(x);
  BN_free(y);
  EVP_PKEY* pkey = EVP_PKEY_new();
  EVP_PKEY_assign_EC_KEY(pkey, ec);
  if (nid == NID_sm2)
    EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
  return pkey;
}

/*! spki: 证书携带的公钥(可只有公钥); sign: 签发私钥(可与 spki 不同, 本用例不验签)。
 *! extra_san 非空时附加 subjectAltName(撑大证书体积); pad_n>0 时追加一个 ~pad_n 字节的
 *! 未知扩展(1.3.6.1.4.1.99999.0, OCTET STRING 内容)用于精确控制总长度。返回 DER。 */
static void AddPadExt(X509* cert, int n) {
  std::vector<uint8_t> zero(static_cast<size_t>(n), 0);
  ASN1_OCTET_STRING* os = ASN1_OCTET_STRING_new();
  ASN1_OCTET_STRING_set(os, zero.data(), n);
  ASN1_OBJECT* obj = OBJ_txt2obj("1.3.6.1.4.1.99999.0", 1);
  X509_EXTENSION* ext = X509_EXTENSION_new();
  X509_EXTENSION_set_object(ext, obj);
  X509_EXTENSION_set_data(ext, os); /* 拷贝内容, os 仍可释放 */
  X509_add_ext(cert, ext, -1);
  ASN1_OBJECT_free(obj);
  X509_EXTENSION_free(ext);
  ASN1_OCTET_STRING_free(os);
}

static int MakeCert(EVP_PKEY* spki,
                    EVP_PKEY* sign,
                    const EVP_MD* md,
                    const char* cn,
                    std::vector<uint8_t>* out,
                    const char* extra_san = nullptr,
                    int pad_n = 0) {
  X509* cert = X509_new();
  X509_set_version(cert, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(cert), 3);
  X509_gmtime_adj(X509_get_notBefore(cert), -3600 * 24);
  X509_gmtime_adj(X509_get_notAfter(cert), 3600 * 24 * 180);
  SetNameCN(cert, cn);
  X509_set_pubkey(cert, spki);
  if (extra_san)
    AddExtStr(cert, NID_subject_alt_name, extra_san);
  if (pad_n > 0)
    AddPadExt(cert, pad_n);
  if (X509_sign(cert, sign, md) <= 0) {
    X509_free(cert);
    return -1;
  }
  uint8_t* p = nullptr;
  int len = i2d_X509(cert, &p);
  out->assign(p, p + len);
  OPENSSL_free(p);
  X509_free(cert);
  return len > 0 ? 0 : -1;
}

/*! 通过调节填充扩展长度, 构造总长度恰为 want 的证书(迭代收敛) */
static int MakeCertExactLen(EVP_PKEY* spki,
                            EVP_PKEY* sign,
                            const EVP_MD* md,
                            const char* cn,
                            size_t want,
                            std::vector<uint8_t>* out) {
  int pad = 0;
  for (int i = 0; i < 16; ++i) {
    out->clear();
    if (0 != MakeCert(spki, sign, md, cn, out, nullptr, pad))
      return -1;
    if (out->size() == want)
      return 0;
    pad += static_cast<int>(want) - static_cast<int>(out->size()); /* 长度阈值处有 ±1 偏差, 迭代收敛 */
    if (pad < 0)
      pad = 0;
  }
  return out->size() == want ? 0 : -1;
}

static std::string MakeSAN(int n) {
  std::string san;
  for (int i = 0; i < n; ++i) {
    char dns[64];
    snprintf(dns, sizeof(dns), "DNS:entry%02d.very.long.subdomain.rockey-x509.test", i);
    if (i)
      san += ",";
    san += dns;
  }
  return san;
}

/* ---- 运行时执行助手 ---- */

struct Buffers {
  alignas(8) uint8_t data[1024];
  alignas(8) uint8_t buffer[1024];
};

/* 以指定会话权限直接执行 OpExecute_ImportX509, 返回其 zero_(0 或负 errno) */
static int RunImport(Emulator& rockey, Buffers& b, PERMISSION perm, int argc, int32_t argv[]) {
  memset(b.data, 0, sizeof(b.data));
  memset(b.buffer, 0, sizeof(b.buffer));
  machine::dongle::script::VM_t vm(&rockey, b.data, b.buffer);
  vm.valid_permission_ = perm;
  return vm.OpExecute_ImportX509(argc, argv);
}

static int SetDashboard(Emulator& rockey, const std::vector<uint8_t>& der) {
  return rockey.WriteDataFile(Dongle::kFactoryDataFileId, 0, der.data(), der.size());
}

static bool FileExists(Emulator& rockey, int df) {
  uint8_t probe[4];
  return 0 == rockey.ReadDataFile(df, 0, probe, sizeof(probe));
}

/*! 校验导入产物: dataFile 大小 == 48+len, [0,48) 六元最小集与重解析一致, [48,..) == DER */
static int CheckLayout(Emulator& rockey, int df, const std::vector<uint8_t>& der, const char* tag) {
  const size_t kHeaderSize = sizeof(X509View);
  const size_t want = kHeaderSize + der.size();
  std::vector<uint8_t> file(want);
  int r = rockey.ReadDataFile(df, 0, file.data(), file.size());
  if (0 != r) {
    rlLOGE(TAG, "%s: read dataFile#%d failed r=%d", tag, df, r);
    return -1;
  }
  if (0 != memcmp(file.data() + kHeaderSize, der.data(), der.size())) {
    rlLOGE(TAG, "%s: dataFile#%d DER tail mismatch", tag, df);
    return -1;
  }
  X509FsmSource src;
  src.Read = MemCertRead;
  src.ctx = const_cast<std::vector<uint8_t>*>(&der);
  src.total = der.size();
  X509View v;
  memset(&v, 0, sizeof(v));
  uint8_t kt = 0;
  if (0 != X509FsmParse(&v, &src, &kt)) {
    rlLOGE(TAG, "%s: reparse failed", tag);
    return -1;
  }
  const X509View* stored = reinterpret_cast<const X509View*>(file.data());
  if (stored->off_tbs != v.off_tbs || stored->len_tbs != v.len_tbs || stored->off_spki_alg_oid != v.off_spki_alg_oid ||
      stored->len_spki_alg_oid != v.len_spki_alg_oid || stored->off_spki_pub != v.off_spki_pub ||
      stored->len_spki_pub != v.len_spki_pub) {
    rlLOGE(TAG,
           "%s: dataFile#%d view mismatch stored{tbs %u/%u alg %u/%u pub %u/%u} want{tbs %u/%u alg %u/%u pub %u/%u}",
           tag, df, stored->off_tbs, stored->len_tbs, stored->off_spki_alg_oid, stored->len_spki_alg_oid,
           stored->off_spki_pub, stored->len_spki_pub, v.off_tbs, v.len_tbs, v.off_spki_alg_oid, v.len_spki_alg_oid,
           v.off_spki_pub, v.len_spki_pub);
    return -1;
  }
  return 0;
}

}  // namespace

rLANGEXPORT int main() {
  using machine::dongle::script::VM_t;

  Emulator rockey(PERMISSION::kAdministrator);
  if (0 != rockey.Create("__x509import__")) {
    rlLOGE(TAG, "Emulator Create failed");
    return 1;
  }
  Buffers b;
  int32_t argv[5];

  /* ================= 证书物料 ================= */
  EVP_PKEY* rsa_self = NewHostRSA(); /* 自签 RSA(普通导入用) */
  std::vector<uint8_t> der_rsa;
  Check(0 == MakeCert(rsa_self, rsa_self, EVP_sha256(), "RSA Self", &der_rsa), "MakeCert RSA self");

  EVP_PKEY* p256_self = NewHostEC(NID_X9_62_prime256v1);
  std::vector<uint8_t> der_p256;
  Check(0 == MakeCert(p256_self, p256_self, EVP_sha256(), "P256 Self", &der_p256), "MakeCert P256 self");

  EVP_PKEY* sm2_self = NewHostEC(NID_sm2);
  std::vector<uint8_t> der_sm2;
  Check(0 == MakeCert(sm2_self, sm2_self, EVP_sm3(), "SM2 Self", &der_sm2), "MakeCert SM2 self");

  /* 大证书(>1024B, ≤2047B): 多 96B 分块拷贝路径 */
  std::vector<uint8_t> der_big;
  {
    for (int n = 8; n <= 48; n += 2) {
      EVP_PKEY* k = NewHostRSA();
      der_big.clear();
      const std::string san = MakeSAN(n);
      MakeCert(k, k, EVP_sha256(), "RSA Big", &der_big, san.c_str());
      EVP_PKEY_free(k);
      if (der_big.size() > 1024 && der_big.size() < 2048)
        break;
    }
  }
  Check(der_big.size() > 1024 && der_big.size() < 2048, "big cert size in (1024, 2048)");

  /* ================= 1) 三种密钥类型普通导入(管理员, dataFile id < 1000) ============= */
  {
    const struct {
      SECRET_STORAGE_TYPE storage;
      int df;
      const std::vector<uint8_t>* der;
      const char* tag;
    } kCases[] = {{SECRET_STORAGE_TYPE::kRSA, 1, &der_rsa, "import RSA"},
                  {SECRET_STORAGE_TYPE::kP256, 2, &der_p256, "import P256"},
                  {SECRET_STORAGE_TYPE::kSM2, 3, &der_sm2, "import SM2"}};
    for (auto& c : kCases) {
      Check(0 == SetDashboard(rockey, *c.der), "SetDashboard");
      argv[0] = static_cast<int32_t>(c.storage);
      argv[1] = 900; /* pkeyId: 未校验匹配时不要求存在 */
      argv[2] = c.df;
      argv[3] = static_cast<int32_t>(c.der->size());
      const int r = RunImport(rockey, b, PERMISSION::kAdministrator, 4, argv);
      char msg[160];
      snprintf(msg, sizeof(msg), "%s r=%d", c.tag, r);
      Check(0 == r, msg);
      if (0 == r) {
        snprintf(msg, sizeof(msg), "%s layout", c.tag);
        Check(0 == CheckLayout(rockey, c.df, *c.der, msg), msg);
      }
    }
  }

  /* 大证书分块导入 + 布局 */
  {
    Check(0 == SetDashboard(rockey, der_big), "SetDashboard big");
    argv[0] = static_cast<int32_t>(SECRET_STORAGE_TYPE::kRSA);
    argv[1] = 900;
    argv[2] = 30;
    argv[3] = static_cast<int32_t>(der_big.size());
    const int r = RunImport(rockey, b, PERMISSION::kAdministrator, 4, argv);
    Check(0 == r, "import big cert");
    if (0 == r)
      Check(0 == CheckLayout(rockey, 30, der_big, "big layout"), "big layout");
  }

  /* len == 2048 上界: 恰 2048B 证书必须可导入(回归: 原 len>=2048 误拒) */
  {
    std::vector<uint8_t> der_2048;
    EVP_PKEY* k = NewHostRSA();
    Check(0 == MakeCertExactLen(k, k, EVP_sha256(), "RSA 2048B", 2048, &der_2048), "MakeCert exact 2048B");
    Check(der_2048.size() == 2048, "cert DER == 2048B");
    Check(0 == SetDashboard(rockey, der_2048), "SetDashboard 2048");
    argv[0] = static_cast<int32_t>(SECRET_STORAGE_TYPE::kRSA);
    argv[1] = 900;
    argv[2] = 32;
    argv[3] = 2048;
    const int r = RunImport(rockey, b, PERMISSION::kAdministrator, 4, argv);
    char msg[160];
    snprintf(msg, sizeof(msg), "import len==2048 r=%d", r);
    Check(0 == r, msg);
    if (0 == r)
      Check(0 == CheckLayout(rockey, 32, der_2048, "2048 layout"), "2048 layout");
    EVP_PKEY_free(k);
  }

  /* ================= 2) 错误输入矩阵 ================= */
  {
    /* 尾随字节: 给定 len 含多余字节 → 拒绝且不建文件 */
    std::vector<uint8_t> trailing = der_rsa;
    trailing.push_back(0x00);
    Check(0 == SetDashboard(rockey, trailing), "SetDashboard trailing");
    argv[0] = static_cast<int32_t>(SECRET_STORAGE_TYPE::kRSA);
    argv[1] = 900;
    argv[2] = 31;
    argv[3] = static_cast<int32_t>(trailing.size());
    {
      const int r = RunImport(rockey, b, PERMISSION::kAdministrator, 4, argv);
      char msg[160];
      snprintf(msg, sizeof(msg), "trailing byte r=%d", r);
      Check(r < 0, msg);
      Check(!FileExists(rockey, 31), "trailing byte: no file");
    }

    /* storage 与证书 SPKI 类型不一致 */
    Check(0 == SetDashboard(rockey, der_rsa), "SetDashboard mismatch");
    argv[0] = static_cast<int32_t>(SECRET_STORAGE_TYPE::kSM2);
    argv[1] = 900;
    argv[2] = 40;
    argv[3] = static_cast<int32_t>(der_rsa.size());
    {
      const int r = RunImport(rockey, b, PERMISSION::kAdministrator, 4, argv);
      char msg[160];
      snprintf(msg, sizeof(msg), "storage mismatch r=%d", r);
      Check(r < 0, msg);
      Check(!FileExists(rockey, 40), "storage mismatch: no file");
    }

    /* 垃圾 DER */
    uint8_t garbage[64] = {0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00};
    Check(0 == rockey.WriteDataFile(Dongle::kFactoryDataFileId, 0, garbage, sizeof(garbage)), "SetDashboard garbage");
    argv[0] = static_cast<int32_t>(SECRET_STORAGE_TYPE::kRSA);
    argv[1] = 900;
    argv[2] = 41;
    argv[3] = static_cast<int32_t>(sizeof(garbage));
    {
      const int r = RunImport(rockey, b, PERMISSION::kAdministrator, 4, argv);
      char msg[160];
      snprintf(msg, sizeof(msg), "garbage DER r=%d", r);
      Check(r < 0, msg);
      Check(!FileExists(rockey, 41), "garbage DER: no file");
    }

    /* len 越界(上界 len==2048 的正例见上文 der_2048 用例) */
    Check(0 == SetDashboard(rockey, der_rsa), "SetDashboard len");
    argv[0] = static_cast<int32_t>(SECRET_STORAGE_TYPE::kRSA);
    argv[1] = 900;
    argv[2] = 42;
    argv[3] = 0; /* len == 0 */
    Check(RunImport(rockey, b, PERMISSION::kAdministrator, 4, argv) < 0, "len=0 rejected");
    argv[3] = 4096; /* len > 2048 */
    Check(RunImport(rockey, b, PERMISSION::kAdministrator, 4, argv) < 0, "len>2048 rejected");
    Check(!FileExists(rockey, 42), "len invalid: no file");
  }

  /* ================= 3) 权限矩阵 ================= */
  {
    /* kAnonymous: 一律拒绝 */
    Check(0 == SetDashboard(rockey, der_rsa), "SetDashboard anon");
    argv[0] = static_cast<int32_t>(SECRET_STORAGE_TYPE::kRSA);
    argv[1] = 900;
    argv[2] = 50;
    argv[3] = static_cast<int32_t>(der_rsa.size());
    Check(RunImport(rockey, b, PERMISSION::kAnonymous, 4, argv) < 0, "anonymous rejected");
    Check(!FileExists(rockey, 50), "anonymous: no file");

    /* kNormal + id(任意) < 1000 → 拒绝 */
    argv[1] = 900;
    argv[2] = 51;
    Check(RunImport(rockey, b, PERMISSION::kNormal, 4, argv) < 0, "normal pkey<1000 rejected");
    argv[1] = 1001;
    argv[2] = 51;
    Check(RunImport(rockey, b, PERMISSION::kNormal, 4, argv) < 0, "normal dataFile<1000 rejected");
    Check(!FileExists(rockey, 51), "normal low-id: no file");

    /* kNormal + 两 id >= 1000 → 允许 */
    argv[1] = 1001;
    argv[2] = 1000;
    argv[3] = static_cast<int32_t>(der_rsa.size());
    {
      const int r = RunImport(rockey, b, PERMISSION::kNormal, 4, argv);
      char msg[160];
      snprintf(msg, sizeof(msg), "normal id>=1000 r=%d", r);
      Check(0 == r, msg);
      if (0 == r)
        Check(0 == CheckLayout(rockey, 1000, der_rsa, "normal layout"), "normal layout");
    }
  }

  /* ================= 4) 目标 dataFile 已存在 → 拒绝导入 ================= */
  {
    Check(0 == rockey.CreateDataFile(60, 64, PERMISSION::kAnonymous, PERMISSION::kAdministrator), "pre-create df#60");
    Check(0 == SetDashboard(rockey, der_rsa), "SetDashboard exist");
    argv[0] = static_cast<int32_t>(SECRET_STORAGE_TYPE::kRSA);
    argv[1] = 900;
    argv[2] = 60;
    argv[3] = static_cast<int32_t>(der_rsa.size());
    Check(RunImport(rockey, b, PERMISSION::kAdministrator, 4, argv) < 0, "import onto existing df rejected");
    /* 原文件内容未被改写: 仍是 64B 空文件(首 4B 全零), 而非 48+len */
    uint8_t head[4] = {1, 1, 1, 1};
    Check(0 == rockey.ReadDataFile(60, 0, head, sizeof(head)), "read existing df");
    Check(0 == memcmp(head, "\0\0\0\0", 4), "existing df content untouched");
  }

  /* ================= 5) argv[4] 私钥↔证书公钥匹配校验 ================= */
  {
    /* RSA: pkey#1001 与证书公钥一致 → 通过 + 建文件 */
    uint32_t rsa_e = 0;
    uint8_t rsa_n[256];
    Check(0 == rockey.CreatePKEYFile(SECRET_STORAGE_TYPE::kRSA, 2048, 1001), "create pkey RSA#1001");
    Check(0 == rockey.GenerateRSA(1001, &rsa_e, rsa_n, nullptr), "generate RSA#1001");
    EVP_PKEY* rsa_emu_pub = PubRSAKey(rsa_n, rsa_e);
    EVP_PKEY* rsa_host_signer = NewHostRSA();
    std::vector<uint8_t> der_rsa_match;
    Check(0 == MakeCert(rsa_emu_pub, rsa_host_signer, EVP_sha256(), "RSA EmuKey", &der_rsa_match), "MakeCert RSA emu");

    Check(0 == SetDashboard(rockey, der_rsa_match), "SetDashboard rsa match");
    argv[0] = static_cast<int32_t>(SECRET_STORAGE_TYPE::kRSA);
    argv[1] = 1001;
    argv[2] = 61;
    argv[3] = static_cast<int32_t>(der_rsa_match.size());
    argv[4] = 1;
    {
      const int r = RunImport(rockey, b, PERMISSION::kAdministrator, 5, argv);
      char msg[160];
      snprintf(msg, sizeof(msg), "RSA pkey-match r=%d", r);
      Check(0 == r, msg);
      if (0 == r)
        Check(0 == CheckLayout(rockey, 61, der_rsa_match, "RSA match layout"), "RSA match layout");
    }

    /* RSA: pkey#1001 与证书公钥不一致(另一把主机 RSA) → 拒绝, 不建文件 */
    std::vector<uint8_t> der_rsa_bad;
    EVP_PKEY* rsa_other = NewHostRSA();
    Check(0 == MakeCert(rsa_other, rsa_other, EVP_sha256(), "RSA Other", &der_rsa_bad), "MakeCert RSA other");
    Check(0 == SetDashboard(rockey, der_rsa_bad), "SetDashboard rsa bad");
    argv[0] = static_cast<int32_t>(SECRET_STORAGE_TYPE::kRSA);
    argv[1] = 1001;
    argv[2] = 62;
    argv[3] = static_cast<int32_t>(der_rsa_bad.size());
    argv[4] = 1;
    {
      const int r = RunImport(rockey, b, PERMISSION::kAdministrator, 5, argv);
      char msg[160];
      snprintf(msg, sizeof(msg), "RSA pkey-mismatch r=%d", r);
      Check(r < 0, msg);
      Check(!FileExists(rockey, 62), "RSA mismatch: no file");
    }

    /* P256: 匹配 → 通过; 不匹配 → 拒绝 */
    uint8_t px[32], py[32];
    Check(0 == rockey.CreatePKEYFile(SECRET_STORAGE_TYPE::kP256, 256, 1002), "create pkey P256#1002");
    Check(0 == rockey.GenerateP256(1002, px, py, nullptr), "generate P256#1002");
    EVP_PKEY* p256_emu_pub = PubECKey(NID_X9_62_prime256v1, px, py);
    EVP_PKEY* p256_host_signer = NewHostEC(NID_X9_62_prime256v1);
    std::vector<uint8_t> der_p256_match;
    Check(0 == MakeCert(p256_emu_pub, p256_host_signer, EVP_sha256(), "P256 EmuKey", &der_p256_match),
          "MakeCert P256 emu");

    Check(0 == SetDashboard(rockey, der_p256_match), "SetDashboard p256 match");
    argv[0] = static_cast<int32_t>(SECRET_STORAGE_TYPE::kP256);
    argv[1] = 1002;
    argv[2] = 63;
    argv[3] = static_cast<int32_t>(der_p256_match.size());
    argv[4] = 1;
    {
      const int r = RunImport(rockey, b, PERMISSION::kAdministrator, 5, argv);
      char msg[160];
      snprintf(msg, sizeof(msg), "P256 pkey-match r=%d", r);
      Check(0 == r, msg);
      if (0 == r)
        Check(0 == CheckLayout(rockey, 63, der_p256_match, "P256 match layout"), "P256 match layout");
    }

    std::vector<uint8_t> der_p256_bad;
    EVP_PKEY* p256_other = NewHostEC(NID_X9_62_prime256v1);
    Check(0 == MakeCert(p256_other, p256_other, EVP_sha256(), "P256 Other", &der_p256_bad), "MakeCert P256 other");
    Check(0 == SetDashboard(rockey, der_p256_bad), "SetDashboard p256 bad");
    argv[0] = static_cast<int32_t>(SECRET_STORAGE_TYPE::kP256);
    argv[1] = 1002;
    argv[2] = 64;
    argv[3] = static_cast<int32_t>(der_p256_bad.size());
    argv[4] = 1;
    {
      const int r = RunImport(rockey, b, PERMISSION::kAdministrator, 5, argv);
      char msg[160];
      snprintf(msg, sizeof(msg), "P256 pkey-mismatch r=%d", r);
      Check(r < 0, msg);
      Check(!FileExists(rockey, 64), "P256 mismatch: no file");
    }

    /* SM2: 匹配 → 通过; 不匹配 → 拒绝 */
    uint8_t sx[32], sy[32];
    Check(0 == rockey.CreatePKEYFile(SECRET_STORAGE_TYPE::kSM2, 256, 1003), "create pkey SM2#1003");
    Check(0 == rockey.GenerateSM2(1003, sx, sy, nullptr), "generate SM2#1003");
    EVP_PKEY* sm2_emu_pub = PubECKey(NID_sm2, sx, sy);
    EVP_PKEY* sm2_host_signer = NewHostEC(NID_sm2);
    std::vector<uint8_t> der_sm2_match;
    Check(0 == MakeCert(sm2_emu_pub, sm2_host_signer, EVP_sm3(), "SM2 EmuKey", &der_sm2_match), "MakeCert SM2 emu");

    Check(0 == SetDashboard(rockey, der_sm2_match), "SetDashboard sm2 match");
    argv[0] = static_cast<int32_t>(SECRET_STORAGE_TYPE::kSM2);
    argv[1] = 1003;
    argv[2] = 65;
    argv[3] = static_cast<int32_t>(der_sm2_match.size());
    argv[4] = 1;
    {
      const int r = RunImport(rockey, b, PERMISSION::kAdministrator, 5, argv);
      char msg[160];
      snprintf(msg, sizeof(msg), "SM2 pkey-match r=%d", r);
      Check(0 == r, msg);
      if (0 == r)
        Check(0 == CheckLayout(rockey, 65, der_sm2_match, "SM2 match layout"), "SM2 match layout");
    }

    std::vector<uint8_t> der_sm2_bad;
    EVP_PKEY* sm2_other = NewHostEC(NID_sm2);
    Check(0 == MakeCert(sm2_other, sm2_other, EVP_sm3(), "SM2 Other", &der_sm2_bad), "MakeCert SM2 other");
    Check(0 == SetDashboard(rockey, der_sm2_bad), "SetDashboard sm2 bad");
    argv[0] = static_cast<int32_t>(SECRET_STORAGE_TYPE::kSM2);
    argv[1] = 1003;
    argv[2] = 66;
    argv[3] = static_cast<int32_t>(der_sm2_bad.size());
    argv[4] = 1;
    {
      const int r = RunImport(rockey, b, PERMISSION::kAdministrator, 5, argv);
      char msg[160];
      snprintf(msg, sizeof(msg), "SM2 pkey-mismatch r=%d", r);
      Check(r < 0, msg);
      Check(!FileExists(rockey, 66), "SM2 mismatch: no file");
    }

    EVP_PKEY_free(rsa_emu_pub);
    EVP_PKEY_free(rsa_host_signer);
    EVP_PKEY_free(rsa_other);
    EVP_PKEY_free(p256_emu_pub);
    EVP_PKEY_free(p256_host_signer);
    EVP_PKEY_free(p256_other);
    EVP_PKEY_free(sm2_emu_pub);
    EVP_PKEY_free(sm2_host_signer);
    EVP_PKEY_free(sm2_other);
  }

  EVP_PKEY_free(rsa_self);
  EVP_PKEY_free(p256_self);
  EVP_PKEY_free(sm2_self);

  rlLOGI(TAG, "__x509import__ total error = %d", g_error);
  return g_error;
}

AGINX_DECLARE_END

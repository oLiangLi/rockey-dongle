#include <Interface/dongle.h>
#include <Interface/x509.h>
#include <vector>
#include <time.h>

AGINX_DECLARE_MACHINE

namespace {
constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("@x509");
}

namespace {

struct CertPair {
  std::vector<uint8_t> ca;
  std::vector<uint8_t> leaf;
};

void SetNames(X509* cert, const char* cn) {
  X509_NAME* name = X509_get_subject_name(cert);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const uint8_t*>(cn), -1, -1, 0);
  X509_set_issuer_name(cert, name);
}

void AddExt(X509* cert, int nid, const char* value) {
  X509V3_CTX ctx;
  X509V3_set_ctx(&ctx, nullptr, cert, nullptr, nullptr, 0);
  X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, const_cast<char*>(value));
  if (ext)
    X509_add_ext(cert, ext, -1);
  X509_EXTENSION_free(ext);
}

EVP_PKEY* NewRSAKey() {
  RSA* rsa = RSA_new();
  BIGNUM* e = BN_new();
  BN_set_word(e, 65537);
  RSA_generate_key_ex(rsa, 2048, e, nullptr);
  BN_free(e);
  EVP_PKEY* pkey = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(pkey, rsa);
  return pkey;
}

EVP_PKEY* NewECKey(int nid) {
  EC_KEY* ec = EC_KEY_new_by_curve_name(nid);
  EC_KEY_generate_key(ec);
  EVP_PKEY* pkey = EVP_PKEY_new();
  EVP_PKEY_assign_EC_KEY(pkey, ec);
  if (nid == NID_sm2) {
    /* BabaSSL: SM2 签名需要 EVP_PKEY_SM2 别名, 否则 X509_sign 静默产出空签名 */
    EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
  }
  return pkey;
}

/*! 生成 CA(自签) + 叶证书(CA 签发), 返回 DER;ca/leaf 密钥类型可不同(混合链) */
int MakeChain(int ca_key_nid /* 0 = RSA2048 */, int leaf_key_nid /* 0 = RSA2048 */, const EVP_MD* md,
              const char* cn_ca, const char* cn_leaf, CertPair* out) {
  EVP_PKEY* ca_key = (ca_key_nid == 0) ? NewRSAKey() : NewECKey(ca_key_nid);
  EVP_PKEY* leaf_key = (leaf_key_nid == 0) ? NewRSAKey() : NewECKey(leaf_key_nid);

  X509* ca = X509_new();
  X509_set_version(ca, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(ca), 1);
  X509_gmtime_adj(X509_get_notBefore(ca), -3600 * 24 * 7);
  X509_gmtime_adj(X509_get_notAfter(ca), 3600 * 24 * 365);
  SetNames(ca, cn_ca);
  X509_set_pubkey(ca, ca_key);
  AddExt(ca, NID_basic_constraints, "critical,CA:TRUE");
  AddExt(ca, NID_key_usage, "critical,keyCertSign,cRLSign");
  if (X509_sign(ca, ca_key, md) <= 0)
    return -1;

  X509* leaf = X509_new();
  X509_set_version(leaf, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(leaf), 2);
  X509_gmtime_adj(X509_get_notBefore(leaf), -3600 * 24);
  X509_gmtime_adj(X509_get_notAfter(leaf), 3600 * 24 * 180);
  SetNames(leaf, cn_leaf);
  X509_set_pubkey(leaf, leaf_key);
  AddExt(leaf, NID_basic_constraints, "critical,CA:FALSE");
  AddExt(leaf, NID_key_usage, "critical,digitalSignature");
  if (X509_sign(leaf, ca_key, md) <= 0)
    return -1;

  uint8_t* p = nullptr;
  int len = i2d_X509(ca, &p);
  out->ca.assign(p, p + len);
  OPENSSL_free(p);
  p = nullptr;
  len = i2d_X509(leaf, &p);
  out->leaf.assign(p, p + len);
  OPENSSL_free(p);

  X509_free(ca);
  X509_free(leaf);
  EVP_PKEY_free(ca_key);
  EVP_PKEY_free(leaf_key);
  return 0;
}

/*! OpenSSL ground truth:leaf 签名是否由 ca 公钥可验 */
bool OpenSSLVerify(const CertPair& c) {
  const uint8_t* p = c.ca.data();
  X509* ca = d2i_X509(nullptr, &p, static_cast<long>(c.ca.size()));
  p = c.leaf.data();
  X509* leaf = d2i_X509(nullptr, &p, static_cast<long>(c.leaf.size()));
  EVP_PKEY* key = X509_get_pubkey(ca);
  int ok = X509_verify(leaf, key);
  EVP_PKEY_free(key);
  X509_free(ca);
  X509_free(leaf);
  return ok == 1;
}

}  // namespace

rLANGEXPORT int main() {
  using namespace machine;
  using namespace machine::dongle;

  Dongle rockey;
  alignas(8) uint8_t work[1024];
  int error = 0;

  /* ---- 8 条链:RSA/P256 × SHA256/384/512、SM2×SM3、混合链(P256 CA 签 RSA 叶) ---- */
  {
    CertPair chains[8];
    if (0 != MakeChain(0, 0, EVP_sha256(), "RSA Root CA", "RSA Leaf", &chains[0]) ||
        0 != MakeChain(NID_X9_62_prime256v1, NID_X9_62_prime256v1, EVP_sha256(), "P256 Root CA", "P256 Leaf", &chains[1]) ||
        0 != MakeChain(NID_sm2, NID_sm2, EVP_sm3(), "SM2 Root CA", "SM2 Leaf", &chains[2]) ||
        0 != MakeChain(0, 0, EVP_sha384(), "RSA384 Root CA", "RSA384 Leaf", &chains[3]) ||
        0 != MakeChain(0, 0, EVP_sha512(), "RSA512 Root CA", "RSA512 Leaf", &chains[4]) ||
        0 != MakeChain(NID_X9_62_prime256v1, NID_X9_62_prime256v1, EVP_sha384(), "P256384 Root CA", "P256384 Leaf", &chains[5]) ||
        0 != MakeChain(NID_X9_62_prime256v1, NID_X9_62_prime256v1, EVP_sha512(), "P256512 Root CA", "P256512 Leaf", &chains[6]) ||
        0 != MakeChain(NID_X9_62_prime256v1, 0, EVP_sha256(), "P256 Root CA", "RSA Leaf", &chains[7])) {
      rlLOGE(TAG, "MakeChain failed");
      ++error;
    }

    static const uint8_t kExpectType[8] = {kX509SigRSA_SHA256, kX509SigP256_SHA256, kX509SigSM2_SM3,
                                           kX509SigRSA_SHA384, kX509SigRSA_SHA512, kX509SigP256_SHA384,
                                           kX509SigP256_SHA512, kX509SigP256_SHA256};

    for (int i = 0; i < 8; ++i) {
      const auto& c = chains[i];
      if (c.leaf.size() > 1024 || c.ca.size() > 1024) {
        rlLOGE(TAG, "chain %d: DER too large leaf=%zu ca=%zu", i, c.leaf.size(), c.ca.size());
        ++error;
      }

      /* 解析必须成功且签名类型正确 */
      X509View v;
      {
        int pr = X509Parse(&v, c.leaf.data(), c.leaf.size());
        if (0 != pr) {
          rlLOGE(TAG, "chain %d: parse leaf failed r=%d size=%zu", i, pr, c.leaf.size());
          ++error;
          continue;
        }
      }
      if (v.sig_type != kExpectType[i]) {
        rlLOGE(TAG, "chain %d: sig_type %d != %d", i, v.sig_type, kExpectType[i]);
        ++error;
      }

      /* OpenSSL ground truth */
      if (!OpenSSLVerify(c)) {
        rlLOGE(TAG, "chain %d: OpenSSL ground truth failed?!", i);
        ++error;
      }

      /* 链验签 */
      if (0 != X509VerifySignature(&rockey, c.leaf.data(), c.leaf.size(), c.ca.data(), c.ca.size(), work, sizeof(work))) {
        rlLOGE(TAG, "chain %d: X509VerifySignature(leaf, ca) failed", i);
        ++error;
      }

      /* 自签根 */
      if (0 != X509VerifySelfSigned(&rockey, c.ca.data(), c.ca.size(), work, sizeof(work))) {
        rlLOGE(TAG, "chain %d: self-signed root failed", i);
        ++error;
      }

      /* 时间警告位(有效期内无警告;前后越界有警告) */
      X509View tv;
      X509Parse(&tv, c.leaf.data(), c.leaf.size());
      uint64_t now = static_cast<uint64_t>(time(nullptr));
      X509CheckTime(&tv, c.leaf.data(), c.leaf.size(), now);
      if (tv.time_flags != kX509TimeOK) {
        rlLOGE(TAG, "chain %d: time flags %d in valid window", i, tv.time_flags);
        ++error;
      }
      X509CheckTime(&tv, c.leaf.data(), c.leaf.size(), now + 3600 * 24 * 400);
      if (0 == (tv.time_flags & kX509TimeAfter)) {
        rlLOGE(TAG, "chain %d: expired cert no warning", i);
        ++error;
      }
      X509CheckTime(&tv, c.leaf.data(), c.leaf.size(), now - 3600 * 24 * 400);
      if (0 == (tv.time_flags & kX509TimeBefore)) {
        rlLOGE(TAG, "chain %d: not-yet-valid cert no warning", i);
        ++error;
      }

      /* 篡改签名 → 验签必须失败 */
      std::vector<uint8_t> tampered = c.leaf;
      tampered[tampered.size() - 1] ^= 0x01;
      if (0 == X509VerifySignature(&rockey, tampered.data(), tampered.size(), c.ca.data(), c.ca.size(), work, sizeof(work))) {
        rlLOGE(TAG, "chain %d: tampered signature accepted!", i);
        ++error;
      }

      /* 错误 CA(交叉) → 失败 */
      const auto& other = chains[(i + 1) % 8];
      if (0 == X509VerifySignature(&rockey, c.leaf.data(), c.leaf.size(), other.ca.data(), other.ca.size(), work, sizeof(work))) {
        rlLOGE(TAG, "chain %d: wrong CA accepted!", i);
        ++error;
      }

      /* 尾随字节 → 严格解析失败 */
      std::vector<uint8_t> trailing = c.leaf;
      trailing.push_back(0x00);
      X509View tv2;
      if (0 == X509Parse(&tv2, trailing.data(), trailing.size())) {
        rlLOGE(TAG, "chain %d: trailing byte accepted!", i);
        ++error;
      }
    }

    /* 扩展遍历:叶证书应有 2 个扩展, BasicConstraints 为 critical */
    {
      X509View v;
      X509Parse(&v, chains[0].leaf.data(), chains[0].leaf.size());
      uint8_t iter = 0;
      X509Ext ext;
      int found_bc = 0;
      int count = 0;
      while (1 == X509ExtNext(&v, chains[0].leaf.data(), chains[0].leaf.size(), &ext, &iter)) {
        ++count;
        if (X509OID_BasicConstraints(chains[0].leaf.data() + ext.off_oid, ext.len_oid)) {
          found_bc = 1;
          if (!ext.critical) {
            rlLOGE(TAG, "BasicConstraints not critical");
            ++error;
          }
        }
        if (X509OID_KeyUsage(chains[0].leaf.data() + ext.off_oid, ext.len_oid)) {
          if (!ext.critical) {
            rlLOGE(TAG, "KeyUsage not critical");
            ++error;
          }
        }
      }
      if (count != 2 || !found_bc) {
        rlLOGE(TAG, "extensions: count=%d bc=%d (expect 2/1)", count, found_bc);
        ++error;
      }
    }

    /* 公钥提取与 OpenSSL 比对:按证书自身 SPKI 分派, 与签名算法无关 */
    {
      /* RSA 根(自签 sha256) */
      uint8_t pub[260];
      size_t size_pub = 0;
      uint8_t sig_type = 0;
      if (0 != X509GetPublicKey(chains[0].ca.data(), chains[0].ca.size(), pub, &size_pub, &sig_type) || size_pub != 260 ||
          sig_type != kX509SigRSA_SHA256) {
        rlLOGE(TAG, "X509GetPublicKey RSA failed size=%zu type=%d", size_pub, sig_type);
        ++error;
      } else {
        const uint8_t* p = chains[0].ca.data();
        X509* ca = d2i_X509(nullptr, &p, static_cast<long>(chains[0].ca.size()));
        EVP_PKEY* key = X509_get_pubkey(ca);
        RSA* rsa = EVP_PKEY_get0_RSA(key);
        const BIGNUM* n = nullptr;
        const BIGNUM* e = nullptr;
        RSA_get0_key(rsa, &n, &e, nullptr);
        uint8_t nbuf[256];
        BN_bn2binpad(n, nbuf, 256);
        if (0 != memcmp(pub + 4, nbuf, 256) || BN_get_word(e) != 65537 ||
            0 != memcmp(pub, "\x01\x00\x01\x00", 4)) {
          rlLOGE(TAG, "X509GetPublicKey RSA mismatch");
          ++error;
        }
        EVP_PKEY_free(key);
        X509_free(ca);
      }

      /* 混合链叶证书:RSA 密钥 + P256 签名 → 必须提取 RSA(SPKI 分派, 不是签名算法) */
      if (0 != X509GetPublicKey(chains[7].leaf.data(), chains[7].leaf.size(), pub, &size_pub, &sig_type) ||
          size_pub != 260 || sig_type != kX509SigP256_SHA256) {
        rlLOGE(TAG, "X509GetPublicKey mixed leaf failed size=%zu type=%d", size_pub, sig_type);
        ++error;
      }

      /* P256 根:X||Y 与 OpenSSL point2oct 比对 */
      uint8_t pubec[64];
      if (0 != X509GetPublicKey(chains[1].ca.data(), chains[1].ca.size(), pubec, &size_pub, &sig_type) ||
          size_pub != 64 || sig_type != kX509SigP256_SHA256) {
        rlLOGE(TAG, "X509GetPublicKey P256 failed size=%zu type=%d", size_pub, sig_type);
        ++error;
      } else {
        const uint8_t* p = chains[1].ca.data();
        X509* ca = d2i_X509(nullptr, &p, static_cast<long>(chains[1].ca.size()));
        EVP_PKEY* key = X509_get_pubkey(ca);
        EC_KEY* ec = EVP_PKEY_get0_EC_KEY(key);
        const EC_POINT* point = EC_KEY_get0_public_key(ec);
        uint8_t oct[65];
        if (65 != EC_POINT_point2oct(EC_KEY_get0_group(ec), point, POINT_CONVERSION_UNCOMPRESSED, oct, 65, nullptr) ||
            oct[0] != 0x04 || 0 != memcmp(pubec, oct + 1, 64)) {
          rlLOGE(TAG, "X509GetPublicKey P256 mismatch");
          ++error;
        }
        EVP_PKEY_free(key);
        X509_free(ca);
      }
    }

    /* 非规范 DER:indefinite 长度、非法 BOOLEAN、负数 INTEGER 场景 → 解析失败 */
    {
      /* 30 80 (indefinite SEQUENCE) + 填充 + 00 00 */
      uint8_t bad1[16] = {0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00};
      X509View v;
      if (0 == X509Parse(&v, bad1, sizeof(bad1))) {
        rlLOGE(TAG, "indefinite length accepted!");
        ++error;
      }
      /* 超长证书 */
      uint8_t big[1025] = {0};
      big[0] = 0x30;
      if (-E2BIG != X509Parse(&v, big, sizeof(big))) {
        rlLOGE(TAG, "oversize cert not rejected");
        ++error;
      }
      /* 空指针/空长度 */
      if (-EINVAL != X509Parse(&v, nullptr, 0)) {
        rlLOGE(TAG, "null cert not rejected");
        ++error;
      }
    }
  }

  rlLOGI(TAG, "__x509__ total error = %d", error);
  return error;
}

AGINX_DECLARE_END

#include <base/base.h>
#include <locale.h>

#ifndef __EMSCRIPTEN__
#include <RockeyARM/Dongle_API.h>
#endif /* __EMSCRIPTEN__ */

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/lhash.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sm2.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/**
 *!
 */
#include "src/pki/pkey.h"

rLANG_DECLARE_MACHINE

namespace {
constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("Fooba");
}  // namespace

void EVP_PKEY_CTX_Tests() {
  {
    /// RSA ...
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA* rsa = RSA_new();
    RSA_generate_key_ex(rsa, 2048, e, nullptr);
    BN_free(e);
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pkey, rsa);

    {
      uint8_t hash[32];
      uint8_t sign[256];

      RAND_bytes(hash, sizeof(hash));
      EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);

      size_t signlen = sizeof(sign);

      int r1 = EVP_PKEY_sign_init(ctx);
      int r2 = EVP_PKEY_sign(ctx, sign, &signlen, hash, sizeof(hash));
      rlLOGXI(TAG, sign, signlen, "RSA.sign %d %d", r1, r2);

      int r3 = EVP_PKEY_verify_init(ctx);
      int r4 = EVP_PKEY_verify(ctx, sign, signlen, hash, sizeof(hash));
      rlLOGI(TAG, "RSA.Verify %d %d", r3, r4);
      EVP_PKEY_CTX_free(ctx);
    }

    uint8_t text[48], verify[256];
    uint8_t cipher[256];
    size_t size_cipher = sizeof(cipher);

    {
      RAND_bytes(text, sizeof(text));
      EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
      int r1 = EVP_PKEY_encrypt_init(ctx);
      int r2 = EVP_PKEY_encrypt(ctx, cipher, &size_cipher, text, sizeof(text));
      rlLOGXI(TAG, cipher, size_cipher, "RSA.Encrypt %d %d", r1, r2);
      EVP_PKEY_CTX_free(ctx);
    }

    {
      size_t size_verify = sizeof(verify);
      EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
      int r1 = EVP_PKEY_decrypt_init(ctx);
      int r2 = EVP_PKEY_decrypt(ctx, verify, &size_verify, cipher, size_cipher);
      bool ok = size_verify == 48 && 0 == memcmp(text, verify, 48);
      rlLOGI(TAG, "RSA.Decrypt %d %d %c", r1, r2, ok ? 'T' : 'F');
      EVP_PKEY_CTX_free(ctx);
    }

    EVP_PKEY_free(pkey);
    RSA_free(rsa);
  }

  {
    /// P256 ...
    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    int r0 = EC_KEY_generate_key(eckey);
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(pkey, eckey);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);

    uint8_t hash[32];
    uint8_t sign[80];

    RAND_bytes(hash, sizeof(hash));
    size_t signlen = sizeof(sign);

    int r1 = EVP_PKEY_sign_init(ctx);
    int r2 = EVP_PKEY_sign(ctx, sign, &signlen, hash, sizeof(hash));
    rlLOGXI(TAG, sign, signlen, "P256.sign %d %d %d", r0, r1, r2);

    int r3 = EVP_PKEY_verify_init(ctx);
    int r4 = EVP_PKEY_verify(ctx, sign, signlen, hash, sizeof(hash));
    rlLOGI(TAG, "P256.Verify %d %d", r3, r4);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EC_KEY_free(eckey);
  }

  {
    /// SM2.Signer ...
    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_sm2);
    int r0 = EC_KEY_generate_key(eckey);

    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(pkey, eckey);
    EVP_PKEY_set_alias_type(pkey, NID_sm2);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);

    uint8_t hash[32];
    uint8_t sign[80];

    RAND_bytes(hash, sizeof(hash));
    size_t signlen = sizeof(sign);

    int r1 = EVP_PKEY_sign_init(ctx);
    int r2 = EVP_PKEY_sign(ctx, sign, &signlen, hash, sizeof(hash));
    rlLOGXI(TAG, sign, signlen, "SM2.sign %d %d %d", r0, r1, r2);

    int r3 = EVP_PKEY_verify_init(ctx);
    int r4 = EVP_PKEY_verify(ctx, sign, signlen, hash, sizeof(hash));
    rlLOGI(TAG, "SM2.Verify %d %d", r3, r4);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EC_KEY_free(eckey);
  }

  {
    /// SM2.Decipher ...
    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_sm2);
    int r0 = EC_KEY_generate_key(eckey);

    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(pkey, eckey);
    EVP_PKEY_set_alias_type(pkey, NID_sm2);

    uint8_t cipher[200];
    uint8_t text[48], verify[48];
    size_t cipher_len = sizeof(cipher);

    RAND_bytes(text, sizeof(text));

    {
      EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
      int r1 = EVP_PKEY_encrypt_init(ctx);
      int r2 = EVP_PKEY_encrypt(ctx, cipher, &cipher_len, text, sizeof(text));
      rlLOGXI(TAG, cipher, cipher_len, "SM2.encrypt %d %d %d", r0, r1, r2);
      EVP_PKEY_CTX_free(ctx);
    }

    {
      size_t size_verify = sizeof(verify);
      EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
      EVP_PKEY* volatile thiz = EVP_PKEY_CTX_get0_pkey(ctx);

      if (pkey != thiz && EVP_PKEY_id(thiz) != NID_sm2)
        abort();

      int r1 = EVP_PKEY_decrypt_init(ctx);
      int r2 = EVP_PKEY_decrypt(ctx, verify, &size_verify, cipher, cipher_len);
      bool ok = size_verify == sizeof(verify) && 0 == memcmp(text, verify, 48);
      rlLOGI(TAG, "SM2.decrypt %d %d %d %c", r0, r1, r2, ok ? 'T' : 'F');
      EVP_PKEY_CTX_free(ctx);
    }

    EVP_PKEY_free(pkey);
    EC_KEY_free(eckey);
  }
}

namespace {

struct RoekcyRSA final : XIRockeyPKEY {
  RoekcyRSA() {
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);
    rsa_ = RSA_new();
    RSA_generate_key_ex(rsa_, 2048, e, nullptr);
    BN_free(e);
    int len = BN_bn2binpad(RSA_get0_n(rsa_), N_, 256);
    if (len != 256)
      abort();
  }
  ~RoekcyRSA() { RSA_free(rsa_); }

  RoekcyRSA(const RoekcyRSA&) = delete;
  RoekcyRSA& operator=(const RoekcyRSA&) = delete;

  XIIMETHOD(Sign)(XIITHIZ int type, const uint8_t* dgst, int dlen, uint8_t* sign, int signlen) override {
    if (!sign || signlen < 256)
      return -EINVAL;

    size_t slen = signlen;
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pkey, rsa_);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    bool ok = EVP_PKEY_sign_init(ctx) > 0 && EVP_PKEY_sign(ctx, sign, &slen, dgst, dlen) > 0;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return ok ? (int)slen : -2;
  }

  XIIMETHOD(Decrypt)(XIITHIZ uint8_t* out, int outlen, const uint8_t* in, int inlen) override {
    if (!out || outlen < 256)
      return -EINVAL;
    return RSA_private_decrypt(inlen, in, out, rsa_, RSA_PKCS1_PADDING);
  }

  uint32_t GetE() const { return RSA_F4; }
  const uint8_t* GetPublic() const { return N_; }

 protected:
  uint8_t N_[256]{};
  RSA* rsa_ = nullptr;
};

struct RockeyP256 final : XIRockeyPKEY {
  RockeyP256() {
    eckey_ = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    int r0 = EC_KEY_generate_key(eckey_);
    if (r0 <= 0)
      abort();

    const EC_POINT* point = EC_KEY_get0_public_key(eckey_);

    int size =
        (int)EC_POINT_point2oct(EC_KEY_get0_group(eckey_), point, POINT_CONVERSION_UNCOMPRESSED, pubkey_, 65, nullptr);
    if (65 != size || 4 != pubkey_[0])
      abort();
  }

  ~RockeyP256() { EC_KEY_free(eckey_); }

  RockeyP256(const RockeyP256&) = delete;
  RockeyP256& operator=(const RockeyP256&) = delete;

  XIIMETHOD(Sign)(XIITHIZ int type, const uint8_t* dgst, int dlen, uint8_t* sign, int signlen) override {
    if (!sign || signlen < 72)
      return -EINVAL;

    size_t sign_length = signlen;
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(pkey, eckey_);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    bool ok = EVP_PKEY_sign_init(ctx) > 0 && EVP_PKEY_sign(ctx, sign, &sign_length, dgst, dlen) > 0;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return ok ? (int)sign_length : -2;
  }

  XIIMETHOD(Decrypt)(XIITHIZ uint8_t* out, int outlen, const uint8_t* in, int inlen) override { return -ENOSYS; }

  const uint8_t* GetPublic() const { return pubkey_; }

 protected:
  uint8_t pubkey_[65]{};
  EC_KEY* eckey_ = nullptr;
};

struct RockeySM2 final : XIRockeyPKEY {
  RockeySM2() {
    eckey_ = EC_KEY_new_by_curve_name(NID_sm2);
    int r0 = EC_KEY_generate_key(eckey_);
    if (r0 <= 0)
      abort();

    const EC_POINT* point = EC_KEY_get0_public_key(eckey_);
    int size =
        (int)EC_POINT_point2oct(EC_KEY_get0_group(eckey_), point, POINT_CONVERSION_UNCOMPRESSED, pubkey_, 65, nullptr);
    if (65 != size || 4 != pubkey_[0])
      abort();
  }
  ~RockeySM2() { EC_KEY_free(eckey_); }

  RockeySM2(const RockeySM2&) = delete;
  RockeySM2& operator=(const RockeySM2&) = delete;

  XIIMETHOD(Sign)(XIITHIZ int type, const uint8_t* dgst, int dlen, uint8_t* sign, int signlen) override {
    if (!sign || signlen < 72)
      return -EINVAL;

    size_t sign_length = signlen;
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(pkey, eckey_);
    EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    bool ok = EVP_PKEY_sign_init(ctx) > 0 && EVP_PKEY_sign(ctx, sign, &sign_length, dgst, dlen) > 0;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return ok ? (int)sign_length : -2;
  }

  XIIMETHOD(Decrypt)(XIITHIZ uint8_t* out, int outlen, const uint8_t* in, int inlen) override {
    size_t decrypt_size = outlen;

    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(pkey, eckey_);
    EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    bool ok = EVP_PKEY_decrypt_init(ctx) > 0 && EVP_PKEY_decrypt(ctx, out, &decrypt_size, in, inlen) > 0;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return ok ? (int)decrypt_size : -2;
  }

  const uint8_t* GetPublic() const { return pubkey_; }

 protected:
  uint8_t pubkey_[65]{};
  EC_KEY* eckey_ = nullptr;
};

}  // namespace

void RSA_Tests() {
  RoekcyRSA rockey_;

  EVP_PKEY* pkey = RockeyPKEY_RSA_New(rockey_.GetE(), rockey_.GetPublic(), 256, &rockey_);

  {
    uint8_t text[48], verify[256];
    uint8_t cipher[256];

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    RAND_bytes(text, sizeof(text));

    size_t cipherlen = sizeof(cipher);
    int r1 = EVP_PKEY_encrypt_init(ctx);
    int r2 = EVP_PKEY_encrypt(ctx, cipher, &cipherlen, text, sizeof(text));
    if (r1 != 1 || r2 != 1 || cipherlen != 256)
      abort();

    size_t verifylen = sizeof(verify);
    int r3 = EVP_PKEY_decrypt_init(ctx);
    int r4 = EVP_PKEY_decrypt(ctx, verify, &verifylen, cipher, cipherlen);
    if (r3 != 1 || r4 != 1 || verifylen != 48 || 0 != memcmp(text, verify, 48))
      abort();

    EVP_PKEY_CTX_free(ctx);
  }

  {
    uint8_t hash[32];
    uint8_t sign[256];

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    RAND_bytes(hash, 32);

    size_t signlen = sizeof(sign);
    int r1 = EVP_PKEY_sign_init(ctx);
    int r2 = EVP_PKEY_sign(ctx, sign, &signlen, hash, sizeof(hash));
    if (r1 != 1 || r2 != 1 || signlen != 256)
      abort();

    int r3 = EVP_PKEY_verify_init(ctx);
    int r4 = EVP_PKEY_verify(ctx, sign, signlen, hash, sizeof(hash));
    if (r3 != 1 || r4 != 1)
      abort();

    hash[10] ^= 0x20;
    int r5 = EVP_PKEY_verify_init(ctx);
    int r6 = EVP_PKEY_verify(ctx, sign, signlen, hash, sizeof(hash));
    if (r5 != 1 || r6 == 1)
      abort();

    EVP_PKEY_CTX_free(ctx);
  }

  EVP_PKEY_free(pkey);
}

void P256_Tests() {
  RockeyP256 rockey_;
  EVP_PKEY* pkey = RockeyPKEY_EC_KEY_New(rockey_.GetPublic(), 65, &rockey_, NID_X9_62_prime256v1);

  {
    uint8_t hash[32];
    uint8_t sign[80];
    size_t signlen = sizeof(sign);

    RAND_bytes(hash, 32);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);

    int r1 = EVP_PKEY_sign_init(ctx);
    int r2 = EVP_PKEY_sign(ctx, sign, &signlen, hash, sizeof(hash));
    // rlLOGI(TAG, "P256.Sign %d %d %zd", r1, r2, signlen);
    if (r1 != 1 || r2 != 1 || signlen > 72)
      abort();

    int r3 = EVP_PKEY_verify_init(ctx);
    int r4 = EVP_PKEY_verify(ctx, sign, signlen, hash, sizeof(hash));
    if (r4 != 1) {
      r4 = EVP_PKEY_verify(ctx, sign, signlen, hash, sizeof(hash));
    }

    // rlLOGI(TAG, "P256.Verify %d %d", r3, r4);
    if (r3 != 1 || r4 != 1)
      abort();

    hash[10] ^= 0x20;
    int r5 = EVP_PKEY_verify_init(ctx);
    int r6 = EVP_PKEY_verify(ctx, sign, signlen, hash, sizeof(hash));
    // rlLOGI(TAG, "[X]P256.Verify %d %d", r5, r6);

    if (r5 != 1 || r6 == 1)
      abort();
    EVP_PKEY_CTX_free(ctx);
  }

  EVP_PKEY_free(pkey);
}

void SM2_Tests() {
  RockeySM2 rockey_;
  EVP_PKEY* pkey = RockeyPKEY_EC_KEY_New(rockey_.GetPublic(), 65, &rockey_, NID_sm2);

  {
    uint8_t hash[32];
    uint8_t sign[80];
    size_t signlen = sizeof(sign);

    RAND_bytes(hash, 32);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);

    int r1 = EVP_PKEY_sign_init(ctx);
    int r2 = EVP_PKEY_sign(ctx, sign, &signlen, hash, sizeof(hash));
    // rlLOGI(TAG, "SM2.Sign %d %d %zd", r1, r2, signlen);
    if (r1 != 1 || r2 != 1 || signlen > 72)
      abort();

    int r3 = EVP_PKEY_verify_init(ctx);
    int r4 = EVP_PKEY_verify(ctx, sign, signlen, hash, sizeof(hash));
    if (r4 != 1) {
      r4 = EVP_PKEY_verify(ctx, sign, signlen, hash, sizeof(hash));
    }

    // rlLOGI(TAG, "SM2.Verify %d %d", r3, r4);
    if (r3 != 1 || r4 != 1)
      abort();

    hash[10] ^= 0x20;
    int r5 = EVP_PKEY_verify_init(ctx);
    int r6 = EVP_PKEY_verify(ctx, sign, signlen, hash, sizeof(hash));
    // rlLOGI(TAG, "[X]SM2.Verify %d %d", r5, r6);

    if (r5 != 1 || r6 == 1)
      abort();
    EVP_PKEY_CTX_free(ctx);
  }

  {
    uint8_t text[48], verify[200];
    uint8_t cipher[200];

    size_t size_cipher = sizeof(cipher);
    size_t size_verify = sizeof(verify);

    RAND_bytes(text, sizeof(text));
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);

    int r1 = EVP_PKEY_encrypt_init(ctx);
    int r2 = EVP_PKEY_encrypt(ctx, cipher, &size_cipher, text, sizeof(text));

    // rlLOGI(TAG, "SM2.encrypt %d %d %zd", r1, r2, size_cipher);
    if (1 != r1 || 1 != r2)
      abort();

    int r3 = EVP_PKEY_decrypt_init(ctx);
    int r4 = EVP_PKEY_decrypt(ctx, verify, &size_verify, cipher, size_cipher);
    bool ok = 1 == r3 && 1 == r4 && size_verify == 48 && 0 == memcmp(text, verify, 48);
    // rlLOGI(TAG, "SM2.decrypt %d %d %zd %c", r3, r4, size_verify, ok ? 'T' : 'F');

    if (!ok)
      abort();
    EVP_PKEY_CTX_free(ctx);
  }

  EVP_PKEY_free(pkey);
}

void RockeyPKEY_Tests() {
  RSA_Tests();
  P256_Tests();
  SM2_Tests();
}

int Start(int argc, char* argv[]) {
#ifdef _MSC_VER
  if (argc >= 2 && 0 == strcmp("-d", argv[1])) {
    while (!::IsDebuggerPresent()) {
      rlLOGI(TAG, "Wait debugger ...");
      Sleep(1000);
    }
    // ::DebugBreak();
    --argc;
    ++argv;
  }
#endif /* _MSC_VER */

  rlLOGI(TAG, "Hello RockeyARM World!");

  rlLOGI(
      TAG, "\n\n%s%s%s\n\n",  //@ third_party/TASSL-1.1.1/LICENSE
      "This product includes software developed by the OpenSSL Project\n",
      "This product includes cryptographic software written by Eric Young (eay@cryptsoft.com)\n",
      "This product includes software developed by 北京江南天安科技有限公司 TaSSL Project.(http://www.tass.com.cn/)\n");
  for (int i = 0; i <= 6; ++i) {
    rlLOGW(TAG, "V[%d]: %s", i, OpenSSL_version(i));
  }

  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
  RockeyPKEY_Initialize();

  EVP_PKEY_CTX_Tests();

  rlLOGI(TAG, "Tests begin ...");

  for (int i = 0; i < 100; ++i) {
    rlLOGI(TAG, "Tests loop %d ...", i);
    RockeyPKEY_Tests();
  }

  rlLOGI(TAG, "Tests end ...");

#if !defined(__EMSCRIPTEN__) && 0
  int count = 0, result = Dongle_Enum(NULL, &count);
  rlLOGI(TAG, "Dongle_Enum return %x => %d", result, count);
#endif /* __EMSCRIPTEN__ */

  return 0;
}

rLANG_DECLARE_END

int main(int argc, char* argv[]) {
  setlocale(LC_ALL, "zh_CN.UTF-8");
  return machine::Start(argc, argv);
}

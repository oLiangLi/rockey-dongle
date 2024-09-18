#include <Interface/dongle.h>
#include <base/base.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include "RockeyARM/Dongle_API.h"

/* Copy from sm2_crypt.c */
struct SM2_Ciphertext_st {
  BIGNUM* C1x;
  BIGNUM* C1y;
  ASN1_OCTET_STRING* C3;
  ASN1_OCTET_STRING* C2;
};

ASN1_SEQUENCE(SM2_Ciphertext) = {
  ASN1_SIMPLE(SM2_Ciphertext, C1x, BIGNUM),
  ASN1_SIMPLE(SM2_Ciphertext, C1y, BIGNUM),
  ASN1_SIMPLE(SM2_Ciphertext, C3, ASN1_OCTET_STRING),
  ASN1_SIMPLE(SM2_Ciphertext, C2, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(SM2_Ciphertext)

IMPLEMENT_ASN1_FUNCTIONS(SM2_Ciphertext)

rLANG_DECLARE_MACHINE

namespace {
constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("DONGLE");
}

namespace dongle {

int SM2Cipher_TextToASN1(const uint8_t* text_cipher, size_t cipher_len, uint8_t* buffer) {
  DONGLE_VERIFY(cipher_len > 96 && cipher_len <= 1024);

  SM2_Ciphertext_st* ciphertext = SM2_Ciphertext_new();
  ciphertext->C1x = BN_bin2bn(&text_cipher[0], 32, nullptr);
  ciphertext->C1y = BN_bin2bn(&text_cipher[32], 32, nullptr);
  ciphertext->C3 = ASN1_OCTET_STRING_new();
  ciphertext->C2 = ASN1_OCTET_STRING_new();

  DONGLE_VERIFY(ciphertext->C1x && ciphertext->C1y && ciphertext->C3 && ciphertext->C2);
  DONGLE_VERIFY(ASN1_OCTET_STRING_set(ciphertext->C3, &text_cipher[64], 32) > 0);
  DONGLE_VERIFY(ASN1_OCTET_STRING_set(ciphertext->C2, &text_cipher[96], static_cast<int>(cipher_len - 96)) > 0);

  int result = i2d_SM2_Ciphertext(ciphertext, &buffer);
  SM2_Ciphertext_free(ciphertext);

  return result;
}
int SM2Cipher_ASN1ToText(const uint8_t* asn1_cipher, size_t cipher_len, uint8_t* buffer) {
  const uint8_t* p = asn1_cipher;
  DONGLE_VERIFY(cipher_len <= 1024);
  SM2_Ciphertext_st* ciphertext = d2i_SM2_Ciphertext(nullptr, &p, static_cast<int>(cipher_len));
  if (!ciphertext)
    return -EINVAL;

  int result = -EINVAL;
  if (p - asn1_cipher == cipher_len && ciphertext->C3->length == 32 && ciphertext->C2->length > 0) {
    if (BN_bn2binpad(ciphertext->C1x, &buffer[0], 32) > 0 && BN_bn2binpad(ciphertext->C1y, &buffer[32], 32) > 0) {
      memcpy(&buffer[64], ciphertext->C3->data, 32);
      memcpy(&buffer[96], ciphertext->C2->data, ciphertext->C2->length);
      result = 96 + ciphertext->C2->length;
    }
  }
  SM2_Ciphertext_free(ciphertext);
  return result;
}

int Dongle::RandBytes(uint8_t* buffer, size_t size) {
  return DONGLE_CHECK(Dongle_GenRandom(handle_, static_cast<int>(size), buffer));
}
int Dongle::SeedSecret(const void* input, size_t size, void* value) {
  return DONGLE_CHECK(Dongle_Seed(handle_, const_cast<uint8_t*>(static_cast<const uint8_t*>(input)),
                                  static_cast<int>(size), static_cast<uint8_t*>(value)));
}
int Dongle::GetRealTime(DWORD* time) {
  return DONGLE_CHECK(Dongle_GetUTCTime(handle_, time));
}
int Dongle::GetExpireTime(DWORD* time) {
  return DONGLE_CHECK(Dongle_GetDeadline(handle_, time));
}
int Dongle::GetTickCount(DWORD* ticks) {
  *ticks = static_cast<DWORD>(rLANG_GetTickCount());
  return 0;
}

int Dongle::GetDongleInfo(DONGLE_INFO* info) {
  if (!handle_)
    return -EBADF;
  *info = dongle_info_;
  return 0;
}
int Dongle::GetPINState(PERMISSION* state) {
  /* *state = PERMISSION::kAnonymous; */
  return DONGLE_CHECK(("Dongle_GetPINState(state)", DONGLE_FAILED));
}

rLANG_ABIREQUIRE(static_cast<int>(LED_STATE::kOff) == LED_OFF && static_cast<int>(LED_STATE::kOn) == LED_ON &&
                 static_cast<int>(LED_STATE::kBlink) == LED_BLINK);
int Dongle::SetLEDState(LED_STATE state) {
  return DONGLE_CHECK(Dongle_LEDControl(handle_, static_cast<int>(state)));
}

int Dongle::ReadShareMemory(uint8_t buffer[32]) {
  return DONGLE_CHECK(Dongle_ReadShareMemory(handle_, &buffer[0]));
}
int Dongle::WriteShareMemory(const uint8_t buffer[32]) {
  return DONGLE_CHECK(Dongle_WriteShareMemory(handle_, const_cast<uint8_t*>(&buffer[0]), 32));
}


int Dongle::DeleteFile(SECRET_STORAGE_TYPE type_, int id) {
  WORD type;
  switch (type_) {
    case SECRET_STORAGE_TYPE::kData:
      type = FILE_DATA;
      break;
    case SECRET_STORAGE_TYPE::kRSA:
      type = FILE_PRIKEY_RSA;
      break;
    case SECRET_STORAGE_TYPE::kP256:
    case SECRET_STORAGE_TYPE::kSM2:
      type = FILE_PRIKEY_ECCSM2;
      break;
    case SECRET_STORAGE_TYPE::kSM4:
    case SECRET_STORAGE_TYPE::kTDES:
      type = FILE_KEY;
      break;
    default:
      return -EINVAL;
  }

  return DONGLE_CHECK(Dongle_DeleteFile(handle_, type, id));
}

int Dongle::CreateDataFile(int id, size_t size, PERMISSION read, PERMISSION write) {
  DATA_FILE_ATTR attr;
  attr.m_Size = static_cast<DWORD>(size);
  attr.m_Lic.m_Read_Priv = static_cast<uint8_t>(read);
  attr.m_Lic.m_Write_Priv = static_cast<uint8_t>(write);
  return DONGLE_CHECK(Dongle_CreateFile(handle_, FILE_DATA, id, reinterpret_cast<uint8_t*>(&attr)));
}
int Dongle::WriteDataFile(int id, size_t offset, const void* buffer, size_t size) {
  if (id == kFactoryDataFileId)
    return DONGLE_CHECK(Dongle_WriteData(handle_, static_cast<int>(offset),
                                         static_cast<uint8_t*>(const_cast<void*>(buffer)), static_cast<int>(size)));
  return DONGLE_CHECK(Dongle_WriteFile(handle_, FILE_DATA, id, static_cast<WORD>(offset),
                                       static_cast<uint8_t*>(const_cast<void*>(buffer)), static_cast<int>(size)));
}
int Dongle::ReadDataFile(int id, size_t offset, void* buffer, size_t size) {
  if (id == kFactoryDataFileId)
    return DONGLE_CHECK(
        Dongle_ReadData(handle_, static_cast<int>(offset), static_cast<uint8_t*>(buffer), static_cast<int>(size)));
  return DONGLE_CHECK(
      Dongle_ReadFile(handle_, id, static_cast<WORD>(offset), static_cast<uint8_t*>(buffer), static_cast<int>(size)));
}

int Dongle::CreatePKEYFile(SECRET_STORAGE_TYPE type_, int bits, int id, const PKEY_LICENCE licence) {
  WORD type;
  PRIKEY_FILE_ATTR attr;
  attr.m_Lic.m_Count = licence.count_limit_;
  attr.m_Lic.m_Priv = static_cast<uint8_t>(licence.permission_);
  attr.m_Lic.m_IsDecOnRAM = licence.global_decrease_ ? 0 : 1;
  attr.m_Lic.m_IsReset = licence.logout_force_;
  attr.m_Lic.m_Reserve = 0;

  if (type_ == SECRET_STORAGE_TYPE::kRSA) {
    type = attr.m_Type = FILE_PRIKEY_RSA;
    if (bits != 2048)
      return -EINVAL;
    attr.m_Size = bits;
  } else if (type_ == SECRET_STORAGE_TYPE::kSM2) {
    type = attr.m_Type = FILE_PRIKEY_ECCSM2;
    if (bits != 256)
      return -EINVAL;
    attr.m_Size = 0x8100;
  } else if (type_ == SECRET_STORAGE_TYPE::kP256) {
    type = attr.m_Type = FILE_PRIKEY_ECCSM2;
    if (bits != 256)
      return -EINVAL;
    attr.m_Size = 256;
  } else {
    return -EINVAL;
  }

  return DONGLE_CHECK(Dongle_CreateFile(handle_, type, id, reinterpret_cast<uint8_t*>(&attr)));
}
int Dongle::GenerateRSA(int id, uint32_t* modulus, uint8_t public_[], uint8_t* private_) {
  RSA_PUBLIC_KEY pubkey;
  SecretBuffer<1, RSA_PRIVATE_KEY> pkey;
  if (0 != DONGLE_CHECK(Dongle_RsaGenPubPriKey(handle_, id, &pubkey, static_cast<RSA_PRIVATE_KEY*>(pkey))))
    return -1;

  *modulus = pubkey.modulus;
  memcpy(public_, pubkey.exponent, pubkey.bits / 8);
  if (private_)
    memcpy(private_, pkey->exponent, pkey->bits / 8);
  return pubkey.bits;
}
int Dongle::ImportRSA(int id, int bits, uint32_t modules, const uint8_t public_[], const uint8_t private_[]) {
  if (bits != 2048)
    return -EINVAL;
  SecretBuffer<1, RSA_PRIVATE_KEY> pkey;
  pkey->bits = bits;
  pkey->modulus = modules;
  memcpy(pkey->publicExponent, public_, bits / 8);
  memcpy(pkey->exponent, private_, bits / 8);
  return DONGLE_CHECK(
      Dongle_WriteFile(handle_, FILE_PRIKEY_RSA, id, 0, reinterpret_cast<uint8_t*>(&pkey), sizeof(pkey)));
}

int Dongle::GenerateP256(int id, uint8_t X[32], uint8_t Y[32], uint8_t* private_) {
  ECCSM2_PUBLIC_KEY pubkey;
  SecretBuffer<1, ECCSM2_PRIVATE_KEY> pkey;
  if (0 != DONGLE_CHECK(Dongle_EccGenPubPriKey(handle_, id, &pubkey, static_cast<ECCSM2_PRIVATE_KEY*>(pkey))))
    return -1;
  CopyReverse<32>(X, pubkey.XCoordinate);
  CopyReverse<32>(Y, pubkey.YCoordinate);
  if (private_)
    CopyReverse<32>(private_, pkey->PrivateKey);
  return 0;
}
int Dongle::ImportP256(int id, const uint8_t K[32]) {
  SecretBuffer<1, ECCSM2_PRIVATE_KEY> pkey;
  pkey->bits = 256;
  CopyReverse<32>(pkey->PrivateKey, K);
  return DONGLE_CHECK(
      Dongle_WriteFile(handle_, FILE_PRIKEY_ECCSM2, id, 0, reinterpret_cast<uint8_t*>(&pkey), sizeof(pkey)));
}

int Dongle::GenerateSM2(int id, uint8_t X[32], uint8_t Y[32], uint8_t* private_) {
  ECCSM2_PUBLIC_KEY pubkey;
  SecretBuffer<1, ECCSM2_PRIVATE_KEY> pkey;
  if (0 != DONGLE_CHECK(Dongle_SM2GenPubPriKey(handle_, id, &pubkey, static_cast<ECCSM2_PRIVATE_KEY*>(pkey))))
    return -1;

  CopyReverse<32>(X, pubkey.XCoordinate);
  CopyReverse<32>(Y, pubkey.YCoordinate);
  if (private_)
    CopyReverse<32>(private_, pkey->PrivateKey);
  return 0;
}
int Dongle::ImportSM2(int id, const uint8_t K[32]) {
  SecretBuffer<1, ECCSM2_PRIVATE_KEY> pkey;
  pkey->bits = 0x8100;
  CopyReverse<32>(pkey->PrivateKey, K);
  return DONGLE_CHECK(
      Dongle_WriteFile(handle_, FILE_PRIKEY_ECCSM2, id, 0, reinterpret_cast<uint8_t*>(&pkey), sizeof(pkey)));
}

int Dongle::CreateKeyFile(int id, PERMISSION permission, SECRET_STORAGE_TYPE type) {
  KEY_FILE_ATTR attr;
  attr.m_Size = 16;
  attr.m_Lic.m_Priv_Enc = static_cast<uint8_t>(permission);
  if (type != SECRET_STORAGE_TYPE::kTDES && type != SECRET_STORAGE_TYPE::kSM4)
    return -EINVAL;
  return DONGLE_CHECK(Dongle_CreateFile(handle_, FILE_KEY, id, reinterpret_cast<uint8_t*>(&attr)));
}
int Dongle::WriteKeyFile(int id, const void* buffer, size_t size, SECRET_STORAGE_TYPE type) {
  if (size != 16)
    return -EINVAL;
  if (type != SECRET_STORAGE_TYPE::kTDES && type != SECRET_STORAGE_TYPE::kSM4)
    return -EINVAL;
  return DONGLE_CHECK(
      Dongle_WriteFile(handle_, FILE_KEY, id, 0, static_cast<uint8_t*>(const_cast<void*>(buffer)), 16));
}

int Dongle::RSAPrivate(int id,
                       uint8_t buffer[] /* length_is(*size_buffer), max_size(bits/8) */,
                       size_t* size_buffer,
                       bool encrypt) {
  size_t size_in = *size_buffer;
  if (encrypt) {
    if (size_in > 256 - 11)
      return -E2BIG;
  } else if (size_in != 256) {
    return -EINVAL;
  }
  int size_out = 256;
  int result = DONGLE_CHECK(Dongle_RsaPri(handle_, id, encrypt ? FLAG_ENCODE : FLAG_DECODE, buffer,
                                          static_cast<int>(size_in), buffer, &size_out));
  if (result >= 0)
    *size_buffer = size_out;
  return result;
}
int Dongle::RSAPrivate(int bits,
                       uint32_t modules,
                       const uint8_t public_[],
                       const uint8_t private_[],
                       uint8_t buffer[] /* length_is(*size_buffer), max_size(bits/8) */,
                       size_t* size_buffer,
                       bool encrypt) {
  int result = 0;
  size_t size_in = *size_buffer;
  if (bits != 2048)
    return -EINVAL;

  if (encrypt) {
    if (size_in > 256 - 11)
      return -E2BIG;
  } else if (size_in != 256) {
    return -EINVAL;
  }

  RSA* rsa = RSA_new();
  BIGNUM* d = BN_bin2bn(private_, 256, nullptr);
  BIGNUM* n = BN_bin2bn(public_, 256, nullptr);
  BIGNUM* e = BN_new();

  DONGLE_VERIFY(rsa && d && n && e);
  DONGLE_VERIFY(1 == BN_set_word(e, modules));
  DONGLE_VERIFY(1 == RSA_set0_key(rsa, n, e, d));

  if (encrypt) {
    int len = RSA_private_encrypt(static_cast<int>(size_in), buffer, buffer, rsa, RSA_PKCS1_PADDING);
    if (len < 0) {
      rlLOGE(TAG, "RSA_private_encrypt %zd error %ld", size_in, ERR_get_error());
      result = -1;
    } else {
      *size_buffer = len;
    }
  } else {
    int len = RSA_private_decrypt(static_cast<int>(size_in), buffer, buffer, rsa, RSA_PKCS1_PADDING);
    if (len < 0) {
      rlLOGE(TAG, "RSA_private_decrypt %zd error %ld", size_in, ERR_get_error());
      result = -1;
    } else {
      *size_buffer = len;
    }
  }
  RSA_free(rsa);

  return result;
}
int Dongle::RSAPublic(int bits,
                      uint32_t modules,
                      const uint8_t public_[],
                      uint8_t buffer[] /* length_is(*size_buffer), max_size(bits/8) */,
                      size_t* size_buffer,
                      bool encrypt) {
  int result = 0;
  size_t size_in = *size_buffer;
  if (bits != 2048)
    return -EINVAL;

  if (encrypt) {
    if (size_in > 256 - 11)
      return -E2BIG;
  } else if (size_in != 256) {
    return -EINVAL;
  }

  RSA* rsa = RSA_new();
  BIGNUM* n = BN_bin2bn(public_, 256, nullptr);
  BIGNUM* e = BN_new();

  DONGLE_VERIFY(rsa && n && e);
  DONGLE_VERIFY(1 == BN_set_word(e, modules));
  DONGLE_VERIFY(1 == RSA_set0_key(rsa, n, e, nullptr));

  if (encrypt) {
    int len = RSA_public_encrypt(static_cast<int>(size_in), buffer, buffer, rsa, RSA_PKCS1_PADDING);
    if (len < 0) {
      rlLOGE(TAG, "RSA_public_encrypt %zd error %ld", size_in, ERR_get_error());
      result = -1;
    } else {
      *size_buffer = len;
    }
  } else {
    int len = RSA_public_decrypt(static_cast<int>(size_in), buffer, buffer, rsa, RSA_PKCS1_PADDING);
    if (len < 0) {
      rlLOGE(TAG, "RSA_public_decrypt %zd error %ld", size_in, ERR_get_error());
      result = -1;
    } else {
      *size_buffer = len;
    }
  }

  RSA_free(rsa);
  return result;
}

int Dongle::P256Sign(int id, const uint8_t hash_[32], uint8_t R[32], uint8_t S[32]) {
  uint8_t sign[64], hash[32];
  CopyReverse<32>(hash, hash_);
  if (0 != DONGLE_CHECK(Dongle_EccSign(handle_, id, hash, 32, sign)))
    return -1;
  memcpy(R, hash, 32);
  memcpy(S, hash + 32, 32);
  CopyReverse<32>(R, &sign[0]);
  CopyReverse<32>(S, &sign[32]);
  return 0;
}

int Dongle::P256Verify(const uint8_t X[32],
                       const uint8_t Y[32],
                       const uint8_t hash_[32],
                       const uint8_t R[32],
                       const uint8_t S[32]) {
  int ret = -2;
  uint8_t pubkey[65], signbuf[80];
  EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  const EC_GROUP* const group = EC_KEY_get0_group(eckey);

  EC_POINT* point = EC_POINT_new(group);
  ECDSA_SIG* sign = ECDSA_SIG_new();
  DONGLE_VERIFY(eckey && point && sign);
  DONGLE_VERIFY(ECDSA_SIG_set0(sign, BN_bin2bn(R, 32, nullptr), BN_bin2bn(S, 32, nullptr)));

  do {
    pubkey[0] = 4;
    memcpy(&pubkey[1], X, 32);
    memcpy(&pubkey[33], Y, 32);
    if (EC_POINT_oct2point(group, point, pubkey, 65, nullptr) <= 0)
      break;
    if (EC_POINT_is_on_curve(group, point, nullptr) <= 0)
      break;
    if (EC_KEY_set_public_key(eckey, point) <= 0)
      break;

    uint8_t* p = signbuf;
    int signlen = i2d_ECDSA_SIG(sign, &p);
    EVP_PKEY* pkey = EVP_PKEY_new();
    DONGLE_VERIFY(pkey && EVP_PKEY_set1_EC_KEY(pkey, eckey) > 0);
    EVP_PKEY_CTX* pkeyCtx = EVP_PKEY_CTX_new(pkey, NULL);
    DONGLE_VERIFY(pkeyCtx && EVP_PKEY_verify_init(pkeyCtx) > 0);
    ret = EVP_PKEY_verify(pkeyCtx, signbuf, signlen, hash_, 32) > 0 ? 0 : -1;
    EVP_PKEY_CTX_free(pkeyCtx);
    EVP_PKEY_free(pkey);
  } while (0);

  ECDSA_SIG_free(sign);
  EC_POINT_free(point);
  EC_KEY_free(eckey);

  if (ret < 0) {
    rlLOGE(TAG, "P256Verify %s", ret == -1 ? "False" : "Error");
    ERR_print_errors_cb(
        [](const char* str, size_t len, void* u) {
          rlLOGE(TAG, "\t%s", str);
          return 1;
        },
        nullptr);
  }

  return ret;
}

int Dongle::P256Sign(const uint8_t prikey[32], const uint8_t hash[32], uint8_t R[32], uint8_t S[32]) {
  int ret = -1;
  uint8_t sign_[80];
  size_t slen = sizeof(sign_);

  EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  BIGNUM* pkey = BN_bin2bn(prikey, 32, nullptr);

  do {
    if (EC_KEY_set_private_key(eckey, pkey) <= 0)
      break;

    EVP_PKEY* pkey = EVP_PKEY_new();
    DONGLE_VERIFY(pkey && EVP_PKEY_set1_EC_KEY(pkey, eckey) > 0);
    EVP_PKEY_CTX* pkeyCtx = EVP_PKEY_CTX_new(pkey, NULL);
    DONGLE_VERIFY(pkeyCtx && EVP_PKEY_sign_init(pkeyCtx) > 0);
    if (EVP_PKEY_sign(pkeyCtx, sign_, &slen, hash, 32) > 0) {
      const uint8_t* p = sign_;
      ECDSA_SIG* s = d2i_ECDSA_SIG(nullptr, &p, static_cast<int>(slen));
      DONGLE_VERIFY(s != nullptr);
      BN_bn2binpad(ECDSA_SIG_get0_r(s), R, 32);
      BN_bn2binpad(ECDSA_SIG_get0_s(s), S, 32);
      ECDSA_SIG_free(s);
      ret = 0;    
    }
    EVP_PKEY_CTX_free(pkeyCtx);
    EVP_PKEY_free(pkey);
  } while (0);

  EC_KEY_free(eckey);
  BN_free(pkey);

  if (ret < 0) {
    rlLOGE(TAG, "P256Sign Error!");
    ERR_print_errors_cb(
        [](const char* str, size_t len, void* u) {
          rlLOGE(TAG, "\t%s", str);
          return 1;
        },
        nullptr);
  }

  return ret;
}

int Dongle::SM2Sign(int id, const uint8_t hash_[32], uint8_t R[32], uint8_t S[32]) {
  uint8_t sign[64], hash[32];
  CopyReverse<32>(hash, hash_);
  if (0 != DONGLE_CHECK(Dongle_SM2Sign(handle_, id, hash, 32, sign)))
    return -1;
  memcpy(R, hash, 32);
  memcpy(S, hash + 32, 32);
  CopyReverse<32>(R, &sign[0]);
  CopyReverse<32>(S, &sign[32]);
  return 0;
}

int Dongle::SM2Verify(const uint8_t X[32],
                      const uint8_t Y[32],
                      const uint8_t hash_[32],
                      const uint8_t R[32],
                      const uint8_t S[32]) {
  int ret = -2;
  uint8_t pubkey[65], signbuf[80];
  EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_sm2);
  const EC_GROUP* const group = EC_KEY_get0_group(eckey);

  EC_POINT* point = EC_POINT_new(group);
  ECDSA_SIG* sign = ECDSA_SIG_new();
  DONGLE_VERIFY(eckey && point && sign);
  DONGLE_VERIFY(ECDSA_SIG_set0(sign, BN_bin2bn(R, 32, nullptr), BN_bin2bn(S, 32, nullptr)));

  do {
    pubkey[0] = 4;
    memcpy(&pubkey[1], X, 32);
    memcpy(&pubkey[33], Y, 32);
    if (EC_POINT_oct2point(group, point, pubkey, 65, nullptr) <= 0)
      break;
    if (EC_POINT_is_on_curve(group, point, nullptr) <= 0)
      break;
    if (EC_KEY_set_public_key(eckey, point) <= 0)
      break;

    uint8_t* p = signbuf;
    int signlen = i2d_ECDSA_SIG(sign, &p);
    if (sm2_verify(hash_, 32, signbuf, signlen, eckey) > 0)
      ret = 0;
    else
      ret = -1;
  } while (0);

  ECDSA_SIG_free(sign);
  EC_POINT_free(point);
  EC_KEY_free(eckey);

  if (ret < 0) {
    rlLOGE(TAG, "SM2Verify %s", ret == -1 ? "False" : "Error");
    ERR_print_errors_cb(
        [](const char* str, size_t len, void* u) {
          rlLOGE(TAG, "\t%s", str);
          return 1;
        },
        nullptr);
  }

  return ret;
}

int Dongle::SM2Sign(const uint8_t prikey[32], const uint8_t hash[32], uint8_t R[32], uint8_t S[32]) {
  int ret = -1;
  uint8_t sign_[80];
  unsigned slen = sizeof(sign_);

  EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_sm2);
  BIGNUM* pkey = BN_bin2bn(prikey, 32, nullptr);

  do {
    if (EC_KEY_set_private_key(eckey, pkey) <= 0)
      break;

    if (sm2_sign(hash, 32, sign_, &slen, eckey) > 0) {
      const uint8_t* p = sign_;
      ECDSA_SIG* s = d2i_ECDSA_SIG(nullptr, &p, slen);
      DONGLE_VERIFY(s != nullptr);
      BN_bn2binpad(ECDSA_SIG_get0_r(s), R, 32);
      BN_bn2binpad(ECDSA_SIG_get0_s(s), S, 32);
      ECDSA_SIG_free(s);
      ret = 0;
    }
  } while (0);

  EC_KEY_free(eckey);
  BN_free(pkey);

  if (ret < 0) {
    rlLOGE(TAG, "SM2Sign Error!");
    ERR_print_errors_cb(
        [](const char* str, size_t len, void* u) {
          rlLOGE(TAG, "\t%s", str);
          return 1;
        },
        nullptr);
  }

  return ret;
}

int Dongle::SM2Decrypt(int id, const uint8_t cipher[], size_t size_cipher, uint8_t text[], size_t* size_text) {
  rlLOGE(TAG, "Dongle_SM2Decrypt/%x Not implements yet!", id);
  return -ENOSYS;
}

int Dongle::SM2Decrypt(const uint8_t private_[32],
                       const uint8_t cipher[],
                       size_t size_cipher,
                       uint8_t text[],
                       size_t* size_text) {
  int ret = -1;
  if (size_cipher < 96 || size_cipher > 512)
    return -EINVAL;

  uint8_t asn1_cipher[1024];
  int asn1_len = SM2Cipher_TextToASN1(cipher, size_cipher, asn1_cipher);
  if (asn1_len <= 0)
    return -EINVAL;

  EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_sm2);
  BIGNUM* pkey = BN_bin2bn(private_, 32, nullptr);

  do {
    if (EC_KEY_set_private_key(eckey, pkey) <= 0)
      break;

    if (sm2_decrypt(eckey, EVP_sm3(), asn1_cipher, asn1_len, text, size_text) > 0)
      ret = 0;
  } while (0);

  EC_KEY_free(eckey);
  BN_free(pkey);

  if (ret < 0) {
    rlLOGE(TAG, "SM2Decrypt Error!");
    ERR_print_errors_cb(
        [](const char* str, size_t len, void* u) {
          rlLOGE(TAG, "\t%s", str);
          return 1;
        },
        nullptr);
  }

  return ret;
}
int Dongle::SM2Encrypt(const uint8_t X[32],
                       const uint8_t Y[32],
                       const uint8_t text[],
                       size_t size_text,
                       uint8_t out_cipher[]) {
  int result = -1;

  DONGLE_VERIFY(size_text > 0 && size_text <= 256);
  EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_sm2);
  const EC_GROUP* const group = EC_KEY_get0_group(eckey);
  EC_POINT* point = EC_POINT_new(group);

  do {
    uint8_t pubkey[65];
    SecretBuffer<512> cipher;

    pubkey[0] = 4;
    memcpy(&pubkey[1], X, 32);
    memcpy(&pubkey[33], Y, 32);
    if (EC_POINT_oct2point(group, point, pubkey, 65, nullptr) <= 0)
      break;
    if (EC_POINT_is_on_curve(group, point, nullptr) <= 0)
      break;
    if (EC_KEY_set_public_key(eckey, point) <= 0)
      break;

    size_t cipher_len = 512;
    if (sm2_encrypt(eckey, EVP_sm3(), text, size_text, cipher, &cipher_len) <= 0)
      break;

    DONGLE_VERIFY(96 + size_text == SM2Cipher_ASN1ToText(cipher, cipher_len, out_cipher));
    result = 0;
  } while (0);
  EC_POINT_free(point);
  EC_KEY_free(eckey);

  if (result < 0) {
    rlLOGE(TAG, "SM2Encrypt Error!");
    ERR_print_errors_cb(
        [](const char* str, size_t len, void* u) {
          rlLOGE(TAG, "\t%s", str);
          return 1;
        },
        nullptr);
  }

  return result;
}

int Dongle::SHA1(const void* input, size_t size, uint8_t md[20]) {
  return DONGLE_CHECK(Dongle_HASH(handle_, FLAG_HASH_SHA1, static_cast<uint8_t*>(const_cast<void*>(input)),
                                  static_cast<int>(size), md));
}
int Dongle::SM3(const void* input, size_t size, uint8_t md[32]) {
  return DONGLE_CHECK(
      Dongle_HASH(handle_, FLAG_HASH_SM3, static_cast<uint8_t*>(const_cast<void*>(input)), static_cast<int>(size), md));
}

int Dongle::TDESECB(int id, uint8_t* buffer, size_t size, bool encrypt) {
  return DONGLE_CHECK(
      Dongle_TDES(handle_, id, encrypt ? FLAG_ENCODE : FLAG_DECODE, buffer, buffer, static_cast<int>(size)));
}
int Dongle::TDESECB(const uint8_t key[16], uint8_t* buffer, size_t size_, bool encrypt) {
  int size = static_cast<int>(size_);

  const EVP_CIPHER* cipher = EVP_des_ede_ecb();
  EVP_CIPHER_CTX* cipherCtx = EVP_CIPHER_CTX_new();
  DONGLE_VERIFY(size % 8 == 0 && 8 == EVP_CIPHER_block_size(cipher) && 16 == EVP_CIPHER_key_length(cipher));

  if (encrypt) {
    DONGLE_VERIFY(EVP_EncryptInit(cipherCtx, cipher, key, nullptr) > 0);
    DONGLE_VERIFY(EVP_EncryptUpdate(cipherCtx, buffer, &size, buffer, size) > 0);
  } else {
    DONGLE_VERIFY(EVP_DecryptInit(cipherCtx, cipher, key, nullptr) > 0);
    DONGLE_VERIFY(EVP_DecryptUpdate(cipherCtx, buffer, &size, buffer, size) > 0);
  }
  EVP_CIPHER_CTX_free(cipherCtx);

  return 0;
}

int Dongle::SM4ECB(int id, uint8_t* buffer, size_t size, bool encrypt) {
  return DONGLE_CHECK(
      Dongle_SM4(handle_, id, encrypt ? FLAG_ENCODE : FLAG_DECODE, buffer, buffer, static_cast<int>(size)));
}
int Dongle::SM4ECB(const uint8_t key[16], uint8_t* buffer, size_t size, bool encrypt) {  
  SM4_KEY sm4key;
  DONGLE_VERIFY(size % 16 == 0 && SM4_set_key(key, &sm4key));
  if (encrypt) {
    for (size_t off = 0; off < size; off += 16, buffer += 16)
      SM4_encrypt(buffer, buffer, &sm4key);
  } else {
    for (size_t off = 0; off < size; off += 16, buffer += 16)
      SM4_decrypt(buffer, buffer, &sm4key);
  }

  return 0;
}


void Dongle::Abort() {
  abort();
}

int Dongle::CheckError(DWORD error) {
  if (DONGLE_SUCCESS == error)
    return 0;
  last_error_ = error;
  return -1;
}

RockeyARM::~RockeyARM() {
  Close();
}

int RockeyARM::Enum(DONGLE_INFO info[64]) {
  int count = 0;
  ::DONGLE_INFO all[64];
  int result = DONGLE_CHECK(Dongle_Enum(all, &count));
  if (result < 0)
    return -1;

  for (int i = 0; info && i < count; ++i)
    GetRockeyDongleInfo(&info[i], all[i]);
  return count;
}


int RockeyARM::VerifyPIN(PERMISSION perm, const char* pin, int* remain) {
  int dummy;
  int flags = FLAG_USERPIN;

  if (!remain)
    remain = &dummy;

  if (perm == PERMISSION::kAdminstrator) {
    flags = FLAG_ADMINPIN;
    if (!pin)
      pin = CONST_ADMINPIN;
  }
  else if (perm == PERMISSION::kNormal) {
    flags = FLAG_USERPIN;
    if (!pin)
      pin = CONST_USERPIN;
  } else {
    return -EINVAL;
  }

  rlLOGW(TAG, "RockeyARM::VerifyPIN %d", static_cast<int>(perm));

  return DONGLE_CHECK(Dongle_VerifyPIN(handle_, flags, const_cast<char*>(pin), remain));
}

int RockeyARM::ResetState() {
  return DONGLE_CHECK(Dongle_ResetState(handle_));
}

int RockeyARM::UpdateExeFile(const void* file, size_t size) {
  EXE_FILE_INFO info;
  if (size >= 0xFFF8)
    return -E2BIG;

  rlLOGI(TAG, "RockeyARM::UpdateExeFile %zd", size);

  info.m_dwSize = static_cast<WORD>(size);
  info.m_wFileID = 1;
  info.m_Priv = 0;
  info.m_pData = const_cast<uint8_t*>(static_cast<const uint8_t*>(file));
  return DONGLE_CHECK(Dongle_DownloadExeFile(handle_, &info, 1));
}
int RockeyARM::ExecuteExeFile(void* InOutBuf, size_t szBuf, int* ret) {
  int dummy = 0;
  if (szBuf > 1024)
    return -E2BIG;
  if (!ret)
    ret = &dummy;
  return DONGLE_CHECK(Dongle_RunExeFile(handle_, 1, static_cast<uint8_t*>(InOutBuf), static_cast<WORD>(szBuf), ret));
}
int RockeyARM::LimitSeedCount(int count) {
  return DONGLE_CHECK(Dongle_LimitSeedCount(handle_, count));
}
#if 0
int RockeyARM::SwitchProtocol(bool ccid) {
  int result = DONGLE_CHECK(Dongle_SwitchProtocol(handle_, ccid ? PROTOCOL_CCID : PROTOCOL_HID));
  if (result >= 0)
    Close();
  return result;
}
#endif /* */
int RockeyARM::SetExpireTime(DWORD time) {
  return DONGLE_CHECK(Dongle_SetDeadline(handle_, time));
}
int RockeyARM::SetUserID(uint32_t id) {
  return DONGLE_CHECK(Dongle_SetUserID(handle_, id));
}

int RockeyARM::ChangePIN(PERMISSION perm, const char* old, const char* pin, int count) {
  return DONGLE_CHECK(Dongle_ChangePIN(handle_,
                                       perm == PERMISSION::kAdminstrator ? FLAG_ADMINPIN
                                       : perm == PERMISSION::kNormal     ? FLAG_USERPIN
                                                                         : -1,
                                       const_cast<char*>(old), const_cast<char*>(pin), count));
}
int RockeyARM::ResetUserPIN(const char* admin) {
  return DONGLE_CHECK(Dongle_ResetUserPIN(handle_, const_cast<char*>(admin)));
}
int RockeyARM::GenUniqueKey(const void* seed, size_t len, char pid[10], char admin[20]) {
  return DONGLE_CHECK(
      Dongle_GenUniqueKey(handle_, static_cast<int>(len), static_cast<uint8_t*>(const_cast<void*>(seed)), pid, admin));
}
int RockeyARM::FactoryReset() {
  int result = DONGLE_CHECK(Dongle_RFS(handle_));
  if (result >= 0)
    Close();
  return result;
}

int RockeyARM::Open(int index) {
  if (index < 0 || index >= 64)
    return -EINVAL;

  int count = 0;
  ::DONGLE_INFO dongle_info_all_[64];
  ::DONGLE_HANDLE handle = nullptr;

  Close();
  if (DONGLE_CHECK(Dongle_Enum(dongle_info_all_, &count)) < 0)
    return -1;

  if (index >= count)
    return -ERANGE;

  GetRockeyDongleInfo(&dongle_info_, dongle_info_all_[index]);
  if (0 != DONGLE_CHECK(Dongle_Open(&handle, index)))
    return -1;

  handle_ = static_cast<ROCKEY_HANDLE>(handle);
  return 0;
}

int RockeyARM::Close(){
  if (!handle_)
    return 0;

  ROCKEY_HANDLE handle = nullptr;
  std::swap(handle, handle_);
  return DONGLE_CHECK(Dongle_Close(handle));
}

} // namespace dongle

rLANG_DECLARE_END

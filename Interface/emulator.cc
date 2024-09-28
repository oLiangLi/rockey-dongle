#include <Interface/dongle.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

/* Copy from sm2_crypt.c */
typedef struct rLANG_SM2_Ciphertext_st rLANG_SM2_Ciphertext;
struct rLANG_SM2_Ciphertext_st {
  BIGNUM* C1x;
  BIGNUM* C1y;
  ASN1_OCTET_STRING* C3;
  ASN1_OCTET_STRING* C2;
};

ASN1_SEQUENCE(rLANG_SM2_Ciphertext) = {
  ASN1_SIMPLE(rLANG_SM2_Ciphertext, C1x, BIGNUM),
  ASN1_SIMPLE(rLANG_SM2_Ciphertext, C1y, BIGNUM),
  ASN1_SIMPLE(rLANG_SM2_Ciphertext, C3, ASN1_OCTET_STRING),
  ASN1_SIMPLE(rLANG_SM2_Ciphertext, C2, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(rLANG_SM2_Ciphertext)

IMPLEMENT_ASN1_FUNCTIONS(rLANG_SM2_Ciphertext)

rLANG_DECLARE_MACHINE

namespace {
constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("Foobar");
}

namespace dongle {

int SM2Cipher_TextToASN1(const uint8_t* text_cipher, size_t cipher_len, uint8_t* buffer) {
  DONGLE_VERIFY(cipher_len > 96 && cipher_len <= 1024);

  rLANG_SM2_Ciphertext_st* ciphertext = rLANG_SM2_Ciphertext_new();
  ciphertext->C1x = BN_bin2bn(&text_cipher[0], 32, nullptr);
  ciphertext->C1y = BN_bin2bn(&text_cipher[32], 32, nullptr);
  ciphertext->C3 = ASN1_OCTET_STRING_new();
  ciphertext->C2 = ASN1_OCTET_STRING_new();

  DONGLE_VERIFY(ciphertext->C1x && ciphertext->C1y && ciphertext->C3 && ciphertext->C2);
  DONGLE_VERIFY(ASN1_OCTET_STRING_set(ciphertext->C3, &text_cipher[64], 32) > 0);
  DONGLE_VERIFY(ASN1_OCTET_STRING_set(ciphertext->C2, &text_cipher[96], static_cast<int>(cipher_len - 96)) > 0);

  int result = i2d_rLANG_SM2_Ciphertext(ciphertext, &buffer);
  rLANG_SM2_Ciphertext_free(ciphertext);

  return result;
}
int SM2Cipher_ASN1ToText(const uint8_t* asn1_cipher, size_t cipher_len, uint8_t* buffer) {
  const uint8_t* p = asn1_cipher;
  DONGLE_VERIFY(cipher_len <= 1024);
  rLANG_SM2_Ciphertext_st* ciphertext = d2i_rLANG_SM2_Ciphertext(nullptr, &p, static_cast<int>(cipher_len));
  if (!ciphertext)
    return -EINVAL;

  int result = -EINVAL;
  if ((size_t)(p - asn1_cipher) == cipher_len && ciphertext->C3->length == 32 && ciphertext->C2->length > 0) {
    if (BN_bn2binpad(ciphertext->C1x, &buffer[0], 32) > 0 && BN_bn2binpad(ciphertext->C1y, &buffer[32], 32) > 0) {
      memcpy(&buffer[64], ciphertext->C3->data, 32);
      memcpy(&buffer[96], ciphertext->C2->data, ciphertext->C2->length);
      result = 96 + ciphertext->C2->length;
    }
  }
  rLANG_SM2_Ciphertext_free(ciphertext);
  return result;
}

int Dongle::RandBytes(uint8_t* buffer, size_t size) {
  RAND_bytes(buffer, (int)size);
  return 0;
}

int Dongle::SeedSecret(const void* input, size_t size, void* value) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::GetRealTime(DWORD* time) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::GetExpireTime(DWORD* time) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::GetTickCount(DWORD* ticks) {
  *ticks = (DWORD)rLANG_GetTickCount();
  return 0;
}

int Dongle::GetDongleInfo(DONGLE_INFO* info) {
  if (!handle_)
    return DONGLE_CHECK(-EBADF);
  *info = dongle_info_;
  return 0;
}

int Dongle::GetPINState(PERMISSION* state) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::SetLEDState(LED_STATE state) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::ReadShareMemory(uint8_t buffer[32]) {
  return DONGLE_CHECK(-ENOSYS);
}
int Dongle::WriteShareMemory(const uint8_t buffer[32]) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::DeleteFile(SECRET_STORAGE_TYPE type_, int id) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::CreateDataFile(int id, size_t size, PERMISSION read, PERMISSION write) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::WriteDataFile(int id, size_t offset, const void* buffer, size_t size) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::ReadDataFile(int id, size_t offset, void* buffer, size_t size) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::CreatePKEYFile(SECRET_STORAGE_TYPE type_, int bits, int id, const PKEY_LICENCE& licence) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::GenerateRSA(int id, uint32_t* modulus, uint8_t public_[], uint8_t* private_) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::ImportRSA(int id, int bits, uint32_t modules, const uint8_t public_[], const uint8_t private_[]) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::GenerateP256(int id, uint8_t X[32], uint8_t Y[32], uint8_t* private_) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::ImportP256(int id, const uint8_t K[32]) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::GenerateSM2(int id, uint8_t X[32], uint8_t Y[32], uint8_t* private_) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::ImportSM2(int id, const uint8_t K[32]) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::CreateKeyFile(int id, PERMISSION permission, SECRET_STORAGE_TYPE type) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::WriteKeyFile(int id, const void* buffer, size_t size, SECRET_STORAGE_TYPE type) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::RSAPrivate(int id,
                       uint8_t buffer[] /* length_is(*size_buffer), max_size(bits/8) */,
                       size_t* size_buffer,
                       bool encrypt) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::RSAPrivate(int bits,
                       uint32_t modules,
                       const uint8_t public_[],
                       const uint8_t private_[],
                       uint8_t buffer[] /* length_is(*size_buffer), max_size(bits/8) */,
                       size_t* size_buffer,
                       bool encrypt) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::RSAPublic(int bits,
                      uint32_t modules,
                      const uint8_t public_[],
                      uint8_t buffer[] /* length_is(*size_buffer), max_size(bits/8) */,
                      size_t* size_buffer,
                      bool encrypt) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::P256Sign(int id, const uint8_t hash_[32], uint8_t R[32], uint8_t S[32]) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::P256Verify(const uint8_t X[32],
                       const uint8_t Y[32],
                       const uint8_t hash_[32],
                       const uint8_t R[32],
                       const uint8_t S[32]) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::P256Sign(const uint8_t prikey[32], const uint8_t hash[32], uint8_t R[32], uint8_t S[32]) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::SM2Sign(int id, const uint8_t hash_[32], uint8_t R[32], uint8_t S[32]) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::SM2Verify(const uint8_t X[32],
                      const uint8_t Y[32],
                      const uint8_t hash_[32],
                      const uint8_t R[32],
                      const uint8_t S[32]) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::SM2Sign(const uint8_t prikey[32], const uint8_t hash[32], uint8_t R[32], uint8_t S[32]) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::SM2Decrypt(int id, const uint8_t cipher[], size_t size_cipher, uint8_t text[], size_t* size_text) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::SM2Decrypt(const uint8_t private_[32],
                       const uint8_t cipher[],
                       size_t size_cipher,
                       uint8_t text[],
                       size_t* size_text) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::SM2Encrypt(const uint8_t X[32],
                       const uint8_t Y[32],
                       const uint8_t text[],
                       size_t size_text,
                       uint8_t out_cipher[]) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::SHA1(const void* input, size_t size, uint8_t md[20]) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::SM3(const void* input, size_t size, uint8_t md[32]) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::TDESECB(int id, uint8_t* buffer, size_t size, bool encrypt) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::TDESECB(const uint8_t key[16], uint8_t* buffer, size_t size_, bool encrypt) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::SM4ECB(int id, uint8_t* buffer, size_t size, bool encrypt) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::SM4ECB(const uint8_t key[16], uint8_t* buffer, size_t size, bool encrypt) {
  return DONGLE_CHECK(-ENOSYS);
}

void Dongle::Abort() {
  abort();
}

int Dongle::CheckError(DWORD error) {
  if (0 == error)
    return 0;
  last_error_ = error;
  return -1;
}

RockeyARM::~RockeyARM() {
  Close();
}

int RockeyARM::Close() {
  return DONGLE_CHECK(-ENOSYS);
}
int RockeyARM::Open(int index) {
  return DONGLE_CHECK(-ENOSYS);
}
int RockeyARM::Enum(DONGLE_INFO info[64]) {
  return DONGLE_CHECK(-ENOSYS);
}
int RockeyARM::VerifyPIN(PERMISSION perm, const char* pin, int* remain) {
  return DONGLE_CHECK(-ENOSYS);
}
int RockeyARM::ResetState() {
  return DONGLE_CHECK(-ENOSYS);
}

int RockeyARM::UpdateExeFile(const void* file, size_t size) {
  return DONGLE_CHECK(-ENOSYS);
}
int RockeyARM::ExecuteExeFile(void* InOutBuf, size_t szBuf, int* ret) {
  return DONGLE_CHECK(-ENOSYS);
}
int RockeyARM::LimitSeedCount(int count) {
  return DONGLE_CHECK(-ENOSYS);
}

int RockeyARM::SetExpireTime(DWORD time) {
  return DONGLE_CHECK(-ENOSYS);
}
int RockeyARM::SetUserID(uint32_t id) {
  return DONGLE_CHECK(-ENOSYS);
}

int RockeyARM::ChangePIN(PERMISSION perm, const char* old, const char* pin, int count) {
  return DONGLE_CHECK(-ENOSYS);
}
int RockeyARM::ResetUserPIN(const char* admin) {
  return DONGLE_CHECK(-ENOSYS);
}

int RockeyARM::GenUniqueKey(const void* seed, size_t len, char pid[10], char admin[20]) {
  return DONGLE_CHECK(-ENOSYS);
}
int RockeyARM::FactoryReset() {
  return DONGLE_CHECK(-ENOSYS);
}

} // namespace dongle

rLANG_DECLARE_END

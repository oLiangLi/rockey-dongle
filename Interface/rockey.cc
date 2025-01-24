#include <Interface/dongle.h>
extern "C" {
#include <MCU/RockeyARM/include/FTRX.h>
}

rLANG_DECLARE_MACHINE

namespace dongle {

int Dongle::RandBytes(uint8_t* buffer, size_t size) {
  return DONGLE_CHECK(get_random(buffer, size));
}
int Dongle::SeedSecret(const void* input, size_t size, void* value) {
  return DONGLE_CHECK(seed(const_cast<uint8_t*>(static_cast<const uint8_t*>(input)), static_cast<int>(size),
                           static_cast<uint8_t*>(value)));
}
int Dongle::GetRealTime(DWORD* time) {
  return DONGLE_CHECK(get_realtime(time));
}
int Dongle::GetExpireTime(DWORD* time) {
  return DONGLE_CHECK(get_expiretime(time));
}
int Dongle::GetTickCount(DWORD* ticks) {
  return DONGLE_CHECK(get_tickcount(ticks));
}

int Dongle::GetDongleInfo(DONGLE_INFO* info) {
  ::DONGLE_INFO dongle;
  if (0 != DONGLE_CHECK(get_keyinfo(&dongle)))
    return -1;
  GetRockeyDongleInfo(info, dongle);
  return 0;
}
int Dongle::GetPINState(PERMISSION* state) {
  DWORD pin = 0;
  if (0 != DONGLE_CHECK(get_pinstate(&pin)))
    return -1;
  *state = pin == PIN_ADMIN  ? PERMISSION::kAdminstrator
           : pin == PIN_USER ? PERMISSION::kNormal
                             : PERMISSION::kAnonymous;
  return 0;
}
int Dongle::SetLEDState(LED_STATE state) {
  return DONGLE_CHECK(led_control(static_cast<uint8_t>(state)));
}

int Dongle::ReadShareMemory(uint8_t buffer[32]) {
  return DONGLE_CHECK(get_sharememory(buffer));
}
int Dongle::WriteShareMemory(const uint8_t buffer[32]) {
  return DONGLE_CHECK(set_sharememory(const_cast<uint8_t*>(buffer)));
}

int Dongle::DeleteFile(SECRET_STORAGE_TYPE type_, int id) {
  WORD type;
  if (type_ == SECRET_STORAGE_TYPE::kData) {
    type = FILE_DATA;
  } else if (type_ == SECRET_STORAGE_TYPE::kRSA) {
    type = FILE_PRIKEY_RSA;
  } else if (type_ == SECRET_STORAGE_TYPE::kP256 || type_ == SECRET_STORAGE_TYPE::kSM2) {
    type = FILE_PRIKEY_ECCSM2;
  } else if (type_ == SECRET_STORAGE_TYPE::kSM4 || type_ == SECRET_STORAGE_TYPE::kTDES) {
    type = FILE_KEY;
  } else {
    return last_error_ = -EINVAL;
  }

  return DONGLE_CHECK(delete_file(type, id));
}

int Dongle::CreateDataFile(int id, size_t size, PERMISSION read, PERMISSION write) {
  DATA_FILE_ATTR attr;
  attr.m_Size = size;
  attr.m_Lic.m_Read_Priv = static_cast<uint8_t>(read);
  attr.m_Lic.m_WritePriv = static_cast<uint8_t>(write);
  return DONGLE_CHECK(create_file(FILE_DATA, id, reinterpret_cast<uint8_t*>(&attr), sizeof(attr)));
}
int Dongle::WriteDataFile(int id, size_t offset, const void* buffer_, size_t size) {
  if (size > 4096)
    return -EINVAL;

  auto Write = [this](int id, size_t offset, const void* buffer, size_t size) {
    return DONGLE_CHECK(write_file(FILE_DATA, id, offset, size, static_cast<uint8_t*>(const_cast<void*>(buffer))));
  };

  const uint8_t* buffer = (const uint8_t*)buffer_;

  while (size >= 256) {
    int r = Write(id, offset, buffer, 256);
    if (0 != r)
      return r;
    offset += 256;
    buffer += 256;
    size -= 256;
  }

  if (size)
    return Write(id, offset, buffer, size);
  return 0;
}
int Dongle::ReadDataFile(int id, size_t offset, void* buffer_, size_t size) {
  if (size > 4096)
    return -EINVAL;

  auto Read = [this](int id, size_t offset, void* buffer, size_t size) {
    return DONGLE_CHECK(read_file(id, offset, size, static_cast<uint8_t*>(buffer)));
  };

  uint8_t* buffer = (uint8_t*)buffer_;
  while (size >= 256) {
    int r = Read(id, offset, buffer, 256);
    if (0 != r)
      return r;
    offset += 256;
    buffer += 256;
    size -= 256;
  }

  if (size)
    return Read(id, offset, buffer, size);
  return 0;
}

int Dongle::CreatePKEYFile(SECRET_STORAGE_TYPE type_, int bits, int id, const PKEY_LICENCE& licence) {
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
      return last_error_ = -EINVAL;
    attr.m_Size = bits;
  } else if (type_ == SECRET_STORAGE_TYPE::kSM2) {
    type = attr.m_Type = FILE_PRIKEY_ECCSM2;
    if (bits != 256)
      return last_error_ = -EINVAL;
    attr.m_Size = 0x8100;
  } else if (type_ == SECRET_STORAGE_TYPE::kP256) {
    type = attr.m_Type = FILE_PRIKEY_ECCSM2;
    if (bits != 256)
      return last_error_ = -EINVAL;
    attr.m_Size = 256;
  } else {
    return last_error_ = -EINVAL;
  }

  return DONGLE_CHECK(create_file(type, id, reinterpret_cast<uint8_t*>(&attr), sizeof(attr)));
}
int Dongle::GenerateRSA(int id, uint32_t* modulus, uint8_t public_[], uint8_t* private_) {
  SecretBuffer<1, RSA_PRIVATE_KEY> pkey;
  if (0 != DONGLE_CHECK(rsa_genkey(id, pkey)))
    return -1;

  *modulus = pkey->modulus;
  memcpy(public_, pkey->publicExponent, pkey->bits / 8);
  if (private_)
    memcpy(private_, pkey->exponent, pkey->bits / 8);
  return pkey->bits;
}
int Dongle::ImportRSA(int id, int bits, uint32_t modules, const uint8_t public_[], const uint8_t private_[]) {
  if (bits != 2048)
    return last_error_ = -EINVAL;
  SecretBuffer<1, RSA_PRIVATE_KEY> pkey;
  pkey->bits = bits;
  pkey->modulus = modules;
  memcpy(pkey->publicExponent, public_, bits / 8);
  memcpy(pkey->exponent, private_, bits / 8);
  return DONGLE_CHECK(write_file(FILE_PRIKEY_RSA, id, 0, sizeof(pkey), reinterpret_cast<uint8_t*>(&pkey)));
}

int Dongle::GenerateP256(int id, uint8_t X[32], uint8_t Y[32], uint8_t* private_) {
  ECCSM2_KEY_PAIR pkey;
  if (0 != DONGLE_CHECK(ecc_genkey(id, &pkey)))
    return -1;
  CopyReverse<32>(X, pkey.Pubkey.XCoordinate);
  CopyReverse<32>(Y, pkey.Pubkey.YCoordinate);
  if (private_)
    CopyReverse<32>(private_, pkey.Prikey.PrivateKey);
  return 0;
}
int Dongle::ImportP256(int id, const uint8_t K[32]) {
  ECCSM2_PRIVATE_KEY pkey;
  pkey.bits = 256;
  CopyReverse<32>(pkey.PrivateKey, K);
  return DONGLE_CHECK(write_file(FILE_PRIKEY_ECCSM2, id, 0, sizeof(pkey), reinterpret_cast<uint8_t*>(&pkey)));
}

int Dongle::GenerateSM2(int id, uint8_t X[32], uint8_t Y[32], uint8_t* private_) {
  ECCSM2_KEY_PAIR pkey;
  if (0 != DONGLE_CHECK(sm2_genkey(id, &pkey)))
    return -1;
  CopyReverse<32>(X, pkey.Pubkey.XCoordinate);
  CopyReverse<32>(Y, pkey.Pubkey.YCoordinate);
  if (private_)
    CopyReverse<32>(private_, pkey.Prikey.PrivateKey);
  return 0;
}
int Dongle::ImportSM2(int id, const uint8_t K[32]) {
  ECCSM2_PRIVATE_KEY pkey;
  pkey.bits = 0x8100;
  CopyReverse<32>(pkey.PrivateKey, K);
  return DONGLE_CHECK(write_file(FILE_PRIKEY_ECCSM2, id, 0, sizeof(pkey), reinterpret_cast<uint8_t*>(&pkey)));
}

int Dongle::CreateKeyFile(int id, PERMISSION permission, SECRET_STORAGE_TYPE type) {
  KEY_FILE_ATTR attr;
  attr.m_Size = 16;
  attr.m_Lic.m_Priv_Enc = static_cast<uint8_t>(permission);
  if (type != SECRET_STORAGE_TYPE::kTDES && type != SECRET_STORAGE_TYPE::kSM4)
    return last_error_ = -EINVAL;
  return DONGLE_CHECK(create_file(FILE_KEY, id, reinterpret_cast<uint8_t*>(&attr), sizeof(attr)));
}
int Dongle::WriteKeyFile(int id, const void* buffer, size_t size, SECRET_STORAGE_TYPE type) {
  if (size != 16)
    return last_error_ = -EINVAL;
  if (type != SECRET_STORAGE_TYPE::kTDES && type != SECRET_STORAGE_TYPE::kSM4)
    return last_error_ = -EINVAL;
  return DONGLE_CHECK(write_file(FILE_KEY, id, 0, size, static_cast<uint8_t*>(const_cast<void*>(buffer))));
}

///
/// RockeyARM, Bug: RSAPrivate([256 dup 0]) freeze ...
///
static int BugCheckZeroInput(const uint8_t* input) {
  int sum = 0;
  for (int i = 0; i < 256; ++i)
    sum += input[i];
  return sum == 0;
}

int Dongle::RSAPrivate(int id,
                       uint8_t buffer[] /* length_is(*size_buffer), max_size(bits/8) */,
                       size_t* size_buffer,
                       bool encrypt) {
  size_t size_in = *size_buffer;
  if (encrypt) {
    if (size_in > 256 - 11)
      return last_error_ = -E2BIG;
  } else if (size_in != 256) {
    return last_error_ = -EINVAL;
  }

  if (!encrypt && BugCheckZeroInput(buffer))
    return -EINVAL;

  WORD size_out = 256;
  int result = DONGLE_CHECK(
      rsa_pri(id, buffer, static_cast<WORD>(size_in), buffer, &size_out, encrypt ? MODE_ENCODE : MODE_DECODE));
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
  size_t size_in = *size_buffer;
  if (bits != 2048)
    return last_error_ = -EINVAL;

  if (encrypt) {
    if (size_in > 256 - 11)
      return last_error_ = -E2BIG;
  } else if (size_in != 256) {
    return last_error_ = -EINVAL;
  }

  if (!encrypt && BugCheckZeroInput(buffer))
    return -EINVAL;

  RSA_PRIVATE_KEY prikey;
  prikey.bits = bits;
  prikey.modulus = modules;
  memcpy(prikey.publicExponent, public_, 256);
  memcpy(prikey.exponent, private_, 256);

  WORD size_out = 256;
  int result = DONGLE_CHECK(
      rsa_pri_raw(&prikey, buffer, static_cast<WORD>(size_in), buffer, &size_out, encrypt ? MODE_ENCODE : MODE_DECODE));
  if (result >= 0)
    *size_buffer = size_out;
  return result;
}
int Dongle::RSAPublic(int bits,
                      uint32_t modules,
                      const uint8_t public_[],
                      uint8_t buffer[] /* length_is(*size_buffer), max_size(bits/8) */,
                      size_t* size_buffer,
                      bool encrypt) {
  size_t size_in = *size_buffer;
  if (bits != 2048)
    return last_error_ = -EINVAL;
  if (encrypt) {
    if (size_in > 256 - 11)
      return last_error_ = -E2BIG;
  } else if (size_in != 256) {
    return last_error_ = -EINVAL;
  }

  RSA_PUBLIC_KEY pubkey;
  pubkey.bits = bits;
  pubkey.modulus = modules;
  memcpy(pubkey.exponent, public_, 256);

  WORD size_out = 256;
  int result = DONGLE_CHECK(
      rsa_pub(buffer, static_cast<WORD>(size_in), &pubkey, buffer, &size_out, encrypt ? MODE_ENCODE : MODE_DECODE));
  if (result >= 0)
    *size_buffer = size_out;
  return result;
}

int Dongle::P256Sign(int id, const uint8_t hash_[32], uint8_t R[32], uint8_t S[32]) {
  WORD len_sign = 64;
  uint8_t sign[64], hash[32];
  CopyReverse<32>(hash, hash_);
  if (0 != DONGLE_CHECK(ecc_sign(id, hash, 32, sign, &len_sign)))
    return -1;
  CopyReverse<32>(R, &sign[0]);
  CopyReverse<32>(S, &sign[32]);
  return 0;
}

int Dongle::P256Sign(const uint8_t private_[32], const uint8_t hash_[32], uint8_t R[32], uint8_t S[32]) {
  WORD len_sign = 64;
  uint8_t sign[64], hash[32];
  SecretBuffer<1, ECCSM2_PRIVATE_KEY> pkey;

  pkey->bits = 256;
  CopyReverse<32>(hash, hash_);
  CopyReverse<32>(pkey->PrivateKey, private_);
  if (0 != DONGLE_CHECK(ecc_sign_raw(pkey, hash, 32, sign, &len_sign)))
    return -1;
  CopyReverse<32>(R, &sign[0]);
  CopyReverse<32>(S, &sign[32]);
  return 0;
}

int Dongle::P256Verify(const uint8_t X[32],
                       const uint8_t Y[32],
                       const uint8_t hash_[32],
                       const uint8_t R[32],
                       const uint8_t S[32]) {
  ECCSM2_PUBLIC_KEY pubkey;
  uint8_t hash[32], sign[64];

  pubkey.bits = 256;
  CopyReverse<32>(pubkey.XCoordinate, X);
  CopyReverse<32>(pubkey.YCoordinate, Y);
  CopyReverse<32>(hash, hash_);
  CopyReverse<32>(&sign[0], R);
  CopyReverse<32>(&sign[32], S);
  return DONGLE_CHECK(ecc_verify(&pubkey, hash, 32, sign));
}

int Dongle::SM2Sign(int id, const uint8_t hash_[32], uint8_t R[32], uint8_t S[32]) {
  WORD len_sign = 64;
  uint8_t sign[64], hash[32];
  CopyReverse<32>(hash, hash_);
  if (0 != DONGLE_CHECK(sm2_sign(id, hash, 32, sign, &len_sign)))
    return -1;
  CopyReverse<32>(R, &sign[0]);
  CopyReverse<32>(S, &sign[32]);
  return 0;
}

int Dongle::SM2Sign(const uint8_t private_[32], const uint8_t hash_[32], uint8_t R[32], uint8_t S[32]) {
  WORD len_sign = 64;
  uint8_t sign[64], hash[32];
  SecretBuffer<1, ECCSM2_PRIVATE_KEY> pkey;

  pkey->bits = 0x8100;
  CopyReverse<32>(hash, hash_);
  CopyReverse<32>(pkey->PrivateKey, private_);
  if (0 != DONGLE_CHECK(sm2_sign_raw(pkey, hash, 32, sign, &len_sign)))
    return -1;
  CopyReverse<32>(R, &sign[0]);
  CopyReverse<32>(S, &sign[32]);
  return 0;
}

int Dongle::SM2Verify(const uint8_t X[32],
              const uint8_t Y[32],
              const uint8_t hash_[32],
              const uint8_t R[32],
              const uint8_t S[32]) override {
  ECCSM2_PUBLIC_KEY pubkey;
  uint8_t hash[32], sign[64];

  pubkey.bits = 0x8100;
  CopyReverse<32>(pubkey.XCoordinate, X);
  CopyReverse<32>(pubkey.YCoordinate, Y);
  CopyReverse<32>(hash, hash_);
  CopyReverse<32>(&sign[0], R);
  CopyReverse<32>(&sign[32], S);
  return DONGLE_CHECK(sm2_verify(&pubkey, hash, 32, sign));
}

int Dongle::SM2Decrypt(int id, const uint8_t cipher[], size_t size_cipher, uint8_t text[], size_t* size_text) override {
  WORD sizeOut = *size_text;
  if (0 != DONGLE_CHECK(sm2_decrypt(id, const_cast<uint8_t*>(cipher), size_cipher, text, &sizeOut)))
    return -1;
  *size_text = sizeOut;
  return 0;
}
int Dongle::SM2Decrypt(const uint8_t private_[32],
                       const uint8_t cipher[],
                       size_t size_cipher,
                       uint8_t text[],
                       size_t* size_text) override {
  WORD sizeOut = *size_text;
  SecretBuffer<1, ECCSM2_PRIVATE_KEY> pkey;
  pkey->bits = 0x8100;
  CopyReverse<32>(pkey->PrivateKey, private_);
  if (0 != DONGLE_CHECK(sm2_decrypt_key(pkey, const_cast<uint8_t*>(cipher), size_cipher, text, &sizeOut)))
    return -1;
  *size_text = sizeOut;
  return 0;
}

int Dongle::SM2Encrypt(const uint8_t X[32],
                       const uint8_t Y[32],
                       const uint8_t text[],
                       size_t size_text,
                       uint8_t cipher[]) override {
  ECCSM2_PUBLIC_KEY pubkey;

  pubkey.bits = 0x8100;
  CopyReverse<32>(pubkey.XCoordinate, X);
  CopyReverse<32>(pubkey.YCoordinate, Y);
  return DONGLE_CHECK(sm2_encrypt(&pubkey, const_cast<uint8_t*>(text), size_text, cipher));
}

int Dongle::SHA1(const void* input, size_t size, uint8_t md[20]) {
  return DONGLE_CHECK(sha1(static_cast<uint8_t*>(const_cast<void*>(input)), size, md));
}
int Dongle::SM3(const void* input, size_t size, uint8_t md[32]) {
  return DONGLE_CHECK(sm3(static_cast<uint8_t*>(const_cast<void*>(input)), size, md));
}

int Dongle::TDESECB(int id, uint8_t* buffer, size_t size, bool encrypt) {
  return DONGLE_CHECK(tdes(buffer, size, encrypt ? MODE_ENCODE : MODE_DECODE, id));
}
int Dongle::TDESECB(const uint8_t key[16], uint8_t* buffer, size_t size, bool encrypt) {
  return DONGLE_CHECK(tdes_raw(buffer, size, encrypt ? MODE_ENCODE : MODE_DECODE, const_cast<uint8_t*>(key)));
}

int Dongle::SM4ECB(int id, uint8_t* buffer, size_t size, bool encrypt) {
  return DONGLE_CHECK(sm4(buffer, size, encrypt ? MODE_ENCODE : MODE_DECODE, id));
}
int Dongle::SM4ECB(const uint8_t key[16], uint8_t* buffer, size_t size, bool encrypt) {
  return DONGLE_CHECK(sm4_raw(buffer, size, encrypt ? MODE_ENCODE : MODE_DECODE, const_cast<uint8_t*>(key)));
}

void Dongle::Abort() {
  for (;;)
    ;
}
int Dongle::CheckError(DWORD error) {
  if (ERR_SUCCESS == error)
    return 0;
  last_error_ = error;
  return -1;
}

} // namespace dongle

rLANG_DECLARE_END

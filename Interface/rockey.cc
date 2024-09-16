#include <Interface/dongle.h>
extern "C" {
#include <MCU/RockeyARM/include/FTRX.h>
}

rLANG_DECLARE_MACHINE

namespace dongle {

int Dongle::RandBytes(uint8_t* buffer, size_t size) {
  return DONGLE_CHECK(get_random(buffer, size));
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

  return DONGLE_CHECK(delete_file(type, id));
}

int Dongle::CreateDataFile(int id, size_t size, PERMISSION read, PERMISSION write) {
  DATA_FILE_ATTR attr;
  attr.m_Size = size;
  attr.m_Lic.m_Read_Priv = static_cast<uint8_t>(read);
  attr.m_Lic.m_WritePriv = static_cast<uint8_t>(write);
  return DONGLE_CHECK(create_file(FILE_DATA, id, reinterpret_cast<uint8_t*>(&attr), sizeof(attr)));
}
int Dongle::WriteDataFile(int id, size_t offset, const void* buffer, size_t size) {
  return DONGLE_CHECK(write_file(FILE_DATA, id, offset, size, static_cast<uint8_t*>(const_cast<void*>(buffer))));
}
int Dongle::ReadDataFile(int id, size_t offset, void* buffer, size_t size) {
  return DONGLE_CHECK(read_file(id, offset, size, static_cast<uint8_t*>(buffer)));
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
    return -EINVAL;
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
int Dongle::ImportP256(int id, const uint8_t X[32], const uint8_t Y[32], const uint8_t K[32]) {
  ECCSM2_KEY_PAIR pkey;
  pkey.Pubkey.bits = pkey.Prikey.bits = 256;
  CopyReverse<32>(pkey.Pubkey.XCoordinate, X);
  CopyReverse<32>(pkey.Pubkey.YCoordinate, Y);
  CopyReverse<32>(pkey.Prikey.PrivateKey, K);
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
int Dongle::ImportSM2(int id, const uint8_t X[32], const uint8_t Y[32], const uint8_t K[32]) {
  ECCSM2_KEY_PAIR pkey;
  pkey.Pubkey.bits = pkey.Prikey.bits = 0x8100;
  CopyReverse<32>(pkey.Pubkey.XCoordinate, X);
  CopyReverse<32>(pkey.Pubkey.YCoordinate, Y);
  CopyReverse<32>(pkey.Prikey.PrivateKey, K);
  return DONGLE_CHECK(write_file(FILE_PRIKEY_ECCSM2, id, 0, sizeof(pkey), reinterpret_cast<uint8_t*>(&pkey)));
}

int Dongle::CreateKeyFile(int id, PERMISSION permission, SECRET_STORAGE_TYPE type) {
  KEY_FILE_ATTR attr;
  attr.m_Size = 16;
  attr.m_Lic.m_Priv_Enc = static_cast<uint8_t>(permission);
  if (type != SECRET_STORAGE_TYPE::kTDES && type != SECRET_STORAGE_TYPE::kSM4)
    return -EINVAL;
  return DONGLE_CHECK(create_file(FILE_KEY, id, reinterpret_cast<uint8_t*>(&attr), sizeof(attr)));
}
int Dongle::WriteKeyFile(int id, const void* buffer, size_t size, SECRET_STORAGE_TYPE type) {
  if (size != 16)
    return -EINVAL;
  if (type != SECRET_STORAGE_TYPE::kTDES && type != SECRET_STORAGE_TYPE::kSM4)
    return -EINVAL;
  return DONGLE_CHECK(write_file(FILE_KEY, id, 0, size, static_cast<uint8_t*>(const_cast<void*>(buffer))));
}

int Dongle::RSAPrivate(int id, const uint8_t* in, size_t size_in, uint8_t out[], size_t* size_out, bool encrypt) {
  WORD size = static_cast<WORD>(*size_out);
  int result = DONGLE_CHECK(rsa_pri(id, const_cast<uint8_t*>(in), static_cast<WORD>(size_in), out, &size,
                                    encrypt ? MODE_ENCODE : MODE_DECODE));
  if (result >= 0)
    *size_out = size;
  return result;
}
int Dongle::RSAPrivate(int bits,
                       uint32_t modules,
                       const uint8_t public_[],
                       const uint8_t private_[],
                       const uint8_t* in,
                       size_t size_in,
                       uint8_t out[],
                       size_t* size_out,
                       bool encrypt) {
  if (bits != 2048)
    return -EINVAL;

  if (encrypt) {
    if (size_in < 16)
      return -EINVAL;
    if (size_in > 256 - 11)
      return -E2BIG;
  } else if (size_in != 256) {
    return -EINVAL;
  }

  RSA_PRIVATE_KEY prikey;
  prikey.bits = bits;
  prikey.modulus = modules;
  memcpy(prikey.publicExponent, public_, 256);
  memcpy(prikey.exponent, private_, 256);
  WORD size = static_cast<WORD>(*size_out);
  int result = DONGLE_CHECK(rsa_pri_raw(&prikey, const_cast<uint8_t*>(in), static_cast<WORD>(size_in), out, &size,
                                        encrypt ? MODE_ENCODE : MODE_DECODE));
  if (result >= 0)
    *size_out = size;
  return result;
}
int Dongle::RSAPublic(int bits,
                      uint32_t modules,
                      const uint8_t public_[],
                      const uint8_t* in,
                      size_t size_in,
                      uint8_t out[],
                      size_t* size_out,
                      bool encrypt) {
  if (bits != 2048)
    return -EINVAL;

  RSA_PUBLIC_KEY pubkey;
  pubkey.bits = bits;
  pubkey.modulus = modules;
  memcpy(pubkey.exponent, public_, 256);
  WORD size = static_cast<WORD>(*size_out);
  int result = DONGLE_CHECK(rsa_pub(const_cast<uint8_t*>(in), static_cast<WORD>(size_in), &pubkey, out, &size,
                                    encrypt ? MODE_ENCODE : MODE_DECODE));
  if (result >= 0)
    *size_out = size;
  return result;
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


#if 0
class Rockey final : public Dongle {
 public:

 public:



 public:
  int DeleteFile(SECRET_STORAGE_TYPE type_, int id) override {
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

    return CheckError(delete_file(type, id));
  }
  int CreateDataFile(int id, size_t size, PERMISSION read, PERMISSION write) override {
    DATA_FILE_ATTR attr;
    attr.m_Size = size;
    attr.m_Lic.m_Read_Priv = static_cast<uint8_t>(read);
    attr.m_Lic.m_WritePriv = static_cast<uint8_t>(write);
    return CheckError(create_file(FILE_DATA, id, reinterpret_cast<uint8_t*>(&attr), sizeof(attr)));
  }
  int WriteDataFile(int id, size_t offset, const void* buffer, size_t size) override {
    return CheckError(write_file(FILE_DATA, id, offset, size, static_cast<uint8_t*>(const_cast<void*>(buffer))));
  }
  int ReadDataFile(int id, size_t offset, void* buffer, size_t size) override {
    return CheckError(read_file(id, offset, size, static_cast<uint8_t*>(buffer)));
  }
  int CreatePKEYFile(SECRET_STORAGE_TYPE type_, int bits, int id, const PKEY_LICENCE licence) override {
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
    }
    else {
      return -EINVAL;
    }

    return CheckError(create_file(type, id, reinterpret_cast<uint8_t*>(&attr), sizeof(attr)));
  }
  int GenerateRSA(int id, uint32_t* modulus, uint8_t public_[], uint8_t* private_) override {
    SecretBuffer<1,RSA_PRIVATE_KEY> pkey;
    if (0 != CheckError(rsa_genkey(id, pkey)))
      return -1;

    *modulus = pkey->modulus;
    memcpy(public_, pkey->publicExponent, pkey->bits / 8);
    if (private_)
      memcpy(private_, pkey->exponent, pkey->bits / 8);
    return pkey->bits;
  }
  int ImportRSA(int id, int bits, uint32_t modules, const uint8_t public_[], const uint8_t private_[]) override {
    if (bits != 2048)
      return -EINVAL;
    SecretBuffer<1,RSA_PRIVATE_KEY> pkey;
    pkey->bits = bits;
    pkey->modulus = modules;
    memcpy(pkey->publicExponent, public_, bits / 8);
    memcpy(pkey->exponent, private_, bits / 8);
    return CheckError(write_file(FILE_PRIKEY_RSA, id, 0, sizeof(pkey), reinterpret_cast<uint8_t*>(&pkey)));
  }

  int GenerateP256(int id, uint8_t X[32], uint8_t Y[32], uint8_t* private_) override {
    ECCSM2_KEY_PAIR pkey;
    if (0 != CheckError(ecc_genkey(id, &pkey)))
      return -1;
    CopyReverse<32>(X, pkey.Pubkey.XCoordinate);
    CopyReverse<32>(Y, pkey.Pubkey.YCoordinate);
    if (private_)
      CopyReverse<32>(private_, pkey.Prikey.PrivateKey);
    return 0;
  }

  int ImportP256(int id, const uint8_t X[32], const uint8_t Y[32], const uint8_t K[32]) override {
    ECCSM2_KEY_PAIR pkey;
    pkey.Pubkey.bits = pkey.Prikey.bits = 256;
    CopyReverse<32>(pkey.Pubkey.XCoordinate, X);
    CopyReverse<32>(pkey.Pubkey.YCoordinate, Y);
    CopyReverse<32>(pkey.Prikey.PrivateKey, K);
    return CheckError(write_file(FILE_PRIKEY_ECCSM2, id, 0, sizeof(pkey), reinterpret_cast<uint8_t*>(&pkey)));
  }

  int GenerateSM2(int id, uint8_t X[32], uint8_t Y[32], uint8_t* private_) override {
    ECCSM2_KEY_PAIR pkey;
    if (0 != CheckError(sm2_genkey(id, &pkey)))
      return -1;
    CopyReverse<32>(X, pkey.Pubkey.XCoordinate);
    CopyReverse<32>(Y, pkey.Pubkey.YCoordinate);
    if (private_)
      CopyReverse<32>(private_, pkey.Prikey.PrivateKey);
    return 0;
  }
  int ImportSM2(int id, const uint8_t X[32], const uint8_t Y[32], const uint8_t K[32]) override {
    ECCSM2_KEY_PAIR pkey;
    pkey.Pubkey.bits = pkey.Prikey.bits = 0x8100;
    CopyReverse<32>(pkey.Pubkey.XCoordinate, X);
    CopyReverse<32>(pkey.Pubkey.YCoordinate, Y);
    CopyReverse<32>(pkey.Prikey.PrivateKey, K);
    return CheckError(write_file(FILE_PRIKEY_ECCSM2, id, 0, sizeof(pkey), reinterpret_cast<uint8_t*>(&pkey)));
  }

  int CreateKeyFile(int id, PERMISSION permission, SECRET_STORAGE_TYPE type) override {
    KEY_FILE_ATTR attr;
    attr.m_Size = 16;
    attr.m_Lic.m_Priv_Enc = static_cast<uint8_t>(permission);
    if (type != SECRET_STORAGE_TYPE::kTDES && type != SECRET_STORAGE_TYPE::kSM4)
      return -EINVAL;
    return CheckError(create_file(FILE_KEY, id, reinterpret_cast<uint8_t*>(&attr), sizeof(attr)));
  }
  int WriteKeyFile(int id, const void* buffer, size_t size, SECRET_STORAGE_TYPE type) override {
    if (size != 16)
      return -EINVAL;
    if (type != SECRET_STORAGE_TYPE::kTDES && type != SECRET_STORAGE_TYPE::kSM4)
      return -EINVAL;
    return CheckError(write_file(FILE_KEY, id, 0, size, static_cast<uint8_t*>(const_cast<void*>(buffer))));
  }

  int RSAPrivate(int id, const uint8_t* in, size_t size_in, uint8_t out[], size_t* size_out, bool encrypt) override {
    WORD sizeOut = *size_out;
    if (0 !=
        CheckError(rsa_pri(id, const_cast<uint8_t*>(in), size_in, out, &sizeOut, encrypt ? MODE_ENCODE : MODE_DECODE)))
      return -1;
    *size_out = sizeOut;
    return 0;
  }
  int RSAPrivate(int bits,
                 uint32_t modules,
                 const uint8_t public_[],
                 const uint8_t private_[],
                 const uint8_t* in,
                 size_t size_in,
                 uint8_t out[],
                 size_t* size_out,
                 bool encrypt) override {
    WORD sizeOut = *size_out;
    if (bits != 2048)
      return -EINVAL;
    SecretBuffer<1,RSA_PRIVATE_KEY> pkey;
    pkey->bits = bits;
    pkey->modulus = modules;
    memcpy(pkey->publicExponent, public_, bits / 8);
    memcpy(pkey->exponent, private_, bits / 8);
    if (0 != CheckError(rsa_pri_raw(pkey, const_cast<uint8_t*>(in), size_in, out, &sizeOut,
                                    encrypt ? MODE_ENCODE : MODE_DECODE)))
      return -1;
    *size_out = sizeOut;
    return 0;
  }
  int RSAPublic(int bits,
                uint32_t modules,
                const uint8_t public_[],
                const uint8_t* in,
                size_t size_in,
                uint8_t out[],
                size_t* size_out,
                bool encrypt) override {
    WORD sizeOut = *size_out;
    if (bits != 2048)
      return -EINVAL;

    RSA_PUBLIC_KEY pubkey;
    pubkey.bits = bits;
    pubkey.modulus = modules;
    memcpy(pubkey.exponent, public_, bits / 8);
    if (0 != CheckError(rsa_pub(const_cast<uint8_t*>(in), size_in, &pubkey, out, &sizeOut,
                                encrypt ? MODE_ENCODE : MODE_DECODE)))
      return -1;
    *size_out = sizeOut;
    return 0;
  }

  int P256Sign(int id, const uint8_t hash_[32], uint8_t R[32], uint8_t S[32]) override {
    WORD len_sign = 64;
    uint8_t sign[64], hash[32];
    CopyReverse<32>(hash, hash_);
    if (0 != CheckError(ecc_sign(id, const_cast<uint8_t*>(hash), 32, sign, &len_sign)))
      return -1;
    CopyReverse<32>(R, &sign[0]);
    CopyReverse<32>(S, &sign[32]);
    return 0;
  }
  int P256Sign(const uint8_t private_[32], const uint8_t hash_[32], uint8_t R[32], uint8_t S[32]) override {
    WORD len_sign = 64;
    uint8_t sign[64], hash[32];
    SecretBuffer<1,ECCSM2_PRIVATE_KEY> pkey;

    pkey->bits = 256;
    CopyReverse<32>(hash, hash_);
    CopyReverse<32>(pkey->PrivateKey, private_);
    if (0 != CheckError(ecc_sign_raw(pkey, const_cast<uint8_t*>(hash), 32, sign, &len_sign)))
      return -1;
    CopyReverse<32>(R, &sign[0]);
    CopyReverse<32>(S, &sign[32]);
    return 0;
  }
  int P256Verify(const uint8_t X[32],
                 const uint8_t Y[32],
                 const uint8_t hash_[32],
                 const uint8_t R[32],
                 const uint8_t S[32]) override {
    ECCSM2_PUBLIC_KEY pubkey;
    uint8_t hash[32], sign[64];

    pubkey.bits = 256;
    CopyReverse<32>(pubkey.XCoordinate, X);
    CopyReverse<32>(pubkey.YCoordinate, Y);
    CopyReverse<32>(hash, hash_);
    CopyReverse<32>(&sign[0], R);
    CopyReverse<32>(&sign[32], S);
    return CheckError(ecc_verify(&pubkey, hash, 32, sign));
  }

  int SM2Sign(int id, const uint8_t hash_[32], uint8_t R[32], uint8_t S[32]) override {
    WORD len_sign = 64;
    uint8_t sign[64], hash[32];
    CopyReverse<32>(hash, hash_);
    if (0 != CheckError(sm2_sign(id, const_cast<uint8_t*>(hash), 32, sign, &len_sign)))
      return -1;
    CopyReverse<32>(R, &sign[0]);
    CopyReverse<32>(S, &sign[32]);
    return 0;
  }
  int SM2Sign(const uint8_t private_[32], const uint8_t hash_[32], uint8_t R[32], uint8_t S[32]) override {
    WORD len_sign = 64;
    uint8_t sign[64], hash[32];
    SecretBuffer<1,ECCSM2_PRIVATE_KEY> pkey;

    pkey->bits = 0x8100;
    CopyReverse<32>(hash, hash_);
    CopyReverse<32>(pkey->PrivateKey, private_);
    if (0 != CheckError(sm2_sign_raw(pkey, const_cast<uint8_t*>(hash), 32, sign, &len_sign)))
      return -1;
    CopyReverse<32>(R, &sign[0]);
    CopyReverse<32>(S, &sign[32]);
    return 0;
  }

  int SM2Verify(const uint8_t X[32],
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
    return CheckError(sm2_verify(&pubkey, hash, 32, sign));
  }

  int SM2Decrypt(int id, const uint8_t cipher[], size_t size_cipher, uint8_t text[], size_t* size_text) override {
    WORD sizeOut = *size_text;
    if (0 != CheckError(sm2_decrypt(id, const_cast<uint8_t*>(cipher), size_cipher, text, &sizeOut)))
      return -1;
    *size_text = sizeOut;
    return 0;
  }
  int SM2Decrypt(const uint8_t private_[32],
                 const uint8_t cipher[],
                 size_t size_cipher,
                 uint8_t text[],
                 size_t* size_text) override {
    WORD sizeOut = *size_text;
    SecretBuffer<1,ECCSM2_PRIVATE_KEY> pkey;
    pkey->bits = 0x8100;
    CopyReverse<32>(pkey->PrivateKey, private_);
    if (0 != CheckError(sm2_decrypt_key(pkey, const_cast<uint8_t*>(cipher), size_cipher, text, &sizeOut)))
      return -1;
    *size_text = sizeOut;
    return 0;
  }

  int SM2Encrypt(const uint8_t X[32],
                 const uint8_t Y[32],
                 const uint8_t text[],
                 size_t size_text,
                 uint8_t cipher[]) override {
    ECCSM2_PUBLIC_KEY pubkey;

    pubkey.bits = 0x8100;
    CopyReverse<32>(pubkey.XCoordinate, X);
    CopyReverse<32>(pubkey.YCoordinate, Y);
    return CheckError(sm2_encrypt(&pubkey, const_cast<uint8_t*>(text), size_text, cipher));
  }

 public:
  int SHA1(const void* input, size_t size, uint8_t md[20]) override {
    return CheckError(sha1(static_cast<uint8_t*>(const_cast<void*>(input)), size, md));
  }
  int SM3(const void* input, size_t size, uint8_t md[32]) override {
    return CheckError(sm3(static_cast<uint8_t*>(const_cast<void*>(input)), size, md));
  }

  int TDESECB(int id, uint8_t* buffer, size_t size, bool encrypt) override {
    return CheckError(tdes(buffer, size, encrypt ? MODE_ENCODE : MODE_DECODE, id));
  }
  int TDESECB(const uint8_t key[16], int id, uint8_t* buffer, size_t size, bool encrypt) override {
    return CheckError(tdes_raw(buffer, size, encrypt ? MODE_ENCODE : MODE_DECODE, const_cast<uint8_t*>(key)));
  }

  int SM4ECB(int id, uint8_t* buffer, size_t size, bool encrypt) override {
    return CheckError(sm4(buffer, size, encrypt ? MODE_ENCODE : MODE_DECODE, id));
  }
  int SM4ECB(const uint8_t key[16], int id, uint8_t* buffer, size_t size, bool encrypt) override {
    return CheckError(sm4_raw(buffer, size, encrypt ? MODE_ENCODE : MODE_DECODE, const_cast<uint8_t*>(key)));
  }

  int SEED(const void* input, size_t size, uint8_t result[16]) override {
    return CheckError(seed(static_cast<uint8_t*>(const_cast<void*>(input)), size, result));
  }

 private:
  DWORD last_error_ = 0;
  int CheckError(DWORD error) {
    if (ERR_SUCCESS == error)
      return 0;
    last_error_ = error;
    return -1;
  }
};


int RockeyARM::RockeyDongle(MemoryHolder* memory, Dongle** dongle) {
  rLANG_ABIREQUIRE(sizeof(Rockey) <= sizeof(RockeyARM::MemoryHolder));
  *dongle = new (memory) Rockey();
  return 0;
}
#endif


} // namespace dongle

rLANG_DECLARE_END

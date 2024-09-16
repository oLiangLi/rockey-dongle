#include <Interface/dongle.h>
#include <base/base.h>

#include "RockeyARM/Dongle_API.h"

rLANG_DECLARE_MACHINE

namespace {
constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("DONGLE");
}

namespace dongle {
    
int Dongle::RandBytes(uint8_t* buffer, size_t size) {
  return DONGLE_CHECK(Dongle_GenRandom(handle_, static_cast<int>(size), buffer));
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
int Dongle::ImportP256(int id, const uint8_t X[32], const uint8_t Y[32], const uint8_t K[32]) {
  SecretBuffer<1, ECCSM2_PRIVATE_KEY> pkey;

  // TODO: LiangLI, Check X,Y ...

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
int Dongle::ImportSM2(int id, const uint8_t X[32], const uint8_t Y[32], const uint8_t K[32]) {
  SecretBuffer<1, ECCSM2_PRIVATE_KEY> pkey;

  // TODO: LiangLI, Check X,Y ...

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

int Dongle::RSAPrivate(int id, const uint8_t* in, size_t size_in, uint8_t out[], size_t* size_out, bool encrypt) {
  int sizeOut = static_cast<int>(*size_out);

  int result = DONGLE_CHECK(Dongle_RsaPri(handle_, id, encrypt ? FLAG_ENCODE : FLAG_DECODE, const_cast<uint8_t*>(in),
                                          static_cast<int>(size_in), out, &sizeOut));
  if (result >= 0)
    *size_out = sizeOut;
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
  int result = 0;
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

  RSA* rsa = RSA_new();
  BIGNUM* d = BN_bin2bn(private_, 256, nullptr);
  BIGNUM* n = BN_bin2bn(public_, 256, nullptr);
  BIGNUM* e = BN_new();

  DONGLE_VERIFY(rsa && d && n && e);
  DONGLE_VERIFY(1 == BN_set_word(e, modules));
  DONGLE_VERIFY(1 == RSA_set0_key(rsa, n, e, d));
  SecretBuffer<256> buffer;

  if (encrypt) {
    int len = RSA_private_encrypt(static_cast<int>(size_in), in, buffer, rsa, RSA_PKCS1_PADDING);
    if (len < 0) {
      rlLOGE(TAG, "RSA_private_encrypt %zd error %ld", size_in, ERR_get_error());
      result = -1;
    } else {
      if (static_cast<size_t>(len) > *size_out) {
        rlLOGE(TAG, "RSA_private_encrypt size %d Out-of-buffer %zd", len, *size_out);
        result = -ENOSPC;
      } else {
        memcpy(out, buffer, len);
        *size_out = len;
      }
    }
  } else {
    int len = RSA_private_decrypt(static_cast<int>(size_in), in, buffer, rsa, RSA_PKCS1_PADDING);
    if (len < 0) {
      rlLOGE(TAG, "RSA_private_decrypt %zd error %ld", size_in, ERR_get_error());
      result = -1;
    } else {
      if (static_cast<size_t>(len) > *size_out) {
        rlLOGE(TAG, "RSA_private_encrypt size %d Out-of-buffer %zd", len, *size_out);
        result = -ENOSPC;
      } else {
        memcpy(out, buffer, len);
        *size_out = len;
      }
    }
  }
  RSA_free(rsa);

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
  int sizeOut = static_cast<int>(*size_out);
  RSA_PUBLIC_KEY pubkey;
  if (bits != 2048)
    return -EINVAL;

  pubkey.bits = bits;
  pubkey.modulus = modules;
  memcpy(pubkey.exponent, public_, 256);
  int result = DONGLE_CHECK(Dongle_RsaPub(handle_, encrypt ? FLAG_ENCODE : FLAG_DECODE, &pubkey,
                                          const_cast<uint8_t*>(in), static_cast<int>(size_in), out, &sizeOut));
  if (result >= 0)
    *size_out = sizeOut;
  return result;
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

#if 0

RockeyARM::~RockeyARM() {
  Close();
}

int RockeyARM::EnumDongle(DONGLE_INFO* info, size_t size, uint32_t* error) {
  DWORD result;
  int count = -1;

  if (!info || !size) {
    result = Dongle_Enum(nullptr, &count);
  } else {
    constexpr size_t kDongleMaxCount = 64;
    ::DONGLE_INFO all[kDongleMaxCount];
    result = Dongle_Enum(all, &count);
    if (result == DONGLE_SUCCESS && count > 0) {
      if (size > static_cast<size_t>(count))
        size = count;
      for (size_t i = 0; i < size; ++i)
        GetDongleInfo(&info[i], all[i]);
    }
  }
  if (error)
    *error = result;
  return count;
}

int RockeyARM::CheckError(uint32_t error) {
  if (DONGLE_SUCCESS == error)
    return 0;
  last_error_ = error;
  return -1;
}

int RockeyARM::Close() {
  Handle h = nullptr;
  std::swap(h, handle_);
  return CheckError(Dongle_Close(h));
}

int RockeyARM::Open(int index) {
  Close();

  DONGLE_HANDLE handle = nullptr;
  if (0 != CheckError(Dongle_Open(&handle, index)))
    return -1;
  handle_ = static_cast<Handle>(handle);
  return 0;
}
#endif


} // namespace dongle

rLANG_DECLARE_END

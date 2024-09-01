#include <Interface/dongle.h>
#include <MCU/RockeyARM/include/FTRX.h>
#include <new>

rLANG_DECLARE_MACHINE

namespace dongle {

class Rockey final : public Dongle {
 public:
  uint32_t GetLastError(void) override { return last_error_; }

 public:
  int RandBytes(uint8_t* buffer, size_t size) override { return CheckError(get_random(buffer, size)); }
  int GetRealTime(DWORD* time) override { return CheckError(get_realtime(time)); }
  int GetExpireTime(DWORD* time) override { return CheckError(get_expiretime(time)); }
  int GetTickCount(DWORD* ticks) override { return CheckError(get_tickcount(ticks)); }
  int GetDongleInfo(DONGLE_INFO* info) override {
    ::DONGLE_INFO dongle;
    if (0 != CheckError(get_keyinfo(&dongle)))
      return -1;
    info->ver_ = dongle.m_Ver;
    info->type_ = dongle.m_Type;
    rLANG_ABIREQUIRE(sizeof(info->birthday_) == sizeof(dongle.m_BirthDay));
    memcpy(info->birthday_, dongle.m_BirthDay, sizeof(dongle.m_BirthDay));
    info->agentId_ = dongle.m_Agent;
    info->pid_ = dongle.m_PID;
    info->uid_ = dongle.m_UserID;

    info->hid_[0] = info->hid_[1] = info->hid_[2] = 0;  // 0.0.0 => RockeyARM ...
    info->hid_[3] = dongle.m_IsMother ? 1 : 0;
    memcpy(&info->hid_[4], dongle.m_HID, sizeof(dongle.m_HID));
    rLANG_ABIREQUIRE(8 == sizeof(dongle.m_HID) && 12 == sizeof(info->hid_));

    return 0;
  }

  int GetPINState(PIN_STATE* state) override {
    DWORD pin = 0;
    if (0 != CheckError(get_pinstate(&pin)))
      return -1;
    *state = pin == PIN_ADMIN ? PIN_STATE::kAdminstrator : pin == PIN_USER ? PIN_STATE::kNormal : PIN_STATE::kAnonymous;
    return 0;
  }

  int SetLEDState(LED_STATE state) override { return CheckError(led_control(static_cast<uint8_t>(state))); }

  int ReadShareMemory(uint8_t buffer[32]) override { return CheckError(get_sharememory(buffer)); }
  int WriteShareMemory(const uint8_t buffer[32]) override {
    return CheckError(set_sharememory(const_cast<uint8_t*>(buffer)));
  }

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
  int GenerateRSA(int id, uint32_t* modulus, uint8_t public_[]) override {
    RSA_PRIVATE_KEY pkey;
    if (0 != CheckError(rsa_genkey(id, &pkey)))
      return -1;

    *modulus = pkey.modulus;
    memcpy(public_, pkey.publicExponent, pkey.bits / 8);
    return pkey.bits;
  }
  int ImportRSA(int id, int bits, uint32_t modules, const uint8_t public_[], const uint8_t private_[]) override {
    if (bits != 2048)
      return -EINVAL;
    RSA_PRIVATE_KEY pkey;
    pkey.bits = bits;
    pkey.modulus = modules;
    memcpy(pkey.publicExponent, public_, bits / 8);
    memcpy(pkey.exponent, private_, bits / 8);
    return CheckError(write_file(FILE_PRIKEY_RSA, id, 0, sizeof(pkey), reinterpret_cast<uint8_t*>(&pkey)));
  }

  int GenerateP256(int id, uint8_t X[32], uint8_t Y[32]) override {
    ECCSM2_KEY_PAIR pkey;
    if (0 != CheckError(ecc_genkey(id, &pkey)))
      return -1;
    CopyReverse<32>(X, pkey.Pubkey.XCoordinate);
    CopyReverse<32>(Y, pkey.Pubkey.YCoordinate);
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

  int GenerateSM2(int id, uint8_t X[32], uint8_t Y[32]) override {
    ECCSM2_KEY_PAIR pkey;
    if (0 != CheckError(sm2_genkey(id, &pkey)))
      return -1;
    CopyReverse<32>(X, pkey.Pubkey.XCoordinate);
    CopyReverse<32>(Y, pkey.Pubkey.YCoordinate);
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
    return CheckError(write_file(FILE_KEY, id, 0, size, static_cast<uint8_t*>(buffer)));
  }

  int RSAPrivate(int id, const uint8_t* in, size_t size_in, uint8_t out[], size_t* size_out, bool encrypt) override {
    return -ENOSYS;
  }
  int RSAPublic(int size,
                uint32_t modules,
                const uint8_t public_[],
                const uint8_t* in,
                size_t size_in,
                uint8_t out[],
                size_t* size_out,
                bool encrypt) override {
    return -ENOSYS;
  }

  int P256Sign(int id, const uint8_t hash[32], uint8_t R[32], uint8_t S[32]) override { return -ENOSYS; }
  int P256Verify(const uint8_t X[32],
                 const uint8_t Y[32],
                 const uint8_t hash[32],
                 const uint8_t R[32],
                 const uint8_t S[32]) override {
    return -ENOSYS;
  }

  int SM2Sign(int id, const uint8_t hash[32], uint8_t R[32], uint8_t S[32]) override { return -ENOSYS; }

  int SM2Verify(const uint8_t X[32],
                const uint8_t Y[32],
                const uint8_t hash[32],
                const uint8_t R[32],
                const uint8_t S[32]) override {
    return -ENOSYS;
  }

  int SM2Decrypt(int id, const uint8_t cipher[], size_t size_cipher, uint8_t text[], size_t* size_text) override {
    return -ENOSYS;
  }

  int SM2Encrypt(const uint8_t X[32],
                 const uint8_t Y[32],
                 const uint8_t text[],
                 size_t size_text,
                 uint8_t cipher[],
                 size_t* size_cipher) override {
    return -ENOSYS;
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


int RockeyARM::CreateDongle(MemoryHolder* memory, Dongle** dongle) {
  rLANG_ABIREQUIRE(sizeof(Rockey) <= sizeof(RockeyARM::MemoryHolder));
  *dongle = new (memory) Rockey();
  return 0;
}


} // namespace dongle

rLANG_DECLARE_END

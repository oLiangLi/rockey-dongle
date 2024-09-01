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

  int SetLEDState(LED_STATE state) override {
    return CheckError(led_control(state == LED_STATE::kBlink ? LED_BLINK : state == LED_STATE::kOn ? LED_ON : LED_OFF));
  }

  int ReadShareMemory(uint8_t buffer[32]) override { return CheckError(get_sharememory(buffer)); }
  int WriteShareMemory(const uint8_t buffer[32]) override {
    return CheckError(set_sharememory(const_cast<uint8_t*>(buffer)));
  }

 public:
  int DeleteFile(SECRET_STORAGE_TYPE type, int id) override { return -ENOSYS; }
  int CreateDataFile(int id, size_t size, PERMISSION read, PERMISSION write) override { return -ENOSYS; }
  int WriteDataFile(int id, size_t offset, const void* buffer, size_t size) override { return -ENOSYS; }
  int ReadDataFile(int id, size_t offset, void* buffer, size_t size) override { return -ENOSYS; }
  int CreatePKEYFile(SECRET_STORAGE_TYPE type, int id, const PKEY_LICENCE licence) override { return -ENOSYS; }
  int GenerateRSA(int id, int size /* 2048 */, uint32_t* modulus, uint8_t public_[]) override { return -ENOSYS; }
  int ImportRSA(int id,
                int size /* 2048 */,
                uint32_t modules,
                const uint8_t pubilc_[],
                const uint8_t private_[]) override {
    return -ENOSYS;
  }
  int GenerateP256(int id, uint8_t X[32], uint8_t Y[32]) override { return -ENOSYS; }
  int ImportP256(int id, const uint8_t K[32]) override { return -ENOSYS; }
  int GenerateSM2(int id, uint8_t X[32], uint8_t Y[32]) override { return -ENOSYS; }
  int ImportSM2(int id, const uint8_t K[32]) override { return -ENOSYS; }
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

  int SM4ECB(int id, uint8_t* buffer, size_t size, bool encrypt) override {
    if (size % 16)
      return -EINVAL;
    return CheckError(sm4(buffer, size, encrypt ? MODE_ENCODE : MODE_DECODE, id));
  }
  int SM4ECB(const uint8_t key[16], int id, uint8_t* buffer, size_t size, bool encrypt) override {
    if (size % 16)
      return -EINVAL;
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

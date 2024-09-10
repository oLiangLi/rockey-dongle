#include <base/base.h>
#include <memory>

rLANG_DECLARE_MACHINE

namespace dongle {

enum class PIN_STATE  : uint8_t { kAnonymous, kNormal, kAdminstrator };
enum class PERMISSION : uint8_t { kAnonymous, kNormal, kAdminstrator };

enum class LED_STATE : uint8_t { kOff, kOn, kBlink };
enum class SECRET_STORAGE_TYPE : uint8_t { kData, kRSA, kP256, kSM2, kSM4, kTDES };

struct PKEY_LICENCE {
  int32_t count_limit_ = -1;
  PERMISSION permission_ = PERMISSION::kAnonymous;
  bool global_decrease_ = false;
  bool logout_force_ = false;

  PKEY_LICENCE& SetLimit(int32_t limit) {
    count_limit_ = limit;
    return *this;
  }
  PKEY_LICENCE& SetPermission(PERMISSION permission) {
    permission_ = permission;
    return *this;
  }
  PKEY_LICENCE& SetGlobalDecrease(bool config = true) {
    global_decrease_ = config;
    return *this;
  }
  PKEY_LICENCE& SetLogoutForce(bool config = true) {
    logout_force_ = config;
    return *this;
  }
};

struct DONGLE_INFO {
  uint32_t ver_;
  uint32_t type_;
  uint8_t birthday_[8];
  uint32_t agentId_;
  uint32_t pid_;
  uint32_t uid_;
  uint8_t hid_[12];
};

rLANG_DECLARE_HANDLE(ROCKEY_HANDLE);

#ifdef __RockeyARM__
#define virtual /* nothing */ /* Welcome to the Real World! */
#define override /* nothing */
#endif /* __RockeyARM__ */

class Dongle {
 public:
  using DWORD = unsigned int;
  using WORD = unsigned short;
  using BYTE = unsigned char;

 public:
  template <size_t N = 32, typename T = uint8_t>
  void CopyReverse(void* to, const void* from) {
    T* target = static_cast<T*>(to);
    const T* source = static_cast<const T*>(from);
    for (size_t i = 0; i < N; ++i)
      target[i] = source[N - 1 - i];
  }
  template <size_t N, typename T = uint8_t>
  struct SecretBuffer {
    ~SecretBuffer() {
      memset(buffer_, 0, sizeof(buffer_));
    }
    size_t size() const { return N; }
    operator T*() { return buffer_; }
    operator const T*() const { return buffer_; }
    T* operator->() { return buffer_; }
    const T* operator->() const { return buffer_; }
    T& operator[](size_t i) { return buffer_[i]; }
    const T& operator[](size_t i) const { return buffer_[i]; }

    T buffer_[N];
  };

 public:
  Dongle() = default;
#ifndef __RockeyARM__
  Dongle(ROCKEY_HANDLE handle) : handle_(handle) {}
#endif /* __RockeyARM__ */

  virtual ~Dongle() = default;

  Dongle(const Dongle&) = delete;
  Dongle& operator=(const Dongle&) = delete;

 public:
  DWORD GetLastError() const { return last_error_; }

 public:
  virtual int RandBytes(uint8_t* buffer, size_t size);

 protected:
#ifndef __RockeyARM__
  ROCKEY_HANDLE handle_ = nullptr;
#endif /* __RockeyARM__ */

  DWORD last_error_ = 0;
  int CheckError(DWORD error);
};

class RockeyARM : public Dongle {
 public:
  ~RockeyARM() override;

 public:
  virtual int Close();
  virtual int Open(int index);
  virtual int Enum(DONGLE_INFO info[64]);


};


#if 0
class Dongle {
 public:
  using DWORD = unsigned int;
  using WORD = unsigned short;
  using BYTE = unsigned char;

 public:
  template <size_t N = 32, typename T = uint8_t>
  void CopyReverse(void* to, const void* from) {
    T* target = static_cast<T*>(to);
    const T* source = static_cast<const T*>(from);
    for (size_t i = 0; i < N; ++i)
      target[i] = source[N - 1 - i];
  }
  template <size_t N, typename T = uint8_t>
  struct SecretBuffer {
    ~SecretBuffer() { memset(buffer_, 0, sizeof(buffer_)); }
    size_t size() const { return N; }
    operator T*() { return buffer_; }
    operator const T*() const { return buffer_; }
    T* operator->() { return buffer_; }
    const T* operator->() const { return buffer_; }
    T& operator[](size_t i) { return buffer_[i]; }
    const T& operator[](size_t i) const { return buffer_[i]; }

    T buffer_[N];
  };

 public:
  virtual uint32_t GetLastError(void) = 0;

 public:
  virtual int RandBytes(uint8_t* buffer, size_t size) = 0;

 public:
  virtual int GetRealTime(DWORD* time) = 0;
  virtual int GetExpireTime(DWORD* time) = 0;
  virtual int GetTickCount(DWORD* ticks) = 0;

 public:
  virtual int GetDongleInfo(DONGLE_INFO* info) = 0;
  virtual int GetPINState(PIN_STATE* state) = 0;
  virtual int SetLEDState(LED_STATE  state) = 0;

 public:
  virtual int ReadShareMemory(uint8_t buffer[32]) = 0;
  virtual int WriteShareMemory(const uint8_t buffer[32]) = 0;

 public:
  virtual int DeleteFile(SECRET_STORAGE_TYPE type, int id) = 0;

  /* SECRET_STORAGE_TYPE::kData */
  virtual int CreateDataFile(int id, size_t size, PERMISSION read, PERMISSION write) = 0;
  virtual int WriteDataFile(int id, size_t offset, const void* buffer, size_t size) = 0;
  virtual int ReadDataFile(int id, size_t offset, void* buffer, size_t size) = 0;

 public:  // PKEY STORAGE ...
  /* SECRET_STORAGE_TYPE::kRSA || SECRET_STORAGE_TYPE::kP256 || SECRET_STORAGE_TYPE::kSM2 */
  virtual int CreatePKEYFile(SECRET_STORAGE_TYPE type, int bits, int id, const PKEY_LICENCE licence = {}) = 0;

  /* SECRET_STORAGE_TYPE::kRSA */
  virtual int GenerateRSA(int id, uint32_t* modulus, uint8_t public_[], uint8_t* private_ = nullptr) = 0;
  virtual int ImportRSA(int id, int bits, uint32_t modules, const uint8_t public_[], const uint8_t private_[]) = 0;

  /* SECRET_STORAGE_TYPE::kP256 */
  virtual int GenerateP256(int id, uint8_t X[32], uint8_t Y[32], uint8_t* private_ = nullptr) = 0;
  virtual int ImportP256(int id, const uint8_t X[32], const uint8_t Y[32], const uint8_t K[32]) = 0;

  /* SECRET_STORAGE_TYPE::kSM2  */
  virtual int GenerateSM2(int id, uint8_t X[32], uint8_t Y[32], uint8_t* private_ = nullptr) = 0;
  virtual int ImportSM2(int id, const uint8_t X[32], const uint8_t Y[32], const uint8_t K[32]) = 0;

 public:  // SessionKey ...
  /* SECRET_STORAGE_TYPE::kSM4 || SECRET_STORAGE_TYPE::kTDES */
  virtual int CreateKeyFile(int id, PERMISSION permission, SECRET_STORAGE_TYPE type) = 0;
  virtual int WriteKeyFile(int id, const void* buffer, size_t size, SECRET_STORAGE_TYPE type) = 0;

 public:  // RSA ...
  virtual int RSAPrivate(int id, const uint8_t* in, size_t size_in, uint8_t out[], size_t* size_out, bool encrypt) = 0;
  virtual int RSAPrivate(int bits,
                         uint32_t modules,
                         const uint8_t public_[],
                         const uint8_t private_[],
                         const uint8_t* in,
                         size_t size_in,
                         uint8_t out[],
                         size_t* size_out,
                         bool encrypt) = 0;
  virtual int RSAPublic(int bits,
                        uint32_t modules,
                        const uint8_t public_[],
                        const uint8_t* in,
                        size_t size_in,
                        uint8_t out[],
                        size_t* size_out,
                        bool encrypt) = 0;

 public:  // P256 ECDSA ...
  virtual int P256Sign(int id, const uint8_t hash[32], uint8_t R[32], uint8_t S[32]) = 0;
  virtual int P256Sign(const uint8_t private_[32], const uint8_t hash[32], uint8_t R[32], uint8_t S[32]) = 0;
  virtual int P256Verify(const uint8_t X[32],
                         const uint8_t Y[32],
                         const uint8_t hash[32],
                         const uint8_t R[32],
                         const uint8_t S[32]) = 0;

 public:  // SM2 ECDSA ...
  virtual int SM2Sign(int id, const uint8_t hash[32], uint8_t R[32], uint8_t S[32]) = 0;
  virtual int SM2Sign(const uint8_t private_[32], const uint8_t hash[32], uint8_t R[32], uint8_t S[32]) = 0;
  virtual int SM2Verify(const uint8_t X[32],
                        const uint8_t Y[32],
                        const uint8_t hash[32],
                        const uint8_t R[32],
                        const uint8_t S[32]) = 0;

 public:  // SM2 ECIES ...
  virtual int SM2Decrypt(int id, const uint8_t cipher[], size_t size_cipher, uint8_t text[], size_t* size_text) = 0;
  virtual int SM2Decrypt(const uint8_t private_[32],
                         const uint8_t cipher[],
                         size_t size_cipher,
                         uint8_t text[],
                         size_t* size_text) = 0;
  virtual int SM2Encrypt(const uint8_t X[32],
                         const uint8_t Y[32],
                         const uint8_t text[],
                         size_t size_text,
                         uint8_t cipher[]) = 0;

 public:  // HASH ...
  virtual int SHA1(const void* input, size_t size, uint8_t md[20]) = 0;
  virtual int SM3(const void* input, size_t size, uint8_t md[32]) = 0;

 public:  // TDES ...
  virtual int TDESECB(int id, uint8_t* buffer, size_t size, bool encrypt) = 0;
  virtual int TDESECB(const uint8_t key[16], int id, uint8_t* buffer, size_t size, bool encrypt) = 0;

 public:  // SM4 ...
  virtual int SM4ECB(int id, uint8_t* buffer, size_t size, bool encrypt) = 0;
  virtual int SM4ECB(const uint8_t key[16], int id, uint8_t* buffer, size_t size, bool encrypt) = 0;

 public:  // PRIVATE SEED ...
  virtual int SEED(const void* input, size_t size, uint8_t result[16]) = 0;

 public:
  Dongle() = default;
  virtual ~Dongle() = default;

  Dongle(const Dongle&) = delete;
  Dongle& operator=(const Dongle&) = delete;
};

class RockeyARM : public Dongle {
 public:
  rLANG_DECLARE_PRIVATE_CONTEXT(MemoryHolder, 2 * sizeof(size_t));
  static int RockeyDongle(MemoryHolder* memory, Dongle** dongle);
  template <typename T>
  static void GetDongleInfo(DONGLE_INFO* info, const T& dongle) {
    rLANG_ABIREQUIRE(sizeof(info->birthday_) == sizeof(dongle.m_BirthDay));
    rLANG_ABIREQUIRE(8 == sizeof(dongle.m_HID) && 12 == sizeof(info->hid_));

    info->ver_ = dongle.m_Ver;
    info->type_ = dongle.m_Type;

    memcpy(info->birthday_, dongle.m_BirthDay, sizeof(dongle.m_BirthDay));
    info->agentId_ = dongle.m_Agent;
    info->pid_ = dongle.m_PID;
    info->uid_ = dongle.m_UserID;

    info->hid_[0] = info->hid_[1] = info->hid_[2] = 0;  // 0.0.0 => RockeyARM ...
    info->hid_[3] = dongle.m_IsMother ? 1 : 0;
    memcpy(&info->hid_[4], dongle.m_HID, sizeof(dongle.m_HID)); 
  }

 public:
  static int EnumDongle(DONGLE_INFO* info, size_t size, uint32_t* error = nullptr);
  int CheckError(uint32_t error);

 public:
  virtual int Open(int index);
  virtual int Close();

 public:
  virtual int Reset();

 public:
  virtual int VerifyPIN(PIN_STATE type, const char* pin, int* remain);
  virtual int ChangePIN(PIN_STATE type, const char* old, const char* pin, int count);
  virtual int ResetUserPIN(const char* admin);

 public:
  virtual int SetUserID(uint32_t id);
  virtual int GetDeadline(uint32_t* time);
  virtual int SetDeadline(uint32_t time);
  virtual int GetUTCTime(uint32_t* time);

 public:
  virtual int SwitchProtocol(bool ccid);
  virtual int UpdateApplication(const void* app, size_t size);
  virtual int ExecuteApplication(void* buffer, size_t size_buffer, int* result);
  virtual int LimitSeedCount(int count);

 public:
  uint32_t GetLastError(void) override { return last_error_; }

 public:
  int RandBytes(uint8_t* buffer, size_t size) override;
  int GetRealTime(DWORD* time) override;
  int GetExpireTime(DWORD* time) override;
  int GetTickCount(DWORD* ticks) override;

 public:
  int GetDongleInfo(DONGLE_INFO* info) override;
  int GetPINState(PIN_STATE* state) override;
  int SetLEDState(LED_STATE state) override;


 public:
  int ReadShareMemory(uint8_t buffer[32]) override;
  int WriteShareMemory(const uint8_t buffer[32]) override;

 public:
  int DeleteFile(SECRET_STORAGE_TYPE type, int id) override;

  /* SECRET_STORAGE_TYPE::kData */
  int CreateDataFile(int id, size_t size, PERMISSION read, PERMISSION write) override;
  int WriteDataFile(int id, size_t offset, const void* buffer, size_t size) override;
  int ReadDataFile(int id, size_t offset, void* buffer, size_t size) override;

 public:  // PKEY STORAGE ...
  /* SECRET_STORAGE_TYPE::kRSA || SECRET_STORAGE_TYPE::kP256 || SECRET_STORAGE_TYPE::kSM2 */
  int CreatePKEYFile(SECRET_STORAGE_TYPE type, int bits, int id, const PKEY_LICENCE licence = {}) override;

  /* SECRET_STORAGE_TYPE::kRSA */
  int GenerateRSA(int id, uint32_t* modulus, uint8_t public_[], uint8_t* private_ = nullptr) override;
  int ImportRSA(int id, int bits, uint32_t modules, const uint8_t public_[], const uint8_t private_[]) override;

  /* SECRET_STORAGE_TYPE::kP256 */
  int GenerateP256(int id, uint8_t X[32], uint8_t Y[32], uint8_t* private_ = nullptr) override;
  int ImportP256(int id, const uint8_t X[32], const uint8_t Y[32], const uint8_t K[32]) override;

  /* SECRET_STORAGE_TYPE::kSM2  */
  int GenerateSM2(int id, uint8_t X[32], uint8_t Y[32], uint8_t* private_ = nullptr) override;
  int ImportSM2(int id, const uint8_t X[32], const uint8_t Y[32], const uint8_t K[32]) override;

 public:  // SessionKey ...
  /* SECRET_STORAGE_TYPE::kSM4 || SECRET_STORAGE_TYPE::kTDES */
  int CreateKeyFile(int id, PERMISSION permission, SECRET_STORAGE_TYPE type) override;
  int WriteKeyFile(int id, const void* buffer, size_t size, SECRET_STORAGE_TYPE type) override;

 public:  // RSA ...
  int RSAPrivate(int id, const uint8_t* in, size_t size_in, uint8_t out[], size_t* size_out, bool encrypt) override;
  int RSAPrivate(int bits,
                 uint32_t modules,
                 const uint8_t public_[],
                 const uint8_t private_[],
                 const uint8_t* in,
                 size_t size_in,
                 uint8_t out[],
                 size_t* size_out,
                 bool encrypt) override;
  int RSAPublic(int bits,
                uint32_t modules,
                const uint8_t public_[],
                const uint8_t* in,
                size_t size_in,
                uint8_t out[],
                size_t* size_out,
                bool encrypt) override;

 public:  // P256 ECDSA ...
  int P256Sign(int id, const uint8_t hash[32], uint8_t R[32], uint8_t S[32]) override;
  int P256Sign(const uint8_t private_[32], const uint8_t hash[32], uint8_t R[32], uint8_t S[32]) override;
  int P256Verify(const uint8_t X[32],
                 const uint8_t Y[32],
                 const uint8_t hash[32],
                 const uint8_t R[32],
                 const uint8_t S[32]) override;

 public:  // SM2 ECDSA ...
  int SM2Sign(int id, const uint8_t hash[32], uint8_t R[32], uint8_t S[32]) override;
  int SM2Sign(const uint8_t private_[32], const uint8_t hash[32], uint8_t R[32], uint8_t S[32]) override;
  int SM2Verify(const uint8_t X[32],
                const uint8_t Y[32],
                const uint8_t hash[32],
                const uint8_t R[32],
                const uint8_t S[32]) override;

 public:  // SM2 ECIES ...
  int SM2Decrypt(int id, const uint8_t cipher[], size_t size_cipher, uint8_t text[], size_t* size_text) override;
  int SM2Decrypt(const uint8_t private_[32],
                         const uint8_t cipher[],
                         size_t size_cipher,
                         uint8_t text[],
                         size_t* size_text) override;
  int SM2Encrypt(const uint8_t X[32],
                         const uint8_t Y[32],
                         const uint8_t text[],
                         size_t size_text,
                         uint8_t cipher[]) override;

 public:  // HASH ...
  int SHA1(const void* input, size_t size, uint8_t md[20]) override;
  int SM3(const void* input, size_t size, uint8_t md[32]) override;

 public:  // TDES ...
  int TDESECB(int id, uint8_t* buffer, size_t size, bool encrypt) override;
  int TDESECB(const uint8_t key[16], int id, uint8_t* buffer, size_t size, bool encrypt) override;

 public:  // SM4 ...
  int SM4ECB(int id, uint8_t* buffer, size_t size, bool encrypt) override;
  int SM4ECB(const uint8_t key[16], int id, uint8_t* buffer, size_t size, bool encrypt) override;

 public:  // PRIVATE SEED ...
  int SEED(const void* input, size_t size, uint8_t result[16]) override;

 public:
  rLANG_DECLARE_HANDLE(Handle);
  RockeyARM(Handle handle) : handle_(handle) {}
  ~RockeyARM() override;

 protected:
  uint32_t last_error_ = 0;
  Handle handle_;
};
#endif /* */



} // namespace dongle

rLANG_DECLARE_END


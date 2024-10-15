#include <base/base.h>
#include <memory>
#include <tuple>

#ifndef X_BUILD_native
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/sm2.h>
#include <openssl/sm3.h>
#include <openssl/sm4.h>
#include <openssl/des.h>
#endif /* X_BUILD_native */

#ifdef _WIN32
#include <windows.h>
#include <malloc.h>
#else /* _WIN32 */
#include <alloca.h>
#endif /* _WIN32 */

rLANG_DECLARE_MACHINE

#ifndef SHA512_DIGEST_LENGTH
#define SHA512_DIGEST_LENGTH  64
#endif /* SHA512_DIGEST_LENGTH */

namespace dongle {

enum class PERMISSION : uint8_t { kAnonymous, kNormal, kAdminstrator };

enum class LED_STATE : uint8_t { kOff, kOn, kBlink };
enum class SECRET_STORAGE_TYPE : uint8_t { kData, kRSA, kP256, kSM2, kSM4, kTDES };

template <typename T>
class HashBase {
 public:
  T& Clear() {
    memset(&ctx_, 0, sizeof(ctx_));
    return *static_cast<T*>(this);
  }

 protected:
  rlCryptoShaCtx ctx_;
};

class Sha256Ctx : public HashBase<Sha256Ctx> {
 public:
  Sha256Ctx& Init();
  Sha256Ctx& Update(const void* input, size_t size);
  Sha256Ctx& Final(uint8_t md[32]);
};

class Sha384Ctx : public HashBase<Sha384Ctx> {
 public:
  Sha384Ctx& Init();
  Sha384Ctx& Update(const void* input, size_t size);
  Sha384Ctx& Final(uint8_t md[48]);
};

class Sha512Ctx : public HashBase<Sha512Ctx> {
 public:
  Sha512Ctx& Init();
  Sha512Ctx& Update(const void* input, size_t size);
  Sha512Ctx& Final(uint8_t md[64]);
};

class Curve25519 {
 public:
  void ComputePubkey(uint8_t pubkey[32], const uint8_t prikey[32]) {
    memset(pubkey, 0, 32);
    pubkey[0] = 9;
    X25519(pubkey, prikey, pubkey);
  }
  void X25519(uint8_t secret[32], const uint8_t prikey[32], const uint8_t pubkey[32]);
};

class Ed25519 {
 public: /* The Ed25519 requires too much stack space */
  void ComputePubkey(void* vExtBuffer, uint8_t pubkey[32], const uint8_t prikey[32]);
  void Sign(void* vExtBuffer, /* Stack Overflow, [X]InOutBuffer ... */
            uint8_t out_sig[64],
            const void* message,
            int message_len,
            const uint8_t public_key[32],
            const uint8_t private_key[32]);
  int Verify(void* vExtBuffer,/* Stack Overflow, [X]InOutBuffer ... */
             const void* message,
             int message_len,
             const uint8_t signature[64],
             const uint8_t public_key[32]);
};

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

#ifdef X_BUILD_native
#define virtual /* nothing */ /* Welcome to the Real World! */
#define override /* nothing */
#endif /* X_BUILD_native */

/**
 *!
 */
rLANGEXPORT int rLANGAPI SM2Cipher_TextToASN1(const uint8_t* text_cipher, size_t cipher_len, uint8_t* buffer);
rLANGEXPORT int rLANGAPI SM2Cipher_ASN1ToText(const uint8_t* asn1_cipher, size_t cipher_len, uint8_t* buffer);

class Dongle {
 public:
#ifndef _WIN32
  using DWORD = unsigned int;
#else  /* _WIN32 */
  using DWORD = ::DWORD;
#endif /* _WIN32 */

  static constexpr int kFactoryDataFileId = 0xFFFF;

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
  template <typename T>
  static void GetRockeyDongleInfo(DONGLE_INFO* info, const T& dongle) {
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
  Dongle() = default;
  virtual ~Dongle() = default;

  Dongle(const Dongle&) = delete;
  Dongle& operator=(const Dongle&) = delete;

 public:
  DWORD GetLastError(bool reset = true) const {
    DWORD result = last_error_;
    if (reset)
      last_error_ = 0;
    return result;
  }
  void ClearLastError() { last_error_ = 0; }

 public:
  virtual int RandBytes(uint8_t* buffer, size_t size);
  virtual int SeedSecret(const void* input, size_t size, void* value /* size_is(16) */);

public:
  virtual int GetRealTime(DWORD* time);
  virtual int GetExpireTime(DWORD* time);
  virtual int GetTickCount(DWORD* ticks);

 public:
  virtual int GetDongleInfo(DONGLE_INFO* info);
  virtual int GetPINState(PERMISSION* state);
  virtual int SetLEDState(LED_STATE state);

 public:
  virtual int ReadShareMemory(uint8_t buffer[32]);
  virtual int WriteShareMemory(const uint8_t buffer[32]);

 public:
  virtual int DeleteFile(SECRET_STORAGE_TYPE type, int id);

 public: // DATA FILE ...
  /* SECRET_STORAGE_TYPE::kData */
  virtual int CreateDataFile(int id, size_t size, PERMISSION read, PERMISSION write);
  virtual int WriteDataFile(int id, size_t offset, const void* buffer, size_t size);
  virtual int ReadDataFile(int id, size_t offset, void* buffer, size_t size);

 public:  // PKEY STORAGE ...
  /* SECRET_STORAGE_TYPE::kRSA || SECRET_STORAGE_TYPE::kP256 || SECRET_STORAGE_TYPE::kSM2 */
  virtual int CreatePKEYFile(SECRET_STORAGE_TYPE type, int bits, int id, const PKEY_LICENCE& licence = {});

  /* SECRET_STORAGE_TYPE::kRSA */
  virtual int GenerateRSA(int id, uint32_t* modulus, uint8_t public_[], uint8_t* private_ = nullptr);
  virtual int ImportRSA(int id, int bits, uint32_t modules, const uint8_t public_[], const uint8_t private_[]);

  /* SECRET_STORAGE_TYPE::kP256 */
  virtual int GenerateP256(int id, uint8_t X[32], uint8_t Y[32], uint8_t* private_ = nullptr);
  virtual int ImportP256(int id, const uint8_t K[32]);

  /* SECRET_STORAGE_TYPE::kSM2  */
  virtual int GenerateSM2(int id, uint8_t X[32], uint8_t Y[32], uint8_t* private_ = nullptr);
  virtual int ImportSM2(int id, const uint8_t K[32]);

 public:  // SessionKey ...
  /* SECRET_STORAGE_TYPE::kSM4 || SECRET_STORAGE_TYPE::kTDES */
  virtual int CreateKeyFile(int id, PERMISSION permission, SECRET_STORAGE_TYPE type);
  virtual int WriteKeyFile(int id, const void* buffer, size_t size, SECRET_STORAGE_TYPE type);

 public:
  virtual int RSAPrivate(int id,
                         uint8_t buffer[] /* length_is(*size_buffer), max_size(bits/8) */,
                         size_t* size_buffer,
                         bool encrypt);
  virtual int RSAPrivate(int bits,
                         uint32_t modules,
                         const uint8_t public_[],
                         const uint8_t private_[],
                         uint8_t buffer[] /* length_is(*size_buffer), max_size(bits/8) */,
                         size_t* size_buffer,
                         bool encrypt);
  virtual int RSAPublic(int bits,
                        uint32_t modules,
                        const uint8_t public_[],
                        uint8_t buffer[] /* length_is(*size_buffer), max_size(bits/8) */,
                        size_t* size_buffer,
                        bool encrypt);

 public:  // P256 ECDSA ...
  virtual int P256Sign(int id, const uint8_t hash[32], uint8_t R[32], uint8_t S[32]);
  virtual int P256Sign(const uint8_t private_[32], const uint8_t hash[32], uint8_t R[32], uint8_t S[32]);
  virtual int P256Verify(const uint8_t X[32],
                         const uint8_t Y[32],
                         const uint8_t hash[32],
                         const uint8_t R[32],
                         const uint8_t S[32]);

 public: // SM2 ECDSA ...
  virtual int SM2Sign(int id, const uint8_t hash[32], uint8_t R[32], uint8_t S[32]);
  virtual int SM2Sign(const uint8_t private_[32], const uint8_t hash[32], uint8_t R[32], uint8_t S[32]);
  virtual int SM2Verify(const uint8_t X[32],
                        const uint8_t Y[32],
                        const uint8_t hash[32],
                        const uint8_t R[32],
                        const uint8_t S[32]);

 public:  // SM2 ECIES ...
  virtual int SM2Decrypt(int id, const uint8_t cipher[], size_t size_cipher, uint8_t text[], size_t* size_text);
  virtual int SM2Decrypt(const uint8_t private_[32],
                         const uint8_t cipher[],
                         size_t size_cipher,
                         uint8_t text[],
                         size_t* size_text);
  virtual int SM2Encrypt(const uint8_t X[32],
                         const uint8_t Y[32],
                         const uint8_t text[],
                         size_t size_text,
                         uint8_t cipher[]);

 public:  // HASH ...
  virtual int SHA1(const void* input, size_t size, uint8_t md[20]);
  virtual int SM3(const void* input, size_t size, uint8_t md[32]);

 public:  // TDES ...
  virtual int TDESECB(int id, uint8_t* buffer, size_t size, bool encrypt);
  virtual int TDESECB(const uint8_t key[16], uint8_t* buffer, size_t size, bool encrypt);

 public:  // SM4 ...
  virtual int SM4ECB(int id, uint8_t* buffer, size_t size, bool encrypt);
  virtual int SM4ECB(const uint8_t key[16], uint8_t* buffer, size_t size, bool encrypt);

 public:  // SHA256/SHA384/SHA512
  virtual int SHA256(const void* input, size_t size, uint8_t md[32]);
  virtual int SHA384(const void* input, size_t size, uint8_t md[48]);
  virtual int SHA512(const void* input, size_t size, uint8_t md[64]);

 public:
  virtual int CHACHAPOLY_Seal(const uint8_t key[32], const uint8_t nonce[12], void* buffer /* max_size(16 + *size) */, size_t* size);
  virtual int CHACHAPOLY_Open(const uint8_t key[32], const uint8_t nonce[12], void* buffer, size_t* size);

 public: /* ... uECC ... */
  /**
   *! ... SM2 ...
   */
  virtual int CheckPointOnCurveSM2(const uint8_t X[32], const uint8_t Y[32]);
  virtual int DecompressPointSM2(uint8_t Y[32], const uint8_t X[32], bool Yodd);

  /**
   *! ... P256 ...
   */
  virtual int CheckPointOnCurvePrime256v1(const uint8_t X[32], const uint8_t Y[32]);
  virtual int DecompressPointPrime256v1(uint8_t Y[32], const uint8_t X[32], bool Yodd);
  virtual int ComputePubkeyPrime256v1(uint8_t X[32], uint8_t Y[32], const uint8_t K[32]);
  virtual int GenerateKeyPairPrime256v1(uint8_t X[32], uint8_t Y[32], uint8_t K[32]);
  virtual int ComputeSecretPrime256v1(uint8_t secret[32],
                                      const uint8_t X[32],
                                      const uint8_t Y[32],
                                      const uint8_t K[32]);
  virtual int SignMessagePrime256v1(const uint8_t K[32], const uint8_t H[32], uint8_t R[32], uint8_t S[32]);
  virtual int VerifySignPrime256v1(const uint8_t X[32],
                                   const uint8_t Y[32],
                                   const uint8_t H[32],
                                   const uint8_t R[32],
                                   const uint8_t S[32]);

  /**
   *! ... Secp256k1 ...
   */
  virtual int CheckPointOnCurveSecp256k1(const uint8_t X[32], const uint8_t Y[32]);
  virtual int DecompressPointSecp256k1(uint8_t Y[32], const uint8_t X[32], bool Yodd);
  virtual int ComputePubkeySecp256k1(uint8_t X[32], uint8_t Y[32], const uint8_t K[32]);
  virtual int GenerateKeyPairSecp256k1(uint8_t X[32], uint8_t Y[32], uint8_t K[32]);
  virtual int ComputeSecretSecp256k1(uint8_t secret[32], const uint8_t X[32], const uint8_t Y[32], const uint8_t K[32]);
  virtual int SignMessageSecp256k1(const uint8_t K[32], const uint8_t H[32], uint8_t R[32], uint8_t S[32]);
  virtual int VerifySignSecp256k1(const uint8_t X[32],
                                  const uint8_t Y[32],
                                  const uint8_t H[32],
                                  const uint8_t R[32],
                                  const uint8_t S[32]);

 public: /* ... Curve25519 ... */
  virtual int GenerateKeyPairCurve25519(uint8_t pubkey[32], uint8_t prikey[32]);
  virtual int ComputePubkeyCurve25519(uint8_t pubkey[32], const uint8_t prikey[32]);
  virtual int ComputeSecretCurve25519(uint8_t secret[32], const uint8_t prikey[32], const uint8_t pubkey[32]);

 public: /* ... Ed25519 ... */
  virtual int GenerateKeyPairEd25519(void* vExtBuffer, uint8_t pubkey[32], uint8_t prikey[32]);
  virtual int ComputePubkeyEd25519(void* vExtBuffer, uint8_t pubkey[32], const uint8_t prikey[32]);
  virtual int SignMessageEd25519(void* vExtBuffer, /* Stack Overflow, [X]InOutBuffer ... */
                                 uint8_t out_sig[64],
                                 const void* message,
                                 int message_len,
                                 const uint8_t public_key[32],
                                 const uint8_t private_key[32]);
  virtual int VerifySignEd25519(void* vExtBuffer, /* Stack Overflow, [X]InOutBuffer ... */
                                const void* message,
                                int message_len,
                                const uint8_t signature[64],
                                const uint8_t public_key[32]);

 public:
#ifndef __RockeyARM__
  virtual bool Ready() const { return handle_ != nullptr; }
#else  /* __RockeyARM__ */
  virtual bool Ready() const { return true; }
#endif /* __RockeyARM__ */

 protected:
#ifndef __RockeyARM__
  ROCKEY_HANDLE handle_{nullptr};
#ifndef __EMULATOR__
  DONGLE_INFO dongle_info_{0};
#endif /* __EMULATOR__  */
#endif /* __RockeyARM__ */

  mutable DWORD last_error_ = 0;

 public:
  int CheckError(DWORD error);
  int CheckError(DWORD error, const char* expr) {
    int result = CheckError(error);
    if (result < 0)
      rlLOGE(rLANG_WORLD_MAGIC, "DONGLE.EXEC '%s' Error %08X", expr, error);
    return result;
  }

  static void Abort();
  static void Verify(bool result, const char* expr) {
    if (!result) {
      rlLOGE(rLANG_WORLD_MAGIC, "DONGLE.EXEC '%s' Fail, Abort", expr);
      Abort();
    }
  }

#ifndef DONGLE_VERIFY
#define DONGLE_VERIFY(expr) ::machine::dongle::Dongle::Verify((expr), #expr)
#endif /* DONGLE_VERIFY */

#ifndef DONGLE_CHECK
#define DONGLE_CHECK(expr) CheckError((expr), #expr)
#endif /* DONGLE_CHECK */
};

class RockeyARM : public Dongle {
 public:
  ~RockeyARM() override;

 public:
  virtual int Close();
  virtual int Open(int index);
  virtual int Enum(DONGLE_INFO info[64]);
  virtual int VerifyPIN(PERMISSION perm, const char* pin, int* remain);
  virtual int ResetState();

  virtual int UpdateExeFile(const void* file, size_t size);
  virtual int ExecuteExeFile(void* InOutBuf, size_t szBuf, int* ret);

  virtual int LimitSeedCount(int count);
  virtual int SetExpireTime(DWORD time);
  virtual int SetUserID(uint32_t id);

  virtual int ChangePIN(PERMISSION perm, const char* old, const char* pin, int count);
  virtual int ResetUserPIN(const char* admin);

 public:
  virtual int GenUniqueKey(const void* seed, size_t len, char pid[10], char admin[20]);
  virtual int FactoryReset();
};

class Emulator : public Dongle {
public:
  Emulator();
  virtual ~Emulator();

  virtual int Close();
  virtual int Create(const uint8_t master_secret[64], uint32_t uid = 0, int loop = 256);
  virtual int Open(const char* file, const uint8_t master_secret[64], int loop = 256);
  virtual int Write(const char* file);

public:
  int Create(const char* master_secret, uint32_t uid = 0, int loop = 256);
  int Open(const char* file, const char* master_secret, int loop = 256);
};



} // namespace dongle

rLANG_DECLARE_END


#include <Interface/dongle.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <map>

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

namespace dongle {

namespace {
constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("Foobar");

constexpr size_t kDongleFileSizeLimit = 64 * 1024;

/**! */
#if defined(__EMSCRIPTEN__) && defined(rLANG_WORLD_STANDALONE)

rLANGIMPORT int rLANGAPI LoadDongleFile(const char* file, uint8_t content[])
    __attribute__((__import_module__("rLANG"), __import_name__("LoadDongleFile")));
rLANGIMPORT int rLANGAPI WriteDongleFile(const char* file, const uint8_t content[], size_t size)
    __attribute__((__import_module__("rLANG"), __import_name__("WriteDongleFile")));

#else /* __EMSCRIPTEN__ && rLANG_WORLD_STANDALONE */

int LoadDongleFile(const char* file, uint8_t content[]) {
  FILE* fp = fopen(file, "rb");
  if (NULL == fp) {
    rlLOGE(TAG, "Can't open %s for read, error: %d", file, errno);
    return -ENOENT;
  }

  size_t size = fread(content, 1, kDongleFileSizeLimit + 16, fp);
  fclose(fp);

  if (size > kDongleFileSizeLimit)
    return -EFAULT;
  return static_cast<int>(size);
}

int WriteDongleFile(const char* file, const uint8_t content[], size_t size) {
  DONGLE_VERIFY(size <= kDongleFileSizeLimit);

  FILE* fp = fopen(file, "wb");
  if (NULL == fp) {
    rlLOGE(TAG, "Can't open %s for write, error: %d", file, errno);
    return -EFAULT;
  }

  size_t sz = fwrite(content, 1, size, fp);
  fclose(fp);

  if (sz != size)
    return -EFAULT;
  return static_cast<int>(size);
}

#endif /* */

class DongleHandle {
public:
  DongleHandle(const DongleHandle&) = delete;
  DongleHandle& operator=(const DongleHandle&) = delete;

  struct SupperBlock {
    struct {
      uint32_t world_magic_;
      uint32_t file_magic_;
      uint32_t reseved_;
      uint8_t world_nonce_[12];
      DONGLE_INFO dongle_info_;
      uint8_t master_ed25519_[32];
      uint8_t master_xx25519_[32];
    } public_;
    uint8_t master_prikey_encrypt_[64]; // Ed25519[32] + X25519[32]
    uint8_t sign_[64];
  };

public:
  static constexpr uint32_t rLANG_DONGLE_MAGIC = rLANG_DECLARE_MAGIC_Xs("DONGL");
  static DongleHandle* Create(const uint8_t master_[64], uint32_t uid, int loop) {
    DongleHandle* self = new DongleHandle;

    SupperBlock& sb = self->sb_;
    uint8_t secret[256], MASTER_PRIKEY[64], *MASTER_PKMASK = self->master_prikey_masked_;
    
    /* Loop.1 */
    memcpy(secret, master_, 64);
    ExtendMasterSecret(secret, loop);

    /* Init.0 */
    RAND_bytes(sb.public_.world_nonce_, sizeof(sb.public_.world_nonce_));
    Sha512Ctx().Init().Update(secret, 64).Final(secret).Clear();
    memcpy(&sb.public_.dongle_info_.pid_, &secret[42], 4);
    Sha512Ctx().Init().Update(sb.public_.world_nonce_, 12).Update(secret, 64).Final(secret).Clear();
    memcpy(&sb.public_.dongle_info_.hid_, secret, 12);
    sb.public_.dongle_info_.hid_[0] = 0xFF;

    sb.public_.world_magic_ = rLANG_WORLD_MAGIC;
    sb.public_.file_magic_ = rLANG_DONGLE_MAGIC;
    sb.public_.reseved_ = 0;

    struct rlTM_t tm;
    rLANG_GetTimeFromDate(&tm, rLANG_GetCurrentDate());

    sb.public_.dongle_info_.ver_ = 0x0101;
    sb.public_.dongle_info_.type_ = rLANG_DECLARE_MAGIC_Xs("EMULA");
    sb.public_.dongle_info_.birthday_[0] = tm.tm_year / 100;
    sb.public_.dongle_info_.birthday_[1] = tm.tm_year % 100;
    sb.public_.dongle_info_.birthday_[2] = tm.tm_month;
    sb.public_.dongle_info_.birthday_[3] = tm.tm_mday;
    sb.public_.dongle_info_.birthday_[4] = tm.tm_hour;
    sb.public_.dongle_info_.birthday_[5] = tm.tm_minute;
    sb.public_.dongle_info_.birthday_[6] = tm.tm_second;
    sb.public_.dongle_info_.birthday_[7] = 0;
    sb.public_.dongle_info_.agentId_ = 0xFFFFFFFF;
    sb.public_.dongle_info_.uid_ = uid;

    /* MASK */
    RAND_bytes((uint8_t*)&self->state_mask_[0], 64);
    rlCryptoChaCha20Block(self->state_mask_, MASTER_PKMASK);

    /* PKEY */
    RAND_bytes(sb.master_prikey_encrypt_, 64);
    memcpy(MASTER_PRIKEY, sb.master_prikey_encrypt_, 64);

    /* SECRET */
    ExtendMasterSecret(secret, loop);

    for (int i = 0; i < 64; ++i) {
      MASTER_PRIKEY[i] ^= secret[i];
      MASTER_PKMASK[i] ^= MASTER_PRIKEY[i];
    }
    rlCryptoEd25519Pubkey(sb.public_.master_ed25519_, &MASTER_PRIKEY[0]);
    rlCryptoX25519Pubkey(sb.public_.master_xx25519_, &MASTER_PRIKEY[32]);
    rlCryptoEd25519Sign(sb.sign_, &sb, sizeof(SupperBlock) - 64, sb.public_.master_ed25519_, &MASTER_PRIKEY[0]);
    DONGLE_VERIFY(Ed25519Verify(&sb, sizeof(SupperBlock), sb.public_.master_ed25519_));

    memset(MASTER_PRIKEY, 0, sizeof(MASTER_PRIKEY));

    uint32_t total = 0;
    memset(secret, 0, 64);
    self->EncryptBuffer(secret, 64);
    DONGLE_VERIFY(self->DecryptBuffer(secret, 64));
    for (int i = 0; i < 64; ++i)
      total += secret[i];
    DONGLE_VERIFY(0 == total);

    {
      DongleHandle* check = nullptr;
      DONGLE_VERIFY(0 == LoadSupperBlock(self->sb_, master_, loop, &check));
      delete check;
    }

    return self;
  }

  static int LoadSupperBlock(const SupperBlock& sb, const uint8_t master_[64], int loop, DongleHandle** outHandle) {
    DONGLE_VERIFY(nullptr == outHandle || nullptr == *outHandle);
    if(rLANG_WORLD_MAGIC != sb.public_.world_magic_ ||
      rLANG_DONGLE_MAGIC != sb.public_.file_magic_ ||
      0xFF != sb.public_.dongle_info_.hid_[0] ||
      !Ed25519Verify(&sb, sizeof(SupperBlock), sb.public_.master_ed25519_)) {
      return -EFAULT;
    }

    if (0 != sb.public_.reseved_)
      return -EFAULT;

    uint8_t secret[256];
    Dongle::SecretBuffer<16, uint32_t> state_mask_;
    Dongle::SecretBuffer<64> MASTER_PKMASK, MASTER_PRIKEY;    

    RAND_bytes((uint8_t*)&state_mask_[0], 64);
    rlCryptoChaCha20Block(state_mask_, MASTER_PKMASK);

    /* Loop.1 */
    memcpy(secret, master_, 64);
    ExtendMasterSecret(secret, loop);

    /* Init.0 */
    Sha512Ctx().Init().Update(secret, 64).Final(secret).Clear();
    if (0 != memcmp(&sb.public_.dongle_info_.pid_, &secret[42], 4))
      return -EACCES;
    Sha512Ctx().Init().Update(sb.public_.world_nonce_, 12).Update(secret, 64).Final(secret).Clear();
    if (0 != memcmp(&sb.public_.dongle_info_.hid_[1], &secret[1], 11))
      return -EACCES;

    /* SECRET */
    ExtendMasterSecret(secret, loop);
    memcpy(&MASTER_PRIKEY[0], sb.master_prikey_encrypt_, 64);

    for (int i = 0; i < 64; ++i) {
      MASTER_PRIKEY[i] ^= secret[i];
      MASTER_PKMASK[i] ^= MASTER_PRIKEY[i];
    }

    rlCryptoEd25519Pubkey(&secret[0], &MASTER_PRIKEY[0]);
    rlCryptoX25519Pubkey(&secret[32], &MASTER_PRIKEY[32]);
    if (0 != memcmp(&secret[0], sb.public_.master_ed25519_, 32) ||
        0 != memcmp(&secret[32], sb.public_.master_xx25519_, 32))
      return -EACCES;

    if (outHandle) {
      DongleHandle* self = *outHandle = new DongleHandle;
      self->sb_ = sb; /* */
      memcpy(&self->state_mask_[0], &state_mask_[0], 64);
      memcpy(&self->master_prikey_masked_, &MASTER_PKMASK[0], 64);

      uint32_t total = 0;
      memset(secret, 0, 64);
      self->EncryptBuffer(secret, 64);
      DONGLE_VERIFY(self->DecryptBuffer(secret, 64));
      for (int i = 0; i < 64; ++i)
        total += secret[i];
      DONGLE_VERIFY(0 == total);
    }
    return 0;
  }

public:
  static bool Ed25519Verify(const void* storage, size_t size, const uint8_t pubkey[32]) {
    DONGLE_VERIFY(size >= 64);

    size -= 64;
    const uint8_t* v = static_cast<const uint8_t*>(storage);
    return rlCryptoEd25519Verify(v, (int)size, &v[size], pubkey) == 0;
  }

  bool Ed25519Verify(const void* storage, size_t size) {
    return Ed25519Verify(storage, size, sb_.public_.master_ed25519_);
  }

  static void ExtendMasterSecret(uint8_t master_secret[64], int loop) {
    if (loop < 256)
      loop = 256;
    
    for (int i = 0; i < loop; ++i) {
      struct {
        uint8_t ed25519[32];
        uint8_t x25519[32];
        uint8_t stream[64];
      } v;

      uint32_t state[16];
      memcpy(state, master_secret, 64);
      rlCryptoChaCha20Block(state, v.stream);
      rlCryptoEd25519Pubkey(v.ed25519, &master_secret[0]);
      rlCryptoX25519Pubkey(v.x25519, &master_secret[32]);
      Sha512Ctx().Init().Update(&v, sizeof(v)).Final(master_secret);
    }
  }

public:
  bool DecryptBuffer(uint8_t buffer[], size_t size) { // buffer : data[size]|pubkey[32]|sign[64]
    if (!Ed25519Verify(buffer, size + 32 + 64))
      return false;

    Dongle::SecretBuffer<32> key;
    Dongle::SecretBuffer<1, rlCryptoChaCha20Ctx> ctx;

    {
      Dongle::SecretBuffer<64> stream;
      rlCryptoChaCha20Block(state_mask_, stream);
      for (int i = 0; i < 64; ++i)
        stream[i] ^= master_prikey_masked_[i];
      rlCryptoX25519(key, &stream[32], &buffer[size]);
      if (0 == ++state_mask_[12])
        ++state_mask_[13];
      rlCryptoChaCha20Block(state_mask_, master_prikey_masked_);
      for (int i = 0; i < 64; ++i)
        master_prikey_masked_[i] ^= stream[i];
    }

    rlCryptoChaCha20Init(ctx);
    rlCryptoChaCha20SetKey(ctx, key);
    rlCryptoChaCha20Starts(ctx, sb_.public_.world_nonce_, 0);
    rlCryptoChaCha20Update(ctx, buffer, buffer, size);
    return true;
  }

  void EncryptBuffer(uint8_t buffer[], size_t size) {  // buffer : data[size]|pubkey[32]|sign[64]
    {
      Dongle::SecretBuffer<32> key;
      Dongle::SecretBuffer<1, rlCryptoChaCha20Ctx> ctx;

      RAND_bytes(key, 32);
      rlCryptoX25519Pubkey(&buffer[size], key);
      rlCryptoX25519(key, key, sb_.public_.master_xx25519_);

      rlCryptoChaCha20Init(ctx);
      rlCryptoChaCha20SetKey(ctx, key);
      rlCryptoChaCha20Starts(ctx, sb_.public_.world_nonce_, 0);
      rlCryptoChaCha20Update(ctx, buffer, buffer, size);
    }

    {
      Dongle::SecretBuffer<64> stream;
      rlCryptoChaCha20Block(state_mask_, stream);
      for (int i = 0; i < 64; ++i)
        stream[i] ^= master_prikey_masked_[i];
      rlCryptoEd25519Sign(&buffer[size + 32], buffer, (int)size + 32, sb_.public_.master_ed25519_, &stream[0]);
      if (0 == ++state_mask_[12])
        ++state_mask_[13];
      rlCryptoChaCha20Block(state_mask_, master_prikey_masked_);
      for (int i = 0; i < 64; ++i)
        master_prikey_masked_[i] ^= stream[i];
    }
  }

protected:
  DongleHandle() = default;
  Dongle::SecretBuffer<16, uint32_t> state_mask_;
  Dongle::SecretBuffer<64> master_prikey_masked_;
  SupperBlock sb_;
};

rLANG_ABIREQUIRE(sizeof(DongleHandle::SupperBlock) == 256);

}  // namespace

rLANGEXPORT int rLANGAPI SM2Cipher_TextToASN1(const uint8_t* text_cipher, size_t cipher_len, uint8_t* buffer) {
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
rLANGEXPORT int rLANGAPI SM2Cipher_ASN1ToText(const uint8_t* asn1_cipher, size_t cipher_len, uint8_t* buffer) {
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

Emulator::Emulator() = default;
Emulator::~Emulator() {
  Close();
}

int Emulator::Close() {
  return 0;
}

int Emulator::Create(const uint8_t master_secret[64], uint32_t uid, int loop) {
  DongleHandle* handle = DongleHandle::Create(master_secret, uid, loop);

  for(int i = 0; i < 10; ++i) {
    uint8_t input[1024 + 100], verify[1024];
    int len = rand() % 1000 + 10;
    
    RAND_bytes(verify, len);
    memcpy(input, verify, len);

    handle->EncryptBuffer(input, len);
    DONGLE_VERIFY(handle->DecryptBuffer(input, len));

    DONGLE_VERIFY(0 == memcmp(input, verify, len));  
  }

  handle_ = reinterpret_cast<ROCKEY_HANDLE>(handle);
  return 0;
}

int Emulator::Open(const char* file, const uint8_t master_secret[64], int loop) {
  SecretBuffer<kDongleFileSizeLimit + 256> content;
  int size = LoadDongleFile(file, content);

  if (size < 0) {
    rlLOGE(TAG, "LoadDongleFile %s, Error %d", file, size);
    return size;
  }





  return -ENOSYS;
}

int Emulator::Write(const char* file) {
  if (!handle_)
    return -EBADF;





  return -ENOSYS;
}

int Emulator::Create(const char* master_secret, uint32_t uid, int loop) {
  SecretBuffer<64> buffer;
  Sha512Ctx().Init().Update(master_secret, strlen(master_secret)).Final(buffer).Clear();
  return Create(&buffer[0], uid, loop);
}

int Emulator::Open(const char* file, const char* master_secret, int loop) {
  SecretBuffer<64> buffer;
  Sha512Ctx().Init().Update(master_secret, strlen(master_secret)).Final(buffer).Clear();
  return Open(file, &buffer[0], loop);
}

} // namespace dongle

rLANG_DECLARE_END

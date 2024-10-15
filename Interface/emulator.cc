#include <Interface/dongle.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <vector>
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
rLANGIMPORT int rLANGAPI SetDongleLEDState(void* thiz, LED_STATE state)
    __attribute__((__import_module__("rLANG"), __import_name__("SetDongleLEDState")));
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
rLANGIMPORT int rLANGAPI SetDongleLEDState(void* thiz, LED_STATE state) {
  rlLOGE(TAG, "TODO: Implements SetDongleLEDState %p/%d", thiz, state);
  return 0;
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

  int GetDongleInfo(DONGLE_INFO* info) {
    *info = sb_.public_.dongle_info_;
    return 0;
  }

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
  size_t Write(uint8_t* buffer) {
    uint8_t* p = buffer;

    memcpy(p, &sb_, sizeof(sb_));
    p += sizeof(sb_);

    memcpy(p, factory_datafile_, sizeof(factory_datafile_));
    p += sizeof(factory_datafile_);

    for (const auto& file : secret_files_) {
      const auto& header = file.first;
      memcpy(p, &header, sizeof(header));
      p += sizeof(header);

      if (!header.empty_file_) {
        const auto& content = file.second;
        size_t size = FileContentSize(header.size_);
        memcpy(p, &content[0], size);
        p += size;
      }
    }

    Sha256Ctx().Init().Update(buffer, p - buffer).Final(p);
    EncryptBuffer(p, 32);
    p += 128;

    return p - buffer;
  }

  static int Load(const uint8_t* p, size_t size, const uint8_t master_[64], int loop, DongleHandle** outHandle) {
    DONGLE_VERIFY(outHandle && !*outHandle);
    SupperBlock sb;
    if (size < sizeof(sb) + kFactoryFileSize + 128)
      return -EFAULT;

    uint8_t sha256[32];
    Sha256Ctx().Init().Update(p, size - 128).Final(sha256);

    memcpy(&sb, p, sizeof(sb));
    size -= sizeof(sb);
    p += sizeof(sb);

    DongleHandle* thiz = nullptr;
    int r = LoadSupperBlock(sb, master_, loop, &thiz);
    if (r < 0)
      return r;

    memcpy(thiz->factory_datafile_, p, kFactoryFileSize);
    size -= kFactoryFileSize;
    p += kFactoryFileSize;

    size -= 128;
    uint8_t verify[128];
    memcpy(verify, p + size, 128);
    if (!thiz->DecryptBuffer(verify, 32) || 0 != memcmp(sha256, verify, 32)) {
      r = -EFAULT;
    }

    while(size > 0 && r >= 0) {
      FileHeader header;

      if (size < sizeof(header)) {
        r = -EFAULT;
        break;
      }

      memcpy(&header, p, sizeof(header));
      size -= sizeof(header);
      p += sizeof(header);

      if (header.type_ > SECRET_STORAGE_TYPE::kTDES || header.index_ <= 0 || header.index_ >= 0xFFFF ||
          header.size_ <= 0 || header.size_ >= 0xFFF0) {
        r = -EFAULT;
        break;
      }

      if(thiz->secret_files_.find(header) != thiz->secret_files_.end()) {
        r = -EFAULT;
        break;
      }

      thiz->current_file_size_ += FileStorageSize(header.size_);
      if (thiz->current_file_size_ > kDongleFileSizeLimit) {
        r = -EFAULT;
        break;
      }

      if (!header.empty_file_) {
        size_t file_size = FileContentSize(header.size_);
        if (size < file_size) {
          r = -EFAULT;
          break;
        }
        if (!thiz->Ed25519Verify(p, file_size)) {
          r = -EFAULT;
          break;
        }

        thiz->secret_files_.insert(std::make_pair(header, std::vector<uint8_t>{p, p + file_size}));
        size -= file_size;
        p += file_size;
      } else {
        thiz->secret_files_.insert(std::make_pair(header, std::vector<uint8_t>{}));
      }
    }

    if (r < 0) {
      delete thiz;
    } else {
      *outHandle = thiz;
    }
    return r;
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
  bool DecryptBuffer(uint8_t buffer[], size_t size) {  // buffer : data[size]|pubkey[32]|sign[64]
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

 public:
  struct FileHeader {
    SECRET_STORAGE_TYPE type_;
    mutable uint8_t empty_file_;
    uint16_t index_;
    uint32_t size_;
  };

  struct RSA2048File {
    uint32_t modulus_;
    uint8_t public_[256];
    uint8_t private_[256];
  };

  friend bool operator<(const FileHeader& lhs, const FileHeader& rhs) {
    if (lhs.type_ != rhs.type_)
      return lhs.type_ < rhs.type_;
    return lhs.index_ < rhs.index_;
  }

  static constexpr size_t FileStorageSize(size_t size) {
    return size + 128;  /* Header[8] + ACL[...] + X25519.pubkey[32] + Ed25519.Sign[64] */
  }
  static constexpr size_t FileContentSize(size_t size) {
    return size + 96;   /* X25519.pubkey[32] + Ed25519.Sign[64] */
  }

  int CreateSecretFile(SECRET_STORAGE_TYPE type, uint16_t index, size_t size) {
    if (size >= 0xFF00)
      return -E2BIG;

    FileHeader header{ type, 1, index, (uint32_t)size };
    if (secret_files_.find(header) != secret_files_.end())
      return -EEXIST;

    if (kDongleFileSizeLimit - current_file_size_ < FileStorageSize(size))
      return -ENOSPC;

    secret_files_.insert(std::make_pair(header, std::vector<uint8_t>{}));
    current_file_size_ += FileStorageSize(size);

    return 0;
  }

  int RemoveSecretFile(SECRET_STORAGE_TYPE type, uint16_t index) {
    auto iter = secret_files_.find(FileHeader{type, 1, index});
    if (iter == secret_files_.end())
      return -ENOENT;

    auto& header = iter->first;
    size_t size = header.size_;
    current_file_size_ -= FileStorageSize(size);
    secret_files_.erase(iter);
    return 0;
  }

  template<typename CALLBACK_FUNCTION_>
  int OpWriteSecretFile(SECRET_STORAGE_TYPE type, uint16_t index, CALLBACK_FUNCTION_ callback) {
    auto iter = secret_files_.find(FileHeader{type, 1, index});
    if (iter == secret_files_.end())
      return -ENOENT;

    auto& header = iter->first;
    size_t size = header.size_;
    int result = 0;
    
    if (header.empty_file_) {
      header.empty_file_ = 0;
      DONGLE_VERIFY(iter->second.empty());
      iter->second.resize(FileContentSize(size));
      result = callback(&iter->second[0], size);
    } else {
      DONGLE_VERIFY(iter->second.size() == FileContentSize(size));
      if (!DecryptBuffer(&iter->second[0], size))
        return -EFAULT;
      result = callback(&iter->second[0], size);
    }

    EncryptBuffer(&iter->second[0], size);
    return result;
  }

  template <typename CALLBACK_FUNCTION_>
  int OpReadSecretFile(SECRET_STORAGE_TYPE type, uint16_t index, CALLBACK_FUNCTION_ callback) {
    auto iter = secret_files_.find(FileHeader{type, 1, index});
    if (iter == secret_files_.end())
      return -ENOENT;

    auto& header = iter->first;
    size_t size = header.size_;

    std::vector<uint8_t> buffer(FileContentSize(size));

    if (!header.empty_file_) {
      memcpy(&buffer[0], &iter->second[0], FileContentSize(size));
      if (!DecryptBuffer(&buffer[0], size))
        return -EFAULT;
    }

    int result = callback(&buffer[0], size);
    memset(&buffer[0], 0, buffer.size());
    return result;
  }

 public:
  static constexpr size_t kFactoryFileSize = 8192;
  static constexpr size_t kSharedMemorySize = 32;
  uint8_t shared_memory_[kSharedMemorySize] = {0};
  uint8_t factory_datafile_[kFactoryFileSize] = {0};

 protected:
  DongleHandle() = default;
  Dongle::SecretBuffer<16, uint32_t> state_mask_;
  Dongle::SecretBuffer<64> master_prikey_masked_;
  SupperBlock sb_;

  size_t current_file_size_ = sizeof(SupperBlock) + kFactoryFileSize + 128 /* sha256[32] + pubkey[32] + sign[64] */;

  std::map<FileHeader, std::vector<uint8_t>> secret_files_;
};

rLANG_ABIREQUIRE(sizeof(DongleHandle::FileHeader) == 8);
rLANG_ABIREQUIRE(sizeof(DongleHandle::SupperBlock) == 256);

}  // namespace

rLANGEXPORT int rLANGAPI SM2Cipher_TextToASN1(const uint8_t* text_cipher, size_t cipher_len, uint8_t* buffer) {
  DONGLE_VERIFY(cipher_len > 96 && cipher_len <= 1024);

  rLANG_SM2_Ciphertext_st* ciphertext = rLANG_SM2_Ciphertext_new();
  BN_bin2bn(&text_cipher[0], 32, ciphertext->C1x);
  BN_bin2bn(&text_cipher[32], 32, ciphertext->C1y);

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
  DongleHandle* thiz = reinterpret_cast<DongleHandle*>(handle_);
  return thiz->GetDongleInfo(info);
}

int Dongle::GetPINState(PERMISSION* state) {
  return DONGLE_CHECK(-ENOSYS);
}

int Dongle::SetLEDState(LED_STATE state) {
  return DONGLE_CHECK(SetDongleLEDState(this, state));
}

int Dongle::ReadShareMemory(uint8_t buffer[32]) {
  if (!handle_)
    return DONGLE_CHECK(-EBADF);
  DongleHandle* thiz = reinterpret_cast<DongleHandle*>(handle_);
  memcpy(buffer, thiz->shared_memory_, 32);
  return 0;
}
int Dongle::WriteShareMemory(const uint8_t buffer[32]) {
  if (!handle_)
    return DONGLE_CHECK(-EBADF);
  DongleHandle* thiz = reinterpret_cast<DongleHandle*>(handle_);
  memcpy(thiz->shared_memory_, buffer, 32);
  return 0;
}

int Dongle::DeleteFile(SECRET_STORAGE_TYPE type_, int id) {
  if (id <= 0 || id >= 0xFFFF)
    return DONGLE_CHECK(-EINVAL);
  if (!handle_)
    return DONGLE_CHECK(-EBADF);
  DongleHandle* thiz = reinterpret_cast<DongleHandle*>(handle_);
  return DONGLE_CHECK(thiz->RemoveSecretFile(type_, id));
}

int Dongle::CreateDataFile(int id, size_t size, PERMISSION read, PERMISSION write) {
  if (id <= 0 || id >= 0xFFFF || size <= 0 || size > 0xFF00)
    return DONGLE_CHECK(-EINVAL);

  if (!handle_)
    return DONGLE_CHECK(-EBADF);

  DongleHandle* thiz = reinterpret_cast<DongleHandle*>(handle_);
  return DONGLE_CHECK(thiz->CreateSecretFile(SECRET_STORAGE_TYPE::kData, id, size));
}

int Dongle::WriteDataFile(int id, size_t offset, const void* buffer, size_t size) {
  if (0 == size)
    return 0;

  if (id <= 0 || id > 0xFFFF ||  offset >= 0xFFF0 || size >= 0xFFF0)
    return DONGLE_CHECK(-EINVAL);

  if (!handle_)
    return DONGLE_CHECK(-EBADF);

  DongleHandle* thiz = reinterpret_cast<DongleHandle*>(handle_);
  auto callback = [offset, buffer, size](void* content, size_t size_content) {
    if (offset >= size_content)
      return -ERANGE;
    if (size_content - offset < size)
      return -ERANGE;
    memcpy((uint8_t*)content + offset, buffer, size);
    return 0;
  };

  if (id == 0xFFFF)
    return DONGLE_CHECK(callback(thiz->factory_datafile_, DongleHandle::kFactoryFileSize));
  return DONGLE_CHECK(thiz->OpWriteSecretFile(SECRET_STORAGE_TYPE::kData, id, std::move(callback)));
}

int Dongle::ReadDataFile(int id, size_t offset, void* buffer, size_t size) {
  if (0 == size)
    return 0;

  if (id <= 0 || id > 0xFFFF || offset >= 0xFFF0 || size >= 0xFFF0)
    return DONGLE_CHECK(-EINVAL);

  if (!handle_)
    return DONGLE_CHECK(-EBADF);

  DongleHandle* thiz = reinterpret_cast<DongleHandle*>(handle_);
  auto callback = [offset, buffer, size](const void* content, size_t size_content) {
    if (offset >= size_content)
      return -ERANGE;
    if (size_content - offset < size)
      return -ERANGE;
    memcpy(buffer, (uint8_t*)content + offset, size);
    return 0;
  };

  if (id == 0xFFFF)
    return DONGLE_CHECK(callback(thiz->factory_datafile_, DongleHandle::kFactoryFileSize));
  return DONGLE_CHECK(thiz->OpReadSecretFile(SECRET_STORAGE_TYPE::kData, id, std::move(callback)));
}

int Dongle::CreatePKEYFile(SECRET_STORAGE_TYPE type_, int bits, int id, const PKEY_LICENCE& licence) {
  size_t size = 0;
  if (id <= 0 || id >= 0xFFFF)
    return last_error_ = -EINVAL;

  if (type_ == SECRET_STORAGE_TYPE::kRSA) {
    size = sizeof(DongleHandle::RSA2048File);
    if (bits != 2048)
      return last_error_ = -EINVAL;
  } else if (type_ == SECRET_STORAGE_TYPE::kSM2) {
    size = 32;
    if (bits != 256)
      return last_error_ = -EINVAL;
  } else if (type_ == SECRET_STORAGE_TYPE::kP256) {
    size = 32;
    if (bits != 256)
      return last_error_ = -EINVAL;
  } else {
    return last_error_ = -EINVAL;
  }

  if (!handle_)
    return DONGLE_CHECK(-EBADF);

  DongleHandle* thiz = reinterpret_cast<DongleHandle*>(handle_);
  return DONGLE_CHECK(thiz->CreateSecretFile(type_, id, size));
}

int Dongle::GenerateRSA(int id, uint32_t* modulus, uint8_t public_[], uint8_t* private_) {
  if (!handle_)
    return DONGLE_CHECK(-EBADF);

  DongleHandle* thiz = reinterpret_cast<DongleHandle*>(handle_);
  auto callback = [&](void* buffer, size_t size) -> int {
    if (size != sizeof(DongleHandle::RSA2048File))
      return last_error_ = -EFAULT;

    DongleHandle::RSA2048File* file = static_cast<DongleHandle::RSA2048File*>(buffer);

    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);

    if (!RSA_generate_key_ex(rsa, 2048, e, nullptr)) {
      rlLOGE(TAG, "RSA_generate_key_ex error %ld", ERR_get_error());
      RSA_free(rsa);
      BN_free(e);
      return last_error_ = -EFAULT;
    }

    file->modulus_ = *modulus = RSA_F4;
    BN_bn2binpad(RSA_get0_d(rsa), file->private_, 256);
    BN_bn2binpad(RSA_get0_n(rsa), file->public_, 256);
    RSA_free(rsa);
    BN_free(e);

    memcpy(public_, file->public_, 256);
    if (private_)
      memcpy(private_, file->private_, 256);
    return 0;
  };
  return DONGLE_CHECK(thiz->OpWriteSecretFile(SECRET_STORAGE_TYPE::kRSA, id, std::move(callback)));
}

int Dongle::ImportRSA(int id, int bits, uint32_t modules, const uint8_t public_[], const uint8_t private_[]) {
  if (bits != 2048)
    return last_error_ = -EINVAL;

  if (!handle_)
    return DONGLE_CHECK(-EBADF);

  DongleHandle* thiz = reinterpret_cast<DongleHandle*>(handle_);
  auto callback = [&](void* buffer, size_t size) -> int {
    if (size != sizeof(DongleHandle::RSA2048File))
      return last_error_ = -EFAULT;

    DongleHandle::RSA2048File* file = static_cast<DongleHandle::RSA2048File*>(buffer);
    file->modulus_ = modules;
    memcpy(file->private_, private_, 256);
    memcpy(file->public_, public_, 256);

    return 0;
  };
  return DONGLE_CHECK(thiz->OpWriteSecretFile(SECRET_STORAGE_TYPE::kRSA, id, std::move(callback)));
}

int Dongle::GenerateP256(int id, uint8_t X[32], uint8_t Y[32], uint8_t* private_) {
  if (!handle_)
    return DONGLE_CHECK(-EBADF);

  DongleHandle* thiz = reinterpret_cast<DongleHandle*>(handle_);
  auto callback = [&](void* p, size_t size) -> int {
    if (size != 32)
      return last_error_ = -EFAULT;
    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!EC_KEY_generate_key(eckey)) {
      EC_KEY_free(eckey);
      return last_error_ = -EFAULT;
    }

    uint8_t pubkey[65];
    DONGLE_VERIFY(BN_bn2binpad(EC_KEY_get0_private_key(eckey), (uint8_t*)p, 32));
    DONGLE_VERIFY(65 == EC_POINT_point2oct(EC_KEY_get0_group(eckey), EC_KEY_get0_public_key(eckey),
                                           POINT_CONVERSION_UNCOMPRESSED, pubkey, 65, nullptr));
    memcpy(X, &pubkey[1], 32);
    memcpy(Y, &pubkey[33], 32);
    if (private_)
      memcpy(private_, p, 32);
    EC_KEY_free(eckey);
    return 0;
  };
  return DONGLE_CHECK(thiz->OpWriteSecretFile(SECRET_STORAGE_TYPE::kP256, id, std::move(callback)));
}

int Dongle::ImportP256(int id, const uint8_t K[32]) {
  if (!handle_)
    return DONGLE_CHECK(-EBADF);

  DongleHandle* thiz = reinterpret_cast<DongleHandle*>(handle_);
  auto callback = [&](void* p, size_t size) -> int {
    if (size != 32)
      return last_error_ = -EFAULT;
    memcpy(p, K, 32);
    return 0;
  };

  return DONGLE_CHECK(thiz->OpWriteSecretFile(SECRET_STORAGE_TYPE::kP256, id, std::move(callback)));
}

int Dongle::GenerateSM2(int id, uint8_t X[32], uint8_t Y[32], uint8_t* private_) {
  if (!handle_)
    return DONGLE_CHECK(-EBADF);

  DongleHandle* thiz = reinterpret_cast<DongleHandle*>(handle_);
  auto callback = [&](void* p, size_t size) -> int {
    if (size != 32)
      return last_error_ = -EFAULT;
    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_sm2);
    if (!EC_KEY_generate_key(eckey)) {
      EC_KEY_free(eckey);
      return last_error_ = -EFAULT;
    }

    uint8_t pubkey[65];
    DONGLE_VERIFY(BN_bn2binpad(EC_KEY_get0_private_key(eckey), (uint8_t*)p, 32));
    DONGLE_VERIFY(65 == EC_POINT_point2oct(EC_KEY_get0_group(eckey), EC_KEY_get0_public_key(eckey),
                                           POINT_CONVERSION_UNCOMPRESSED, pubkey, 65, nullptr));
    memcpy(X, &pubkey[1], 32);
    memcpy(Y, &pubkey[33], 32);
    if (private_)
      memcpy(private_, p, 32);
    EC_KEY_free(eckey);
    return 0;
  };
  return DONGLE_CHECK(thiz->OpWriteSecretFile(SECRET_STORAGE_TYPE::kSM2, id, std::move(callback)));
}

int Dongle::ImportSM2(int id, const uint8_t K[32]) {
  if (!handle_)
    return DONGLE_CHECK(-EBADF);

  DongleHandle* thiz = reinterpret_cast<DongleHandle*>(handle_);
  auto callback = [&](void* p, size_t size) -> int {
    if (size != 32)
      return last_error_ = -EFAULT;
    memcpy(p, K, 32);
    return 0;
  };

  return DONGLE_CHECK(thiz->OpWriteSecretFile(SECRET_STORAGE_TYPE::kSM2, id, std::move(callback)));
}

int Dongle::CreateKeyFile(int id, PERMISSION permission, SECRET_STORAGE_TYPE type) {
  if (id <= 0 || id >= 0xFFFF)
    return last_error_ = -EINVAL;
  if (type != SECRET_STORAGE_TYPE::kTDES && type != SECRET_STORAGE_TYPE::kSM4)
    return last_error_ = -EINVAL;
  if (!handle_)
    return DONGLE_CHECK(-EBADF);

  DongleHandle* thiz = reinterpret_cast<DongleHandle*>(handle_);
  return DONGLE_CHECK(thiz->CreateSecretFile(type, id, 16));
}

int Dongle::WriteKeyFile(int id, const void* buffer, size_t size, SECRET_STORAGE_TYPE type) {
  if (id <= 0 || id >= 0xFFFF || size != 16)
    return last_error_ = -EINVAL;
  if (type != SECRET_STORAGE_TYPE::kTDES && type != SECRET_STORAGE_TYPE::kSM4)
    return last_error_ = -EINVAL;
  if (!handle_)
    return DONGLE_CHECK(-EBADF);

  DongleHandle* thiz = reinterpret_cast<DongleHandle*>(handle_);
  auto callback = [&](void* p, size_t size) -> int {
    if (size != 16)
      return last_error_ = -EFAULT;
    memcpy(p, buffer, 16);
    return 0;
  };
  return DONGLE_CHECK(thiz->OpWriteSecretFile(type, id, std::move(callback)));
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

  if (!handle_)
    return DONGLE_CHECK(-EBADF);

  DongleHandle* thiz = reinterpret_cast<DongleHandle*>(handle_);
  auto callback = [&](const void* p, size_t size) -> int {
    if (size != sizeof(DongleHandle::RSA2048File))
      return last_error_ = -EFAULT;

    const DongleHandle::RSA2048File* file = static_cast<const DongleHandle::RSA2048File*>(p);
    return RSAPrivate(2048, file->modulus_, file->public_, file->private_, buffer, size_buffer, encrypt);
  };
  return DONGLE_CHECK(thiz->OpReadSecretFile(SECRET_STORAGE_TYPE::kRSA, id, std::move(callback)));
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
    return last_error_ = -EINVAL;

  if (encrypt) {
    if (size_in > 256 - 11)
      return last_error_ = -E2BIG;
  } else if (size_in != 256) {
    return last_error_ = -EINVAL;
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
    return last_error_ = -EINVAL;

  if (encrypt) {
    if (size_in > 256 - 11)
      return last_error_ = -E2BIG;
  } else if (size_in != 256) {
    return last_error_ = -EINVAL;
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
  if (!handle_)
    return DONGLE_CHECK(-EBADF);

  DongleHandle* thiz = reinterpret_cast<DongleHandle*>(handle_);
  auto callback = [&](const void* p, size_t size) -> int {
    if (size != 32)
      return last_error_ = -EFAULT;
    return P256Sign((const uint8_t*)p, hash_, R, S);
  };
  return DONGLE_CHECK(thiz->OpReadSecretFile(SECRET_STORAGE_TYPE::kP256, id, std::move(callback)));
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
  if (!handle_)
    return DONGLE_CHECK(-EBADF);

  DongleHandle* thiz = reinterpret_cast<DongleHandle*>(handle_);
  auto callback = [&](const void* p, size_t size) -> int {
    if (size != 32)
      return last_error_ = -EFAULT;
    return SM2Sign((const uint8_t*)p, hash_, R, S);
  };
  return DONGLE_CHECK(thiz->OpReadSecretFile(SECRET_STORAGE_TYPE::kSM2, id, std::move(callback)));
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
  if (!handle_)
    return DONGLE_CHECK(-EBADF);

  DongleHandle* thiz = reinterpret_cast<DongleHandle*>(handle_);
  auto callback = [&](const void* p, size_t size) -> int {
    if (size != 32)
      return last_error_ = -EFAULT;
    return SM2Decrypt((const uint8_t*)p, cipher, size_cipher, text, size_text);
  };
  return DONGLE_CHECK(thiz->OpReadSecretFile(SECRET_STORAGE_TYPE::kSM2, id, std::move(callback)));
}

int Dongle::SM2Decrypt(const uint8_t private_[32],
                       const uint8_t cipher[],
                       size_t size_cipher,
                       uint8_t text[],
                       size_t* size_text) {
  int ret = -1;
  if (size_cipher < 96 || size_cipher > 512)
    return last_error_ = -EINVAL;

  uint8_t asn1_cipher[1024];
  int asn1_len = SM2Cipher_TextToASN1(cipher, size_cipher, asn1_cipher);
  if (asn1_len <= 0)
    return last_error_ = -EFAULT;

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

    DONGLE_VERIFY(96 + size_text == (size_t)SM2Cipher_ASN1ToText(cipher, cipher_len, out_cipher));
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
  ::SHA1((const uint8_t*)input, size, md);
  return 0;
}

int Dongle::SM3(const void* input, size_t size, uint8_t md[32]) {
  SM3_CTX ctx;
  sm3_init(&ctx);
  sm3_update(&ctx, input, size);
  sm3_final(md, &ctx);
  return 0;
}

int Dongle::TDESECB(int id, uint8_t* buffer, size_t size, bool encrypt) {
  if (!handle_)
    return DONGLE_CHECK(-EBADF);

  DongleHandle* thiz = reinterpret_cast<DongleHandle*>(handle_);
  auto callback = [&](const void* key, size_t size) -> int {
    if (size != 16)
      return last_error_ = -EFAULT;
    return TDESECB((const uint8_t*)key, buffer, size, encrypt);
  };
  return thiz->OpReadSecretFile(SECRET_STORAGE_TYPE::kTDES, id, std::move(callback));
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
  if (!handle_)
    return DONGLE_CHECK(-EBADF);

  DongleHandle* thiz = reinterpret_cast<DongleHandle*>(handle_);
  auto callback = [&](const void* key, size_t size) -> int {
    if (size != 16)
      return last_error_ = -EFAULT;
    return SM4ECB((const uint8_t*)key, buffer, size, encrypt);
  };
  return thiz->OpReadSecretFile(SECRET_STORAGE_TYPE::kSM4, id, std::move(callback));
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
  if (handle_) {
    delete reinterpret_cast<DongleHandle*>(handle_);
    handle_ = nullptr;
  }

  return 0;
}

int Emulator::Create(const uint8_t master_secret[64], uint32_t uid, int loop) {
  Close();
  DongleHandle* handle = DongleHandle::Create(master_secret, uid, loop);
  handle_ = reinterpret_cast<ROCKEY_HANDLE>(handle);
  return 0;
}

int Emulator::Open(const char* file, const uint8_t master_secret[64], int loop) {
  Close();

  SecretBuffer<kDongleFileSizeLimit + 256> content;
  int size = LoadDongleFile(file, content);

  if (size < 0) {
    rlLOGE(TAG, "LoadDongleFile %s, Error %d", file, size);
    return size;
  }
  return DongleHandle::Load(&content[0], size, master_secret, loop, reinterpret_cast<DongleHandle**>(&handle_));
}

int Emulator::Write(const char* file) {
  if (!handle_)
    return -EBADF;

  SecretBuffer<kDongleFileSizeLimit + 256> dongle_file_;
  DongleHandle* thiz = reinterpret_cast<DongleHandle*>(handle_);
  size_t size = thiz->Write(&dongle_file_[0]);
  DONGLE_VERIFY(size <= kDongleFileSizeLimit &&
                size >= sizeof(DongleHandle::SupperBlock) + DongleHandle::kFactoryFileSize + 128);
  return WriteDongleFile(file, &dongle_file_[0], size);
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

#include "script.h"
#include <Interface/x509.h>

rLANG_DECLARE_MACHINE

static constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("EXECV");

namespace dongle {
namespace script {

static int RockeyTrustDecryptData(VM_t& vm, const ScriptText* text, size_t szData, RuntimeHeader& runtime_header_) {
  uint8_t mac[16];
  uint8_t sm3[32];

  /**
   *!
   */
  uint8_t* const vmdata = static_cast<uint8_t*>(vm.data_) + 256;
  if (text->ver_major_ != rLANG_DONGLE_VERSION_MAJOR || text->ver_minor_ != rLANG_DONGLE_VERSION_MINOR)
    return -EINVAL;
  if (text->size_public_ > 1024)
    return -EINVAL;

  vm.dongle_->SM3(text, sizeof(ScriptText) - 16, sm3);

  rlCryptoChaChaPolyCtx& ctx = *(rlCryptoChaChaPolyCtx*)vm.buffer_;
  rlCryptoChaChaPolyInit(&ctx);
  rlCryptoChaChaPolySetKey(&ctx, sm3);
  rlCryptoChaChaPolyStarts(&ctx, &text->nonce_[0], 0);
  rlCryptoChaChaPolyUpdate(&ctx, vmdata, vmdata, szData);
  rlCryptoChaChaPolyFinish(&ctx, mac);

  if (0 != memcmp(mac, text->check_, 16)) {
    rlLOGE(TAG, "CryptoChaChaPoly.mac error, size %zd!", szData);
    return -EINVAL;
  }

  runtime_header_.zero_ = 0;
  runtime_header_.world_magic_ = rLANG_WORLD_MAGIC;
  runtime_header_.ver_major_ = rLANG_DONGLE_VERSION_MAJOR;
  runtime_header_.ver_minor_ = rLANG_DONGLE_VERSION_MINOR;
  runtime_header_.size_public_ = text->size_public_;
  runtime_header_.file_magic_ = text->file_magic_;
  runtime_header_.reserved_0_ = 0;

  /**
   *!
   */
  switch (runtime_header_.script_category_) {
    case RuntimeHeader::ScriptCategory::kScriptLimit:
      memcpy(runtime_header_.text_sign_, (uint8_t*)text->script_ + sizeof(text->script_) - 64, 64);
      break;
    case RuntimeHeader::ScriptCategory::kScriptAdmin:
      memcpy(runtime_header_.data_sign_, vmdata + szData, 64);
      break;
    case RuntimeHeader::ScriptCategory::kScriptBootstrap:
    case RuntimeHeader::ScriptCategory::kScriptAtomic:
      memset(runtime_header_.zero_fill_, 0, 64);
      break;
    default:
      rlLOGE(TAG, "INVALID SCRIPT CATEGORY %08X!", (int)runtime_header_.script_category_);
      return -EFAULT;
  }

  ((Sha512Ctx*)vm.buffer_)->Init().Update(text->script_, sizeof(text->script_)).Final(runtime_header_.text_sha512_);
  ((Sha512Ctx*)vm.buffer_)->Init().Update(vmdata, szData).Final(runtime_header_.data_sha512_);
  memcpy(vm.data_, &runtime_header_, sizeof(RuntimeHeader));
  return 0;
}

rLANGEXPORT int rLANGAPI RockeyTrustExecutePrepare(VM_t& vm, void* InOutBuf /* 1024 */, void* ExtendBuf) {
  union DecodeTextContext {
    uint8_t data_[256];
    ScriptText text_;
    struct {
      WorldCreateHeader header_;
      ScriptText text_;
    } raw_;
  };
  RuntimeHeader& runtime_header_ = *(RuntimeHeader*)((uint8_t*)ExtendBuf + 256);
  DecodeTextContext& v = *(DecodeTextContext*)((uint8_t*)ExtendBuf + 512);

  int result = 0;
  if (vm.data_ != InOutBuf || vm.buffer_ != ExtendBuf)
    return -EBADF;

  rLANG_ABIREQUIRE(256 == sizeof(v));
  memcpy(&v, InOutBuf, sizeof(v));
  memset(&runtime_header_, 0, sizeof(RuntimeHeader));
  if (0 != vm.dongle_->GetDongleInfo(&runtime_header_.dongle_info_))
    return -EFAULT;

  if (vm.valid_permission_ != PERMISSION::kAdministrator) {
    PERMISSION permission_login = PERMISSION::kAnonymous;
    result = vm.dongle_->GetPINState(&permission_login);
    if (0 != result)
      return result;
    if (permission_login == PERMISSION::kAdministrator)
      vm.valid_permission_ = PERMISSION::kAdministrator;
  }

  if (vm.valid_permission_ != PERMISSION::kAdministrator) {
    DONGLE_INFO thiz_dongle_;
    DONGLE_INFO check_dongle_;

    if (vm.dongle_->GetDongleInfo(&thiz_dongle_) < 0)
      return -EBADF;

    if (vm.dongle_->ReadDataFile(Dongle::kFactoryDataFileId,
                                 WorldPublic::kOffsetDataFile + WorldPublic::kOffsetDongleInfo, &check_dongle_,
                                 sizeof(check_dongle_)) < 0)
      return -EBADF;

    if (0 != memcmp(&thiz_dongle_, &check_dongle_, sizeof(check_dongle_))) {
      rlLOGE(TAG, "INVALID kDongleInfo!!");
      return -EBADF;
    }
  }

  if (vm.valid_permission_ == PERMISSION::kAdministrator && v.raw_.header_.zero_ == 0 &&
      v.raw_.header_.world_magic_ == rLANG_WORLD_MAGIC &&
      v.raw_.header_.create_magic_ == WorldCreateHeader::kMagicCreate &&
      v.raw_.header_.target_magic_ == WorldCreateHeader::kMagicWorld &&
      v.raw_.text_.file_magic_ == ScriptText::kAdminFileMagic && v.raw_.text_.size_public_ <= 1024 &&
      v.raw_.text_.ver_major_ == rLANG_DONGLE_VERSION_MAJOR && v.raw_.text_.ver_minor_ == rLANG_DONGLE_VERSION_MINOR) {
    /**
     *!
     */
    memmove(&v.text_, &v.raw_.text_, sizeof(ScriptText));
    runtime_header_.script_category_ = RuntimeHeader::ScriptCategory::kScriptBootstrap;
    result = RockeyTrustDecryptData(vm, &v.text_, 1024 - 256, runtime_header_);
    if (result < 0) {
      rlLOGE(TAG, "Bootstrap script, decrypt data Failed: %d", result);
      return result;
    } else {
      rlLOGW(TAG, "Bootstrap script call!");
    }

    return vm.Initialize(&v.text_.script_, sizeof(v.text_.script_), v.text_.size_public_);
  }

  size_t size = sizeof(v);
  result = vm.dongle_->RSAPrivate(vm.kKeyIdGlobalRSA2048, v.data_, &size, false);
  if (result < 0) {
    rlLOGXE(TAG, &v.raw_.header_, sizeof(v.raw_.header_), "RSA.Master.Decode Text Failed: %d, %08X/%d!", result,
            (int)v.raw_.text_.file_magic_, v.raw_.text_.size_public_);
    return -EFAULT;
  } else if (size != sizeof(ScriptText)) {
    rlLOGE(TAG, "Invalid ScriptText %zd", size);
    return -EBADMSG;
  } else if (v.text_.file_magic_ == ScriptText::kLimitFileMagic) {
    uint8_t sm3[32], sign[64];
    uint8_t ecies_pubkey[64];
    const uint8_t* input = (const uint8_t*)&v.text_;

    runtime_header_.script_category_ = RuntimeHeader::ScriptCategory::kScriptLimit;
    result = RockeyTrustDecryptData(vm, &v.text_, 1024 - 256, runtime_header_);
    if (0 != result)
      return result;

    constexpr int kSizeText = offsetof(ScriptText, nonce_) - 64;
    memcpy(sign, &input[kSizeText], 64);
    result = vm.dongle_->SM3(input, kSizeText, sm3);
    if (0 != result)
      return result;

    if (vm.dongle_->ReadDataFile(Dongle::kFactoryDataFileId,
                                 WorldPublic::kOffsetDataFile + WorldPublic::kOffsetPubkey_SM2ECIES, &ecies_pubkey,
                                 64) < 0)
      return -EBADF;

    if (vm.dongle_->CheckPointOnCurveSM2(&ecies_pubkey[0], &ecies_pubkey[32]))
      return -EBADF;

    result = vm.dongle_->SM2Verify(&ecies_pubkey[0], &ecies_pubkey[32], sm3, &sign[0], &sign[32]);
    if (0 != result)
      return result;

    /**
     *! kSign.fill(kInv)
     */
    memset(const_cast<uint8_t*>(input) + kSizeText, 0, 64);

    /**
     *! CHECK.SM2ECIES.Key ...
     */
    if (vm.dongle_->SM2Sign(WorldPublic::kFileSM2ECIES, sm3, &sign[0], &sign[32]) < 0) /* Check SM2.ecies key */
      return -EBADF;
    if (vm.dongle_->SM2Verify(&ecies_pubkey[0], &ecies_pubkey[32], sm3, &sign[0], &sign[32]) < 0)
      return -EBADF;
    vm.valid_permission_ = PERMISSION::kAdministrator; /* Granting privileges administrator */
  } else if (v.text_.file_magic_ == ScriptText::kAdminFileMagic) {
    uint8_t sm3[32], sign[64];
    uint8_t ecies_pubkey[64];
    uint8_t* const vmdata = (uint8_t*)vm.data_;
    memcpy(sign, &vmdata[1024 - 64], 64);

    /**
     *!
     */
    runtime_header_.script_category_ = RuntimeHeader::ScriptCategory::kScriptAdmin;
    result = RockeyTrustDecryptData(vm, &v.text_, 1024 - 256 - 64, runtime_header_);
    if (0 != result)
      return result;

    if (vm.dongle_->ReadDataFile(Dongle::kFactoryDataFileId,
                                 WorldPublic::kOffsetDataFile + WorldPublic::kOffsetPubkey_SM2ECIES, &ecies_pubkey,
                                 64) < 0)
      return -EBADF;

    if (vm.dongle_->SM3(vmdata + 256, 1024 - 256 - 64, sm3) < 0)
      return -EBADF;

    if (vm.dongle_->SM2Verify(&ecies_pubkey[0], &ecies_pubkey[32], sm3, &sign[0], &sign[32]) < 0)
      return -EBADF;

    /**
     *! CHECK.SM2ECIES.Key ...
     */
    if (vm.dongle_->SM2Sign(WorldPublic::kFileSM2ECIES, sm3, &sign[0], &sign[32]) < 0) /* Check SM2.ecies key */
      return -EBADF;
    if (vm.dongle_->SM2Verify(&ecies_pubkey[0], &ecies_pubkey[32], sm3, &sign[0], &sign[32]) < 0)
      return -EBADF;
    vm.valid_permission_ = PERMISSION::kAdministrator; /* Granting privileges administrator */
  } else {
    runtime_header_.script_category_ = RuntimeHeader::ScriptCategory::kScriptAtomic;
    result = RockeyTrustDecryptData(vm, &v.text_, 1024 - 256, runtime_header_);
    if (0 != result)
      return result;
  }

  if (0 != result)
    return result;

  if (v.text_.size_public_ > 1024) {
    rlLOGE(TAG, "Invalid Size.public %d", v.text_.size_public_);
    return -EBADMSG;
  }

  if (vm.valid_permission_ != PERMISSION::kAdministrator) {
    WorldPublic::Header public_header_; /*!! Administrator mode check */
    result = vm.dongle_->ReadDataFile(Dongle::kFactoryDataFileId, WorldPublic::kOffsetDataFile, &public_header_,
                                      sizeof(public_header_));
    if (0 != result)
      return result;

    if (public_header_.category_magic_ == WorldPublic::kCategoryHeaderMagicAdmin) {
      rlLOGXE(TAG, &public_header_, sizeof(public_header_), "EACCES: Adminstrator requirement!");
      return -EACCES;
    }
  }

  std::ignore = TAG;
  return vm.Initialize(&v.text_.script_, sizeof(v.text_.script_), v.text_.size_public_);
}

int VM_t::OpExecute(uint16_t op, int argc, int32_t argv[]) {
  if (op == OpCode::kExecuteHelloWorld) {
    return OpExecute_HelloWorld(argc, argv);
  } else if (op == OpCode::kExecuteImportMasterSecret) {
    if (valid_permission_ != PERMISSION::kAdministrator)
      return zero_ = -EACCES;
    return zero_ = OpExecute_ImportMasterSecret(argc, argv);
  } else if (op == OpCode::kExecuteExchangeMasterSecret) {
    if (valid_permission_ != PERMISSION::kAdministrator)
      return zero_ = -EACCES;
    return zero_ = OpExecute_ExchangeMasterSecret(argc, argv);
  } else if (op == OpCode::kExecuteImportX509) {
    return zero_ = OpExecute_ImportX509(argc, argv);
  } else {
    return zero_ = SIGILL;
  }
}

int VM_t::OpExecute_HelloWorld(int argc, int32_t argv[]) {
  return dongle_->RandBytes((uint8_t*)data_, 1024);
}

/**
 *! K0: A B C
 *! K1: A D E
 *! K2: B D F
 *! K3: C E F
 */
struct MASTER_SECRET_Header {
  uint8_t hid_[12];
  uint8_t kid_[3];
  uint8_t index_;
};

struct MASTER_SECRET_Key {
  MASTER_SECRET_Header header_;
  uint8_t PREV_MASTER_SECRET[32];
};

int VM_t::OpExecute_ExchangeMasterSecret(int argc, int32_t argv[]) {
  uint8_t pkey[64];
  struct {
    uint8_t x25519_pubkey[4][32];
    uint32_t rsa_modulus_;
    uint8_t rsa_pubkey_[256];
  } Context;
  enum class Name : uint8_t { A, B, C, D, E, F };
  enum Index { K0, K1, K2, K3 };

  using Key = MASTER_SECRET_Key;
  memcpy(&Context, (uint8_t*)data_ + 256, sizeof(Context));
  memset(data_, 0, 1024);

  if (Context.rsa_modulus_ == 0 || Context.rsa_modulus_ + 1 == 0 || *(int32_t*)Context.rsa_pubkey_ == 0) {
    rlLOGXE(TAG, Context.rsa_pubkey_, 256, "INVALID RSA.Pubkey %d", (int)Context.rsa_modulus_);
    return -EINVAL;
  }

  memset(pkey, -1, sizeof(pkey));
  int result = OpManager_ComputeSecretBytes(pkey, 0);
  if (0 != result)
    return result;

  result = dongle_->ComputePubkeyCurve25519(&pkey[0], &pkey[32]);
  if (0 != result)
    return result;

  auto Exchange = [&](const Index index) {
    DONGLE_INFO info;
    Name KeyIndex[3];
    Key* const keys = (Key*)data_;
    int result = dongle_->GetDongleInfo(&info);
    if (0 != result)
      return result;

    switch (index) {
      default:
      case Index::K0:  // A B C
        KeyIndex[0] = Name::A;
        KeyIndex[1] = Name::B;
        KeyIndex[2] = Name::C;
        break;

      case Index::K1:  // A D E
        KeyIndex[0] = Name::A;
        KeyIndex[1] = Name::D;
        KeyIndex[2] = Name::E;
        break;

      case Index::K2:  // B D F
        KeyIndex[0] = Name::B;
        KeyIndex[1] = Name::D;
        KeyIndex[2] = Name::F;
        break;

      case Index::K3:  // C E F
        KeyIndex[0] = Name::C;
        KeyIndex[1] = Name::E;
        KeyIndex[2] = Name::F;
        break;
    }

    int Z_count = 0;
    for (int ii = 0; ii < 4; ++ii) {
      if (ii == (int)index)
        continue;

      memcpy(&keys[Z_count].header_.hid_[0], &info.hid_[0], 12);
      memset(&keys[Z_count].header_.kid_[0], 0xff, 3);
      keys[Z_count].header_.index_ = (uint8_t)KeyIndex[Z_count];

      /**
       *!
       */
      dongle_->ComputeSecretCurve25519(&keys[Z_count].PREV_MASTER_SECRET[0], &pkey[32], &Context.x25519_pubkey[ii][0]);

      /**
       *!
       */
      ++Z_count;
    }

    if (Z_count != 3) {
      rlLOGE(TAG, "Exchange[%d].count %d != 3!!", (int)index, Z_count);
      dongle_->Abort();
    } else {
      rlLOGI(TAG, "Exchange[%d] OK!", (int)index);
    }

    size_t size = sizeof(Key) * 3;
    return dongle_->RSAPublic(2048, Context.rsa_modulus_, Context.rsa_pubkey_, (uint8_t*)data_, &size, true);
  };

  for (int i = 0; i < 4; ++i) {
    if (0 != memcmp(&Context.x25519_pubkey[i][0], pkey, 32))
      continue;
    result = Exchange((Index)i);
    memset(&pkey[0], 0, sizeof(pkey));
    return result;
  }

  rlLOGE(TAG, "[ENOENT]X25519.pubkey 404 Not Found!");
  return -ENOENT;
}

int VM_t::OpExecute_ImportMasterSecret(int argc, int32_t argv[]) {
  int error = 0;
  uint32_t key_mask = 0;

  using Key = MASTER_SECRET_Key;
  using Header = MASTER_SECRET_Header;

  union SECRET_CONTEXT {
    SECRET_CONTEXT() { memset(PREV_MASTER_SECRET, 0, sizeof(PREV_MASTER_SECRET)); }
    ~SECRET_CONTEXT() { memset(PREV_MASTER_SECRET, 0, sizeof(PREV_MASTER_SECRET)); }

    uint8_t PREV_MASTER_SECRET[6][32];
    uint8_t MASTER_SECRET[kSize_MASTER_SECRET];
  };

  SECRET_CONTEXT V;
  rLANG_ABIREQUIRE(16 == sizeof(Header));

  /**
   *!
   */
  memset(data_, 0, 256);  // Header[6]
  Header* const output_header = (Header*)data_;
  uint8_t* const output_fingerprint = (uint8_t*)data_ + 96;

  auto Decrypt = [&](void* cipher) {
    size_t size = 256;
    int result = dongle_->RSAPrivate(kKeyIdGlobalRSA2048, (uint8_t*)cipher, &size, false);
    if (0 == result && size % sizeof(Key) == 0) {
      const int kCount = (int)(size / sizeof(Key));
      Key* const keys = (Key*)cipher;
      rlLOGI(TAG, "==== Decrypt PREV_MASTER_SECRET Count: %d ====", kCount);

      for (int i = 0; i < kCount; ++i) {
        Key& key = keys[i];

        const int index = key.header_.index_;
        if (index >= 0 && index < 6) {
          if (0 != (key_mask & (1 << index))) {
            if (0 != memcmp(&V.PREV_MASTER_SECRET[index][0], key.PREV_MASTER_SECRET, 32)) {
              rlLOGE(TAG, "Key[%d] mismatch!", index);
              ++error;
            } else {
              rlLOGI(TAG, "Key[%d] check OK!", index);
            }
          } else {
            key_mask |= 1 << index;
            memcpy(&V.PREV_MASTER_SECRET[index][0], key.PREV_MASTER_SECRET, 32);
            memcpy(&output_header[index], &key.header_, sizeof(Header));
            rlLOGI(TAG, "Key[%d] imported!", index);
          }
        } else {
          rlLOGE(TAG, "Invalid Key index: %d", index);
          ++error;
        }
      }
    } else {
      rlLOGE(TAG, "RSA.decrypt Error %d, size: %zd", result, size);
      ++error;
    }

    memset(cipher, 0, 256);
  };

  auto Import = [&] {
    int result = dongle_->SHA512(V.PREV_MASTER_SECRET, sizeof(V.PREV_MASTER_SECRET), V.MASTER_SECRET);
    DONGLE_VERIFY(0 == result);

    dongle_->SHA256(V.MASTER_SECRET, sizeof(V.MASTER_SECRET), output_fingerprint);
    rlLOGXI(TAG, output_fingerprint, 8, "SHA256(MASTER_SECRET)[0...7]:");

    return WRITE_MASTER_SECRET(V.MASTER_SECRET);
  };

  /**
   *!
   */
  Decrypt((uint8_t*)data_ + 256 * 1);
  Decrypt((uint8_t*)data_ + 256 * 2);
  Decrypt((uint8_t*)data_ + 256 * 3);

  if (key_mask != 0x3F) {
    rlLOGE(TAG, "Invalid Key.mask 0x%02X != 0x3F", key_mask);
    ++error;
  }

  if (0 == error)
    error = Import();

  if (0 == error)
    rlLOGXI(TAG, output_header, sizeof(Header) * 6, "Import MASTER_SECRET OK!");
  else
    rlLOGE(TAG, "Import MASTER_SECRET Error: %d!", error);

  memset((uint8_t*)data_ + 96 + 8, 0, 1024 - 96 - 8);
  return error ? -EFAULT : 0;
}

/* ================= OpExecute_ImportX509 =================
 * 证书 DER 位于 dashboard[0, len)(工厂 dataFile 0xFFFF), BER 宽松 FSM 流式解析;
 * argv[0]=SECRET_STORAGE_TYPE(kRSA/kP256/kSM2) argv[1]=pkeyId argv[2]=dataFileId(已存在则报错)
 * argv[3]=DER 长度(0<len<=2048), argv[4](可选)!=0 → 校验 argv[1] 私钥与证书公钥匹配。
 *
 * 导入数据文件布局 = [X509View][X509.DER](先 view 后 DER)。
 * BSP:COS 验签/签名把 ExtendBuf 当工作区 → 三步走, 公钥/临时量全放 InOutBuf。 */
namespace {

static int X509_DashboardRead(void* ctx, size_t off, uint8_t* dst, size_t len) {
  Dongle* d = static_cast<Dongle*>(ctx);
  if (!d || (len && !dst)) return -EINVAL;
  return len ? d->ReadDataFile(Dongle::kFactoryDataFileId, off, dst, len) : 0;
}

/* SPKI BIT STRING 内容解析: RSA = SEQ{INTEGER n, INTEGER e} → [e:u32LE][n:256B];
 * EC = 04||X||Y 或裸 X||Y → xy(64)。返回 0。 */
static int X509_KeyFromPub(const uint8_t* in, size_t in_len, uint8_t* out_e_n, const uint8_t** xy, size_t* xy_len) {
  *xy = nullptr;
  *xy_len = 0;
  if (!in || in_len == 0) return -EBADMSG;
  if (in[0] == 0x04) {
    if (in_len < 65) return -EBADMSG;
    *xy = in + 1;
    *xy_len = 64;
    return 0;
  }
  if (in[0] != 0x30) {
    if (in_len < 64) return -EBADMSG;
    *xy = in;
    *xy_len = 64;
    return 0;
  }
  /* RSA SEQUENCE{ INTEGER n, INTEGER e } */
  size_t p = 1;
  if (p >= in_len) return -EBADMSG;
  uint8_t l = in[p++];
  size_t total;
  if (l & 0x80) {
    uint8_t n = l & 0x7F;
    if (!n || n > 2 || p + n > in_len) return -EBADMSG;
    total = 0;
    while (n--) total = (total << 8) | in[p++];
  } else {
    total = l;
  }
  if (p + total != in_len) return -EBADMSG;
  uint8_t nbuf[256];
  memset(nbuf, 0, sizeof(nbuf));
  uint32_t e = 0;
  bool have_n = false;
  for (int k = 0; k < 2 && p < in_len; ++k) {
    if (in[p++] != 0x02) return -EBADMSG;
    if (p >= in_len) return -EBADMSG;
    l = in[p++];
    size_t ilen;
    if (l & 0x80) {
      uint8_t nn = l & 0x7F;
      if (!nn || nn > 2 || p + nn > in_len) return -EBADMSG;
      ilen = 0;
      while (nn--) ilen = (ilen << 8) | in[p++];
    } else {
      ilen = l;
    }
    if (p + ilen > in_len) return -EBADMSG;
    size_t start = p;
    size_t vlen = ilen;
    if (vlen && in[start] == 0x00) {
      ++start;
      --vlen;
    }
    if (!have_n) {
      if (vlen > 256) return -EBADMSG;
      memcpy(nbuf + (256 - vlen), in + start, vlen);
      have_n = true;
    } else {
      if (vlen > 4) return -EBADMSG;
      e = 0;
      for (size_t i = 0; i < vlen; ++i) e = (e << 8) | in[start + i];
    }
    p += ilen;
  }
  if (!have_n || !out_e_n) return -EBADMSG;
  out_e_n[0] = static_cast<uint8_t>(e);
  out_e_n[1] = static_cast<uint8_t>(e >> 8);
  out_e_n[2] = static_cast<uint8_t>(e >> 16);
  out_e_n[3] = static_cast<uint8_t>(e >> 24);
  memcpy(out_e_n + 4, nbuf, 256);
  return 0;
}

}  // namespace

int VM_t::OpExecute_ImportX509(int argc, int32_t argv[]) {
  if (argc < 4 || argc > 5)
    return zero_ = -EINVAL;
  const int32_t storage = argv[0];
  const int32_t pkey_id = argv[1];
  const int32_t datafile_id = argv[2];
  const int32_t len = argv[3];

  if (valid_permission_ != PERMISSION::kAdministrator && valid_permission_ != PERMISSION::kNormal)
    return zero_ = -EACCES;
  if ((pkey_id < kUserFileID || datafile_id < kUserFileID) && valid_permission_ != PERMISSION::kAdministrator)
    return zero_ = -EACCES;

  if (len <= 0 || len > 2048)
    return zero_ = -EINVAL;
  if (storage != (int32_t)SECRET_STORAGE_TYPE::kRSA && storage != (int32_t)SECRET_STORAGE_TYPE::kP256 &&
      storage != (int32_t)SECRET_STORAGE_TYPE::kSM2)
    return zero_ = -EINVAL;
  if (pkey_id < 1 || pkey_id > 0xffff || datafile_id < 1 || datafile_id > 0xffff)
    return zero_ = -EINVAL;

  /* dashboard[0, len) 流式 BER 解析(不整块驻留) */
  X509View view;
  X509FsmSource src;
  uint8_t key_type = 0;
  int sign_error = 0;
  int error = 0;

  src.Read = X509_DashboardRead;
  src.ctx = dongle_;
  src.total = static_cast<size_t>(len);

  if (0 != X509FsmParse(&view, &src, &key_type))
    return zero_ = -EBADMSG;
  if ((int32_t)key_type != storage)
    return zero_ = -EBADMSG; /* argv0 私钥类型与证书 SPKI 不一致 */

  if (argc > 4 && argv[4]) {
    /* ===== 三步密钥↔证书公钥匹配(COS 用 ExtendBuf, 公钥/临时量放 InOutBuf) ===== */
    uint8_t* const inout = static_cast<uint8_t*>(data_);
    /* 第 1 步: 拉取 SPKI 公钥内容到 InOutBuf+0 并解析(e/n 或 X||Y)。
     * RSA-2048 的 SPKI 内容最大 ~271B(模数 257B DER INTEGER 带前导 0), 上限须 >260;
     * 公钥读入 [0, 0x200) 临时区, 不与 +0x200 起的 block/sig 工作区重叠 */
    if (view.len_spki_pub == 0 || view.len_spki_pub > 0x200 - 1)
      return zero_ = -EBADMSG;
    error = dongle_->ReadDataFile(Dongle::kFactoryDataFileId, view.off_spki_pub, inout, view.len_spki_pub);
    if (0 != error)
      return zero_ = -EFAULT;
    const uint8_t* xy = nullptr;
    size_t xy_len = 0;
    if (0 != X509_KeyFromPub(inout, view.len_spki_pub, inout, &xy, &xy_len))
      return zero_ = -EBADMSG;

    /* 第 2 步(私钥签名) 与 第 3 步(证书公钥验签): 临时量放 InOutBuf[0x200, 0x400) */
    uint8_t* const block = inout + 0x200;
    uint8_t* const sig = inout + 0x300;
    size_t sig_size = 256;
    switch (static_cast<SECRET_STORAGE_TYPE>(storage)) {
      case SECRET_STORAGE_TYPE::kP256:
      case SECRET_STORAGE_TYPE::kSM2: {
        sign_error = dongle_->RandBytes(block, 32);
        if (0 == sign_error) {
          if (storage == (int32_t)SECRET_STORAGE_TYPE::kP256)
            sign_error = dongle_->P256Sign(pkey_id, block, sig, sig + 32);
          else
            sign_error = dongle_->SM2Sign(pkey_id, block, sig, sig + 32);
        }
        if (0 == sign_error && xy && xy_len == 64) {
          if (storage == (int32_t)SECRET_STORAGE_TYPE::kP256)
            sign_error = dongle_->P256Verify(xy, xy + 32, block, sig, sig + 32);
          else
            sign_error = dongle_->SM2Verify(xy, xy + 32, block, sig, sig + 32);
        } else if (0 == sign_error) {
          sign_error = -EBADMSG;
        }
        break;
      }
      case SECRET_STORAGE_TYPE::kRSA: {
        const uint32_t e =
            (uint32_t)inout[0] | ((uint32_t)inout[1] << 8) | ((uint32_t)inout[2] << 16) | ((uint32_t)inout[3] << 24);
        /* PKCS#1 v1.5: 私钥/公钥操作上限 256-11 字节(COS 与模拟器同为有填充),
         * 负载 245B 随机 → 私钥"加密"成 256B 签名 → 证书公钥解密回 245B 明文比对 */
        constexpr size_t kPayload = 256 - 11;
        sign_error = dongle_->RandBytes(block, kPayload);
        if (0 == sign_error) {
          memcpy(sig, block, kPayload);
          sig_size = kPayload;
          sign_error = dongle_->RSAPrivate(pkey_id, sig, &sig_size, true);
        }
        if (0 == sign_error && sig_size == 256)
          sign_error = dongle_->RSAPublic(2048, e, inout + 4, sig, &sig_size, false);
        if (0 == sign_error && (sig_size != kPayload || 0 != memcmp(sig, block, kPayload)))
          sign_error = -EFAULT; /* 与证书公钥不匹配 */
        break;
      }
      default:
        sign_error = -EINVAL;
        break;
    }
    memset(block, 0, 0x400 - 0x200);
  }

  /* argv[4] 请求的私钥↔证书匹配校验失败 → 不得创建数据文件 */
  if (sign_error) {
    rlLOGE(TAG, "ImportX509 pkey#%d cert mismatch: %d, 拒绝导入", (int)pkey_id, sign_error);
    return zero_ = -EFAULT;
  }

  /* 导入 dataFile(argv[2], 须不存在): 布局 = [X509View][X509.DER] */
  const size_t kHeaderSize = sizeof(X509View);
  error = dongle_->CreateDataFile(datafile_id, kHeaderSize + static_cast<size_t>(len), PERMISSION::kAnonymous,
                                  PERMISSION::kAdministrator);
  if (0 == error)
    error = dongle_->WriteDataFile(datafile_id, 0, &view, kHeaderSize);
  if (0 == error) {
    uint8_t chunk[96];
    size_t pos = 0;
    while (pos < static_cast<size_t>(len)) {
      size_t n = static_cast<size_t>(len) - pos;
      if (n > sizeof(chunk))
        n = sizeof(chunk);
      int r = dongle_->ReadDataFile(Dongle::kFactoryDataFileId, pos, chunk, n);
      if (0 != r) {
        error = r;
        break;
      }
      r = dongle_->WriteDataFile(datafile_id, kHeaderSize + pos, chunk, n);
      if (0 != r) {
        error = r;
        break;
      }
      pos += n;
    }
  }
  if (0 != error)
    return zero_ = -EFAULT;
  rlLOGI(TAG, "ImportX509 file#%d layout=[view|DER] len=%d storage=%d OK", (int)datafile_id, (int)len, (int)storage);
  if (argc > 4 && 0 != argv[4])
    rlLOGI(TAG, "ImportX509 file#%d pkey#%d match cert OK", (int)datafile_id, (int)pkey_id);
  return zero_ = 0;
}
}  // namespace script
}  // namespace dongle

rLANG_DECLARE_END

#include "script.h"

rLANG_DECLARE_MACHINE

static constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("EXECV");

namespace dongle {
namespace script {

static int RockeyTrustDecryptData(VM_t& vm, const ScriptText* text, size_t szData) {
  uint8_t mac[16];
  uint8_t sm3[32];

  uint8_t* const vmdata = static_cast<uint8_t*>(vm.data_) + 256;
  if (text->ver_major_ != rLANG_DONGLE_VERSION_MAJOR || text->ver_minor_ != rLANG_DONGLE_VERSION_MINOR)
    return -EINVAL;
  if (text->size_public_ > 1024)
    return -EINVAL;

  vm.dongle_->SM3(text, sizeof(ScriptText) - 16, sm3);

  rlCryptoChaChaPolyCtx ctx;
  rlCryptoChaChaPolyInit(&ctx);
  rlCryptoChaChaPolySetKey(&ctx, sm3);
  rlCryptoChaChaPolyStarts(&ctx, &text->nonce_[0], 0);
  rlCryptoChaChaPolyUpdate(&ctx, vmdata, vmdata, szData);
  rlCryptoChaChaPolyFinish(&ctx, mac);
  if (0 != memcmp(mac, text->check_, 16)) {
    rlLOGE(TAG, "CryptoChaChaPoly.mac error, size %zd!", szData);
    return -EINVAL;
  }
  return 0;
}

rLANGEXPORT int rLANGAPI RockeyTrustExecutePrepare(VM_t& vm, void* InOutBuf /* 1024 */, void* ExtendBuf) {
  union {
    uint8_t data_[256];
    ScriptText text_;
    struct {
      WorldCreateHeader header_;
      ScriptText text_;
    } raw_;
  } v;

  int result = 0;
  rLANG_ABIREQUIRE(256 == sizeof(v));
  memcpy(&v, InOutBuf, sizeof(v));
  if (vm.data_ != InOutBuf || vm.buffer_ != ExtendBuf)
    return -EBADF;

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

  size_t size = sizeof(v);
  result = vm.dongle_->RSAPrivate(vm.kKeyIdGlobalRSA2048, v.data_, &size, false);
  if (result < 0) {
    if (vm.valid_permission_ != PERMISSION::kAdministrator) {
      rlLOGE(TAG, "EACCES: Adminstrator requirement, plain text script call!");
      return -EACCES;
    }

    memcpy(&v, InOutBuf, sizeof(v));
    const WorldCreateHeader& header = v.raw_.header_;
    if (header.zero_ == 0 && header.world_magic_ == rLANG_WORLD_MAGIC &&
        header.create_magic_ == WorldCreateHeader::kMagicCreate &&
        header.target_magic_ == WorldCreateHeader::kMagicWorld &&
        v.raw_.text_.file_magic_ == ScriptText::kAdminFileMagic) {
      memmove(&v.text_, &v.raw_.text_, sizeof(ScriptText));
      result = RockeyTrustDecryptData(vm, &v.text_, 1024 - 256);
      if (0 != result)
        return result;
    } else {
      rlLOGXE(TAG, &v.raw_.header_, sizeof(v.raw_.header_), "RSA.Master.Decode Text %08X Failed!",
              (int)v.raw_.text_.file_magic_);
      return -EACCES;
    }
  } else if (size != sizeof(ScriptText)) {
    rlLOGE(TAG, "Invalid ScriptText %zd", size);
    return -EBADMSG;
  } else if (v.text_.file_magic_ == ScriptText::kLimitFileMagic) {
    uint8_t sm3[32], sign[64];
    uint8_t ecies_pubkey[64];
    const uint8_t* input = (const uint8_t*)&v.text_;

    result = RockeyTrustDecryptData(vm, &v.text_, 1024 - 256);
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
    result = RockeyTrustDecryptData(vm, &v.text_, 1024 - 256 - 64);
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
    result = RockeyTrustDecryptData(vm, &v.text_, 1024 - 256);
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
  } else {
    return zero_ = SIGILL;
  }
}

int VM_t::READ_MASTER_SECRET(uint8_t MASTER_SECRET[64]) {
  uint8_t ENCRYPT_MASTER_SECRET[256];
  int result = dongle_->ReadDataFile(kKeyIdGlobalSECRET, 0, ENCRYPT_MASTER_SECRET, sizeof(ENCRYPT_MASTER_SECRET));
  if (0 != result) {
    rlLOGE(TAG, "kFactoryDataFileId.Read Failed %d!", result);
    return result;
  }

  size_t size = 256;
  result = dongle_->RSAPrivate(kKeyIdGlobalRSA2048, ENCRYPT_MASTER_SECRET, &size, false);
  if (0 != result || size != kSize_MASTER_SECRET) {
    rlLOGE(TAG, "kKeyIdGlobalRSA2048.Decrypt Failed %d/%zd!", result, size);
    return -EFAULT;
  }

  memcpy(MASTER_SECRET, ENCRYPT_MASTER_SECRET, kSize_MASTER_SECRET);
  memset(ENCRYPT_MASTER_SECRET, 0, sizeof(ENCRYPT_MASTER_SECRET));
  return 0;
}

int VM_t::WRITE_MASTER_SECRET(const uint8_t MASTER_SECRET[64]) {
  struct {
    uint32_t modulus_;
    uint8_t pubkey_[256];
  } pubk;
  uint8_t ENCRYPT_MASTER_SECRET[256];

  int result =
      dongle_->ReadDataFile(Dongle::kFactoryDataFileId,
                            WorldPublic::kOffsetDataFile + WorldPublic::kOffsetPubkey_RSA2048, &pubk, sizeof(pubk));
  if (0 != result) {
    rlLOGE(TAG, "Read RSA2048.pubkey Failed %d!", result);
    return result;
  }

  if (pubk.modulus_ == 0 || pubk.modulus_ == 0xFFFFFFFF || *(int32_t*)pubk.pubkey_ == 0) {
    rlLOGXE(TAG, &pubk, sizeof(pubk), "INVALID RSA2048.pubkey!");
    return -EFAULT;
  }

  size_t size = 64;
  memcpy(&ENCRYPT_MASTER_SECRET[0], MASTER_SECRET, 64);
  result = dongle_->RSAPublic(2048, pubk.modulus_, pubk.pubkey_, &ENCRYPT_MASTER_SECRET[0], &size, true);
  if (0 != result) {
    rlLOGE(TAG, "RSA.Encrypt Failed %d!", result);
    return result;
  }

  size = 256;
  memcpy(pubk.pubkey_, &ENCRYPT_MASTER_SECRET[0], 256);
  result = dongle_->RSAPrivate(kKeyIdGlobalRSA2048, pubk.pubkey_, &size, false);
  memset(pubk.pubkey_, 0, 256);
  if (0 != result) {
    rlLOGE(TAG, "kKeyIdGlobalRSA2048.Verify Failed %d!", result);
    return result;
  }

  dongle_->DeleteFile(SECRET_STORAGE_TYPE::kData, kKeyIdGlobalSECRET);
  result = dongle_->CreateDataFile(kKeyIdGlobalSECRET, 256, PERMISSION::kAdministrator, PERMISSION::kAdministrator);
  if (0 != result) {
    rlLOGE(TAG, "kKeyIdGlobalSECRET.Create Failed %d!", result);
    return result;
  }

  result = dongle_->WriteDataFile(kKeyIdGlobalSECRET, 0, &ENCRYPT_MASTER_SECRET[0], 256);
  if (0 != result) {
    rlLOGE(TAG, "kKeyIdGlobalSECRET.Write Failed %d!", result);
    dongle_->DeleteFile(SECRET_STORAGE_TYPE::kData, kKeyIdGlobalSECRET);
    return result;
  }

  return result;
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

}  // namespace script
}  // namespace dongle

rLANG_DECLARE_END

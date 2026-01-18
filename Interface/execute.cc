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
  rlCryptoChaChaPolyStarts(&ctx, sm3, 0);
  rlCryptoChaChaPolyUpdate(&ctx, vmdata, vmdata, szData);
  rlCryptoChaChaPolyFinish(&ctx, mac);
#if 0
  if (0 != memcmp(mac, text->check_, 16)) {
    rlLOGE(TAG, "CryptoChaChaPoly.mac error, size %zd!", szData);
    return -EINVAL;
  }
#endif
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

  if (vm.valid_permission_ != PERMISSION::kAdminstrator) {
    PERMISSION permission_login = PERMISSION::kAnonymous;
    result = vm.dongle_->GetPINState(&permission_login);
    if (0 != result)
      return result;
    if (permission_login == PERMISSION::kAdminstrator)
      vm.valid_permission_ = PERMISSION::kAdminstrator;
  }

  if (vm.valid_permission_ != PERMISSION::kAdminstrator) {
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
    if (vm.valid_permission_ != PERMISSION::kAdminstrator) {
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
      if(0 != result)
        return result;
    } else {
      rlLOGXE(TAG, &v.raw_.header_, sizeof(v.raw_.header_), "RSA.Master.Decode Text %08X Failed!",
              (int)v.raw_.text_.file_magic_);
      return -EACCES;
    }
  } else if (size != sizeof(ScriptText)) {
    rlLOGE(TAG, "Invalid ScriptText %zd", size);
    return -EBADMSG;
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

    /**
     *!
     */
    if (vm.valid_permission_ != PERMISSION::kAdminstrator) {
      if (vm.dongle_->ReadDataFile(Dongle::kFactoryDataFileId,
                                   WorldPublic::kOffsetDataFile + WorldPublic::kOffsetPubkey_SM2ECIES, &ecies_pubkey,
                                   64) < 0)
        return -EBADF;

      if (vm.dongle_->SM3(vmdata + 256, 1024 - 256 - 64, sm3) < 0)
        return -EBADF;

      if (vm.dongle_->SM2Verify(&ecies_pubkey[0], &ecies_pubkey[32], sm3, &sign[0], &sign[32]) < 0)
        return -EBADF;

      if (vm.dongle_->SM2Sign(WorldPublic::kFileSM2ECIES, sm3, &sign[0], &sign[32]) < 0) /* Check SM2.ecies key */
        return -EBADF;

      if (vm.dongle_->SM2Verify(&ecies_pubkey[0], &ecies_pubkey[32], sm3, &sign[0], &sign[32]) < 0)
        return -EBADF;

      vm.valid_permission_ = PERMISSION::kAdminstrator; /* Granting privileges administrator */
    }
  } else {
    result = RockeyTrustDecryptData(vm, &v.text_, 1024 - 256);
    if(0 != result)
      return result;
  }

  if (0 != result)
    return result;

  if (v.text_.size_public_ > 1024) {
    rlLOGE(TAG, "Invalid Size.public %d", v.text_.size_public_);
    return -EBADMSG;
  }

  if (vm.valid_permission_ != PERMISSION::kAdminstrator) {
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

}  // namespace script
}  // namespace dongle

rLANG_DECLARE_END

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
    if (vm.valid_permission_ != PERMISSION::kAdministrator) {
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

      vm.valid_permission_ = PERMISSION::kAdministrator; /* Granting privileges administrator */
    }
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

#if !defined(__RockeyARM__)
constexpr char* StringFromHID(char hid_[26], const uint8_t v_[12]) {
  char* p = hid_;
  const uint8_t* v = v_;
  for (int i = 0; i < 12; ++i) {
    int c = *v++;
    int x = c >> 4;
    c &= 0x0F;

    if (i == 4)
      *p++ = '-';
    *p++ = (char)(x < 10 ? '0' + x : 'a' - 10 + x);
    *p++ = (char)(c < 10 ? '0' + c : 'a' - 10 + c);
  }
  *p = 0;

  return hid_;
}

constexpr char* StringFromKID(char kid_[7], const uint8_t v_[3]) {
  char* p = kid_;
  const uint8_t* v = v_;

  for (int i = 0; i < 3; ++i) {
    int c = *v++;
    int x = c >> 4;
    c &= 0x0F;

    *p++ = (char)(x < 10 ? '0' + x : 'a' - 10 + x);
    *p++ = (char)(c < 10 ? '0' + c : 'a' - 10 + c);
  }
  *p = 0;

  return kid_;
}
#endif /* !defined(__RockeyARM__) */

constexpr bool IsEmptyHid(const uint8_t v_[12]) {
  for (int i = 0; i < 12; ++i) {
    if (v_[i])
      return false;
  }
  return true;
}

static int RockeyUpdateECIESKey(Dongle* dongle, void* InOutBuf, void* ExtendBuf, const uint8_t* X_Y_K);
static int RockeyCreateEnTrust(Dongle* dongle, void* data, void* buffer, uint8_t* X_Y_K, EnTrustRequest& req);

rLANGEXPORT int rLANGAPI RockeyTrustExecuteCreateEnTrust(VM_t& vm, void* InOutBuf /* 1024 */, void* ExtendBuf) {
  EnTrustRequest request;
  if (vm.valid_permission_ != PERMISSION::kAdministrator) {
    rlLOGE(TAG, "EACCES: Adminstrator requirement, RockeyTrustExecuteCreateEnTrust!");
    return -EACCES;
  }

  memcpy(&request, (uint8_t*)InOutBuf + EnTrustRequest::kOffsetInOutBuffer, sizeof(request));
  memset(InOutBuf, 0, 1024); /* */

  if (request.kWorldMagic != rLANG_WORLD_MAGIC || request.kTrustMagic != EnTrustRequest::kEnTrustRequestMagic) {
    rlLOGE(TAG, "EINVAL: Invalid Magic %08X, %08X", request.kWorldMagic, request.kTrustMagic);
    return -EINVAL;
  }

  int error = 0, entrust_count = 0;
  rlLOGI(TAG, "EnTrust::CheckKeys ...");

  for (size_t i = 0; i < EnTrustRequest::kMaxKeys; ++i) {
    const auto& entrust = request.dongle_entrust_[i];
    if (IsEmptyHid(entrust.hid_)) {
      rlLOGW(TAG, "  EnTrust.Keys[%zd]: N/A", i);
      continue;
    }
#if !defined(__RockeyARM__)
    char hid_[26], kid_[7], sid_[160];
    StringFromHID(hid_, entrust.hid_);
    StringFromKID(kid_, entrust.kid_);
    rl_BASE64_Write(sid_, (uint8_t*)&entrust, sizeof(entrust));
#endif /* !defined(__RockeyARM__) */

    if (0 != entrust.zero_) {
      rlLOGE(TAG, "EINVAL: EnTrust.Keys[%zd], EnTrust.Zero_(%d) != 0, hid: %s, kid: %s, %s", i, entrust.zero_, hid_,
             kid_, sid_);
      ++error;
    } else if (0 != vm.dongle_->CheckPointOnCurveSM2(&entrust.point_[0], &entrust.point_[32])) {
      rlLOGE(TAG, "EINVAL: EnTrust.Keys[%zd], CheckPointOnCurveSM2 != 0, hid: %s, kid: %s, %s", i, hid_, kid_, sid_);
      ++error;
    } else {
      rlLOGI(TAG, "EnTrust.Keys[%zd], CheckPointOnCurveSM2 OK, hid: %s, kid: %s, %s", i, hid_, kid_, sid_);
      ++entrust_count;
    }
  }

  if (0 != error) {
    rlLOGE(TAG, "EINVAL Error: %d, Count: %d", error, entrust_count);
    return -EINVAL;
  } else {
    rlLOGI(TAG, "EnTrust::Keys::Count %d", entrust_count);
  }

  int check_master = RockeyTrustExecuteCheckMaster(vm.dongle_, InOutBuf, ExtendBuf);
  rlLOGI(TAG, "RockeyTrustExecuteCheckMaster: %d", check_master);
  if (0 != check_master)
    return check_master;

  uint8_t* X_Y_K = &vm.text_as_buffer_[0];
  int result = vm.dongle_->GenerateSM2(WorldPublic::kFileSM2ECIES, &X_Y_K[0], &X_Y_K[32], &X_Y_K[64]);
  if (0 != result)
    return result;

  result = RockeyUpdateECIESKey(vm.dongle_, InOutBuf, ExtendBuf, X_Y_K);
  if (0 != result)
    return result;

  result = RockeyCreateEnTrust(vm.dongle_, InOutBuf, ExtendBuf, X_Y_K, request);
  rlLOGI(TAG, "RockeyCreateEnTrust return %d", result);
  memset(vm.text_, 0, sizeof(vm.text_));
  if (0 != result)
    return result;

  result = RockeyTrustExecuteCheckEnTrust(vm.dongle_, InOutBuf, ExtendBuf, true);
  if (0 != result)
    return result;

  return vm.dongle_->ReadDataFile(Dongle::kFactoryDataFileId, WorldEnTrust::kOffsetDataFile, InOutBuf, 1024);
}

static int RockeyUpdateECIESKey(Dongle* dongle, void* InOutBuf, void* ExtendBuf, const uint8_t* X_Y_K) {
  auto* world = static_cast<WorldPublic*>(InOutBuf);
  int result = dongle->ReadDataFile(Dongle::kFactoryDataFileId, WorldPublic::kOffsetDataFile, world, sizeof(*world));
  if (0 != result)
    return result;

  memcpy(world->dongle_sm2ecies_pubkey_, X_Y_K, 64);
  result = dongle->SM3(InOutBuf, WorldPublic::kOffsetSign_SM2ECIES, &world->dongle_sm2ecies_sign_[0]);
  if (0 != result)
    return result;

  result = dongle->SM2Sign(WorldPublic::kFileSM2ECIES, &world->dongle_sm2ecies_sign_[0],
                           &world->dongle_sm2ecies_sign_[0], &world->dongle_sm2ecies_sign_[32]);
  if (0 != result)
    return result;

  size_t size = 32;
  result = dongle->SHA256(InOutBuf, WorldPublic::kOffsetSign_RSA2048, &world->dongle_rsa2048_sign_[0]);
  if (0 != result)
    return result;

  result = dongle->RSAPrivate(WorldPublic::kFileRSA2048, &world->dongle_rsa2048_sign_[0], &size, true);
  if (0 != result || size != 256)
    return -EBADF;

  result = dongle->SHA256(InOutBuf, WorldPublic::kOffsetSign_Secp256r1, &world->dongle_secp256r1_sign_[0]);
  if (0 != result)
    return result;

  result = dongle->P256Sign(WorldPublic::kFileSECP256r1, &world->dongle_secp256r1_sign_[0],
                            &world->dongle_secp256r1_sign_[0], &world->dongle_secp256r1_sign_[32]);
  if (0 != result)
    return result;

  result = dongle->SM3(InOutBuf, WorldPublic::kOffsetSign_SM2ECDSA, &world->dongle_sm2ecdsa_sign_[0]);
  if (0 != result)
    return result;

  result = dongle->SM2Sign(WorldPublic::kFileSM2ECDSA, &world->dongle_sm2ecdsa_sign_[0],
                           &world->dongle_sm2ecdsa_sign_[0], &world->dongle_sm2ecdsa_sign_[32]);
  if (0 != result)
    return result;

  rlLOGW(TAG, "SM2ECIES.MasterKey Update OK!");
  result = dongle->WriteDataFile(Dongle::kFactoryDataFileId, WorldPublic::kOffsetDataFile, world, sizeof(*world));
  if (0 != result)
    return result;

  return RockeyTrustExecuteCheckMaster(dongle, InOutBuf, ExtendBuf);
}

rLANGEXPORT int rLANGAPI RockeyTrustExecuteCheckMaster(Dongle* dongle, void* InOutBuf /* 1024 */, void* ExtendBuf) {
  size_t size;
  uint8_t hash[32];
  DONGLE_INFO info;
  WorldPublic* world = static_cast<WorldPublic*>(InOutBuf);
  int result = dongle->ReadDataFile(Dongle::kFactoryDataFileId, WorldPublic::kOffsetDataFile, world, sizeof(*world));
  if (0 != result)
    return result;

  if (world->header_.world_magic_ != rLANG_WORLD_MAGIC) {
    rlLOGE(TAG, "EBADF, WorldMagic %08X", world->header_.world_magic_);
    return -EBADF;
  }

  result = dongle->GetDongleInfo(&info);
  if (0 != result)
    return result;

  if (0 != memcmp(&info, &world->dongle_info_, sizeof(info))) {
    rlLOGE(TAG, "EBADF: Invalid DONGLE_INFO!");
    return -EBADF;
  }

  if (world->header_.reserved_0_ != 0 || world->header_.reserved_1_ != 0 ||
      world->header_.ver_major_ != rLANG_DONGLE_VERSION_MAJOR ||
      world->header_.ver_minor_ != rLANG_DONGLE_VERSION_MINOR || world->header_.siz_public_ != sizeof(WorldPublic)) {
    rlLOGE(TAG, "EBADF, Header [%d,%d], Ver [%d.%d], Size: %d", world->header_.reserved_0_, world->header_.reserved_1_,
           world->header_.ver_major_, world->header_.ver_minor_, world->header_.siz_public_);
    return -EBADF;
  }

  result = dongle->CheckPointOnCurveSM2(&world->dongle_sm2ecdsa_pubkey_[0], &world->dongle_sm2ecdsa_pubkey_[32]);
  if (0 != result) {
    rlLOGE(TAG, "EBADF, SM2ECDSA.CheckPointOnCurveSM2 Failed %d!", result);
    return result;
  }

  result = dongle->CheckPointOnCurveSM2(&world->dongle_sm2ecies_pubkey_[0], &world->dongle_sm2ecies_pubkey_[32]);
  if (0 != result) {
    rlLOGE(TAG, "EBADF, SM2ECDSA.CheckPointOnCurveSM2 Failed %d!", result);
    return result;
  }

  result =
      dongle->CheckPointOnCurvePrime256v1(&world->dongle_secp256r1_pubkey_[0], &world->dongle_secp256r1_pubkey_[32]);
  if (0 != result) {
    rlLOGE(TAG, "EBADF, CheckPointOnCurvePrime256v1 Failed %d!", result);
    return result;
  }

  uint32_t RSA_Modules = 0;
  const uint8_t* RSA = &world->dongle_rsa2048_pubkey_[0];
  for (int i = 0; i < 4; ++i)
    RSA_Modules |= RSA[i] << (8 * i);

  if (0 == RSA_Modules || 0 == (RSA[4] | RSA[5] | RSA[6] | RSA[7])) {
    rlLOGXE(TAG, RSA, 16, "EBADF, Invalid RSA2048 Pubkey!");
    return -EBADF;
  }

  result = dongle->SM3(InOutBuf, WorldPublic::kOffsetSign_SM2ECDSA, hash);
  if (0 != result)
    return result;

  result = dongle->SM2Verify(&world->dongle_sm2ecdsa_pubkey_[0], &world->dongle_sm2ecdsa_pubkey_[32], hash,
                             &world->dongle_sm2ecdsa_sign_[0], &world->dongle_sm2ecdsa_sign_[32]);
  if (0 != result)
    return result;

  result = dongle->SM3(InOutBuf, WorldPublic::kOffsetSign_SM2ECIES, hash);
  if (0 != result)
    return result;

  result = dongle->SM2Verify(&world->dongle_sm2ecies_pubkey_[0], &world->dongle_sm2ecies_pubkey_[32], hash,
                             &world->dongle_sm2ecies_sign_[0], &world->dongle_sm2ecies_sign_[32]);
  if (0 != result)
    return result;

  result = dongle->SHA256(InOutBuf, WorldPublic::kOffsetSign_Secp256r1, hash);
  if (0 != result)
    return result;

  result = dongle->P256Verify(&world->dongle_secp256r1_pubkey_[0], &world->dongle_secp256r1_pubkey_[32], hash,
                              &world->dongle_secp256r1_sign_[0], &world->dongle_secp256r1_sign_[32]);
  if (0 != result)
    return result;

  result = dongle->SHA256(InOutBuf, WorldPublic::kOffsetSign_RSA2048, hash);
  if (0 != result)
    return result;

  size = 256;
  result = dongle->RSAPublic(2048, RSA_Modules, &RSA[4], &world->dongle_rsa2048_sign_[0], &size, false);
  if (0 != result || size != 32 || 0 != memcmp(hash, &world->dongle_rsa2048_sign_[0], 32)) {
    rlLOGE(TAG, "RSA2048.Verify Error %d, %zd!", result, size);
    return -EBADF;
  }

  rlLOGI(TAG, "RockeyTrustExecuteCheckMaster public.check OK!");

  result = dongle->RSAPublic(2048, RSA_Modules, &RSA[4], &world->dongle_rsa2048_sign_[0], &size, true);
  if (0 != result)
    return result;

  result = dongle->RSAPrivate(WorldPublic::kFileRSA2048, &world->dongle_rsa2048_sign_[0], &size, false);
  if (0 != result || size != 32 || 0 != memcmp(hash, &world->dongle_rsa2048_sign_[0], 32)) {
    rlLOGE(TAG, "RSA2048.Decrypt Error %d, %zd!", result, size);
    return -EBADF;
  }

  result = dongle->SM2Sign(WorldPublic::kFileSM2ECDSA, hash, &world->dongle_sm2ecdsa_sign_[0],
                           &world->dongle_sm2ecdsa_sign_[32]);
  if (0 != result)
    return result;

  result = dongle->SM2Verify(&world->dongle_sm2ecdsa_pubkey_[0], &world->dongle_sm2ecdsa_pubkey_[32], hash,
                             &world->dongle_sm2ecdsa_sign_[0], &world->dongle_sm2ecdsa_sign_[32]);
  if (0 != result)
    return result;

  result = dongle->SM2Sign(WorldPublic::kFileSM2ECIES, hash, &world->dongle_sm2ecies_sign_[0],
                           &world->dongle_sm2ecies_sign_[32]);
  if (0 != result)
    return result;

  result = dongle->SM2Verify(&world->dongle_sm2ecies_pubkey_[0], &world->dongle_sm2ecies_pubkey_[32], hash,
                             &world->dongle_sm2ecies_sign_[0], &world->dongle_sm2ecies_sign_[32]);
  if (0 != result)
    return result;

  result = dongle->P256Sign(WorldPublic::kFileSECP256r1, hash, &world->dongle_secp256r1_sign_[0],
                            &world->dongle_secp256r1_sign_[32]);
  if (0 != result)
    return result;

  result = dongle->P256Verify(&world->dongle_secp256r1_pubkey_[0], &world->dongle_secp256r1_pubkey_[32], hash,
                              &world->dongle_secp256r1_sign_[0], &world->dongle_secp256r1_sign_[32]);
  if (0 != result)
    return result;

  rlLOGI(TAG, "RockeyTrustExecuteCheckMaster private.check OK!");
  return 0;
}

rLANGEXPORT int rLANGAPI RockeyTrustExecuteCheckEnTrust(Dongle* dongle, void* data, void* buffer, bool check_master) {
  uint8_t* const ecdsa_pubkey = (uint8_t*)buffer + 256;
  int result = RockeyTrustExecuteCheckMaster(dongle, data, buffer);
  if (0 != result)
    return result;

  memcpy(ecdsa_pubkey, (uint8_t*)data + WorldPublic::kOffsetPubkey_SM2ECDSA, 64);
  result = dongle->ReadDataFile(Dongle::kFactoryDataFileId, WorldEnTrust::kOffsetDataFile, data, 1024);
  if (0 != result)
    return result;

  auto* entrust = static_cast<WorldEnTrust*>(data);
  result = dongle->SM3(entrust, WorldEnTrust::kOffset_SM2ECDSASignature_, (uint8_t*)buffer);
  if (0 != result)
    return result;
  result = dongle->SM2Verify(ecdsa_pubkey, ecdsa_pubkey + 32, (uint8_t*)buffer, entrust->dongle_sm2ecdsa_sign_,
                             entrust->dongle_sm2ecdsa_sign_ + 32);
  if (0 != result)
    return result;

  rlLOGI(TAG, "ExecuteCheckEnTrust OK ... 1");
  if(!check_master)
    return 0;

  size_t size = sizeof(entrust->dongle_master_secret__);
  uint8_t* const MASTER_SECRET = (uint8_t*)buffer + 32;
  result = dongle->SM2Decrypt(WorldPublic::kFileSM2ECDSA, entrust->dongle_master_secret__,
                              sizeof(entrust->dongle_master_secret__), MASTER_SECRET, &size);
  if (0 != result) {
    rlLOGE(TAG, "SM2Decrypt MASTER_SECRET Failed %d!", result);
    return result;
  }

  memcpy(MASTER_SECRET - 28, entrust->nonce_, sizeof(entrust->nonce_));
  *(uint32_t*)buffer = WorldEnTrust::kEx25519Magic;
  result = dongle->SM3(buffer, 32 + 128, (uint8_t*)buffer);
  memset(MASTER_SECRET, 0, 128);
  if (0 != result)
    return result;

  result = dongle->ComputePubkeyCurve25519((uint8_t*)buffer, (uint8_t*)buffer);
  if (0 != result || 0 != memcmp(entrust->dongle__x25519_pubkey_, buffer, 32)) {
    rlLOGE(TAG, "MASTER_SECRET.CHECK Failed %d!", result);
    return -EFAULT;
  }

  rlLOGI(TAG, "ExecuteCheckEnTrust OK ... 2");
  return 0;
}

static int RockeyCreateEnTrust(Dongle* dongle, void* data, void* buffer, uint8_t* X_Y_K, EnTrustRequest& req) {
  int result = 0, error = 0;
  auto* entrust = static_cast<WorldEnTrust*>(data);

  memset(entrust, 0, sizeof(WorldEnTrust));
  entrust->header_.world_magic_ = req.kWorldMagic;
  entrust->header_.category_magic_ = req.kTrustMagic;
  entrust->header_.ver_major_ = rLANG_DONGLE_VERSION_MAJOR;
  entrust->header_.ver_minor_ = rLANG_DONGLE_VERSION_MINOR;
  entrust->header_.siz_public_ = sizeof(WorldEnTrust);

  uint8_t* const K = &X_Y_K[0];
  uint8_t* const cipher = &X_Y_K[32];
  memmove(K, &X_Y_K[64], 32);

#if 1
  result = dongle->RandBytes(&entrust->nonce_[0], sizeof(entrust->nonce_));
  if (0 != result)
    return result;
#else
  result = dongle->RandBytes((uint8_t*)&req, 8);
  if(0 != result)
    return result;
  result = dongle->SM3(&req, sizeof(EnTrustRequest), &X_Y_K[32]);
  if(0 != result)
    return result;
  memcpy(entrust->nonce_, &X_Y_K[32], 28);
#endif

  for (int i = 0; i < 5; ++i) {
    WorldEnTrust::EnTrustKey& ekey = entrust->dongle_entrust_[i];
    EnTrustRequest::EnTrustKey& ckey = req.dongle_entrust_[i];

    if (IsEmptyHid(ckey.hid_))
      continue;

    memcpy(ekey.hid_, ckey.hid_, 12);
    memcpy(ekey.kid_, ckey.kid_, 3);
    result = dongle->SM2Encrypt(&ckey.point_[0], &ckey.point_[32], K, 32, cipher);
    if (0 != result) {
      rlLOGE(TAG, "RockeyCreateEnTrust SM2Encrypt[%d] Error: %d", i, result);
      ++error;
    } else {
      memcpy(&ekey.cipher_[0], &cipher[0], 32);
      memcpy(&ekey.cipher_[32], &cipher[64], 64);
      ekey.Yodd_ = cipher[63] & 1;

      result = dongle->DecompressPointSM2((uint8_t*)buffer, cipher, ekey.Yodd_);
      if (0 != result || 0 != memcmp(&cipher[32], buffer, 32)) {
        rlLOGE(TAG, "RockeyCreateEnTrust DecompressPointSM2[%d] Error %d!", i, result);
        ++error;
      }
    }
  }

  if (0 != error) {
    rlLOGE(TAG, "RockeyCreateEnTrust EncryptECIES.PKey Error %d", error);
    return -EFAULT;
  }

  memcpy(&X_Y_K[4], entrust->nonce_, 28);       /// KDF[4] | NONCE[28] | MKEY[128] ...
  result = dongle->RandBytes(&X_Y_K[32], 128);  /// MASTER_SECRET ...
  if (0 != result)
    return result;

  result = dongle->ReadDataFile(Dongle::kFactoryDataFileId,
                                WorldPublic::kOffsetDataFile + WorldPublic::kOffsetPubkey_SM2ECDSA, buffer, 64);
  if (0 != result)
    return result;

  result =
      dongle->SM2Encrypt((uint8_t*)buffer, (uint8_t*)buffer + 32, &X_Y_K[32], 128, entrust->dongle_master_secret__);
  if (0 != result)
    return result;

  result = dongle->WriteDataFile(Dongle::kFactoryDataFileId, WorldEnTrust::kOffsetDataFile, data, 1024);
  if (0 != result)
    return result;

  *(uint32_t*)X_Y_K = WorldEnTrust::kEd25519Magic;
  result = dongle->SM3(&X_Y_K[0], 160, &X_Y_K[160]);
  if (0 != result)
    return result;

  *(uint32_t*)X_Y_K = WorldEnTrust::kEx25519Magic;
  result = dongle->SM3(&X_Y_K[0], 160, &X_Y_K[32]);
  if (0 != result)
    return result;

  memcpy(&X_Y_K[0], &X_Y_K[160], 32);
  memset(&X_Y_K[64], 0, 200 - 64);

  result = dongle->ComputePubkeyCurve25519(&X_Y_K[96], &X_Y_K[32]);
  if (0 != result)
    return result;

  result = dongle->ComputePubkeyEd25519(buffer, &X_Y_K[64], &X_Y_K[0]);
  if (0 != result)
    return result;

  /// || Ed25519.PKEY[32] | X25519.PKEY[32] | Ed25519.Pubkey[32] | X25519.Pubkey[32] ||
  result = dongle->ReadDataFile(Dongle::kFactoryDataFileId, WorldEnTrust::kOffsetDataFile, data, 1024);
  if (0 != result)
    return result;

  memcpy(entrust->dongle_ed25519_pubkey_, &X_Y_K[64], 32);
  memcpy(entrust->dongle__x25519_pubkey_, &X_Y_K[96], 32);
  result = dongle->WriteDataFile(Dongle::kFactoryDataFileId, WorldEnTrust::kOffsetDataFile, data, 1024);
  if (0 != result)
    return result;

  result = dongle->SHA512(entrust, WorldEnTrust::kOffset_Ed25519Signature_, &X_Y_K[128]);
  if (0 != result)
    return result;

  result = dongle->SignMessageEd25519(buffer, &X_Y_K[128], &X_Y_K[128], 64, &X_Y_K[64], &X_Y_K[0]);
  if (0 != result)
    return result;

  result = dongle->ReadDataFile(Dongle::kFactoryDataFileId, WorldEnTrust::kOffsetDataFile, data, 1024);
  if (0 != result)
    return result;

  memcpy(entrust->dongle_ed25519_sign_, &X_Y_K[128], 64);
  result = dongle->SM3(entrust, WorldEnTrust::kOffset_SM2ECDSASignature_, entrust->dongle_sm2ecdsa_sign_);
  if (0 != result)
    return result;
  result = dongle->SM2Sign(WorldPublic::kFileSM2ECDSA, entrust->dongle_sm2ecdsa_sign_,
                           &entrust->dongle_sm2ecdsa_sign_[0], &entrust->dongle_sm2ecdsa_sign_[32]);
  if (0 != result)
    return result;

  return dongle->WriteDataFile(Dongle::kFactoryDataFileId, WorldEnTrust::kOffsetDataFile, data, 1024);
}

}  // namespace script
}  // namespace dongle

rLANG_DECLARE_END

#include "script.h"

rLANG_DECLARE_MACHINE

namespace dongle {
namespace script {

constexpr int kSizeDashboard = 8 * 1024;
constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("k@mgr");

int VM_t::OpManager_WorldInitialize() {
  uint8_t init[256];
  memset(init, 0, sizeof(init));

  int error = 0;
  dongle_->DeleteFile(SECRET_STORAGE_TYPE::kSM2, kKeyIdGlobalSM2ECDSA);
  dongle_->DeleteFile(SECRET_STORAGE_TYPE::kSM2, kKeyIdGlobalSM2ECIES);
  dongle_->DeleteFile(SECRET_STORAGE_TYPE::kP256, kKeyIdGlobalP256ECDSA);
  dongle_->DeleteFile(SECRET_STORAGE_TYPE::kRSA, kKeyIdGlobalRSA2048);
  dongle_->DeleteFile(SECRET_STORAGE_TYPE::kData, kKeyIdGlobalSECRET);
  dongle_->WriteShareMemory(init);

  for (int off = 0; off < kSizeDashboard; off += sizeof(init)) {
    if (0 != dongle_->WriteDataFile(Dongle::kFactoryDataFileId, off, init, sizeof(init)))
      ++error;
  }

  if (error) {
    rlLOGE(TAG, "Initialize Factory DataFile Error %d", error);
    return -EFAULT;
  }

  return 0;
}

int VM_t::OpManager_VerifyWorldPublic() {
  size_t size;
  uint8_t hash[32];
  DONGLE_INFO info;
  auto* const dongle = dongle_;
  WorldPublic world_public_, *const world = &world_public_;
  int result = dongle_->ReadDataFile(Dongle::kFactoryDataFileId, WorldPublic::kOffsetDataFile, &world_public_,
                                     sizeof(world_public_));
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

  result = dongle->SM3(world, WorldPublic::kOffsetSign_SM2ECDSA, hash);
  if (0 != result)
    return result;

  result = dongle->SM2Verify(&world->dongle_sm2ecdsa_pubkey_[0], &world->dongle_sm2ecdsa_pubkey_[32], hash,
                             &world->dongle_sm2ecdsa_sign_[0], &world->dongle_sm2ecdsa_sign_[32]);
  if (0 != result)
    return result;

  result = dongle->SM3(world, WorldPublic::kOffsetSign_SM2ECIES, hash);
  if (0 != result)
    return result;

  result = dongle->SM2Verify(&world->dongle_sm2ecies_pubkey_[0], &world->dongle_sm2ecies_pubkey_[32], hash,
                             &world->dongle_sm2ecies_sign_[0], &world->dongle_sm2ecies_sign_[32]);
  if (0 != result)
    return result;

  result = dongle->SHA256(world, WorldPublic::kOffsetSign_Secp256r1, hash);
  if (0 != result)
    return result;

  result = dongle->P256Verify(&world->dongle_secp256r1_pubkey_[0], &world->dongle_secp256r1_pubkey_[32], hash,
                              &world->dongle_secp256r1_sign_[0], &world->dongle_secp256r1_sign_[32]);
  if (0 != result)
    return result;

  result = dongle->SHA256(world, WorldPublic::kOffsetSign_RSA2048, hash);
  if (0 != result)
    return result;

  size = 256;
  result = dongle->RSAPublic(2048, RSA_Modules, &RSA[4], &world->dongle_rsa2048_sign_[0], &size, false);
  if (0 != result || size != 32 || 0 != memcmp(hash, &world->dongle_rsa2048_sign_[0], 32)) {
    rlLOGE(TAG, "RSA2048.Verify Error %d, %zd!", result, size);
    return -EBADF;
  }

  rlLOGI(TAG, "kVerifyWorldPublic public.check OK!");

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

  rlLOGI(TAG, "kVerifyWorldPublic private.check OK!");

  uint8_t MASTER_SECRET[kSize_MASTER_SECRET];
  result = READ_MASTER_SECRET(MASTER_SECRET);
  memset(MASTER_SECRET, 0, sizeof(MASTER_SECRET));

  if (0 != result) {
    rlLOGE(TAG, "VERIFY.MASTER_SECRET Failed %d!", result);
    return result;
  }

  rlLOGI(TAG, "kVerifyWorldPublic MASTER_SECRET.check OK!");

  return 0;
}

int VM_t::OpManager_UpdateSM2ECIESKey(uint8_t public_[64], uint8_t* private_) {
  WorldPublic world_public_;
  int result = dongle_->ReadDataFile(Dongle::kFactoryDataFileId, WorldPublic::kOffsetDataFile, &world_public_,
                                     sizeof(world_public_));
  if (0 != result)
    return result;

  result = dongle_->GenerateSM2(WorldPublic::kFileSM2ECIES, &public_[0], &public_[32], private_);
  if (0 != result)
    return result;

  memcpy(&world_public_.dongle_sm2ecies_pubkey_[0], public_, 64);
  result = dongle_->SM3(&world_public_, WorldPublic::kOffsetSign_SM2ECIES, &world_public_.dongle_sm2ecies_sign_[0]);
  if (0 != result)
    return result;

  result = dongle_->SM2Sign(WorldPublic::kFileSM2ECIES, &world_public_.dongle_sm2ecies_sign_[0],
                            &world_public_.dongle_sm2ecies_sign_[0], &world_public_.dongle_sm2ecies_sign_[32]);
  if (0 != result)
    return result;

  result = dongle_->SHA256(&world_public_, WorldPublic::kOffsetSign_RSA2048, &world_public_.dongle_rsa2048_sign_[0]);
  if (0 != result)
    return result;

  size_t size = 32;
  result = dongle_->RSAPrivate(WorldPublic::kFileRSA2048, &world_public_.dongle_rsa2048_sign_[0], &size, true);
  if (0 != result)
    return result;

  result =
      dongle_->SHA256(&world_public_, WorldPublic::kOffsetSign_Secp256r1, &world_public_.dongle_secp256r1_sign_[0]);
  if (0 != result)
    return result;

  result = dongle_->P256Sign(WorldPublic::kFileSECP256r1, &world_public_.dongle_secp256r1_sign_[0],
                             &world_public_.dongle_secp256r1_sign_[0], &world_public_.dongle_secp256r1_sign_[32]);
  if (0 != result)
    return result;

  result = dongle_->SM3(&world_public_, WorldPublic::kOffsetSign_SM2ECDSA, &world_public_.dongle_sm2ecdsa_sign_[0]);
  if (0 != result)
    return result;

  result = dongle_->SM2Sign(WorldPublic::kFileSM2ECDSA, &world_public_.dongle_sm2ecdsa_sign_[0],
                            &world_public_.dongle_sm2ecdsa_sign_[0], &world_public_.dongle_sm2ecdsa_sign_[32]);
  if (0 != result)
    return result;

  result = dongle_->WriteDataFile(Dongle::kFactoryDataFileId, WorldPublic::kOffsetDataFile, &world_public_,
                                  sizeof(world_public_));
  if (0 != result)
    return result;
  return 0;
}

int VM_t::OpManager_UpdateMasterSecret() {
  uint8_t MASTER_SECRET[kSize_MASTER_SECRET];
  int result = dongle_->RandBytes(MASTER_SECRET, sizeof(MASTER_SECRET));
  if (0 != result)
    return result;

  result = WRITE_MASTER_SECRET(MASTER_SECRET);
  memset(MASTER_SECRET, 0, sizeof(MASTER_SECRET));
  return result;
}

int VM_t::OpManager_ComputeSecretBytes(uint8_t* bytes_, int32_t type) {
  struct Context {
    DONGLE_INFO info_;
    uint32_t seed_0_;
    uint32_t bytes_[16];
    uint32_t seed_1_;
    uint8_t MASTER_SECRET[kSize_MASTER_SECRET];
    uint32_t seed_2_;
    uint32_t type_;
    uint32_t seed_3_;
  };

  int result = 0, error = 0;
  Context MASTER_SECRET_CONTEXT = {};

  /**
   *!
   */
  MASTER_SECRET_CONTEXT.type_ = type;
  memcpy(MASTER_SECRET_CONTEXT.bytes_, bytes_, 64);
  rlLOGI(TAG, "OpManager_ComputeSecretBytes %02X %d!", bytes_[0], type);
  if (0 != READ_MASTER_SECRET(MASTER_SECRET_CONTEXT.MASTER_SECRET))
    ++error;

  if (0 == type) {
    MASTER_SECRET_CONTEXT.seed_0_ = rLANG_WORLD_SEED_0;
    MASTER_SECRET_CONTEXT.seed_1_ = rLANG_WORLD_SEED_1;
    MASTER_SECRET_CONTEXT.seed_2_ = rLANG_WORLD_SEED_2;
    MASTER_SECRET_CONTEXT.seed_3_ = rLANG_WORLD_SEED_3;

    dongle_->LocalChaos(MASTER_SECRET_CONTEXT.bytes_);
    result = dongle_->GetDongleInfo(&MASTER_SECRET_CONTEXT.info_);
    if (0 != result)
      ++error;
  } else {
    MASTER_SECRET_CONTEXT.seed_0_ = 0;
    MASTER_SECRET_CONTEXT.seed_1_ = rLANG_WORLD_MAGIC;
    MASTER_SECRET_CONTEXT.seed_2_ = rLANG_ATOMC_WORLD_MAGIC;
    MASTER_SECRET_CONTEXT.seed_3_ = rLANG_COSMO_WORLD_MAGIC;
  }

  if (0 != dongle_->SHA512(&MASTER_SECRET_CONTEXT, sizeof(MASTER_SECRET_CONTEXT), bytes_))
    ++error;
  memset(&MASTER_SECRET_CONTEXT, 0, sizeof(MASTER_SECRET_CONTEXT));
  if (0 != result || 0 != error)
    return -EFAULT;
  return 0;
}

int VM_t::OpManager_ComputeEnTrustData(int argc, int32_t argv[]) {
  constexpr int kSizeLimit = 64;
  if (argc != 3)
    return zero_ = -EINVAL;

  int input_length = argv[2];
  if (input_length < 16 || input_length > kSizeLimit)
    return zero_ = -EINVAL;
  const uint8_t* input_bytes = (const uint8_t*)OpCheckMM(argv[1], input_length);
  if (!input_bytes)
    return zero_ = SIGSEGV;

  int output_length = 80 + input_length;
  uint8_t* InOutBuff = (uint8_t*)OpCheckMM(argv[0], output_length);
  if (!InOutBuff)
    return zero_ = SIGSEGV;

  auto CheckHid = [this](const uint8_t* key) {
    /* || hid[12] | kid[3] | Zero | X[32] | Y[32] || */
    uint8_t value = 0;
    for (int i = 0; i < 12; ++i)
      value |= key[i];
    if (0 == value)
      return 0;
    if (key[15] != 0)
      return 2;
    int result = dongle_->CheckPointOnCurveSM2(&key[16], &key[48]);
    if (0 != result)
      return 2;
    return 1;
  };

  int result = CheckHid(InOutBuff);
  if (result > 1)
    return zero_ = -EINVAL;

  if (0 == result) {
    memset(InOutBuff, 0, output_length);
    return 0;
  }

  uint8_t OutputBuffer[kSizeLimit + 96];
  result = dongle_->SM2Encrypt(&InOutBuff[16], &InOutBuff[48], input_bytes, input_length, OutputBuffer);
  if (0 != result)
    return zero_ = result;

  /* || hid[12] | kid[3] | Yodd | X[32] | H[32] | XOR[length] || */
  InOutBuff[15] = OutputBuffer[63] & 1;
  memcpy(&InOutBuff[16], &OutputBuffer[0], 32);
  memcpy(&InOutBuff[48], &OutputBuffer[64], 32 + input_length);

  result = dongle_->DecompressPointSM2(&OutputBuffer[64], &InOutBuff[16], InOutBuff[15]);
  if (0 != result)
    return zero_ = result;
  if (0 != memcmp(&OutputBuffer[64], &OutputBuffer[32], 32))
    return zero_ = -EFAULT;
  return 0;
}

int VM_t::OpManager(uint16_t op, int argc, int32_t argv[]) {
  if (valid_permission_ != PERMISSION::kAdministrator)
    return zero_ = -EACCES;
  std::ignore = TAG;

  cycles_ -= 64 * 1024;
  if (op == OpCode::kWorldInitialize) {
    if (0 != argc)
      return zero_ = -EINVAL;
    return zero_ = OpManager_WorldInitialize();
  } else if (op == OpCode::kVerifyWorldPublic) {
    if (0 != argc)
      return zero_ = -EINVAL;
    return zero_ = OpManager_VerifyWorldPublic();
  } else if (op == OpCode::kUpdateSM2ECIESKey) {
    if (argc != 1 && argc != 2)
      return zero_ = -EINVAL;
    uint8_t* public_ = (uint8_t*)OpCheckMM(argv[0], 64);
    uint8_t* private_ = nullptr;
    if (argc == 2 && !(private_ = (uint8_t*)OpCheckMM(argv[1], 32)))
      return zero_ = SIGSEGV;
    return zero_ = OpManager_UpdateSM2ECIESKey(public_, private_);
  } else if (op == OpCode::kUpdateMasterSecret) {
    if (0 != argc)
      return zero_ = -EINVAL;
    return zero_ = OpManager_UpdateMasterSecret();
  } else if (op == OpCode::kComputeSecretBytes) {
    if (1 != argc && 2 != argc)
      return zero_ = -EINVAL;
    int32_t type = argc == 2 ? argv[1] : 0;
    uint8_t* bytes_ = (uint8_t*)OpCheckMM(argv[0], 64);
    if (!bytes_)
      return zero_ = SIGSEGV;
    return zero_ = OpManager_ComputeSecretBytes(bytes_, type);
  } else if (op == OpCode::kComputeEnTrustData) {
    return zero_ = OpManager_ComputeEnTrustData(argc, argv);
  } else {
    return zero_ = SIGILL;
  }
}

}  // namespace script
}  // namespace dongle

rLANG_DECLARE_END

#include "script.h"

rLANG_DECLARE_MACHINE

/**
 *!
 */
#ifndef rLANG_WORLD_SECRET_SEED_0
#define rLANG_WORLD_SECRET_SEED_0 0
#endif /* rLANG_WORLD_SECRET_SEED_0 */

#ifndef rLANG_WORLD_SECRET_SEED_1
#define rLANG_WORLD_SECRET_SEED_1 0
#endif /* rLANG_WORLD_SECRET_SEED_1 */

#ifndef rLANG_WORLD_SECRET_SEED_2
#define rLANG_WORLD_SECRET_SEED_2 0
#endif /* rLANG_WORLD_SECRET_SEED_2 */

#ifndef rLANG_WORLD_SECRET_SEED_3
#define rLANG_WORLD_SECRET_SEED_3 0
#endif /* rLANG_WORLD_SECRET_SEED_3 */

#if 0 == rLANG_WORLD_SECRET_SEED_0 || 0 == rLANG_WORLD_SECRET_SEED_1 || 0 == rLANG_WORLD_SECRET_SEED_2 || \
    0 == rLANG_WORLD_SECRET_SEED_3
#error "Configure rLANG_WORLD_SECRET_SEED[0...3]"
#endif /* Makefile */

namespace dongle {

constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("sec@k");

static void InitializeCipherState(uint32_t cipher[16]) {
  cipher[0] = (uint32_t)rLANG_WORLD_SEED_0 + (uint32_t)rLANG_WORLD_SECRET_SEED_0;
  cipher[1] = (uint32_t)rLANG_WORLD_SEED_1 + (uint32_t)rLANG_WORLD_SECRET_SEED_2;
  cipher[2] = (uint32_t)rLANG_WORLD_SEED_2 + (uint32_t)rLANG_WORLD_SECRET_SEED_1;
  cipher[3] = (uint32_t)rLANG_WORLD_SEED_3 + (uint32_t)rLANG_WORLD_SECRET_SEED_3;

  cipher[4] = (uint32_t)rLANG_WORLD_SEED_0;
  cipher[5] = (uint32_t)rLANG_WORLD_SEED_1;
  cipher[6] = (uint32_t)rLANG_WORLD_SEED_2;
  cipher[7] = (uint32_t)rLANG_WORLD_SEED_3;

  cipher[8] = (uint32_t)rLANG_WORLD_SEED_1 ^ (uint32_t)rLANG_WORLD_SECRET_SEED_3;
  cipher[9] = (uint32_t)rLANG_WORLD_SEED_3 ^ (uint32_t)rLANG_WORLD_SECRET_SEED_1;
  cipher[10] = (uint32_t)rLANG_WORLD_SEED_2 ^ (uint32_t)rLANG_WORLD_SECRET_SEED_2;
  cipher[11] = (uint32_t)rLANG_WORLD_SEED_0 ^ (uint32_t)rLANG_WORLD_SECRET_SEED_0;

  cipher[12] = (uint32_t)rLANG_WORLD_SECRET_SEED_0;
  cipher[13] = (uint32_t)rLANG_WORLD_SECRET_SEED_0;
  cipher[14] = (uint32_t)rLANG_WORLD_SECRET_SEED_0;
  cipher[15] = (uint32_t)rLANG_WORLD_SECRET_SEED_0;
}

int Dongle::SeedBytes(const void* buffer, size_t size) {
  uint32_t cipher[16];
  InitializeCipherState(cipher);

  Sha512Ctx()
      .Init()
      .Update(cipher, sizeof(cipher))
      .Update(entropy_local_, sizeof(entropy_local_))
      .Update(buffer, size)
      .Final((uint8_t*)entropy_local_);
  return 0;
}

void Dongle::LocalChaos(uint32_t state[16], uint8_t loop) {
  union {
    uint8_t stream[64];
    uint32_t cipher[16];
  };
  InitializeCipherState(cipher);

  {
    union {
      DONGLE_INFO info;
      uint32_t ival_[10];
      uint8_t sm3_[32];
    } V;
    memset(&V, 0, sizeof(V));
    if (Ready()) {
      GetDongleInfo(&V.info);
      SM3(&V, sizeof(V), V.sm3_);
    }
    for (int i = 0; i < 10; ++i)
      cipher[i] += V.ival_[i];
  }

  for (int ii = 0; ii < loop; ++ii) {
    for (int i = 0; i < 16; ++i)
      cipher[i] += state[15 - i];
    rlCryptoChaCha20Block(cipher, stream);
    for (int i = 0; i < 16; ++i)
      state[i] ^= cipher[i];
  }
}

void Dongle::InitializeEntropyLocal() {
  uint32_t cipher[16];
  InitializeCipherState(cipher);
  LocalChaos(cipher, 10);
  for (int i = 0; i < 16; ++i)
    entropy_local_[i] ^= cipher[i];
  memset(cipher, 0, sizeof(cipher));
}

namespace script {

static void MASTER_SECRET_PROCESS(uint8_t ENCRYPT_MASTER_SECRET[256], Dongle* dongle) {
  union {
    uint8_t stream[64];
    uint32_t cipher[16];
  };
  uint8_t* p = ENCRYPT_MASTER_SECRET;
  InitializeCipherState(cipher);
  dongle->LocalChaos(cipher, 2);
  for (int i = 0; i < 4; ++i) {
    rlCryptoChaCha20Block(cipher, stream);
    for (int i = 0; i < 64; ++i)
      p[i] ^= stream[i];
    p += 64;
  }
  memset(cipher, 0, sizeof(cipher));
}

int VM_t::READ_MASTER_SECRET(uint8_t MASTER_SECRET[64]) {
  uint8_t ENCRYPT_MASTER_SECRET[256];
  int result = dongle_->ReadDataFile(kKeyIdGlobalSECRET, 0, ENCRYPT_MASTER_SECRET, sizeof(ENCRYPT_MASTER_SECRET));
  if (0 != result) {
    rlLOGE(TAG, "kFactoryDataFileId.Read Failed %d!", result);
    return result;
  }

  size_t size = 256;
  MASTER_SECRET_PROCESS(ENCRYPT_MASTER_SECRET, dongle_);
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

  MASTER_SECRET_PROCESS(ENCRYPT_MASTER_SECRET, dongle_);
  result = dongle_->WriteDataFile(kKeyIdGlobalSECRET, 0, &ENCRYPT_MASTER_SECRET[0], 256);
  if (0 != result) {
    rlLOGE(TAG, "kKeyIdGlobalSECRET.Write Failed %d!", result);
    dongle_->DeleteFile(SECRET_STORAGE_TYPE::kData, kKeyIdGlobalSECRET);
    return result;
  }

  return result;
}

}  // namespace script
}  // namespace dongle

rLANG_DECLARE_END

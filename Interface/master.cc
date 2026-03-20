#include "script.h"

rLANG_DECLARE_MACHINE

namespace dongle {
namespace script {

int VM_t::OpManager(uint16_t op, int argc, int32_t argv[]) {
  int value = 0;
  constexpr int kSizeDashboard = 8 * 1024;
  constexpr int kSize_MASTER_SECRET = 128;
  if (valid_permission_ != PERMISSION::kAdministrator)
    return zero_ = -EACCES;

  cycles_ -= 64 * 1024;
  if (op == OpCode::kWorldInitialize) {
    uint8_t init[256];
    memset(init, 0, sizeof(init));

    dongle_->DeleteFile(SECRET_STORAGE_TYPE::kSM2, kKeyIdGlobalSM2ECDSA);
    dongle_->DeleteFile(SECRET_STORAGE_TYPE::kSM2, kKeyIdGlobalSM2ECIES);
    dongle_->DeleteFile(SECRET_STORAGE_TYPE::kP256, kKeyIdGlobalP256ECDSA);
    dongle_->DeleteFile(SECRET_STORAGE_TYPE::kRSA, kKeyIdGlobalRSA2048);
    dongle_->DeleteFile(SECRET_STORAGE_TYPE::kData, kKeyIdGlobalSECRET);
    dongle_->WriteShareMemory(init);

    for (int off = 0; off < kSizeDashboard; off += sizeof(init)) {
      dongle_->WriteDataFile(Dongle::kFactoryDataFileId, off, init, sizeof(init));
    }
  } else if (op == OpCode::kVerifyWorldPublic) {
  } else if (op == OpCode::kUpdateSM2ECIESKey) {
  } else if (op == OpCode::kUpdateMasterSecret) {
  } else if (op == OpCode::kComputeSecretBytes) {
  } else if (op == OpCode::kComputeEnTrustData) {
  } else {
    return zero_ = SIGILL;
  }

  return value;
}

}
}  // namespace dongle

rLANG_DECLARE_END

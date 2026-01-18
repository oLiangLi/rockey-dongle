#include "script.h"

rLANG_DECLARE_MACHINE

namespace dongle {
namespace script {

static inline constexpr int Opcode_argc(uint16_t op) {
  return (op >> 11) & 0x0F;
}
static inline constexpr int Opcode_void(uint16_t op) {
  return !!(op & 0x0400);
}
static inline constexpr int Opcode_basic(uint16_t op) {
  return op & 0x03FF;
}

static inline constexpr bool operator==(uint16_t op, OpCode code) {
  return static_cast<uint16_t>(code) == op;
}
static inline constexpr bool operator!=(uint16_t op, OpCode code) {
  return static_cast<uint16_t>(code) != op;
}
static inline constexpr bool operator<(uint16_t op, OpCode code) {
  return static_cast<OpCode>(op) < code;
}
static inline constexpr bool operator>(uint16_t op, OpCode code) {
  return static_cast<OpCode>(op) > code;
}
static inline constexpr bool operator<=(uint16_t op, OpCode code) {
  return static_cast<OpCode>(op) <= code;
}
static inline constexpr bool operator>=(uint16_t op, OpCode code) {
  return static_cast<OpCode>(op) >= code;
}
static inline constexpr PERMISSION PermissionFrom(int code) {
  if (code == static_cast<int>(PERMISSION::kAdminstrator))
    return PERMISSION::kAdminstrator;
  if (code == static_cast<int>(PERMISSION::kNormal))
    return PERMISSION::kNormal;
  return PERMISSION::kAnonymous;
}

VM_t::VM_t(Dongle* dongle, void* data, void* buffer)
    : dongle_(dongle), data_(data), buffer_(buffer) {
  memset(text_, 0, sizeof(text_));
  memset(stack_, 0, sizeof(stack_));
  assert(dongle && data && buffer);
}

int VM_t::Initialize(const void* text, int szText, int szOut) {
  if (szText <= 0 || (size_t)szText > kSizeCode * sizeof(uint16_t) || szText % sizeof(uint16_t))
    return zero_ = -EINVAL;
  if (szOut < 0 || szOut > kSizeData)
    return zero_ = -EINVAL;
  memcpy(text_, text, szText);
  kSizeOutput = szOut;
  return zero_ = 0;
}

int VM_t::OpLoadValue(int32_t value) {
  if (nstk_ >= kSizeStack)
    return zero_ = SIGSEGV;
  stack_[nstk_++] = value;
  return 0;
}
int VM_t::OpAddValue(int32_t value) {
  if (nstk_ < 1 || nstk_ > kSizeStack)
    return zero_ = SIGSEGV;
  stack_[nstk_ - 1] += value;
  return 0;
}
void* VM_t::OpCheckMM(int32_t addr, int32_t size) {
  if (size < 0 || size > kSizeData || addr < 0 || addr > kSizeData || addr + size > kSizeData) {
    zero_ = SIGSEGV;
  } else {
    return &(static_cast<uint8_t*>(data_)[addr]);
  }
  return nullptr;
}

int VM_t::OpFuncBasic(uint16_t op, int argc, int32_t argv[]) {
  int value = 0;
  if (op == OpCode::kValidPINState) {
    cycles_ -= 256;
    if (argc == 0)
      value = static_cast<uint8_t>(valid_permission_);
    else
      zero_ = SIGILL;
  } else if (op == OpCode::kRandBytes) {
    if (argc != 2) {
      zero_ = SIGILL;
    } else {
      int addr = argv[0], size = argv[1];
      void* p = OpCheckMM(addr, size);
      cycles_ -= 256 + 16 * size;
      if (p) {
        value = dongle_->RandBytes(static_cast<uint8_t*>(p), size);
      }
    }
  } else if (op == OpCode::kSecretBytes) {
    cycles_ -= 256;
    if (argc != 1) {
      zero_ = SIGILL;
    } else {
      void* p = OpCheckMM(argv[0], 16);
      if (p)
        value = dongle_->SeedSecret(p, 16, p);
    }
  } else if (op == OpCode::kReadDongleInfo) {
    cycles_ -= 256;
    if (argc != 1) {
      zero_ = SIGILL;
    } else {
      DONGLE_INFO info;
      value = dongle_->GetDongleInfo(&info);
      void* p = OpCheckMM(argv[0], sizeof(DONGLE_INFO));
      if (p)
        memcpy(p, &info, sizeof(info));
    }
  } else if (op == OpCode::kLEDControl) {
    cycles_ -= 64;
    if (argc != 1) {
      zero_ = SIGILL;
    } else {
      value = dongle_->SetLEDState(static_cast<LED_STATE>(argv[0]));
    }
  } else if (op == OpCode::kReadSharedMemory) {
    cycles_ -= 256;
    if (argc != 1) {
      zero_ = SIGILL;
    } else {
      void* p = OpCheckMM(argv[0], 32);
      if (p)
        value = dongle_->ReadShareMemory(static_cast<uint8_t*>(p));
    }
  } else if (op == OpCode::kWriteSharedMemory) {
    cycles_ -= 256;
    if (argc != 1) {
      zero_ = SIGILL;
    } else {
      void* p = OpCheckMM(argv[0], 32);
      if (p)
        value = dongle_->WriteShareMemory(static_cast<uint8_t*>(p));
    }
  } else {
    zero_ = SIGILL;
  }

  return value;
}

int VM_t::OpFuncDataFile(uint16_t op, int argc, int32_t argv[]) {
  int value = 0;

  if (op == OpCode::kDeleteDataFile) {
    cycles_ -= 1024;
    if (argc != 1) {
      zero_ = SIGILL;
    } else {
      int id = argv[0];
      if (id < kUserFileID && valid_permission_ != PERMISSION::kAdminstrator) {
        zero_ = -EACCES;
      } else {
        value = dongle_->DeleteFile(SECRET_STORAGE_TYPE::kData, id);
      }
    }
  } else if (op == OpCode::kCreateDataFile) {
    cycles_ -= 1024;
    if (argc < 2 || argc > 4) {
      zero_ = SIGILL;
    } else {
      int id = argv[0], size = argv[1];
      PERMISSION rPerm = argc >= 3 ? PermissionFrom(argv[2]) : PERMISSION::kAnonymous;
      PERMISSION wPerm = argc >= 4 ? PermissionFrom(argv[3]) : PERMISSION::kAnonymous;

      if (id < kUserFileID && valid_permission_ != PERMISSION::kAdminstrator) {
        zero_ = -EACCES;
      } else {
        value = dongle_->CreateDataFile(id, size, rPerm, wPerm);
      }
    }
  } else if (op == OpCode::kWriteDataFile || op == OpCode::kReadDataFile) {
    cycles_ -= 1024;

    if (argc != 4) {
      zero_ = SIGILL;
    } else {
      int id = argv[0], offset = argv[1], addr = argv[2], size = argv[3];
      void* p = OpCheckMM(addr, size);
      if (p) {
        if (op == OpCode::kWriteDataFile) {
          if ((id < kUserFileID || id == Dongle::kFactoryDataFileId) &&
              valid_permission_ != PERMISSION::kAdminstrator) {
            zero_ = -EACCES;
          } else {
            value = dongle_->WriteDataFile(id, offset, p, size);
          }
        } else {
          value = dongle_->ReadDataFile(id, offset, p, size);
        }
      }
    }
  } else {
    zero_ = SIGILL;
  }

  return value;
}

int VM_t::OpFuncRSA(uint16_t op, int argc, int32_t argv[]) {
  int value = 0;
  constexpr int kCyclesPubkey = 0x4000;
  constexpr int kCyclesPrikey = kCyclesPubkey << 4;
  constexpr int kCyclesGenkey = kCyclesPrikey << 2;

  Dongle::SecretBuffer<256, uint8_t> buffer;
  struct {
    uint32_t modulus_;
    uint8_t pubkey_[256];
  } pubk;

  if (op == OpCode::kDeleteRSAFile) {
    cycles_ -= 1024;
    if (argc != 1) {
      zero_ = SIGILL;
    } else {
      int id = argv[0];
      if (id < kUserFileID && valid_permission_ != PERMISSION::kAdminstrator) {
        zero_ = -EACCES;
      } else {
        value = dongle_->DeleteFile(SECRET_STORAGE_TYPE::kRSA, id);
      }
    }
  } else if (op == OpCode::kCreateRSAFile) {
    cycles_ -= 1024;
    if (argc < 1 || argc > 5) {
      zero_ = SIGILL;
    } else {
      int id = argv[0];
      if (id < kUserFileID && valid_permission_ != PERMISSION::kAdminstrator) {
        zero_ = -EACCES;
      } else {
        PKEY_LICENCE licence;

        if (argc >= 2)
          licence.SetPermission(PermissionFrom(argv[1]));
        if (argc >= 3)
          licence.SetLimit(argv[2]);
        if (argc >= 4)
          licence.SetGlobalDecrease(!!argv[3]);
        if (argc >= 5)
          licence.SetLogoutForce(!!argv[4]);
        value = dongle_->CreatePKEYFile(SECRET_STORAGE_TYPE::kRSA, 2048, id, licence);
      }
    }
  } else if (op == OpCode::kGenerateRSA) {
    cycles_ -= kCyclesGenkey;

    if (argc < 2 || argc > 3) {
      zero_ = SIGILL;
    } else {
      int id = argv[0];
      if (id < kUserFileID && valid_permission_ != PERMISSION::kAdminstrator) {
        zero_ = -EACCES;
      } else {
        value =
            dongle_->GenerateRSA(id, &pubk.modulus_, pubk.pubkey_, argc >= 3 ? static_cast<uint8_t*>(buffer) : nullptr);
        if (value >= 0) {
          void* storage_pubkey = OpCheckMM(argv[1], sizeof(pubk));
          if (storage_pubkey)
            memcpy(storage_pubkey, &pubk, sizeof(pubk));
          if (argc >= 3) {
            void* storage_prikey = OpCheckMM(argv[2], 256);
            if (storage_prikey)
              memcpy(storage_prikey, buffer, 256);
          }
        }
      }
    }
  } else if (op == OpCode::kImportRSA) {
    cycles_ -= kCyclesPrikey;

    if (argc != 3) {
      zero_ = SIGILL;
    } else {
      int id = argv[0];
      const void* pubkey = OpCheckMM(argv[1], sizeof(pubk));
      const void* prikey = OpCheckMM(argv[2], 256);

      if (id < kUserFileID && valid_permission_ != PERMISSION::kAdminstrator) {
        zero_ = -EACCES;
      } else if (pubkey && prikey) {
        memcpy(buffer, prikey, 256);
        memcpy(&pubk, pubkey, sizeof(pubk));
        value = dongle_->ImportRSA(id, 2048, pubk.modulus_, pubk.pubkey_, buffer);
      }
    }
  } else if (op == OpCode::kRSAPrivateDecrypt) {
    cycles_ -= kCyclesPrikey;

    if (argc != 2) {
      zero_ = SIGILL;
    } else {
      int id = argv[0];
      void* iobuf = OpCheckMM(argv[1], 256);
      if (iobuf) {
        size_t szbuf = 256;
        memcpy(buffer, iobuf, 256);
        value = dongle_->RSAPrivate(id, buffer, &szbuf, false);
        if (value >= 0) {
          value = static_cast<int>(szbuf);
          memcpy(iobuf, buffer, szbuf);
        }
      }
    }
  } else if (op == OpCode::kRSAPrivateEncrypt) {
    cycles_ -= kCyclesPrikey;

    if (argc != 3) {
      zero_ = SIGILL;
    } else {
      int id = argv[0];
      size_t szbuf = argv[2];
      void* iobuf = OpCheckMM(argv[1], 256);
      if (szbuf <= 0 || szbuf > 256 - 11) {
        value = -EINVAL;
      } else {
        memcpy(buffer, iobuf, szbuf);
        value = dongle_->RSAPrivate(id, buffer, &szbuf, true);
        if (value >= 0) {
          value = static_cast<int>(szbuf);
          memcpy(iobuf, buffer, szbuf);
        }
      }
    }
  } else if (op == OpCode::kExRSAPrivateDecrypt) {
    cycles_ -= kCyclesPrikey;

    if (argc != 3) {
      zero_ = SIGILL;
    } else {
      const void* storage_pubkey = OpCheckMM(argv[0], sizeof(pubk));
      const void* storage_prikey = OpCheckMM(argv[1], 256);
      void* iobuf = OpCheckMM(argv[2], 256);

      if (storage_pubkey && storage_prikey && iobuf) {
        size_t szbuf = 256;
        memcpy(buffer, iobuf, 256);
        memcpy(&pubk, storage_pubkey, sizeof(pubk));

        value = dongle_->RSAPrivate(2048, pubk.modulus_, pubk.pubkey_, static_cast<const uint8_t*>(storage_prikey),
                                    buffer, &szbuf, false);
        if (value >= 0) {
          memcpy(iobuf, buffer, szbuf);
          value = static_cast<int>(szbuf);
        }
      }
    }
  } else if (op == OpCode::kExRSAPrivateEncrypt) {
    cycles_ -= kCyclesPrikey;

    if (argc != 4) {
      zero_ = SIGILL;
    } else {
      size_t szbuf = argv[3];
      if (szbuf <= 0 || szbuf > 256 - 11) {
        value = -EINVAL;
      } else {
        const void* storage_pubkey = OpCheckMM(argv[0], sizeof(pubk));
        const void* storage_prikey = OpCheckMM(argv[1], 256);
        void* iobuf = OpCheckMM(argv[2], 256);

        if (storage_pubkey && storage_prikey && iobuf) {
          memcpy(buffer, iobuf, szbuf);
          memcpy(&pubk, storage_pubkey, sizeof(pubk));
          value = dongle_->RSAPrivate(2048, pubk.modulus_, pubk.pubkey_, static_cast<const uint8_t*>(storage_prikey),
                                      buffer, &szbuf, true);
          if (value >= 0) {
            value = static_cast<int>(szbuf);
            memcpy(iobuf, buffer, szbuf);
          }
        }
      }
    }
  } else if (op == OpCode::kExRSAPublicEncrypt) {
    cycles_ -= kCyclesPubkey;

    if (argc != 3) {
      zero_ = SIGILL;
    } else {
      size_t szbuf = argv[2];
      if (szbuf <= 0 || szbuf > 256 - 11) {
        value = -EINVAL;
      } else {
        const void* storage_pubkey = OpCheckMM(argv[0], sizeof(pubk));
        void* iobuf = OpCheckMM(argv[2], 256);

        if (storage_pubkey && iobuf) {
          memcpy(&pubk, storage_pubkey, sizeof(pubk));
          value = dongle_->RSAPublic(2048, pubk.modulus_, pubk.pubkey_, static_cast<uint8_t*>(iobuf), &szbuf, true);
          if (value >= 0)
            value = static_cast<int>(szbuf);
        }
      }
    }
  } else if (op == OpCode::kExRSAPublicDecrypt) {
    cycles_ -= kCyclesPubkey;

    if (argc != 2) {
      zero_ = SIGILL;
    } else {
      size_t szbuf = 256;
      const void* storage_pubkey = OpCheckMM(argv[0], sizeof(pubk));
      void* iobuf = OpCheckMM(argv[2], 256);

      if (storage_pubkey && iobuf) {
        memcpy(&pubk, storage_pubkey, sizeof(pubk));
        value = dongle_->RSAPublic(2048, pubk.modulus_, pubk.pubkey_, static_cast<uint8_t*>(iobuf), &szbuf, false);
        if (value >= 0)
          value = static_cast<int>(szbuf);
      }
    }
  } else {
    zero_ = SIGILL;
  }

  return value;
}

int VM_t::OpFuncP256(uint16_t op, int argc, int32_t argv[]) {
  int value = 0;
  constexpr int kCyclesInternal = 0x10000;
  constexpr int kCyclesExternal = 0x100000;
  if (op == OpCode::kDeleteP256File) {
    cycles_ -= 1024;

    if (argc != 1) {
      zero_ = SIGILL;
    } else {
      int id = argv[0];
      if (id < kUserFileID && valid_permission_ != PERMISSION::kAdminstrator) {
        zero_ = -EACCES;
      } else {
        value = dongle_->DeleteFile(SECRET_STORAGE_TYPE::kP256, id);
      }
    }
  } else if (op == OpCode::kCreateP256File) {
    cycles_ -= 1024;

    if (argc < 1 || argc > 5) {
      zero_ = SIGILL;
    } else {
      int id = argv[0];
      if (id < kUserFileID && valid_permission_ != PERMISSION::kAdminstrator) {
        zero_ = -EACCES;
      } else {
        PKEY_LICENCE licence;

        if (argc >= 2)
          licence.SetPermission(PermissionFrom(argv[1]));
        if (argc >= 3)
          licence.SetLimit(argv[2]);
        if (argc >= 4)
          licence.SetGlobalDecrease(!!argv[3]);
        if (argc >= 5)
          licence.SetLogoutForce(!!argv[4]);
        value = dongle_->CreatePKEYFile(SECRET_STORAGE_TYPE::kP256, 256, id, licence);
      }
    }
  } else if (op == OpCode::kGenerateP256) {
    cycles_ -= kCyclesInternal;

    if (argc < 2 || argc > 3) {
      zero_ = SIGILL;
    } else {
      void* pkey = nullptr;
      uint8_t* pubk = static_cast<uint8_t*>(OpCheckMM(argv[1], 64));

      int id = argv[0];
      if (id < kUserFileID && valid_permission_ != PERMISSION::kAdminstrator) {
        zero_ = -EACCES;
      } else if (!pubk || (argc >= 3 && !(pkey = OpCheckMM(argv[2], 32)))) {
        zero_ = SIGSEGV;
      } else {
        value = dongle_->GenerateP256(id, &pubk[0], &pubk[32], static_cast<uint8_t*>(pkey));
      }
    }
  } else if (op == OpCode::kImportP256) {
    cycles_ -= kCyclesInternal;

    if (argc != 2) {
      zero_ = SIGILL;
    } else {
      int id = argv[0];
      if (id < kUserFileID && valid_permission_ != PERMISSION::kAdminstrator) {
        zero_ = -EACCES;
      } else {
        uint8_t* pkey = static_cast<uint8_t*>(OpCheckMM(argv[1], 32));
        if (pkey) {
          value = dongle_->ImportP256(id, pkey);
        }
      }
    }
  } else if (op == OpCode::kP256Sign) {
    cycles_ -= kCyclesInternal;

    if (argc != 3) {
      zero_ = SIGILL;
    } else {
      int id = argv[0];
      const uint8_t* hash = static_cast<uint8_t*>(OpCheckMM(argv[1], 32));
      uint8_t* sign = static_cast<uint8_t*>(OpCheckMM(argv[2], 64));
      if (hash && sign)
        value = dongle_->P256Sign(id, hash, &sign[0], &sign[32]);
    }
  } else if (op == OpCode::kExP256CheckPointOnCurve) {
    cycles_ -= kCyclesExternal / 8;

    if (argc != 1) {
      zero_ = SIGILL;
    } else {
      const uint8_t* XY = static_cast<uint8_t*>(OpCheckMM(argv[0], 64));
      if (XY) {
        value = dongle_->CheckPointOnCurvePrime256v1(&XY[0], &XY[32]);
      }
    }
  } else if (op == OpCode::kExP256DecompressPoint) {
    cycles_ -= kCyclesExternal / 4;

    if (argc != 3) {
      zero_ = SIGILL;
    } else {
      const uint8_t* cX = static_cast<uint8_t*>(OpCheckMM(argv[1], 32));
      uint8_t* cY = static_cast<uint8_t*>(OpCheckMM(argv[2], 32));
      if (cX && cY)
        value = dongle_->DecompressPointPrime256v1(cY, cX, !!argv[0]);
    }
  } else if (op == OpCode::kExP256ComputePubkey) {
    cycles_ -= kCyclesExternal;

    if (argc != 2) {
      zero_ = SIGILL;
    } else {
      const uint8_t* cK = static_cast<uint8_t*>(OpCheckMM(argv[0], 32));
      uint8_t* XY = static_cast<uint8_t*>(OpCheckMM(argv[1], 64));
      if (cK && XY)
        value = dongle_->ComputePubkeyPrime256v1(&XY[0], &XY[32], cK);
    }
  } else if (op == OpCode::kExP256GenerateKeyPair) {
    cycles_ -= kCyclesExternal;

    if (argc != 2) {
      zero_ = SIGILL;
    } else {
      uint8_t* cK = static_cast<uint8_t*>(OpCheckMM(argv[0], 32));
      uint8_t* XY = static_cast<uint8_t*>(OpCheckMM(argv[1], 64));
      if (cK && XY)
        value = dongle_->GenerateKeyPairPrime256v1(&XY[0], &XY[32], cK);
    }
  } else if (op == OpCode::kExP256Sign) {
    cycles_ -= kCyclesInternal;

    if (argc != 3) {
      zero_ = SIGILL;
    } else {
      const uint8_t* cK = static_cast<uint8_t*>(OpCheckMM(argv[0], 32));
      const uint8_t* hash = static_cast<uint8_t*>(OpCheckMM(argv[1], 32));
      uint8_t* sign = static_cast<uint8_t*>(OpCheckMM(argv[2], 64));
      if (hash && sign)
        value = dongle_->P256Sign(cK, hash, &sign[0], &sign[32]);
    }
  } else if (op == OpCode::kExP256Verify) {
    cycles_ -= kCyclesInternal;

    if (argc != 3) {
      zero_ = SIGILL;
    } else {
      const uint8_t* hash = static_cast<uint8_t*>(OpCheckMM(argv[0], 32));
      const uint8_t* XY = static_cast<uint8_t*>(OpCheckMM(argv[1], 64));
      const uint8_t* sign = static_cast<uint8_t*>(OpCheckMM(argv[2], 64));
      if (hash && XY && sign)
        value = dongle_->P256Verify(&XY[0], &XY[32], hash, &sign[0], &sign[32]);
    }
  } else if (op == OpCode::kExP256ComputeSecret) {
    cycles_ -= kCyclesExternal;

    if (argc != 3) {
      zero_ = SIGILL;
    } else {
      const uint8_t* cK = static_cast<uint8_t*>(OpCheckMM(argv[0], 32));
      const uint8_t* XY = static_cast<uint8_t*>(OpCheckMM(argv[1], 64));
      uint8_t* secret = static_cast<uint8_t*>(OpCheckMM(argv[2], 32));
      if (cK && XY && secret)
        value = dongle_->ComputeSecretPrime256v1(secret, &XY[0], &XY[32], cK);
    }
  } else {
    zero_ = SIGILL;
  }

  return value;
}

int VM_t::OpFuncSM2(uint16_t op, int argc, int32_t argv[]) {
  int value = 0;
  constexpr int kCyclesInternal = 0x10000;
  constexpr int kCyclesExternal = 0x100000;

  if (op == OpCode::kDeleteSM2File) {
    cycles_ -= 1024;

    if (argc != 1) {
      zero_ = SIGILL;
    } else {
      int id = argv[0];
      if (id < kUserFileID && valid_permission_ != PERMISSION::kAdminstrator) {
        zero_ = -EACCES;
      } else {
        value = dongle_->DeleteFile(SECRET_STORAGE_TYPE::kSM2, id);
      }
    }
  } else if (op == OpCode::kCreateSM2File) {
    cycles_ -= 1024;

    if (argc < 1 || argc > 5) {
      zero_ = SIGILL;
    } else {
      int id = argv[0];
      if (id < kUserFileID && valid_permission_ != PERMISSION::kAdminstrator) {
        zero_ = -EACCES;
      } else {
        PKEY_LICENCE licence;

        if (argc >= 2)
          licence.SetPermission(PermissionFrom(argv[1]));
        if (argc >= 3)
          licence.SetLimit(argv[2]);
        if (argc >= 4)
          licence.SetGlobalDecrease(!!argv[3]);
        if (argc >= 5)
          licence.SetLogoutForce(!!argv[4]);
        value = dongle_->CreatePKEYFile(SECRET_STORAGE_TYPE::kSM2, 256, id, licence);
      }
    }
  } else if (op == OpCode::kGenerateSM2) {
    cycles_ -= kCyclesInternal;

    if (argc < 2 || argc > 3) {
      zero_ = SIGILL;
    } else {
      void* pkey = nullptr;
      uint8_t* pubk = static_cast<uint8_t*>(OpCheckMM(argv[1], 64));

      int id = argv[0];
      if (id < kUserFileID && valid_permission_ != PERMISSION::kAdminstrator) {
        zero_ = -EACCES;
      } else if (!pubk || (argc >= 3 && !(pkey = OpCheckMM(argv[2], 32)))) {
        zero_ = SIGSEGV;
      } else {
        value = dongle_->GenerateSM2(id, &pubk[0], &pubk[32], static_cast<uint8_t*>(pkey));
      }
    }
  } else if (op == OpCode::kImportSM2) {
    cycles_ -= kCyclesInternal;

    if (argc != 2) {
      zero_ = SIGILL;
    } else {
      int id = argv[0];
      if (id < kUserFileID && valid_permission_ != PERMISSION::kAdminstrator) {
        zero_ = -EACCES;
      } else {
        uint8_t* pkey = static_cast<uint8_t*>(OpCheckMM(argv[1], 32));
        if (pkey) {
          value = dongle_->ImportSM2(id, pkey);
        }
      }
    }
  } else if (op == OpCode::kSM2Sign) {
    cycles_ -= kCyclesInternal;

    if (argc != 3) {
      zero_ = SIGILL;
    } else {
      int id = argv[0];
      if (id == kKeyIdGlobalSM2ECIES && valid_permission_ != PERMISSION::kAdminstrator) {
        zero_ = -EACCES;
      } else {
        auto* hash = static_cast<const uint8_t*>(OpCheckMM(argv[1], 32));
        auto* sign = static_cast<uint8_t*>(OpCheckMM(argv[2], 64));
        if (hash && sign)
          value = dongle_->SM2Sign(id, hash, &sign[0], &sign[32]);
      }
    }
  } else if (op == OpCode::kSM2Decrypt) {
    cycles_ -= kCyclesInternal;

    if (argc != 4) {
      zero_ = SIGILL;
    } else {
      int id = argv[0];
      size_t size = argv[2];
      if (size <= 96 || size > 512) {
        value = -E2BIG;
      } else {
        Dongle::SecretBuffer<512> copy;
        auto* data = static_cast<uint8_t*>(OpCheckMM(argv[1], (int)size));
        if (data) {
          value = dongle_->SM2Decrypt(id, data, size, copy, &size);
          if (value >= 0) {
            value = static_cast<int>(size);
            memcpy(data, copy, size);
          }
        }
      }
    }
  } else if (op == OpCode::kExSM2CheckPointOnCurve) {
    cycles_ -= kCyclesExternal / 8;

    if (argc != 1) {
      zero_ = SIGILL;
    } else {
      const uint8_t* XY = static_cast<uint8_t*>(OpCheckMM(argv[0], 64));
      if (XY) {
        value = dongle_->CheckPointOnCurveSM2(&XY[0], &XY[32]);
      }
    }
  } else if (op == OpCode::kExSM2DecompressPoint) {
    cycles_ -= kCyclesExternal / 4;

    if (argc != 3) {
      zero_ = SIGILL;
    } else {
      const uint8_t* cX = static_cast<uint8_t*>(OpCheckMM(argv[1], 32));
      uint8_t* cY = static_cast<uint8_t*>(OpCheckMM(argv[2], 32));
      if (cX && cY)
        value = dongle_->DecompressPointSM2(cY, cX, !!argv[0]);
    }
  } else if (op == OpCode::kExSM2Sign) {
    cycles_ -= kCyclesInternal;

    if (argc != 3) {
      zero_ = SIGILL;
    } else {
      const uint8_t* cK = static_cast<uint8_t*>(OpCheckMM(argv[0], 32));
      const uint8_t* hash = static_cast<uint8_t*>(OpCheckMM(argv[1], 32));
      uint8_t* sign = static_cast<uint8_t*>(OpCheckMM(argv[2], 64));
      if (hash && sign)
        value = dongle_->SM2Sign(cK, hash, &sign[0], &sign[32]);
    }
  } else if (op == OpCode::kExSM2Verify) {
    cycles_ -= kCyclesInternal;

    if (argc != 3) {
      zero_ = SIGILL;
    } else {
      const uint8_t* hash = static_cast<uint8_t*>(OpCheckMM(argv[0], 32));
      const uint8_t* XY = static_cast<uint8_t*>(OpCheckMM(argv[1], 64));
      const uint8_t* sign = static_cast<uint8_t*>(OpCheckMM(argv[2], 64));
      if (hash && XY && sign)
        value = dongle_->SM2Verify(&XY[0], &XY[32], hash, &sign[0], &sign[32]);
    }
  } else if (op == OpCode::kExSM2Decrypt) {
    cycles_ -= kCyclesInternal;

    if (argc != 4) {
      zero_ = SIGILL;
    } else {
      Dongle::SecretBuffer<32> pkey;
      size_t size = argv[2];

      const void* cK = OpCheckMM(argv[0], 32);
      if (cK) {
        memcpy(pkey, cK, 32);
        if (size <= 96) {
          value = -EINVAL;
        } else if (size > 512) {
          value = -E2BIG;
        } else {
          Dongle::SecretBuffer<512> copy;
          uint8_t* data = static_cast<uint8_t*>(OpCheckMM(argv[1], (int)size));
          if (data) {
            value = dongle_->SM2Decrypt(pkey, data, size, copy, &size);
            if (value >= 0) {
              value = static_cast<int>(size);
              memcpy(data, copy, size);
            }
          }
        }
      }
    }
  } else if (op == OpCode::kExSM2Encrypt) {
    cycles_ -= kCyclesInternal;

    uint8_t pubk[64];
    uint8_t cipher[512];
    size_t size = argv[2];

    if (size < 1) {
      value = -EINVAL;
    } else if (size > 512 - 96) {
      value = -E2BIG;
    } else {
      const void* cK = OpCheckMM(argv[0], 64);
      uint8_t* data = static_cast<uint8_t*>(OpCheckMM(argv[1], (int)size + 96));
      if (cK && data) {
        memcpy(pubk, cK, 64);
        value = dongle_->SM2Encrypt(&pubk[0], &pubk[32], data, size, cipher);
        if (value >= 0) {
          value = static_cast<int>(96 + size);
          memcpy(data, cipher, value);
        }
      }
    }
  } else {
    zero_ = SIGILL;
  }

  return value;
}

int VM_t::OpFuncDigest(uint16_t op, int argc, int32_t argv[]) {
  int value = 0;
  if (argc != 3) {
    zero_ = SIGILL;
  } else {
    int size = argv[1];
    const void* input = OpCheckMM(argv[0], size);
    if (input) {
      cycles_ -= 1024 + 64 * size;
      if (op == OpCode::kDigestSHA1) {
        uint8_t* md = static_cast<uint8_t*>(OpCheckMM(argv[2], 20));
        value = dongle_->SHA1(input, size, md);
      } else if (op == OpCode::kDigestSM3) {
        uint8_t* md = static_cast<uint8_t*>(OpCheckMM(argv[2], 32));
        value = dongle_->SM3(input, size, md);
      } else if (op == OpCode::kExDigestSHA256) {
        uint8_t* md = static_cast<uint8_t*>(OpCheckMM(argv[2], 32));
        value = dongle_->SHA256(input, size, md);
      } else if (op == OpCode::kExDigestSHA384) {
        uint8_t* md = static_cast<uint8_t*>(OpCheckMM(argv[2], 48));
        value = dongle_->SHA384(input, size, md);
      } else if (op == OpCode::kExDigestSHA512) {
        uint8_t* md = static_cast<uint8_t*>(OpCheckMM(argv[2], 64));
        value = dongle_->SHA512(input, size, md);
      } else {
        zero_ = SIGILL;
      }
    }
  }

  return value;
}

int VM_t::OpFuncSM4(uint16_t op, int argc, int32_t argv[]) {
  int value = 0;
  cycles_ -= 1024;

  if (op == OpCode::kDeleteSM4File) {
    if (argc != 1) {
      zero_ = SIGILL;
    } else {
      int id = argv[0];
      if (id < kUserFileID && valid_permission_ != PERMISSION::kAdminstrator) {
        zero_ = -EACCES;
      } else {
        value = dongle_->DeleteFile(SECRET_STORAGE_TYPE::kSM4, id);
      }
    }
  } else if (op == OpCode::kCreateSM4File) {
    if (argc < 1 || argc > 2) {
      zero_ = SIGILL;
    } else {
      int id = argv[0];
      if (id < kUserFileID && valid_permission_ != PERMISSION::kAdminstrator) {
        zero_ = -EACCES;
      } else {
        value = dongle_->CreateKeyFile(id, argc > 1 ? PermissionFrom(argv[1]) : PERMISSION::kAnonymous,
                                       SECRET_STORAGE_TYPE::kSM4);
      }
    }
  } else if (op == OpCode::kWriteSM4File) {
    if (argc != 2) {
      zero_ = SIGILL;
    } else {
      int id = argv[0];
      if (id < kUserFileID && valid_permission_ != PERMISSION::kAdminstrator) {
        zero_ = -EACCES;
      } else {
        const uint8_t* key = static_cast<uint8_t*>(OpCheckMM(argv[1], 16));
        if (key) {
          value = dongle_->WriteKeyFile(id, key, 16, SECRET_STORAGE_TYPE::kSM4);
        }
      }
    }
  } else if (op >= OpCode::kSM4ECBEncrypt && op <= OpCode::kExSM4ECBDecrypt && argc == 3) {
    int size = argv[2];
    uint8_t* buffer = static_cast<uint8_t*>(OpCheckMM(argv[1], size));
    if (buffer) {
      cycles_ -= 64 * size;
      if (size <= 0 || size % 16 != 0) {
        value = -EINVAL;
      } else {
        if (op == OpCode::kSM4ECBEncrypt) {
          value = dongle_->SM4ECB(argv[0], buffer, size, true);
        } else if (op == OpCode::kSM4ECBDecrypt) {
          value = dongle_->SM4ECB(argv[0], buffer, size, false);
        } else {
          const uint8_t* key = static_cast<uint8_t*>(OpCheckMM(argv[0], 16));
          if (key) {
            if (op == OpCode::kExSM4ECBEncrypt) {
              value = dongle_->SM4ECB(key, buffer, size, true);
            } else {
              value = dongle_->SM4ECB(key, buffer, size, false);
            }
          }
        }
      }
    }
  } else {
    zero_ = SIGILL;
  }

  return value;
}

int VM_t::OpFuncTDES(uint16_t op, int argc, int32_t argv[]) {
  int value = 0;
  cycles_ -= 1024;

  if (op == OpCode::kDeleteTDESFile) {
    if (argc != 1) {
      zero_ = SIGILL;
    } else {
      int id = argv[0];
      if (id < kUserFileID && valid_permission_ != PERMISSION::kAdminstrator) {
        zero_ = -EACCES;
      } else {
        value = dongle_->DeleteFile(SECRET_STORAGE_TYPE::kTDES, id);
      }
    }
  } else if (op == OpCode::kCreateTDESFile) {
    if (argc < 1 || argc > 2) {
      zero_ = SIGILL;
    } else {
      int id = argv[0];
      if (id < kUserFileID && valid_permission_ != PERMISSION::kAdminstrator) {
        zero_ = -EACCES;
      } else {
        value = dongle_->CreateKeyFile(id, argc > 1 ? PermissionFrom(argv[1]) : PERMISSION::kAnonymous,
                                       SECRET_STORAGE_TYPE::kTDES);
      }
    }
  } else if (op == OpCode::kWriteTDESFile) {
    if (argc != 2) {
      zero_ = SIGILL;
    } else {
      int id = argv[0];
      if (id < kUserFileID && valid_permission_ != PERMISSION::kAdminstrator) {
        zero_ = -EACCES;
      } else {
        const uint8_t* key = static_cast<uint8_t*>(OpCheckMM(argv[1], 16));
        if (key) {
          value = dongle_->WriteKeyFile(id, key, 16, SECRET_STORAGE_TYPE::kTDES);
        }
      }
    }
  } else if (op >= OpCode::kTDESECBEncrypt && op <= OpCode::kExTDESECBDecrypt && argc == 3) {
    int size = argv[2];
    uint8_t* buffer = static_cast<uint8_t*>(OpCheckMM(argv[1], size));
    if (buffer) {
      cycles_ -= 64 * size;
      if (size <= 0 || size % 16 != 0) {
        value = -EINVAL;
      } else {
        if (op == OpCode::kTDESECBEncrypt) {
          value = dongle_->TDESECB(argv[0], buffer, size, true);
        } else if (op == OpCode::kTDESECBDecrypt) {
          value = dongle_->TDESECB(argv[0], buffer, size, false);
        } else {
          const uint8_t* key = static_cast<uint8_t*>(OpCheckMM(argv[0], 16));
          if (key) {
            if (op == OpCode::kExTDESECBEncrypt) {
              value = dongle_->TDESECB(key, buffer, size, true);
            } else {
              value = dongle_->TDESECB(key, buffer, size, false);
            }
          }
        }
      }
    }
  } else {
    zero_ = SIGILL;
  }

  return value;
}

int VM_t::OpFuncChaChaPoly(uint16_t op, int argc, int32_t argv[]) {
  int value = 0;

  if (op >= OpCode::kExChaChaPolySeal && op <= OpCode::kExChaChaPolyOpen && argc == 4) {
    size_t size = argv[3];
    if ((int)size <= 0) {
      value = -EINVAL;
    } else if (size > 1024) {
      zero_ = SIGSEGV;
    } else {
      cycles_ -= 1024 + 64 * (int)size;
      const uint8_t* key = static_cast<uint8_t*>(OpCheckMM(argv[0], 32));
      const uint8_t* nonce = static_cast<uint8_t*>(OpCheckMM(argv[1], 12));
      if (key && nonce) {
        if (op == OpCode::kExChaChaPolySeal) {
          uint8_t* buffer = static_cast<uint8_t*>(OpCheckMM(argv[2], (int)size + 16));
          if (buffer) {
            value = dongle_->CHACHAPOLY_Seal(key, nonce, buffer, &size);
            if (value >= 0)
              value = (int)size;
          }
        } else {
          uint8_t* buffer = static_cast<uint8_t*>(OpCheckMM(argv[2], (int)size));
          if (buffer) {
            value = dongle_->CHACHAPOLY_Open(key, nonce, buffer, &size);
            if (value >= 0)
              value = (int)size;
          }
        }
      }
    }
  } else {
    zero_ = SIGILL;
  }

  return value;
}

int VM_t::OpSecp256k1(uint16_t op, int argc, int32_t argv[]) {
  int value = 0;
  constexpr int kCyclesExternal = 0x100000;

  if (op == OpCode::kExSecp256K1CheckPointOnCurve) {
    cycles_ -= kCyclesExternal / 8;
    if (argc != 1) {
      zero_ = SIGILL;
    } else {
      const uint8_t* XY = static_cast<uint8_t*>(OpCheckMM(argv[0], 64));
      if (XY) {
        value = dongle_->CheckPointOnCurveSecp256k1(&XY[0], &XY[32]);
      }
    }
  } else if (op == OpCode::kExSecp256K1DecompressPoint) {
    cycles_ -= kCyclesExternal / 4;

    if (argc != 3) {
      zero_ = SIGILL;
    } else {
      const uint8_t* cX = static_cast<uint8_t*>(OpCheckMM(argv[1], 32));
      uint8_t* cY = static_cast<uint8_t*>(OpCheckMM(argv[2], 32));
      if (cX && cY)
        value = dongle_->DecompressPointSecp256k1(cY, cX, !!argv[0]);
    }
  } else if (op == OpCode::kExSecp256K1ComputePubkey) {
    cycles_ -= kCyclesExternal;

    if (argc != 2) {
      zero_ = SIGILL;
    } else {
      const uint8_t* cK = static_cast<uint8_t*>(OpCheckMM(argv[0], 32));
      uint8_t* XY = static_cast<uint8_t*>(OpCheckMM(argv[1], 64));
      if (cK && XY)
        value = dongle_->ComputePubkeySecp256k1(&XY[0], &XY[32], cK);
    }
  } else if (op == OpCode::kExSecp256K1GenerateKeyPair) {
    cycles_ -= kCyclesExternal;

    if (argc != 2) {
      zero_ = SIGILL;
    } else {
      uint8_t* cK = static_cast<uint8_t*>(OpCheckMM(argv[0], 32));
      uint8_t* XY = static_cast<uint8_t*>(OpCheckMM(argv[1], 64));
      if (cK && XY)
        value = dongle_->GenerateKeyPairSecp256k1(&XY[0], &XY[32], cK);
    }
  } else if (op == OpCode::kExSecp256K1Sign) {
    cycles_ -= kCyclesExternal;

    if (argc != 3) {
      zero_ = SIGILL;
    } else {
      const uint8_t* cK = static_cast<uint8_t*>(OpCheckMM(argv[0], 32));
      const uint8_t* hash = static_cast<uint8_t*>(OpCheckMM(argv[1], 32));
      uint8_t* sign = static_cast<uint8_t*>(OpCheckMM(argv[2], 64));
      if (cK && hash && sign)
        value = dongle_->SignMessageSecp256k1(cK, hash, &sign[0], &sign[32]);
    }
  } else if (op == OpCode::kExSecp256K1Verify) {
    cycles_ -= kCyclesExternal;

    if (argc != 3) {
      zero_ = SIGILL;
    } else {
      const uint8_t* hash = static_cast<uint8_t*>(OpCheckMM(argv[0], 32));
      const uint8_t* XY = static_cast<uint8_t*>(OpCheckMM(argv[1], 64));
      const uint8_t* sign = static_cast<uint8_t*>(OpCheckMM(argv[2], 64));
      if (hash && XY && sign)
        value = dongle_->VerifySignSecp256k1(&XY[0], &XY[32], hash, &sign[0], &sign[32]);
    }
  } else if (op == OpCode::kExSecp256K1ComputeSecret) {
    cycles_ -= kCyclesExternal;

    if (argc != 3) {
      zero_ = SIGILL;
    } else {
      const uint8_t* cK = static_cast<uint8_t*>(OpCheckMM(argv[0], 32));
      const uint8_t* XY = static_cast<uint8_t*>(OpCheckMM(argv[1], 64));
      uint8_t* secret = static_cast<uint8_t*>(OpCheckMM(argv[2], 32));
      if (cK && XY && secret)
        value = dongle_->ComputeSecretSecp256k1(secret, &XY[0], &XY[32], cK);
    }
  } else {
    zero_ = SIGILL;
  }

  return value;
}

int VM_t::OpCurve25519(uint16_t op, int argc, int32_t argv[]) {
  int value = 0;
  constexpr int kCyclesExternal = 0x100000;

  cycles_ -= kCyclesExternal;

  if (op == OpCode::kExCurve25519ComputePubkey) {
    if (argc != 2) {
      zero_ = SIGILL;
    } else {
      const uint8_t* cK = static_cast<uint8_t*>(OpCheckMM(argv[0], 32));
      uint8_t* pubkey = static_cast<uint8_t*>(OpCheckMM(argv[1], 32));
      if (cK && pubkey)
        value = dongle_->ComputePubkeyCurve25519(pubkey, cK);
    }
  } else if (op == OpCode::kExCurve25519GenerateKeyPair) {
    if (argc != 2) {
      zero_ = SIGILL;
    } else {
      uint8_t* cK = static_cast<uint8_t*>(OpCheckMM(argv[0], 32));
      uint8_t* pubkey = static_cast<uint8_t*>(OpCheckMM(argv[1], 32));
      if (cK && pubkey)
        value = dongle_->GenerateKeyPairCurve25519(pubkey, cK);
    }
  } else if (op == OpCode::kExCurve25519ComputeSecret) {
    if (argc != 3) {
      zero_ = SIGILL;
    } else {
      const uint8_t* cK = static_cast<uint8_t*>(OpCheckMM(argv[0], 32));
      const uint8_t* pubkey = static_cast<uint8_t*>(OpCheckMM(argv[1], 32));
      uint8_t* secret = static_cast<uint8_t*>(OpCheckMM(argv[2], 32));
      if (cK && pubkey && secret)
        value = dongle_->ComputeSecretCurve25519(secret, cK, pubkey);
    }
  } else {
    zero_ = SIGILL;
  }

  return value;
}

int VM_t::OpEd25519(uint16_t op, int argc, int32_t argv[]) {
  int value = 0;
  constexpr int kCyclesExternal = 0x100000;

  cycles_ -= kCyclesExternal;
  if (op == OpCode::kExEd25519ComputePubkey) {
    if (argc != 2) {
      zero_ = SIGILL;
    } else {
      const uint8_t* cK = static_cast<uint8_t*>(OpCheckMM(argv[0], 32));
      uint8_t* pubkey = static_cast<uint8_t*>(OpCheckMM(argv[1], 32));
      if (cK && pubkey)
        value = dongle_->ComputePubkeyEd25519(buffer_, pubkey, cK);
    }
  } else if (op == OpCode::kExEd25519GenerateKeyPair) {
    if (argc != 2) {
      zero_ = SIGILL;
    } else {
      uint8_t* cK = static_cast<uint8_t*>(OpCheckMM(argv[0], 32));
      uint8_t* pubkey = static_cast<uint8_t*>(OpCheckMM(argv[1], 32));
      if (cK && pubkey)
        value = dongle_->GenerateKeyPairEd25519(buffer_, pubkey, cK);
    }
  } else if (op == OpCode::kExEd25519Sign) {
    if (argc != 5) {
      zero_ = SIGILL;
    } else {
      int len = argv[3];
      const uint8_t* pubkey = static_cast<uint8_t*>(OpCheckMM(argv[0], 32));
      const uint8_t* pkey = static_cast<uint8_t*>(OpCheckMM(argv[1], 32));
      const void* message = OpCheckMM(argv[2], len);
      uint8_t* sign = static_cast<uint8_t*>(OpCheckMM(argv[4], 64));

      if (pubkey && pkey && message && sign)
        value = dongle_->SignMessageEd25519(buffer_, sign, message, len, pubkey, pkey);
    }
  } else if (op == OpCode::kExEd25519Verify) {
    if (argc != 4) {
      zero_ = SIGILL;
    } else {
      int len = argv[3];
      const uint8_t* pubkey = static_cast<uint8_t*>(OpCheckMM(argv[0], 32));
      const uint8_t* sign = static_cast<uint8_t*>(OpCheckMM(argv[1], 64));
      const void* message = OpCheckMM(argv[2], len);
      if (pubkey && sign && message)
        value = dongle_->VerifySignEd25519(buffer_, message, len, sign, pubkey);
    }
  } else {
    zero_ = SIGILL;
  }

  return value;
}

int VM_t::Execute() {
  while (zero_ == 0) {
    if (pc_ == kSizeCode)
      break; /* exit(0) */

    if (--cycles_ < 0) {
      zero_ = -ETIMEDOUT;
      break;
    }
    if (pc_ < 0 || pc_ >= kSizeCode) {
      zero_ = SIGILL;
      break;
    }

    int pc = pc_++;
    uint16_t op = text_[pc];

    if (op & 0x8000) {
      if (op >= 0xB000) {
        int32_t value = op & 0x0FFF;
        op &= 0xF000;

        if (op == OpCode::kLoadMUI) {
          OpLoadValue(value << 12);
        } else if (op == OpCode::kAddMUI) {
          OpAddValue(value << 12);
        } else if (op == OpCode::kLoadUI) {
          OpLoadValue(value);
        } else if (op == OpCode::kLoadNI) {
          OpLoadValue(-1 - value);
        } else if (op == OpCode::kAddUI) {
          OpAddValue(value);
        } else {
          zero_ = SIGILL;
        }
      } else if (op >= 0x9000) {
        int addr = op & 0x03FF;
        op &= 0xFC00;

        cycles_ -= 4;
        if (op == OpCode::kLoadI8) {
          OpLoadValue(LoadMM<int8_t>(addr));
        } else if (op == OpCode::kLoadU8) {
          OpLoadValue(LoadMM<uint8_t>(addr));
        } else if (op == OpCode::kLoadI16) {
          OpLoadValue(LoadMM<int16_t>(addr));
        } else if (op == OpCode::kLoadU16) {
          OpLoadValue(LoadMM<uint16_t>(addr));
        } else if (op == OpCode::kLoadI32) {
          OpLoadValue(LoadMM<int32_t>(addr));
        } else if (nstk_ > 0 && nstk_ <= kSizeStack) {
          int32_t value = stack_[--nstk_];
          if (op == OpCode::kStoreI8) {
            StoreMM<int8_t>(addr, value);
          } else if (op == OpCode::kStoreI16) {
            StoreMM<int16_t>(addr, value);
          } else if (op == OpCode::kStoreI32) {
            StoreMM<int32_t>(addr, value);
          }
        } else {
          zero_ = SIGSEGV;
        }
      } else {
        int8_t value = op & 0xFF;
        op &= 0xFF00;

        if (op == OpCode::kLoadHUI) {
          OpLoadValue(value << 24);
        } else if (op == OpCode::kLoadMNI) {
          OpLoadValue((-1 - (uint8_t)value) << 12);
        } else if (op == OpCode::kJmp) {
          cycles_ -= value < 0 ? 64 : 4;
          pc_ = pc + value;
        } else if (nstk_ > 0 && nstk_ <= kSizeStack) {
          int32_t a = stack_[--nstk_];

          if (op == OpCode::kJmpF) {
            if (!a) {
              cycles_ -= value < 0 ? 64 : 4;
              pc_ = pc + value;
            }
          } else if (op == OpCode::kJmpT) {
            if (a) {
              cycles_ -= value < 0 ? 64 : 4;
              pc_ = pc + value;
            }
          } else if (op == OpCode::kSltI) {
            OpLoadValue(a < value);
          } else if (op == OpCode::kOrI) {
            OpLoadValue(a | value);
          } else if (op == OpCode::kXorI) {
            OpLoadValue(a ^ value);
          } else if (op == OpCode::kAndI) {
            OpLoadValue(a & value);
          } else if (op == OpCode::kSllI) {
            OpLoadValue(a << (value & 0x1F));
          } else if (op == OpCode::kSrlI) {
            OpLoadValue((uint32_t)a >> (value & 0x1F));
          } else if (op == OpCode::kSraI) {
            OpLoadValue(a >> (value & 0x1F));
          } else if (op == OpCode::kSubI) {
            OpLoadValue(a - (uint8_t)value);
          } else if (op == OpCode::kMulI) {
            cycles_ -= 8;
            OpLoadValue(a * value);
          } else {
            cycles_ -= 64;
            if (value == 0 || (value == -1 && a == (int32_t)0x80000000)) {
              zero_ = SIGFPE;
            } else if (op == OpCode::kDivI) {
              OpLoadValue(a / value);
            } else if (op == OpCode::kModI) {
              OpLoadValue(a % value);
            } else {
              zero_ = SIGILL;
            }
          }
        } else {
          zero_ = SIGILL;
        }
      }
    } else {
      int argc_ = Opcode_argc(op);
      int void_ = Opcode_void(op);
      op = Opcode_basic(op);

      if (nstk_ >= argc_ && nstk_ <= kSizeStack) {
        int32_t value = 0;
        nstk_ -= argc_;
        int32_t* argv_ = &stack_[nstk_];

        cycles_ -= 2 * argc_;
        if (op < 0x100) {
          if (op < 0x10) {
            if (op == OpCode::kDup) {
              if (0 != argc_) {
                zero_ = SIGILL;
              } else if (nstk_ < 1) {
                zero_ = SIGSEGV;
              } else {
                value = argv_[-1];
              }
            } else if (op == OpCode::kNop) {
              value = 0;
            } else if (op == OpCode::kExit) {
              if (argc_ > 1) {
                zero_ = SIGILL;
              } else if (argc_) {
                zero_ = argv_[0];
              }
              break;
            } else {
              zero_ = SIGILL;
            }
          } else if (op < 0x20) {
            cycles_ -= 4;
            if (op <= OpCode::kLoadXI32 && argc_ == 1) {
              int addr = stack_[nstk_];

              if (op == OpCode::kLoadXI8) {
                value = LoadMM<int8_t>(addr);
              } else if (op == OpCode::kLoadXU8) {
                value = LoadMM<uint8_t>(addr);
              } else if (op == OpCode::kLoadXI16) {
                value = LoadMM<int16_t>(addr);
              } else if (op == OpCode::kLoadXU16) {
                value = LoadMM<uint16_t>(addr);
              } else if (op == OpCode::kLoadXI32) {
                value = LoadMM<int32_t>(addr);
              }
            } else if (op >= OpCode::kStoreXI8 && op <= OpCode::kStoreXI32 && argc_ == 2) {
              int addr = stack_[nstk_];
              value = stack_[nstk_ + 1];

              if (op == OpCode::kStoreXI8) {
                StoreMM<int8_t>(addr, value);
              } else if (op == OpCode::kStoreXI16) {
                StoreMM<int16_t>(addr, value);
              } else {
                StoreMM<int32_t>(addr, value);
              }
            } else {
              zero_ = SIGILL;
            }
          } else if (op < 0x30) {
            if (argc_ == 2) {
              int32_t a = argv_[0], b = argv_[1];

              if (op == OpCode::kEQ) {
                value = a == b;
              } else if (op == OpCode::kNE) {
                value = a != b;
              } else if (op == OpCode::kLT) {
                value = a < b;
              } else if (op == OpCode::kLE) {
                value = a <= b;
              } else if (op == OpCode::kGT) {
                value = a > b;
              } else if (op == OpCode::kGE) {
                value = a >= b;
              } else {
                zero_ = SIGILL;
              }
            } else if (argc_ == 1) {
              int32_t a = argv_[0];

              if (op == OpCode::kNot) {
                value = a ? 0 : 1;
              } else if (op == OpCode::kBitNot) {
                value = ~a;
              } else if (op == OpCode::kNegative) {
                value = -a;
              } else {
                zero_ = SIGILL;
              }
            } else {
              zero_ = SIGILL;
            }
          } else if (op < 0x40) {
            if (argc_ == 2) {
              int32_t a = argv_[0], b = argv_[1];

              if (op == OpCode::kAdd) {
                value = a + b;
              } else if (op == OpCode::kSub) {
                value = a - b;
              } else if (op == OpCode::kMul) {
                cycles_ -= 8;
                value = a * b;
              } else if (op == OpCode::kDiv || op == OpCode::kMod) {
                cycles_ -= 64;
                if (b == 0 || (b == -1 && a == (int32_t)0x80000000)) {
                  zero_ = SIGFPE;
                } else if (op == OpCode::kDiv) {
                  value = a / b;
                } else {
                  value = a % b;
                }
              } else if (op == OpCode::kSll) {
                value = a << (b & 0x1F);
              } else if (op == OpCode::kSrl) {
                value = (uint32_t)a >> (b & 0x1F);
              } else if (op == OpCode::kSra) {
                value = a >> (b & 0x1F);
              } else if (op == OpCode::kXor) {
                value = a ^ b;
              } else if (op == OpCode::kOr) {
                value = a | b;
              } else if (op == OpCode::kAnd) {
                value = a & b;
              } else {
                zero_ = SIGILL;
              }
            } else {
              zero_ = SIGILL;
            }
          } else if (op <= 0x50) {
            if (op <= OpCode::kMemcmp && argc_ == 3) {
              int addr = value = argv_[0], v = argv_[1], size = argv_[2];

              void* dest = OpCheckMM(addr, size);
              if (dest) {
                cycles_ -= 8 + 2 * size;

                if (op == OpCode::kMemset) {
                  memset(dest, v, size);
                } else {
                  void* src = OpCheckMM(v, size);
                  if (src) {
                    if (op == OpCode::kMemcpy) {
                      memmove(dest, src, size);
                    } else {
                      value = memcmp(dest, src, size);
                    }
                  }
                }
              }
            } else {
              zero_ = SIGILL;
            }
          } else {
            zero_ = SIGILL;
          }
        } else if (op < 0x200) {
          if (op < 0x180) {
            if (op < 0x140) /* 0x100, 0x120 */ {
              if (op < 0x120) {
                value = OpFuncBasic(op, argc_, argv_);
              } else {
                value = OpFuncDataFile(op, argc_, argv_);
              }
            } else /* 0x140, 0x160 */ {
              if (op < 0x160) {
                value = OpFuncRSA(op, argc_, argv_);
              } else {
                value = OpFuncP256(op, argc_, argv_);
              }
            }
          } else /* 0x180 ... 0x1FF */ {
            if (op < 0x1C0) /* 0x180, 0x1A0 */ {
              if (op < 0x1A0) {
                value = OpFuncSM2(op, argc_, argv_);
              } else {
                value = OpFuncDigest(op, argc_, argv_);
              }
            } else /* 0x1C0, 0x1FF */ {
              if (op < 0x1E0) {
                if (op < 0x1C8) {
                  value = OpFuncSM4(op, argc_, argv_);
                } else {
                  value = OpFuncTDES(op, argc_, argv_);
                }
              } else /* 0x1E0 ... 0x1FF */ {
                value = OpFuncChaChaPoly(op, argc_, argv_);
              }
            }
          }
        } else if (op < 0x300) {
          if (op < 0x280) {
            if (op < 0x240) {
              if (op < 0x220) {
                value = OpSecp256k1(op, argc_, argv_);
              } else if (op < 0x230) {
                value = OpCurve25519(op, argc_, argv_);
              } else {
                value = OpEd25519(op, argc_, argv_);
              }
            } else /* 0x240 ... 0x27F */ {
              zero_ = SIGILL;
            }
          } else /* 0x280 ... 0x2FF */ {
            zero_ = SIGILL;
          }
        } else {
          zero_ = SIGILL;
        }

        if (0 == zero_ && !void_)
          OpLoadValue(value);
      } else {
        zero_ = SIGSEGV;
      }
    }
  }

  if (zero_) {
    memset(data_, 0, kSizeData);

    zero_ = (zero_ & 0xFF) | ((nstk_ & 0xFF) << 8) | ((pc_ & 0xFF) << 16) | (1 << 30);

  } else if (kSizeOutput < kSizeData) {
    memset(&static_cast<uint8_t*>(data_)[kSizeOutput], 0, kSizeData - kSizeOutput);
  }

  return zero_;
}

}  // namespace script
}  // namespace dongle

rLANG_DECLARE_END

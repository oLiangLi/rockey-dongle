#include <Interface/dongle.h>
#include <base/base.h>

rLANG_DECLARE_MACHINE

namespace {
constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("App@T");
}

namespace dongle {

using DWORD = Dongle::DWORD;

enum class kTestingIndex : int {
  CreateDataFile = 1,

  ReadWriteDataFile,

  ReadWriteFactoryData,

  CreateRSAFile,

  RSAExec,

  SM2Exec,

  P256Exec,

};

struct Context_t {
  union {
    uint32_t argv_[4];
    uint32_t result_[4];
    uint8_t bytes_[16];
  };
  uint32_t seed_[8];
  uint32_t error_[8];

  PERMISSION permission_;
  DWORD realTime_, expireTime_, ticks_;

  uint8_t share_memory_1_[32];
  uint8_t share_memory_2_[32];

  DONGLE_INFO dongle_info_;
  uint8_t bytes[64];
};

int Testing_CreateDataFile(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  int error = 0;

  Context->result_[3] = rLANG_WORLD_MAGIC;

  rlLOGI(TAG, "Testing ... %s ...", __FUNCTION__);
  for (int id = 1; id <= 3; ++id) {
    if (0 != rockey.DeleteFile(SECRET_STORAGE_TYPE::kData, id)) {
      Context->error_[id - 1] = rockey.GetLastError();
      ++error;
    }
  }

  if (0 != rockey.CreateDataFile(1, 256, PERMISSION::kAdminstrator, PERMISSION::kAdminstrator)) {
    Context->error_[3] = rockey.GetLastError();
    ++error;
  }

  if (0 != rockey.CreateDataFile(2, 256, PERMISSION::kNormal, PERMISSION::kNormal)) {
    Context->error_[4] = rockey.GetLastError();
    ++error;
  }

  if (0 != rockey.CreateDataFile(3, 256, PERMISSION::kAnonymous, PERMISSION::kAnonymous)) {
    Context->error_[5] = rockey.GetLastError();
    ++error;
  }

  Context->result_[2] = rLANG_ATOMC_WORLD_MAGIC;

  return error;
}

int Testing_ReadWriteDataFile(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  int error = 0, counter = 0;
  uint32_t state[16];
  uint8_t stream[64], verify[64];
  memset(state, 0, sizeof(state));
  memcpy(state, Context->argv_, sizeof(Context->argv_));

  Context->result_[3] = rLANG_WORLD_MAGIC;

  rlLOGI(TAG, "Testing ... %s ...", __FUNCTION__);

  for (int id = 1; id <= 3; ++id) {
    for (int off = 0; off < 256; off += 64) {
      rlLOGI(TAG, "Write File %d %d", id, off);
      state[12] = counter++;
      rlCryptoChaCha20Block(state, stream);
      if (0 != rockey.WriteDataFile(id, off, stream, sizeof(stream))) {
        Context->error_[7] = rockey.GetLastError();
        ++error;
      }
    }
  }

  counter = 0;
  for (int id = 1; id <= 3; ++id) {
    for (int off = 0; off < 256; off += 64) {
      rlLOGI(TAG, "Read File %d %d", id, off);
      state[12] = counter++;
      rlCryptoChaCha20Block(state, verify);
      if (0 != rockey.ReadDataFile(id, off, stream, sizeof(stream))) {
        Context->error_[6] = rockey.GetLastError();
        ++error;
      }
      if (0 != memcmp(stream, verify, sizeof(verify)))
        ++error;
    }
  }

  Context->result_[2] = rLANG_ATOMC_WORLD_MAGIC;

  return error;
}

int Testing_ReadWriteFactoryData(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  int error = 0, counter = 0;
  uint32_t state[16];
  uint8_t stream[64], verify[64];
  memset(state, 0, sizeof(state));
  memcpy(state, Context->argv_, sizeof(Context->argv_));

  Context->result_[3] = rLANG_WORLD_MAGIC;

  rlLOGI(TAG, "Testing ... %s ...", __FUNCTION__);

  for (int off = 0; off < 8192; off += 64) {
    rlLOGI(TAG, "Write File %x %d", Dongle::kFactoryDataFileId, off);
    state[12] = counter++;
    rlCryptoChaCha20Block(state, stream);
    if (0 != rockey.WriteDataFile(Dongle::kFactoryDataFileId, off, stream, sizeof(stream))) {
      Context->error_[7] = rockey.GetLastError();
      ++error;
    }
  }

  counter = 0;
  for (int off = 0; off < 8192; off += 64) {
    rlLOGI(TAG, "Read File %x %d", Dongle::kFactoryDataFileId, off);
    state[12] = counter++;
    rlCryptoChaCha20Block(state, verify);
    if (0 != rockey.ReadDataFile(Dongle::kFactoryDataFileId, off, stream, sizeof(stream))) {
      Context->error_[6] = rockey.GetLastError();
      ++error;
    }
    if (0 != memcmp(stream, verify, sizeof(verify)))
      ++error;
  }

  Context->result_[2] = rLANG_ATOMC_WORLD_MAGIC;

  return error;
}

int Testing_CreateRSAFile(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  int error = 0;

  Context->result_[3] = rLANG_WORLD_MAGIC;

  rlLOGI(TAG, "Testing ... %s ...", __FUNCTION__);

  for (int id = 100; id <= 102; ++id) {
    if (rockey.DeleteFile(SECRET_STORAGE_TYPE::kRSA, id) < 0) {
      rlLOGE(TAG, "rockey.DeleteFile kRSA %d Error", id);
      Context->error_[id - 100] = rockey.GetLastError();
      ++error;
    }
  }

  if (rockey.CreatePKEYFile(SECRET_STORAGE_TYPE::kRSA, 2048, 100,
                            PKEY_LICENCE{}.SetPermission(PERMISSION::kAdminstrator)) < 0) {
    ++error;
    Context->error_[4] = rockey.GetLastError();
    rlLOGE(TAG, "rockey.CreatePKEYFile 100 Error");
  }
  if (rockey.CreatePKEYFile(SECRET_STORAGE_TYPE::kRSA, 2048, 101, PKEY_LICENCE{}.SetPermission(PERMISSION::kNormal)) <
      0) {
    ++error;
    Context->error_[5] = rockey.GetLastError();
    rlLOGE(TAG, "rockey.CreatePKEYFile 101 Error");
  }
  if (rockey.CreatePKEYFile(SECRET_STORAGE_TYPE::kRSA, 2048, 102,
                            PKEY_LICENCE{}.SetPermission(PERMISSION::kAnonymous)) < 0) {
    ++error;
    Context->error_[6] = rockey.GetLastError();
    rlLOGE(TAG, "rockey.CreatePKEYFile 102 Error");
  }

  Context->result_[2] = rLANG_ATOMC_WORLD_MAGIC;

  return error;
}

int Testing_RSAExec(Dongle& rockey, Context_t* Context_, void* ExtendBuf) {
  struct RSAExecContext : public Context_t {
    uint8_t prikey_[256];
    uint8_t pubkey_[256];
  };
  RSAExecContext* Context = static_cast<RSAExecContext*>(Context_);
  memset(Context->prikey_, 0, 256);
  memset(Context->pubkey_, 0, 256);

  int error = 0;
  uint8_t input[128], output[256], verify[256];

  size_t szOut = 256;
  uint32_t modules = 0;
  if (rockey.GenerateRSA(100, &modules, Context->pubkey_, Context->prikey_) < 0) {
    rlLOGE(TAG, "rockey.GenerateRSA 100 Error");
    return 123;
  }

  rlLOGXI(TAG, Context->pubkey_, 256, "rockey.GenerateRSA %x", modules);

  rockey.RandBytes(input, sizeof(input));

  szOut = sizeof(input);
  memcpy(output, input, sizeof(input));
  if (rockey.RSAPrivate(100, output, &szOut, true) < 0) {
    rlLOGE(TAG, "rockey.RSAPrivate sign error");
    ++error;
  } else {
    memcpy(verify, output, szOut);
    if (rockey.RSAPublic(2048, modules, Context->pubkey_, verify, &szOut, false) < 0) {
      rlLOGE(TAG, "rockey.RSAPublic verify error");
      ++error;
    } else {
      DONGLE_VERIFY(szOut == sizeof(input) && 0 == memcmp(input, verify, sizeof(input)));
    }
  }

  if (rockey.ImportRSA(102, 2048, modules, Context->pubkey_, Context->prikey_) < 0) {
    rlLOGE(TAG, "rockey.ImportRSA 102 Error");
    return 234;
  }

  szOut = sizeof(input);
  memcpy(output, input, sizeof(input));
  if (rockey.RSAPublic(2048, modules, Context->pubkey_, output, &szOut, true) < 0) {
    rlLOGE(TAG, "rockey.RSAPublic encrypt error");
    ++error;
  } else {
    DONGLE_VERIFY(szOut == 256);
    memcpy(verify, output, szOut);

    if (rockey.RSAPrivate(102, verify, &szOut, false) < 0) {
      rlLOGE(TAG, "rockey.RSAPrivate decrypt 102 error");
      ++error;
    } else {
      DONGLE_VERIFY(szOut == sizeof(input) && 0 == memcmp(input, verify, sizeof(input)));
    }

    szOut = 256;
    if (rockey.RSAPrivate(2048, modules, Context->pubkey_, Context->prikey_, output, &szOut, false) < 0) {
      rlLOGE(TAG, "rockey.RSAPrivate decrypt error");
      ++error;
    } else {
      DONGLE_VERIFY(szOut == sizeof(input) && 0 == memcmp(input, output, sizeof(input)));
    }
  }

  return error;
}

int Testing_SM2Exec(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  int error = 0;
  if (rockey.DeleteFile(SECRET_STORAGE_TYPE::kSM2, 0x8100) < 0) {
    ++error;
    Context->error_[0] = rockey.GetLastError();
  }

  if (rockey.DeleteFile(SECRET_STORAGE_TYPE::kSM2, 0x8101) < 0) {
    ++error;
    Context->error_[1] = rockey.GetLastError();
  }

  if (rockey.CreatePKEYFile(SECRET_STORAGE_TYPE::kSM2, 256, 0x8100) < 0) {
    ++error;
    Context->error_[2] = rockey.GetLastError();
  }

  if (rockey.CreatePKEYFile(SECRET_STORAGE_TYPE::kSM2, 256, 0x8101) < 0) {
    ++error;
    Context->error_[3] = rockey.GetLastError();
  }

  uint8_t X[32], Y[32], K[32], H[32], R[32], S[32];

  rockey.RandBytes(H, 32);
  if (rockey.GenerateSM2(0x8100, X, Y, K)) {
    ++error;
    Context->error_[4] = rockey.GetLastError();
    return 111;
  } else {
    rlLOGXI(TAG, X, 32, "SM2.X");
    rlLOGXI(TAG, Y, 32, "SM2.Y");
    rlLOGXI(TAG, K, 32, "SM2.K");
  }

  if (rockey.SM2Sign(0x8100, H, R, S) < 0 || rockey.SM2Verify(X, Y, H, R, S) < 0 || rockey.SM2Sign(K, H, R, S) < 0 ||
      rockey.SM2Verify(X, Y, H, R, S) < 0) {
    ++error;
    Context->error_[5] = rockey.GetLastError();
  }

  if (rockey.ImportSM2(0x8101, K) < 0) {
    ++error;
    Context->error_[6] = rockey.GetLastError();
  }

  if (rockey.SM2Sign(0x8101, H, R, S) < 0 || rockey.SM2Verify(X, Y, H, R, S) < 0 || rockey.SM2Sign(K, H, R, S) < 0 ||
      rockey.SM2Verify(X, Y, H, R, S) < 0) {
    ++error;
    Context->error_[7] = rockey.GetLastError();
  }

#if 1
  S[0] ^= 1;
  if (rockey.SM2Verify(X, Y, H, R, S) >= 0)
    ++error;
  S[0] ^= 1;
#endif

#if 1
  X[0] ^= 1;
  if (rockey.SM2Verify(X, Y, H, R, S) >= 0)
    ++error;
  X[0] ^= 1;

  DONGLE_VERIFY(rockey.SM2Verify(X, Y, H, R, S) >= 0);
#endif

  uint8_t VV[32];
  size_t szVV = 32;
  uint8_t sm2_cipher_[128];
  memset(sm2_cipher_, 0xEE, sizeof(sm2_cipher_));

#if 1
  // TODO: LiangLI, BugFix, Invalid (X, Y) point ...
  X[0] ^= 1;
  if (rockey.SM2Encrypt(X, Y, H, 32, sm2_cipher_) >= 0)
    ++error;
  X[0] ^= 1;
#endif

  if (rockey.SM2Encrypt(X, Y, H, 32, sm2_cipher_) < 0) {
    ++error;
    rlLOGXI(TAG, sm2_cipher_, sizeof(sm2_cipher_), "sm2_cipher_");
  }

  Context->result_[3] = rockey.SM2Decrypt(K, sm2_cipher_, 96 + 32, VV, &szVV);
  if (Context->result_[3] < 0 || szVV != 32 || 0 != memcmp(VV, H, 32)) {
    ++error;
  }

#if 1
  K[0] ^= 1;
  DONGLE_VERIFY(rockey.SM2Decrypt(K, sm2_cipher_, 96 + 32, VV, &szVV) < 0);
  K[0] ^= 1;

  sm2_cipher_[0] ^= 1;
  DONGLE_VERIFY(rockey.SM2Decrypt(K, sm2_cipher_, 96 + 32, VV, &szVV) < 0);
  sm2_cipher_[0] ^= 1;

  sm2_cipher_[64] ^= 1;
  DONGLE_VERIFY(rockey.SM2Decrypt(K, sm2_cipher_, 96 + 32, VV, &szVV) < 0);
  sm2_cipher_[64] ^= 1;

  DONGLE_VERIFY(rockey.SM2Decrypt(K, sm2_cipher_, 96 + 32, VV, &szVV) >= 0);
#endif

  memset(VV, 0, sizeof(VV));
  Context->result_[2] = rockey.SM2Decrypt(0x8101, sm2_cipher_, 96 + 32, VV, &szVV);
  if ((Context->result_[2] & (1<<31)) != 0 || szVV != 32 || 0 != memcmp(VV, H, 32)) {
    ++error;
  }

  return error;
}

int Testing_P256Exec(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  int error = 0;
  if (rockey.DeleteFile(SECRET_STORAGE_TYPE::kP256, 0x100) < 0) {
    ++error;
    Context->error_[0] = rockey.GetLastError();
  }

  if (rockey.DeleteFile(SECRET_STORAGE_TYPE::kP256, 0x101) < 0) {
    ++error;
    Context->error_[1] = rockey.GetLastError();
  }

  if (rockey.CreatePKEYFile(SECRET_STORAGE_TYPE::kP256, 256, 0x100) < 0) {
    ++error;
    Context->error_[2] = rockey.GetLastError();
  }

  if (rockey.CreatePKEYFile(SECRET_STORAGE_TYPE::kP256, 256, 0x101) < 0) {
    ++error;
    Context->error_[3] = rockey.GetLastError();
  }

  uint8_t X[32], Y[32], K[32], H[32], R[32], S[32];

  rockey.RandBytes(H, 32);
  if (rockey.GenerateP256(0x100, X, Y, K)) {
    ++error;
    Context->error_[4] = rockey.GetLastError();
    return 111;
  } else {
    rlLOGXI(TAG, X, 32, "P256.X");
    rlLOGXI(TAG, Y, 32, "P256.Y");
    rlLOGXI(TAG, K, 32, "P256.K");
  }

  if (rockey.P256Sign(0x100, H, R, S) < 0 || rockey.P256Verify(X, Y, H, R, S) < 0 || rockey.P256Sign(K, H, R, S) < 0 ||
      rockey.P256Verify(X, Y, H, R, S) < 0) {
    ++error;
    Context->error_[5] = rockey.GetLastError();
  }

  if (rockey.ImportP256(0x101, K) < 0) {
    ++error;
    Context->error_[6] = rockey.GetLastError();
  }

  if (rockey.P256Sign(0x101, H, R, S) < 0 || rockey.P256Verify(X, Y, H, R, S) < 0 || rockey.P256Sign(K, H, R, S) < 0 ||
      rockey.P256Verify(X, Y, H, R, S) < 0) {
    ++error;
    Context->error_[7] = rockey.GetLastError();
  }

#if 1
  S[0] ^= 1;
  if (rockey.P256Verify(X, Y, H, R, S) >= 0)
    ++error;
  S[0] ^= 1;
#endif

#if 1
  X[0] ^= 1;
  if (rockey.P256Verify(X, Y, H, R, S) >= 0)
    ++error;
  X[0] ^= 1;


  DONGLE_VERIFY(rockey.P256Verify(X, Y, H, R, S) >= 0);
#endif

  return error;
}

int Start(void* InOutBuf, void* ExtendBuf) {
  int result = 0;
  Context_t* Context = (Context_t*)InOutBuf;

#if !defined(__RockeyARM__)
  Context_t CopyContext = *Context;

  RockeyARM rockey;
  DONGLE_INFO dongle_info[64];

  result = rockey.Enum(dongle_info);
  rlLOGI(TAG, "rockey.Enum return %d/%08x", result, rockey.GetLastError());

  for (int i = 0; i < result; ++i) {
    rlLOGXI(TAG, &dongle_info[i], sizeof(DONGLE_INFO), "rockey.Enum %d/%d", i + 1, result);
  }

  result = rockey.Open(0);
  rlLOGI(TAG, "rockey.Open return %d/%08x", result, rockey.GetLastError());

  result = rockey.ResetState();
  rlLOGI(TAG, "rockey.ResetState return %d/%08x", result, rockey.GetLastError());

  result = rockey.RandBytes(Context->bytes, sizeof(Context->bytes));
  rlLOGI(TAG, "rockey.RandBytes return %d/%08X", result, rockey.GetLastError());

  if (Context->permission_ != PERMISSION::kAnonymous) {
    result = rockey.VerifyPIN(Context->permission_, nullptr, nullptr);
    rlLOGI(TAG, "rockey.VerifyPIN %d/%08X", result, rockey.GetLastError());
  }

  const char* app_dongle = getenv("WT_APP_DONGLE");
  if (app_dongle) {
    uint8_t app_[64 * 1024];
    FILE* fp = fopen(app_dongle, "rb");
    if (!fp) {
      rlLOGE(TAG, "Can't open %s for read!", app_dongle);
    } else {
      size_t size = fread(app_, 1, sizeof(app_), fp);
      fclose(fp);

      if (size < 64 || size >= 0xFFFF) {
        rlLOGE(TAG, "Invalid %s app.size %zd", app_dongle, size);
      } else {
        result = rockey.UpdateExeFile(app_, size);
        rlLOGI(TAG, "rockey.UpdateExeFile %s %d/%08X", app_dongle, result, rockey.GetLastError());
      }
    }
  }
#else  // __RockeyARM__

  Dongle rockey;

#endif  // __RockeyARM__

  result = rockey.RandBytes(Context->bytes, sizeof(Context->bytes));
  rlLOGI(TAG, "rockey.RandBytes %d/%08x", result, rockey.GetLastError());

  result = rockey.SeedSecret(Context->argv_, sizeof(Context->argv_), Context->seed_);
  rlLOGI(TAG, "rockey.SeedSecret %d/%08x", result, rockey.GetLastError(false));
  Context->seed_[7] = rockey.GetLastError();
  Context->seed_[6] = result;

  rockey.SetLEDState(LED_STATE::kBlink);

  rockey.GetRealTime(&Context->realTime_);
  rockey.GetExpireTime(&Context->expireTime_);
  rockey.GetTickCount(&Context->ticks_);
  rockey.GetDongleInfo(&Context->dongle_info_);
  rockey.GetPINState(&Context->permission_);

  rockey.ReadShareMemory(Context->share_memory_2_);
  rockey.WriteShareMemory(&Context->bytes[32]);
  rockey.ReadShareMemory(Context->share_memory_1_);

  int index = Context->argv_[0] & 0xFF, result2 = 0;
  rlLOGXI(TAG, Context, sizeof(Context_t), "rockey Test.0 return %d/%08x", result, rockey.GetLastError());
  rockey.ClearLastError();
#define DONGLE_RUN_TESTING(Name)                            \
  do {                                                      \
    if (index == static_cast<int>(kTestingIndex::Name))     \
      result2 = Testing_##Name(rockey, Context, ExtendBuf); \
  } while (0)

  DONGLE_RUN_TESTING(CreateDataFile);
  DONGLE_RUN_TESTING(ReadWriteDataFile);
  DONGLE_RUN_TESTING(ReadWriteFactoryData);
  DONGLE_RUN_TESTING(CreateRSAFile);
  DONGLE_RUN_TESTING(RSAExec);
  DONGLE_RUN_TESTING(SM2Exec);
  DONGLE_RUN_TESTING(P256Exec);

  Context->result_[0] = result;
  Context->result_[1] = result2;
  rlLOGXI(TAG, Context, sizeof(Context_t), "rockey Test.%d return %d/%08x", index, result2, rockey.GetLastError());
  result += result2;

#if !defined(__RockeyARM__)
  int main_result = 0, result3 = rockey.ExecuteExeFile(&CopyContext, sizeof(CopyContext), &main_result);
  rlLOGXI(TAG, &CopyContext, sizeof(CopyContext), "rockey.ExecuteExeFile return %d, mainRet %d, %08X", result3,
          main_result, rockey.GetLastError());
  if (result3 < 0)
    ++result;
#endif /* __RockeyARM__ */

  std::ignore = TAG;
  return 10086 - result;
}

}  // namespace dongle

rLANG_DECLARE_END

int main(int argc, char* argv[]) {
  using namespace machine;
  using namespace machine::dongle;
#ifdef _MSC_VER
  if (argc >= 2 && 0 == strcmp("-d", argv[1])) {
    while (!::IsDebuggerPresent()) {
      rlLOGI(TAG, "Wait debugger ...");
      Sleep(1000);
    }
    ::DebugBreak();
    --argc;
    ++argv;
  }
#endif /* _MSC_VER */

  rLANG_ABIREQUIRE(sizeof(Context_t) <= 1024);
  Context_t* Context = (Context_t*)calloc(1, 3 << 10);
  uint64_t ExtendBuf[(1 << 10) / 8] = {0};

  Context->permission_ = PERMISSION::kAnonymous;
  if (argc >= 2 && '-' == argv[1][0]) {
    switch (argv[1][1]) {
      case '2':
        Context->permission_ = PERMISSION::kAdminstrator;
        break;
      case '1':
        Context->permission_ = PERMISSION::kNormal;
        break;
      case '0':
        Context->permission_ = PERMISSION::kAnonymous;
        break;
    }
    --argc;
    ++argv;
  }

  for (int i = 1; i <= 4 && i < argc; ++i) {
    Context->argv_[i - 1] = strtoul(argv[i], nullptr, 16);
  }

  return Start(Context, ExtendBuf);
}

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

};

struct Context_t {
  union {
    uint32_t argv_[4];
    uint32_t result_[4];
    uint8_t bytes_[16];
  };

  uint32_t error_[8];

  PERMISSION permission_;
  DWORD realTime_, expireTime_, ticks_;

  uint8_t share_memory_1_[32];
  uint8_t share_memory_2_[32];

  DONGLE_INFO dongle_info_;
  uint8_t bytes[64];

  uint8_t prikey_[256]; // RSA/ECC ...
  uint8_t pubkey_[256]; // RSA/ECC ...
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

int Testing_RSAExec(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  int error = 0;
  uint8_t input[64], output[256], verify[256];
  size_t szOut = 256, szOut2 = 256;
  uint32_t modules = 0;

  if (rockey.GenerateRSA(100, &modules, Context->pubkey_) < 0) {
    ++error;
    rlLOGE(TAG, "rockey.GenerateRSA 100 Error");
  } else {
    rlLOGXI(TAG, Context->pubkey_, 256, "rockey.GenerateRSA %x", modules);

    rockey.RandBytes(input, sizeof(input));
    if (rockey.RSAPrivate(100, input, sizeof(input), output, &szOut, true) < 0) {
      rlLOGE(TAG, "rockey.RSAPrivate encrypt error");
      ++error;
    } else if (rockey.RSAPublic(2048, modules, Context->pubkey_, output, szOut, verify, &szOut2, false) < 0) {
      rlLOGE(TAG, "rockey.RSAPublic error");
      ++error;
    } else {
      DONGLE_VERIFY(szOut2 == sizeof(input) && 0 == memcmp(input, verify, sizeof(input)));
    }
  }

  if (rockey.GenerateRSA(101, &modules, Context->pubkey_, Context->prikey_) < 0) {
    ++error;
    rlLOGE(TAG, "rockey.GenerateRSA 101 Error");
  } else {
    rlLOGXI(TAG, Context->pubkey_, 256, "rockey.GenerateRSA.pubkey %x", modules);
    rlLOGXI(TAG, Context->prikey_, 256, "rockey.GenerateRSA.prikey");

    rockey.RandBytes(input, sizeof(input));
    szOut = 256;
    szOut2 = 256;
    DONGLE_VERIFY(rockey.RSAPublic(2048, modules, Context->pubkey_, input, sizeof(input), output, &szOut, true) >= 0 &&
                  szOut == 256);

    szOut = 256;
    szOut2 = 256;
    DONGLE_VERIFY(rockey.RSAPrivate(101, output, szOut, verify, &szOut2, false) >= 0 && szOut2 == sizeof(input));
    DONGLE_VERIFY(0 == memcmp(input, verify, 64));

    szOut = 256;
    szOut2 = 256;
    DONGLE_VERIFY(rockey.RSAPrivate(101, output, szOut, verify, &szOut2, false) >= 0 && szOut2 == sizeof(input));
    DONGLE_VERIFY(0 == memcmp(input, verify, 64));

    rockey.RandBytes(input, sizeof(input));
    szOut = 256;
    szOut2 = 256;
    DONGLE_VERIFY(rockey.RSAPublic(2048, modules, Context->pubkey_, input, sizeof(input), output, &szOut, true) >= 0 &&
                  szOut == 256);

    szOut = 256;
    szOut2 = 256;
    DONGLE_VERIFY(rockey.RSAPrivate(2048, modules, Context->pubkey_, Context->prikey_, output, szOut, verify, &szOut2,
                                    false) >= 0 && szOut2 == 64);
    DONGLE_VERIFY(0 == memcmp(input, verify, 64));
  }

  if (rockey.ImportRSA(102, 2048, modules, Context->pubkey_, Context->prikey_) < 0) {
    ++error;
    rlLOGE(TAG, "rockey.ImportRSA 102 Error");
  } else {
    rockey.RandBytes(input, sizeof(input));
    szOut = 256;
    szOut2 = 256;
    DONGLE_VERIFY(rockey.RSAPublic(2048, modules, Context->pubkey_, input, sizeof(input), output, &szOut, true) >= 0 &&
                  szOut == 256);

    szOut = 256;
    szOut2 = 256;
    DONGLE_VERIFY(rockey.RSAPrivate(102, output, szOut, verify, &szOut2, false) >= 0 && szOut2 == sizeof(input));
    DONGLE_VERIFY(0 == memcmp(input, verify, 64));

    DONGLE_VERIFY(rockey.RSAPrivate(2048, modules, Context->pubkey_, Context->prikey_, input, sizeof(input), output,
                                    &szOut, true) >= 0 &&
                  szOut == 256);
    DONGLE_VERIFY(rockey.RSAPublic(2048, modules, Context->pubkey_, output, szOut, verify, &szOut2, false) >= 0 &&
                  szOut2 == sizeof(input));
    DONGLE_VERIFY(0 == memcmp(input, verify, sizeof(input)));
  }
  
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
#else  // __RockeyARM__

  Dongle rockey;

#endif  // __RockeyARM__

  result = rockey.RandBytes(Context->bytes, sizeof(Context->bytes));

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

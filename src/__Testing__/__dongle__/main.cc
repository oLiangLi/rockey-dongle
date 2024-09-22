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

  KeyExec,

  HashExec,

  Secp256K1Exec,

  ChaChaPoly,

  Sha256Test

};

struct Context_t {
  union {
    uint32_t argv_[4];
    uint32_t result_[4];
    uint8_t bytes_[16];
  };
  union {
    uint32_t ts_[8];
    uint8_t hash_[32];
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
  DWORD tick0 = 0, tick1 = 0, tick2 = 0, tick3 = 0, tick4 = 0, tick5 = 0;
  rockey.GetTickCount(&tick0);

  for (int i = 0; i < 5; ++i) {
    if (rockey.GenerateSM2(0x8100, X, Y, K)) {
      ++error;
      Context->error_[4] = rockey.GetLastError();
      return 111;
    } else {
      rlLOGXI(TAG, X, 32, "SM2.X");
      rlLOGXI(TAG, Y, 32, "SM2.Y");
      rlLOGXI(TAG, K, 32, "SM2.K");
    }

    rockey.GetTickCount(&tick1);
    if (rockey.CheckPointOnCurveSM2(X, Y) < 0) {
      ++error;
      rlLOGE(TAG, "rockey.CheckPointOnCurveSM2 Error ...");    
    }
    rockey.GetTickCount(&tick2);
    X[0] ^= 1;
    if (rockey.CheckPointOnCurveSM2(X, Y) >= 0) {
      ++error;
      rlLOGE(TAG, "rockey.CheckPointOnCurveSM2 Error ...");    
    }
    X[0] ^= 1;
    rockey.GetTickCount(&tick3);
    rockey.DecompressPointSM2(S, X, Y[31] % 2 == 1);
    rockey.GetTickCount(&tick4);

    Context->ts_[0] = tick1;
    Context->ts_[1] = tick2;
    Context->ts_[2] = tick3;
    Context->ts_[3] = tick4;

    if (0 != memcmp(Y, S, 32)) {
      rlLOGXW(TAG, Y, 32, "DecompressPointSM2 Error!");
      rlLOGXW(TAG, S, 32, "DecompressPointSM2 Error!");
      ++error;
    }
  }
  rockey.GetTickCount(&tick5);
  Context->ts_[5] = tick5 - tick0;
  Context->ts_[6] = tick0;
  Context->ts_[7] = tick5;

  for (int i = 0; i < 2; ++i) {
    rockey.RandBytes(H, 32);
    if (rockey.SM2Sign(0x8100, H, R, S) < 0 || rockey.SM2Verify(X, Y, H, R, S) < 0 || rockey.SM2Sign(K, H, R, S) < 0 ||
        rockey.SM2Verify(X, Y, H, R, S) < 0) {
      ++error;
      Context->error_[5] = rockey.GetLastError();
    }
  }

  for (int i = 0; i < 2; ++i) {
    if (rockey.ImportSM2(0x8101, K) < 0) {
      ++error;
      Context->error_[6] = rockey.GetLastError();
    }
  }

  for (int i = 0; i < 2; ++i) {
    if (rockey.SM2Sign(0x8101, H, R, S) < 0 || rockey.SM2Verify(X, Y, H, R, S) < 0 || rockey.SM2Sign(K, H, R, S) < 0 ||
        rockey.SM2Verify(X, Y, H, R, S) < 0) {
      ++error;
      Context->error_[7] = rockey.GetLastError();
    }
  }

#if 1
  for (int i = 0; i < 2; ++i) {
    S[0] ^= 1;
    if (rockey.SM2Verify(X, Y, H, R, S) >= 0)
      ++error;
    S[0] ^= 1;
  }
#endif

  for (int i = 0; i < 2; ++i) {
#if 1
    X[0] ^= 1;
    if (rockey.SM2Verify(X, Y, H, R, S) >= 0)
      ++error;
    X[0] ^= 1;

    DONGLE_VERIFY(rockey.SM2Verify(X, Y, H, R, S) >= 0);
#endif
  }

  uint8_t VV[32];
  size_t szVV = 32;
  uint8_t sm2_cipher_[128];
  memset(sm2_cipher_, 0xEE, sizeof(sm2_cipher_));

#if 1
  for (int i = 0; i < 3; ++i) {
    X[0] ^= 1;
    if (rockey.CheckPointOnCurveSM2(X, Y) >= 0)
      ++error;
    X[0] ^= 1;
  }
#endif

  uint8_t CK[32];
  rockey.RandBytes(H, 32);
  if (rockey.SM2Encrypt(X, Y, H, 16, sm2_cipher_) < 0) {
    ++error;
    rlLOGXI(TAG, sm2_cipher_, sizeof(sm2_cipher_), "sm2_cipher_.encrypt.16");
  } else if (rockey.CheckPointOnCurveSM2(sm2_cipher_, sm2_cipher_ + 32) < 0) {
    ++error;
    rlLOGI(TAG, "CheckPointOnCurveSM2.sm2.cipher Error ....");
  }

  if (rockey.DecompressPointSM2(CK, sm2_cipher_, sm2_cipher_[63] % 2) < 0 || 0 != memcmp(CK, sm2_cipher_ + 32, 32)) {
    ++error;
    rlLOGI(TAG, "DecompressPointSM2.sm2.cipher Error ....");
  }

  szVV = 32;
  if (rockey.SM2Decrypt(0x8101, sm2_cipher_, 96 + 16, VV, &szVV) < 0 || szVV != 16 || 0 != memcmp(VV, H, 16)) {
    ++error;
    rlLOGW(TAG, "sm2_cipher_.decrypt.16 error");
  }

  rockey.RandBytes(H, 32);
  if (rockey.SM2Encrypt(X, Y, H, 10, sm2_cipher_) < 0) {
    ++error;
    rlLOGXI(TAG, sm2_cipher_, sizeof(sm2_cipher_), "sm2_cipher_.encrypt.16");
  } else if (rockey.CheckPointOnCurveSM2(sm2_cipher_, sm2_cipher_ + 32) < 0) {
    ++error;
    rlLOGI(TAG, "CheckPointOnCurveSM2.sm2.cipher Error ....");
  }

  if (rockey.DecompressPointSM2(CK, sm2_cipher_, sm2_cipher_[63] % 2) < 0 || 0 != memcmp(CK, sm2_cipher_ + 32, 32)) {
    ++error;
    rlLOGI(TAG, "DecompressPointSM2.sm2.cipher Error ....");
  }

  szVV = 32;
  if (rockey.SM2Decrypt(K, sm2_cipher_, 96 + 10, VV, &szVV) < 0 || szVV != 10 || 0 != memcmp(VV, H, 10)) {
    ++error;
    rlLOGXI(TAG, sm2_cipher_, sizeof(sm2_cipher_), "sm2_cipher_.decrypt.16");
  }

  if (rockey.SM2Encrypt(X, Y, H, 32, sm2_cipher_) < 0) {
    ++error;
    rlLOGXI(TAG, sm2_cipher_, sizeof(sm2_cipher_), "sm2_cipher_");
  } else if (rockey.CheckPointOnCurveSM2(sm2_cipher_, sm2_cipher_ + 32) < 0) {
    ++error;
    rlLOGI(TAG, "CheckPointOnCurveSM2.sm2.cipher Error ....");
  }

  if (rockey.DecompressPointSM2(CK, sm2_cipher_, sm2_cipher_[63] % 2) < 0 || 0 != memcmp(CK, sm2_cipher_ + 32, 32)) {
    ++error;
    rlLOGI(TAG, "DecompressPointSM2.sm2.cipher Error ....");
  }

  szVV = 32;
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
  for (int i = 0; i < 2; ++i) {
    if (rockey.GenerateP256(0x100, X, Y, K)) {
      ++error;
      Context->error_[4] = rockey.GetLastError();
      return 111;
    } else {
      rlLOGXI(TAG, X, 32, "P256.X");
      rlLOGXI(TAG, Y, 32, "P256.Y");
      rlLOGXI(TAG, K, 32, "P256.K");
    }

    if (rockey.CheckPointOnCurvePrime256v1(X, Y) < 0) {
      ++error;
      rlLOGE(TAG, "CheckPointOnCurvePrime256v1 Error ...");
    }

    X[0] ^= 1;
    if (rockey.CheckPointOnCurvePrime256v1(X, Y) >= 0) {
      ++error;
      rlLOGE(TAG, "CheckPointOnCurvePrime256v1 Error ...");
    }
    X[0] ^= 1;

    uint8_t V[32];
    if (rockey.DecompressPointPrime256v1(V, X, Y[31] % 2 != 0) < 0 || 0 != memcmp(V, Y, 32)) {
      ++error;
      rlLOGXE(TAG, V, 32, "DecompressPointPrime256v1 Error ...");
    }

    rockey.RandBytes(H, 32);
    if (rockey.SignMessagePrime256v1(K, H, R, S) < 0) {
      ++error;
      rlLOGE(TAG, "SignMessagePrime256v1 Error ...");
    }

    if (rockey.P256Verify(X, Y, H, R, S) < 0) {
      ++error;
      rlLOGE(TAG, "SignMessagePrime256v1/P256Verify Error ...");
    }

    if (rockey.VerifySignPrime256v1(X, Y, H, R, S) < 0) {
      ++error;
      rlLOGE(TAG, "VerifySignPrime256v1 Error ...");
    }

    R[0] ^= 1;
    if (rockey.VerifySignPrime256v1(X, Y, H, R, S) >= 0) {
      ++error;
      rlLOGE(TAG, "VerifySignPrime256v1 Error ...");
    }
    R[0] ^= 1;

    uint8_t K2[32], X2[32], Y2[32];
    if (rockey.GenerateKeyPairPrime256v1(X2, Y2, K2) < 0) {
      ++error;
      rlLOGE(TAG, "GenerateKeyPairPrime256v1 Error ...");
    }

    uint8_t SECRET1[32], SECRET2[32];
    if (rockey.ComputeSecretPrime256v1(SECRET1, X, Y, K2) < 0) {
      ++error;
      rlLOGE(TAG, "ComputeSecretPrime256v1 Error ...");
    }

    if (rockey.ComputeSecretPrime256v1(SECRET2, X2, Y2, K) < 0) {
      ++error;
      rlLOGE(TAG, "ComputeSecretPrime256v1 Error ...");
    }

    if (0 != memcmp(SECRET1, SECRET2, 32)) {
      ++error;
      rlLOGE(TAG, "0 != memcmp(SECRET1, SECRET2, 32)");
      rlLOGXE(TAG, SECRET1, 32, "SECRET1");
      rlLOGXE(TAG, SECRET2, 32, "SECRET2");
    } else {
      rlLOGXI(TAG, SECRET1, 32, "ComputeSecretPrime256v1 OK");
    }
  }

  rockey.RandBytes(H, 32);
  if (rockey.P256Sign(0x100, H, R, S) < 0 || rockey.P256Verify(X, Y, H, R, S) < 0 || rockey.P256Sign(K, H, R, S) < 0 ||
      rockey.P256Verify(X, Y, H, R, S) < 0) {
    ++error;
    Context->error_[5] = rockey.GetLastError();
  }

  if (rockey.GenerateKeyPairPrime256v1(X, Y, K) < 0) {
    ++error;
    rlLOGE(TAG, "GenerateKeyPairPrime256v1 ... 2 Error ...");
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

int Testing_KeyExec(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  int error = 0;
  uint8_t K[16], input[64], cipher[64], verify[64];

  if (rockey.DeleteFile(SECRET_STORAGE_TYPE::kTDES, 8) < 0)
    ++error;

  if (rockey.DeleteFile(SECRET_STORAGE_TYPE::kSM4, 9) < 0)
    ++error;

  if (rockey.CreateKeyFile(8, PERMISSION::kAdminstrator, SECRET_STORAGE_TYPE::kTDES) < 0)
    ++error;

  if (rockey.CreateKeyFile(9, PERMISSION::kAdminstrator, SECRET_STORAGE_TYPE::kSM4) < 0)
    ++error;

  if (rockey.RandBytes(K, sizeof(K)) < 0)
    ++error;

  if (rockey.RandBytes(input, sizeof(input)) < 0)
    ++error;

  memcpy(cipher, input, sizeof(input));
  if (rockey.SM4ECB(K, cipher, sizeof(input), true) < 0)
    ++error;

  memcpy(verify, cipher, sizeof(cipher));
  if (rockey.SM4ECB(K, verify, sizeof(input), false) < 0)
    ++error;

  if (0 != memcmp(input, verify, sizeof(input)))
    ++error;

  if (rockey.RandBytes(K, sizeof(K)) < 0)
    ++error;

  if (rockey.RandBytes(input, sizeof(input)) < 0)
    ++error;

  memcpy(cipher, input, sizeof(input));
  if (rockey.TDESECB(K, cipher, sizeof(input), true) < 0)
    ++error;

  memcpy(verify, cipher, sizeof(cipher));
  if (rockey.TDESECB(K, verify, sizeof(input), false) < 0)
    ++error;

  if (0 != memcmp(input, verify, sizeof(input)))
    ++error;

  if (rockey.RandBytes(K, sizeof(K)) < 0)
    ++error;

  if (rockey.WriteKeyFile(8, K, 16, SECRET_STORAGE_TYPE::kTDES) < 0)
    ++error;

  if (rockey.RandBytes(input, sizeof(input)) < 0)
    ++error;

  memcpy(cipher, input, sizeof(input));
  if (rockey.TDESECB(8, cipher, sizeof(cipher), true) < 0)
    ++error;

  memcpy(verify, cipher, sizeof(input));
  if (rockey.TDESECB(K, verify, sizeof(verify), false) < 0)
    ++error;

  memcpy(cipher, input, sizeof(input));
  if (rockey.TDESECB(K, cipher, sizeof(cipher), true) < 0)
    ++error;

  memcpy(verify, cipher, sizeof(input));
  if (rockey.TDESECB(8, verify, sizeof(verify), false) < 0)
    ++error;

  if (0 != memcmp(input, verify, sizeof(input)))
    ++error;

  if (rockey.RandBytes(K, sizeof(K)) < 0)
    ++error;
  if (rockey.WriteKeyFile(9, K, 16, SECRET_STORAGE_TYPE::kSM4) < 0)
    ++error;

  if (rockey.RandBytes(input, sizeof(input)) < 0)
    ++error;
  memcpy(cipher, input, sizeof(input));
  if (rockey.SM4ECB(9, cipher, sizeof(cipher), true) < 0)
    ++error;

  memcpy(verify, cipher, sizeof(cipher));
  if (rockey.SM4ECB(K, verify, sizeof(verify), false) < 0)
    ++error;

  if (rockey.RandBytes(input, sizeof(input)) < 0)
    ++error;
  memcpy(cipher, input, sizeof(input));
  if (rockey.SM4ECB(K, cipher, sizeof(cipher), true) < 0)
    ++error;

  memcpy(verify, cipher, sizeof(cipher));
  if (rockey.SM4ECB(9, verify, sizeof(verify), false) < 0)
    ++error;
  
  return error;
}

int Testing_HashExec(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  int error = 0;
  uint8_t sha1[20];
  uint8_t sm3[32];
  uint8_t input[100];

  for (int i = 1; i <= 10; ++i) {
    if (rockey.RandBytes(input, sizeof(input)) < 0)
      ++error;

    if (rockey.SHA1(input, i * 10, sha1) < 0)
      ++error;

    if (rockey.SM3(input, i * 10, sm3) < 0)
      ++error;

#if !defined(X_BUILD_native)
    auto SM3 = [](const unsigned char* d, size_t n, unsigned char* md) {
      SM3_CTX ctx;
      sm3_init(&ctx);
      sm3_update(&ctx, d, n);
      sm3_final(md, &ctx);
    };

    //input[0] ^= 1;
    uint8_t v_sha1[20], v_sm3[32];
    SHA1(input, i * 10, v_sha1);
    SM3(input, i * 10, v_sm3);

    if (0 != memcmp(v_sha1, sha1, sizeof(sha1)))
      ++error;
    if (0 != memcmp(v_sm3, sm3, sizeof(sm3)))
      ++error;
#endif /* X_BUILD_native */
  }

  return error;
}

int Testing_Secp256K1Exec(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  int error = 0;
  uint8_t X1[32], Y1[32], K1[32], V1[32];
  uint8_t X2[32], Y2[32], K2[32], V2[32];

  for (int i = 0; i < 2; ++i) {
    if (rockey.GenerateKeyPairSecp256k1(X1, Y1, K1) < 0) {
      ++error;
      rlLOGE(TAG, "GenerateKeyPairSecp256k1..1 Error ...");
    }
    if (rockey.GenerateKeyPairSecp256k1(X2, Y2, K2) < 0) {
      ++error;
      rlLOGE(TAG, "GenerateKeyPairSecp256k1..2 Error ...");
    }
    if (rockey.CheckPointOnCurveSecp256k1(X1, Y1) < 0) {
      ++error;
      rlLOGE(TAG, "CheckPointOnCurveSecp256k1 Error ...");
    }
    X1[0] ^= 1;
    if (rockey.CheckPointOnCurveSecp256k1(X1, Y1) >= 0) {
      ++error;
      rlLOGE(TAG, "CheckPointOnCurveSecp256k1 Error ...");
    }
    X1[0] ^= 1;

    if (rockey.ComputeSecretSecp256k1(V1, X1, Y1, K2) < 0) {
      ++error;
      rlLOGE(TAG, "ComputeSecretSecp256k1 .. 1 Error ...");
    }
    if (rockey.ComputeSecretSecp256k1(V2, X2, Y2, K1) < 0) {
      ++error;
      rlLOGE(TAG, "ComputeSecretSecp256k1 .. 2 Error ...");
    }

    if (0 != memcmp(V1, V2, 32)) {
      ++error;
      rlLOGE(TAG, "0 != memcmp(V1, V2, 32)");
    } else {
      rlLOGXI(TAG, V1, 32, "ComputeSecretSecp256k1 OK");
    }

    uint8_t H[32], R[32], S[32];
    if (rockey.RandBytes(H, 32) < 0) {
      ++error;
      rlLOGE(TAG, "RandBytes 32 Error ...");
    }

    if (rockey.SignMessageSecp256k1(K1, H, R, S) < 0) {
      ++error;
      rlLOGE(TAG, "SignMessageSecp256k1 Error ...");
    }

    R[0] ^= 1;
    if (rockey.VerifySignSecp256k1(X1, Y1, H, R, S) >= 0) {
      ++error;
      rlLOGE(TAG, "VerifySignSecp256k1 ... 1 Error ...");
    }
    R[0] ^= 1;

    H[0] ^= 1;
    if (rockey.VerifySignSecp256k1(X1, Y1, H, R, S) >= 0) {
      ++error;
      rlLOGE(TAG, "VerifySignSecp256k1 ... 1 Error ...");
    }
    H[0] ^= 1;

    if (rockey.VerifySignSecp256k1(X1, Y1, H, R, S) < 0) {
      ++error;
      rlLOGE(TAG, "VerifySignSecp256k1 ... 1 Error ...");
    }
  }




  return error;
}

int Testing_ChaChaPoly(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  int error = 0;
  uint32_t state[16];
  rockey.RandBytes(reinterpret_cast<uint8_t*>(state), sizeof(state));

  for (int i = 0; i < 10; ++i) {
    uint8_t sm3[32], verify[32];
    uint8_t key[64];
    uint8_t buffer[512 + 16];

#if !defined(X_BUILD_native)
    uint8_t check_[1024];
#endif /* X_BUILD_native */

    rockey.RandBytes(key, sizeof(key));
    for (int off = 0; off < 512; off += 64, ++state[12])
      rlCryptoChaCha20Block(state, &buffer[off]);

    size_t size = 1 + state[0] % 512, size_origin = size;
    if (rockey.SM3(buffer, size, sm3) < 0)
      ++error;

#if !defined(X_BUILD_native)
    {
      int out_size = 1024, mac_size = 16;
      EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
      DONGLE_VERIFY(ctx && EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key, key + 32) == 1);
      DONGLE_VERIFY(EVP_EncryptUpdate(ctx, check_, &out_size, buffer, (int)size) == 1);
      DONGLE_VERIFY((int)size == out_size);
      
      DONGLE_VERIFY(EVP_EncryptFinal_ex(ctx, check_ + out_size, &mac_size) == 1);
      DONGLE_VERIFY(mac_size == 0);
      mac_size = 16;
      DONGLE_VERIFY(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, check_ + out_size) == 1);
      EVP_CIPHER_CTX_free(ctx);
    }
#endif /* X_BUILD_native */

    if (rockey.CHACHAPOLY_Seal(key, key + 32, buffer, &size) < 0)
      ++error;

    if (size != size_origin + 16)
      ++error;

#if !defined(X_BUILD_native)
    {
      int out_size = 1024, mac_size = 16;      
      DONGLE_VERIFY(0 == memcmp(buffer, check_, size));

      EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
      DONGLE_VERIFY(ctx && EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key, key + 32) == 1);
      DONGLE_VERIFY(EVP_DecryptUpdate(ctx, check_, &out_size, buffer, (int)size - 16) == 1);
      DONGLE_VERIFY(out_size == (int)size - 16);
      DONGLE_VERIFY(EVP_DecryptFinal_ex(ctx, check_ + out_size, &mac_size) == 1 && mac_size == 0);
      DONGLE_VERIFY(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, check_ + out_size) == 1);
      EVP_CIPHER_CTX_free(ctx);
    }
#endif /* X_BUILD_native */

    if (rockey.CHACHAPOLY_Open(key, key + 32, buffer, &size) < 0)
      ++error;

    if (size_origin != size)
      ++error;

#if !defined(X_BUILD_native)
    DONGLE_VERIFY(0 == memcmp(buffer, check_, size));
#endif /* X_BUILD_native */

    if (rockey.SM3(buffer, size, verify) < 0)
      ++error;

    if (0 != memcmp(sm3, verify, 32))
      ++error;
  }

  return error;
}

int Testing_Sha256Test(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  if (rockey.SHA256(Context->argv_, sizeof(Context->argv_), Context->hash_) < 0)
    return 1;
  return 0;
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

  if (Context->permission_ == PERMISSION::kAdminstrator) {
    char pid[20] = "", admin[20] = "";
    result = rockey.GenUniqueKey("10086", 5, pid, admin);
    rlLOGI(TAG, "rockey.GenUniqueKey %d/%08x %s %s", result, rockey.GetLastError(), pid, admin);

    result = rockey.ChangePIN(PERMISSION::kAdminstrator, admin, "FFFFFFFFFFFFFFFF", 255);
    rlLOGI(TAG, "rockey.ChangePIN %d/%08x", result, rockey.GetLastError());

    result = rockey.Open(0);
    rlLOGI(TAG, "rockey.Open return %d/%08x", result, rockey.GetLastError());

    result = rockey.VerifyPIN(PERMISSION::kAdminstrator, nullptr, nullptr);
    rlLOGI(TAG, "rockey.VerifyPIN %d/%08X", result, rockey.GetLastError());

    result = rockey.SetUserID(rLANG_WORLD_MAGIC);
    rlLOGI(TAG, "rockey.SetUserID %d/%08x", result, rockey.GetLastError());
  }

  result = rockey.LimitSeedCount(10);
  rlLOGI(TAG, "rockey.LimitSeedCount %d/%08x", result, rockey.GetLastError());

  result = rockey.SetExpireTime(10000);
  rlLOGI(TAG, "rockey.SetExpireTime %d/%08x", result, rockey.GetLastError());

  result = rockey.ChangePIN(PERMISSION::kNormal, "12345678", "12345678", 10);
  rlLOGI(TAG, "rockey.ChangePIN %d/%08x", result, rockey.GetLastError());

  result = rockey.ChangePIN(PERMISSION::kAdminstrator, "FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", 255);
  rlLOGI(TAG, "rockey.ChangePIN %d/%08x", result, rockey.GetLastError());

  result = rockey.ResetUserPIN("FFFFFFFFFFFFFFFF");
  rlLOGI(TAG, "rockey.ResetUserPIN %d/%08x", result, rockey.GetLastError());

#if 0
  result = rockey.FactoryReset();
  rlLOGI(TAG, "rockey.FactoryReset %d/%08x", result, rockey.GetLastError());
#endif

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

  if (!rockey.Ready())
    exit(1);
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
#define DONGLE_RUN_TESTING(Name)                                 \
  do {                                                           \
    if (index == static_cast<int>(kTestingIndex::Name)) {        \
      rlLOGI(TAG, "===== DONGLE_RUN_TESTING: %s ===== ", #Name); \
      result2 = Testing_##Name(rockey, Context, ExtendBuf);      \
    }                                                            \
  } while (0)

  DONGLE_RUN_TESTING(CreateDataFile);
  DONGLE_RUN_TESTING(ReadWriteDataFile);
  DONGLE_RUN_TESTING(ReadWriteFactoryData);
  DONGLE_RUN_TESTING(CreateRSAFile);
  DONGLE_RUN_TESTING(RSAExec);
  DONGLE_RUN_TESTING(SM2Exec);
  DONGLE_RUN_TESTING(P256Exec);
  DONGLE_RUN_TESTING(KeyExec);
  DONGLE_RUN_TESTING(HashExec);
  DONGLE_RUN_TESTING(Secp256K1Exec);
  DONGLE_RUN_TESTING(ChaChaPoly);
  DONGLE_RUN_TESTING(Sha256Test);

  Context->result_[0] = result;
  Context->result_[1] = result2;
  rlLOGXI(TAG, Context, sizeof(Context_t), "rockey Test.%d return %d/%08x", index, result2, rockey.GetLastError());
  result += result2;

#if !defined(__RockeyARM__)
  auto start = rLANG_GetTickCount();
  int main_result = 0, result3 = rockey.ExecuteExeFile(&CopyContext, sizeof(CopyContext), &main_result);
  auto end = rLANG_GetTickCount();
  rlLOGXI(TAG, &CopyContext, sizeof(CopyContext), "rockey.ExecuteExeFile return %d, mainRet %d, %08X, in %lld ms", result3,
          main_result, rockey.GetLastError(), static_cast<long long>(end - start));
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

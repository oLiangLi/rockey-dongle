#include <Interface/dongle.h>
#include <Interface/script.h>
#include <base/base.h>
#include <tuple>

#ifdef _WIN32
#include <corecrt_io.h>
#elif !defined(__RockeyARM__)
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif /* _WIN32 */

#include "app.h"

rLANG_DECLARE_MACHINE

namespace dongle {

static constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("SHELL");

template <class _Ty = RockeyARM>
int Main(void* InOutBuf, void* ExtendBuf, _Ty* dongle) {
  int result = 0;

#if defined(__RockeyARM__) || defined(__EMULATOR__)
  script::VM_t vm(dongle, InOutBuf, ExtendBuf);
  result = script::RockeyTrustExecutePrepare(vm, InOutBuf, ExtendBuf);

  if (0 == result)
    result = vm.Execute();

  if (0 == result && vm.kSizeOutput < 1024) {
    dongle->RandBytes((uint8_t*)InOutBuf + vm.kSizeOutput, 1024 - vm.kSizeOutput);
  }
#else  /* __RockeyARM__ || __EMULATOR__ */
  int execute_result = 0;
  result = dongle->ExecuteExeFile(InOutBuf, 1024, &execute_result);
  rlLOGI(TAG, "dongle->ExecuteExeFile return %d/%d", result, execute_result);
  if (0 == result)
    result = execute_result;
#endif /* __RockeyARM__ || __EMULATOR__ */

  if (0 != result) {
    memset(InOutBuf, 0, 1024);
  }

  return result;
}

#if !defined(__RockeyARM__) && !defined(__EMULATOR__)
char* StringFromHID(char* hid, const uint8_t v[12]) {
  rl_HEX_Write(hid, v, 12);
  memmove(&hid[9], &hid[8], 17);
  hid[8] = '-'; /* 012345678-091234... */
  for (char* p = hid; *p; ++p) {
    *p = tolower(*p);
  }
  return hid;
}

int OpenRockeyById(const uint8_t use_hid[12], RockeyARM& rockey) {
  DONGLE_INFO info[64];
  int rockey_count = rockey.Enum(info);
  int rockey_select = -1;
  for (int i = 0; i < rockey_count; ++i) {
    if (0 == memcmp(info[i].hid_, use_hid, 12)) {
      rockey_select = i;
      break;
    }
  }

  char s_hid_1[50], s_hid_2[50];
  if (rockey_select < 0 || 0 != rockey.Open(rockey_select)) {
    rlLOGE(TAG, "Can't open dongle: %s", StringFromHID(s_hid_1, use_hid));
    return -ENOENT;
  }

  if (0 != rockey.GetDongleInfo(&info[0]) || 0 != memcmp(use_hid, info[0].hid_, 12)) {
    rlLOGE(TAG, "Open dongle hid mismatch %s %s", StringFromHID(s_hid_1, use_hid),
           StringFromHID(s_hid_2, info[0].hid_));
    return -EFAULT;
  }

  return 0;
}

static int RockeyARM_VerifyExecvHelper(uint16_t opCode, uint16_t verify, RockeyARM* dongle) {
  int result = 0;
  using ScriptText = script::ScriptText;
  using WorldCreateHeader = script::WorldCreateHeader;
  using WorldPublic = script::WorldPublic;

  WorldPublic public_;
  result = dongle->ReadDataFile(Dongle::kFactoryDataFileId, WorldPublic::kOffsetDataFile, &public_, sizeof(public_));
  if (0 != result)
    return result;

  union {
    uint8_t InOutBuffer[1024];
    struct {
      WorldCreateHeader header_;
      ScriptText script_text_;
    } V;
  };

  const char* prefix = nullptr;
  RAND_bytes(InOutBuffer, sizeof(InOutBuffer));
  V.header_.zero_ = 0;
  V.header_.world_magic_ = rLANG_WORLD_MAGIC;
  V.header_.create_magic_ = WorldCreateHeader::kMagicCreate;
  V.header_.target_magic_ = WorldCreateHeader::kMagicWorld;

  if (verify == 0) {
    prefix = "TEXT.SIGN";
    V.script_text_.file_magic_ = ScriptText::kLimitFileMagic;
  } else if (verify == 1) {
    prefix = "NORMAL   ";
    V.script_text_.file_magic_ = rLANG_ATOMC_WORLD_MAGIC;
  } else {
    if (verify == 42)
      prefix = "DATA.SIGN";
    else
      prefix = "BOOTSTRAP";
    V.script_text_.file_magic_ = ScriptText::kAdminFileMagic;
  }

  V.script_text_.ver_major_ = rLANG_DONGLE_VERSION_MAJOR;
  V.script_text_.ver_minor_ = rLANG_DONGLE_VERSION_MINOR;
  V.script_text_.size_public_ = 0;

  V.script_text_.script_[0] = opCode;
  V.script_text_.script_[1] = (uint16_t)script::OpCode::kExit | 0x0C00;  // argc = 1; void = 1;

  uint8_t sm3[32];
  rlCryptoChaChaPolyCtx ctx;

  int sizeData = verify != 42 ? 1024 - 256 : 1024 - 256 - 64;
  if (verify == 42) {
    result = dongle->SM3(&InOutBuffer[256], sizeData, sm3);
    if (0 != result)
      return result;
    result = dongle->SM2Sign(WorldPublic::kFileSM2ECIES, sm3, &InOutBuffer[1024 - 64], &InOutBuffer[1024 - 32]);
    if (0 != result)
      return result;
  } else if (verify == 0) {
    result = dongle->SM3(&V.script_text_, sizeof(ScriptText) - 64 - 32, sm3);
    if (0 != result)
      return result;
    result = dongle->SM2Sign(WorldPublic::kFileSM2ECIES, sm3, (uint8_t*)&V.script_text_ + sizeof(ScriptText) - 64 - 32,
                             (uint8_t*)&V.script_text_ + sizeof(ScriptText) - 64);
    if (0 != result)
      return result;
  }

  result = dongle->SM3(&V.script_text_, sizeof(ScriptText) - 16, sm3);
  if (0 != result)
    return result;

  rlCryptoChaChaPolyInit(&ctx);
  rlCryptoChaChaPolySetKey(&ctx, sm3);
  rlCryptoChaChaPolyStarts(&ctx, &V.script_text_.nonce_[0], 1);
  rlCryptoChaChaPolyUpdate(&ctx, &InOutBuffer[256], &InOutBuffer[256], sizeData);
  rlCryptoChaChaPolyFinish(&ctx, V.script_text_.check_);

  if (42 == verify || 0 == verify || 1 == verify) {
    size_t size = sizeof(ScriptText);
    memmove(InOutBuffer, &V.script_text_, size);
    result = dongle->RSAPublic(2048, *(uint32_t*)public_.dongle_rsa2048_pubkey_, &public_.dongle_rsa2048_pubkey_[4],
                               InOutBuffer, &size, true);
    if (0 != result || size != 256)
      return -EFAULT;
  }

  int execute_result = 0;
  long long ts = rLANG_GetTickCount();
  result = dongle->ExecuteExeFile(InOutBuffer, 1024, &execute_result);
  ts = rLANG_GetTickCount() - ts;

  if (0 == result && 0 == verify && 0 == execute_result) {
    rlLOGI(TAG, "%s ExecuteExeFile opCode: %04X, verify: %04X, result: %d, exec.result: %08X, OK", prefix, opCode,
           verify, result, execute_result);
  } else if (0 == result && (execute_result & 0xFFFF) == verify) {
    rlLOGI(TAG, "%s ExecuteExeFile opCode: %04X, verify: %04X, result: %d, exec.result: %08X, OK", prefix, opCode,
           verify, result, execute_result);
    execute_result = verify;
  } else {
    rlLOGE(TAG, "%s ExecuteExeFile opCode: %04X, verify: %04X, result: %d, exec.result: %08X, Failed!", prefix, opCode,
           verify, result, execute_result);
  }

  if (0 == result && execute_result != verify)
    result = -EFAULT;
  return result;
}

static int RockeyARM_Lock(RockeyARM* dongle, const char* hid) {
  char sPIN[20];
  uint8_t zPIN[8];

  RAND_bytes(zPIN, sizeof(zPIN));
  dongle->RandBytes((uint8_t*)sPIN, sizeof(sPIN));
  for (int i = 0; i < 8; ++i)
    zPIN[i] ^= sPIN[i];

  rl_HEX_Write(sPIN, zPIN, 8);

  for (int i = 0; i < 3; ++i) {
    rlLOGW(TAG, "%d) RockeyARM_Lock <%s> HPIN <%s>", i, hid, sPIN);
  }

  const char* const default_admin_pin_ = dongle->GetDefaultPIN(PERMISSION::kAdministrator);
  return dongle->ChangePIN(PERMISSION::kAdministrator, default_admin_pin_, sPIN, 100);
}

int Utilities(int stdout_, const char* type, RockeyARM* dongle, bool adminMode, const char* hid) {
  int result = 0;

  DONGLE_INFO dongle_info_;
  result = dongle->GetDongleInfo(&dongle_info_);
  if (0 != result)
    return result;

  enum class EncodeFormat : int { kHex, kBase64 };
  auto ReadLine = [](uint8_t* line, int size, EncodeFormat encode, const char* prompt) {
    int bytes = 0;
    constexpr int kInputLimit = 128 * 1024;
    rlLOGW(TAG, "Input %s, size: %d:", prompt, size);
    Dongle::SecretBuffer<kInputLimit, char> sline_;
    Dongle::SecretBuffer<kInputLimit> buffer_;

    memset(&buffer_[0], 0, kInputLimit);

    for (;;) {
      memset(&sline_[0], 0, kInputLimit);
      if (!fgets(&sline_[0], kInputLimit - 1, stdin))
        return -EIO;
      if (sline_[0] && sline_[0] != '\r' && sline_[0] != '\n')
        break;
    }

    for (int i = 0; i < kInputLimit; ++i) {
      if (sline_[i] == '\r' || sline_[i] == '\n')
        sline_[i] = 0;
      if (sline_[i] == 0)
        break;
    }

    if (encode == EncodeFormat::kBase64)
      bytes = rl_BASE64_Read(&buffer_[0], &sline_[0], -1);
    else
      bytes = rl_HEX_Read(&buffer_[0], &sline_[0], -1);

    if (bytes == size) {
      memcpy(line, &buffer_[0], size);
      return 0;
    }

    rlLOGE(TAG, "ReadLine %s size: %d, read: %d", prompt, size, bytes);
    return -EIO;
  };

  rlLOGI(TAG, ">>>> Enter Utilities.%s ....", type);
  if (0 == strcmp(type, "dashboard")) {
    constexpr int kSizePublic = 8 * 1024;
    uint8_t kFactoryData[kSizePublic + 32];
    char line[kSizePublic + kSizePublic / 2] = "";
    result = dongle->ReadDataFile(dongle->kFactoryDataFileId, 0, &kFactoryData[0], kSizePublic);
    if (0 == result) {
      Sha256Ctx().Init().Update(&kFactoryData[0], kSizePublic).Final(&kFactoryData[kSizePublic]).Init();
      int len = rl_BASE64_Write(line, kFactoryData, sizeof(kFactoryData));
      line[len++] = '\n';
      if (len != write(stdout_, line, len))
        result = -EIO;
    }
  } else if (0 == strcmp(type, "--reset")) {
    ///
    /// 内部使用, 一些之前的uKey没有正常的重置管理员密码为缺省值, 不要在后台中把接口暴露出去 ...
    ///
    uint8_t sha256[32], check[32];
    result = ReadLine(sha256, 32, EncodeFormat::kBase64, "Input SHA256(HID):");
    Sha256Ctx().Init().Update(hid, strlen(hid)).Final(check);
    if (0 != memcmp(sha256, check, 32)) {
      rlLOGE(TAG, "Verify SHA256(HID) Failed!");
      result = -EFAULT;
    } else {
      result = dongle->FactoryReset();
      rlLOGI(TAG, "result = dongle->FactoryReset return %d", result);
    }
  } else if (0 == strcmp(type, "factory")) {
    constexpr int kSizeUid = 4;
    constexpr int kSizeSeed = 64;
    constexpr int kSizeFile = 65520;
    constexpr int kSizeTotal = kSizeUid + kSizeSeed + kSizeFile;

    ///
    /// 工厂设置需要输入以下内容(请牢记种子码对应PIN码): || UID[4] | SEED[64] | TRUST[65520] | SHA256[32] ||
    ///
    Dongle::SecretBuffer<kSizeTotal + 32> init_;
    result = ReadLine(&init_[0], kSizeTotal + 32, EncodeFormat::kBase64, "Input UID/Seed/ExeFile/Verify:");

    if (0 == result) {
      uint8_t verify[32];
      Sha256Ctx().Init().Update(&init_[0], kSizeTotal).Final(verify);
      if (0 != memcmp(&init_[kSizeTotal], verify, 32)) {
        rlLOGE(TAG, "SHA256.Verify Failed!");
        result = -EBADMSG;
      } else {
        rlLOGXI(TAG, verify, sizeof(verify), "Verify INPUT.SHA256 OK:");
      }
    }

    if (0 == result)
      result = dongle->FactoryReset();

    RockeyARM factory_;
    if (0 == result) {
      rlLOGI(TAG, "dongle->FactoryReset OK!");
      for (int loop = 0; loop < 10; ++loop) {
#if defined(_WIN32)
        ::Sleep(1000);
#else  /* */
        ::usleep(1'000'000);
#endif /* */
        result = OpenRockeyById(dongle_info_.hid_, factory_);
        rlLOGI(TAG, "Open dongle loop %d => %d", loop, result);
        if (0 == result)
          break;
      }

      if (0 == result)
        dongle = &factory_;
    }

    const char* const default_admin_pin_ = dongle->GetDefaultPIN(PERMISSION::kAdministrator);
    if (0 == result)
      result = dongle->VerifyPIN(PERMISSION::kAdministrator, default_admin_pin_, nullptr);

    if (0 == result) {
      uint32_t uid = 0;
      for (int i = 0; i < kSizeUid; ++i)
        uid = (uid << 8) | init_[i];

      char admin[32], pid[10], stag_[10];
      result = dongle->GenUniqueKey(&init_[kSizeUid], kSizeSeed, pid, admin);
      rlLOGW(TAG, "dongle->GenUniqueKey: pid %s/%s, admin: %s => %d", pid,
             rLANG_DECLARE_MAGIC_Vs(strtoul(pid, nullptr, 16), stag_), admin, result);
      if (0 == result) {
        result = dongle->ChangePIN(PERMISSION::kAdministrator, admin, default_admin_pin_, 255);
        rlLOGW(TAG, "dongle->ChangePIN.default => %d", result);
        if (0 == result) {
          result = dongle->VerifyPIN(PERMISSION::kAdministrator, default_admin_pin_, nullptr);
          rlLOGW(TAG, "dongle->VerifyPIN.default => %d", result);
        }
        if (0 == result) {
          result = dongle->SetUserID(uid);
          rlLOGW(TAG, "dongle->SetUserID %08X => %d", (int)uid, result);
        }
      }
    }

    if (0 == result) {
      result = dongle->UpdateExeFile(&init_[kSizeUid + kSizeSeed], kSizeFile);
      rlLOGW(TAG, "dongle->UpdateExeFile => %d", result);
    }
  } else if (0 == strcmp(type, "lock")) {
    ///
    /// 当 KeyID : 1,2,3,4 已经被正确的创建, MASTER_SECRET已经创建, 系统已经初始化完成 ...
    /// 1) 我们可以使用SM2ECIES签名的代码作为管理员运行, 不应该再有管理员了 ...
    /// 2) 应该彻底的忘记管理员PIN码以避免uKey内容被无意识的修改或者读取    ...
    ///
    char s_sha256[80], s_check[80];
    uint8_t sha256[32] = {0}, check[32] = {0}, dashboard[8192];

    if (!adminMode) {
      rlLOGE(TAG, "[EACCES]Utilities.Lock kAdministrator require!!");
      result = -EACCES;
    }

    if (0 == result)
      result = dongle->ReadDataFile(dongle->kFactoryDataFileId, 0, &dashboard[0], sizeof(dashboard));
    if (0 == result)
      result = ReadLine(sha256, 32, EncodeFormat::kBase64, "Input SHA256(Dashboard):");
    Sha256Ctx().Init().Update(dashboard, sizeof(dashboard)).Final(check);

    if (0 == result && 0 != memcmp(sha256, check, 32)) {
      rl_HEX_Write(s_sha256, sha256, 32);
      rl_HEX_Write(s_check, check, 32);
      rlLOGE(TAG, "SHA256(Dashboard) mismatch '%s' != '%s'!", s_sha256, s_check);
      result = -EFAULT;
    }

    if (0 == result) {
      rlLOGI(TAG, "Check HASH Value OK!!");
      result = RockeyARM_VerifyExecvHelper((uint16_t)script::OpCode::kLoadUI | 42, 42, dongle);

      if (0 == result)
        result = RockeyARM_VerifyExecvHelper((uint16_t)script::OpCode::kLoadUI | 1, 1, dongle);

      for (int loop = 0; 0 == result && loop < 3; ++loop) {
        uint32_t verify = rand();
        RAND_bytes((uint8_t*)&verify, sizeof(verify));
        verify = (verify & 0xfff) | 0x400;
        result = RockeyARM_VerifyExecvHelper((uint16_t)script::OpCode::kLoadUI | verify, verify, dongle);
      }

      if (0 == result)
        result = RockeyARM_VerifyExecvHelper((uint16_t)script::OpCode::kVerifyWorldPublic, 0, dongle);

      if (0 == result) {
        rlLOGI(TAG, "kVerifyWorldPublic OK!");
        result = RockeyARM_Lock(dongle, hid);
      }
    }
  } else {
    rlLOGE(TAG, "##ENOENT: Utilities.%s NOT IMPLEMENTS YET!!", type);
    result = rLANG_E_CLASSNOTFOUND;
  }
  if (0 == result && 4 != write(stdout_, "OK\n\n", 4))
    result = -EIO;
  rlLOGI(TAG, ">>>> Leave Utilities.%s => %d", type, result);
  return result == 0 ? 0 : EXIT_FAILURE;
}

#endif /* !defined(__RockeyARM__) && !defined(__EMULATOR__) */

#if defined(__RockeyARM__) && !defined(__EMULATOR__)
int Start(void* InOutBuf, void* ExtendBuf) {
  Dongle rockey;
  return Main(InOutBuf, ExtendBuf, &rockey);
}
#endif /* defined(__RockeyARM__) && !defined(__EMULATOR__) */

}  // namespace dongle

rLANG_DECLARE_END

#if !defined(__RockeyARM__)
int main(int argc, char* argv[]) {
  using namespace machine;
  using namespace machine::dongle;
  using namespace machine::dongle::script;

  rlLOGI(TAG, "ZION.Execv argc: %d", argc);
  for (int i = 0; i < argc; ++i) {
    rlLOGI(TAG, "  argv[%d/%d] : %s", i, argc, argv[i]);
  }

  uint64_t InOutBuf[(3 << 10) / 8] = {0};
  uint64_t ExtendBuf[(1 << 10) / 8] = {0};

#if defined(_WIN32)
  if (argc >= 2 && 0 == strcmp("-d", argv[1])) {
    --argc;
    ++argv;

    while (!::IsDebuggerPresent()) {
      rlLOGW(TAG, "Wait DebuggerPresent ...");
      ::Sleep(1000);
    }
    //::DebugBreak();
  }
#endif /* */

  if (argc >= 2 && 0 == strcmp("--check", argv[1])) {
    --argc;
    ++argv;

    constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("z@foo");
    rlLOGI(TAG, "FoobarTestings %p, %p", InOutBuf, ExtendBuf);

    auto Wait = [] {
#if defined(_WIN32)
      ::Sleep(500);
#else  /* */
      ::usleep(500);
#endif /* */
    };

    uint8_t input[64];
    uint8_t sha256_1[32], sha256_2[32];
    uint8_t sha384_1[48], sha384_2[48];
    uint8_t sha512_1[64], sha512_2[64];
    uint8_t pubkey_ed25519_1[32], pubkey_ed25519_2[32], sign_ed25519_1[64], sign_ed25519_2[64];
    uint8_t pubkey_x25519_1[32], pubkey_x25519_2[32], secret_1[32], secret_2[32];
    int error = 0;

    for (int i = 0; i < 2; ++i) {
      RAND_bytes(input, sizeof(input));
      rlLOGXI(TAG, input, sizeof(input), "Input[64]");

      rlCryptoShaCtx ctx;
      Sha256Ctx().Init().Update(input, sizeof(input)).Final(sha256_1);
      Sha384Ctx().Init().Update(input, sizeof(input)).Final(sha384_1);
      Sha512Ctx().Init().Update(input, sizeof(input)).Final(sha512_1);

      rlCryptoSha256CtxInit(&ctx);
      rlCryptoSha256CtxUpdate(&ctx, input, sizeof(input));
      rlCryptoSha256CtxFinal(&ctx, sha256_2);
      rlCryptoSha384CtxInit(&ctx);
      rlCryptoSha384CtxUpdate(&ctx, input, sizeof(input));
      rlCryptoSha384CtxFinal(&ctx, sha384_2);
      rlCryptoSha512CtxInit(&ctx);
      rlCryptoSha512CtxUpdate(&ctx, input, sizeof(input));
      rlCryptoSha512CtxFinal(&ctx, sha512_2);

      rlLOGXI(TAG, sha256_1, sizeof(sha256_1), "Sha256Ctx()");
      rlLOGXI(TAG, sha256_2, sizeof(sha256_2), "rlCryptoSha256Ctx()");
      if (0 != memcmp(sha256_1, sha256_2, sizeof(sha256_1)))
        ++error, rlLOGE(TAG, "SHA256.Check Failed!");
      else
        rlLOGI(TAG, "SHA256.Check OK!");
      Wait();

      rlLOGXI(TAG, sha384_1, sizeof(sha384_1), "Sha384Ctx()");
      rlLOGXI(TAG, sha384_2, sizeof(sha384_2), "rlCryptoSha384Ctx()");
      if (0 != memcmp(sha384_1, sha384_2, sizeof(sha384_1)))
        ++error, rlLOGE(TAG, "SHA384.Check Failed!");
      else
        rlLOGI(TAG, "SHA384.Check OK!");
      Wait();

      rlLOGXI(TAG, sha512_1, sizeof(sha512_1), "Sha512Ctx()");
      rlLOGXI(TAG, sha512_2, sizeof(sha512_2), "rlCryptoSha512Ctx()");
      if (0 != memcmp(sha512_1, sha512_2, sizeof(sha512_1)))
        ++error, rlLOGE(TAG, "SHA512.Check Failed!");
      else
        rlLOGI(TAG, "SHA512.Check OK!");
      Wait();

      Ed25519().ComputePubkey(ExtendBuf, pubkey_ed25519_1, input);
      rlCryptoEd25519Pubkey(pubkey_ed25519_2, input);

      rlLOGXI(TAG, pubkey_ed25519_1, sizeof(pubkey_ed25519_1), "Ed25519().ComputePubkey()");
      rlLOGXI(TAG, pubkey_ed25519_2, sizeof(pubkey_ed25519_2), "rlCryptoEd25519Pubkey()");
      if (0 != memcmp(pubkey_ed25519_1, pubkey_ed25519_2, sizeof(pubkey_ed25519_1)))
        ++error, rlLOGE(TAG, "rlCryptoEd25519Pubkey.Check Failed!");
      else
        rlLOGI(TAG, "rlCryptoEd25519Pubkey OK!");
      Wait();

      Ed25519().Sign(ExtendBuf, sign_ed25519_1, input, sizeof(input), pubkey_ed25519_1, input);
      rlCryptoEd25519Sign(sign_ed25519_2, input, sizeof(input), pubkey_ed25519_2, input);

      rlLOGXI(TAG, sign_ed25519_1, sizeof(sign_ed25519_1), "Ed25519().Sign()");
      rlLOGXI(TAG, sign_ed25519_2, sizeof(sign_ed25519_2), "rlCryptoEd25519Sign");
      if (0 != memcmp(sign_ed25519_1, sign_ed25519_2, sizeof(sign_ed25519_1)))
        ++error, rlLOGE(TAG, "rlCryptoEd25519Sign.Check Failed!");
      else
        rlLOGI(TAG, "rlCryptoEd25519Sign.Check OK!");
      Wait();

      int v1 = Ed25519().Verify(ExtendBuf, input, sizeof(input), sign_ed25519_1, pubkey_ed25519_1);
      int v2 = rlCryptoEd25519Verify(input, sizeof(input), sign_ed25519_2, pubkey_ed25519_2);
      rlLOGI(TAG, "rlCryptoEd25519Verify %d %d", v1, v2);

      if (v1 != v2)
        ++error, rlLOGE(TAG, "rlCryptoEd25519Verify Failed!");
      Wait();

      uint8_t pkey1[32], pkey2[32];
      RAND_bytes(pkey1, sizeof(pkey1));
      RAND_bytes(pkey2, sizeof(pkey2));

      Curve25519().ComputePubkey(pubkey_x25519_1, pkey1);
      rlCryptoX25519Pubkey(pubkey_x25519_2, pkey1);
      rlLOGXI(TAG, pubkey_x25519_1, sizeof(pubkey_x25519_1), "Curve25519().ComputePubkey()");
      rlLOGXI(TAG, pubkey_x25519_2, sizeof(pubkey_x25519_2), "rlCryptoX25519Pubkey()");
      if (0 != memcmp(pubkey_x25519_1, pubkey_x25519_2, sizeof(pubkey_x25519_1)))
        ++error, rlLOGE(TAG, "rlCryptoX25519Pubkey Failed!");
      else
        rlLOGI(TAG, "rlCryptoX25519Pubkey OK!");
      Wait();

      Curve25519().ComputePubkey(pubkey_x25519_1, pkey1);
      Curve25519().ComputePubkey(pubkey_x25519_2, pkey2);
      rlLOGXI(TAG, pubkey_x25519_2, sizeof(pubkey_x25519_2), "Curve25519().ComputePubkey.2");

      Curve25519().X25519(secret_1, pkey2, pubkey_x25519_1);
      Curve25519().X25519(secret_2, pkey1, pubkey_x25519_2);
      if (0 != memcmp(secret_1, secret_2, sizeof(secret_1)))
        ++error, rlLOGE(TAG, "Curve25519().X25519 Failed!");
      else
        rlLOGI(TAG, "Curve25519().X25519 OK!");

      rlCryptoX25519Pubkey(pubkey_x25519_1, pkey1);
      rlCryptoX25519Pubkey(pubkey_x25519_2, pkey2);
      rlCryptoX25519(secret_1, pkey2, pubkey_x25519_1);
      rlCryptoX25519(secret_2, pkey1, pubkey_x25519_2);
      rlLOGXI(TAG, secret_1, sizeof(secret_1), "rlCryptoX25519.1");
      rlLOGXI(TAG, secret_2, sizeof(secret_2), "rlCryptoX25519.2");
      if (0 != memcmp(secret_1, secret_2, sizeof(secret_1)))
        ++error, rlLOGE(TAG, "rlCryptoX25519 Failed!");
      else
        rlLOGI(TAG, "rlCryptoX25519 OK!");
      Wait();

      rlCryptoX25519Pubkey(pubkey_x25519_1, pkey1);
      rlCryptoX25519Pubkey(pubkey_x25519_2, pkey2);
      Curve25519().X25519(secret_1, pkey2, pubkey_x25519_1);
      rlCryptoX25519(secret_2, pkey1, pubkey_x25519_2);
      rlLOGXI(TAG, secret_1, sizeof(secret_1), "rlCryptoX25519.X.1");
      rlLOGXI(TAG, secret_2, sizeof(secret_2), "rlCryptoX25519.X.2");
      if (0 != memcmp(secret_1, secret_2, sizeof(secret_1)))
        ++error, rlLOGE(TAG, "rlCryptoX25519 Failed!");
      else
        rlLOGI(TAG, "rlCryptoX25519 OK!");
      Wait();
    }

    rlLOGW(TAG, "Foobar Tests Error %d", error);
    Wait();
  }

  int result = 0;
  int stdout_ = dup(fileno(stdout));

  /**
   *!
   */
  close(fileno(stdout));
  std::ignore = dup2(fileno(stderr), fileno(stdout));

#if defined(__EMULATOR__)
  const char* dongleFile = ".foobar-dongle.bin";
  const char* dongleSecret = "1234567812345678";
  const char* adminPasswd = "-"; /* default Administrator, 'X' for Anonymous */

  if (argc < 2) {
    rlLOGE(TAG, "usage: RockeyEmu <input> [dongleFile] [dongleSecret] [X]");
    exit(EXIT_FAILURE);
  }

  if (argc > 2)
    dongleFile = argv[2];

  if (argc > 3)
    dongleSecret = argv[3];

  if (argc > 4)
    adminPasswd = argv[4];

  Emulator rockey(adminPasswd[0] != 'X' ? PERMISSION::kAdministrator : PERMISSION::kAnonymous);
  if (rockey.Open(dongleFile, dongleSecret) < 0)
    rockey.Create(dongleSecret);
#elif !defined(__RockeyARM__)
  RockeyARM rockey;
  if (argc >= 2 && 0 == strcmp(argv[1], "--list")) {
    constexpr int kCountDongle = 80;
    char line[2048] = "";
    union {
      DONGLE_INFO info[kCountDongle];
      uint8_t data[kCountDongle * sizeof(DONGLE_INFO)];
    };

    int count = rockey.Enum(info);
    if (count < 0 || count > 64)
      count = 0;

    for (int i = 0; i < count; ++i) {
      char hid[50];
      const DONGLE_INFO& v = info[i];
      rlLOGI(TAG, /* birthday : 1248BCD */
             "[%d/%d], Ver: %08x Type: %08x, PID: %08x, UID: %08x, birthday: 20%02x-%02x-%02x %02x:%02x:%02x, HID: %s",
             i, count, v.ver_, v.type_, v.pid_, v.uid_, v.birthday_[0], v.birthday_[1], v.birthday_[2], v.birthday_[3],
             v.birthday_[4], v.birthday_[5], StringFromHID(hid, v.hid_));
    }

    const int kSizeTotal = count * sizeof(DONGLE_INFO);
    Sha256Ctx().Init().Update(data, kSizeTotal).Final(&data[kSizeTotal]).Init();

    int len = rl_BASE64_Write(line, &data[0], kSizeTotal + 32);
    len += sprintf(&line[len], "\nOK\n\n");
    if (len != write(stdout_, line, len))
      return -EIO;
    return 0;
  }

  if (argc < 3) {
    DONGLE_INFO info[64];
    const int count = rockey.Enum(info);
    rlLOGE(TAG, "usage: RockeyARM <input> <hid> [admin]");

    for (int i = 0; i < count; ++i) {
      char hid[50];
      const DONGLE_INFO& v = info[i];
      rlLOGI(TAG, /* birthday : 1248BCD */
             "[%d/%d], Ver: %08x Type: %08x, PID: %08x, UID: %08x, birthday: 20%02x-%02x-%02x %02x:%02x:%02x, HID: %s",
             i, count, v.ver_, v.type_, v.pid_, v.uid_, v.birthday_[0], v.birthday_[1], v.birthday_[2], v.birthday_[3],
             v.birthday_[4], v.birthday_[5], StringFromHID(hid, v.hid_));
    }
    exit(EXIT_FAILURE);
  }

  uint8_t use_hid[12];
  const char* adminPasswd = nullptr;
  char hexHid[32] = "";

  if (argc > 3)
    adminPasswd = argv[3];

  for (char *inp = argv[2], *oup = hexHid; *inp && oup - hexHid < 30; ++inp) {
    if (isxdigit(*inp)) {
      *oup++ = *inp;
    } else if (*inp != '-') {
      hexHid[0] = 0;
      break;
    }
  }

  if (24 != strlen(hexHid)) {
    rlLOGE(TAG, "Invalid HID %s", argv[2]);
    exit(10);
  }
  rl_HEX_Read(use_hid, hexHid, 24);

  DONGLE_INFO dongle_info_;
  char s_hid_1[50], s_hid_2[50];

  result = OpenRockeyById(use_hid, rockey);
  if (0 != result || 0 != rockey.ResetState()) {
    rlLOGE(TAG, "rockey.ResetState Failed!");
    exit(EXIT_FAILURE);
  }

  if (adminPasswd) {
    int remain = -1;
    const char* const passwd = 0 == strcmp(adminPasswd, "-") ? nullptr : adminPasswd;
    if (0 != rockey.VerifyPIN(PERMISSION::kAdministrator, passwd, &remain)) {
      rlLOGE(TAG, "VerifyPIN Error, remain %d", remain);
      exit(EXIT_FAILURE);
    }
  } else {
    if (rockey.ReadDataFile(Dongle::kFactoryDataFileId, WorldPublic::kOffsetDataFile + WorldPublic::kOffsetDongleInfo,
                            &dongle_info_, sizeof(DONGLE_INFO)) < 0 ||
        0 != memcmp(use_hid, dongle_info_.hid_, 12)) {
      rlLOGE(TAG, "Open dongle hid mismatch %s %s!!", StringFromHID(s_hid_1, use_hid),
             StringFromHID(s_hid_2, dongle_info_.hid_));
      exit(EXIT_FAILURE);
    }
  }

  if (argv[1][0] == '-' && argv[1][1] == '-')
    return Utilities(stdout_, argv[1] + 2, &rockey, adminPasswd != nullptr, StringFromHID(s_hid_1, use_hid));
#endif /* __EMULATOR__ || !__RockeyARM__ */

  char line[4 * 1024] = {0};
  uint8_t binary[4 * 1024];
  const char* input = argv[1];

  if (0 == strcmp(input, "-")) {
    for (;;) {
      rlLOGW(TAG, "Input Message:");
      memset(line, 0, sizeof(line));
      if (!fgets(line, sizeof(line) - 1, stdin))
        break;
      for (auto& cc : line) {
        if (cc == 0 || cc == 13 || cc == 10) {
          cc = 0;
          break;
        }
      }
      if (line[0])
        break;
    }
    input = line;
  }

  int input_size = (int)strlen(input);
  if (input_size > (int)sizeof(binary)) {
    rlLOGE(TAG, "Out-of-memory %d", input_size);
    exit(EXIT_FAILURE);
  }

  int size_binary = rl_BASE64_Read(binary, input, input_size);
  if (1024 != size_binary) {
    rlLOGE(TAG, "EINVAL: Input message.size %d != 1024", size_binary);
    exit(EXIT_FAILURE);
  }

  memcpy(InOutBuf, binary, 1024);

  long long ts = rLANG_GetTickCount();
  result = Main(InOutBuf, ExtendBuf, &rockey);
  ts = rLANG_GetTickCount() - ts;

  if (0 == result) {
    rlLOGI(TAG, "Rockey.Execute OK in %lld ms", ts);
    memcpy(binary, InOutBuf, 1024);
    Sha256Ctx().Init().Update(&binary[0], 1024).Final(&binary[1024]).Init();
    int output_size = rl_BASE64_Write(line, binary, 1024 + 32);
    output_size += sprintf(&line[output_size], "\nOK\n\n");
    int write_size = write(stdout_, line, output_size);
    if (output_size != write_size) {
      rlLOGW(TAG, "[*IO*]Write output file error %d => %d", output_size, write_size);
      result = -EIO;
    }
  } else {
    rlLOGE(TAG, "Rockey.Execute Error %d in %lld ms", result, ts);
  }

  memset(InOutBuf, 0, sizeof(InOutBuf));
  memset(ExtendBuf, 0, sizeof(ExtendBuf));
  memset(binary, 0, sizeof(binary));
  memset(line, 0, sizeof(line));

#if defined(__EMULATOR__)
  rockey.Write(dongleFile);
#else  /* RockeyARM */
  rockey.ResetState();
#endif /* __EMULATOR__ */

  return result == 0 ? 0 : EXIT_FAILURE;
}
#endif /* main */

#ifdef __linux__

/**
 *! warning: Using 'xxx' in statically linked applications requires at runtime the shared libraries from the glibc
 *version used for linking
 */
rLANGEXPORT void* dlopen(const char* filename, int flags) {
  errno = ENOSYS;
  return nullptr;
}
rLANGEXPORT int dlclose(void* handle) {
  errno = ENOSYS;
  return -1;
}
rLANGEXPORT int getaddrinfo(const char* node,
                            const char* service,
                            const struct addrinfo* hints,
                            struct addrinfo** res) {
  errno = ENOSYS;
  return -1;
}
rLANGEXPORT void freeaddrinfo(struct addrinfo* res) {}
rLANGEXPORT struct hostent* gethostbyname(const char* name) {
  errno = ENOSYS;
  return nullptr;
}

/**
 *!
 */
struct DSO_METHOD {
  const char* impl;
  void* NullMethod[16];
};
static struct DSO_METHOD dso_meth_null = {"NULL shared library method"};

rLANGEXPORT struct DSO_METHOD* DSO_METHOD_openssl(void) {
  return &dso_meth_null;
}

#endif /* __linux__ */

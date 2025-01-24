#include <Interface/dongle.h>
#include <Interface/script.h>
#include <base/base.h>
#include <tuple>

#if !defined(__RockeyARM__)
#include <third_party/nlohmann/json.hpp>
#endif /* __RockeyARM__ */

#include "app.h"

rLANG_DECLARE_MACHINE

namespace dongle {
namespace {
constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("App@K");

#if !defined(__RockeyARM__)
#if defined(__EMULATOR__)
const char* dongleFile = ".foobar-dongle.bin";
const char* dongleSecret = "1234567812345678";
#else  /* !__EMULATOR__ */
const char* adminPasswd = nullptr;
uint8_t use_hid[12];
#endif /* !__EMULATOR__ */

struct DongleInput {
  bool encrypt_script_ = false;
  bool update_shm_ = false;
  bool origin_data_ = false;
  bool dongle_exec_ = false;
  bool logout_ = true;

  size_t size_public_ = 0;
  size_t size_data_ = 0;  // [0...768]/1024

  uint8_t script_[2 * script::VM_t::kSizeCode];
  uint8_t data_[1024];

  size_t size_import_ = 0;  // 4K limit ...
  uint8_t shm_[32];
  uint8_t import_data_[4096];
};
DongleInput dongle_input_;

void Initialize(Dongle* dongle, void* InOutBuf, void* ExtendBuf) {
  if (dongle_input_.size_public_ > 1024) {
    rlLOGE(TAG, "Invalid size.public %zd .GT. 1024", dongle_input_.size_public_);
    exit(99);
  }

  if (dongle_input_.update_shm_) {
    if (0 != dongle->WriteShareMemory(dongle_input_.shm_))
      exit(100);
  }

  if (dongle_input_.size_import_) {
    void* p = dongle_input_.import_data_;
    size_t sz = dongle_input_.size_import_;
    if (sz > 4096) {
      rlLOGE(TAG, "Shared data size %zd .GT. 4096", sz);
      exit(101);
    }
    if (0 != dongle->WriteDataFile(Dongle::kFactoryDataFileId, 0, p, sz))
      exit(102);
  }

  uint8_t sm3[32];
  uint8_t* const vmdata = (uint8_t*)InOutBuf;
  union {
    uint8_t data_[256];
    DongleScriptText text_;
    struct {
      WorldCreateHeader header_;
      DongleScriptText text_;
    } raw_;
  } v;
  rLANG_ABIREQUIRE(sizeof(v) == 256);

  if (dongle_input_.origin_data_) {
    if (1024 != dongle_input_.size_data_) {
      rlLOGE(TAG, "Invalid encrypt origin.script (size %zd .NE. 1024) request!", dongle_input_.size_data_);
      exit(103);
    }
    memcpy(vmdata, dongle_input_.data_, 1024);
  } else if (!dongle_input_.encrypt_script_) {
    if (dongle_input_.size_data_ > 1024 - 256) {
      rlLOGE(TAG, "Invalid input data size %zd .GT. (1024-256)", dongle_input_.size_data_);
      exit(105);
    }

    auto* p = &v.raw_;
    p->header_.zero_ = 0;
    p->header_.world_magic_ = rLANG_WORLD_MAGIC;
    p->header_.create_magic_ = WorldCreateHeader::kMagicCreate;
    p->header_.target_magic_ = WorldCreateHeader::kMagicWorld;

    p->text_.file_magic_ = DongleScriptText::kAdminFileMagic;
    p->text_.ver_major_ = rLANG_DONGLE_VERSION_MAJOR;
    p->text_.ver_minor_ = rLANG_DONGLE_VERSION_MINOR;
    p->text_.size_public_ = (uint16_t)dongle_input_.size_public_;
    memcpy(&p->text_.script_[0], dongle_input_.script_, sizeof(dongle_input_.script_));

    memset(&vmdata[256], 0, 1024 - 256);
    memcpy(&vmdata[256], dongle_input_.data_, dongle_input_.size_data_);
    if (dongle->RandBytes(p->text_.nonce_, sizeof(p->text_.nonce_)) < 0)
      exit(106);
    if (dongle->SM3(&p->text_, sizeof(DongleScriptText) - 16, sm3) < 0)
      exit(107);

    rlCryptoChaChaPolyCtx ctx;
    rlCryptoChaChaPolyInit(&ctx);
    rlCryptoChaChaPolySetKey(&ctx, sm3);
    rlCryptoChaChaPolyStarts(&ctx, sm3, 1);
    rlCryptoChaChaPolyUpdate(&ctx, &vmdata[256], &vmdata[256], 1024 - 256);
    rlCryptoChaChaPolyFinish(&ctx, p->text_.check_);

    memcpy(vmdata, &v.data_[0], sizeof(v));
  } else {
    struct {
      uint32_t modules_;
      uint8_t public_[256];
    } kMasterKey;
    rLANG_ABIREQUIRE(260 == sizeof(kMasterKey));

    if (dongle_input_.size_data_ > 1024 - 256) {
      rlLOGE(TAG, "Invalid input data size %zd .GT. (1024-256)", dongle_input_.size_data_);
      exit(111);
    }

    if (dongle->ReadDataFile(Dongle::kFactoryDataFileId,
                             DonglePublic::kOffsetDonglePublic + DonglePublic::kOffsetPubkey_RSA2048, &kMasterKey,
                             sizeof(kMasterKey)) < 0 ||
        kMasterKey.modules_ < 3) {
      rlLOGE(TAG, "Read RSA2048.Master Failed!");
      exit(112);
    }

    auto* text = &v.text_;
    if (dongle->RandBytes(sm3, sizeof(sm3)) < 0) {
      rlLOGE(TAG, "dongle->RandBytes Failed!");
      exit(113);
    }

    memcpy(&text->file_magic_, sm3, sizeof(text->file_magic_));
    memcpy(&text->nonce_, &sm3[16], sizeof(text->nonce_));
    text->ver_major_ = rLANG_DONGLE_VERSION_MAJOR;
    text->ver_minor_ = rLANG_DONGLE_VERSION_MINOR;
    text->size_public_ = (uint16_t)dongle_input_.size_public_;
    memcpy(&text->script_[0], dongle_input_.script_, sizeof(dongle_input_.script_));
    text->file_magic_ &= ~1; /* VERIFY(text->file_magic_ != DongleScriptText::kAdminFileMagic) */

    memset(&vmdata[256], 0, 1024 - 256);
    memcpy(&vmdata[256], dongle_input_.data_, dongle_input_.size_data_);
    if (dongle->SM3(&text, sizeof(DongleScriptText) - 16, sm3) < 0)
      exit(114);

    rlCryptoChaChaPolyCtx ctx;
    rlCryptoChaChaPolyInit(&ctx);
    rlCryptoChaChaPolySetKey(&ctx, sm3);
    rlCryptoChaChaPolyStarts(&ctx, sm3, 1);
    rlCryptoChaChaPolyUpdate(&ctx, &vmdata[256], &vmdata[256], 1024 - 256);
    rlCryptoChaChaPolyFinish(&ctx, text->check_);

    size_t size = sizeof(DongleScriptText);
    if (dongle->RSAPublic(2048, kMasterKey.modules_, kMasterKey.public_, &v.data_[0], &size, true) < 0)
      exit(115);

    memcpy(vmdata, &v.data_[0], sizeof(v));
  }
}
#endif /* __RockeyARM__ */
}  // namespace

int DecryptScriptData(script::VM_t& vm, const DongleScriptText* text, size_t szData) {
  uint8_t mac[16];
  uint8_t sm3[32];

  uint8_t* const vmdata = static_cast<uint8_t*>(vm.data_) + 256;
  if (text->ver_major_ != rLANG_DONGLE_VERSION_MAJOR || text->ver_minor_ != rLANG_DONGLE_VERSION_MINOR)
    return -EINVAL;
  if (text->size_public_ > 1024)
    return -EINVAL;

  vm.dongle_->SM3(text, sizeof(DongleScriptText) - 16, sm3);

  rlCryptoChaChaPolyCtx ctx;
  rlCryptoChaChaPolyInit(&ctx);
  rlCryptoChaChaPolySetKey(&ctx, sm3);
  rlCryptoChaChaPolyStarts(&ctx, sm3, 0);
  rlCryptoChaChaPolyUpdate(&ctx, vmdata, vmdata, szData);
  rlCryptoChaChaPolyFinish(&ctx, mac);
  if (0 != memcmp(mac, text->check_, 16))
    return -EINVAL;
  return 0;
}

int Initialize(script::VM_t& vm) {
  int result = 0;
  PERMISSION permission_login = PERMISSION::kAnonymous;

#if !defined(__RockeyARM__) && !defined(__EMULATOR__)
  if (adminPasswd) {
    permission_login = PERMISSION::kAdminstrator;
  } else
#else  /* */
  {
    result = vm.dongle_->GetPINState(&permission_login);
  }
#endif /* !__RockeyARM__ && !__EMULATOR__ */
  if (0 != result)
    return 101;

  union {
    uint8_t data_[256];
    DongleScriptText text_;
    struct {
      WorldCreateHeader header_;
      DongleScriptText text_;
    } raw_;
  } v;

  rLANG_ABIREQUIRE(256 == sizeof(v));
  memcpy(&v, vm.data_, 256);

  size_t size = sizeof(v);
  result = vm.dongle_->RSAPrivate(DonglePublic::kFileRSA2048, v.data_, &size, false);
  if (result < 0) {
    memcpy(&v, vm.data_, 256);
    const WorldCreateHeader& header = v.raw_.header_;
    if (header.zero_ == 0 && header.world_magic_ == rLANG_WORLD_MAGIC &&
        header.create_magic_ == WorldCreateHeader::kMagicCreate &&
        header.target_magic_ == WorldCreateHeader::kMagicWorld &&
        v.raw_.text_.file_magic_ == DongleScriptText::kAdminFileMagic &&
        permission_login == PERMISSION::kAdminstrator) {
      memmove(&v.text_, &v.raw_.text_, sizeof(DongleScriptText));
      vm.valid_permission_ = PERMISSION::kAdminstrator;
      if (0 != DecryptScriptData(vm, &v.text_, 1024 - 256))
        return 102;
    } else {
      return 103;
    }
  } else if (size != sizeof(DongleScriptText)) {
    rlLOGE(TAG, "Invalid scirpt text size %zd", size);
    return 120;
  } else if (v.text_.file_magic_ == DongleScriptText::kAdminFileMagic) {
    uint8_t sm3[32], sign[64];
    uint8_t ecies_pubkey[64];
    uint8_t* const vmdata = (uint8_t*)vm.data_;
    memcpy(sign, &vmdata[1024 - 64], 64);
    if (0 != DecryptScriptData(vm, &v.text_, 1024 - 256 - 64))
      return 104;
    if (vm.dongle_->ReadDataFile(Dongle::kFactoryDataFileId,
                                 DonglePublic::kOffsetDonglePublic + DonglePublic::kOffsetPubkey_SM2ECIES,
                                 &ecies_pubkey, 64) < 0)
      return 105;
    if (vm.dongle_->SM3(vmdata + 256, 1024 - 256 - 64, sm3) < 0)
      return 106;
    if (vm.dongle_->SM2Verify(&ecies_pubkey[0], &ecies_pubkey[32], sm3, &sign[0], &sign[32]) < 0)
      return 107;
    if (vm.dongle_->SM2Sign(DonglePublic::kFileSM2ECIES, sm3, &sign[0], &sign[32]) < 0) /* Check SM2.ecies key */
      return 108;
    if (vm.dongle_->SM2Verify(&ecies_pubkey[0], &ecies_pubkey[32], sm3, &sign[0], &sign[32]) < 0)
      return 109;
    vm.valid_permission_ = PERMISSION::kAdminstrator;
  } else {
    if (0 != DecryptScriptData(vm, &v.text_, 1024 - 256))
      return 110;
  }

  vm.Initialize(&v.text_.script_, sizeof(v.text_.script_), v.text_.size_public_);
  return 0;
}

int Start(void* InOutBuf, void* ExtendBuf) {
  int result = 0;
#if !defined(__RockeyARM__) && defined(__EMULATOR__)
  Emulator rockey(PERMISSION::kAdminstrator);
  if (rockey.Open(dongleFile, dongleSecret) < 0)
    rockey.Create(dongleSecret);
  Initialize(&rockey, InOutBuf, ExtendBuf);
#elif !defined(__RockeyARM__)
  RockeyARM rockey;
  DONGLE_INFO info[64];
  int count = rockey.Enum(info), select = -1;
  for (int i = 0; i < count; ++i) {
    if (0 == memcmp(info[i].hid_, use_hid, 12)) {
      select = i;
      break;
    }
  }
  if (select < 0) {
    rlLOGXE(TAG, use_hid, sizeof(use_hid), "Can't open dongle:");
    exit(11);
  }
  if (0 != rockey.Open(select)) {
    rlLOGXE(TAG, use_hid, sizeof(use_hid), "Open dongle failed!");
    exit(12);
  }
  if (0 != rockey.GetDongleInfo(&info[0]) || 0 != memcmp(use_hid, info[0].hid_, 12)) {
    rlLOGXE(TAG, use_hid, sizeof(use_hid), "Open dongle hid mismatch!!");
    exit(13);
  }

  if (!adminPasswd) {
    if (rockey.ReadDataFile(Dongle::kFactoryDataFileId,
                            DonglePublic::kOffsetDonglePublic + DonglePublic::kOffsetDongleInfo, &info[0],
                            sizeof(DONGLE_INFO)) < 0 ||
        0 != memcmp(use_hid, info[0].hid_, 12)) {
      rlLOGXE(TAG, use_hid, sizeof(use_hid), "Open dongle hid mismatch!!");
      exit(14);
    }
  }

  if (dongle_input_.logout_ && 0 != rockey.ResetState()) {
    rlLOGE(TAG, "rockey.ResetState Error!");
    exit(15);
  }

  Initialize(&rockey, InOutBuf, ExtendBuf);

  if (adminPasswd) {
    int remain = -1;
    const char* const passwd = 0 == strcmp(adminPasswd, "-") ? nullptr : adminPasswd;
    if (0 != rockey.VerifyPIN(PERMISSION::kAdminstrator, passwd, &remain)) {
      rlLOGE(TAG, "VerifyPIN Error, remain %d", remain);
      exit(16);
    }
  }
#else  /* __RockeyARM__ */
  Dongle rockey;
#endif /* __RockeyARM__ */

#if !defined(__RockeyARM__) && !defined(__EMULATOR__)
  uint8_t BackupInOutBuf[1024];
  memcpy(BackupInOutBuf, InOutBuf, 1024);
#endif /* ... X ... */

  script::VM_t vm(&rockey, InOutBuf, ExtendBuf);

  result = Initialize(vm);
  if (0 != result)
    return result;

#if !defined(__RockeyARM__)
  if (dongle_input_.size_public_ != vm.kSizeOutput) {
    rlLOGE(TAG, "VM.kSizeOutput mismatch %zd => %d", dongle_input_.size_public_, vm.kSizeOutput);
    exit(17);
  }
#endif /* __RockeyARM__ */

#if !defined(__RockeyARM__) && !defined(__EMULATOR__)
  if (dongle_input_.dongle_exec_) {
    int ret = 0;
    long long ticks = rLANG_GetTickCount();
    memcpy(InOutBuf, BackupInOutBuf, 1024);
    result = rockey.ExecuteExeFile(InOutBuf, 1024, &ret);
    ticks = rLANG_GetTickCount() - ticks;
    rlLOGW(TAG, "rockey.ExecuteExeFile Error %d/%d %08X in %lld", result, ret, ret, ticks);

    if (0 != result || 0 != ret) {
      if (0 == result)
        result = ret;
    }
  } else
#endif /* !__RockeyARM__ && !__EMULATOR__ */
  {
    result = vm.Execute();
  }

#if !defined(__RockeyARM__) && defined(__EMULATOR__)
  rockey.Write(dongleFile);
#endif /* __RockeyARM__ */

  if (0 != result) {
    memset(InOutBuf, 0, 1024);
  } else {
    size_t szOut = vm.kSizeOutput;
    if (szOut > 1024)
      szOut = 1024;
    std::ignore = szOut;

    rlLOGXI(TAG, InOutBuf, szOut, "Exec dongle OK!");
  }
  return result;
}

#if !defined(__RockeyARM__)
void Usage() {
#if defined(__EMULATOR__)
  rlLOGE(TAG, "usage: dongleEmu <input> [dongleFile] [dongleSecret]");
#else  /* __EMULATOR__ */
  RockeyARM rockey;
  DONGLE_INFO info[64];
  rlLOGE(TAG, "usage: dongleApp [--exec] <input> <hid> [admin]");
  int count = rockey.Enum(info);

  for (int i = 0; i < count; ++i) {
    char hid[50];
    rl_HEX_Write(hid, info[i].hid_, sizeof(info[i].hid_));
    memmove(&hid[9], &hid[8], 17);
    hid[8] = '-'; /* 012345678-091234... */
    for (char* p = hid; *p; ++p)
      *p = tolower(*p);
    rlLOGXI(TAG, &info[i].birthday_, sizeof(info[i].birthday_),
            "Dongle [%d/%d], Ver: %08x Type: %08x, PID: %08x, UID: %08x, HID: %s", i, count, info[i].ver_,
            info[i].type_, info[i].pid_, info[i].uid_, hid);
  }
#endif /* __EMULATOR__ */
}
#endif /* !__RockeyARM__ */

}  // namespace dongle

rLANG_DECLARE_END

int main(int argc, char* argv[]) {
  using namespace machine;
  using namespace machine::dongle;
  uint64_t InOutBuf[(3 << 10) / 8] = {0};
  uint64_t ExtendBuf[(1 << 10) / 8] = {0};

  const char* input = nullptr;

#if defined(_WIN32)
  if (argc >= 2 && 0 == strcmp("-d", argv[1])) {
    rlLOGW(TAG, ".......");
    --argc;
    ++argv;

    while (!::IsDebuggerPresent()) {
      rlLOGW(TAG, "Wait DebuggerPresent ...");
      ::Sleep(1000);
    }
  }
#endif /* */

#if !defined(__RockeyARM__) && defined(__EMULATOR__)
  if (argc < 2) {
    machine::dongle::Usage();
    exit(1);
  }
  input = argv[1];
  if (argc >= 3)
    dongleFile = argv[2];
  if (argc >= 4)
    dongleSecret = argv[3];
#elif !defined(__RockeyARM__)
  char hexHid[32] = "";

  if (argc >= 2 && 0 == strcmp("--exec", argv[1])) {
    dongle_input_.dongle_exec_ = true;
    --argc;
    ++argv;
  }

  if (argc < 3 || argc > 4) {
    machine::dongle::Usage();
    exit(1);
  }
  input = argv[1];
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

  if (argc > 3)
    adminPasswd = argv[3];
#endif /* __RockeyARM__ */

#if !defined(__RockeyARM__)
  {
    constexpr size_t kSizeLimit = 64 * 1024;
    char json_text[kSizeLimit + 1];
    FILE* fp = fopen(input, "rb");
    if (!fp) {
      rlLOGE(TAG, "Can't open %s for read!", input);
      exit(2);
    }
    size_t size = fread(json_text, 1, kSizeLimit, fp);
    fclose(fp);

    if (size <= 0 || size >= kSizeLimit) {
      rlLOGE(TAG, "Read file %s invalid size %zd", input, size);
      exit(4);
    }
    json_text[size] = 0;

    try {
      auto json = nlohmann::json::parse(json_text, json_text + size);

      auto decodeBase64 = [&](const std::string& key) {
        std::string value = json[key].get<std::string>();
        size_t len = value.length();
        std::vector<uint8_t> result(4 + len * 3 / 4);

        int size = rl_BASE64_Read(&result[0], value.c_str(), (int)len);
        result.resize(size);

        return result;
      };

      dongle_input_.size_public_ = static_cast<size_t>(json["size_public"].get<int>());
      if (json.find("logout") != json.end())
        dongle_input_.logout_ = json["logout"].get<bool>();

      if (json.find("shm") != json.end()) {
        auto shm = decodeBase64("shm");
        if (shm.size() != 32) {
          rlLOGE(TAG, "shm.size %zd != 32", shm.size());
          exit(5);
        }
        dongle_input_.update_shm_ = true;
        memcpy(dongle_input_.shm_, &shm[0], 32);
      }

      if (json.find("import_data") != json.end()) {
        auto import_data = decodeBase64("import_data");
        if (import_data.size() > 4096) {
          rlLOGE(TAG, "Import.data.size %zd .GT. 4096", import_data.size());
          exit(5);
        }

        dongle_input_.size_import_ = import_data.size();
        memcpy(&dongle_input_.import_data_[0], &import_data[0], import_data.size());
      }

      if (json.find("encrypt") != json.end()) {
        dongle_input_.encrypt_script_ = json["encrypt"].get<bool>();
      }

      if (json.find("origin") != json.end()) {
        auto origin_data = decodeBase64("origin");
        if (origin_data.size() != 1024) {
          rlLOGE(TAG, "origin.size %zd != 1024", origin_data.size());
          exit(5);
        }
        dongle_input_.origin_data_ = true;
        dongle_input_.size_data_ = 1024;
        memcpy(dongle_input_.data_, &origin_data[0], 1024);
      } else {
        auto code = decodeBase64("code");
        if (code.size() > sizeof(dongle_input_.script_) || code.size() % 2 != 0) {
          rlLOGE(TAG, "Invalid code.size %zd", code.size());
          exit(5);
        }
        memcpy(dongle_input_.script_, &code[0], code.size());

        if (json.find("data") != json.end()) {
          auto data = decodeBase64("data");
          if (data.size() > 1024 - 256) {
            rlLOGE(TAG, "Invalid data.size %zd .GT. %d", data.size(), 1024 - 256);
            exit(5);
          }

          dongle_input_.size_data_ = data.size();
          memcpy(dongle_input_.data_, &data[0], data.size());
        }
      }
    } catch (const std::exception& err) {
      rlLOGXE(TAG, json_text, size, "Read %s json error %s", input, err.what());
      exit(5);
    }
  }
#endif /* __RockeyARM__ */

  std::ignore = TAG;
  std::ignore = input;

  return machine::dongle::Start(InOutBuf, ExtendBuf);
}

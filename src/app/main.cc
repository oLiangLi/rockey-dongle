#include <Interface/dongle.h>
#include <Interface/script.h>
#include <base/base.h>
#include <tuple>

#ifdef _WIN32
#include <corecrt_io.h>
#elif !defined(__RockeyARM__)
#include <errno.h>
#include <execinfo.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif /* _WIN32 */

#include "app.h"

rLANG_DECLARE_MACHINE

namespace dongle {

static constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("SHELL");

template <class _Ty>
int Main(void* InOutBuf, void* ExtendBuf, _Ty* dongle) {
  int result = 0;

#if defined(__RockeyARM__) || defined(__EMULATOR__)
  script::VM_t vm(dongle, InOutBuf, ExtendBuf);
  result = script::RockeyTrustExecutePrepare(vm, InOutBuf, ExtendBuf);

  if (0 == result)
    result = vm.Execute();

  if (0 == result && vm.kSizeOutput < 1024) {
    memset((uint8_t*)InOutBuf + vm.kSizeOutput, 0, 1024 - vm.kSizeOutput);
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
  uint64_t InOutBuf[(3 << 10) / 8] = {0};
  uint64_t ExtendBuf[(1 << 10) / 8] = {0};

  int stdout_ = dup(fileno(stdout));

  /**
   *!
   */
  close(fileno(stdout));
  std::ignore = dup2(fileno(stderr), fileno(stdout));

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

  Emulator rockey(adminPasswd[0] != 'X' ? PERMISSION::kAdminstrator : PERMISSION::kAnonymous);
  if (rockey.Open(dongleFile, dongleSecret) < 0)
    rockey.Create(dongleSecret);
#elif !defined(__RockeyARM__)
  RockeyARM rockey;
  DONGLE_INFO info[64];
  int rockey_count = rockey.Enum(info);
  int rockey_select = -1;

  auto StringFromHID = [](char* hid, const uint8_t v[12]) {
    rl_HEX_Write(hid, v, 12);
    memmove(&hid[9], &hid[8], 17);
    hid[8] = '-'; /* 012345678-091234... */
    for (char* p = hid; *p; ++p) {
      *p = tolower(*p);
    }
    return hid;
  };

  if (argc < 3) {
    const int count = rockey_count;
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

  for (int i = 0; i < rockey_count; ++i) {
    if (0 == memcmp(info[i].hid_, use_hid, 12)) {
      rockey_select = i;
      break;
    }
  }

  char s_hid_1[50], s_hid_2[50];
  if (rockey_select < 0 || 0 != rockey.Open(rockey_select)) {
    rlLOGE(TAG, "Can't open dongle: %s", StringFromHID(s_hid_1, use_hid));
    exit(EXIT_FAILURE);
  }

  if (0 != rockey.GetDongleInfo(&info[0]) || 0 != memcmp(use_hid, info[0].hid_, 12)) {
    rlLOGE(TAG, "Open dongle hid mismatch %s %s", StringFromHID(s_hid_1, use_hid),
           StringFromHID(s_hid_2, info[0].hid_));
    exit(EXIT_FAILURE);
  }

  if (0 != rockey.ResetState()) {
    rlLOGE(TAG, "rockey.ResetState Failed!");
    exit(EXIT_FAILURE);
  }

  if (adminPasswd) {
    int remain = -1;
    const char* const passwd = 0 == strcmp(adminPasswd, "-") ? nullptr : adminPasswd;
    if (0 != rockey.VerifyPIN(PERMISSION::kAdminstrator, passwd, &remain)) {
      rlLOGE(TAG, "VerifyPIN Error, remain %d", remain);
      exit(EXIT_FAILURE);
    }
  } else {
    if (rockey.ReadDataFile(Dongle::kFactoryDataFileId, WorldPublic::kOffsetDataFile + WorldPublic::kOffsetDongleInfo,
                            &info[0], sizeof(DONGLE_INFO)) < 0 ||
        0 != memcmp(use_hid, info[0].hid_, 12)) {
      rlLOGE(TAG, "Open dongle hid mismatch %s %s!!", StringFromHID(s_hid_1, use_hid),
             StringFromHID(s_hid_2, info[0].hid_));
      exit(EXIT_FAILURE);
    }
  }
#endif /* __EMULATOR__ || !__RockeyARM__ */

  char line[4 * 1024] = {0};
  uint8_t binary[4 * 1024];
  const char* input = argv[1];

  if (0 == strcmp(input, "-")) {
    while (0 == line[0] || '\r' == line[0] || '\n' == line[0]) {
      rlLOGW(TAG, "Input Message:");
      fgets(line, sizeof(line) - 1, stdin);
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
    rlLOGE(TAG, "EINVAL: Input message.size != 1024", size_binary);
    exit(EXIT_FAILURE);
  }

  memcpy(InOutBuf, binary, 1024);

  long long ts = rLANG_GetTickCount();
  int result = Main(InOutBuf, ExtendBuf, &rockey);
  ts = rLANG_GetTickCount() - ts;

  if (0 == result) {
    rlLOGI(TAG, "Rockey.Execute OK in %lld ms", ts);
    int output_size = rl_BASE64_Write(line, (uint8_t*)InOutBuf, 1024);
    line[output_size++] = '\n'; /* */
    line[output_size++] = '\n'; /* */
    int write_size = write(stdout_, line, output_size);
    if (output_size != write_size) {
      rlLOGW(TAG, "[*IO*]Write output file error %d => %d", output_size, write_size);
    }
  } else {
    rlLOGE(TAG, "Rockey.Execute Error %d in %lld ms", result, ts);
  }

#if defined(__EMULATOR__)
  rockey.Write(dongleFile);
#else  /* RockeyARM */
  rockey.ResetState();
#endif /* __EMULATOR__ */

  return result == 0 ? 0 : EXIT_FAILURE;
}
#endif /* main */

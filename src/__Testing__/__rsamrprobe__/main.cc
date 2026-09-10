/*! __Testing__rsamrprobe__ — RsaPrimeMR 单数字分块探测(独立 host 程序, 真 ukey)。
 *!
 *! 背景: ukey 内 GetTickCount 不自走、无日志、长任务受限 → "每轮只测一个候选数字"
 *! (一次 isPrimeMRW)并立即返回, host 侧累计探测次数与墙钟, 得出"设备单探测耗时",
 *! 用于判定 1024 位素数恢复(≈355 个奇数候选/素数)是否可行。
 *!
 *! 设备侧: 需已刷新含"单数字快速路径"的 rockey_dongle 固件(见 __Testing__dongle__
 *! Start 顶部 rsaprobe::kMagic 拦截 → Testing_RsaPrimeOne); 可先经 WT_APP_DONGLE
 *! 更新 ukey 的 exe 槽。
 *!
 *! 用法: __Testing__rsamrprobe__ [-2] [rounds] [maxProbes]
 *!   -2           管理权限(VerifyPIN admin); 缺省按匿名尝试
 *!   rounds        每候选 MR 轮数(默认 8)
 *!   maxProbes     探测上限(默认 2000; 期望 1024 位命中约 355 次)
 *! env: WT_RKEY_DEVICE=<枚举索引>; WT_APP_DONGLE=<rockey_dongle.bin 路径>
 *! 退出码: 0=命中素数, 1=达上限/失败
 */
#include <Interface/dongle.h>
#include <base/base.h>
#include "../__rsamr__/rsa_mr.h"
#include "../__rsamr__/probe_io.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>

rLANG_DECLARE_MACHINE

namespace {
constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("RSPP");
}

namespace dongle {

using DWORD = Dongle::DWORD;

static double NowMs() {
  using namespace std::chrono;
  return duration<double, std::milli>(steady_clock::now().time_since_epoch()).count();
}

int RsaprProbeMain(int argc, char* argv[]) {
  (void)TAG;
  bool admin = false;
  bool cos_mode = false;
  int rounds = 8;
  int maxProbes = 2000;
  int ai = 1;
  if (ai < argc && 0 == strcmp("-2", argv[ai])) {
    admin = true;
    ++ai;
  }
  if (ai < argc && 0 == strcmp("-cos", argv[ai])) {
    cos_mode = true; /* COS 心跳候选微基准: -2 -cos [iters] */
    ++ai;
  }
  if (ai < argc) rounds = atoi(argv[ai++]);
  if (ai < argc) maxProbes = atoi(argv[ai++]);
  if (rounds < 1) rounds = 1;
  if (rounds > 16) rounds = 16;
  if (maxProbes < 1) maxProbes = 1;

  /* ---- 打开真 ukey(与 __Testing__dongle__ 同款路径) ---- */
  RockeyARM rockey;
  DONGLE_INFO dongle_info[64];
  const char* rkey_dev = getenv("WT_RKEY_DEVICE");
  const int dev_index = rkey_dev ? atoi(rkey_dev) : 0;

  int r = rockey.Enum(dongle_info);
  std::printf("[rsamrprobe] rockey.Enum return %d/%08x\n", r, rockey.GetLastError());
  if (r <= 0) return 1;
  r = rockey.Open(dev_index);
  std::printf("[rsamrprobe] rockey.Open(%d) return %d/%08x\n", dev_index, r, rockey.GetLastError());
  if (r < 0) return 1;
  rockey.ResetState();
  if (admin) {
    r = rockey.VerifyPIN(PERMISSION::kAdministrator, nullptr, nullptr);
    std::printf("[rsamrprobe] VerifyPIN(admin) return %d/%08x\n", r, rockey.GetLastError());
  }

  const char* app_dongle = getenv("WT_APP_DONGLE");
  if (app_dongle) {
    FILE* fp = fopen(app_dongle, "rb");
    if (!fp) {
      std::printf("[rsamrprobe] can't open %s\n", app_dongle);
    } else {
      uint8_t app_[64 * 1024];
      const size_t size = fread(app_, 1, sizeof(app_), fp);
      fclose(fp);
      if (size < 64 || size >= 0xFFFF) {
        std::printf("[rsamrprobe] invalid app size %zu\n", size);
      } else {
        r = rockey.UpdateExeFile(app_, (int)size);
        std::printf("[rsamrprobe] UpdateExeFile %s return %d/%08x\n", app_dongle, r,
                    rockey.GetLastError());
      }
    }
  }
  if (!rockey.Ready()) {
    std::printf("[rsamrprobe] rockey not ready\n");
    return 1;
  }

  /* ---- COS 心跳候选微基准: 每个候选跑 maxProbes 次, 测单次代价并核对副作用 ---- */
  if (cos_mode) {
    PERMISSION pin_before = PERMISSION::kAnonymous;
    uint8_t share_before[32] = {0};
    rockey.GetPINState(&pin_before);
    rockey.ReadShareMemory(share_before);

    rsaprobe::ProbeIO io;
    static const char* kNames[6] = {"-", "get_pinstate", "get_tickcount", "led_control(blink)",
                                    "get_sharememory", "get_keyinfo"};
    for (int cand = 1; cand <= 5; ++cand) {
      std::memset(&io, 0, sizeof(io));
      io.argv_[0] = static_cast<uint32_t>(rsaprobe::kIndexRsaPrimeMR);
      io.error_[0] = rsaprobe::kMagic;
      io.error_[1] = rsaprobe::kModeCos;
      io.error_[2] = static_cast<uint32_t>(cand);
      io.error_[3] = static_cast<uint32_t>(maxProbes);
      int mret = 0;
      const double t0 = NowMs();
      const int rc = rockey.ExecuteExeFile(&io, sizeof(io), &mret);
      const double t1 = NowMs();
      const double total = t1 - t0;
      std::printf("[cos] %-18s iters=%d rc=%d total=%.1f ms per_call_us=%.2f "
                  "pin=%u share0=%u lasterr=%08x done=%u\n",
                  kNames[cand], maxProbes, rc, total,
                  maxProbes ? total * 1000.0 / maxProbes : 0.0,
                  static_cast<unsigned>(io.error_[4]), static_cast<unsigned>(io.error_[5]),
                  static_cast<unsigned>(io.error_[6]), static_cast<unsigned>(io.error_[7]));
      (void)mret;
    }
    std::printf("[cos] pre: pin=%u share0=%u(与上面各行对比即可判定副作用; LED 是否闪烁请目视)\n",
                static_cast<unsigned>(pin_before), static_cast<unsigned>(share_before[0]));
    return 0;
  }

  /* ---- 种子 → 候选(与设备 seedToOdd 同规则) ---- */
  uint8_t seed[128];
  r = rockey.RandBytes(seed, sizeof(seed));
  std::printf("[rsamrprobe] RandBytes(seed) return %d/%08x\n", r, rockey.GetLastError());
  if (r < 0) return 1;
  rsa_mr::BN cand;
  rsa_mr::seedToOdd(cand, seed);

  /* ---- 分块探测循环: 每次 ExecuteExeFile 测一个候选 ---- */
  rsaprobe::ProbeIO io;
  std::memset(&io, 0, sizeof(io));
  io.argv_[0] = static_cast<uint32_t>(rsaprobe::kIndexRsaPrimeMR); /* 0x14, 设备 Start 读 index */

  int found = 0;
  unsigned calls = 0;
  double sum_ms = 0;
  const double t_start = NowMs();
  for (int i = 0; i < maxProbes; ++i) {
    if (i > 0) rsa_mr::addSmall(cand, 2);
    rsaprobe::packCandidate(io, cand.v, rounds);
    const double t0 = NowMs();
    int mret = 0;
    const int rc = rockey.ExecuteExeFile(&io, sizeof(io), &mret);
    const double t1 = NowMs();
    const double ms = t1 - t0;
    ++calls;
    sum_ms += ms;
    if (rc < 0) {
      std::printf("[rsamrprobe] #%d ExecuteExeFile err %d/%08x (%.1f ms)\n", i, rc,
                  rockey.GetLastError(), ms);
      break;
    }
    if (rsaprobe::statusOf(io) != 0) {
      std::printf("[rsamrprobe] #%d device status %u\n", i,
                  static_cast<unsigned>(rsaprobe::statusOf(io)));
      break;
    }
    const uint32_t prime = rsaprobe::resultOf(io);
    if (i < 3 || prime)
      std::printf("[rsamrprobe] #%d prime=%u ms=%.2f\n", i, prime, ms);
    if (prime) {
      found = 1;
      std::printf("[rsamrprobe] FOUND prime at call #%u\n", calls);
      break;
    }
  }
  const double t_end = NowMs();

  std::printf("[rsamrprobe] calls=%u found=%d total=%.1f ms avg_ms/call=%.3f\n", calls, found,
              t_end - t_start, calls ? sum_ms / calls : 0.0);
  if (calls) {
    const double avg = sum_ms / calls;
    const double per_prime_ms = avg * 355.0;      /* 每素数期望 ~355 个奇数候选 */
    const double two_prime_ms = per_prime_ms * 2; /* p+q */
    std::printf("[rsamrprobe] 推算: 单素数 ≈ %.0f ms (%.1f s); p+q ≈ %.0f ms (%.1f s)\n",
                per_prime_ms, per_prime_ms / 1000.0, two_prime_ms, two_prime_ms / 1000.0);
  }
  std::printf("[rsamrprobe] 退出码 %d\n", found ? 0 : 1);
  return found ? 0 : 1;
}

} /* namespace dongle */

rLANG_DECLARE_END

rLANGEXPORT int main(int argc, char* argv[]) {
  using namespace machine;
  using namespace machine::dongle;
  return RsaprProbeMain(argc, argv);
}

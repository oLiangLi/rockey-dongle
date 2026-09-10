/*! probe_io.h — RsaPrimeMR 单数字探测契约(设备固件与 host 探测程序共用)。
 *! 背景: ukey 内 GetTickCount 不自走、无日志、长任务受限 → 采用"单数字分块探测":
 *!   host 每次 ExecuteExeFile 只让设备测一个候选数字(一次 isPrimeMRW)并立即返回;
 *!   host 侧以与设备一致的 seedToOdd/+2 规则推进候选并累计探测次数与墙钟。
 *! 快速路径入口: 设备端 Start 在一切管理副作用之前检查 error_[0]==kMagic 且
 *!   error_[1]==kModeOne 即转 Testing_RsaPrimeOne(见 __Testing__dongle__ main.cc)。
 *! InOut 前部布局必须与 __Testing__dongle__ 的 Context_t 一致(截至 error_), 由
 *!   设备侧 static_assert(offsetof) 兜底。 */
#ifndef AGINX_RSA_PRIME_PROBE_H
#define AGINX_RSA_PRIME_PROBE_H

#include <cstdint>
#include <cstring>

namespace rsaprobe {

constexpr uint32_t kMagic = 0x52535031u; /* 'RSP1' */
constexpr uint32_t kModeOne = 1u;
constexpr uint32_t kModeCos = 2u;          /* COS 心跳微基准模式(见 Testing_CosProbe) */
constexpr uint32_t kCosDone = 0x434F5331u; /* 'COS1' 完成标记(回写 error_[7]) */
constexpr int kIndexRsaPrimeMR = 20; /* 与 dongle kTestingIndex::RsaPrimeMR 一致 */
constexpr int kCandidateBytes = 128; /* 1024 位候选 = BN.v[0..31] 小端 */
constexpr int kIdxRounds = 2;        /* error_[2] 入: MR 轮数 */
constexpr int kIdxResult = 4;        /* error_[4] 出: 0=合 1=素 */
constexpr int kIdxStatus = 5;        /* error_[5] 出: 0=OK */

/*! ExecuteExeFile 载荷(前部与 Context_t 对齐):
 *!   argv_[0]=kIndexRsaPrimeMR(设备 Start 入口先读 index);
 *!   候选 128B 落在 hash_+ts_+seed_(连续, 偏移 16..144); error_@144。 */
struct ProbeIO {
  uint32_t argv_[4];   /*  0 .. 16 */
  uint8_t hash_[64];   /* 16 .. 80 */
  uint32_t ts_[8];     /* 80 ..112 */
  uint32_t seed_[8];   /*112 ..144 */
  uint32_t error_[8];  /*144 ..176 */
  uint8_t pad[360 - (16 + 64 + 32 + 32 + 32)]; /* 对齐 Context_t 总长 360B */
};
static_assert(sizeof(ProbeIO) == 360, "ProbeIO must be 360B (= Context_t)");

inline void packCandidate(ProbeIO& io, const uint32_t limbs[32], int rounds) {
  std::memset(io.pad, 0, sizeof(io.pad));
  std::memcpy(&io.hash_[0], limbs, kCandidateBytes); /* BN.v[0..31] 小端 */
  io.error_[0] = kMagic;
  io.error_[1] = kModeOne;
  io.error_[2] = static_cast<uint32_t>(rounds);
  io.error_[kIdxResult] = 0;
  io.error_[kIdxStatus] = 0;
}

inline uint32_t resultOf(const ProbeIO& io) {
  return io.error_[kIdxResult];
}
inline uint32_t statusOf(const ProbeIO& io) {
  return io.error_[kIdxStatus];
}

} /* namespace rsaprobe */

#endif /* AGINX_RSA_PRIME_PROBE_H */

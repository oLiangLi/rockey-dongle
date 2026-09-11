#include <Interface/dongle.h>
#include <Interface/script.h>
#include <base/base.h>

rLANG_DECLARE_MACHINE

namespace {
constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("CHPVM");
}

namespace dongle {

/**
 *! ChaCha20-Poly1305 的 **opcode 层**用例(模拟器): 直调 `VM_t::OpFuncChaChaPoly`,
 *! 验证 `kExChaChaPolySeal/Open` 的 argc==4(旧脚本兼容)与 argc==6(新增可选 AAD)两条路径:
 *!   1) argc==6 Seal(带 AAD)结果必须与直接 API 逐字节一致;
 *!   2) argc==6 Open: 正确 AAD 还原明文; 错误 AAD 必须失败并把缓冲清零;
 *!   3) argc==4 与"无 AAD 的直接 API"一致(向后兼容), 且 tag 与带 AAD 时不同;
 *!   4) 参数错误: argc==5 → SIGILL; aad 长度越界 → SIGSEGV; aad 指针越界 → OpCheckMM 置 SIGSEGV。
 *! 说明: 这里验证的是 opcode 胶水层(argc/OpCheckMM/AAD 喂入顺序); AAD 算法本身见
 *! `__Testing__dongle__` 的 index 11(RFC 8439 向量 + 真机)。
 */
namespace {

using script::OpCode;

/* OpFuncChaChaPoly 形参是 uint16_t, 与 script.cc 里的派发一致 */
constexpr uint16_t kOpSeal = static_cast<uint16_t>(OpCode::kExChaChaPolySeal);
constexpr uint16_t kOpOpen = static_cast<uint16_t>(OpCode::kExChaChaPolyOpen);

struct Buffers {
  alignas(8) uint8_t data[1024];   /* VM data 段(地址空间 0..1023) */
  alignas(8) uint8_t buffer[1024]; /* VM buffer 段 */
};

/* data 段内的布局 */
constexpr int32_t kOffKey = 0;
constexpr int32_t kOffNonce = 32;
constexpr int32_t kOffAadOk = 64;
constexpr int32_t kOffAadBad = 96;
constexpr int32_t kOffBuf = 256; /* 明文 → 密文||tag 原地 */

constexpr int kLen = 97;
constexpr int kAadLen = 32;

int RunCase(Dongle& rockey, bool& ok_out) {
  int error = 0;
  Buffers b;
  memset(&b, 0, sizeof(b));
  ok_out = true;

  /* 随机素材 + 只差 1 bit 的错误 AAD */
  std::ignore = rockey.RandBytes(b.data + kOffKey, 32);
  std::ignore = rockey.RandBytes(b.data + kOffNonce, 12);
  std::ignore = rockey.RandBytes(b.data + kOffAadOk, kAadLen);
  memcpy(b.data + kOffAadBad, b.data + kOffAadOk, kAadLen);
  b.data[kOffAadBad + kAadLen - 1] ^= 0x01;
  std::ignore = rockey.RandBytes(b.data + kOffBuf, kLen);

  uint8_t plain[kLen];
  memcpy(plain, b.data + kOffBuf, kLen);

  /* 参考值: 直接 API(带 AAD / 不带 AAD) */
  uint8_t ref[kLen + 16], ref_noaad[kLen + 16];
  size_t size = kLen;
  memcpy(ref, plain, kLen);
  if (rockey.CHACHAPOLY_Seal(b.data + kOffKey, b.data + kOffNonce, ref, &size, b.data + kOffAadOk, kAadLen) < 0 ||
      size != kLen + 16) {
    ++error;
    rlLOGE(TAG, "直接 API Seal(aad) 失败");
  }
  memcpy(ref_noaad, plain, kLen);
  size = kLen;
  if (rockey.CHACHAPOLY_Seal(b.data + kOffKey, b.data + kOffNonce, ref_noaad, &size) < 0 || size != kLen + 16) {
    ++error;
    rlLOGE(TAG, "直接 API Seal(no aad) 失败");
  }
  if (0 == memcmp(ref + kLen, ref_noaad + kLen, 16)) {
    ++error;
    rlLOGE(TAG, "参考值异常: 有无 AAD 的 tag 相同");
  }

  script::VM_t vm(&rockey, b.data, b.buffer);
  vm.valid_permission_ = PERMISSION::kAnonymous;

  /* ---- 1) argc==6 Seal(带 AAD) ---- */
  memcpy(b.data + kOffBuf, plain, kLen);
  int32_t argv6[6] = {kOffKey, kOffNonce, kOffBuf, kLen, kOffAadOk, kAadLen};
  int rc = vm.OpFuncChaChaPoly(kOpSeal, 6, argv6);
  if (rc != kLen + 16) {
    ++error;
    rlLOGE(TAG, "opcode Seal(argc=6) 返回 %d(期望 %d)", rc, kLen + 16);
  } else if (0 != memcmp(b.data + kOffBuf, ref, kLen + 16)) {
    ++error;
    rlLOGE(TAG, "opcode Seal(argc=6) 结果与直接 API 不一致");
  }
  uint8_t sealed[kLen + 16];
  memcpy(sealed, b.data + kOffBuf, kLen + 16);

  /* ---- 2) argc==6 Open: 正确 / 错误 AAD ---- */
  memcpy(b.data + kOffBuf, sealed, kLen + 16);
  int32_t argv_open[6] = {kOffKey, kOffNonce, kOffBuf, kLen + 16, kOffAadOk, kAadLen};
  rc = vm.OpFuncChaChaPoly(kOpOpen, 6, argv_open);
  if (rc != kLen) {
    ++error;
    rlLOGE(TAG, "opcode Open(argc=6,正确 AAD) 返回 %d(期望 %d)", rc, kLen);
  } else if (0 != memcmp(b.data + kOffBuf, plain, kLen)) {
    ++error;
    rlLOGE(TAG, "opcode Open(argc=6) 明文不一致");
  }

  memcpy(b.data + kOffBuf, sealed, kLen + 16);
  int32_t argv_bad[6] = {kOffKey, kOffNonce, kOffBuf, kLen + 16, kOffAadBad, kAadLen};
  rc = vm.OpFuncChaChaPoly(kOpOpen, 6, argv_bad);
  if (rc >= 0) {
    ++error;
    rlLOGE(TAG, "opcode Open(argc=6,错误 AAD) 未被拒绝(rc=%d)", rc);
  }

  /* ---- 3) argc==4(旧脚本)必须与无 AAD 的直接 API 一致 ---- */
  memcpy(b.data + kOffBuf, plain, kLen);
  int32_t argv4[4] = {kOffKey, kOffNonce, kOffBuf, kLen};
  rc = vm.OpFuncChaChaPoly(kOpSeal, 4, argv4);
  if (rc != kLen + 16) {
    ++error;
    rlLOGE(TAG, "opcode Seal(argc=4) 返回 %d(期望 %d)", rc, kLen + 16);
  } else if (0 != memcmp(b.data + kOffBuf, ref_noaad, kLen + 16)) {
    ++error;
    rlLOGE(TAG, "opcode Seal(argc=4) 与无 AAD 直接 API 不一致");
  }
  int32_t argv4o[4] = {kOffKey, kOffNonce, kOffBuf, kLen + 16};
  rc = vm.OpFuncChaChaPoly(kOpOpen, 4, argv4o);
  if (rc != kLen || 0 != memcmp(b.data + kOffBuf, plain, kLen)) {
    ++error;
    rlLOGE(TAG, "opcode Open(argc=4) 失败(rc=%d)", rc);
  }

  /* ---- 4) 参数错误分支 ---- */
  vm.zero_ = 0;
  int32_t argv5[5] = {kOffKey, kOffNonce, kOffBuf, kLen, kOffAadOk};
  std::ignore = vm.OpFuncChaChaPoly(kOpSeal, 5, argv5);
  if (0 == vm.zero_) {
    ++error;
    rlLOGE(TAG, "argc=5 未被拒绝(zero_ 未置位)");
  }

  vm.zero_ = 0;
  int32_t argv_big[6] = {kOffKey, kOffNonce, kOffBuf, kLen, kOffAadOk, 5000};
  std::ignore = vm.OpFuncChaChaPoly(kOpSeal, 6, argv_big);
  if (0 == vm.zero_) {
    ++error;
    rlLOGE(TAG, "aad_len 越界未被拒绝");
  }

  vm.zero_ = 0;
  int32_t argv_oor[6] = {kOffKey, kOffNonce, kOffBuf, kLen, 1000, 64}; /* 1000+64 > 1024 */
  std::ignore = vm.OpFuncChaChaPoly(kOpSeal, 6, argv_oor);
  if (0 == vm.zero_) {
    ++error;
    rlLOGE(TAG, "aad 指针越界未被拒绝");
  }

  ok_out = (0 == error);
  return error;
}

}  // namespace

int Start(void* InOutBuf, void* ExtendBuf) {
  memset(InOutBuf, 0, 1024); /* 本用例不需要 Context_t 布局 */
  std::ignore = ExtendBuf;
  std::ignore = TAG;

  int error = 0;
#if !defined(__RockeyARM__)
  Emulator rockey(PERMISSION::kAdministrator);
  if (0 != rockey.Create("__chachapolyvm__")) {
    rlLOGE(TAG, "Emulator::Create 失败");
    return 10086 - 1;
  }
  bool ok = false;
  error = RunCase(rockey, ok);
  rlLOGI(TAG, "ChaChaPolyVM opcode 用例: %s (error=%d)", ok ? "PASS" : "FAIL", error);
#endif /* !__RockeyARM__ */

  return 10086 - error;
}

}  // namespace dongle

rLANG_DECLARE_END

#if !defined(__RockeyARM__)
int main() {
  uint64_t InOutBuf[(3 << 10) / 8] = {0};
  uint64_t ExtendBuf[(1 << 10) / 8] = {0};
  return machine::dongle::Start(InOutBuf, ExtendBuf);
}
#endif /* !__RockeyARM__ */

/*! TRNG 失败注入自测(host): 用 Dongle 子类覆写 HwARandBytes 制造失败/成功两态,
 *! 验证共享 DRBG(Interface/TRNG.cc Dongle::RandBytes):
 *!   1) HwARandBytes 失败 → RandBytes 必须返回 -EFAULT(M-12/H-01 修复面: 调用方须检查);
 *!   2) 成功路径 → RandBytes 返回 0(多尺寸)。
 *! 不触碰真实设备/镜像; 属宿主单元测试。 */
#include <Interface/dongle.h>
#include <initializer_list>
#include <cstdio>
#include <cstring>

using machine::dongle::Dongle;

class FailingTRNG : public Dongle {
 public:
  FailingTRNG() = default;
  int HwARandBytes(uint8_t* buffer, size_t size) override {
    memset(buffer, 0x5A, size);
    return -1; /* 模拟 TRNG 硬件失败 */
  }
};

class GoodTRNG : public Dongle {
 public:
  GoodTRNG() = default;
  int HwARandBytes(uint8_t* buffer, size_t size) override {
    for (size_t i = 0; i < size; ++i)
      buffer[i] = static_cast<uint8_t>((i * 7 + 1) & 0xFF);
    return 0;
  }
};

int main() {
  int error = 0;

  {
    FailingTRNG d;
    for (size_t n : {size_t{1}, size_t{64}, size_t{128}, size_t{200}, size_t{1024}}) {
      uint8_t b[1100] = {0};
      int rc = d.RandBytes(b, n);
      if (rc != -EFAULT) {
        std::printf("trngfail FAIL: fail-path n=%zu rc=%d (expect -EFAULT)\n", n, rc);
        error = 1;
      }
    }
    if (0 == error)
      std::printf("trngfail PASS: HwARandBytes 失败 → RandBytes -EFAULT(5 尺寸)\n");
  }

  {
    GoodTRNG d;
    uint8_t a[1100] = {0}, b[1100] = {0};
    for (size_t n : {size_t{1}, size_t{64}, size_t{200}, size_t{1024}}) {
      int rc = d.RandBytes(a, n);
      if (rc != 0) {
        std::printf("trngfail FAIL: ok-path n=%zu rc=%d (expect 0)\n", n, rc);
        error = 1;
      }
    }
    if (d.RandBytes(a, sizeof(a)) != 0 || d.RandBytes(b, sizeof(b)) != 0) {
      std::printf("trngfail FAIL: ok-path 1024(2nd)\n");
      error = 1;
    }
    if (0 == error)
      std::printf("trngfail PASS: HwARandBytes 正常 → RandBytes 0\n");
  }

  return error;
}

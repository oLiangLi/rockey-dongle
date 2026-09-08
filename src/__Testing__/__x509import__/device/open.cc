/*! windows 真机板(无 X4C_BOARD): X509ImportOpen —— RockeyARM 打开设备并以管理员登录。
 *! 设备选择沿用 WT_RKEY_DEVICE(默认 0); 先以缺省管理员 PIN(nullptr → CONST_ADMINPIN)登录,
 *! 失败时可用 WT_RKEY_X509_PIN 显式提供管理员 PIN。 */
#include <Interface/dongle.h>
#include <cstdlib>
#include "../x509import.h"

using machine::dongle::Dongle;
using machine::dongle::PERMISSION;
using machine::dongle::RockeyARM;

int X509ImportOpen(Dongle** out, bool* out_persistent_device) {
  if (!out || !out_persistent_device)
    return -EINVAL;

  const char* rkey_dev = std::getenv("WT_RKEY_DEVICE");
  const int dev_index = rkey_dev ? std::atoi(rkey_dev) : 0;

  RockeyARM* rockey = new RockeyARM();
  int result = rockey->Open(dev_index);
  if (0 != result) {
    delete rockey;
    return -EBADF;
  }

  /* 缺省管理员 PIN 登录; 若失败再试环境变量显式 PIN */
  result = rockey->VerifyPIN(PERMISSION::kAdministrator, nullptr, nullptr);
  const char* pin = std::getenv("WT_RKEY_X509_PIN");
  if (0 != result && pin && pin[0])
    result = rockey->VerifyPIN(PERMISSION::kAdministrator, pin, nullptr);
  if (0 != result) {
    delete rockey;
    return -EACCES;
  }

  *out_persistent_device = true;
  *out = rockey;
  return 0;
}

/*! foobar(模拟器)板: X509ImportOpen —— 新建管理员内存世界 */
#include <Interface/dongle.h>
#include "../x509import.h"

using machine::dongle::Dongle;
using machine::dongle::Emulator;
using machine::dongle::PERMISSION;

int X509ImportOpen(Dongle** out, bool* out_persistent_device) {
  if (!out || !out_persistent_device)
    return -EINVAL;
  Emulator* emu = new Emulator(PERMISSION::kAdministrator);
  if (0 != emu->Create("__x509import__")) {
    delete emu;
    return -EIO;
  }
  *out_persistent_device = false;
  *out = emu;
  return 0;
}

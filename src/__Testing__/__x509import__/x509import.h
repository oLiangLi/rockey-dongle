#pragma once

#ifndef __WTINC_TESTING_X509IMPORT_H__
#define __WTINC_TESTING_X509IMPORT_H__

#include <Interface/dongle.h>

namespace machine {
namespace dongle {
class Dongle;
}
}  // namespace machine

/*! 打开用于 X509 导入用例的 Dongle, 由各构建板各自实现(单一翻译单元, 避免 #if 包裹):
 *!  - foobar 模拟器: emu/open.cc —— 新建管理员内存世界(非持久);
 *!  - windows 真机(无 X4C_BOARD): device/open.cc —— RockeyARM 打开指定索引设备并以缺省
 *!    管理员 PIN 登录(失败可用 WT_RKEY_X509_PIN 显式给 PIN), *out_persistent = true。
 *! 成功返回 0 并置 *out(调用方负责生命周期); 失败返回负 errno。 */
int X509ImportOpen(machine::dongle::Dongle** out, bool* out_persistent_device);

#endif /* __WTINC_TESTING_X509IMPORT_H__ */

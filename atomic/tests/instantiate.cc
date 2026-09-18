/* 显式实例化检查: 一行就让编译器把 VM_t<Impl> 的全部成员函数体都检查一遍。
   注意: 模板成员函数"按需实例化", 没人调用就不检查 —— 本文件是对策。
   用法 (2026-09-18 起本文件在 atomic/tests/):
     g++ -std=c++17 -Wall -Werror -fsyntax-only -I <ROOT> -I <ROOT>/atomic/include atomic/tests/instantiate.cc
   统一跑法: node tools/rockey/ATOMC/ci/atomic-tests.cjs  (或 make test-atomic) */
#include <base/base.h>
#include "../include/rv32im-atomic.hpp"

struct Impl : machine::hyper::VM_t<Impl> {};

template struct machine::hyper::VM_t<Impl>;   /* 强制实例化全部成员 */

int main() { return 0; }

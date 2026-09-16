/* 显式实例化检查: 一行就让编译器把 VM_t<Impl> 的全部成员函数体都检查一遍。
   注意: 模板成员函数"按需实例化", 没人调用就不检查 —— 本文件是对策。
   用法: g++ -std=c++17 -Wall -Werror -fsyntax-only -I <ATOMIC> -I <ATOMIC>/atomic/include instantiate.cc */
#include <base/base.h>
#include "rv32im-atomic.hpp"

struct Impl : machine::hyper::VM_t<Impl> {};

template struct machine::hyper::VM_t<Impl>;   /* 强制实例化全部成员 */

int main() { return 0; }

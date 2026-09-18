/**
 *! 本文件只用于在HOST环境下完成对 atomic 定义的 ABI 规范检查
 */
#include <base/base.h>

#include "../include/rv32im-atomic.hpp"

rLANG_DECLARE_MACHINE

namespace foobar {
class rLANG_ABI_CHECK final : public hyper::VM_t<rLANG_ABI_CHECK> {};

int Start() {
  rLANG_ABI_CHECK abi_;
  rLANG_ABI_CHECK::hart_t hart_;

  hart_.Enable();

  return abi_.Execv(&hart_, 0x10000);
}

} /// namespace foobar 

rLANG_DECLARE_END

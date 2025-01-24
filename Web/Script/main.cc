#include <tuple>
#include "base/base.h"
#include "base/grammar/grammar.h"

rLANG_DECLARE_MACHINE

rLANGWASMIMPORT(void, jsGrammar_yyCopyValue, (int offset), {}, "rLANG", "jsGrammar_yyCopyValue")

namespace {
constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("SCRIPT");

struct jsGrammar_t {
  int yyLen() const { return f_yylen; }  
  int yyOffset() const { return (int)XDPDA_YYOFF(this); }
  int yyNextState(int reason);

  static constexpr int kStackSize = 256;
  short yy_yyssa[kStackSize];
  int yy_yyvsa[kStackSize];
  XDPDA_GRAMMAR_TYPE_ENTRY(int)
};

#ifdef __EMSCRIPTEN__
#define XDPDA_CB_COPY_YYLVALUE() jsGrammar_yyCopyValue(self->yyOffset())
#endif /* __EMSCRIPTEN__ */

#define _XDPDA_OUTPUT_TRACE 1
#define _XDPDA_IMPLEMENT_TOKENENUMS_DECLARE_
#define XDPDA_GRAMMAR_DECLARE_FILE "Web/Script/grammar/dongle.jy.INL"
#include XDPDA_GRAMMAR_DECLARE_FILE

#define XDPDA_IMPLEMENT_NEXTSTATE_FUNCTION_USERCODE const int* const value = nullptr
#define XDPDA_IMPLEMENT_NEXTSTATE_FUNCTION_DECLARE static int jsGrammar_yyNextState(jsGrammar_t* const self, int reason)
#include "base/grammar/XDPDA_MACHINE_DECLARE.INL"

int jsGrammar_t::yyNextState(int reason) {
  std::ignore = TAG;
  if (reason == XDPDA_RESUME_INITIALIZE)
    XDPDA_CONTEXT_INIT_STACK(this, kStackSize, yy_yyssa, yy_yyvsa);
  return jsGrammar_yyNextState(this, reason);
}

static jsGrammar_t grammar;
}

rLANGWASMEXPORT int jsGrammar_yyLen() {
  return grammar.yyLen();
}
rLANGWASMEXPORT int jsGrammar_yyOffset() {
  return grammar.yyOffset();
}
rLANGWASMEXPORT int jsGrammar_yyNextState(int reason) {
  return grammar.yyNextState(reason);
}

rLANG_DECLARE_END

int main() {
  return 0;
}

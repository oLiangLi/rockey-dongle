#ifndef __WTINC_SCANNER_H__
#define __WTINC_SCANNER_H__

#include "../base.h"
#include <setjmp.h>

rLANG_DECLARE_MACHINE

class rlLexicalScannerGenerator {
 public:
  using Char = int;
  static int CreateLexicalScannerGenerator(rlLexicalScannerGenerator** newGenerator,
                                           int csize = 256,
                                           int sconCount = 1,
                                           bool caseless = false,
                                           const int* cclower = nullptr,
                                           const int* charmap = nullptr);
  static void DestroyLexicalScannerGenerator(rlLexicalScannerGenerator* self);

 public:
  struct LexicalRegexpHelper_t {
    static constexpr int kStackSize = 64;
    int yyLen() const { return f_yylen; }
    int yyGetVal() const { return XDPDA_YYVAL(this); }
    void yySetVal(int val) { XDPDA_YYVAL(this) = val; }
    void yySetLval(int val) { XDPDA_YYLVAL(this) = val; }
    int yyOffset() { return (int)(XDPDA_YYOFF(this)); }
    int yyVar(int N) const { return XDPDA_YYVAR(this, N); }

    int yyNextState(int reason);

    short yy_yyssa[kStackSize];
    int yy_yyvsa[kStackSize];
    XDPDA_GRAMMAR_TYPE_ENTRY(int)
  };

 public:
  struct LexicalScanner_t {
    int yy_lastdfa, yy_jambase, yy_default_rule, yy_charsize;

    int *yy_accept, yy_accept_size;
    int *yy_ec, yy_ec_size;
    int *yy_meta, yy_meta_size;
    int *yy_base, yy_base_size;
    int *yy_def, yy_def_size;
    int *yy_nxt, yy_nxt_size;
    int *yy_chk, yy_chk_size;
  };

  static constexpr int        /*          */
      kOpCode_MakeNil = 0x00, /* $$ += mkstate(e)   */
      kOpCode_MakeChr = 0x01, /* $$ += mkstate(+$<) */
      kOpCode_MakeCcl = 0x02, /* $$ += mkstate(-$<) */

      kOpCode_LinkChr = 0x03, /* $$ = link_machines($$, mkstate($<)) */
      kOpCode_LinkNil = 0x04, /* $$ = link_machines($1, $2) */

      kOpCode_MakeClos = 0x05,  /* $$ = ($$)*  */
      kOpCode_MakePoscl = 0x06, /* $$ = ($$)+  */
      kOpCode_MakeOpt = 0x07,   /* $$ = ($$)?  */

      kOpCode_MakeRep1 = 0x08,   /* $$ = ($$){$<} */
      kOpCode_MakeRep1X = 0x09,  /* $$ = ($$){$<,} */
      kOpCode_MakeRep2EX = 0x0A, /* $$ = ($$){$<,$<<} */

      kOpCode_MakeOr = 0x0B /* $$ = ($1)|($2) */
      ;

 protected:
  rlLexicalScannerGenerator(Char* const cclflags__,
                            int* const nextecm__,
                            int* const ecgroup__,
                            int* const tecfwd__,
                            int* const tecbck__,
                            const int csize = 256,
                            const int sconCount = 1,
                            const bool caseless = false,
                            const int* const cclower__ = nullptr, /* global */
                            const int* const charmap__ = nullptr /* global */);

  rlLexicalScannerGenerator(const rlLexicalScannerGenerator&) = delete;
  rlLexicalScannerGenerator& operator=(const rlLexicalScannerGenerator&) = delete;

 public:
  int AddShareSconList(int scon);
  int SetSconList(int count, const int* sconlist);
  int AddNewCCl(bool negate, int count, const int* cclist);
  int AddNewRule(bool bol, int size, const int opcode[]);
  int GenerateScanner(LexicalScanner_t* storage);
  int GetErrorCode() const { return rlErrorCode; }
  void* MemoryRealloc(void* p, int size) {
    assert(size >= 0);
    return reallocate_array(p, size, 1);
  }

 public:
  static constexpr int MSP = 50, ONE_STACK_SIZE = 500;
#if defined(rLANG_CONFIG_MINIMAL)
  static constexpr int PROT_SAVE_SIZE = 4 * 1024;
#else  /* rLANG_CONFIG_uNiAPI_MINIMAL */
  static constexpr int PROT_SAVE_SIZE = 1 * 1024 * 1024;
#endif /* rLANG_CONFIG_uNiAPI_MINIMAL */
  static constexpr int SCON_ANY = -1, SCON_SHARED = 0, SCON_INITIAL = 1, SCON_USER = 2, kINFINITY = -1;

 public:
  bool x_isupper(int c) const {
    if (c < 0 || c > CSIZE)
      return false;
    if (tolower_)
      return c != tolower_[c];
    else
      return c >= 'A' && c <= 'Z';
  }
  int x_tolower(int c) const {
    assert(c >= 0 && c <= CSIZE);
    if (tolower_)
      return tolower_[c];
    else
      return 'a' - 'A' + c;
  }
  int x_charmap(int c) const {
    if (c < 0 || c > CSIZE)
      return c;
    return charmap_ ? charmap_[c] : c;
  }

 public:
  LexicalScanner_t GetLexicalScanner();
  static LexicalScanner_t* LexicalScannerClone(const LexicalScanner_t& scanner);
  static void LexicalScannerDestroy(LexicalScanner_t* scanner);

 protected:
  int context_init();

  void finish_define_rule(bool bol, int rule);
  void add_share_scon_list(int scon);
  void set_scon_list(int count, const int scon_list[]);
  void add_scon_list(int scon);

  void new_rule();
  void finish_rule(int);
  void add_accept(int, int);
  int copysingl(int, int);
  void mkxtion(int, int);
  int dupmachine(int);
  int link_machines(int, int);
  int mkbranch(int, int);
  int mkclos(int);
  int mkopt(int);
  int mkor(int, int);
  int mkposcl(int);
  int mkrep(int, int, int);
  int mkstate(int);

  void ccladd(int, int);
  int cclinit();
  void cclnegate(int);

  void ccl2ecl();
  int cre8ecs(int[], int[], int);
  void mkeccl(Char[], int, int[], int[], int, int);
  void mkechar(int, int[], int[]);

  void bldtbl(int[], int, int, int, int);
  void cmptmps();
  void expand_nxt_chk();
  int find_table_space(int*, int);
  void inittbl();
  void mkdeftbl();
  void mk1tbl(int, int, int, int);
  void place_state(int*, int, int);
  void stack1(int, int, int, int);

  void increase_max_dfas();
  void mkentry(int*, int, int, int, int);
  void mkprot(int[], int, int);
  void mktemplate(int[], int, int);
  void mv2front(int);
  int tbldiff(int[], int, int[]);

  void sympartition(int[], int, int[], int[]);
  int symfollowset(int[], int, int, int[]);
  int* epsclosure(int*, int*, int[], int*, int*);
  int snstods(int[], int, int[], int, int, int*);

  void ntod();
  void gen_table();
  void generate();

 protected:
  static constexpr size_t kMemoryBlockSizeLimit = 2000 * 1024 * 1024;
  rLANG_LIST_HEAD_t memory_list_{&memory_list_, &memory_list_};
  void scanner_memory_clean(void);
  void* scanner_memory_realloc(void* p, size_t n, size_t s);

 protected:
  Char* ccltbl;
  int *scset, *scbol, *scon_stk, scon_stk_ptr;
  int scon_stk_share_ptr, *scon_stk_share, scon_stk_share_count;
  int numecs, nummecs;
  int lastccl, *cclmap, *ccllen, *cclng, cclreuse;
  int current_maxccls, current_max_ccl_tbl_size;

  int current_mns, current_max_rules;
  int num_rules, num_eof_rules, default_rule = -1, lastnfa;
  int *firstst, *lastst, *finalst, *transchar, *trans1, *trans2;
  int *accptnum, *assoc_rule, *state_type;
  int *rule_type, *rule_useful;
  int numtemps, numprots, protprev[MSP], protnext[MSP], prottbl[MSP];
  int protcomst[MSP], firstprot, lastprot, protsave[PROT_SAVE_SIZE];
  int current_max_dfa_size, current_max_xpairs;
  int current_max_template_xpairs, current_max_dfas;
  int lastdfa, *nxt, *chk, *tnxt;
  int *base, *def, *nultrans, NUL_ec, tblend, firstfree, **dss, *dfasiz;
  int* dfaacc;
  int *accsiz, *dhash, numas;
  int numsnpairs, jambase, jamstate;
  int end_of_buffer_state;
  int onestate[ONE_STACK_SIZE], onesym[ONE_STACK_SIZE];
  int onenext[ONE_STACK_SIZE], onedef[ONE_STACK_SIZE], onesp;
  int did_stk_init, *stk;

 protected:
  const int CSIZE, SYM_EPSILON, SCON_COUNT;
  const bool IGNCASE;

 protected: /* size_is(CSIZE + 1) */
  Char* const cclflags;
  int *const nextecm, *const ecgroup, *const tecfwd, *const tecbck;
  const int *const tolower_, *const charmap_;

 protected:
  void* allocate_array(int n, int s) { return scanner_memory_realloc(nullptr, n, s); }
  void* reallocate_array(void* p, int n, int s) { return scanner_memory_realloc(p, n, s); }
  void free_array(void* p) { scanner_memory_realloc(p, 0, 0); }

  int* allocate_integer_array(int size) { return (int*)allocate_array(size, sizeof(int)); }
  int* reallocate_integer_array(int* p, int size) { return (int*)reallocate_array(p, size, sizeof(int)); }
  int** allocate_int_ptr_array(int size) { return (int**)allocate_array(size, sizeof(int*)); }
  int** reallocate_int_ptr_array(int** p, int size) { return (int**)reallocate_array(p, size, sizeof(int*)); }

  Char* allocate_Character_array(int size) { return (Char*)allocate_array(size, sizeof(Char)); }
  Char* reallocate_Character_array(Char* p, int size) { return (Char*)reallocate_array(p, size, sizeof(Char)); }

 private:
  jmp_buf* execpt_handler = nullptr;
  int rlErrorCode = 0;

 protected:
  template <typename CALLBACK>
  int Execute(CALLBACK function) {
    if (rlErrorCode != 0)
      return rlErrorCode;

    if (execpt_handler)
      return rlErrorCode = -EALREADY;

    jmp_buf handler;
    execpt_handler = &handler;
    int code = setjmp(handler);
    rlErrorCode = code ? code : function();
    execpt_handler = nullptr;

    if (rlErrorCode > 0)
      rlErrorCode = -EFAULT;
    return rlErrorCode;
  }
};



rLANG_DECLARE_END

#endif /* __WTINC_SCANNER_H__ */


#include "./scanner.h"
#include "../grammar/grammar.h"
#include <algorithm>

rLANG_DECLARE_MACHINE

#ifndef MAX_RULE
#define MAX_RULE (1 * 1024 * 1024)
#endif /* MAX_RULE */

#ifndef MAXIMUM_MNS
#define MAXIMUM_MNS (100000000)
#endif /* MAXIMUM_MNS */

#define NIL 0

#define JAM -1
#define NO_TRANSITION NIL
#define UNIQUE -1

#define INITIAL_MAX_DFA_SIZE 256
#define MAX_DFA_SIZE_INCREMENT 1024

#define INITIAL_MAX_CCLS 128
#define MAX_CCLS_INCREMENT 128

#define INITIAL_MAX_CCL_TBL_SIZE 256
#define MAX_CCL_TBL_SIZE_INCREMENT 256

#define INITIAL_MAX_RULES 50
#define MAX_RULES_INCREMENT 100

#define INITIAL_MNS 200
#define MNS_INCREMENT 1000

#define INITIAL_MAX_DFAS 100
#define MAX_DFAS_INCREMENT 1000

#define JAMSTATE -2147483640

#define MARKER_DIFFERENCE (MAXIMUM_MNS + 2)
#define INITIAL_MAX_XPAIRS 200
#define MAX_XPAIRS_INCREMENT 1000

#define INITIAL_MAX_TEMPLATE_XPAIRS 250
#define MAX_TEMPLATE_XPAIRS_INCREMENT 1000

#define SAME_TRANS -1

#define PROTO_SIZE_PERCENTAGE 15
#define CHECK_COM_PERCENTAGE 50
#define FIRST_MATCH_DIFF_PERCENTAGE 10
#define ACCEPTABLE_DIFF_PERCENTAGE 50
#define TEMPLATE_SAME_PERCENTAGE 60
#define NEW_PROTO_DIFF_PERCENTAGE 20
#define INTERIOR_FIT_PERCENTAGE 15
#define MAX_XTIONS_FULL_INTERIOR_FIT 4

#define MARK_STATE(state) trans1[state] = trans1[state] - MARKER_DIFFERENCE;
#define IS_MARKED(state) (trans1[state] < 0)
#define UNMARK_STATE(state) trans1[state] = trans1[state] + MARKER_DIFFERENCE;

#define CHECK_ACCEPT(state)      \
  {                              \
    nfaccnum = accptnum[state];  \
    if (nfaccnum != NIL)         \
      accset[++nacc] = nfaccnum; \
  }

#define DO_REALLOCATION                                        \
  {                                                            \
    int incl = current_max_dfa_size / 4;                       \
    if (incl < MAX_DFA_SIZE_INCREMENT)                         \
      incl = MAX_DFA_SIZE_INCREMENT;                           \
    current_max_dfa_size += incl;                              \
    t = reallocate_integer_array(t, current_max_dfa_size);     \
    stk = reallocate_integer_array(stk, current_max_dfa_size); \
  }

#define PUT_ON_STACK(state)               \
  {                                       \
    if (++stkend >= current_max_dfa_size) \
      DO_REALLOCATION                     \
    stk[stkend] = state;                  \
    MARK_STATE(state)                     \
  }

#define ADD_STATE(state)                     \
  {                                          \
    if (++numstates >= current_max_dfa_size) \
      DO_REALLOCATION                        \
    t[numstates] = state;                    \
    hashval += state;                        \
  }

#define STACK_STATE(state)                                  \
  {                                                         \
    PUT_ON_STACK(state)                                     \
    CHECK_ACCEPT(state)                                     \
    if (nfaccnum != NIL || transchar[state] != SYM_EPSILON) \
      ADD_STATE(state)                                      \
  }

#define FREE_EPSILON(state) \
  (transchar[state] == SYM_EPSILON && trans2[state] == NO_TRANSITION && finalst[state] != state)
#define SUPER_FREE_EPSILON(state) (transchar[state] == SYM_EPSILON && trans1[state] == NO_TRANSITION)

#define X_LEXICAL_FAILED(code, args) \
  do {                               \
    rlLOGE args;                     \
    assert(code != 0);               \
    longjmp(*execpt_handler, code);  \
  } while (0)

    namespace {
  constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("Lex@0");
}


//
// Memory management ...
//
void rlLexicalScannerGenerator::scanner_memory_clean() {
  rLANG_LIST_NODE_t* node;

  for (;;) {
    XDS_list_pop_front(&memory_list_, node = (rLANG_LIST_NODE_t*));
    if (node == &memory_list_)
      break;
    free(node);
  }
}

void* rlLexicalScannerGenerator::scanner_memory_realloc(void* p, size_t n, size_t s) {
  constexpr size_t kSizeMemoryLimit = 2000 * 1024 * 1024;
  if (s == 0 || n == 0) {
    if (p) {
      rLANG_LIST_NODE_t* node = (rLANG_LIST_NODE_t*)p - 1;
      XDS_list_erase(node, (void));
      free(node);
    }
    return nullptr;
  }

  if (kSizeMemoryLimit / s < n) {
    X_LEXICAL_FAILED(-ENOMEM, (TAG, "[*OOM*]memory.alloc failed %p %zd %zd", p, n, s));
    return nullptr;
  }

  rLANG_LIST_NODE_t* node = nullptr;
  const auto size = s * n;

  if (!p) {
    node = (rLANG_LIST_NODE_t*)malloc(sizeof(rLANG_LIST_NODE_t) + size);
  } else {
    rLANG_LIST_NODE_t* origin = (rLANG_LIST_NODE_t*)p - 1;
    XDS_list_erase(origin, (void));

    node = (rLANG_LIST_NODE_t*)realloc(origin, sizeof(rLANG_LIST_NODE_t) + size);
    if (!node)
      XDS_list_push_back(&memory_list_, origin);
  }
  
  if (!node) {
    X_LEXICAL_FAILED(-ENOMEM, (TAG, "[*OOM*]memory.alloc failed %p %zd %zd", p, n, s));
    return nullptr;
  } else {
    XDS_list_push_back(&memory_list_, node);
  }

  return node + 1;
}


#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 26495)  // C26495: rlLexicalScannerGenerator::value is uninitialized
#endif                            /* _MSC_VER */


rlLexicalScannerGenerator::rlLexicalScannerGenerator(Char* const cclflags__,
                                                     int* const nextecm__,
                                                     int* const ecgroup__,
                                                     int* const tecfwd__,
                                                     int* const tecbck__,
                                                     const int csize,
                                                     const int sconCount,
                                                     const bool caseless,
                                                     const int* const cclower__, /* global */
                                                     const int* const charmap__ /* global */)
    : CSIZE(csize),
      SYM_EPSILON(csize + 1),
      SCON_COUNT(sconCount),
      IGNCASE(caseless),

      cclflags(cclflags__),
      nextecm(nextecm__),
      ecgroup(ecgroup__),
      tecfwd(tecfwd__),
      tecbck(tecbck__),

      tolower_(cclower__),
      charmap_(charmap__) {
  assert(CSIZE >= 16 && SCON_COUNT >= 1);
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif /* _MSC_VER */

int rlLexicalScannerGenerator::CreateLexicalScannerGenerator(rlLexicalScannerGenerator** newGenerator,
                                                             int CSIZE,
                                                             int sconCount,
                                                             bool caseless,
                                                             const int* cclower,
                                                             const int* charmap) {
  *newGenerator = nullptr;
  constexpr int kMaximumCharacter = 2 << 20;
  if (CSIZE < 16 || CSIZE > kMaximumCharacter || sconCount < 1)
    return -EINVAL;

  if (charmap) {
    for (int i = 0; i < CSIZE; ++i) {
      if (charmap[i] < 0 || charmap[i] >= CSIZE)
        return -EINVAL;
    }
  }

  if (cclower) {
    for (int i = 0; i < CSIZE; ++i) {
      if (cclower[i] < 0 || cclower[i] >= CSIZE)
        return -EINVAL;
    }
  }

  const size_t CSIZE_ALIGN = ((size_t)CSIZE + 8) & -4;
  const size_t size_memory = sizeof(rlLexicalScannerGenerator) + CSIZE_ALIGN * (sizeof(Char) + 4 * sizeof(int));

  void* const memory = calloc(1, size_memory);
  if (!memory)
    return -ENOMEM;

  Char* const cclflags__ = (Char*)((uint8_t*)memory + sizeof(rlLexicalScannerGenerator)) + 2;
  int* const nextecm__ = (int*)&cclflags__[CSIZE_ALIGN];
  int* const ecgroup__ = (int*)&nextecm__[CSIZE_ALIGN];
  int* const tecfwd__ = (int*)&ecgroup__[CSIZE_ALIGN];
  int* const tecbck__ = (int*)&tecfwd__[CSIZE_ALIGN];

  auto* self = ::new (memory) rlLexicalScannerGenerator(cclflags__, nextecm__, ecgroup__, tecfwd__, tecbck__, CSIZE,
                                                      sconCount, caseless, cclower, charmap);
  assert((void*)self == memory);

  int rlCode = self->Execute([self] { return self->context_init(); });

  if (0 != rlCode) {
    DestroyLexicalScannerGenerator(self);
    return rlCode < 0 ? rlCode : -EFAULT;
  }

  *newGenerator = self;
  return 0;
}

void rlLexicalScannerGenerator::DestroyLexicalScannerGenerator(rlLexicalScannerGenerator* self) {
  if (!self)
    return;
  self->scanner_memory_clean();
  free(self);
}


int rlLexicalScannerGenerator::SetSconList(int count, const int* sconlist) {
  if (count > 0) {
    if (!sconlist)
      return -EINVAL;

    for (int i = 0; i < count; ++i) {
      if (sconlist[i] < 1 || sconlist[i] > SCON_COUNT)
        return -EINVAL;
    }
    set_scon_list(count, sconlist);
  } else {
    set_scon_list(0 == count ? SCON_SHARED : SCON_ANY, nullptr);
  }

  return 0;
}
int rlLexicalScannerGenerator::AddShareSconList(int scon) {
  if (scon < 1 || scon > SCON_COUNT)
    return -ERANGE;
  add_share_scon_list(scon);
  return 0;
}

int rlLexicalScannerGenerator::AddNewCCl(bool negate, int count, const int* cclist) {
  int result = -1;
  int code = Execute([this, negate, count, cclist, &result] {
    int ccl = cclinit();
    for (int i = 0; i < count; ++i)
      ccladd(ccl, cclist[i]);
    if (negate)
      cclnegate(ccl);
    mkeccl(ccltbl + cclmap[ccl], ccllen[ccl], nextecm, ecgroup, CSIZE, CSIZE);
    result = ccl;
    return 0;
  });

  if (code != 0)
    return code < 0 ? code : -EFAULT;
  return result;
}

int rlLexicalScannerGenerator::AddNewRule(bool bol, int size, const int opcode[]) {
  int result = -1;
  int code = Execute([this, bol, size, opcode, &result] {
    constexpr int kSizeStack = 256;
    int vStack[kSizeStack + 2], nStack = 0, errCode = 0, index;
    char message[128];

    new_rule();
    message[0] = 0;
    for (index = 0; 0 == errCode && index < size; ++index) {
      const int op = opcode[index] >> 24;
      const int val = opcode[index] & 0xFFFFFF;

      switch (op) {
        case kOpCode_LinkChr:
        case kOpCode_MakeClos:
        case kOpCode_MakePoscl:
        case kOpCode_MakeOpt:
        case kOpCode_MakeRep1:
        case kOpCode_MakeRep1X:
        case kOpCode_MakeRep2EX: {
          if (nStack < 1 || nStack >= kSizeStack) {
            errCode = -EBADMSG;
            sprintf(message, "invalid op: %d, stack.size %d (.GE. 1)", op, nStack);
          }
        } break;

        case kOpCode_LinkNil:
        case kOpCode_MakeOr: {
          if (nStack < 2 || nStack >= kSizeStack) {
            errCode = -EBADMSG;
            sprintf(message, "invalid op: %d, stack.size %d (.GE. 2)", op, nStack);
          }
        } break;

        default:
        case kOpCode_MakeNil:
        case kOpCode_MakeChr:
        case kOpCode_MakeCcl: {
          if (nStack < 0 || nStack >= kSizeStack) {
            errCode = -EBADMSG;
            sprintf(message, "invalid op: %d, stack.size %d (.LT. %d)", op, nStack, kSizeStack);
          }
        } break;
      }

      if (0 != errCode)
        break;

      switch (op) {
        case kOpCode_MakeNil: {
          vStack[nStack++] = mkstate(SYM_EPSILON);
        } break;

        case kOpCode_MakeChr: {
          if (val < 0 || val > CSIZE) {
            errCode = -ERANGE;
            sprintf(message, "Character out-of-range %d %d", val, CSIZE);
          } else {
            vStack[nStack++] = mkstate(val);
          }
        } break;

        case kOpCode_MakeCcl: {
          if (val <= 0 || val > lastccl) {
            errCode = -ERANGE;
            sprintf(message, "ccl out-of-range %d %d", val, lastccl);
          } else {
            vStack[nStack++] = mkstate(-val);
          }
        } break;

        case kOpCode_LinkChr: {
          assert(nStack >= 1);
          if (val < 0 || val > CSIZE) {
            errCode = -ERANGE;
            sprintf(message, "Character out-of-range %d %d", val, CSIZE);
          } else {
            vStack[nStack - 1] = link_machines(vStack[nStack - 1], mkstate(val));
          }
        } break;

        case kOpCode_LinkNil: {
          assert(nStack >= 2);
          vStack[nStack - 2] = link_machines(vStack[nStack - 2], vStack[nStack - 1]);
          --nStack;
        } break;

        case kOpCode_MakeClos: {
          assert(nStack >= 1);
          vStack[nStack - 1] = mkclos(vStack[nStack - 1]);
        } break;

        case kOpCode_MakePoscl: {
          assert(nStack >= 1);
          vStack[nStack - 1] = mkposcl(vStack[nStack - 1]);
        } break;

        case kOpCode_MakeOpt: {
          assert(nStack >= 1);
          vStack[nStack - 1] = mkopt(vStack[nStack - 1]);
        } break;

        case kOpCode_MakeRep1: {
          assert(nStack >= 1);
          if (val <= 0) {
            errCode = -ERANGE;
            sprintf(message, "iteration value must be positive %d", val);
          } else {
            vStack[nStack - 1] = link_machines(vStack[nStack - 1], copysingl(vStack[nStack - 1], val - 1));
          }
        } break;

        case kOpCode_MakeRep1X: {
          assert(nStack >= 1);
          if (val <= 0) {
            errCode = -ERANGE;
            sprintf(message, "iteration value must be positive %d", val);
          } else if (val == 1) {
            vStack[nStack - 1] = mkposcl(vStack[nStack - 1]);
          } else {
            vStack[nStack - 1] = mkrep(vStack[nStack - 1], val, kINFINITY);
          }
        } break;

        case kOpCode_MakeRep2EX: {
          assert(nStack >= 1);
          int v2 = -1;

          if (++index < size)
            v2 = opcode[index];

          if (val < 0 || val > v2 || (val == 0 && v2 == 0)) {
            errCode = -ERANGE;
            sprintf(message, "bad iteration values %d %d", val, v2);
          } else {
            if (val == 0)
              vStack[nStack - 1] = mkopt(mkrep(vStack[nStack - 1], 1, v2));
            else
              vStack[nStack - 1] = mkrep(vStack[nStack - 1], val, v2);
          }
        } break;

        case kOpCode_MakeOr: {
          assert(nStack >= 2);
          vStack[nStack - 2] = mkor(vStack[nStack - 2], vStack[nStack - 1]);
          --nStack;
        } break;

        default: {
          errCode = -EBADMSG;
          sprintf(message, "invalid OpCode %d/%d", op, val);
        } break;
      }
    }

    if (0 == errCode) {
      if (1 != nStack) {
        errCode = -EBADMSG;
        sprintf(message, "invalid stack.size %d (.EQ. 1)", nStack);
      } else {
        finish_define_rule(bol, vStack[0]);
        result = num_rules;
      }
    }

    if (0 != errCode)
      X_LEXICAL_FAILED(errCode, (TAG, "Syntax error (%d/%d): %d/%s", index, size, errCode, message));

    return 0;
  });

  if (code != 0)
    return code < 0 ? code : -EFAULT;
  return result;
}

int rlLexicalScannerGenerator::GenerateScanner(LexicalScanner_t* storage) {
  if (!storage)
    return -EINVAL;

  memset(storage, 0, sizeof(*storage));
  int code = Execute([this, storage] {
    generate();
    *storage = GetLexicalScanner();
    return 0;
  });

  if (code != 0)
    return code < 0 ? code : -EFAULT;
  return code;
}

int rlLexicalScannerGenerator::context_init() {
  int i;
  lastprot = 1;
  ecgroup[1] = NIL;

  for (i = 2; i <= CSIZE; ++i) {
    ecgroup[i] = i - 1;
    nextecm[i - 1] = i;
  }

  nextecm[CSIZE] = NIL;
  current_mns = INITIAL_MNS;
  firstst = allocate_integer_array(current_mns);
  lastst = allocate_integer_array(current_mns);
  finalst = allocate_integer_array(current_mns);
  transchar = allocate_integer_array(current_mns);
  trans1 = allocate_integer_array(current_mns);
  trans2 = allocate_integer_array(current_mns);
  accptnum = allocate_integer_array(current_mns);
  assoc_rule = allocate_integer_array(current_mns);

  current_max_rules = INITIAL_MAX_RULES;
  rule_type = allocate_integer_array(current_max_rules);
  rule_useful = allocate_integer_array(current_max_rules);

  scset = allocate_integer_array(SCON_COUNT + 1);
  scbol = allocate_integer_array(SCON_COUNT + 1);
  scon_stk = allocate_integer_array(SCON_COUNT + 1);
  scon_stk_ptr = 0;

  scon_stk_share = allocate_integer_array(SCON_COUNT + 1);
  scon_stk_share_count = SCON_COUNT;
  scon_stk_share_ptr = 1;
  scon_stk_share[1] = SCON_INITIAL;

  for (i = 1; i <= SCON_COUNT; ++i) {
    scset[i] = mkstate(SYM_EPSILON);
    scbol[i] = mkstate(SYM_EPSILON);
  }

  current_maxccls = INITIAL_MAX_CCLS;
  cclmap = allocate_integer_array(current_maxccls);
  ccllen = allocate_integer_array(current_maxccls);
  cclng = allocate_integer_array(current_maxccls);

  current_max_ccl_tbl_size = INITIAL_MAX_CCL_TBL_SIZE;
  ccltbl = allocate_Character_array(current_max_ccl_tbl_size);

  current_max_dfa_size = INITIAL_MAX_DFA_SIZE;

  current_max_xpairs = INITIAL_MAX_XPAIRS;
  nxt = allocate_integer_array(current_max_xpairs);
  chk = allocate_integer_array(current_max_xpairs);

  current_max_template_xpairs = INITIAL_MAX_TEMPLATE_XPAIRS;
  tnxt = allocate_integer_array(current_max_template_xpairs);

  current_max_dfas = INITIAL_MAX_DFAS;
  base = allocate_integer_array(current_max_dfas);
  def = allocate_integer_array(current_max_dfas);
  dfasiz = allocate_integer_array(current_max_dfas);
  accsiz = allocate_integer_array(current_max_dfas);
  dhash = allocate_integer_array(current_max_dfas);
  dss = allocate_int_ptr_array(current_max_dfas);
  dfaacc = allocate_integer_array(current_max_dfas + 4);
  nultrans = nullptr;

  return 0;
}

void rlLexicalScannerGenerator::finish_define_rule(bool bol, int rule) {
  int i, sc, *scl;

  finish_rule(rule);
  if (scon_stk_ptr >= 1) {
    sc = scon_stk_ptr;
    scl = scon_stk;
  } else {
    sc = scon_stk_share_ptr;
    scl = scon_stk_share;
  }

  if (bol) {
    for (i = 1; i <= sc; ++i) {
      scbol[scl[i]] = mkbranch(scbol[scl[i]], rule);
    }
  } else {
    for (i = 1; i <= sc; ++i) {
      scset[scl[i]] = mkbranch(scset[scl[i]], rule);
    }
  }
}


void rlLexicalScannerGenerator::set_scon_list(int count, const int scon_list[]) {
  if (count == SCON_ANY) {
    for (int i = 1; i <= SCON_COUNT; ++i)
      scon_stk[i] = i;
    scon_stk_ptr = SCON_COUNT;
  } else {
    scon_stk_ptr = 0;
    for (int i = 0; i < count; ++i)
      add_scon_list(scon_list[i]);
  }
}

void rlLexicalScannerGenerator::add_scon_list(int scon) {
  assert(scon >= 1 && scon <= SCON_COUNT);
  for (int i = 1; i <= scon_stk_ptr; ++i) {
    if (scon_stk[i] == scon)
      return;
  }
  scon_stk[++scon_stk_ptr] = scon;
}

void rlLexicalScannerGenerator::add_share_scon_list(int scon) {
  assert(scon >= 1 && scon <= SCON_COUNT);
  for (int i = 1; i <= scon_stk_share_count; ++i) {
    if (scon_stk_share[i] == scon)
      return;
  }
  scon_stk_share[++scon_stk_share_count] = scon;
}

void rlLexicalScannerGenerator::new_rule() {
  if (default_rule > 0) {
    X_LEXICAL_FAILED(-EALREADY, (TAG, "new_rule after generate table!"));
  }

  if (++num_rules > MAX_RULE) {
    X_LEXICAL_FAILED(-ENOMEM, (TAG, "too many rules ( > %d)!", MAX_RULE));
  }

  if (num_rules >= current_max_rules) {
    int incl_rules = current_max_rules / 4;
    if (incl_rules < MAX_RULES_INCREMENT)
      incl_rules = MAX_RULES_INCREMENT;

    current_max_rules += incl_rules;
    rule_type = reallocate_integer_array(rule_type, current_max_rules);
    rule_useful = reallocate_integer_array(rule_useful, current_max_rules);
  }
  rule_useful[num_rules] = false;
}

void rlLexicalScannerGenerator::finish_rule(int mach) {
  add_accept(mach, num_rules);
}

void rlLexicalScannerGenerator::add_accept(int mach, int accepting_number) {
  if (transchar[finalst[mach]] == SYM_EPSILON)
    accptnum[finalst[mach]] = accepting_number;
  else {
    int astate = mkstate(SYM_EPSILON);
    accptnum[astate] = accepting_number;
    link_machines(mach, astate);
  }
}

int rlLexicalScannerGenerator::copysingl(int singl, int num) {
  int copy, i;

  copy = mkstate(SYM_EPSILON);

  for (i = 1; i <= num; ++i)
    copy = link_machines(copy, dupmachine(singl));

  return copy;
}

void rlLexicalScannerGenerator::mkxtion(int statefrom, int stateto) {
  if (trans1[statefrom] == NO_TRANSITION)
    trans1[statefrom] = stateto;

  else if ((transchar[statefrom] != SYM_EPSILON) || (trans2[statefrom] != NO_TRANSITION)) {
    X_LEXICAL_FAILED(-ENOMEM, (TAG, "found too many transitions in mkxtion()"));
  }

  else {
    trans2[statefrom] = stateto;
  }
}

int rlLexicalScannerGenerator::dupmachine(int mach) {
  int i, init = 0, state_offset;
  int state = 0;
  int last = lastst[mach];

  for (i = firstst[mach]; i <= last; ++i) {
    state = mkstate(transchar[i]);

    if (trans1[i] != NO_TRANSITION) {
      mkxtion(finalst[state], trans1[i] + state - i);

      if (transchar[i] == SYM_EPSILON && trans2[i] != NO_TRANSITION)
        mkxtion(finalst[state], trans2[i] + state - i);
    }

    accptnum[state] = accptnum[i];
  }

  if (state == 0) {
    X_LEXICAL_FAILED(-EINVAL, (TAG, "empty machine in dupmachine()"));
  } else {
    state_offset = state - i + 1;

    init = mach + state_offset;
    firstst[init] = firstst[mach] + state_offset;
    finalst[init] = finalst[mach] + state_offset;
    lastst[init] = lastst[mach] + state_offset;
  }

  return init;
}

int rlLexicalScannerGenerator::link_machines(int first, int last) {
  if (first == NIL)
    return last;

  else if (last == NIL)
    return first;
  else {
    mkxtion(finalst[first], last);
    finalst[first] = finalst[last];
    lastst[first] = std::max(lastst[first], lastst[last]);
    firstst[first] = std::min(firstst[first], firstst[last]);

    return first;
  }
}

int rlLexicalScannerGenerator::mkbranch(int first, int second) {
  int eps;

  if (first == NO_TRANSITION)
    return second;

  else if (second == NO_TRANSITION)
    return first;

  eps = mkstate(SYM_EPSILON);

  mkxtion(eps, first);
  mkxtion(eps, second);

  return eps;
}

int rlLexicalScannerGenerator::mkclos(int state) {
  return mkopt(mkposcl(state));
}

int rlLexicalScannerGenerator::mkopt(int mach) {
  int eps;

  if (!SUPER_FREE_EPSILON(finalst[mach])) {
    eps = mkstate(SYM_EPSILON);
    mach = link_machines(mach, eps);
  }

  eps = mkstate(SYM_EPSILON);
  mach = link_machines(eps, mach);

  mkxtion(mach, finalst[mach]);

  return mach;
}

int rlLexicalScannerGenerator::mkor(int first, int second) {
  int eps, orend;

  if (first == NIL)
    return second;

  else if (second == NIL)
    return first;

  else {
    eps = mkstate(SYM_EPSILON);

    first = link_machines(eps, first);

    mkxtion(first, second);

    if (SUPER_FREE_EPSILON(finalst[first]) && accptnum[finalst[first]] == NIL) {
      orend = finalst[first];
      mkxtion(finalst[second], orend);
    }

    else if (SUPER_FREE_EPSILON(finalst[second]) && accptnum[finalst[second]] == NIL) {
      orend = finalst[second];
      mkxtion(finalst[first], orend);
    }

    else {
      eps = mkstate(SYM_EPSILON);

      first = link_machines(first, eps);
      orend = finalst[first];

      mkxtion(finalst[second], orend);
    }
  }

  finalst[first] = orend;
  return first;
}


int rlLexicalScannerGenerator::mkposcl(int state) {
  int eps;

  if (SUPER_FREE_EPSILON(finalst[state])) {
    mkxtion(finalst[state], state);
    return state;
  }

  else {
    eps = mkstate(SYM_EPSILON);
    mkxtion(eps, state);
    return link_machines(state, eps);
  }
}

int rlLexicalScannerGenerator::mkrep(int mach, int lb, int ub) {
  int base_mach, tail, copy, i;

  base_mach = copysingl(mach, lb - 1);

  if (ub == kINFINITY) {
    copy = dupmachine(mach);
    mach = link_machines(mach, link_machines(base_mach, mkclos(copy)));
  }

  else {
    tail = mkstate(SYM_EPSILON);

    for (i = lb; i < ub; ++i) {
      copy = dupmachine(mach);
      tail = mkopt(link_machines(copy, tail));
    }

    mach = link_machines(mach, link_machines(base_mach, tail));
  }

  return mach;
}

int rlLexicalScannerGenerator::mkstate(int sym) {
  if (++lastnfa >= current_mns) {
    if (current_mns >= MAXIMUM_MNS) {
      X_LEXICAL_FAILED(-ERANGE, (TAG, "input rules are too complicated (>= %d NFA states)", current_mns));
    }

    int incl = current_mns / 4;
    if (incl < MNS_INCREMENT)
      incl = MNS_INCREMENT;

    current_mns += incl;

    firstst = reallocate_integer_array(firstst, current_mns);
    lastst = reallocate_integer_array(lastst, current_mns);
    finalst = reallocate_integer_array(finalst, current_mns);
    transchar = reallocate_integer_array(transchar, current_mns);
    trans1 = reallocate_integer_array(trans1, current_mns);
    trans2 = reallocate_integer_array(trans2, current_mns);
    accptnum = reallocate_integer_array(accptnum, current_mns);
    assoc_rule = reallocate_integer_array(assoc_rule, current_mns);
  }

  firstst[lastnfa] = lastnfa;
  finalst[lastnfa] = lastnfa;
  lastst[lastnfa] = lastnfa;
  transchar[lastnfa] = sym;
  trans1[lastnfa] = NO_TRANSITION;
  trans2[lastnfa] = NO_TRANSITION;
  accptnum[lastnfa] = NIL;
  assoc_rule[lastnfa] = num_rules;

  if (sym < 0) {
    if (sym > lastccl)
      X_LEXICAL_FAILED(-ERANGE, (TAG, "invalid ccl %d/%d", sym, lastccl));
  }

  else if (sym == SYM_EPSILON) {
    ;
  }

  else {
    if (IGNCASE && x_isupper(sym))
      sym = x_tolower(sym);
    sym = x_charmap(sym);

    if (sym > CSIZE)
      X_LEXICAL_FAILED(-ERANGE, (TAG, "input character OutOfRange %d > %d", sym, CSIZE));

    transchar[lastnfa] = sym;
    mkechar(sym ? sym : CSIZE, nextecm, ecgroup);
  }

  return lastnfa;
}

void rlLexicalScannerGenerator::ccladd(int cclp, int ch) {
  int ind, len, newpos, i;

  if (ch > CSIZE || ch < 0)
    X_LEXICAL_FAILED(-ERANGE, (TAG, "input character OutOfRange %d > %d", ch, CSIZE));
  if (IGNCASE && x_isupper(ch))
    ch = x_tolower(ch);
  ch = x_charmap(ch);
  if (ch > CSIZE || ch < 0)
    X_LEXICAL_FAILED(-ERANGE, (TAG, "input character OutOfRange %d > %d", ch, CSIZE));

  len = ccllen[cclp];
  ind = cclmap[cclp];

  for (i = 0; i < len; ++i)
    if (ccltbl[ind + i] == ch)
      return;

  newpos = ind + len;

  if (newpos >= current_max_ccl_tbl_size) {
    int incl = current_max_ccl_tbl_size / 4;
    if (incl < MAX_CCL_TBL_SIZE_INCREMENT)
      incl = MAX_CCL_TBL_SIZE_INCREMENT;
    current_max_ccl_tbl_size += incl;

    ccltbl = reallocate_Character_array(ccltbl, current_max_ccl_tbl_size);
  }

  ccllen[cclp] = len + 1;
  ccltbl[newpos] = ch;
}

int rlLexicalScannerGenerator::cclinit() {
  if (++lastccl >= current_maxccls) {
    int incl = current_maxccls / 4;
    if (incl < MAX_CCLS_INCREMENT)
      incl = MAX_CCLS_INCREMENT;
    current_maxccls += incl;

    cclmap = reallocate_integer_array(cclmap, current_maxccls);
    ccllen = reallocate_integer_array(ccllen, current_maxccls);
    cclng = reallocate_integer_array(cclng, current_maxccls);
  }

  if (lastccl == 1)
    cclmap[lastccl] = 0;
  else
    cclmap[lastccl] = cclmap[lastccl - 1] + ccllen[lastccl - 1];

  ccllen[lastccl] = 0;
  cclng[lastccl] = 0;

  return lastccl;
}

void rlLexicalScannerGenerator::cclnegate(int cclp) {
  cclng[cclp] = 1;
}

void rlLexicalScannerGenerator::ccl2ecl() {
  int i, ich, newlen, cclp, ccls, cclmec;

  for (i = 1; i <= lastccl; ++i) {
    newlen = 0;
    cclp = cclmap[i];

    for (ccls = 0; ccls < ccllen[i]; ++ccls) {
      ich = ccltbl[cclp + ccls];
      cclmec = ecgroup[ich];

      if (cclmec > 0) {
        ccltbl[cclp + newlen] = cclmec;
        ++newlen;
      }
    }

    ccllen[i] = newlen;
  }
}

int rlLexicalScannerGenerator::cre8ecs(int fwd[], int bck[], int num) {
  int i, j, numcl;

  numcl = 0;

  for (i = 1; i <= num; ++i)
    if (bck[i] == NIL) {
      bck[i] = ++numcl;
      for (j = fwd[i]; j != NIL; j = fwd[j])
        bck[j] = -numcl;
    }

  return numcl;
}

void rlLexicalScannerGenerator::mkeccl(Char ccls[], int lenccl, int fwd[], int bck[], int llsiz, int NUL_mapping) {
  int cclp, oldec, newec;
  int cclm, i, j;

  cclp = 0;

  while (cclp < lenccl) {
    cclm = ccls[cclp];

    if (NUL_mapping && cclm == 0)
      cclm = NUL_mapping;

    oldec = bck[cclm];
    newec = cclm;

    j = cclp + 1;

    for (i = fwd[cclm]; i != NIL && i <= llsiz; i = fwd[i]) {
      for (; j < lenccl; ++j) {
        int ccl_char;

        if (NUL_mapping && ccls[j] == 0)
          ccl_char = NUL_mapping;
        else
          ccl_char = ccls[j];

        if (ccl_char > i)
          break;

        if (ccl_char == i && !cclflags[j]) {
          bck[i] = newec;
          fwd[newec] = i;
          newec = i;

          cclflags[j] = 1;
          goto next_pt;
        }
      }

      bck[i] = oldec;

      if (oldec != NIL)
        fwd[oldec] = i;

      oldec = i;

    next_pt:;
    }

    if (bck[cclm] != NIL || oldec != bck[cclm]) {
      bck[cclm] = NIL;
      fwd[oldec] = NIL;
    }

    fwd[newec] = NIL;

    for (++cclp; cclflags[cclp] && cclp < lenccl; ++cclp) {
      cclflags[cclp] = 0;
    }
  }
}

void rlLexicalScannerGenerator::mkechar(int tch, int fwd[], int bck[]) {
  if (fwd[tch] != NIL)
    bck[fwd[tch]] = bck[tch];

  if (bck[tch] != NIL)
    fwd[bck[tch]] = fwd[tch];

  fwd[tch] = NIL;
  bck[tch] = NIL;
}

void rlLexicalScannerGenerator::increase_max_dfas() {
  int incl = current_max_dfas / 4;
  if (incl < MAX_DFAS_INCREMENT)
    incl = MAX_DFAS_INCREMENT;
  current_max_dfas += incl;

  base = reallocate_integer_array(base, current_max_dfas);
  def = reallocate_integer_array(def, current_max_dfas);
  dfasiz = reallocate_integer_array(dfasiz, current_max_dfas);
  accsiz = reallocate_integer_array(accsiz, current_max_dfas);
  dhash = reallocate_integer_array(dhash, current_max_dfas);
  dss = reallocate_int_ptr_array(dss, current_max_dfas);
  dfaacc = reallocate_integer_array(dfaacc, current_max_dfas + 4);

  if (nultrans)
    nultrans = reallocate_integer_array(nultrans, current_max_dfas);
}

void rlLexicalScannerGenerator::bldtbl(int state[], int statenum, int totaltrans, int comstate, int comfreq) {
  int* extrct_memory = allocate_integer_array(2 + 2 * CSIZE);
  int extptr, *extrct[2] = {&extrct_memory[0], &extrct_memory[1 + CSIZE]};
  int mindiff, minprot, i, d;

  extptr = 0;

  if ((totaltrans * 100) < (numecs * PROTO_SIZE_PERCENTAGE))
    mkentry(state, numecs, statenum, JAMSTATE, totaltrans);

  else {
    int checkcom = comfreq * 100 > totaltrans * CHECK_COM_PERCENTAGE;

    minprot = firstprot;
    mindiff = totaltrans;

    if (checkcom) {
      for (i = firstprot; i != NIL; i = protnext[i])
        if (protcomst[i] == comstate) {
          minprot = i;
          mindiff = tbldiff(state, minprot, extrct[extptr]);
          break;
        }
    }

    else {
      comstate = 0;

      if (firstprot != NIL) {
        minprot = firstprot;
        mindiff = tbldiff(state, minprot, extrct[extptr]);
      }
    }

    if (mindiff * 100 > totaltrans * FIRST_MATCH_DIFF_PERCENTAGE) {
      for (i = minprot; i != NIL; i = protnext[i]) {
        d = tbldiff(state, i, extrct[1 - extptr]);
        if (d < mindiff) {
          extptr = 1 - extptr;
          mindiff = d;
          minprot = i;
        }
      }
    }

    if (mindiff * 100 > totaltrans * ACCEPTABLE_DIFF_PERCENTAGE) {
      if (comfreq * 100 >= totaltrans * TEMPLATE_SAME_PERCENTAGE)
        mktemplate(state, statenum, comstate);

      else {
        mkprot(state, statenum, comstate);
        mkentry(state, numecs, statenum, JAMSTATE, totaltrans);
      }
    }

    else {
      mkentry(extrct[extptr], numecs, statenum, prottbl[minprot], mindiff);

      if (mindiff * 100 >= totaltrans * NEW_PROTO_DIFF_PERCENTAGE)
        mkprot(state, statenum, comstate);

      mv2front(minprot);
    }
  }

  free_array(extrct_memory);
}

void rlLexicalScannerGenerator::cmptmps() {
  int* tmpstorage = allocate_integer_array(CSIZE + 1);
  int *tmp = tmpstorage, i, j;
  int totaltrans, trans;

  if (1) {
    nummecs = cre8ecs(tecfwd, tecbck, numecs);
  }

  while (lastdfa + numtemps + 1 >= current_max_dfas)
    increase_max_dfas();

  for (i = 1; i <= numtemps; ++i) {
    totaltrans = 0;

    for (j = 1; j <= numecs; ++j) {
      trans = tnxt[numecs * i + j];

      if (1) {
        if (tecbck[j] > 0) {
          tmp[tecbck[j]] = trans;

          if (trans > 0)
            ++totaltrans;
        }
      }
#if 0
      else {
        tmp[j] = trans;

        if (trans > 0)
          ++totaltrans;
      }
#endif
    }

    mkentry(tmp, nummecs, lastdfa + i + 1, JAMSTATE, totaltrans);
  }

  free_array(tmpstorage);
}


void rlLexicalScannerGenerator::expand_nxt_chk() {
  int old_max = current_max_xpairs;

  int incl = current_max_xpairs / 4;
  if (incl < MAX_XPAIRS_INCREMENT)
    incl = MAX_XPAIRS_INCREMENT;
  current_max_xpairs += MAX_XPAIRS_INCREMENT;

  nxt = reallocate_integer_array(nxt, current_max_xpairs);
  chk = reallocate_integer_array(chk, current_max_xpairs);

  memset((char*)(chk + old_max), 0, (size_t)(MAX_XPAIRS_INCREMENT * sizeof(int)));
}

int rlLexicalScannerGenerator::find_table_space(int* state, int numtrans) {
  int i;
  int *state_ptr, *chk_ptr;
  int* ptr_to_last_entry_in_state;

  if (numtrans > MAX_XTIONS_FULL_INTERIOR_FIT) {
    if (tblend < 2)
      return 1;

    i = tblend - numecs;
  }

  else
    i = firstfree;

  while (1) {
    while (i + numecs >= current_max_xpairs)
      expand_nxt_chk();

    while (1) {
      if (chk[i - 1] == 0) {
        if (chk[i] == 0)
          break;

        else
          i += 2;
      }

      else
        ++i;

      while (i + numecs >= current_max_xpairs)
        expand_nxt_chk();
    }

    if (numtrans <= MAX_XTIONS_FULL_INTERIOR_FIT)
      firstfree = i + 1;

    state_ptr = &state[1];
    ptr_to_last_entry_in_state = &chk[i + numecs + 1];

    for (chk_ptr = &chk[i + 1]; chk_ptr != ptr_to_last_entry_in_state; ++chk_ptr) {
      if (*(state_ptr++) != 0 && *chk_ptr != 0)
        break;

      if (chk_ptr == ptr_to_last_entry_in_state)
        return i;

      else
        ++i;
    }
  }
}

void rlLexicalScannerGenerator::inittbl() {
  int i;

  memset((char*)chk, 0, (size_t)(current_max_xpairs * sizeof(int)));

  tblend = 0;
  firstfree = tblend + 1;
  numtemps = 0;

  if (1) {
    tecbck[1] = NIL;

    for (i = 2; i <= numecs; ++i) {
      tecbck[i] = i - 1;
      tecfwd[i - 1] = i;
    }

    tecfwd[numecs] = NIL;
  }
}

void rlLexicalScannerGenerator::mkdeftbl() {
  int i;

  jamstate = lastdfa + 1;

  ++tblend;

  while (tblend + numecs >= current_max_xpairs)
    expand_nxt_chk();

  nxt[tblend] = end_of_buffer_state;
  chk[tblend] = jamstate;

  for (i = 1; i <= numecs; ++i) {
    nxt[tblend + i] = 0;
    chk[tblend + i] = jamstate;
  }

  jambase = tblend;

  base[jamstate] = jambase;
  def[jamstate] = 0;

  tblend += numecs;
  ++numtemps;
}

void rlLexicalScannerGenerator::mkentry(int* state, int numchars, int statenum, int deflink, int totaltrans) {
  int minec, maxec, i, baseaddr;
  int tblbase, tbllast;

  if (totaltrans == 0) {
    if (deflink == JAMSTATE)
      base[statenum] = JAMSTATE;
    else
      base[statenum] = 0;

    def[statenum] = deflink;
    return;
  }

  for (minec = 1; minec <= numchars; ++minec) {
    if (state[minec] != SAME_TRANS)
      if (state[minec] != 0 || deflink != JAMSTATE)
        break;
  }

  if (totaltrans == 1) {
    stack1(statenum, minec, state[minec], deflink);
    return;
  }

  for (maxec = numchars; maxec > 0; --maxec) {
    if (state[maxec] != SAME_TRANS)
      if (state[maxec] != 0 || deflink != JAMSTATE)
        break;
  }

  if (totaltrans * 100 <= numchars * INTERIOR_FIT_PERCENTAGE) {
    baseaddr = firstfree;

    while (baseaddr < minec) {
      for (++baseaddr; chk[baseaddr] != 0; ++baseaddr)
        ;
    }

    while (baseaddr + maxec - minec + 1 >= current_max_xpairs)
      expand_nxt_chk();

    for (i = minec; i <= maxec; ++i)
      if (state[i] != SAME_TRANS && (state[i] != 0 || deflink != JAMSTATE) && chk[baseaddr + i - minec] != 0) {
        for (++baseaddr; baseaddr < current_max_xpairs && chk[baseaddr] != 0; ++baseaddr)
          ;

        while (baseaddr + maxec - minec + 1 >= current_max_xpairs)
          expand_nxt_chk();

        i = minec - 1;
      }
  }

  else {
    baseaddr = std::max(tblend + 1, minec);
  }

  tblbase = baseaddr - minec;
  tbllast = tblbase + maxec;

  while (tbllast + 1 >= current_max_xpairs)
    expand_nxt_chk();

  base[statenum] = tblbase;
  def[statenum] = deflink;

  for (i = minec; i <= maxec; ++i) {
    if (state[i] != SAME_TRANS) {
      if (state[i] != 0 || deflink != JAMSTATE) {
        nxt[tblbase + i] = state[i];
        chk[tblbase + i] = statenum;
      }
    }

    if (baseaddr == firstfree) {
      for (++firstfree; chk[firstfree] != 0; ++firstfree)
        ;
    }

    tblend = std::max(tblend, tbllast);
  }
}

void rlLexicalScannerGenerator::mk1tbl(int state, int sym, int onenxt, int _onedef) {
  if (firstfree < sym)
    firstfree = sym;

  while (chk[firstfree] != 0) {
    if (++firstfree >= current_max_xpairs)
      expand_nxt_chk();
  }

  base[state] = firstfree - sym;
  def[state] = _onedef;
  chk[firstfree] = state;
  nxt[firstfree] = onenxt;

  if (firstfree > tblend) {
    tblend = firstfree++;

    if (firstfree >= current_max_xpairs)
      expand_nxt_chk();
  }
}

void rlLexicalScannerGenerator::mkprot(int state[], int statenum, int comstate) {
  int i, slot, tblbase;

  if (++numprots >= MSP || numecs * numprots >= PROT_SAVE_SIZE) {
    slot = lastprot;
    lastprot = protprev[lastprot];
    protnext[lastprot] = NIL;
  }

  else
    slot = numprots;

  protnext[slot] = firstprot;

  if (firstprot != NIL)
    protprev[firstprot] = slot;

  firstprot = slot;
  prottbl[slot] = statenum;
  protcomst[slot] = comstate;

  tblbase = numecs * (slot - 1);

  for (i = 1; i <= numecs; ++i)
    protsave[tblbase + i] = state[i];
}

void rlLexicalScannerGenerator::mktemplate(int state[], int statenum, int comstate) {
  int i, numdiff, tmpbase, *tmp = allocate_integer_array(CSIZE + 1);
  Char* transset = allocate_Character_array(CSIZE + 1);
  int tsptr;

  ++numtemps;

  tsptr = 0;

  tmpbase = numtemps * numecs;

  if (tmpbase + numecs >= current_max_template_xpairs) {
    int incl = current_max_template_xpairs / 4;
    if (incl < MAX_TEMPLATE_XPAIRS_INCREMENT)
      incl = MAX_TEMPLATE_XPAIRS_INCREMENT;

    current_max_template_xpairs += incl;
    if (current_max_template_xpairs <= tmpbase + numecs)
      current_max_template_xpairs = tmpbase + numecs + MAX_TEMPLATE_XPAIRS_INCREMENT;

    tnxt = reallocate_integer_array(tnxt, current_max_template_xpairs);
  }

  for (i = 1; i <= numecs; ++i) {
    if (state[i] == 0)
      tnxt[tmpbase + i] = 0;
    else {
      transset[tsptr++] = i;
      tnxt[tmpbase + i] = comstate;
    }
  }

  if (1)
    mkeccl(transset, tsptr, tecfwd, tecbck, numecs, 0);

  mkprot(tnxt + tmpbase, -numtemps, comstate);

  numdiff = tbldiff(state, firstprot, tmp);
  mkentry(tmp, numecs, statenum, -numtemps, numdiff);

  free_array(tmp);
  free_array(transset);
}

void rlLexicalScannerGenerator::mv2front(int qelm) {
  if (firstprot != qelm) {
    if (qelm == lastprot)
      lastprot = protprev[lastprot];

    protnext[protprev[qelm]] = protnext[qelm];

    if (protnext[qelm] != NIL)
      protprev[protnext[qelm]] = protprev[qelm];

    protprev[qelm] = NIL;
    protnext[qelm] = firstprot;
    protprev[firstprot] = qelm;
    firstprot = qelm;
  }
}

void rlLexicalScannerGenerator::place_state(int* state, int statenum, int transnum) {
  int i;
  int* state_ptr;
  int position = find_table_space(state, transnum);

  base[statenum] = position;

  chk[position - 1] = 1;

  chk[position] = 1;

  state_ptr = &state[1];

  for (i = 1; i <= numecs; ++i, ++state_ptr) {
    if (*state_ptr != 0) {
      chk[position + i] = i;
      nxt[position + i] = *state_ptr;
    }

    if (position + numecs > tblend)
      tblend = position + numecs;
  }
}

void rlLexicalScannerGenerator::stack1(int statenum, int sym, int nextstate, int deflink) {
  if (onesp >= ONE_STACK_SIZE - 1)
    mk1tbl(statenum, sym, nextstate, deflink);

  else {
    ++onesp;
    onestate[onesp] = statenum;
    onesym[onesp] = sym;
    onenext[onesp] = nextstate;
    onedef[onesp] = deflink;
  }
}

int rlLexicalScannerGenerator::tbldiff(int state[], int pr, int ext[]) {
  int i, *sp = state, *ep = ext, *protp;
  int numdiff = 0;

  protp = &protsave[numecs * (pr - 1)];

  for (i = numecs; i > 0; --i) {
    if (*++protp == *++sp)
      *++ep = SAME_TRANS;
    else {
      *++ep = *sp;
      ++numdiff;
    }
  }

  return numdiff;
}

void rlLexicalScannerGenerator::sympartition(int ds[], int numstates, int symlist[], int duplist[]) {
  int tch, i, j, k, ns, *dupfwd = allocate_integer_array(CSIZE + 1), lenccl, cclp, ich;

  for (i = 1; i <= numecs; ++i) {
    duplist[i] = i - 1;
    dupfwd[i] = i + 1;
  }

  duplist[1] = NIL;
  dupfwd[numecs] = NIL;

  for (i = 1; i <= numstates; ++i) {
    ns = ds[i];
    tch = transchar[ns];

    if (tch != SYM_EPSILON) {
      if (tch < -lastccl || tch >= CSIZE) {
        X_LEXICAL_FAILED(-EINVAL, (TAG, "bad transition character detected in sympartition()"));
      }

      if (tch >= 0) {
        int ec = ecgroup[tch];

        mkechar(ec, dupfwd, duplist);
        symlist[ec] = 1;
      }

      else {
        tch = -tch;

        lenccl = ccllen[tch];
        cclp = cclmap[tch];
        mkeccl(ccltbl + cclp, lenccl, dupfwd, duplist, numecs, NUL_ec);

        if (cclng[tch]) {
          j = 0;

          for (k = 0; k < lenccl; ++k) {
            ich = ccltbl[cclp + k];

            if (ich == 0)
              ich = NUL_ec;

            for (++j; j < ich; ++j)
              symlist[j] = 1;
          }

          for (++j; j <= numecs; ++j)
            symlist[j] = 1;
        }

        else {
          for (k = 0; k < lenccl; ++k) {
            ich = ccltbl[cclp + k];

            if (ich == 0)
              ich = NUL_ec;

            symlist[ich] = 1;
          }
        }
      }
    }
  }

  free_array(dupfwd);
}

int rlLexicalScannerGenerator::symfollowset(int ds[], int dsize, int transsym, int nset[]) {
  int ns, tsp, sym, i, j, lenccl, ch, numstates, ccllist;

  numstates = 0;

  for (i = 1; i <= dsize; ++i) {
    ns = ds[i];
    sym = transchar[ns];
    tsp = trans1[ns];

    if (sym < 0) {
      sym = -sym;
      ccllist = cclmap[sym];
      lenccl = ccllen[sym];

      if (cclng[sym]) {
        for (j = 0; j < lenccl; ++j) {
          ch = ccltbl[ccllist + j];

          if (ch == 0)
            ch = NUL_ec;

          if (ch > transsym)
            break;

          else if (ch == transsym)
            goto bottom;
        }

        nset[++numstates] = tsp;
      }

      else
        for (j = 0; j < lenccl; ++j) {
          ch = ccltbl[ccllist + j];

          if (ch == 0)
            ch = NUL_ec;

          if (ch > transsym)
            break;
          else if (ch == transsym) {
            nset[++numstates] = tsp;
            break;
          }
        }
    }

    else if (IGNCASE && x_isupper(sym)) {
      X_LEXICAL_FAILED(-EINVAL, (TAG, "consistency check failed in symfollowset"));
    } else if (sym == SYM_EPSILON) {
    }

    else if (std::abs(ecgroup[sym]) == transsym)
      nset[++numstates] = tsp;

  bottom:;
  }

  return numstates;
}

int* rlLexicalScannerGenerator::epsclosure(int* t, int* ns_addr, int accset[], int* nacc_addr, int* hv_addr) {
  int stkpos, ns, tsp;
  int numstates = *ns_addr, nacc, hashval, transsym, nfaccnum;
  int stkend, nstate;

  if (!did_stk_init) {
    stk = allocate_integer_array(current_max_dfa_size);
    did_stk_init = true;
  }

  nacc = stkend = hashval = 0;

  for (nstate = 1; nstate <= numstates; ++nstate) {
    ns = t[nstate];

    if (!IS_MARKED(ns)) {
      PUT_ON_STACK(ns)
      CHECK_ACCEPT(ns)
      hashval += ns;
    }
  }

  for (stkpos = 1; stkpos <= stkend; ++stkpos) {
    ns = stk[stkpos];
    transsym = transchar[ns];

    if (transsym == SYM_EPSILON) {
      tsp = trans1[ns] + MARKER_DIFFERENCE;

      if (tsp != NO_TRANSITION) {
        if (!IS_MARKED(tsp))
          STACK_STATE(tsp)

        tsp = trans2[ns];

        if (tsp != NO_TRANSITION && !IS_MARKED(tsp))
          STACK_STATE(tsp)
      }
    }
  }

  for (stkpos = 1; stkpos <= stkend; ++stkpos) {
    if (IS_MARKED(stk[stkpos])) {
      UNMARK_STATE(stk[stkpos])
    } else {
      X_LEXICAL_FAILED(-EINVAL, (TAG, "consistency check failed in epsclosure()"));
    }
  }

  *ns_addr = numstates;
  *hv_addr = hashval;
  *nacc_addr = nacc;

  return t;
}

int rlLexicalScannerGenerator::snstods(int sns[], int numstates, int accset[], int nacc, int hashval, int* newds_addr) {
  int didsort = 0;
  int i, j;
  int newds, *oldsns;

  for (i = 1; i <= lastdfa; ++i) {
    if (hashval == dhash[i]) {
      if (numstates == dfasiz[i]) {
        oldsns = dss[i];

        if (!didsort) {
          std::sort(sns, sns + numstates);
          didsort = 1;
        }

        for (j = 1; j <= numstates; ++j)
          if (sns[j] != oldsns[j])
            break;

        if (j > numstates) {
          *newds_addr = i;
          return 0;
        }
      }

      else
        ;
    }
  }

  if (++lastdfa >= current_max_dfas)
    increase_max_dfas();

  newds = lastdfa;

  dss[newds] = allocate_integer_array(numstates + 1);

  if (!didsort)
    std::sort(sns, sns + numstates);

  for (i = 1; i <= numstates; ++i)
    dss[newds][i] = sns[i];

  dfasiz[newds] = numstates;
  dhash[newds] = hashval;

  if (nacc == 0) {
    dfaacc[newds] = 0;
    accsiz[newds] = 0;
  }

  else {
    j = num_rules + 1;

    for (i = 1; i <= nacc; ++i)
      if (accset[i] < j)
        j = accset[i];

    dfaacc[newds] = j;

    if (j <= num_rules)
      rule_useful[j] = true;
  }

  *newds_addr = newds;

  return 1;
}

void rlLexicalScannerGenerator::ntod() {
  int *accset, ds, nacc, newds;
  int sym, hashval, numstates, dsize;
  int *nset, *dset;
  int targptr, totaltrans, i, comstate, comfreq, targ;
  int* symlist = allocate_integer_array(CSIZE + 1);
  int num_start_states;
  int todo_head, todo_next;

  int *duplist = allocate_integer_array(CSIZE + 1), *state = allocate_integer_array(CSIZE + 1);
  int *targfreq = allocate_integer_array(CSIZE + 1), *targstate = allocate_integer_array(CSIZE + 1);

  accset = allocate_integer_array(num_rules + 1);
  nset = allocate_integer_array(current_max_dfa_size);

  todo_head = todo_next = 0;

  for (i = 0; i <= CSIZE; ++i) {
    duplist[i] = NIL;
    symlist[i] = false;
  }

  for (i = 0; i <= num_rules; ++i)
    accset[i] = NIL;

  inittbl();

  if (ecgroup[0] == numecs) {
    int use_NUL_table = (numecs == CSIZE);

    if (use_NUL_table)
      nultrans = allocate_integer_array(current_max_dfas);
  }

  num_start_states = SCON_COUNT * 2;

  for (i = 1; i <= num_start_states; ++i) {
    numstates = 1;

    if (i % 2 == 1)
      nset[numstates] = scset[(i / 2) + 1];
    else
      nset[numstates] = mkbranch(scbol[i / 2], scset[i / 2]);

    nset = epsclosure(nset, &numstates, accset, &nacc, &hashval);

    if (snstods(nset, numstates, accset, nacc, hashval, &ds)) {
      numas += nacc;
      ++todo_next;
    }
  }

  {
    if (!snstods(nset, 0, accset, 0, 0, &end_of_buffer_state)) {
      X_LEXICAL_FAILED(-EFAULT, (TAG, "could not create unique end-of-buffer state"));
    }

    ++numas;
    ++num_start_states;
    ++todo_next;
  }

  while (todo_head < todo_next) {
    targptr = 0;
    totaltrans = 0;

    for (i = 1; i <= numecs; ++i)
      state[i] = 0;

    ds = ++todo_head;

    dset = dss[ds];
    dsize = dfasiz[ds];

    sympartition(dset, dsize, symlist, duplist);

    for (sym = 1; sym <= numecs; ++sym) {
      if (symlist[sym]) {
        symlist[sym] = 0;

        if (duplist[sym] == NIL) {
          numstates = symfollowset(dset, dsize, sym, nset);
          nset = epsclosure(nset, &numstates, accset, &nacc, &hashval);

          if (snstods(nset, numstates, accset, nacc, hashval, &newds)) {
            ++todo_next;
            numas += nacc;
          }

          state[sym] = newds;

          targfreq[++targptr] = 1;
          targstate[targptr] = newds;
        }

        else {
          targ = state[duplist[sym]];
          state[sym] = targ;

          i = 0;
          while (targstate[++i] != targ)
            ;

          ++targfreq[i];
        }

        ++totaltrans;
        duplist[sym] = NIL;
      }
    }

    numsnpairs += totaltrans;

    if (nultrans) {
      nultrans[ds] = state[NUL_ec];
      state[NUL_ec] = 0;
    }

    if (ds == end_of_buffer_state)
      stack1(ds, 0, 0, JAMSTATE);

    else {
      comfreq = 0;
      comstate = 0;

      for (i = 1; i <= targptr; ++i)
        if (targfreq[i] > comfreq) {
          comfreq = targfreq[i];
          comstate = targstate[i];
        }

      bldtbl(state, ds, totaltrans, comstate, comfreq);
    }
  }

  {
    cmptmps();

    while (onesp > 0) {
      mk1tbl(onestate[onesp], onesym[onesp], onenext[onesp], onedef[onesp]);
      --onesp;
    }

    mkdeftbl();
  }

  free_array((void*)accset);
  free_array((void*)nset);

  free_array(symlist);
  free_array(duplist);
  free_array(state);
  free_array(targfreq);
  free_array(targstate);
}

void rlLexicalScannerGenerator::gen_table() {
  int i, total_states;
  int end_of_buffer_action = num_rules + 1;
  dfaacc[end_of_buffer_state] = end_of_buffer_action;
  dfaacc[lastdfa + 1] = 0; /* add accepting number for jam state */

  for (i = 1; i < CSIZE; ++i) {
    if (IGNCASE && x_isupper(i))
      ecgroup[i] = ecgroup[x_tolower(i)];
    ecgroup[i] = std::abs(ecgroup[i]);
  }

  for (i = 1; i <= lastdfa; ++i) {
    int d = def[i];

    if (base[i] == JAMSTATE)
      base[i] = jambase;

    if (d == JAMSTATE)
      def[i] = jamstate;

    else if (d < 0) {
      def[i] = lastdfa - d + 1;
    }
  }
  total_states = lastdfa + numtemps;

  for (++i; i <= total_states; ++i)
    def[i] = jamstate;

  for (i = 1; i <= tblend; ++i)
    if (chk[i] == 0 || nxt[i] == 0)
      nxt[i] = jamstate;
}

void rlLexicalScannerGenerator::generate() {
  int def_rule, pat, i;
  if (default_rule > 0)
    return;

  new_rule();
  pat = cclinit();
  cclnegate(pat);
  def_rule = mkstate(-pat);

  default_rule = num_rules;
  finish_rule(def_rule);

  for (i = 1; i <= SCON_COUNT; ++i)
    scset[i] = mkbranch(scset[i], def_rule);

  numecs = cre8ecs(nextecm, ecgroup, CSIZE);
  ecgroup[0] = ecgroup[CSIZE];
  NUL_ec = ecgroup[0];
  if (NUL_ec < 0)
    NUL_ec = -NUL_ec;
  ccl2ecl();

  ntod();
  gen_table();

  for (i = 1; i <= numecs; ++i) {
    if (tecbck[i] < 0)
      tecbck[i] = -tecbck[i];
  }
}

rlLexicalScannerGenerator::LexicalScanner_t rlLexicalScannerGenerator::GetLexicalScanner() {
  LexicalScanner_t scanner;
  assert(0 == rlErrorCode && default_rule > 0);

  scanner.yy_lastdfa = lastdfa;
  scanner.yy_jambase = jambase;
  scanner.yy_default_rule = default_rule;
  scanner.yy_charsize = CSIZE;

  scanner.yy_accept = dfaacc;
  scanner.yy_accept_size = lastdfa + 2;

  scanner.yy_ec = ecgroup;
  scanner.yy_ec_size = CSIZE;

  scanner.yy_meta = tecbck;
  scanner.yy_meta_size = numecs + 1;

  scanner.yy_base = base;
  scanner.yy_base_size = lastdfa + numtemps + 1;

  scanner.yy_def = def;
  scanner.yy_def_size = lastdfa + numtemps + 1;

  scanner.yy_nxt = nxt;
  scanner.yy_nxt_size = tblend + 1;

  scanner.yy_chk = chk;
  scanner.yy_chk_size = tblend + 1;

  scanner.yy_accept[0] = 0;
  scanner.yy_ec[0] = 0;
  scanner.yy_meta[0] = 0;
  scanner.yy_base[0] = 0;
  scanner.yy_def[0] = 0;
  scanner.yy_nxt[0] = 0;
  scanner.yy_chk[0] = 0;

  return scanner;
}


rlLexicalScannerGenerator::LexicalScanner_t* rlLexicalScannerGenerator::LexicalScannerClone(
    const LexicalScanner_t& scanner) {
  size_t size = sizeof(LexicalScanner_t) +
                sizeof(int) * (scanner.yy_accept_size + scanner.yy_ec_size + scanner.yy_meta_size +
                               scanner.yy_base_size + scanner.yy_def_size + scanner.yy_nxt_size + scanner.yy_chk_size);

  void* memory = malloc(size);
  if (!memory)
    return nullptr;

  LexicalScanner_t* copy = (LexicalScanner_t*)memory;
  int* p = (int*)(copy + 1);

  memcpy(copy, &scanner, sizeof(LexicalScanner_t));

#undef YY_COPY
#define YY_COPY(name)                                        \
  do {                                                       \
    const int yy_size = scanner.name##_size;                 \
    copy->name = p;                                          \
    p += yy_size;                                            \
    memcpy(copy->name, scanner.name, sizeof(int) * yy_size); \
  } while (0)

  YY_COPY(yy_accept);
  YY_COPY(yy_ec);
  YY_COPY(yy_meta);
  YY_COPY(yy_base);
  YY_COPY(yy_def);
  YY_COPY(yy_nxt);
  YY_COPY(yy_chk);

  assert((uint8_t*)p == (uint8_t*)memory + size);
  return copy;
}

void rlLexicalScannerGenerator::LexicalScannerDestroy(LexicalScanner_t* scanner) {
  free(scanner);
}

namespace {
#define _XDPDA_OUTPUT_TRACE 1 /* */
#define _XDPDA_IMPLEMENT_TOKENENUMS_DECLARE_
#define XDPDA_GRAMMAR_DECLARE_FILE "Web/Grammar/regexp.jy.INL"

#define XDPDA_IMPLEMENT_NEXTSTATE_FUNCTION_USERCODE const int* const value = nullptr
#define XDPDA_IMPLEMENT_NEXTSTATE_FUNCTION_DECLARE \
  static int rlLexicalRegexpHelper_yyNextState(rlLexicalScannerGenerator::LexicalRegexpHelper_t* const self, int reason)

#include XDPDA_GRAMMAR_DECLARE_FILE
#include "base/grammar/XDPDA_MACHINE_DECLARE.INL"
}  // namespace

int rlLexicalScannerGenerator::LexicalRegexpHelper_t::yyNextState(int reason) {
  if (reason == XDPDA_RESUME_INITIALIZE)
    XDPDA_CONTEXT_INIT_STACK(this, kStackSize, yy_yyssa, yy_yyvsa);
  return rlLexicalRegexpHelper_yyNextState(this, reason);
}

rLANG_DECLARE_END

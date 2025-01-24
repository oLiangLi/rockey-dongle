

/* auto generate */


export const enum Token {
    YYEOF                                    = 0,
    YYerror                                  = 256,
    YYUNDEF                                  = 257,
    TK_NUMBER                                = 258,
    TK_IF                                    = 259,
    TK_ELSE                                  = 260,
    TK_FOR                                   = 261,
    TK_WHILE                                 = 262,
    TK_DO                                    = 263,
    TK_CONST                                 = 264,
    TK_IDEN                                  = 265,
    TK_PUBLIC                                = 266,
    OP_LOGIC_OR                              = 267,
    OP_LOGIC_AND                             = 268,
    OP_EQ                                    = 269,
    OP_NE                                    = 270,
    OP_LE                                    = 271,
    OP_GE                                    = 272,
    OP_SHIFT_LEFT                            = 273,
    OP_SHIFT_RIGHT                           = 274,
    OP_SHIFT_RIGHT_U                         = 275,
    PREC_THEN                                = 276,

$MAX_TOKEN_VALUE = 276

}


export const enum Action {
    AC_PUBLIC_SIZE_0                         = 4,
    AC_PUBLIC_SIZE_X                         = 5,
    AC_CONST_STATEMENT                       = 10,
    AC_DECL_1                                = 11,
    AC_DECL_X                                = 12,
    AC_EMPTY_STMT                            = 20,
    AC_BLOCK_EMPTY                           = 21,
    AC_BLOCK_DECLARE                         = 22,
    AC_EXPRESSION_DECLARE                    = 23,
    AC_IF_STATEMENT                          = 24,
    AC_IF_ELSE_STATEMENT                     = 25,
    AC_WHILE_STATEMENT                       = 26,
    AC_DO_WHILE_STATEMENT                    = 27,
    AC_FOR_STATEMENT                         = 28,
    AC_OPT_EXPR_NULL                         = 29,
    AC_EXPR_LOGIC_OR                         = 32,
    AC_EXPR_LOGIC_AND                        = 33,
    AC_EXPR_BIT_OR                           = 34,
    AC_EXPR_BIT_XOR                          = 35,
    AC_EXPR_BIT_AND                          = 36,
    AC_EXPR_EQ                               = 37,
    AC_EXPR_NE                               = 38,
    AC_EXPR_LE                               = 39,
    AC_EXPR_GE                               = 40,
    AC_EXPR_GT                               = 41,
    AC_EXPR_LT                               = 42,
    AC_EXPR_SHIFT_LEFT                       = 43,
    AC_EXPR_SHIFT_RIGHT                      = 44,
    AC_EXPR_SHIFT_RIGHT_U                    = 45,
    AC_EXPR_ADD                              = 46,
    AC_EXPR_SUB                              = 47,
    AC_EXPR_MUL                              = 48,
    AC_EXPR_DIV                              = 49,
    AC_EXPR_MOD                              = 50,
    AC_EXPR_UNARY_ADD                        = 52,
    AC_EXPR_UNARY_SUB                        = 53,
    AC_EXPR_BIT_NOT                          = 54,
    AC_EXPR_LOGIC_NOT                        = 55,
    AC_PRI_EXPR_0                            = 56,
    AC_PRI_IDEN                              = 57,
    AC_PRI_NUMBER                            = 58,
    AC_CALL_0                                = 60,
    AC_CALL_X                                = 61,
    AC_ARGLIST_1                             = 62,
    AC_ARGLIST_X                             = 63,

}


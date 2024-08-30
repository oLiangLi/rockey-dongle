

/* auto generate */


export const enum Token {
    YYEOF                                    = 0,
    YYerror                                  = 256,
    YYUNDEF                                  = 257,
    TK_CHAR                                  = 258,
    TK_CCL                                   = 259,
    TK_NUMBER                                = 260,
    TK_EXT                                   = 261,

$MAX_TOKEN_VALUE = 261

}


export const enum Action {
    AC_RE_SERIES                             = 2,
    AC_RE2_SERIES                            = 3,
    AC_SERIES_SINGLETON                      = 4,
    AC_SERIES2_SINGLETON                     = 5,
    AC_SINGLETON_RE                          = 6,
    AC_SINGLETON_MKCLOS                      = 7,
    AC_SINGLETON_MKPOSCL                     = 8,
    AC_SINGLETON_MKOPT                       = 9,
    AC_SINGLETON_MKREP1                      = 10,
    AC_SINGLETON_MKREP1X                     = 11,
    AC_SINGLETON_MKREP2EX                    = 12,
    AC_SINGLETON_CHAR                        = 13,
    AC_SINGLETON_CCL                         = 14,
    AC_SINGLETON_EMPTY                       = 15,
    AC_SINGLETON_STRING                      = 16,
    AC_SINGLETON_EXT                         = 17,
    AC_SINGLETON_ANYCHR                      = 18,
    AC_STRING_CHAR                           = 19,
    AC_STRING2_CHAR                          = 20,

}


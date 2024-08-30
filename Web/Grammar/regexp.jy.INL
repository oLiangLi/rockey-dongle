
/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Skeleton implementation for Bison's Yacc-like parsers in C

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2022
   Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

  
/* C XLALR(1) parser skeleton written by liang.li , tables only */

#ifndef _XDPDA_IMPLEMENT_TABLE_STORE
#define _XDPDA_IMPLEMENT_TABLE_STORE(__entry__)		__entry__
#endif /* _XDPDA_IMPLEMENT_TABLE_STORE */

   
/*
 * X1 -- _XDPDA_IMPLEMENT_IDENTIFICATION_DECLARE_ BEGIN ...
 */   
#ifdef _XDPDA_IMPLEMENT_IDENTIFICATION_DECLARE_

/* Identify Bison output, and Bison version.  */
#define YYBISON 30802

/* Bison version string.  */
#define YYBISON_VERSION "3.8.2"

/* Skeleton name.  */
#define YYSKELETON_NAME "Build/tools/script/grammar.yc"


#endif /* _XDPDA_IMPLEMENT_IDENTIFICATION_DECLARE_ */
/*
 * X1 -- _XDPDA_IMPLEMENT_IDENTIFICATION_DECLARE_ END.
 */

/*
 * X1 -- _XDPDA_IMPLEMENT_TOKENENUMS_DECLARE_ BEGIN ...
 */
#ifdef _XDPDA_IMPLEMENT_TOKENENUMS_DECLARE_

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    YYEOF = 0,                     /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    TK_CHAR = 258,                 /* TK_CHAR  */
    TK_CCL = 259,                  /* TK_CCL  */
    TK_NUMBER = 260,               /* TK_NUMBER  */
    TK_EXT = 261                   /* TK_EXT  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif


#endif /*_XDPDA_IMPLEMENT_TOKENENUMS_DECLARE_*/
/* 
 * X1 -- _XDPDA_IMPLEMENT_TOKENENUMS_DECLARE_ END.
 */

/*
 * X2 -- _XDPDA_IMPLEMENT_CONSTANT_DECLARE_ BEGIN ...
 */
 #ifdef _XDPDA_IMPLEMENT_CONSTANT_DECLARE_
 
/* YYFINAL -- State number of the termination state.  */
#define _XDPDACD_YYFINAL  		14
/* YYLAST -- Last index in YYTABLE.  */
#define _XDPDACD_YYLAST   		28

/* YYNTOKENS -- Number of terminals.  */
#define _XDPDACD_YYNTOKENS  	18
/* YYNNTS -- Number of nonterminals.  */
#define _XDPDACD_YYNNTS  		5
/* YYNRULES -- Number of rules.  */
#define _XDPDACD_YYNRULES  		20
/* YYNRULES -- Number of states.  */
#define _XDPDACD_YYNSTATES  	31

#define _XDPDACD_YYUNDEFTOK  	YYUNDEF
#define _XDPDACD_YYMAXUTOK   	261

#define _XDPDACD_YYPACT_NINF 	-12
#define _XDPDACD_YYTABLE_NINF 	-1

#endif /* _XDPDA_IMPLEMENT_CONSTANT_DECLARE_ */
/*
 * X2 -- _XDPDA_IMPLEMENT_CONSTANT_DECLARE_ END.
 */
 
 /*
  * X3 -- _XDPDA_IMPLEMENT_STATE_TYPE_DECLARE_ BEGIN ...
  */
 #ifdef _XDPDA_IMPLEMENT_STATE_TYPE_DECLARE_
 
#define _XDPDAST_yytranslate _XDPDAST_IMPLEMENT_OF( uint8_t )
#define _XDPDAST_yyprhs      _XDPDAST_IMPLEMENT_OF( uint8_t )
#define _XDPDAST_yyrhs       _XDPDAST_IMPLEMENT_OF( int8_t )
#define _XDPDAST_yyrline     _XDPDAST_IMPLEMENT_OF( uint8_t )
#define _XDPDAST_yytoknum    _XDPDAST_IMPLEMENT_OF( uint16_t )
#define _XDPDAST_yyr1        _XDPDAST_IMPLEMENT_OF( uint8_t )
#define _XDPDAST_yyr2        _XDPDAST_IMPLEMENT_OF( uint8_t )
#define _XDPDAST_yydefact    _XDPDAST_IMPLEMENT_OF( uint8_t )
#define _XDPDAST_yydefgoto   _XDPDAST_IMPLEMENT_OF( uint8_t )
#define _XDPDAST_yypact      _XDPDAST_IMPLEMENT_OF( int8_t )
#define _XDPDAST_yypgoto     _XDPDAST_IMPLEMENT_OF( int8_t )
#define _XDPDAST_yytable     _XDPDAST_IMPLEMENT_OF( uint8_t )
#define _XDPDAST_yycheck     _XDPDAST_IMPLEMENT_OF( int8_t )
#define _XDPDAST_yystos      _XDPDAST_IMPLEMENT_OF( uint8_t )

#endif /*_XDPDA_IMPLEMENT_STATE_TYPE_DECLARE_*/
/*
 * X3 -- _XDPDA_IMPLEMENT_STATE_TYPE_DECLARE_ END   ...
 */  
 
/*
 * X4 -- _XDPDA_IMPLEMENT_TNAME_DECLARE_ BEGIN ...
 */
#ifdef _XDPDA_IMPLEMENT_TNAME_DECLARE_
static const char *const 
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yytname )[]) =
{
  "\"end of file\"", "error", "\"invalid token\"", "TK_CHAR", "TK_CCL",
  "TK_NUMBER", "TK_EXT", "'|'", "'('", "')'", "'*'", "'+'", "'?'", "'{'",
  "'}'", "','", "'\"'", "'.'", "$accept", "re", "series", "singleton",
  "string", YY_NULLPTR
};
#endif /* _XDPDA_IMPLEMENT_TNAME_DECLARE_ */
/*
 * X4 -- _XDPDA_IMPLEMENT_TNAME_DECLARE_ END.
 */
 
/*
 * X5 -- _XDPDA_IMPLEMENT_TOKNUM_DECLARE_ BEGIN ...
 */
#ifdef _XDPDA_IMPLEMENT_TOKNUM_DECLARE_
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint16_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yytoknum )[]) =
{
       0,   256,   257,   258,   259,   260,   261,   124,    40,    41,
      42,    43,    63,   123,   125,    44,    34,    46
};
#endif /* _XDPDA_IMPLEMENT_TOKNUM_DECLARE_ */
/*
 * X5 -- _XDPDA_IMPLEMENT_TOKNUM_DECLARE_ END.
 */ 
 
/*
 * X6 -- _XDPDA_IMPLEMENT_DBGTBL_DECLARE_ BEGIN ...
 */
#ifdef _XDPDA_IMPLEMENT_DBGTBL_DECLARE_
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yyprhs )[]) =
{
       0,     0,     3,     5,     9,    11,    14,    18,    21,    24,
      27,    32,    38,    45,    47,    49,    52,    56,    58,    60,
      62
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( int8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yyrhs )[]) =
{
      19,     0,    -1,    20,    -1,    19,     7,    20,    -1,    21,
      -1,    20,    21,    -1,     8,    19,     9,    -1,    21,    10,
      -1,    21,    11,    -1,    21,    12,    -1,    21,    13,     5,
      14,    -1,    21,    13,     5,    15,    14,    -1,    21,    13,
       5,    15,     5,    14,    -1,     3,    -1,     4,    -1,    16,
      16,    -1,    16,    22,    16,    -1,     6,    -1,    17,    -1,
       3,    -1,    22,     3,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yyrline )[]) =
{
       0,     6,     6,     8,    12,    14,    18,    20,    22,    24,
      26,    28,    30,    32,    34,    36,    38,    40,    42,    46,
      48
};
#endif /* _XDPDA_IMPLEMENT_DBGTBL_DECLARE_ */
/*
 * X6 -- _XDPDA_IMPLEMENT_DBGTBL_DECLARE_ END.
 */
  	 
/*
 * X7 -- _XDPDA_IMPLEMENT_TABLE_DECLARE_ BEGIN ...
 */  	 
#ifdef _XDPDA_IMPLEMENT_TABLE_DECLARE_

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yytranslate) []) =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,    16,     2,     2,     2,     2,     2,
       8,     9,    10,    11,    15,     2,    17,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    12,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    13,     7,    14,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6
};	

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yyr1 )[]) =
{
       0,    18,    19,    19,    20,    20,    21,    21,    21,    21,
      21,    21,    21,    21,    21,    21,    21,    21,    21,    22,
      22
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yyr2 )[]) =
{
       0,     2,     1,     3,     1,     2,     3,     2,     2,     2,
       4,     5,     6,     1,     1,     2,     3,     1,     1,     1,
       2
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yydefact )[]) =
{
       0,    13,    14,    17,     0,     0,    18,     0,     2,     4,
       0,    19,    15,     0,     1,     0,     5,     7,     8,     9,
       0,     6,    20,    16,     3,     0,    10,     0,     0,    11,
      12
};

/* YYDEFGOTO[NTERM-NUM].  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yydefgoto )[]) =
{
       0,     7,     8,     9,    13
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */

static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( int8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yypact )[]) =
{
      -2,   -12,   -12,   -12,    -2,     2,   -12,    12,    -2,    11,
      18,   -12,   -12,     4,   -12,    -2,    11,   -12,   -12,   -12,
       6,   -12,   -12,   -12,    -2,    -5,   -12,     3,   -11,   -12,
     -12
};

/* YYPGOTO[NTERM-NUM].  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( int8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yypgoto )[]) =
{
     -12,     9,    13,    -8,   -12
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */

static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yytable )[]) =
{
      16,     1,     2,    30,     3,    11,     4,    22,    28,    26,
      27,    25,    14,    10,     5,     6,    16,    29,    12,    15,
      23,    17,    18,    19,    20,    15,     0,    21,    24
};

static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( int8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yycheck )[]) =
{
       8,     3,     4,    14,     6,     3,     8,     3,     5,    14,
      15,     5,     0,     4,    16,    17,    24,    14,    16,     7,
      16,    10,    11,    12,    13,     7,    -1,     9,    15
};

#if 0
/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yystos )[]) =
{
       0,     3,     4,     6,     8,    16,    17,    19,    20,    21,
      19,     3,    16,    22,     0,     7,    21,    10,    11,    12,
      13,     9,     3,    16,    20,     5,    14,    15,     5,    14,
      14
};
#endif

#endif /* _XDPDA_IMPLEMENT_TABLE_DECLARE_ */
/*
 * X7 -- _XDPDA_IMPLEMENT_TABLE_DECLARE_ END.
 */   

/**
 *!
 */
#undef _XDPDA_IMPLEMENT_TABLE_STORE


    
/*
 *! XZ1 -- _XDPDA_IMPLEMENT_USER_ACTIONLIST_DECLARE_  BEGIN ...
 */
#ifdef _XDPDA_IMPLEMENT_USER_ACTIONLIST_DECLARE_  
enum {
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
};

#endif /* _XDPDA_IMPLEMENT_USER_ACTIONLIST_DECLARE_ */
/*
 *!  XZ1 -- _XDPDA_IMPLEMENT_USER_ACTIONLIST_DECLARE_  END.
 */ 


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
    TK_NUMBER = 258,               /* TK_NUMBER  */
    TK_IF = 259,                   /* TK_IF  */
    TK_ELSE = 260,                 /* TK_ELSE  */
    TK_FOR = 261,                  /* TK_FOR  */
    TK_WHILE = 262,                /* TK_WHILE  */
    TK_DO = 263,                   /* TK_DO  */
    TK_CONST = 264,                /* TK_CONST  */
    TK_IDEN = 265,                 /* TK_IDEN  */
    TK_PUBLIC = 266,               /* TK_PUBLIC  */
    OP_LOGIC_OR = 267,             /* OP_LOGIC_OR  */
    OP_LOGIC_AND = 268,            /* OP_LOGIC_AND  */
    OP_EQ = 269,                   /* OP_EQ  */
    OP_NE = 270,                   /* OP_NE  */
    OP_LE = 271,                   /* OP_LE  */
    OP_GE = 272,                   /* OP_GE  */
    OP_SHIFT_LEFT = 273,           /* OP_SHIFT_LEFT  */
    OP_SHIFT_RIGHT = 274,          /* OP_SHIFT_RIGHT  */
    OP_SHIFT_RIGHT_U = 275,        /* OP_SHIFT_RIGHT_U  */
    PREC_THEN = 276                /* PREC_THEN  */
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
#define _XDPDACD_YYFINAL  		5
/* YYLAST -- Last index in YYTABLE.  */
#define _XDPDACD_YYLAST   		563

/* YYNTOKENS -- Number of terminals.  */
#define _XDPDACD_YYNTOKENS  	45
/* YYNNTS -- Number of nonterminals.  */
#define _XDPDACD_YYNNTS  		29
/* YYNRULES -- Number of rules.  */
#define _XDPDACD_YYNRULES  		77
/* YYNRULES -- Number of states.  */
#define _XDPDACD_YYNSTATES  	157

#define _XDPDACD_YYUNDEFTOK  	YYUNDEF
#define _XDPDACD_YYMAXUTOK   	276

#define _XDPDACD_YYPACT_NINF 	-109
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
#define _XDPDAST_yyprhs      _XDPDAST_IMPLEMENT_OF( uint16_t )
#define _XDPDAST_yyrhs       _XDPDAST_IMPLEMENT_OF( int8_t )
#define _XDPDAST_yyrline     _XDPDAST_IMPLEMENT_OF( uint8_t )
#define _XDPDAST_yytoknum    _XDPDAST_IMPLEMENT_OF( uint16_t )
#define _XDPDAST_yyr1        _XDPDAST_IMPLEMENT_OF( uint8_t )
#define _XDPDAST_yyr2        _XDPDAST_IMPLEMENT_OF( uint8_t )
#define _XDPDAST_yydefact    _XDPDAST_IMPLEMENT_OF( uint8_t )
#define _XDPDAST_yydefgoto   _XDPDAST_IMPLEMENT_OF( uint8_t )
#define _XDPDAST_yypact      _XDPDAST_IMPLEMENT_OF( int16_t )
#define _XDPDAST_yypgoto     _XDPDAST_IMPLEMENT_OF( int8_t )
#define _XDPDAST_yytable     _XDPDAST_IMPLEMENT_OF( uint8_t )
#define _XDPDAST_yycheck     _XDPDAST_IMPLEMENT_OF( int16_t )
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
  "\"end of file\"", "error", "\"invalid token\"", "TK_NUMBER", "TK_IF",
  "TK_ELSE", "TK_FOR", "TK_WHILE", "TK_DO", "TK_CONST", "TK_IDEN",
  "TK_PUBLIC", "OP_LOGIC_OR", "OP_LOGIC_AND", "OP_EQ", "OP_NE", "OP_LE",
  "OP_GE", "OP_SHIFT_LEFT", "OP_SHIFT_RIGHT", "OP_SHIFT_RIGHT_U", "'|'",
  "'^'", "'&'", "'<'", "'>'", "'+'", "'-'", "'*'", "'/'", "'%'",
  "PREC_THEN", "';'", "'{'", "'}'", "'='", "'('", "')'", "'~'", "'!'",
  "','", "'@'", "'['", "']'", "'$'", "$accept", "goal", "public_size",
  "const_declares", "const_statement_declare_list", "const_statement",
  "declares", "statement", "empty_statement", "block_statement",
  "expr_statement", "if_statement", "while_statement",
  "do_while_statement", "for_statement", "opt_expr", "expr",
  "unary_expression", "primary_expression", "callfunc", "arglist",
  "input_statement", "input_decl_end", "input_decl_begin",
  "input_decl_offset", "input_decl_size", "input_decl_options",
  "input_decl_list", "input_decl", YY_NULLPTR
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
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   124,    94,    38,    60,    62,    43,    45,    42,    47,
      37,   276,    59,   123,   125,    61,    40,    41,   126,    33,
      44,    64,    91,    93,    36
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
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint16_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yyprhs )[]) =
{
       0,     0,     3,     7,    10,    11,    15,    19,    24,    26,
      29,    34,    36,    39,    41,    43,    45,    47,    49,    51,
      53,    55,    57,    60,    64,    67,    73,    81,    87,    95,
     105,   106,   108,   110,   114,   118,   122,   126,   130,   134,
     138,   142,   146,   150,   154,   158,   162,   166,   170,   174,
     178,   182,   186,   188,   191,   194,   197,   200,   204,   206,
     208,   210,   214,   219,   221,   225,   232,   237,   239,   242,
     244,   248,   254,   257,   261,   263,   267,   269
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( int8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yyrhs )[]) =
{
      46,     0,    -1,    47,    48,    51,    -1,    47,    51,    -1,
      -1,    11,     3,    32,    -1,     9,    33,    34,    -1,     9,
      33,    49,    34,    -1,    50,    -1,    49,    50,    -1,    10,
      35,    61,    32,    -1,    52,    -1,    51,    52,    -1,    53,
      -1,    55,    -1,    56,    -1,    57,    -1,    58,    -1,    59,
      -1,    54,    -1,    66,    -1,    32,    -1,    33,    34,    -1,
      33,    51,    34,    -1,    61,    32,    -1,     4,    36,    61,
      37,    52,    -1,     4,    36,    61,    37,    52,     5,    52,
      -1,     7,    36,    61,    37,    52,    -1,     8,    52,     7,
      36,    61,    37,    32,    -1,     6,    36,    60,    32,    60,
      32,    60,    37,    52,    -1,    -1,    61,    -1,    62,    -1,
      61,    12,    61,    -1,    61,    13,    61,    -1,    61,    21,
      61,    -1,    61,    22,    61,    -1,    61,    23,    61,    -1,
      61,    14,    61,    -1,    61,    15,    61,    -1,    61,    16,
      61,    -1,    61,    17,    61,    -1,    61,    25,    61,    -1,
      61,    24,    61,    -1,    61,    18,    61,    -1,    61,    19,
      61,    -1,    61,    20,    61,    -1,    61,    26,    61,    -1,
      61,    27,    61,    -1,    61,    28,    61,    -1,    61,    29,
      61,    -1,    61,    30,    61,    -1,    63,    -1,    26,    62,
      -1,    27,    62,    -1,    38,    62,    -1,    39,    62,    -1,
      36,    61,    37,    -1,    10,    -1,     3,    -1,    64,    -1,
      10,    36,    37,    -1,    10,    36,    65,    37,    -1,    61,
      -1,    65,    40,    61,    -1,    68,    69,    70,    35,    71,
      67,    -1,    68,    69,    70,    67,    -1,    32,    -1,    10,
      41,    -1,    61,    -1,    42,    61,    43,    -1,    42,    61,
      40,    61,    43,    -1,    33,    34,    -1,    33,    72,    34,
      -1,    73,    -1,    72,    40,    73,    -1,    61,    -1,    44,
      33,    10,    34,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yyrline )[]) =
{
       0,    38,    38,    40,    44,    46,    50,    52,    56,    58,
      62,    66,    68,    72,    74,    76,    78,    80,    82,    84,
      86,    90,    94,    96,   100,   104,   106,   110,   114,   118,
     122,   124,   128,   130,   132,   134,   136,   138,   140,   142,
     144,   146,   148,   150,   152,   154,   156,   158,   160,   162,
     164,   166,   170,   172,   174,   176,   178,   182,   184,   186,
     188,   192,   194,   198,   200,   204,   206,   210,   214,   218,
     222,   224,   228,   230,   234,   236,   240,   242
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
       2,     2,     2,    39,     2,     2,    44,    30,    23,     2,
      36,    37,    28,    26,    40,    27,     2,    29,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,    32,
      24,    35,    25,     2,    41,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    42,     2,    43,    22,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    33,    21,    34,    38,     2,     2,     2,
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
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    31
};	

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yyr1 )[]) =
{
       0,    45,    46,    46,    47,    47,    48,    48,    49,    49,
      50,    51,    51,    52,    52,    52,    52,    52,    52,    52,
      52,    53,    54,    54,    55,    56,    56,    57,    58,    59,
      60,    60,    61,    61,    61,    61,    61,    61,    61,    61,
      61,    61,    61,    61,    61,    61,    61,    61,    61,    61,
      61,    61,    62,    62,    62,    62,    62,    63,    63,    63,
      63,    64,    64,    65,    65,    66,    66,    67,    68,    69,
      70,    70,    71,    71,    72,    72,    73,    73
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yyr2 )[]) =
{
       0,     2,     3,     2,     0,     3,     3,     4,     1,     2,
       4,     1,     2,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     2,     3,     2,     5,     7,     5,     7,     9,
       0,     1,     1,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     1,     2,     2,     2,     2,     3,     1,     1,
       1,     3,     4,     1,     3,     6,     4,     1,     2,     1,
       3,     5,     2,     3,     1,     3,     1,     4
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yydefact )[]) =
{
       4,     0,     0,     0,     0,     1,    59,     0,     0,     0,
       0,     0,    58,     0,     0,    21,     0,     0,     0,     0,
       0,     3,    11,    13,    19,    14,    15,    16,    17,    18,
       0,    32,    52,    60,    20,     0,     5,     0,    30,     0,
       0,     0,     0,    68,    58,    53,    54,    22,     0,     0,
      55,    56,     2,    12,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    24,    69,     0,     0,     0,    31,     0,
       0,     0,     6,     0,     8,    61,    63,     0,    23,    57,
      33,    34,    38,    39,    40,    41,    44,    45,    46,    35,
      36,    37,    43,    42,    47,    48,    49,    50,    51,     0,
       0,     0,    30,     0,     0,     0,     7,     9,    62,     0,
       0,    67,     0,    66,    25,     0,    27,     0,     0,    64,
       0,    70,     0,     0,     0,    30,     0,    10,     0,    72,
       0,    76,     0,    74,    65,    26,     0,    28,    71,     0,
      73,     0,     0,     0,    75,    29,    77
};

/* YYDEFGOTO[NTERM-NUM].  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yydefgoto )[]) =
{
       0,     2,     3,    20,    83,    84,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    77,    30,    31,    32,    33,
      87,    34,   123,    35,    75,   110,   133,   142,   143
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */

static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( int16_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yypact )[]) =
{
      -4,    12,     6,   149,   -11,  -109,  -109,   -14,   -13,    -3,
     208,    13,   -22,    -2,    -2,  -109,   157,    -2,    -2,    -2,
     208,   208,  -109,  -109,  -109,  -109,  -109,  -109,  -109,  -109,
     390,  -109,  -109,  -109,  -109,    -2,  -109,    -2,    -2,    -2,
      32,    -8,   226,  -109,    49,  -109,  -109,  -109,   194,   286,
    -109,  -109,   208,  -109,    -2,    -2,    -2,    -2,    -2,    -2,
      -2,    -2,    -2,    -2,    -2,    -2,    -2,    -2,    -2,    -2,
      -2,    -2,    -2,  -109,   432,    50,   312,    63,   432,   338,
      60,    10,  -109,    -5,  -109,  -109,   432,     3,  -109,  -109,
     450,   467,   533,   533,   230,   230,    61,    61,    61,   484,
     501,   518,   230,   230,    70,    70,  -109,  -109,  -109,    -2,
       9,   208,    -2,   208,    -2,    -2,  -109,  -109,  -109,    -2,
      54,  -109,    71,  -109,   101,    79,  -109,   364,   411,   432,
      -2,  -109,    83,    82,   208,    -2,    84,  -109,   254,  -109,
      85,   432,   -31,  -109,  -109,  -109,    78,  -109,  -109,   116,
    -109,   110,   208,    95,  -109,  -109,  -109
};

/* YYPGOTO[NTERM-NUM].  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( int8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yypgoto )[]) =
{
    -109,  -109,  -109,  -109,  -109,    47,     0,   -10,  -109,  -109,
    -109,  -109,  -109,  -109,  -109,  -108,    -7,    -1,  -109,  -109,
    -109,  -109,     1,  -109,  -109,  -109,  -109,  -109,   -20
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */

static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yytable )[]) =
{
      40,     6,    81,   150,   125,    81,     5,     1,    44,   151,
      49,    53,    45,    46,    42,     4,    48,    50,    51,    43,
      52,    36,    37,    38,    13,    14,    82,   146,    74,   116,
      76,    78,    79,    39,    17,    86,    18,    19,    53,    80,
     118,   121,    53,   119,   122,   115,    41,    90,    91,    92,
      93,    94,    95,    96,    97,    98,    99,   100,   101,   102,
     103,   104,   105,   106,   107,   108,    54,    55,    56,    57,
      58,    59,    60,    61,    62,    63,    64,    65,    66,    67,
      68,    69,    70,    71,    72,    42,     6,    68,    69,    70,
      71,    72,   109,    44,   130,   112,   114,   131,    70,    71,
      72,   124,   120,   126,   132,    78,   134,   127,   128,    13,
      14,   135,   129,     6,   121,   152,   147,   139,   149,    17,
      44,    18,    19,   138,   145,   141,   153,   140,    78,   156,
     117,   154,     0,     0,   144,     0,    13,    14,     0,     0,
       0,     0,   155,     0,   141,     0,    17,     0,    18,    19,
       0,     0,     6,     7,   140,     8,     9,    10,    11,    12,
       6,     7,     0,     8,     9,    10,     0,    12,     0,     0,
       0,     0,     0,     0,     0,    13,    14,     0,     0,     0,
       0,    15,    16,    13,    14,    17,     0,    18,    19,    15,
      16,    47,     0,    17,     0,    18,    19,     6,     7,     0,
       8,     9,    10,     0,    12,     0,     0,     0,     0,     0,
       0,     6,     7,     0,     8,     9,    10,     0,    12,     0,
      13,    14,     0,     0,     0,     0,    15,    16,    88,     6,
      17,     0,    18,    19,    13,    14,    44,     0,     0,     0,
      15,    16,     0,     0,    17,     0,    18,    19,    60,    61,
      62,     0,    13,    14,     0,     0,    68,    69,    70,    71,
      72,     0,    17,    85,    18,    19,    54,    55,    56,    57,
      58,    59,    60,    61,    62,    63,    64,    65,    66,    67,
      68,    69,    70,    71,    72,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   148,    54,    55,
      56,    57,    58,    59,    60,    61,    62,    63,    64,    65,
      66,    67,    68,    69,    70,    71,    72,     0,     0,     0,
       0,     0,     0,    89,    54,    55,    56,    57,    58,    59,
      60,    61,    62,    63,    64,    65,    66,    67,    68,    69,
      70,    71,    72,     0,     0,     0,     0,     0,     0,   111,
      54,    55,    56,    57,    58,    59,    60,    61,    62,    63,
      64,    65,    66,    67,    68,    69,    70,    71,    72,     0,
       0,     0,     0,     0,     0,   113,    54,    55,    56,    57,
      58,    59,    60,    61,    62,    63,    64,    65,    66,    67,
      68,    69,    70,    71,    72,     0,     0,     0,     0,     0,
       0,   136,    54,    55,    56,    57,    58,    59,    60,    61,
      62,    63,    64,    65,    66,    67,    68,    69,    70,    71,
      72,     0,    73,    54,    55,    56,    57,    58,    59,    60,
      61,    62,    63,    64,    65,    66,    67,    68,    69,    70,
      71,    72,     0,   137,    54,    55,    56,    57,    58,    59,
      60,    61,    62,    63,    64,    65,    66,    67,    68,    69,
      70,    71,    72,    55,    56,    57,    58,    59,    60,    61,
      62,    63,    64,    65,    66,    67,    68,    69,    70,    71,
      72,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    56,    57,
      58,    59,    60,    61,    62,     0,    64,    65,    66,    67,
      68,    69,    70,    71,    72,    56,    57,    58,    59,    60,
      61,    62,     0,     0,    65,    66,    67,    68,    69,    70,
      71,    72,    56,    57,    58,    59,    60,    61,    62,     0,
       0,     0,    66,    67,    68,    69,    70,    71,    72,    58,
      59,    60,    61,    62,     0,     0,     0,    66,    67,    68,
      69,    70,    71,    72
};

static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( int16_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yycheck )[]) =
{
      10,     3,    10,    34,   112,    10,     0,    11,    10,    40,
      17,    21,    13,    14,    36,     3,    16,    18,    19,    41,
      20,    32,    36,    36,    26,    27,    34,   135,    35,    34,
      37,    38,    39,    36,    36,    42,    38,    39,    48,     7,
      37,    32,    52,    40,    35,    35,    33,    54,    55,    56,
      57,    58,    59,    60,    61,    62,    63,    64,    65,    66,
      67,    68,    69,    70,    71,    72,    12,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    36,     3,    26,    27,    28,
      29,    30,    42,    10,    40,    32,    36,    43,    28,    29,
      30,   111,   109,   113,    33,   112,     5,   114,   115,    26,
      27,    32,   119,     3,    32,    37,    32,    34,    33,    36,
      10,    38,    39,   130,   134,   132,    10,    44,   135,    34,
      83,   151,    -1,    -1,   133,    -1,    26,    27,    -1,    -1,
      -1,    -1,   152,    -1,   151,    -1,    36,    -1,    38,    39,
      -1,    -1,     3,     4,    44,     6,     7,     8,     9,    10,
       3,     4,    -1,     6,     7,     8,    -1,    10,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    26,    27,    -1,    -1,    -1,
      -1,    32,    33,    26,    27,    36,    -1,    38,    39,    32,
      33,    34,    -1,    36,    -1,    38,    39,     3,     4,    -1,
       6,     7,     8,    -1,    10,    -1,    -1,    -1,    -1,    -1,
      -1,     3,     4,    -1,     6,     7,     8,    -1,    10,    -1,
      26,    27,    -1,    -1,    -1,    -1,    32,    33,    34,     3,
      36,    -1,    38,    39,    26,    27,    10,    -1,    -1,    -1,
      32,    33,    -1,    -1,    36,    -1,    38,    39,    18,    19,
      20,    -1,    26,    27,    -1,    -1,    26,    27,    28,    29,
      30,    -1,    36,    37,    38,    39,    12,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    43,    12,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    -1,    -1,    -1,
      -1,    -1,    -1,    37,    12,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    -1,    -1,    -1,    -1,    -1,    -1,    37,
      12,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    -1,
      -1,    -1,    -1,    -1,    -1,    37,    12,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    -1,    -1,    -1,    -1,    -1,
      -1,    37,    12,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    -1,    32,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    -1,    32,    12,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    14,    15,
      16,    17,    18,    19,    20,    -1,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    14,    15,    16,    17,    18,
      19,    20,    -1,    -1,    23,    24,    25,    26,    27,    28,
      29,    30,    14,    15,    16,    17,    18,    19,    20,    -1,
      -1,    -1,    24,    25,    26,    27,    28,    29,    30,    16,
      17,    18,    19,    20,    -1,    -1,    -1,    24,    25,    26,
      27,    28,    29,    30
};

#if 0
/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yystos )[]) =
{
       0,    11,    46,    47,     3,     0,     3,     4,     6,     7,
       8,     9,    10,    26,    27,    32,    33,    36,    38,    39,
      48,    51,    52,    53,    54,    55,    56,    57,    58,    59,
      61,    62,    63,    64,    66,    68,    32,    36,    36,    36,
      52,    33,    36,    41,    10,    62,    62,    34,    51,    61,
      62,    62,    51,    52,    12,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    32,    61,    69,    61,    60,    61,    61,
       7,    10,    34,    49,    50,    37,    61,    65,    34,    37,
      61,    61,    61,    61,    61,    61,    61,    61,    61,    61,
      61,    61,    61,    61,    61,    61,    61,    61,    61,    42,
      70,    37,    32,    37,    36,    35,    34,    50,    37,    40,
      61,    32,    35,    67,    52,    60,    52,    61,    61,    61,
      40,    43,    33,    71,     5,    32,    37,    32,    61,    34,
      44,    61,    72,    73,    67,    52,    60,    32,    43,    33,
      34,    40,    37,    10,    73,    52,    34
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
    AC_GOAL_1                                = 2,
    AC_GOAL_2                                = 3,
    AC_PUBLIC_SIZE_0                         = 4,
    AC_PUBLIC_SIZE_X                         = 5,
    AC_CONST_STATEMENT                       = 10,
    AC_DECL_1                                = 11,
    AC_DECL_X                                = 12,
    AC_EMPTY_STMT                            = 21,
    AC_BLOCK_EMPTY                           = 22,
    AC_BLOCK_DECLARE                         = 23,
    AC_EXPRESSION_DECLARE                    = 24,
    AC_IF_STATEMENT                          = 25,
    AC_IF_ELSE_STATEMENT                     = 26,
    AC_WHILE_STATEMENT                       = 27,
    AC_DO_WHILE_STATEMENT                    = 28,
    AC_FOR_STATEMENT                         = 29,
    AC_OPT_EXPR_NULL                         = 30,
    AC_EXPR_LOGIC_OR                         = 33,
    AC_EXPR_LOGIC_AND                        = 34,
    AC_EXPR_BIT_OR                           = 35,
    AC_EXPR_BIT_XOR                          = 36,
    AC_EXPR_BIT_AND                          = 37,
    AC_EXPR_EQ                               = 38,
    AC_EXPR_NE                               = 39,
    AC_EXPR_LE                               = 40,
    AC_EXPR_GE                               = 41,
    AC_EXPR_GT                               = 42,
    AC_EXPR_LT                               = 43,
    AC_EXPR_SHIFT_LEFT                       = 44,
    AC_EXPR_SHIFT_RIGHT                      = 45,
    AC_EXPR_SHIFT_RIGHT_U                    = 46,
    AC_EXPR_ADD                              = 47,
    AC_EXPR_SUB                              = 48,
    AC_EXPR_MUL                              = 49,
    AC_EXPR_DIV                              = 50,
    AC_EXPR_MOD                              = 51,
    AC_EXPR_UNARY_ADD                        = 53,
    AC_EXPR_UNARY_SUB                        = 54,
    AC_EXPR_BIT_NOT                          = 55,
    AC_EXPR_LOGIC_NOT                        = 56,
    AC_PRI_EXPR_0                            = 57,
    AC_PRI_IDEN                              = 58,
    AC_PRI_NUMBER                            = 59,
    AC_CALL_0                                = 61,
    AC_CALL_X                                = 62,
    AC_ARGLIST_1                             = 63,
    AC_ARGLIST_X                             = 64,
    AC_INPUT_END                             = 67,
    AC_INPUT_BEGIN                           = 68,
    AC_INPUT_OFFSET                          = 69,
    AC_INPUT_SIZE_1                          = 70,
    AC_INPUT_SIZE_2                          = 71,
    AC_INPUT_EXPR                            = 76,
    AC_INPUT_EXTERN                          = 77,
};

#endif /* _XDPDA_IMPLEMENT_USER_ACTIONLIST_DECLARE_ */
/*
 *!  XZ1 -- _XDPDA_IMPLEMENT_USER_ACTIONLIST_DECLARE_  END.
 */ 

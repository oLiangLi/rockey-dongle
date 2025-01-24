
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
#define _XDPDACD_YYLAST   		468

/* YYNTOKENS -- Number of terminals.  */
#define _XDPDACD_YYNTOKENS  	41
/* YYNNTS -- Number of nonterminals.  */
#define _XDPDACD_YYNNTS  		21
/* YYNRULES -- Number of rules.  */
#define _XDPDACD_YYNRULES  		63
/* YYNRULES -- Number of states.  */
#define _XDPDACD_YYNSTATES  	127

#define _XDPDACD_YYUNDEFTOK  	YYUNDEF
#define _XDPDACD_YYMAXUTOK   	276

#define _XDPDACD_YYPACT_NINF 	-103
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
#define _XDPDAST_yypact      _XDPDAST_IMPLEMENT_OF( int16_t )
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
  "\"end of file\"", "error", "\"invalid token\"", "TK_NUMBER", "TK_IF",
  "TK_ELSE", "TK_FOR", "TK_WHILE", "TK_DO", "TK_CONST", "TK_IDEN",
  "TK_PUBLIC", "OP_LOGIC_OR", "OP_LOGIC_AND", "OP_EQ", "OP_NE", "OP_LE",
  "OP_GE", "OP_SHIFT_LEFT", "OP_SHIFT_RIGHT", "OP_SHIFT_RIGHT_U", "'|'",
  "'^'", "'&'", "'<'", "'>'", "'+'", "'-'", "'*'", "'/'", "'%'",
  "PREC_THEN", "';'", "'{'", "'}'", "'='", "'('", "')'", "'~'", "'!'",
  "','", "$accept", "goal", "public_size", "const_declares",
  "const_statement_declare_list", "const_statement", "declares",
  "statement", "empty_statement", "block_statement", "expr_statement",
  "if_statement", "while_statement", "do_while_statement", "for_statement",
  "opt_expr", "expr", "unary_expression", "primary_expression", "callfunc",
  "arglist", YY_NULLPTR
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
      44
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
       0,     0,     3,     7,    10,    11,    15,    19,    24,    26,
      29,    34,    36,    39,    41,    43,    45,    47,    49,    51,
      53,    55,    58,    62,    65,    71,    79,    85,    93,   103,
     104,   106,   108,   112,   116,   120,   124,   128,   132,   136,
     140,   144,   148,   152,   156,   160,   164,   168,   172,   176,
     180,   184,   186,   189,   192,   195,   198,   202,   204,   206,
     208,   212,   217,   219
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( int8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yyrhs )[]) =
{
      42,     0,    -1,    43,    44,    47,    -1,    43,    47,    -1,
      -1,    11,     3,    32,    -1,     9,    33,    34,    -1,     9,
      33,    45,    34,    -1,    46,    -1,    45,    46,    -1,    10,
      35,    57,    32,    -1,    48,    -1,    47,    48,    -1,    49,
      -1,    51,    -1,    52,    -1,    53,    -1,    54,    -1,    55,
      -1,    50,    -1,    32,    -1,    33,    34,    -1,    33,    47,
      34,    -1,    57,    32,    -1,     4,    36,    57,    37,    48,
      -1,     4,    36,    57,    37,    48,     5,    48,    -1,     7,
      36,    57,    37,    48,    -1,     8,    48,     7,    36,    57,
      37,    32,    -1,     6,    36,    56,    32,    56,    32,    56,
      37,    48,    -1,    -1,    57,    -1,    58,    -1,    57,    12,
      57,    -1,    57,    13,    57,    -1,    57,    21,    57,    -1,
      57,    22,    57,    -1,    57,    23,    57,    -1,    57,    14,
      57,    -1,    57,    15,    57,    -1,    57,    16,    57,    -1,
      57,    17,    57,    -1,    57,    25,    57,    -1,    57,    24,
      57,    -1,    57,    18,    57,    -1,    57,    19,    57,    -1,
      57,    20,    57,    -1,    57,    26,    57,    -1,    57,    27,
      57,    -1,    57,    28,    57,    -1,    57,    29,    57,    -1,
      57,    30,    57,    -1,    59,    -1,    26,    58,    -1,    27,
      58,    -1,    38,    58,    -1,    39,    58,    -1,    36,    57,
      37,    -1,    10,    -1,     3,    -1,    60,    -1,    10,    36,
      37,    -1,    10,    36,    61,    37,    -1,    57,    -1,    61,
      40,    57,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yyrline )[]) =
{
       0,    38,    38,    40,    44,    46,    50,    52,    56,    58,
      62,    66,    68,    72,    74,    76,    78,    80,    82,    84,
      88,    92,    94,    98,   102,   104,   108,   112,   116,   120,
     122,   126,   128,   130,   132,   134,   136,   138,   140,   142,
     144,   146,   148,   150,   152,   154,   156,   158,   160,   162,
     164,   168,   170,   172,   174,   176,   180,   182,   184,   186,
     190,   192,   196,   198
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
       2,     2,     2,    39,     2,     2,     2,    30,    23,     2,
      36,    37,    28,    26,    40,    27,     2,    29,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,    32,
      24,    35,    25,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,    22,     2,     2,     2,     2,     2,
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
       0,    41,    42,    42,    43,    43,    44,    44,    45,    45,
      46,    47,    47,    48,    48,    48,    48,    48,    48,    48,
      49,    50,    50,    51,    52,    52,    53,    54,    55,    56,
      56,    57,    57,    57,    57,    57,    57,    57,    57,    57,
      57,    57,    57,    57,    57,    57,    57,    57,    57,    57,
      57,    58,    58,    58,    58,    58,    59,    59,    59,    59,
      60,    60,    61,    61
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yyr2 )[]) =
{
       0,     2,     3,     2,     0,     3,     3,     4,     1,     2,
       4,     1,     2,     1,     1,     1,     1,     1,     1,     1,
       1,     2,     3,     2,     5,     7,     5,     7,     9,     0,
       1,     1,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     1,     2,     2,     2,     2,     3,     1,     1,     1,
       3,     4,     1,     3
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yydefact )[]) =
{
       4,     0,     0,     0,     0,     1,    58,     0,     0,     0,
       0,     0,    57,     0,     0,    20,     0,     0,     0,     0,
       0,     3,    11,    13,    19,    14,    15,    16,    17,    18,
       0,    31,    51,    59,     5,     0,    29,     0,     0,     0,
       0,    52,    53,    21,     0,     0,    54,    55,     2,    12,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    23,
       0,     0,    30,     0,     0,     0,     6,     0,     8,    60,
      62,     0,    22,    56,    32,    33,    37,    38,    39,    40,
      43,    44,    45,    34,    35,    36,    42,    41,    46,    47,
      48,    49,    50,     0,    29,     0,     0,     0,     7,     9,
      61,     0,    24,     0,    26,     0,     0,    63,     0,    29,
       0,    10,    25,     0,    27,     0,    28
};

/* YYDEFGOTO[NTERM-NUM].  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yydefgoto )[]) =
{
       0,     2,     3,    20,    77,    78,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    71,    30,    31,    32,    33,
      81
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */

static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( int16_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yypact )[]) =
{
      -7,     7,    15,    74,   -16,  -103,  -103,   -18,   -17,    -5,
     164,     0,     1,   178,   178,  -103,   113,   178,   178,   178,
     164,   164,  -103,  -103,  -103,  -103,  -103,  -103,  -103,  -103,
     310,  -103,  -103,  -103,  -103,   178,   178,   178,    19,    -9,
     172,  -103,  -103,  -103,   127,   206,  -103,  -103,   164,  -103,
     178,   178,   178,   178,   178,   178,   178,   178,   178,   178,
     178,   178,   178,   178,   178,   178,   178,   178,   178,  -103,
     232,    44,   352,   258,     3,    55,  -103,    -4,  -103,  -103,
     352,   -32,  -103,  -103,   370,   387,    45,    45,    -6,    -6,
      59,    59,    59,   404,   421,   438,    -6,    -6,    38,    38,
    -103,  -103,  -103,   164,   178,   164,   178,   178,  -103,  -103,
    -103,   178,    86,    47,  -103,   284,   331,   352,   164,   178,
      60,  -103,  -103,    57,  -103,   164,  -103
};

/* YYPGOTO[NTERM-NUM].  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( int8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yypgoto )[]) =
{
    -103,  -103,  -103,  -103,  -103,    20,   -13,   -10,  -103,  -103,
    -103,  -103,  -103,  -103,  -103,  -102,    -8,    22,  -103,  -103,
    -103
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */

static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yytable )[]) =
{
      38,    75,   113,    44,     1,   110,    75,    48,   111,    45,
       4,    49,    56,    57,    58,     5,    34,   123,    35,    36,
      64,    65,    66,    67,    68,    76,    74,    70,    72,    73,
     108,    37,    80,    39,    49,    41,    42,    40,    49,   106,
      46,    47,    84,    85,    86,    87,    88,    89,    90,    91,
      92,    93,    94,    95,    96,    97,    98,    99,   100,   101,
     102,    54,    55,    56,    57,    58,    66,    67,    68,    62,
      63,    64,    65,    66,    67,    68,   104,     6,     7,   119,
       8,     9,    10,    11,    12,    64,    65,    66,    67,    68,
     107,   118,   124,   112,   125,   114,    72,   109,   115,   116,
      13,    14,     0,   117,     0,     0,    15,    16,   122,     0,
      17,    72,    18,    19,     0,   126,     6,     7,     0,     8,
       9,    10,     0,    12,     0,     0,     0,     0,     0,     0,
       6,     7,     0,     8,     9,    10,     0,    12,     0,    13,
      14,     0,     0,     0,     0,    15,    16,    43,     0,    17,
       0,    18,    19,    13,    14,     0,     0,     0,     0,    15,
      16,    82,     0,    17,     0,    18,    19,     6,     7,     0,
       8,     9,    10,     0,    12,     6,     0,     0,     0,     0,
       0,     6,    12,     0,     0,     0,     0,     0,    12,     0,
      13,    14,     0,     0,     0,     0,    15,    16,    13,    14,
      17,     0,    18,    19,    13,    14,     0,     0,    17,    79,
      18,    19,     0,     0,    17,     0,    18,    19,    50,    51,
      52,    53,    54,    55,    56,    57,    58,    59,    60,    61,
      62,    63,    64,    65,    66,    67,    68,     0,     0,     0,
       0,     0,     0,    83,    50,    51,    52,    53,    54,    55,
      56,    57,    58,    59,    60,    61,    62,    63,    64,    65,
      66,    67,    68,     0,     0,     0,     0,     0,     0,   103,
      50,    51,    52,    53,    54,    55,    56,    57,    58,    59,
      60,    61,    62,    63,    64,    65,    66,    67,    68,     0,
       0,     0,     0,     0,     0,   105,    50,    51,    52,    53,
      54,    55,    56,    57,    58,    59,    60,    61,    62,    63,
      64,    65,    66,    67,    68,     0,     0,     0,     0,     0,
       0,   120,    50,    51,    52,    53,    54,    55,    56,    57,
      58,    59,    60,    61,    62,    63,    64,    65,    66,    67,
      68,     0,    69,    50,    51,    52,    53,    54,    55,    56,
      57,    58,    59,    60,    61,    62,    63,    64,    65,    66,
      67,    68,     0,   121,    50,    51,    52,    53,    54,    55,
      56,    57,    58,    59,    60,    61,    62,    63,    64,    65,
      66,    67,    68,    51,    52,    53,    54,    55,    56,    57,
      58,    59,    60,    61,    62,    63,    64,    65,    66,    67,
      68,    52,    53,    54,    55,    56,    57,    58,    59,    60,
      61,    62,    63,    64,    65,    66,    67,    68,    52,    53,
      54,    55,    56,    57,    58,     0,    60,    61,    62,    63,
      64,    65,    66,    67,    68,    52,    53,    54,    55,    56,
      57,    58,     0,     0,    61,    62,    63,    64,    65,    66,
      67,    68,    52,    53,    54,    55,    56,    57,    58,     0,
       0,     0,    62,    63,    64,    65,    66,    67,    68
};

static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( int8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yycheck )[]) =
{
      10,    10,   104,    16,    11,    37,    10,    20,    40,    17,
       3,    21,    18,    19,    20,     0,    32,   119,    36,    36,
      26,    27,    28,    29,    30,    34,     7,    35,    36,    37,
      34,    36,    40,    33,    44,    13,    14,    36,    48,    36,
      18,    19,    50,    51,    52,    53,    54,    55,    56,    57,
      58,    59,    60,    61,    62,    63,    64,    65,    66,    67,
      68,    16,    17,    18,    19,    20,    28,    29,    30,    24,
      25,    26,    27,    28,    29,    30,    32,     3,     4,    32,
       6,     7,     8,     9,    10,    26,    27,    28,    29,    30,
      35,     5,    32,   103,    37,   105,   104,    77,   106,   107,
      26,    27,    -1,   111,    -1,    -1,    32,    33,   118,    -1,
      36,   119,    38,    39,    -1,   125,     3,     4,    -1,     6,
       7,     8,    -1,    10,    -1,    -1,    -1,    -1,    -1,    -1,
       3,     4,    -1,     6,     7,     8,    -1,    10,    -1,    26,
      27,    -1,    -1,    -1,    -1,    32,    33,    34,    -1,    36,
      -1,    38,    39,    26,    27,    -1,    -1,    -1,    -1,    32,
      33,    34,    -1,    36,    -1,    38,    39,     3,     4,    -1,
       6,     7,     8,    -1,    10,     3,    -1,    -1,    -1,    -1,
      -1,     3,    10,    -1,    -1,    -1,    -1,    -1,    10,    -1,
      26,    27,    -1,    -1,    -1,    -1,    32,    33,    26,    27,
      36,    -1,    38,    39,    26,    27,    -1,    -1,    36,    37,
      38,    39,    -1,    -1,    36,    -1,    38,    39,    12,    13,
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
      -1,    -1,    24,    25,    26,    27,    28,    29,    30
};

#if 0
/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yystos )[]) =
{
       0,    11,    42,    43,     3,     0,     3,     4,     6,     7,
       8,     9,    10,    26,    27,    32,    33,    36,    38,    39,
      44,    47,    48,    49,    50,    51,    52,    53,    54,    55,
      57,    58,    59,    60,    32,    36,    36,    36,    48,    33,
      36,    58,    58,    34,    47,    57,    58,    58,    47,    48,
      12,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    32,
      57,    56,    57,    57,     7,    10,    34,    45,    46,    37,
      57,    61,    34,    37,    57,    57,    57,    57,    57,    57,
      57,    57,    57,    57,    57,    57,    57,    57,    57,    57,
      57,    57,    57,    37,    32,    37,    36,    35,    34,    46,
      37,    40,    48,    56,    48,    57,    57,    57,     5,    32,
      37,    32,    48,    56,    32,    37,    48
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
};

#endif /* _XDPDA_IMPLEMENT_USER_ACTIONLIST_DECLARE_ */
/*
 *!  XZ1 -- _XDPDA_IMPLEMENT_USER_ACTIONLIST_DECLARE_  END.
 */ 

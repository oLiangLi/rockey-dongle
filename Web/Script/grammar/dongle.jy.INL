
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
#define _XDPDACD_YYLAST   		621

/* YYNTOKENS -- Number of terminals.  */
#define _XDPDACD_YYNTOKENS  	46
/* YYNNTS -- Number of nonterminals.  */
#define _XDPDACD_YYNNTS  		33
/* YYNRULES -- Number of rules.  */
#define _XDPDACD_YYNRULES  		83
/* YYNRULES -- Number of states.  */
#define _XDPDACD_YYNSTATES  	170

#define _XDPDACD_YYUNDEFTOK  	YYUNDEF
#define _XDPDACD_YYMAXUTOK   	276

#define _XDPDACD_YYPACT_NINF 	-118
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
#define _XDPDAST_yyrline     _XDPDAST_IMPLEMENT_OF( uint16_t )
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
  "','", "'@'", "'['", "']'", "'$'", "':'", "$accept", "goal",
  "public_size", "const_declares", "const_statement_declare_list",
  "const_statement", "declares", "statement", "empty_statement",
  "block_statement", "expr_statement", "if_statement", "while_statement",
  "do_while_statement", "for_statement", "opt_expr", "expr",
  "unary_expression", "primary_expression", "callfunc", "arglist",
  "input_statement", "input_decl_end", "input_decl_begin",
  "input_decl_offset", "input_decl_size", "input_decl_options",
  "input_decl_list", "input_decl", "output_statement", "output_offset",
  "output_type", "output_size", YY_NULLPTR
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
      44,    64,    91,    93,    36,    58
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
      53,    55,    57,    59,    62,    66,    69,    75,    83,    89,
      97,   107,   108,   110,   112,   116,   120,   124,   128,   132,
     136,   140,   144,   148,   152,   156,   160,   164,   168,   172,
     176,   180,   184,   188,   190,   193,   196,   199,   202,   206,
     208,   210,   212,   216,   221,   223,   227,   234,   239,   241,
     244,   246,   250,   256,   259,   263,   265,   269,   271,   276,
     283,   286,   287,   289
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( int8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yyrhs )[]) =
{
      47,     0,    -1,    48,    49,    52,    -1,    48,    52,    -1,
      -1,    11,     3,    32,    -1,     9,    33,    34,    -1,     9,
      33,    50,    34,    -1,    51,    -1,    50,    51,    -1,    10,
      35,    62,    32,    -1,    53,    -1,    52,    53,    -1,    54,
      -1,    56,    -1,    57,    -1,    58,    -1,    59,    -1,    60,
      -1,    55,    -1,    67,    -1,    75,    -1,    32,    -1,    33,
      34,    -1,    33,    52,    34,    -1,    62,    32,    -1,     4,
      36,    62,    37,    53,    -1,     4,    36,    62,    37,    53,
       5,    53,    -1,     7,    36,    62,    37,    53,    -1,     8,
      53,     7,    36,    62,    37,    32,    -1,     6,    36,    61,
      32,    61,    32,    61,    37,    53,    -1,    -1,    62,    -1,
      63,    -1,    62,    12,    62,    -1,    62,    13,    62,    -1,
      62,    21,    62,    -1,    62,    22,    62,    -1,    62,    23,
      62,    -1,    62,    14,    62,    -1,    62,    15,    62,    -1,
      62,    16,    62,    -1,    62,    17,    62,    -1,    62,    25,
      62,    -1,    62,    24,    62,    -1,    62,    18,    62,    -1,
      62,    19,    62,    -1,    62,    20,    62,    -1,    62,    26,
      62,    -1,    62,    27,    62,    -1,    62,    28,    62,    -1,
      62,    29,    62,    -1,    62,    30,    62,    -1,    64,    -1,
      26,    63,    -1,    27,    63,    -1,    38,    63,    -1,    39,
      63,    -1,    36,    62,    37,    -1,    10,    -1,     3,    -1,
      65,    -1,    10,    36,    37,    -1,    10,    36,    66,    37,
      -1,    62,    -1,    66,    40,    62,    -1,    69,    70,    71,
      35,    72,    68,    -1,    69,    70,    71,    68,    -1,    32,
      -1,    10,    41,    -1,    62,    -1,    42,    62,    43,    -1,
      42,    62,    40,    62,    43,    -1,    33,    34,    -1,    33,
      73,    34,    -1,    74,    -1,    73,    40,    74,    -1,    62,
      -1,    44,    33,    10,    34,    -1,    76,    77,    78,    45,
      10,    32,    -1,    41,    62,    -1,    -1,    10,    -1,    42,
      62,    43,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint16_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yyrline )[]) =
{
       0,    38,    38,    40,    44,    46,    50,    52,    56,    58,
      62,    66,    68,    72,    74,    76,    78,    80,    82,    84,
      86,    88,    92,    96,    98,   102,   106,   108,   112,   116,
     120,   124,   126,   130,   132,   134,   136,   138,   140,   142,
     144,   146,   148,   150,   152,   154,   156,   158,   160,   162,
     164,   166,   168,   172,   174,   176,   178,   180,   184,   186,
     188,   190,   194,   196,   200,   202,   206,   208,   212,   216,
     220,   224,   226,   230,   232,   236,   238,   242,   244,   248,
     252,   256,   258,   262
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
       2,     2,     2,     2,     2,     2,     2,     2,    45,    32,
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
       0,    46,    47,    47,    48,    48,    49,    49,    50,    50,
      51,    52,    52,    53,    53,    53,    53,    53,    53,    53,
      53,    53,    54,    55,    55,    56,    57,    57,    58,    59,
      60,    61,    61,    62,    62,    62,    62,    62,    62,    62,
      62,    62,    62,    62,    62,    62,    62,    62,    62,    62,
      62,    62,    62,    63,    63,    63,    63,    63,    64,    64,
      64,    64,    65,    65,    66,    66,    67,    67,    68,    69,
      70,    71,    71,    72,    72,    73,    73,    74,    74,    75,
      76,    77,    77,    78
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yyr2 )[]) =
{
       0,     2,     3,     2,     0,     3,     3,     4,     1,     2,
       4,     1,     2,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     2,     3,     2,     5,     7,     5,     7,
       9,     0,     1,     1,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     1,     2,     2,     2,     2,     3,     1,
       1,     1,     3,     4,     1,     3,     6,     4,     1,     2,
       1,     3,     5,     2,     3,     1,     3,     1,     4,     6,
       2,     0,     1,     3
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yydefact )[]) =
{
       4,     0,     0,     0,     0,     1,    60,     0,     0,     0,
       0,     0,    59,     0,     0,    22,     0,     0,     0,     0,
       0,     0,     3,    11,    13,    19,    14,    15,    16,    17,
      18,     0,    33,    53,    61,    20,     0,    21,    81,     5,
       0,    31,     0,     0,     0,     0,    69,    59,    54,    55,
      23,     0,     0,    56,    57,    80,     2,    12,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    25,    70,     0,
      82,     0,     0,     0,    32,     0,     0,     0,     6,     0,
       8,    62,    64,     0,    24,    58,    34,    35,    39,    40,
      41,    42,    45,    46,    47,    36,    37,    38,    44,    43,
      48,    49,    50,    51,    52,     0,     0,     0,     0,     0,
      31,     0,     0,     0,     7,     9,    63,     0,     0,    68,
       0,    67,     0,     0,    26,     0,    28,     0,     0,    65,
       0,    71,     0,     0,    83,     0,     0,    31,     0,    10,
       0,    73,     0,    77,     0,    75,    66,    79,    27,     0,
      29,    72,     0,    74,     0,     0,     0,    76,    30,    78
};

/* YYDEFGOTO[NTERM-NUM].  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yydefgoto )[]) =
{
       0,     2,     3,    21,    89,    90,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    83,    31,    32,    33,    34,
      93,    35,   131,    36,    79,   116,   143,   154,   155,    37,
      38,    81,   118
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */

static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( int16_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yypact )[]) =
{
      -6,     6,    20,   115,   -11,  -118,  -118,   -14,   -13,    -4,
     233,    16,   -17,   180,   180,  -118,   155,   180,   180,   180,
     180,   233,   233,  -118,  -118,  -118,  -118,  -118,  -118,  -118,
    -118,   463,  -118,  -118,  -118,  -118,   180,  -118,    60,  -118,
     180,   180,   180,    70,    -9,   140,  -118,    43,  -118,  -118,
    -118,   194,   359,  -118,  -118,   505,   233,  -118,   180,   180,
     180,   180,   180,   180,   180,   180,   180,   180,   180,   180,
     180,   180,   180,   180,   180,   180,   180,  -118,   505,    50,
    -118,    51,   385,    66,   505,   411,    67,    79,  -118,    -8,
    -118,  -118,   505,    59,  -118,  -118,   523,   540,    56,    56,
     -12,   -12,    61,    61,    61,   557,   574,   591,   -12,   -12,
      98,    98,  -118,  -118,  -118,   180,    65,   180,    72,   233,
     180,   233,   180,   180,  -118,  -118,  -118,   180,   263,  -118,
      96,  -118,   295,    91,   100,    99,  -118,   437,   484,   505,
     180,  -118,    68,   102,  -118,   105,   233,   180,   106,  -118,
     327,  -118,    97,   505,    10,  -118,  -118,  -118,  -118,    95,
    -118,  -118,   129,  -118,     1,   233,   110,  -118,  -118,  -118
};

/* YYPGOTO[NTERM-NUM].  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( int8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yypgoto )[]) =
{
    -118,  -118,  -118,  -118,  -118,    57,    15,   -10,  -118,  -118,
    -118,  -118,  -118,  -118,  -118,  -117,    -7,    29,  -118,  -118,
    -118,  -118,     2,  -118,  -118,  -118,  -118,  -118,   -15,  -118,
    -118,  -118,  -118
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */

static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yytable )[]) =
{
      43,    87,    87,   135,     6,     1,    64,    65,    66,     4,
      52,    47,    57,    55,    72,    73,    74,    75,    76,    45,
       5,    39,    40,    41,    46,    88,   124,    13,    14,    78,
     159,    51,    42,    82,    84,    85,    56,    17,    92,    18,
      19,    57,    48,    49,   163,   152,    57,    53,    54,    44,
     164,    96,    97,    98,    99,   100,   101,   102,   103,   104,
     105,   106,   107,   108,   109,   110,   111,   112,   113,   114,
      80,     6,    62,    63,    64,    65,    66,    86,    47,    45,
      70,    71,    72,    73,    74,    75,    76,    72,    73,    74,
      75,    76,   115,   117,    13,    14,   126,   129,   120,   127,
     130,   145,   151,   122,    17,   146,    18,    19,   128,   134,
     132,   136,   152,    84,   123,   137,   138,   133,     6,     7,
     139,     8,     9,    10,    11,    12,    74,    75,    76,   142,
     162,   147,   165,   150,   129,   153,   158,   157,   160,   166,
      84,    13,    14,     6,   169,   156,   125,    15,    16,   167,
      47,    17,     0,    18,    19,   168,    20,   153,     6,     7,
       0,     8,     9,    10,     0,    12,    13,    14,     0,     0,
       0,     0,     0,     0,     0,     0,    17,    91,    18,    19,
       0,    13,    14,     6,     0,     0,     0,    15,    16,    50,
      47,    17,     0,    18,    19,     0,    20,     6,     7,     0,
       8,     9,    10,     0,    12,     0,    13,    14,     0,     0,
       0,     0,     0,     0,     0,     0,    17,     0,    18,    19,
      13,    14,     0,     0,     0,     0,    15,    16,    94,     0,
      17,     0,    18,    19,     0,    20,     6,     7,     0,     8,
       9,    10,     0,    12,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    13,
      14,     0,     0,     0,     0,    15,    16,     0,     0,    17,
       0,    18,    19,     0,    20,    58,    59,    60,    61,    62,
      63,    64,    65,    66,    67,    68,    69,    70,    71,    72,
      73,    74,    75,    76,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   140,     0,     0,   141,    58,    59,    60,
      61,    62,    63,    64,    65,    66,    67,    68,    69,    70,
      71,    72,    73,    74,    75,    76,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   144,    58,
      59,    60,    61,    62,    63,    64,    65,    66,    67,    68,
      69,    70,    71,    72,    73,    74,    75,    76,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     161,    58,    59,    60,    61,    62,    63,    64,    65,    66,
      67,    68,    69,    70,    71,    72,    73,    74,    75,    76,
       0,     0,     0,     0,     0,     0,    95,    58,    59,    60,
      61,    62,    63,    64,    65,    66,    67,    68,    69,    70,
      71,    72,    73,    74,    75,    76,     0,     0,     0,     0,
       0,     0,   119,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,     0,     0,     0,     0,     0,     0,   121,    58,
      59,    60,    61,    62,    63,    64,    65,    66,    67,    68,
      69,    70,    71,    72,    73,    74,    75,    76,     0,     0,
       0,     0,     0,     0,   148,    58,    59,    60,    61,    62,
      63,    64,    65,    66,    67,    68,    69,    70,    71,    72,
      73,    74,    75,    76,     0,    77,    58,    59,    60,    61,
      62,    63,    64,    65,    66,    67,    68,    69,    70,    71,
      72,    73,    74,    75,    76,     0,   149,    58,    59,    60,
      61,    62,    63,    64,    65,    66,    67,    68,    69,    70,
      71,    72,    73,    74,    75,    76,    59,    60,    61,    62,
      63,    64,    65,    66,    67,    68,    69,    70,    71,    72,
      73,    74,    75,    76,    60,    61,    62,    63,    64,    65,
      66,    67,    68,    69,    70,    71,    72,    73,    74,    75,
      76,    60,    61,    62,    63,    64,    65,    66,     0,    68,
      69,    70,    71,    72,    73,    74,    75,    76,    60,    61,
      62,    63,    64,    65,    66,     0,     0,    69,    70,    71,
      72,    73,    74,    75,    76,    60,    61,    62,    63,    64,
      65,    66,     0,     0,     0,    70,    71,    72,    73,    74,
      75,    76
};

static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( int16_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yycheck )[]) =
{
      10,    10,    10,   120,     3,    11,    18,    19,    20,     3,
      17,    10,    22,    20,    26,    27,    28,    29,    30,    36,
       0,    32,    36,    36,    41,    34,    34,    26,    27,    36,
     147,    16,    36,    40,    41,    42,    21,    36,    45,    38,
      39,    51,    13,    14,    34,    44,    56,    18,    19,    33,
      40,    58,    59,    60,    61,    62,    63,    64,    65,    66,
      67,    68,    69,    70,    71,    72,    73,    74,    75,    76,
      10,     3,    16,    17,    18,    19,    20,     7,    10,    36,
      24,    25,    26,    27,    28,    29,    30,    26,    27,    28,
      29,    30,    42,    42,    26,    27,    37,    32,    32,    40,
      35,    10,    34,    36,    36,     5,    38,    39,   115,   119,
     117,   121,    44,   120,    35,   122,   123,    45,     3,     4,
     127,     6,     7,     8,     9,    10,    28,    29,    30,    33,
      33,    32,    37,   140,    32,   142,   146,    32,    32,    10,
     147,    26,    27,     3,    34,   143,    89,    32,    33,   164,
      10,    36,    -1,    38,    39,   165,    41,   164,     3,     4,
      -1,     6,     7,     8,    -1,    10,    26,    27,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    36,    37,    38,    39,
      -1,    26,    27,     3,    -1,    -1,    -1,    32,    33,    34,
      10,    36,    -1,    38,    39,    -1,    41,     3,     4,    -1,
       6,     7,     8,    -1,    10,    -1,    26,    27,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    36,    -1,    38,    39,
      26,    27,    -1,    -1,    -1,    -1,    32,    33,    34,    -1,
      36,    -1,    38,    39,    -1,    41,     3,     4,    -1,     6,
       7,     8,    -1,    10,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    26,
      27,    -1,    -1,    -1,    -1,    32,    33,    -1,    -1,    36,
      -1,    38,    39,    -1,    41,    12,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    40,    -1,    -1,    43,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    43,    12,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      43,    12,    13,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      -1,    -1,    -1,    -1,    -1,    -1,    37,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    -1,    -1,    -1,    -1,
      -1,    -1,    37,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    -1,    -1,    -1,    -1,    -1,    -1,    37,    12,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    -1,    -1,
      -1,    -1,    -1,    -1,    37,    12,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    -1,    32,    12,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    -1,    32,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    14,    15,    16,    17,    18,    19,    20,    -1,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    14,    15,
      16,    17,    18,    19,    20,    -1,    -1,    23,    24,    25,
      26,    27,    28,    29,    30,    14,    15,    16,    17,    18,
      19,    20,    -1,    -1,    -1,    24,    25,    26,    27,    28,
      29,    30
};

#if 0
/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const 
_XDPDA_IMPLEMENT_STATE_TYPE_OF( uint8_t )
_XDPDA_IMPLEMENT_TABLE_STORE(_XDPDA_IMPLEMENT_NAME_OF( yystos )[]) =
{
       0,    11,    47,    48,     3,     0,     3,     4,     6,     7,
       8,     9,    10,    26,    27,    32,    33,    36,    38,    39,
      41,    49,    52,    53,    54,    55,    56,    57,    58,    59,
      60,    62,    63,    64,    65,    67,    69,    75,    76,    32,
      36,    36,    36,    53,    33,    36,    41,    10,    63,    63,
      34,    52,    62,    63,    63,    62,    52,    53,    12,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    32,    62,    70,
      10,    77,    62,    61,    62,    62,     7,    10,    34,    50,
      51,    37,    62,    66,    34,    37,    62,    62,    62,    62,
      62,    62,    62,    62,    62,    62,    62,    62,    62,    62,
      62,    62,    62,    62,    62,    42,    71,    42,    78,    37,
      32,    37,    36,    35,    34,    51,    37,    40,    62,    32,
      35,    68,    62,    45,    53,    61,    53,    62,    62,    62,
      40,    43,    33,    72,    43,    10,     5,    32,    37,    32,
      62,    34,    44,    62,    73,    74,    68,    32,    53,    61,
      32,    43,    33,    34,    40,    37,    10,    74,    53,    34
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
    AC_EMPTY_STMT                            = 22,
    AC_BLOCK_EMPTY                           = 23,
    AC_BLOCK_DECLARE                         = 24,
    AC_EXPRESSION_DECLARE                    = 25,
    AC_IF_STATEMENT                          = 26,
    AC_IF_ELSE_STATEMENT                     = 27,
    AC_WHILE_STATEMENT                       = 28,
    AC_DO_WHILE_STATEMENT                    = 29,
    AC_FOR_STATEMENT                         = 30,
    AC_OPT_EXPR_NULL                         = 31,
    AC_EXPR_LOGIC_OR                         = 34,
    AC_EXPR_LOGIC_AND                        = 35,
    AC_EXPR_BIT_OR                           = 36,
    AC_EXPR_BIT_XOR                          = 37,
    AC_EXPR_BIT_AND                          = 38,
    AC_EXPR_EQ                               = 39,
    AC_EXPR_NE                               = 40,
    AC_EXPR_LE                               = 41,
    AC_EXPR_GE                               = 42,
    AC_EXPR_GT                               = 43,
    AC_EXPR_LT                               = 44,
    AC_EXPR_SHIFT_LEFT                       = 45,
    AC_EXPR_SHIFT_RIGHT                      = 46,
    AC_EXPR_SHIFT_RIGHT_U                    = 47,
    AC_EXPR_ADD                              = 48,
    AC_EXPR_SUB                              = 49,
    AC_EXPR_MUL                              = 50,
    AC_EXPR_DIV                              = 51,
    AC_EXPR_MOD                              = 52,
    AC_EXPR_UNARY_ADD                        = 54,
    AC_EXPR_UNARY_SUB                        = 55,
    AC_EXPR_BIT_NOT                          = 56,
    AC_EXPR_LOGIC_NOT                        = 57,
    AC_PRI_EXPR_0                            = 58,
    AC_PRI_IDEN                              = 59,
    AC_PRI_NUMBER                            = 60,
    AC_CALL_0                                = 62,
    AC_CALL_X                                = 63,
    AC_ARGLIST_1                             = 64,
    AC_ARGLIST_X                             = 65,
    AC_INPUT_END                             = 68,
    AC_INPUT_BEGIN                           = 69,
    AC_INPUT_OFFSET                          = 70,
    AC_INPUT_SIZE_1                          = 71,
    AC_INPUT_SIZE_2                          = 72,
    AC_INPUT_EXPR                            = 77,
    AC_INPUT_EXTERN                          = 78,
    AC_OUTPUT_STMT                           = 79,
    AC_OUTPUT_OFFSET                         = 80,
    AC_OUTPUT_TYPE_BUFFER                    = 81,
    AC_OUTPUT_TYPE_INTEGER                   = 82,
    AC_OUTPUT_SIZE                           = 83,
};

#endif /* _XDPDA_IMPLEMENT_USER_ACTIONLIST_DECLARE_ */
/*
 *!  XZ1 -- _XDPDA_IMPLEMENT_USER_ACTIONLIST_DECLARE_  END.
 */ 

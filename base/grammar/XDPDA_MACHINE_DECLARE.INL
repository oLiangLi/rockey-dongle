
#undef _XDPDA_IMPLEMENT_IDENTIFICATION_DECLARE_
#undef _XDPDA_IMPLEMENT_TOKENENUMS_DECLARE_
#undef _XDPDA_IMPLEMENT_CONSTANT_DECLARE_
#undef _XDPDA_IMPLEMENT_STATE_TYPE_DECLARE_
#undef _XDPDA_IMPLEMENT_TNAME_DECLARE_
#undef _XDPDA_IMPLEMENT_TOKNUM_DECLARE_
#undef _XDPDA_IMPLEMENT_DBGTBL_DECLARE_
#undef _XDPDA_IMPLEMENT_TABLE_DECLARE_
#undef _XDPDA_IMPLEMENT_USER_ACTIONS_DECLARE_

#undef _XDPDA_IMPLEMENT_STATE_TYPE_OF
#undef _XDPDA_IMPLEMENT_NAME_OF

#define _XDPDA_IMPLEMENT_STATE_TYPE_OF(type)		type
#define _XDPDA_IMPLEMENT_NAME_OF(name)					_xdpda_table_ ## name
#ifndef _XDPDAM_STATE_get
#define _XDPDAM_STATE_get(name,N)								(_xdpda_table_ ## name[(N)])
#endif /* _XDPDAM_STATE_get */

#ifndef _XDPDA_VAR
#define _XDPDA_VAR(v)														(self->f_ ## v)
#endif /* _XDPDA_VAR */

#ifndef YY_NULLPTR
#define YY_NULLPTR															0
#endif /* YY_NULLPTR */

/*
 *
 */
#ifdef XDPDA_GRAMMAR_DECLARE_FILE

/**
 *!
 */
#ifndef XDPDA_CB_COPY_YYLVALUE
#define XDPDA_CB_COPY_YYLVALUE()
#endif /* XDPDA_CB_COPY_YYLVALUE */

/*
 *	================ Tokens ================
 */
#ifdef XDPDA_GRAMMAR_DECLARE_TOKENENUMS
#define _XDPDA_IMPLEMENT_TOKENENUMS_DECLARE_
#include XDPDA_GRAMMAR_DECLARE_FILE
#undef  _XDPDA_IMPLEMENT_TOKENENUMS_DECLARE_
#endif /* XDPDA_GRAMMAR_DECLARE_TOKENENUMS */

/*
 *	================ Actions ===============
 */
#ifdef XDPDA_GRAMMAR_DECLARE_ACTIONLIST
#define _XDPDA_IMPLEMENT_USER_ACTIONLIST_DECLARE_
#include XDPDA_GRAMMAR_DECLARE_FILE
#undef  _XDPDA_IMPLEMENT_USER_ACTIONLIST_DECLARE_
#endif /* XDPDA_GRAMMAR_DECLARE_ACTIONLIST */


/*
 *	================ Deterministic pushdown automaton ================
 */
#ifdef XDPDA_IMPLEMENT_NEXTSTATE_FUNCTION_DECLARE
	XDPDA_IMPLEMENT_NEXTSTATE_FUNCTION_DECLARE
#ifndef XDPDA_IMPLEMENT_NEXTSTATE_FUNCTION
#define XDPDA_IMPLEMENT_NEXTSTATE_FUNCTION
#endif /* XDPDA_IMPLEMENT_NEXTSTATE_FUNCTION */
#undef XDPDA_IMPLEMENT_NEXTSTATE_FUNCTION_DECLARE
#elif defined(XDPDA_IMPLEMENT_NEXTSTATE_FUNCTION)
int rLANGAPI  XDPDA_IMPLEMENT_NEXTSTATE_FUNCTION(XDPDA_GRAMMAR* self, int reason, XDPDA_YYVALUE* value)
#endif	/* XDPDA_IMPLEMENT_NEXTSTATE_FUNCTION_DECLARE */

#ifdef XDPDA_IMPLEMENT_NEXTSTATE_FUNCTION
{
	int result = XDPDA_RESULT_FAILED_ERROR;

XULIB_SPECIFIC_BLOCK_BEGIN

#ifdef XDPDA_IMPLEMENT_NEXTSTATE_FUNCTION_USERCODE
	XDPDA_IMPLEMENT_NEXTSTATE_FUNCTION_USERCODE
#endif /* XDPDA_IMPLEMENT_NEXTSTATE_FUNCTION_USER_BLOCK */
	;;
XULIB_SPECIFIC_BLOCK_BEGIN

#define _XDPDA_IMPLEMENT_CONSTANT_DECLARE_
#if defined(_XDPDA_OUTPUT_TRACE) && _XDPDA_OUTPUT_TRACE
#define _XDPDA_IMPLEMENT_TNAME_DECLARE_
#else
#undef  _XDPDA_IMPLEMENT_TNAME_DECLARE_
#endif
#define _XDPDA_IMPLEMENT_TABLE_DECLARE_
#include XDPDA_GRAMMAR_DECLARE_FILE
#undef  _XDPDA_IMPLEMENT_CONSTANT_DECLARE_
#undef  _XDPDA_IMPLEMENT_TNAME_DECLARE_
#undef  _XDPDA_IMPLEMENT_TABLE_DECLARE_

XULIB_SPECIFIC_BLOCK_BEGIN	

#define XDPDA_MACHINE_GOTO_label( __label__ )		goto _label_XDPDA_MACHINE_ ## __label__
#define XDPDA_MACHINE_HANDLE( __label__ )				_label_XDPDA_MACHINE_ ## __label__:
#define XDPDA_MACHINE_RETURN(v)									do { result = (v); XDPDA_MACHINE_GOTO_label(_machine_return); } while(0)
#define XDPDA_UNEXPECTED_STATE_RAISE						XDPDA_MACHINE_RETURN(XDPDA_RESULT_FAILED_ERROR)

	if (reason < 0) {
		switch (0 - reason) {
			case 0 - XDPDA_RESUME_INITIALIZE: {
				XULIB_ASSERT(NULL != self->f_yyssa && self->f_yyvsa &&
										 self->f_yystacksize >= 8);

				self->f_yychar = 0;
				self->f_yynerrs = 0;
				self->f_yystate = 0;
				self->f_yyn = 0;
				self->f_yyerrstatus = 0;
				self->f_yytoken = 0;

				_XDPDA_YYVALUE_INIT(self->f_yylval);
				_XDPDA_YYVALUE_INIT(self->f_yyval);

				self->f_yylen = 0;
				self->f_yyss = self->f_yyssp = self->f_yyssa;
				self->f_yyvs = self->f_yyvsp = self->f_yyvsa;

				self->f_yychar = XDPDA_YYEMPTY;
				XDPDA_MACHINE_GOTO_label(yysetstate);
			} break;
			case 0 - XDPDA_RESUME_REDUCE: {
				if (self->X_state_internal <= 0)
					XDPDA_UNEXPECTED_STATE_RAISE;
				XDPDA_MACHINE_GOTO_label(resume_reduce);
			} break;
			case 0 - XDPDA_RESUME_EXTEND_STACK: {
				if (self->X_state_internal != XDPDA_RESULT_PENDING_EXTEND_STACK)
					XDPDA_UNEXPECTED_STATE_RAISE;
				XDPDA_MACHINE_GOTO_label(resume_extend_stack);
			} break;
			case 0 - XDPDA_RESUME_SYNTAX_ERROR: {
				if (self->X_state_internal != XDPDA_RESULT_FAILED_SYNTAX_ERROR)
					XDPDA_UNEXPECTED_STATE_RAISE;
				XDPDA_MACHINE_GOTO_label(resume_syntax_error);
			} break;
			case 0 - XDPDA_RESUME_YYACCEPT: {
				if (self->X_state_internal <= 0)
					XDPDA_UNEXPECTED_STATE_RAISE;
				XDPDA_MACHINE_GOTO_label(yyacceptlab);
			} break;
			case 0 - XDPDA_RESUME_YYERROR: {
				if (self->X_state_internal <= 0)
					XDPDA_UNEXPECTED_STATE_RAISE;
				XDPDA_MACHINE_GOTO_label(yyerrorlab);
			} break;
			case 0 - XDPDA_RESUME_YYABORT: {
				if (self->X_state_internal <= 0)
					XDPDA_UNEXPECTED_STATE_RAISE;
				XDPDA_MACHINE_GOTO_label(yyabortlab);
			} break;
			default:
				XDPDA_UNEXPECTED_STATE_RAISE;
				break;
		}
	} else {
		if (self->X_state_internal != XDPDA_RESULT_PENDING_MORE_INPUT)
			XDPDA_UNEXPECTED_STATE_RAISE;
		XULIB_ASSERT(XDPDA_YYEMPTY == self->f_yychar);

		self->f_yychar = reason;
		if (NULL != value)
			_XDPDA_YYVALUE_COPY(self->f_yylval, value);
		XDPDA_MACHINE_GOTO_label(resume_yylex);
	}

XULIB_SPECIFIC_BLOCK_END

/*
 *	
 */
XDPDA_MACHINE_HANDLE(yynewstate)
	self->f_yyssp ++ ;
XDPDA_MACHINE_HANDLE(yysetstate)
	*self->f_yyssp = (short)self->f_yystate;
	if(self->f_yyss + self->f_yystacksize - 1 <= self->f_yyssp)
	{
		XDPDA_MACHINE_RETURN(XDPDA_RESULT_PENDING_EXTEND_STACK);
	}
XDPDA_MACHINE_HANDLE(resume_extend_stack)
	XULIB_ASSERT( self->f_yyss + self->f_yystacksize - 1 > self->f_yyssp );
/* XDPDA_MACHINE_HANDLE(yybackup) */
	if( _XDPDACD_YYPACT_NINF == (self->f_yyn = _XDPDAM_STATE_get( yypact , self->f_yystate ) ) )
		XDPDA_MACHINE_GOTO_label( yydefault );
	/* Not known => get a look-ahead token if don't already have one.  */
	/* YYCHAR is either YYEMPTY or YYEOF or a valid look-ahead symbol. */

	if(XDPDA_YYEMPTY == self->f_yychar)
	{
		XDPDA_MACHINE_RETURN(XDPDA_RESULT_PENDING_MORE_INPUT);
	}
XDPDA_MACHINE_HANDLE( resume_yylex )
	XULIB_ASSERT(self->f_yychar >= 0);
	if(self->f_yychar == XDPDA_YYEOF)
	{
		self->f_yytoken = XDPDA_YYEOF;
	}
	else
	{
		if(self->f_yychar <= _XDPDACD_YYMAXUTOK)
			self->f_yytoken = _XDPDAM_STATE_get(yytranslate , self->f_yychar);
		else
			self->f_yytoken = _XDPDACD_YYUNDEFTOK;
	}
	
	self->f_yyn += self->f_yytoken;
	
	if( self->f_yyn < 0 || _XDPDACD_YYLAST < self->f_yyn || 
		_XDPDAM_STATE_get( yycheck , self->f_yyn ) != self->f_yytoken )
		XDPDA_MACHINE_GOTO_label( yydefault );
	
	if( (self->f_yyn = _XDPDAM_STATE_get( yytable , self->f_yyn ) ) <= 0 )
	{
		if( self->f_yyn == 0 || self->f_yyn == _XDPDACD_YYTABLE_NINF )
			XDPDA_MACHINE_GOTO_label( yyerrlab );
		self->f_yyn = - self->f_yyn;
		XDPDA_MACHINE_GOTO_label( yyreduce );
	}
	
	if( self->f_yyn == _XDPDACD_YYFINAL )
		XDPDA_MACHINE_GOTO_label( yyacceptlab );		
		/* Count tokens shifted since error; after three, turn off error status.  */
	if( self->f_yyerrstatus )
		self->f_yyerrstatus--;
	/* Shift the look-ahead token.  */
	
	/* Discard the shifted token unless it is eof.  */
	if( self->f_yychar != XDPDA_YYEOF )
		self->f_yychar = XDPDA_YYEMPTY;
	
	self->f_yystate = self->f_yyn;
	_XDPDA_YYVALUE_COPY( *++self->f_yyvsp , &self->f_yylval  );
	XDPDA_CB_COPY_YYLVALUE();

	XDPDA_MACHINE_GOTO_label( yynewstate );
/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
XDPDA_MACHINE_HANDLE( yydefault )
	if( 0 == (self->f_yyn = _XDPDAM_STATE_get( yydefact , self->f_yystate ) ) )
		XDPDA_MACHINE_GOTO_label( yyerrlab );
	
/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
XDPDA_MACHINE_HANDLE( yyreduce )
	/* yyn is the number of a rule to reduce with.  */
	self->f_yylen = _XDPDAM_STATE_get( yyr2 , self->f_yyn );
		
	/* YYPOPSTACK */
	self->f_yyvsp -= self->f_yylen;
	self->f_yyssp -= self->f_yylen;
		
	_XDPDA_YYVALUE_COPY(self->f_yyval , &self->f_yyvsp[1] );

/*
 *	
 */
#ifdef XDPDA_GRAMMAR_DECLARE_USER_ACTION
	switch(self->f_yyn)
	{
#define _XDPDA_IMPLEMENT_USER_ACTIONS_DECLARE_
#include XDPDA_GRAMMAR_DECLARE_FILE
#undef  _XDPDA_IMPLEMENT_USER_ACTIONS_DECLARE_
	default:
		break;
	}
#else /* XDPDA_GRAMMAR_DECLARE_USER_ACTION */
	XDPDA_MACHINE_RETURN(self->f_yyn);	
#endif /* XDPDA_GRAMMAR_DECLARE_USER_ACTION */

XDPDA_MACHINE_HANDLE( resume_reduce )
	self->f_yylen = 0;

	_XDPDA_YYVALUE_COPY( *++self->f_yyvsp , &self->f_yyval );
  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
	self->f_yyn = _XDPDAM_STATE_get( yyr1 , self->f_yyn );
	self->f_yystate = _XDPDAM_STATE_get( yypgoto , self->f_yyn - _XDPDACD_YYNTOKENS ) + *self->f_yyssp;
	
	if (0 <= self->f_yystate && self->f_yystate <= _XDPDACD_YYLAST && 
		_XDPDAM_STATE_get( yycheck , self->f_yystate ) == *self->f_yyssp )
		self->f_yystate = _XDPDAM_STATE_get( yytable , self->f_yystate );
	else
		self->f_yystate = _XDPDAM_STATE_get( yydefgoto , self->f_yyn - _XDPDACD_YYNTOKENS );
	
	XDPDA_MACHINE_GOTO_label( yynewstate );
XDPDA_MACHINE_HANDLE( yyerrlab )
	/* If not already recovering from an error, report this error.  */
	if (!self->f_yyerrstatus)
	{
		++self->f_yynerrs;

#if defined(_XDPDA_OUTPUT_TRACE) && _XDPDA_OUTPUT_TRACE
		{
			int yystate = self->f_yystate, yychar = self->f_yychar, yytype;
			int yyn = _XDPDAM_STATE_get(yypact, yystate);
			if (_XDPDACD_YYPACT_NINF < yyn && yyn <= _XDPDACD_YYLAST)
			{
				if (yychar <= _XDPDACD_YYMAXUTOK && yychar >= 0)
					yytype = _XDPDAM_STATE_get(yytranslate, yychar);
				else
					yytype = _XDPDACD_YYUNDEFTOK;

				{
					int yychecklim = _XDPDACD_YYLAST - yyn + 1;
					int yyx, yyxend = yychecklim < _XDPDACD_YYNTOKENS ? yychecklim : _XDPDACD_YYNTOKENS;
					int yyxbegin = yyn < 0 ? -yyn : 0;
					int yycount = 1;

					XULIB_GRAMMAR_ERROR_OUTPUT("[PARSE.ERROR]syntax error, unexpected", _XDPDAM_STATE_get(yytname, yytype));

					for (yyx = yyxbegin; yyx < yyxend; ++yyx)
					{
						if (_XDPDAM_STATE_get(yycheck, yyx + yyn) == yyx && yyx != XDPDA_YYTERROR)
						{
							if (yycount++ == 1)
								XULIB_GRAMMAR_ERROR_OUTPUT("\texpecting", _XDPDAM_STATE_get(yytname, yyx));
							else
								XULIB_GRAMMAR_ERROR_OUTPUT("\t\tor", _XDPDAM_STATE_get(yytname, yyx));
						}
					}
				}
			}
		}
#endif
		XDPDA_MACHINE_RETURN(XDPDA_RESULT_FAILED_SYNTAX_ERROR);
XDPDA_MACHINE_HANDLE(resume_syntax_error)
		;;
	}
	if (self->f_yyerrstatus == 3)
	{
	/* If just tried and failed to reuse look-ahead token after an
		error, discard it.  */
		
		if (self->f_yychar <= XDPDA_YYEOF)
		{
			/* Return failure if at end of input.  */
			if (self->f_yychar == XDPDA_YYEOF)
				XDPDA_MACHINE_GOTO_label( yyabortlab );
		}
		else
		{
			self->f_yychar = XDPDA_YYEMPTY;
		}
	}	
	/* Else will try to reuse look-ahead token after shifting the error	token.  */
	XDPDA_MACHINE_GOTO_label( yyerrlab1 );
/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
XDPDA_MACHINE_HANDLE( yyerrorlab )
  /* Do not reclaim the symbols of the rule which action triggered
	 this YYERROR.  */
		
	/* YYPOPSTACK */
	self->f_yyvsp -= self->f_yylen;
	self->f_yyssp -= self->f_yylen;

	self->f_yylen = 0;
	self->f_yystate = *self->f_yyssp;
/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
XDPDA_MACHINE_HANDLE( yyerrlab1 )
	self->f_yyerrstatus = 3;	/* Each real token shifted decrements this.  */
		
	for (;;)
	{
		self->f_yyn = _XDPDAM_STATE_get( yypact , self->f_yystate );
		if (self->f_yyn != _XDPDACD_YYPACT_NINF)
		{
			self->f_yyn += XDPDA_YYTERROR;
			if (0 <= self->f_yyn && self->f_yyn <= _XDPDACD_YYLAST && 
				_XDPDAM_STATE_get( yycheck , self->f_yyn ) == XDPDA_YYTERROR)
			{
				self->f_yyn = _XDPDAM_STATE_get( yytable , self->f_yyn );
				if (0 < self->f_yyn)
					break;
			}
		}
		/* Pop the current state because it cannot handle the error token.  */
		if (self->f_yyssp == self->f_yyss)			
		{
			XDPDA_MACHINE_GOTO_label( yyabortlab );	
		}
		
		/* YYPOPSTACK(1) */
		self->f_yyvsp --;
		self->f_yyssp --;
		self->f_yystate = *self->f_yyssp;
	}

	if (self->f_yyn == _XDPDACD_YYFINAL)
		XDPDA_MACHINE_GOTO_label(yyacceptlab);

	_XDPDA_YYVALUE_COPY( *++self->f_yyvsp , &self->f_yylval );
	XDPDA_CB_COPY_YYLVALUE();

	/* Shift the error token.  */		
	self->f_yystate = self->f_yyn;
	XDPDA_MACHINE_GOTO_label(yynewstate);
	
/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
XDPDA_MACHINE_HANDLE( yyacceptlab )	
	XDPDA_MACHINE_RETURN(XDPDA_RESULT_ACCEPTED);

XDPDA_MACHINE_HANDLE(yyabortlab)
	XDPDA_MACHINE_RETURN(XDPDA_RESULT_FAILED_ABORT);
/*
 *
 */
XDPDA_MACHINE_HANDLE( _machine_return )

XULIB_SPECIFIC_BLOCK_BEGIN
#ifdef XDPDA_IMPLEMENT_NEXTSTATE_FUNCTION_USERCODE_FILTER_RESULT
	XDPDA_IMPLEMENT_NEXTSTATE_FUNCTION_USERCODE_FILTER_RESULT
#endif /* XDPDA_IMPLEMENT_NEXTSTATE_FUNCTION_USERCODE_FILTER_RESULT */
		;;
	return self->X_state_internal = result;
XULIB_SPECIFIC_BLOCK_END
XULIB_SPECIFIC_BLOCK_END
XULIB_SPECIFIC_BLOCK_END
}
#undef XDPDA_IMPLEMENT_NEXTSTATE_FUNCTION
#endif /* XDPDA_IMPLEMENT_NEXTSTATE_FUNCTION */

#undef _XDPDA_TRACE_TAG				    /**/
#undef XDPDA_GRAMMAR_DECLARE_FILE	/**/
#undef XDPDA_CB_COPY_YYLVALUE	    /**/
#endif /* XDPDA_GRAMMAR_DECLARE_FILE */



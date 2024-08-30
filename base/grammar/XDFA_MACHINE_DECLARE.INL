
#undef  _XDFA_MACHINE_GOTO_label
#undef  _XDFA_MACHINE_HANDLE

#ifndef _XDFAM_STATE_get
	#define _XDFAM_STATE_get(__NAME__, __N__)			__NAME__ [(__N__)]
#endif /* _XDFAM_STATE_get */

#define _XDFA_MACHINE_GOTO_label( __label__ )		goto _label_XDFA_MACHINE_ ## __label__
#define _XDFA_MACHINE_HANDLE( __label__ )				_label_XDFA_MACHINE_ ## __label__:

#ifdef XDFA_IMPLEMENT_NEXTSTATE_FUNCTION_DECLARE
	XDFA_IMPLEMENT_NEXTSTATE_FUNCTION_DECLARE
#define XDFA_IMPLEMENT_NEXTSTATE_FUNCTION
#undef XDFA_IMPLEMENT_NEXTSTATE_FUNCTION_DECLARE
#elif defined(XDFA_IMPLEMENT_NEXTSTATE_FUNCTION)
int rLANGAPI XDFA_IMPLEMENT_NEXTSTATE_FUNCTION(XDFA_WSCANNER_PTR self, int reason)
#endif /* XDFA_IMPLEMENT_NEXTSTATE_FUNCTION_DECLARE */

#ifdef XDFA_IMPLEMENT_NEXTSTATE_FUNCTION
{
	int YYC , YYLEN , ACTION , RESULT = -1;

XULIB_SPECIFIC_BLOCK_BEGIN
#ifdef XDFA_IMPLEMENT_NEXTSTATE_FUNCTION_USERCODE
	XDFA_IMPLEMENT_NEXTSTATE_FUNCTION_USERCODE
#undef XDFA_IMPLEMENT_NEXTSTATE_FUNCTION_USERCODE
#endif /* XDFA_IMPLEMENT_NEXTSTATE_FUNCTION_USERCODE */
	;;
XULIB_SPECIFIC_BLOCK_BEGIN
	switch(reason)
	{
	case XDFA_RESUME_NIL:
		self->f_current = self->f_start + (self->f_flags & XDFA_FLAGS_BOL);
		if(NULL == self->X_text_end)
			self->X_text_end = self->X_buffer_begin;
		self->X_text = self->X_text_end;
		break;
	case XDFA_RESUME_READ_DATA:
		XULIB_ASSERT(self->X_input_end <= self->X_buffer_end);
		XULIB_ASSERT(self->X_buffer_begin == self->X_text);
		break;
	default:
	case XDFA_RESUME_EXTEND_BUFFER:
		XULIB_ASSERT(reason == XDFA_RESUME_EXTEND_BUFFER);
		break;
	}

_XDFA_MACHINE_HANDLE(X_on_GetNextState)
	{
		if(XULIB_UNLIKELY(self->X_text_end >= self->X_input_end))	/* EOB */
		{
			if(self->X_text == self->X_text_end)	/* NIL */
			{
				if(self->f_flags & XDFA_FLAGS_EOF)
					_XDFA_MACHINE_GOTO_label(X_on_EndOfFile);

				self->X_input_end = self->X_text = self->X_text_end = self->X_buffer_begin;
				_XDFA_MACHINE_GOTO_label(X_on_ReadMoreInput);
			}
			else if(self->f_flags & XDFA_FLAGS_EOF)
				_XDFA_MACHINE_GOTO_label(X_on_FindAction);
			else if(self->X_text == self->X_buffer_begin)
			{
				if(self->X_input_end == self->X_buffer_end)
					_XDFA_MACHINE_GOTO_label(X_on_ExtendBuffer);
				else
					_XDFA_MACHINE_GOTO_label(X_on_ReadMoreInput);
			}
			else
			{
				YYLEN = (int)(self->X_text_end - self->X_text);
				memmove(self->X_buffer_begin , self->X_text , YYLEN * sizeof(*self->X_text));
				self->X_text = self->X_buffer_begin;
				self->X_text_end = self->X_input_end = self->X_buffer_begin + YYLEN;
				_XDFA_MACHINE_GOTO_label(X_on_ReadMoreInput);
			}	
		}
		else
		{
#ifdef XDFA_SCANNER_READ_NEXT_INPUT
			XDFA_SCANNER_READ_NEXT_INPUT
				;;
#undef XDFA_SCANNER_READ_NEXT_INPUT
#else	/* XDFA_SCANNER_READ_NEXT_INPUT */
      YYC = *self->X_text_end;

      if (YYC >= YY_CHARSIZ || YYC < 0)
        YYC = YY_CHARNIL;
      else
        YYC = _XDFAM_STATE_get(yy_ec, YYC);
#endif	/* XDFA_SCANNER_READ_NEXT_INPUT */
		}

		if(_XDFAM_STATE_get(yy_accept, self->f_current))
		{
			self->f_backup = self->f_current;
			self->f_pos_accepted = (int)(self->X_text_end - self->X_text);
		}

		while(_XDFAM_STATE_get(yy_chk, _XDFAM_STATE_get(yy_base, self->f_current) + YYC) != self->f_current )
		{
			if( ( self->f_current= _XDFAM_STATE_get(yy_def, self->f_current)) >= YY_LASTDFA + 2 )
				YYC = _XDFAM_STATE_get(yy_meta, YYC);
		}
		self->f_current = _XDFAM_STATE_get(yy_nxt, _XDFAM_STATE_get(yy_base, self->f_current) + YYC);

#ifdef XDFA_SCANNER_SET_NEXT_INPUT
		{
			XDFA_SCANNER_SET_NEXT_INPUT
				;;
		}
#undef XDFA_SCANNER_SET_NEXT_INPUT
#else	/* XDFA_SCANNER_SET_NEXT_INPUT */
		if(self->X_text_end < self->X_input_end)
			++self->X_text_end;
#endif	/* XDFA_SCANNER_SET_NEXT_INPUT */

		if(_XDFAM_STATE_get(yy_base, self->f_current) == YY_JAMBASE)
		{
_XDFA_MACHINE_HANDLE(X_on_FindAction)
			ACTION = _XDFAM_STATE_get(yy_accept, self->f_current);

#ifndef XDFA_IMPLEMENT_FAST_FORWARD__
			if(0 == ACTION)
			{
				self->f_current  = self->f_backup;
				self->X_text_end = self->f_pos_accepted + self->X_text;
				ACTION = _XDFAM_STATE_get(yy_accept, self->f_current);
			}
#else  /* XDFA_IMPLEMENT_FAST_FORWARD__ */
		XDFA_IMPLEMENT_FAST_FORWARD__
				;;
#undef XDFA_IMPLEMENT_FAST_FORWARD__
#endif /* XDFA_IMPLEMENT_FAST_FORWARD__ */

		RESULT = ACTION;

#ifdef _XDFA_SCANNER_ACTION_DECLARE_FILE_
			switch(ACTION)
			{
#include _XDFA_SCANNER_ACTION_DECLARE_FILE_
			default:
				_XDFA_MACHINE_GOTO_label(X_on_NextMatch);
				break;
			}
			_XDFA_MACHINE_GOTO_label(X_on_NextMatch);
#elif  defined(_XDFA_MACHINE_ON_ACTION)
			XULIB_SPECIFIC_BLOCK_BEGIN
				_XDFA_MACHINE_ON_ACTION(RESULT, ACTION, self , _XDFA_MACHINE_GOTO_label(X_on_ReturnAction), _XDFA_MACHINE_GOTO_label(X_on_NextMatch) )
				;;
			XULIB_SPECIFIC_BLOCK_END
#endif /* _XDFA_MACHINE_ON_ACTION */
			_XDFA_MACHINE_GOTO_label(X_on_ReturnAction);
			_XDFA_MACHINE_GOTO_label(X_on_NextMatch);
_XDFA_MACHINE_HANDLE(X_on_NextMatch)
			self->f_current = self->f_start + (self->f_flags & XDFA_FLAGS_BOL);
 			self->X_text = self->X_text_end;
		}
	}
	_XDFA_MACHINE_GOTO_label(X_on_GetNextState);

_XDFA_MACHINE_HANDLE(X_on_ReturnAction)	
	_XDFA_MACHINE_GOTO_label(X_on_FinalReturn);

_XDFA_MACHINE_HANDLE(X_on_EndOfFile)
	RESULT = XDFA_RESULT_EOF;
	_XDFA_MACHINE_GOTO_label(X_on_FinalReturn);

_XDFA_MACHINE_HANDLE(X_on_ReadMoreInput)
	RESULT = XDFA_RESULT_PENDING_MORE_INPUT;
	_XDFA_MACHINE_GOTO_label(X_on_FinalReturn);

_XDFA_MACHINE_HANDLE(X_on_ExtendBuffer)
	RESULT = XDFA_RESULT_PENDING_EXTEND_BUFFER;
	_XDFA_MACHINE_GOTO_label(X_on_FinalReturn);

_XDFA_MACHINE_HANDLE(X_on_FinalReturn)
	return RESULT;

XULIB_SPECIFIC_BLOCK_END
XULIB_SPECIFIC_BLOCK_END
}
#endif /* XDFA_IMPLEMENT_NEXTSTATE_FUNCTION */
#undef _XDFA_MACHINE_ON_ACTION
#undef _XDFA_SCANNER_ACTION_DECLARE_FILE_
#undef XDFA_IMPLEMENT_NEXTSTATE_FUNCTION
#undef _XDFA_YYUNDEFCHAR
#undef _XDFA_MACHINE_GOTO_label
#undef _XDFA_MACHINE_HANDLE
#undef _XDFAM_STATE_get

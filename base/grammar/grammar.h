#pragma once

#ifndef __WTINC_GRAMMAR_GRAMMAR_H__
#define __WTINC_GRAMMAR_GRAMMAR_H__

#ifndef ___WTINC_BITS_BASE_H__
#include "../base.h" /* */
#endif /* ___WTINC_BITS_BASE_H__ */

rLANG_DECLARE_MACHINE

#define XULIB_ASSERT(expr)												assert(expr)
#define XULIB_UNLIKELY(expr)											rLANG_UNLIKELY(expr)

#ifndef XULIB_ERROR_PRINTK
#define XULIB_ERROR_PRINTK(fmt, ...)							rlLOGE(TAG, (fmt), ##__VA_ARGS__)
#endif /* XULIB_ERROR_PRINTK */

#ifndef XULIB_GRAMMAR_ERROR_OUTPUT
#if defined(X_ARCH_wasm) && defined(rLANG_CONFIG_MINIMAL)
rLANGIMPORT void jsGrammar_yyError(const char* prefix, const char* symbol) \
	__attribute__((__import_module__("rLANG"), __import_name__("jsGrammar_yyError")));
#define XULIB_GRAMMAR_ERROR_OUTPUT(prefix, symbol)	jsGrammar_yyError(prefix, symbol)
#elif defined(rLANG_CONFIG_MINIMAL)
#define XULIB_GRAMMAR_ERROR_OUTPUT(prefix, symbol)	fprintf(stderr, prefix " %s\n", symbol)
#else  /* rLANG_CONFIG_uNiAPI_MINIMAL */
#define XULIB_GRAMMAR_ERROR_OUTPUT(prefix, symbol)	XULIB_ERROR_PRINTK(prefix " %s", symbol)
#endif /* rLANG_CONFIG_uNiAPI_MINIMAL */
#endif /* XULIB_GRAMMAR_ERROR_OUTPUT */

#ifndef XULIB_TRACE
#define XULIB_TRACE(args)													((void)0)
#endif /* XULIB_TRACE */

#define XULIB_SPECIFIC_BLOCK_BEGIN								{{
#define XULIB_SPECIFIC_BLOCK_END									}}


#ifndef XDFA_SCANNER_resumeX
#define XDFA_SCANNER_resumeX(am,reason)						((am)->X_machine((am) , (reason)))
#endif /* XDFA_SCANNER_resumeX */

#define XDFA_SCANNER_resume(am)										XDFA_SCANNER_resumeX(am, XDFA_RESUME_NIL)
#define XDFA_SCANNER_resume_input(am)							XDFA_SCANNER_resumeX(am, XDFA_RESUME_READ_DATA)
#define XDFA_SCANNER_resume_buffer(am)						XDFA_SCANNER_resumeX(am, XDFA_RESUME_EXTEND_BUFFER)


#ifndef XDPDA_GRAMMAR_RESUME_X
#define XDPDA_GRAMMAR_RESUME_X(self,reason,value)		((self)->X_machine((self), (reason), (value)))
#endif /* XDPDA_GRAMMAR_RESUME_X */

#define XDPDA_GRAMMAR_INITIALIZE(self)						XDPDA_GRAMMAR_RESUME_X(self, XDPDA_RESUME_INITIALIZE, NULL)
#define XDPDA_GRAMMAR_INPUT_0(self, lexin)				XDPDA_GRAMMAR_RESUME_X(self, lexin, NULL)
#define XDPDA_GRAMMAR_INPUT_1(self, lexin, value)	XDPDA_GRAMMAR_RESUME_X(self, lexin, value)
#define XDPDA_GRAMMAR_INPUT_EOF(self)							XDPDA_GRAMMAR_RESUME_X(self, XDPDA_YYEOF, NULL)
#define XDPDA_GRAMMAR_RESUME_REDUCE(self)					XDPDA_GRAMMAR_RESUME_X(self, XDPDA_RESUME_REDUCE, NULL)
#define XDPDA_GRAMMAR_RESUME_EXTENDSTACK(self)		XDPDA_GRAMMAR_RESUME_X(self, XDPDA_RESUME_EXTEND_STACK, NULL)
#define XDPDA_GRAMMAR_RESUME_SYNTAX_ERROR(self)		XDPDA_GRAMMAR_RESUME_X(self, XDPDA_RESUME_SYNTAX_ERROR, NULL)
#define XDPDA_GRAMMAR_YYACCEPT(self)							XDPDA_GRAMMAR_RESUME_X(self, XDPDA_RESUME_YYACCEPT, NULL)
#define XDPDA_GRAMMAR_YYERROR(self)								XDPDA_GRAMMAR_RESUME_X(self, XDPDA_RESUME_YYERROR , NULL)
#define XDPDA_GRAMMAR_YYABORT(self)								XDPDA_GRAMMAR_RESUME_X(self, XDPDA_RESUME_YYABORT , NULL)

#ifndef _XDPDA_YYVALUE_COPY
#define _XDPDA_YYVALUE_COPY( __dst__ , __src_ptr__ )		( (__dst__) = *(__src_ptr__) )
#endif /* _XDPDA_YYVALUE_COPY */

#ifndef _XDPDA_YYVALUE_INIT
#define _XDPDA_YYVALUE_INIT( __var__ )									((__var__) = 0)
#endif /* _XDPDA_YYVALUE_INIT */

#define XDPDA_GRAMMAR_EXTEND_STACK(XDPDA_YYVALUE, _xdpda_lv_self, stacksize, ssa, vsa)	\
		do {	\
			short*	  _xdpda_lv_new_ssa = (short*)(ssa);				\
			XDPDA_YYVALUE*	_xdpda_lv_new_vsa = (XDPDA_YYVALUE*)(vsa);	\
			int		  off_yyss  = _xdpda_lv_self->f_yyss  - _xdpda_lv_self->f_yyssa ,	\
			off_yyssp = _xdpda_lv_self->f_yyssp - _xdpda_lv_self->f_yyssa ,	\
			off_yyvs  = _xdpda_lv_self->f_yyvs  - _xdpda_lv_self->f_yyvsa ,	\
			off_yyvsp = _xdpda_lv_self->f_yyvsp - _xdpda_lv_self->f_yyvsa;	\
			_xdpda_lv_self->f_yystacksize = stacksize;					\
			_xdpda_lv_self->f_yyssa = _xdpda_lv_new_ssa;				\
			_xdpda_lv_self->f_yyss = _xdpda_lv_new_ssa + off_yyss;		\
			_xdpda_lv_self->f_yyssp = _xdpda_lv_new_ssa + off_yyssp;	\
			_xdpda_lv_self->f_yyvsa = _xdpda_lv_new_vsa;				\
			_xdpda_lv_self->f_yyvs = _xdpda_lv_new_vsa + off_yyvs;		\
			_xdpda_lv_self->f_yyvsp = _xdpda_lv_new_vsa + off_yyvsp;	\
		} while(0)

rLANG_DECLARE_END

#endif /* __WTINC_GRAMMAR_GRAMMAR_H__ */

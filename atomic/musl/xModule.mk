LOCAL_PATH := $(my-dir)

rLANG_MUSL_ROOT := $(wORLD_ROOT)/third_party/musl

$(call clear-local-vars)

##
## musl 编译起来警告有点多 ...
##
LOCAL_STRICT := 0

LOCAL_MODULE := musl

LOCAL_CFLAGS  := \
    -I$(LOCAL_PATH)/musl-build-local/internal \
    -I$(rLANG_MUSL_ROOT)/src/internal \
    -I$(rLANG_MUSL_ROOT)/src/include  \
    \
    \
    -Wno-unused-parameter           \
    -Wno-unused-value               \
    -Wno-parentheses                \
    -Wno-sign-compare               \
    -Wno-implicit-fallthrough       \
    -Wno-maybe-uninitialized        \
    -Wno-dangling-pointer           \
    -Wno-unused-but-set-variable    \
    -Wno-unknown-pragmas

LOCAL_CFLAGS  += -D_XOPEN_SOURCE=700

##
## <string.h>
##
MUSL_ALL_STRING_FILES := \
    bcmp.c stpncpy.c strcspn.c strncmp.c strspn.c wcscasecmp.c wcslen.c wcsrchr.c wmemmove.c                    \
    bcopy.c memmem.c strcasecmp.c strdup.c strncpy.c strstr.c wcscasecmp_l.c wcsncasecmp.c wcsspn.c wmemset.c   \
    bzero.c memmove.c strcasestr.c strerror_r.c strndup.c strtok.c wcscat.c wcsncasecmp_l.c wcsstr.c            \
    explicit_bzero.c mempcpy.c strcat.c strlcat.c strnlen.c strtok_r.c wcschr.c wcsncat.c wcstok.c              \
    index.c memrchr.c strchr.c strlcpy.c strpbrk.c strverscmp.c wcscmp.c wcsncmp.c wcswcs.c                     \
    memccpy.c strchrnul.c strlen.c strrchr.c swab.c wcscpy.c wcsncpy.c wmemchr.c                                \
    memchr.c rindex.c strcmp.c strncasecmp.c strsep.c wcpcpy.c wcscspn.c wcsnlen.c wmemcmp.c                    \
    memcmp.c stpcpy.c strcpy.c strncat.c strsignal.c wcpncpy.c wcsdup.c wcspbrk.c wmemcpy.c

##
## <ctype.h>
##
MUSL_ALL_CTYPE_FILES := \
    __ctype_b_loc.c isblank.c isspace.c iswdigit.c iswxdigit.c wctrans.c            \
    __ctype_get_mb_cur_max.c iscntrl.c isupper.c iswgraph.c isxdigit.c wcwidth.c    \
    __ctype_tolower_loc.c isdigit.c iswalnum.c iswlower.c toascii.c     \
    __ctype_toupper_loc.c isgraph.c iswalpha.c iswprint.c tolower.c     \
    isalnum.c islower.c iswblank.c iswpunct.c toupper.c     \
    isalpha.c isprint.c iswcntrl.c iswspace.c towctrans.c   \
    isascii.c ispunct.c iswctype.c iswupper.c wcswidth.c

##
## <stdlib.h>
##
MUSL_ALL_STDLIB_FILES := \
    abs.c atoi.c atoll.c div.c fcvt.c imaxabs.c labs.c llabs.c qsort.c strtod.c wcstod.c atof.c \
    atol.c bsearch.c ecvt.c gcvt.c imaxdiv.c ldiv.c lldiv.c qsort_nr.c strtol.c wcstol.c

##
## <stdio.h>
##
MUSL_ALL_STDIO_FILES := \
    __fclose_ca.c __uflow.c fgetwc.c fscanf.c getchar_unlocked.c printf.c setbuf.c tmpnam.c vswprintf.c     \
    __fdopen.c asprintf.c fgetws.c fseek.c getdelim.c putc.c setbuffer.c ungetc.c vswscanf.c                \
    __fmodeflags.c clearerr.c fileno.c fsetpos.c getline.c putc.h setlinebuf.c ungetwc.c vwprintf.c         \
    __fopen_rb_ca.c dprintf.c flockfile.c ftell.c gets.c putc_unlocked.c setvbuf.c vasprintf.c vwscanf.c    \
    __lockfile.c ext.c fmemopen.c ftrylockfile.c getw.c putchar.c snprintf.c vdprintf.c wprintf.c           \
    __overflow.c ext2.c fopen.c funlockfile.c getwc.c putchar_unlocked.c sprintf.c vfprintf.c wscanf.c      \
    __stdio_close.c fclose.c fopencookie.c fwide.c getwchar.c puts.c sscanf.c vfscanf.c         \
    __stdio_exit.c feof.c fprintf.c fwprintf.c ofl.c putw.c stderr.c vfwprintf.c                \
    __stdio_read.c ferror.c fputc.c fwrite.c ofl_add.c putwc.c stdin.c vfwscanf.c               \
    __stdio_seek.c fflush.c fputs.c fwscanf.c open_memstream.c putwchar.c stdout.c vprintf.c    \
    __stdio_write.c fgetc.c fputwc.c getc.c open_wmemstream.c remove.c swprintf.c vscanf.c      \
    __stdout_write.c fgetln.c fputws.c getc.h pclose.c rename.c swscanf.c vsnprintf.c           \
    __toread.c fgetpos.c fread.c getc_unlocked.c perror.c rewind.c tempnam.c vsprintf.c         \
    __towrite.c fgets.c freopen.c getchar.c popen.c scanf.c tmpfile.c vsscanf.c

##
## rand/srand
##
MUSL_ALL_PRNG_FILES := \
    __rand48_step.c __seed48.c drand48.c lcong48.c lrand48.c mrand48.c rand.c rand_r.c random.c seed48.c srand48.c

##
## <math.h>
##
MUSL_ALL_MATH_FILES := \
    __cos.c __rem_pio2l.c atan2f.c erfl.c floorf.c j0f.c log1p.c nanf.c rintl.c sqrt.c              \
    __cosdf.c __signbit.c atan2l.c exp.c floorl.c j1.c log1pf.c nanl.c round.c sqrt_data.c          \
    __cosl.c __signbitf.c atanf.c exp_data.c fma.c j1f.c log1pl.c nearbyint.c roundf.c sqrtf.c      \
    __expo2.c __signbitl.c atanh.c exp10.c fmaf.c jn.c log2.c nearbyintf.c roundl.c sqrtl.c         \
    __expo2f.c __sin.c atanhf.c exp10f.c fmal.c jnf.c log2_data.c nearbyintl.c scalb.c tan.c        \
    __fpclassify.c __sindf.c atanhl.c exp10l.c fmax.c ldexp.c log2f.c nextafter.c scalbf.c tanf.c   \
    __fpclassifyf.c __sinl.c atanl.c exp2.c fmaxf.c ldexpf.c log2f_data.c nextafterf.c scalbln.c tanh.c     \
    __fpclassifyl.c __tan.c cbrt.c exp2f.c fmaxl.c ldexpl.c log2l.c nextafterl.c scalblnf.c tanhf.c         \
    __invtrigl.c __tandf.c cbrtf.c exp2f_data.c fmin.c lgamma.c logb.c nexttoward.c scalblnl.c tanhl.c      \
    __math_divzero.c __tanl.c cbrtl.c exp2l.c fminf.c lgamma_r.c logbf.c nexttowardf.c scalbn.c tanl.c      \
    __math_divzerof.c acos.c ceil.c expf.c fminl.c lgammaf.c logbl.c nexttowardl.c scalbnf.c tgamma.c       \
    __math_invalid.c acosf.c ceilf.c expl.c fmod.c lgammaf_r.c logf.c pow.c scalbnl.c tgammaf.c             \
    __math_invalidf.c acosh.c ceill.c expm1.c fmodf.c lgammal.c logf_data.c pow_data.c signgam.c tgammal.c  \
    __math_invalidl.c acoshf.c copysign.c expm1f.c fmodl.c llrint.c logl.c powf.c significand.c trunc.c     \
    __math_oflow.c acoshl.c copysignf.c expm1l.c frexp.c llrintf.c lrint.c powf_data.c significandf.c       \
    __math_oflowf.c acosl.c copysignl.c fabs.c frexpf.c llrintl.c lrintf.c powl.c sin.c truncl.c    \
    __math_uflow.c asin.c cos.c fabsf.c frexpl.c llround.c lrintl.c remainder.c sincos.c            \
    __math_uflowf.c asinf.c cosf.c fabsl.c hypot.c llroundf.c lround.c remainderf.c sincosf.c       \
    __math_xflow.c asinh.c cosh.c fdim.c hypotf.c llroundl.c lroundf.c remainderl.c sincosl.c       \
    __math_xflowf.c asinhf.c coshf.c fdimf.c hypotl.c log.c lroundl.c remquo.c sinf.c   \
    __polevll.c asinhl.c coshl.c fdiml.c ilogb.c log_data.c modf.c remquof.c sinh.c     \
    __rem_pio2.c asinl.c cosl.c finite.c ilogbf.c log10.c modff.c remquol.c sinhf.c     \
    __rem_pio2_large.c atan.c erf.c finitef.c ilogbl.c log10f.c modfl.c rint.c sinhl.c  \
    __rem_pio2f.c atan2.c erff.c floor.c j0.c log10l.c nan.c rintf.c sinl.c truncf.c

##
##
##
MUSL_ALL_FENV_FILES := \
    riscv32/fenv-sf.c riscv32/fenv.S

##
## Makefile Entry
##
$(foreach __file,$(MUSL_ALL_STRING_FILES),  \
    $(call add_general_source_files,        \
        $(rLANG_MUSL_ROOT)/src/string/$(__file)))

$(foreach __file,$(MUSL_ALL_CTYPE_FILES),   \
    $(call add_general_source_files,        \
        $(rLANG_MUSL_ROOT)/src/ctype/$(__file)))

$(foreach __file,$(MUSL_ALL_STDLIB_FILES),  \
    $(call add_general_source_files,        \
        $(rLANG_MUSL_ROOT)/src/stdlib/$(__file)))

$(foreach __file,$(MUSL_ALL_STDIO_FILES),   \
    $(call add_general_source_files,        \
        $(rLANG_MUSL_ROOT)/src/stdio/$(__file)))

$(foreach __file,$(MUSL_ALL_PRNG_FILES),    \
    $(call add_general_source_files,        \
        $(rLANG_MUSL_ROOT)/src/prng/$(__file)))

##
## 我们平台没有 FD 指令集, 后期所有的 libm 函数在 HOST 侧 op_GATE() 实现 ...
##
$(foreach __file,$(MUSL_ALL_MATH_FILES),    \
    $(call add_general_source_files,        \
        $(rLANG_MUSL_ROOT)/src/math/$(__file)))

$(foreach __file,$(MUSL_ALL_FENV_FILES),    \
    $(call add_general_source_files,        \
        $(rLANG_MUSL_ROOT)/src/fenv/$(__file)))


$(call build-library)


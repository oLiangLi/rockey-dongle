#pragma once

#ifndef ___WTINC_BITS_BASE_H__
#define ___WTINC_BITS_BASE_H__

#define rLANG_VERSION_MAJOR 4
#define rLANG_VERSION_MINOR 10
#define rLANG_VERSION_RELEASE 100

#define rLANG_VERSION() (((rLANG_VERSION_MAJOR) << 24) | ((rLANG_VERSION_MINOR) << 16) | (rLANG_VERSION_RELEASE))

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4996 4127 4201)
#endif /* _MSC_VER */

#if !defined(rLANG_ABIREQUIRE) && !defined(__cplusplus)
#define rLANG_ABIREQUIRE(expr, ...) extern void rLANG_ABIREQUIRE__(int argv[(expr) ? 1 : -1])
#elif !defined(rLANG_ABIREQUIRE)
#define rLANG_ABIREQUIRE(expr, ...) static_assert(expr, #expr)
#endif /* rLANG_ABIREQUIRE */

#if !defined(rLANG_DECLARE_MACHINE) && defined(__cplusplus)
#define rLANG_DECLARE_MACHINE namespace machine {
#define rLANG_DECLARE_END }
#elif !defined(rLANG_DECLARE_MACHINE)
#define rLANG_DECLARE_MACHINE
#define rLANG_DECLARE_END
#endif /* rLANG_DECLARE_MACHINE */

#if !defined(rLANG_LIKELY) && (defined(__GNUC__) || defined(__clang__))
#define rLANG_LIKELY(x) (__builtin_expect(!!(x), 1))
#elif !defined(rLANG_LIKELY)
#define rLANG_LIKELY(x) (x)
#endif /* rLANG_LIKELY */

#if !defined(rLANG_UNLIKELY) && (defined(__GNUC__) || defined(__clang__))
#define rLANG_UNLIKELY(x) (__builtin_expect(!!(x), 0))
#elif !defined(rLANG_UNLIKELY)
#define rLANG_UNLIKELY(x) (x)
#endif /* rLANG_UNLIKELY */

#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(WIN32) && !defined(_WIN32)
#define _WIN32
#endif /* _WIN32 */

#if defined(WIN64) && !defined(_WIN64)
#define _WIN64
#endif /* _WIN64 */

#ifdef __EMSCRIPTEN__
#include <emscripten/emscripten.h>
#endif /* __EMSCRIPTEN__ */

rLANG_DECLARE_MACHINE

/**
 *!
 */
#ifndef rLANG_WORLD_MAGIC                        /* "rLANG" */
#define rLANG_WORLD_MAGIC ((uint32_t)0xC8C04E1F) /* DRAM: ~8KB   */
#endif                                           /* rLANG_WORLD_MAGIC */

#ifndef rLANG_ATOMC_WORLD_MAGIC                                           /* "ATOMC" */
#define rLANG_ATOMC_WORLD_MAGIC ((uint32_t)0x0543CD0F) /* DRAM: ~640KB */ /* 640K Ought to be Enough for Anyone */
#endif                                                                    /* rLANG_ROBOT_WORLD_MAGIC */

#ifndef rLANG_uNiAPI_WORLD_MAGIC                        /* "$uNi@" */
#define rLANG_uNiAPI_WORLD_MAGIC ((uint32_t)0xFF53A903) /* DRAM: ~32768K  */
#endif                                                  /* rLANG_uNiAPI_WORLD_MAGIC */

#ifndef rLANG_CHROM_WORLD_MAGIC                        /* "CHROM" */
#define rLANG_CHROM_WORLD_MAGIC ((uint32_t)0x0C848F37) /* DRAM: ~1TB     */
#endif                                                 /* rLANG_CHROM_WORLD_MAGIC  */

#ifndef rLANG_GOOGO_WORLD_MAGIC                        /* "GOOGO" */
#define rLANG_GOOGO_WORLD_MAGIC ((uint32_t)0x1CF3C73F) /* DRAM: ~10**100 */
#endif                                                 /* rLANG_GOOGO_WORLD_MAGIC */

#ifndef rLANG_COSMO_WORLD_MAGIC                        /* "COSMO" */
#define rLANG_COSMO_WORLD_MAGIC ((uint32_t)0x0CF4CD3F) /* DRAM: ~TREE(3) */
#endif                                                 /* rLANG_COSMO_WORLD_MAGIC */

/**
 *!
 */
#ifndef rLANG_STRINGIFY
#define rLANG_STRINGIFY(v) #v
#endif /* rLANG_STRINGIFY */

/**
 *!
 */
#define rLANG_S_OK (0)
#define rLANG_S_FALSE (1)
#define rLANG_E_CLASSNOTFOUND ((int32_t)0xC8C00404) /* 404 Not Found             */
#define rLANG_E_EXECEPTION ((int32_t)0xC8C00500)    /* 500 Internal Server Error */
#define rLANG_E_NOINTERFACE ((int32_t)0xC8C00501)   /* 501 Not Implemented       */
#define rLANG_E_UNAVAILABLE ((int32_t)0xC8C00503)   /* 503 Service Unavailable   */
#define rLANG_E_WOULDBLOCK ((int32_t)0xC8C00100)    /* 100 Continue              */

/**
 *!
 */
#if !defined(rLANGALIGN) && (defined(_MSC_VER) && !defined(__clang__))
#define rLANGALIGN(n) __declspec(align(n))
#elif !defined(rLANGALIGN)
#define rLANGALIGN(n) __attribute__((aligned(n)))
#endif /* rLANGALIGN */

/**
 *!
 */
#if !defined(rLANGAPI) && defined(_MSC_VER)
#define rLANGAPI __fastcall
#elif !defined(rLANGAPI) && defined(__GNUC__) && defined(__i386__)
#define rLANGAPI __attribute__((fastcall))
#elif !defined(rLANGAPI) && defined(__clang__) && defined(__i386__)
#define rLANGAPI __fastcall
#endif /* rLANGAPI */

#if !defined(rLANGNOVTBL) && defined(_MSC_VER)
#define rLANGNOVTBL __declspec(novtable)
#elif !defined(rLANGNOVTBL)
#define rLANGNOVTBL
#endif /* rLANGNOVTBL */

#ifndef rLANGAPI
#define rLANGAPI
#endif /* rLANGAPI */

/**
 *!
 */
#if defined(_MSC_VER) && !defined(__clang__) && !defined(__attribute__)
#define __attribute__(__name__)
#endif /* !defined(__attribute__) */

#if !defined(rLANGCXXONLY) && defined(__cplusplus)
#define rLANGCXXONLY(__code__) __code__
#elif !defined(rLANGCXXONLY)
#define rLANGCXXONLY(__code__)
#endif /* rLANGCXXONLY */

#if !defined(rLANGCONSTEXPR) && defined(__cplusplus)
#define rLANGCONSTEXPR constexpr
#elif !defined(rLANGCONSTEXPR)
#define rLANGCONSTEXPR
#endif /* rLANGCONSTEXPR */

#ifndef rLANGEXPORT_
#define rLANGEXPORT_
#endif /* rLANGEXPORT_ */

#ifndef rLANGIMPORT_
#define rLANGIMPORT_
#endif /* rLANGIMPORT_ */

#ifndef rlBASECC_INLINE
#define rlBASECC_INLINE static rLANGCONSTEXPR inline
#endif /* rlBASECC_INLINE */

#ifndef rlBASE_INLINE
#define rlBASE_INLINE static inline
#endif /* rlBASE_INLINE */

/**
 *!
 */
#ifndef rLANG_MODULE_EXTERN
#define rLANG_MODULE_EXTERN extern rLANGCXXONLY("C")
#endif /* rLANG_MODULE_EXTERN */

#ifndef rLANGEXPORT
#define rLANGEXPORT rLANGEXPORT_ rLANG_MODULE_EXTERN
#endif /* rLANGEXPORT */

#ifndef rLANGIMPORT
#define rLANGIMPORT rLANGIMPORT_ rLANG_MODULE_EXTERN
#endif /* rLANGIMPORT */

#ifndef rLANGEXPORTWEAK
#define rLANGEXPORTWEAK rLANGEXPORT __attribute__((weak))
#endif /* rLANGEXPORTWEAK */

#if !defined(rLANGWASMEXPORT) && defined(__EMSCRIPTEN__)
#define rLANGWASMEXPORT rLANGEXPORT EMSCRIPTEN_KEEPALIVE
#elif !defined(rLANGWASMEXPORT)
#define rLANGWASMEXPORT rLANGEXPORT
#endif /* rLANGWASMEXPORT */

#if !defined(rLANGWASMIMPORT) && defined(__EMSCRIPTEN__) && defined(rLANG_WORLD_STANDALONE)
#define rLANGWASMIMPORT(type, name, args, body, libn, func) \
  rLANGIMPORT type rLANGAPI name args __attribute__((__import_module__(libn), __import_name__(func)));
#elif !defined(rLANGWASMIMPORT) && defined(__EMSCRIPTEN__) && !defined(rLANG_WORLD_STANDALONE)
#define rLANGWASMIMPORT(type, name, args, body, libn, func) rLANGEXPORT type rLANGAPI name args body
#elif !defined(rLANGWASMIMPORT)
#define rLANGWASMIMPORT(type, name, args, body, libn, func)
#endif /* rLANGWASMIMPORT */

#if defined(NDEBUG) && !defined(rLANG_RELEASE) && !defined(rLANG_DEBUG)
#define rLANG_RELEASE
#elif !defined(rLANG_RELEASE)
#define rLANG_DEBUG
#endif /* rLANG_RELEASE || rLANG_DEBUG */

/**
 *!
 */
#ifndef rLANG_DECLARE_HANDLE
#define rLANG_DECLARE_HANDLE(NAME) \
  typedef struct {                 \
    int j__none_of_your_bussiness; \
  } NAME##__, *NAME
#endif /* rLANG_DECLARE_HANDLE */

#ifndef rLANG_DECLARE_PRIVATE_CONTEXT
#define rLANG_DECLARE_PRIVATE_CONTEXT(NAME, SIZE)                          \
  typedef struct {                                                         \
    uint64_t j__none_of_your_bussiness[1 + ((SIZE)-1) / sizeof(uint64_t)]; \
  } NAME
#endif /* rLANG_DECLARE_PRIVATE_CONTEXT */

/* rlCipherSuiteV0: [SHA1 [*N/A*]]/SHA256/SHA384/SHA512/X25519/ED25519/CHACHA20/POLY1305 */
rLANG_DECLARE_PRIVATE_CONTEXT(rlCryptoShaCtx, 240);
rLANG_DECLARE_PRIVATE_CONTEXT(rlCryptoChaCha20Ctx, 144);
rLANG_DECLARE_PRIVATE_CONTEXT(rlCryptoPoly1305Ctx, 80);
rLANG_DECLARE_PRIVATE_CONTEXT(rlCryptoChaChaPolyCtx, 256);

/* for dongle */
rLANGEXPORT void rLANGAPI rlCryptoEd25519PubkeyEx(uint8_t out_public_key[32], const uint8_t az_[32]);

/* Definite output, only related to seedBytes/randBytes calls  */
rLANGEXPORT void rLANGAPI rlCryptoRandBytes(void* p, int size);
rLANGEXPORT void rLANGAPI rlCryptoSeedBytes(const void* p, int size);

rLANGEXPORT void rLANGAPI rlCryptoSha1CtxInit(rlCryptoShaCtx* ctx);
rLANGEXPORT void rLANGAPI rlCryptoSha1CtxUpdate(rlCryptoShaCtx* ctx, const void* data, int len);
rLANGEXPORT int rLANGAPI rlCryptoSha1CtxFinal(rlCryptoShaCtx* ctx, uint8_t md[20]);

rLANGEXPORT void rLANGAPI rlCryptoSha256CtxInit(rlCryptoShaCtx* ctx);
rLANGEXPORT void rLANGAPI rlCryptoSha256CtxUpdate(rlCryptoShaCtx* ctx, const void* data, int len);
rLANGEXPORT int rLANGAPI rlCryptoSha256CtxFinal(rlCryptoShaCtx* ctx, uint8_t md[32]);

rLANGEXPORT void rLANGAPI rlCryptoSha384CtxInit(rlCryptoShaCtx* ctx);
rLANGEXPORT void rLANGAPI rlCryptoSha384CtxUpdate(rlCryptoShaCtx* ctx, const void* data, int len);
rLANGEXPORT int rLANGAPI rlCryptoSha384CtxFinal(rlCryptoShaCtx* ctx, uint8_t md[48]);

rLANGEXPORT void rLANGAPI rlCryptoSha512CtxInit(rlCryptoShaCtx* ctx);
rLANGEXPORT void rLANGAPI rlCryptoSha512CtxUpdate(rlCryptoShaCtx* ctx, const void* data, int len);
rLANGEXPORT int rLANGAPI rlCryptoSha512CtxFinal(rlCryptoShaCtx* ctx, uint8_t md[64]);

rLANGEXPORT int rLANGAPI rlCryptoEd25519Verify(const void* message,
                                               int message_len,
                                               const uint8_t signature[64],
                                               const uint8_t public_key[32]);
rLANGEXPORT void rLANGAPI rlCryptoEd25519Pubkey(uint8_t out_public_key[32], const uint8_t private_key[32]);
rLANGEXPORT void rLANGAPI rlCryptoEd25519Sign(uint8_t out_sig[64],
                                              const void* message,
                                              int message_len,
                                              const uint8_t public_key[32],
                                              const uint8_t private_key[32]);
rLANGEXPORT void rLANGAPI rlCryptoX25519(uint8_t out_shared_key[32],
                                         const uint8_t private_key[32],
                                         const uint8_t peer_public_value[32]);
rLANGEXPORT void rLANGAPI rlCryptoX25519Pubkey(uint8_t out_public_value[32], const uint8_t private_key[32]);

rLANGEXPORT void rLANGAPI rlCryptoChaCha20Init(rlCryptoChaCha20Ctx* ctx);
rLANGEXPORT void rLANGAPI rlCryptoChaCha20SetKey(rlCryptoChaCha20Ctx* ctx, const uint8_t key[32]);
rLANGEXPORT void rLANGAPI rlCryptoChaCha20Starts(rlCryptoChaCha20Ctx* ctx, const uint8_t nonce[12], uint32_t counter);
rLANGEXPORT void rLANGAPI rlCryptoChaCha20Update(rlCryptoChaCha20Ctx* ctx,
                                                 const void* input,
                                                 void* output,
                                                 size_t size);
rLANGEXPORT void rLANGAPI rlCryptoChaCha20Block(const uint32_t state[16], uint8_t stream[64]);

rLANGEXPORT void rLANGAPI rlCryptoPoly1305Init(rlCryptoPoly1305Ctx* ctx);
rLANGEXPORT void rLANGAPI rlCryptoPoly1305Starts(rlCryptoPoly1305Ctx* ctx, const uint8_t key[32]);
rLANGEXPORT void rLANGAPI rlCryptoPoly1305Update(rlCryptoPoly1305Ctx* ctx, const void* input, size_t size);
rLANGEXPORT void rLANGAPI rlCryptoPoly1305Finish(rlCryptoPoly1305Ctx* ctx, uint8_t mac[16]);

rLANGEXPORT void rLANGAPI rlCryptoChaChaPolyInit(rlCryptoChaChaPolyCtx* ctx);
rLANGEXPORT void rLANGAPI rlCryptoChaChaPolySetKey(rlCryptoChaChaPolyCtx* ctx, const uint8_t key[32]);
rLANGEXPORT void rLANGAPI rlCryptoChaChaPolyStarts(rlCryptoChaChaPolyCtx* ctx, const uint8_t nonce[12], int encrypt);
rLANGEXPORT void rLANGAPI rlCryptoChaChaPolyUpdateAAd(rlCryptoChaChaPolyCtx* ctx, const void* aad, size_t alen);
rLANGEXPORT void rLANGAPI rlCryptoChaChaPolyUpdate(rlCryptoChaChaPolyCtx* ctx,
                                                   const void* input,
                                                   void* output,
                                                   size_t size);
rLANGEXPORT void rLANGAPI rlCryptoChaChaPolyFinish(rlCryptoChaChaPolyCtx* ctx, uint8_t mac[16]);

/**
 *!
 */
rLANGEXPORT int rLANGAPI rl_HEX_Read(uint8_t* zOUT, const char* zIN, int zLEN);
rLANGEXPORT int rLANGAPI rl_HEX_Write(char* zOUT, const uint8_t* zIN, int zLEN);
rLANGEXPORT int rLANGAPI rl_BASE64_Read(uint8_t* zOUT, const char* zIN, int zLEN);
rLANGEXPORT int rLANGAPI rl_BASE64_Write(char* zOUT, const uint8_t* zIN, int zLEN);
rLANGEXPORT int rLANGAPI rl_BASE64Url_Read(uint8_t* zOUT, const char* zIN, int zLEN);
rLANGEXPORT int rLANGAPI rl_BASE64Url_Write(char* zOUT, const uint8_t* zIN, int zLEN);

#ifndef rLANG_DECLARE_MAGIC_X
#define rLANG_DECLARE_MAGIC_X(a0, a1, a2, a3, a4)                                                              \
  ((((uint32_t)((0x3F & (a0))) << 26) | ((0x3F & (a1)) << 20) | ((0x3F & (a2)) << 14) | ((0x3F & (a3)) << 8) | \
    ((0x3F & (a4)) << 2) | 3))
#endif /* rLANG_DECLARE_MAGIC_X */

rlBASECC_INLINE int rLANG_DECLARE_MAGIC_Vc(int cc) {
  cc = 0x40 | (cc & 0x3F);

  switch (cc) {
    case 0x5B:
    case 0x5C:
    case 0x5D:
    case 0x5E:
    case 0x5F:
      cc = '1' - 0x5B + cc;
      break;

    case 0x60:
      cc = '0';
      break;

    case 0x7B:
    case 0x7C:
    case 0x7D:
    case 0x7E:
      cc = '6' - 0x7B + cc;
      break;

    case 0x7F:
      cc = '$';
      break;
  }

  return cc;
}

rlBASECC_INLINE int rLANG_DECLARE_MAGIC_Xc(int cc) {
  if rLANG_LIKELY ((cc >= 0x40 && cc <= 0x5A) || (cc >= 0x61 && cc <= 0x7A)) {
    cc &= 0x3F;
  } else {
    switch (cc) {
      case '0':
        cc = 0x20;
        break;

      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
        cc = 0x1B - '1' + cc;
        break;

      case '6':
      case '7':
      case '8':
      case '9':
        cc = 0x3B - '6' + cc;
        break;

      default:
        cc = 0x3F;
        break;
    }
  }

  return cc;
}

rlBASECC_INLINE char* rLANG_DECLARE_MAGIC_Vs(uint32_t magic, char buffer[6]) {
  for (int i = 0; i < 5; ++i) {
    buffer[i] = (char)rLANG_DECLARE_MAGIC_Vc(magic >> (26 - 6 * i));
  }
  buffer[5] = 0;
  return buffer;
}

rlBASECC_INLINE uint32_t rLANG_DECLARE_MAGIC_Xs(const char* const s) {
  return rLANG_DECLARE_MAGIC_X(rLANG_DECLARE_MAGIC_Xc(s[0]), rLANG_DECLARE_MAGIC_Xc(s[1]), rLANG_DECLARE_MAGIC_Xc(s[2]),
                               rLANG_DECLARE_MAGIC_Xc(s[3]), rLANG_DECLARE_MAGIC_Xc(s[4]));
}

rlBASECC_INLINE uint64_t rLANG_DECLARE_MAGIC_XXs(const char* const magic, const char* const word) {
  return ((uint64_t)rLANG_DECLARE_MAGIC_Xs(magic) << 32) | rLANG_DECLARE_MAGIC_Xs(word);
}

rlBASECC_INLINE uint32_t rLANG_CALCHASH_1(uint32_t v, uint8_t c) {
  return 0x3001 * v + c;
}

rlBASECC_INLINE int rLANG_CALCHASH_Xs(const char* const s, int len) {
  uint32_t v = 0;
  for (int i = 0; i < len; ++i) {
    v = rLANG_CALCHASH_1(v, s[i]);
  }
  return (v ^ len) & INT32_MAX;
}

rlBASECC_INLINE int rLANG_CALCHASH_Vs(const char* const s, int length, int* outLengthIf) {
  if rLANG_LIKELY (length < 0) {
    uint32_t v = 0;
    const char* p = s;

    while (*p) {
      v = rLANG_CALCHASH_1(v, *p++);
    }

    length = (int)(p - s);
    if rLANG_LIKELY (outLengthIf) {
      *outLengthIf = length;
    }
    return (v ^ length) & INT32_MAX;
  } else {
    return rLANG_CALCHASH_Xs(s, length);
  }
}

/**
 *!
 */
#ifndef XII_DECLARE_INTERFACE_BEGIN
#if defined(__cplusplus) && __cplusplus
#define XII_DECLARE_INTERFACE_BEGIN0(Name) struct rLANGNOVTBL Name {
#define XII_DECLARE_INTERFACE_BEGIN(Name, Base) struct rLANGNOVTBL Name : public Base {
#define XII_DECLARE_INTERFACE_END(Name) \
  }                                     \
  ;
#define XIIMETHOD_(type, name) virtual type rLANGAPI name
#define XIIPURE = 0
#define XIITHIZ0
#define XIITHIZ
#define XIITHIZARG0
#define XIITHIZARG
#define XIITHIZARG0_(var)
#define XIITHIZARG_(var)
#define XIIN(Name) struct Name
#define XIIMETHODCALL(type, object, method) ((type*)(object))->method
#define XIIMETHODIMPL_(type, cls, name) type rLANGAPI cls::name
#define XIIDECL(type) type
#else /* __cplusplus */
#define XII_DECLARE_INTERFACE_BEGIN0(Name) \
  struct Name##_;                          \
  struct Name##_vtbl;                      \
  typedef struct Name##_ Name;             \
  struct Name##_ {                         \
    const struct Name##_vtbl* X_vtbl;      \
  };                                       \
  struct Name##_vtbl {
#define XII_DECLARE_INTERFACE_BEGIN(Name, Base) \
  struct Name##_;                               \
  struct Name##_vtbl;                           \
  typedef struct Name##_ Name;                  \
  struct Name##_ {                              \
    const struct Name##_vtbl* X_vtbl;           \
  };                                            \
  struct Name##_vtbl {                          \
    struct Base##_vtbl _base;

#define XII_DECLARE_INTERFACE_END(Name) \
  }                                     \
  ;
#define XIIMETHOD_(type, name) type(rLANGAPI* name)
#define XIIPURE
#define XIITHIZ0 void* const thiz
#define XIITHIZ void *const thiz,
#define XIITHIZARG0 thiz
#define XIITHIZARG thiz,
#define XIITHIZARG0_(var) (var)
#define XIITHIZARG_(var) (var),
#define XIIN(Name) struct Name##_
#define XIIVTBLNAME(cls) struct cls##_vtbl
#define XIIVTBLVAL(var) ((var)->X_vtbl)
#define XIIMETHODCALL(type, object, method) (*XIIVTBLVAL((type*)(object))->method)
#define XIIMETHODNAME(cls, name) cls##_##name
#define XIIMETHODIMPL_(type, cls, name) type rLANGAPI cls##_##name
#define XIIDECL(type) void
#endif /* __cplusplus */

/**
 *!
 */
#define XIIMETHOD(name) XIIMETHOD_(int, name)
#define XIIMETHODIMPL(cls, name) XIIMETHODIMPL_(int, cls, name)
#define XIIMETHODTHIZCALL(type, method) XIIMETHODCALL(type, thiz, method)
#endif /* XII_DECLARE_INTERFACE_BEGIN */

typedef enum {
  rlLOG_NONE,

  rlLOG_ERROR,
  rlLOG_WARN,
  rlLOG_INFO,
  rlLOG_DEBUG,
  rlLOG_VERBOSE
} rlLogLevel;

typedef int64_t rlDate_t; /* UTC, Microseconds from 0000/1/1 00:00:00.000000 */

struct rlTM_t {
  int tm_year;  /* -99999 ... 99999 */
  int tm_month; /* 1 ... 12 */
  int tm_mday;  /* 1 ... 31 */

  int tm_hour;        /* 0 ... 23 */
  int tm_minute;      /* 0 ... 59 */
  int tm_second;      /* 0 ... 59 */
  int tm_microsecond; /* 0 ... 999999 */

  int tm_wday; /* 0 ... 6  */
};

/**
 *!
 */
rlBASECC_INLINE bool rLANG_IsLeapYear(int y) {
  return ((y & 3) == 0) && ((y % 100) != 0 || y % 400 == 0);
}
rlBASECC_INLINE int rLANG_LeapYearNdays(int year) { /* -1 day for normal year ... */
  return year * 365 + year / 4 - year / 100 + year / 400;
}

rLANGEXPORT uint32_t rLANGAPI rLANG_GetVersion(void);
rLANGEXPORT uint64_t rLANGAPI rLANG_GetTickCount(void);
rLANGEXPORT uint64_t rLANGAPI rLANG_SetTickCount0(uint64_t tick);
rLANGEXPORT rlDate_t rLANGAPI rLANG_GetCurrentDate(void);
rLANGEXPORT rlDate_t rLANGAPI rLANG_GetDateFromTime(const struct rlTM_t* tm);
rLANGEXPORT void rLANGAPI rLANG_GetTimeFromDate(struct rlTM_t* tm, rlDate_t dt);

rLANGEXPORT rlLogLevel rLANGAPI rlLoggingSetLevel(rlLogLevel level);
rLANGEXPORT void rlLoggingWriteEx(int level, uint32_t tag, int line, const void* data, int len, const char* fmt, ...)
    __attribute__((format(printf, 6, 7)));
rLANGEXPORT void rlLoggingWrite(int level, uint32_t tag, int line, const char* fmt, ...)
    __attribute__((format(printf, 4, 5)));

rlBASE_INLINE uint64_t rLANG_GetTickCount0() {
  return rLANG_SetTickCount0(0);
}
rlBASE_INLINE rlLogLevel rlLoggingGetLevel() {
  return rlLoggingSetLevel(rlLOG_NONE); /* invalid argument : level < rlLOG_ERROR */
}

/**
 *!
 */
#ifndef rlLOGV
#define rlLOGV(tag, fmt, ...) rlLoggingWrite(rlLOG_VERBOSE, (tag), __LINE__, (fmt), ##__VA_ARGS__)
#define rlLOGD(tag, fmt, ...) rlLoggingWrite(rlLOG_DEBUG, (tag), __LINE__, (fmt), ##__VA_ARGS__)
#define rlLOGI(tag, fmt, ...) rlLoggingWrite(rlLOG_INFO, (tag), __LINE__, (fmt), ##__VA_ARGS__)
#define rlLOGW(tag, fmt, ...) rlLoggingWrite(rlLOG_WARN, (tag), __LINE__, (fmt), ##__VA_ARGS__)
#define rlLOGE(tag, fmt, ...) rlLoggingWrite(rlLOG_ERROR, (tag), __LINE__, (fmt), ##__VA_ARGS__)

#define rlLOGXV(tag, dat, len, fmt, ...) \
  rlLoggingWriteEx(rlLOG_VERBOSE, (tag), __LINE__, (dat), (int)(len), (fmt), ##__VA_ARGS__)
#define rlLOGXD(tag, dat, len, fmt, ...) \
  rlLoggingWriteEx(rlLOG_DEBUG, (tag), __LINE__, (dat), (int)(len), (fmt), ##__VA_ARGS__)
#define rlLOGXI(tag, dat, len, fmt, ...) \
  rlLoggingWriteEx(rlLOG_INFO, (tag), __LINE__, (dat), (int)(len), (fmt), ##__VA_ARGS__)
#define rlLOGXW(tag, dat, len, fmt, ...) \
  rlLoggingWriteEx(rlLOG_WARN, (tag), __LINE__, (dat), (int)(len), (fmt), ##__VA_ARGS__)
#define rlLOGXE(tag, dat, len, fmt, ...) \
  rlLoggingWriteEx(rlLOG_ERROR, (tag), __LINE__, (dat), (int)(len), (fmt), ##__VA_ARGS__)
#endif /* rlLOGV */

/**
 *!
 */
struct rLANG_SLIST_NODE_t {
  struct rLANG_SLIST_NODE_t* xd_next;
};
struct rLANG_LIST_NODE_t {
  struct rLANG_LIST_NODE_t *xd_next, *xd_prev;
};
typedef struct rLANG_SLIST_NODE_t rLANG_SLIST_NODE_t, rLANG_SLIST_HEAD_t;
typedef struct rLANG_LIST_NODE_t rLANG_LIST_NODE_t, rLANG_LIST_HEAD_t;

/**
 *!
 */
#ifndef XDS_null_slist_init
#define XDS_null_slist_init(__h__) ((__h__)->xd_next = NULL)
#define XDS_null_slist_insert_after(__h__, __p__) \
  do {                                            \
    (__p__)->xd_next = (__h__)->xd_next;          \
    (__h__)->xd_next = (__p__);                   \
  } while (0)
#define XDS_null_slist_erase_after(__h__, __f__)    \
  do {                                              \
    void* __p_next_node__ = (__h__)->xd_next;       \
    if (NULL != __p_next_node__)                    \
      (__h__)->xd_next = (__h__)->xd_next->xd_next; \
    else                                            \
      (__h__)->xd_next = NULL;                      \
    __f__(__p_next_node__);                         \
  } while (0)
#define XDS_null_slist_push_front(__h__, __p__) XDS_null_slist_insert_after(__h__, __p__)
#define XDS_null_slist_pop_front(__h__, __f__) XDS_null_slist_erase_after(__h__, __f__)
#define XDS_null_slist_for_each(__h__, __n__) \
  for ((__n__) = (__h__)->xd_next; NULL != (__n__); (__n__) = (__n__)->xd_next)
#endif /* XDS_null_slist_init */

/**
 *!
 */
#ifndef XDS_list_init
#define XDS_list_init(__h__) ((__h__)->xd_prev = (__h__)->xd_next = (__h__))
#define XDS_list_insert_before(__n__, __p__) \
  do {                                       \
    (__p__)->xd_next = (__n__);              \
    (__p__)->xd_prev = (__n__)->xd_prev;     \
    (__n__)->xd_prev->xd_next = (__p__);     \
    (__n__)->xd_prev = (__p__);              \
  } while (0)
#define XDS_list_insert_before_2(__n__, __b__, __e__) \
  do {                                                \
    (__e__)->xd_next = (__n__);                       \
    (__b__)->xd_prev = (__n__)->xd_prev;              \
    (__n__)->xd_prev->xd_next = (__b__);              \
    (__n__)->xd_prev = (__e__);                       \
  } while (0)
#define XDS_list_insert_after(__n__, __p__) \
  do {                                      \
    (__p__)->xd_prev = (__n__);             \
    (__p__)->xd_next = (__n__)->xd_next;    \
    (__n__)->xd_next->xd_prev = (__p__);    \
    (__n__)->xd_next = (__p__);             \
  } while (0)
#define XDS_list_insert_after_2(__n__, __b__, __e__) \
  do {                                               \
    (__b__)->xd_prev = (__n__);                      \
    (__e__)->xd_next = (__n__)->xd_next;             \
    (__n__)->xd_next->xd_prev = (__e__);             \
    (__n__)->xd_next = (__b__);                      \
  } while (0)
#define XDS_list_push_back(__h__, __p__) XDS_list_insert_before(__h__, __p__)
#define XDS_list_push_front(__h__, __p__) XDS_list_insert_after(__h__, __p__)
#define XDS_list_erase(__n__, __f__)              \
  do {                                            \
    (__n__)->xd_prev->xd_next = (__n__)->xd_next; \
    (__n__)->xd_next->xd_prev = (__n__)->xd_prev; \
    __f__(__n__);                                 \
  } while (0)
#define XDS_list_erase_2(__b__, __e__)            \
  do {                                            \
    (__b__)->xd_prev->xd_next = (__e__)->xd_next; \
    (__e__)->xd_next->xd_prev = (__b__)->xd_prev; \
  } while (0)
#define XDS_list_pop_back(__h__, __f__)           \
  do {                                            \
    void* __the_node__ = (__h__)->xd_prev;        \
    (__h__)->xd_prev->xd_prev->xd_next = (__h__); \
    (__h__)->xd_prev = (__h__)->xd_prev->xd_prev; \
    __f__(__the_node__);                          \
  } while (0)
#define XDS_list_pop_front(__h__, __f__)          \
  do {                                            \
    void* __the_node__ = (__h__)->xd_next;        \
    (__h__)->xd_next->xd_next->xd_prev = (__h__); \
    (__h__)->xd_next = (__h__)->xd_next->xd_next; \
    __f__(__the_node__);                          \
  } while (0)
#define XDS_list_cleanup(__h__, __f__)                 \
  do {                                                 \
    void* __the_first_node__;                          \
    while (1) {                                        \
      XDS_list_pop_front(__h__, __the_first_node__ =); \
      if (__the_first_node__ == __h__)                 \
        break;                                         \
      __f__(__the_first_node__);                       \
    }                                                  \
  } while (0)
#define XDS_list_for_each(__h__, __n__) for ((__n__) = (__h__)->xd_next; (__h__) != (__n__); (__n__) = (__n__)->xd_next)
#endif /* XDS_list_init */

/**
 *! RBTREE
 */
#ifndef rLANG_RBTREE_DECLARE_NODE_ENTRY
/* maximum index count : sizeof( uintptr_t ) * 8 */
/******************************************************************/
/******************************************************************/
#define rLANG_RBTREE_DECLARE_NODE_ENTRY(__index_count__) \
  void* __none_of_your_business_for_rbtree_node__[3 * (__index_count__) + 1]
#define rLANG_RBTREE_USER_DATA_MASK(__index_count__) (((uintptr_t)~0) << (__index_count__))
#define rLANG_RBTREE_USER_DATA(__node__) (((uintptr_t*)(__node__))[0])
/******************************************************************/
/******************************************************************/
#define rLANG_RBTREE_PARENT(__node__, __index__) (((void**)(__node__))[1 + 3 * (__index__) + 0])
#define rLANG_RBTREE_LEFT_CHILD(__node__, __index__) (((void**)(__node__))[1 + 3 * (__index__) + 1])
#define rLANG_RBTREE_RIGHT_CHILD(__node__, __index__) (((void**)(__node__))[1 + 3 * (__index__) + 2])
#define rLANG_RBTREE_COLOR(__node__) (((uintptr_t*)(__node__))[0])
/******************************************************************/
/******************************************************************/
#define rLANG_RBTREE_PARENT_0(__node__) rLANG_RBTREE_PARENT(__node__, 0)
#define rLANG_RBTREE_PARENT_1(__node__) rLANG_RBTREE_PARENT(__node__, 1)
#define rLANG_RBTREE_PARENT_2(__node__) rLANG_RBTREE_PARENT(__node__, 2)
#define rLANG_RBTREE_PARENT_3(__node__) rLANG_RBTREE_PARENT(__node__, 3)
/******************************************************************/
/******************************************************************/
#define rLANG_RBTREE_LEFT_CHILD_0(__node__) rLANG_RBTREE_LEFT_CHILD(__node__, 0)
#define rLANG_RBTREE_LEFT_CHILD_1(__node__) rLANG_RBTREE_LEFT_CHILD(__node__, 1)
#define rLANG_RBTREE_LEFT_CHILD_2(__node__) rLANG_RBTREE_LEFT_CHILD(__node__, 2)
#define rLANG_RBTREE_LEFT_CHILD_3(__node__) rLANG_RBTREE_LEFT_CHILD(__node__, 3)
/******************************************************************/
/******************************************************************/
#define rLANG_RBTREE_RIGHT_CHILD_0(__node__) rLANG_RBTREE_RIGHT_CHILD(__node__, 0)
#define rLANG_RBTREE_RIGHT_CHILD_1(__node__) rLANG_RBTREE_RIGHT_CHILD(__node__, 1)
#define rLANG_RBTREE_RIGHT_CHILD_2(__node__) rLANG_RBTREE_RIGHT_CHILD(__node__, 2)
#define rLANG_RBTREE_RIGHT_CHILD_3(__node__) rLANG_RBTREE_RIGHT_CHILD(__node__, 3)
/******************************************************************/
/******************************************************************/
#define rLANG_RBTREE_COLOR_MASK(__index__) ((uintptr_t)1 << (__index__))
#define rLANG_RBTREE_COLOR_UNMASK(__index__) (~((uintptr_t)1 << (__index__)))
/******************************************************************/
/******************************************************************/
#define rLANG_RBTREE_IS_RED_(__node__, __mask__) (0 == (rLANG_RBTREE_COLOR(__node__) & (__mask__)))
#define rLANG_RBTREE_IS_BLACK_(__node__, __mask__) (0 != (rLANG_RBTREE_COLOR(__node__) & (__mask__)))
#define rLANG_RBTREE_SET_RED_(__node__, __unmask__) ((rLANG_RBTREE_COLOR(__node__) &= (__unmask__)))
#define rLANG_RBTREE_SET_BLACK_(__node__, __mask__) ((rLANG_RBTREE_COLOR(__node__) |= (__mask__)))
#define rLANG_RBTREE_ASSIGN_CLR_(__lhs__, __rhs__, __mask__) \
  (rLANG_RBTREE_COLOR(__lhs__) ^= ((__mask__) & (rLANG_RBTREE_COLOR(__lhs__) ^ rLANG_RBTREE_COLOR(__rhs__))))
#define rLANG_RBTREE_CLR_SWAP_(__lhs__, __rhs__, __mask__)                          \
  do {                                                                              \
    if ((__mask__) & (rLANG_RBTREE_COLOR(__lhs__) ^ rLANG_RBTREE_COLOR(__rhs__))) { \
      rLANG_RBTREE_COLOR(__lhs__) ^= (__mask__);                                    \
      rLANG_RBTREE_COLOR(__rhs__) ^= (__mask__);                                    \
    }                                                                               \
  } while (0)
/******************************************************************/
/******************************************************************/
#define rLANG_RBTREE_IS_RED_0(__node__) rLANG_RBTREE_IS_RED_(__node__, (1 << 0))
#define rLANG_RBTREE_IS_RED_1(__node__) rLANG_RBTREE_IS_RED_(__node__, (1 << 1))
#define rLANG_RBTREE_IS_RED_2(__node__) rLANG_RBTREE_IS_RED_(__node__, (1 << 2))
#define rLANG_RBTREE_IS_RED_3(__node__) rLANG_RBTREE_IS_RED_(__node__, (1 << 3))
/******************************************************************/
/******************************************************************/
#define rLANG_RBTREE_IS_BLACK_0(__node__) rLANG_RBTREE_IS_BLACK_(__node__, (1 << 0))
#define rLANG_RBTREE_IS_BLACK_1(__node__) rLANG_RBTREE_IS_BLACK_(__node__, (1 << 1))
#define rLANG_RBTREE_IS_BLACK_2(__node__) rLANG_RBTREE_IS_BLACK_(__node__, (1 << 2))
#define rLANG_RBTREE_IS_BLACK_3(__node__) rLANG_RBTREE_IS_BLACK_(__node__, (1 << 3))
/******************************************************************/
/******************************************************************/
#define rLANG_RBTREE_NODE_MINIMUM(__type__, __node__, __ret__, __index__) \
  do {                                                                    \
    (__ret__) = (__type__)(__node__);                                     \
    while (rLANG_RBTREE_LEFT_CHILD(__ret__, __index__))                   \
      (__ret__) = (__type__)rLANG_RBTREE_LEFT_CHILD(__ret__, __index__);  \
  } while (0)

#define rLANG_RBTREE_NODE_MAXIMUM(__type__, __node__, __ret__, __index__) \
  do {                                                                    \
    (__ret__) = (__type__)(__node__);                                     \
    while (rLANG_RBTREE_RIGHT_CHILD(__ret__, __index__))                  \
      (__ret__) = (__type__)rLANG_RBTREE_RIGHT_CHILD(__ret__, __index__); \
  } while (0)

#define rLANG_RBTREE_NODE_NEXT(__type__, __node__, __ret__, __index__)                                         \
  do {                                                                                                         \
    (__ret__) = (__type__)(__node__);                                                                          \
    if (rLANG_RBTREE_RIGHT_CHILD(__ret__, __index__))                                                          \
      rLANG_RBTREE_NODE_MINIMUM(__type__, rLANG_RBTREE_RIGHT_CHILD(__ret__, __index__), __ret__, __index__);   \
    else {                                                                                                     \
      void* __the_temp_node__ = rLANG_RBTREE_PARENT(__ret__, __index__);                                       \
      while (__the_temp_node__ && __ret__ == (__type__)rLANG_RBTREE_RIGHT_CHILD(__the_temp_node__, __index__)) \
        (__ret__) = (__type__)__the_temp_node__,                                                               \
        __the_temp_node__ = rLANG_RBTREE_PARENT(__the_temp_node__, __index__);                                 \
      (__ret__) = (__type__)__the_temp_node__;                                                                 \
    }                                                                                                          \
  } while (0)
#define rLANG_RBTREE_NODE_PREV(__type__, __node__, __ret__, __index__)                                        \
  do {                                                                                                        \
    (__ret__) = (__type__)(__node__);                                                                         \
    if (rLANG_RBTREE_LEFT_CHILD(__ret__, __index__))                                                          \
      rLANG_RBTREE_NODE_MAXIMUM(__type__, rLANG_RBTREE_LEFT_CHILD(__ret__, __index__), __ret__, __index__);   \
    else {                                                                                                    \
      void* __the_temp_node__ = rLANG_RBTREE_PARENT(__ret__, __index__);                                      \
      while (__the_temp_node__ && __ret__ == (__type__)rLANG_RBTREE_LEFT_CHILD(__the_temp_node__, __index__)) \
        (__ret__) = (__type__)__the_temp_node__,                                                              \
        __the_temp_node__ = rLANG_RBTREE_PARENT(__the_temp_node__, __index__);                                \
      (__ret__) = (__type__)__the_temp_node__;                                                                \
    }                                                                                                         \
  } while (0)

/******************************************************************/
/******************************************************************/
/****
(__compare_op__)  :
0  :	__node_ret__ == RESULT
>0 :	__node_ret__  > RESULT
<0 :	__node_ret__  < RESULT
****/
#define rLANG_RBTREE_FIND(__type__, __node__, __node_ret__, __compare_op__, __index__) \
  do {                                                                                 \
    intptr_t __compare_find__;                                                         \
    (__node_ret__) = (__type__)(__node__);                                             \
    while ((__node_ret__)) {                                                           \
      __compare_find__ = (__compare_op__);                                             \
      if (0 == __compare_find__)                                                       \
        break;                                                                         \
      if (__compare_find__ > 0)                                                        \
        (__node_ret__) = (__type__)rLANG_RBTREE_LEFT_CHILD(__node_ret__, __index__);   \
      else                                                                             \
        (__node_ret__) = (__type__)rLANG_RBTREE_RIGHT_CHILD(__node_ret__, __index__);  \
    }                                                                                  \
  } while (0)

/****
(__compare_lt__)   :
<>0	:	__node_cmp__ <  RESULT
0   :   __node_cmp__ >= RESULT
****/
#define rLANG_RBTREE_LOWER_BOUND(__type__, __node__, __node_cmp__, __ret__, __compare_lt__, __index__) \
  do {                                                                                                 \
    (__ret__) = NULL;                                                                                  \
    (__node_cmp__) = (__type__)(__node__);                                                             \
    while ((__node_cmp__)) {                                                                           \
      if (!(__compare_lt__))                                                                           \
        (__ret__) = (__type__)(__node_cmp__),                                                          \
        (__node_cmp__) = (__type__)rLANG_RBTREE_LEFT_CHILD((__node_cmp__), __index__);                 \
      else                                                                                             \
        (__node_cmp__) = (__type__)rLANG_RBTREE_RIGHT_CHILD((__node_cmp__), __index__);                \
    }                                                                                                  \
  } while (0)
/****
(__compare_gt__)   :
<>0	:	__node_cmp__ >  RESULT
0   :   __node_cmp__ <= RESULT
****/
#define rLANG_RBTREE_UPPER_BOUND(__type__, __node__, __node_cmp__, __ret__, __compare_gt__, __index__) \
  do {                                                                                                 \
    (__ret__) = NULL;                                                                                  \
    (__node_cmp__) = (__type__)(__node__);                                                             \
    while ((__node_cmp__)) {                                                                           \
      if ((__compare_gt__))                                                                            \
        (__ret__) = (__type__)(__node_cmp__),                                                          \
        (__node_cmp__) = (__type__)rLANG_RBTREE_LEFT_CHILD((__node_cmp__), __index__);                 \
      else                                                                                             \
        (__node_cmp__) = (__type__)rLANG_RBTREE_RIGHT_CHILD((__node_cmp__), __index__);                \
    }                                                                                                  \
  } while (0)
/******************************************************************/
/******************************************************************/
/****
(__compare_lt__)   :
<>0	:	__node_cmp__ <  __node__
0   :   __node_cmp__ >= __node__
****/
#define rLANG_RBTREE_PREV_INSERT_NODE(__type__, __root__, __node_cmp__, __compare_lt__, __node__, __index__) \
  do {                                                                                                       \
    (__node_cmp__) = (__type__)(__root__);                                                                   \
    rLANG_RBTREE_PARENT(__node__, __index__) = rLANG_RBTREE_LEFT_CHILD(__node__, __index__) =                \
        rLANG_RBTREE_RIGHT_CHILD(__node__, __index__) = 0;                                                   \
    if (!(__node_cmp__)) {                                                                                   \
      (__root__) = (__node__);                                                                               \
      break; /* do ... while */                                                                              \
    }                                                                                                        \
    while (1) {                                                                                              \
      if ((__compare_lt__)) {                                                                                \
        if (!rLANG_RBTREE_RIGHT_CHILD(__node_cmp__, __index__)) {                                            \
          rLANG_RBTREE_RIGHT_CHILD(__node_cmp__, __index__) = (__node__);                                    \
          rLANG_RBTREE_PARENT(__node__, __index__) = (__node_cmp__);                                         \
          break;                                                                                             \
        } else                                                                                               \
          (__node_cmp__) = (__type__)rLANG_RBTREE_RIGHT_CHILD(__node_cmp__, __index__);                      \
      } else {                                                                                               \
        if (!rLANG_RBTREE_LEFT_CHILD(__node_cmp__, __index__)) {                                             \
          rLANG_RBTREE_LEFT_CHILD(__node_cmp__, __index__) = (__node__);                                     \
          rLANG_RBTREE_PARENT(__node__, __index__) = (__node_cmp__);                                         \
          break;                                                                                             \
        } else                                                                                               \
          (__node_cmp__) = (__type__)rLANG_RBTREE_LEFT_CHILD(__node_cmp__, __index__);                       \
      }                                                                                                      \
    }                                                                                                        \
  } while (0)
/****
(__compare_op__)     :
<0  : __node_cmp__ <  __node__
0  : __node_cmp__ == __node__
>0  : __node_cmp__ >  __node__
(__reduplicate_do__) :
__node_cmp__ reduplicate, use (<<return>> or <<goto>> or <<setflag&&break>>) leave while(1) loop ....
****/
#define rLANG_RBTREE_PREV_INSERT_UNIQUE(__type__, __root__, __node_cmp__, __compare_op__, __node__, __index__, \
                                        __reduplicate_do__)                                                    \
  do {                                                                                                         \
    intptr_t __result_of_insert_unique__;                                                                      \
    (__node_cmp__) = (__type__)(__root__);                                                                     \
    rLANG_RBTREE_PARENT(__node__, __index__) = rLANG_RBTREE_LEFT_CHILD(__node__, __index__) =                  \
        rLANG_RBTREE_RIGHT_CHILD(__node__, __index__) = 0;                                                     \
    if (!(__node_cmp__)) {                                                                                     \
      (__root__) = (__node__);                                                                                 \
      break; /* do ... while */                                                                                \
    }                                                                                                          \
    while (1) {                                                                                                \
      __result_of_insert_unique__ = (__compare_op__);                                                          \
      if (0 == __result_of_insert_unique__) {                                                                  \
        __reduplicate_do__ /* */;                                                                              \
        assert(false);                                                                                         \
      } else if (__result_of_insert_unique__ < 0) {                                                            \
        if (!rLANG_RBTREE_RIGHT_CHILD(__node_cmp__, __index__)) {                                              \
          rLANG_RBTREE_RIGHT_CHILD(__node_cmp__, __index__) = (__node__);                                      \
          rLANG_RBTREE_PARENT(__node__, __index__) = (__node_cmp__);                                           \
          break;                                                                                               \
        } else                                                                                                 \
          (__node_cmp__) = (__type__)rLANG_RBTREE_RIGHT_CHILD(__node_cmp__, __index__);                        \
      } else {                                                                                                 \
        if (!rLANG_RBTREE_LEFT_CHILD(__node_cmp__, __index__)) {                                               \
          rLANG_RBTREE_LEFT_CHILD(__node_cmp__, __index__) = (__node__);                                       \
          rLANG_RBTREE_PARENT(__node__, __index__) = (__node_cmp__);                                           \
          break;                                                                                               \
        } else                                                                                                 \
          (__node_cmp__) = (__type__)rLANG_RBTREE_LEFT_CHILD(__node_cmp__, __index__);                         \
      }                                                                                                        \
    }                                                                                                          \
  } while (0)
#endif /* rLANG_RBTREE_DECLARE_NODE_ENTRY */

/**
 *!
 */
rLANGEXPORT void rLANGAPI rLANG_RBTREE_INSERT_NODE_0(void* node, void** root);
rLANGEXPORT void rLANGAPI rLANG_RBTREE_INSERT_NODE_1(void* node, void** root);
rLANGEXPORT void rLANGAPI rLANG_RBTREE_INSERT_NODE_X(void* node, void** root, const int index);

rLANGEXPORT void rLANGAPI rLANG_RBTREE_ERASE_NODE_0(void* node, void** root);
rLANGEXPORT void rLANGAPI rLANG_RBTREE_ERASE_NODE_1(void* node, void** root);
rLANGEXPORT void rLANGAPI rLANG_RBTREE_ERASE_NODE_X(void* node, void** root, const int index);

/**
 *! DFA scanner && LALR(1) parser ....
 */
#ifndef XDFA_SCANNER_TYPE_ENTRY
#define XDFA_SCANNER_TYPE_ENTRY(j__charType)                                      \
  j__charType *X_buffer_begin, *X_buffer_end, *X_input_end, *X_text, *X_text_end; \
  int f_flags, f_start, f_current, f_backup, f_pos_accepted;
#endif /* XDFA_SCANNER_TYPE_ENTRY */

#ifndef XDPDA_GRAMMAR_TYPE_ENTRY
#define XDPDA_GRAMMAR_TYPE_ENTRY(j__valueType)                                                                   \
  int X_state_internal, f_yystate, f_yyn, f_yyerrstatus, f_yytoken, f_yylen, f_yychar, f_yynerrs, f_yystacksize; \
  short *f_yyssa, *f_yyss, *f_yyssp;                                                                             \
  j__valueType *f_yyvsa, *f_yyvs, *f_yyvsp, f_yyval, f_yylval;
#endif /* XDPDA_GRAMMAR_TYPE_ENTRY */

#define XDFA_RESULT_ERROR (-3)
#define XDFA_RESULT_PENDING_EXTEND_BUFFER (-2)
#define XDFA_RESULT_PENDING_MORE_INPUT (-1)
#define XDFA_RESULT_EOF (0)
#define XDFA_RESULT_ACTION_BEGIN (1)

#define XDFA_RESUME_NIL (0)
#define XDFA_RESUME_READ_DATA (1)
#define XDFA_RESUME_EXTEND_BUFFER (2)

/**
 *! manual update BOL) default) X_text_end[-1] == '\r' || X_text_end[-1] == '\n'
 */
#define XDFA_FLAGS_BOL (0001)
#define XDFA_FLAGS_EOF (0002)

/**
 *!
 */
#define XDFA_SCANNER_SCON_INITIAL (0)

#define XDFA_SCANNER_START(am) ((((am)->f_start) - 1) / 2)
#define XDFA_SCANNER_BEGIN(am, x) ((am)->f_start = 2 * (x) + 1)

#define XDFA_SCANNER_SET_BOL(am) ((am)->f_flags |= XDFA_FLAGS_BOL)
#define XDFA_SCANNER_CLR_BOL(am) ((am)->f_flags &= ~XDFA_FLAGS_BOL)
#define XDFA_SCANNER_GET_BOL(am) ((am)->f_flags & XDFA_FLAGS_BOL)

#define XDFA_SCANNER_SET_EOF(am) ((am)->f_flags |= XDFA_FLAGS_EOF)
#define XDFA_SCANNER_GET_EOF(am) ((am)->f_flags & XDFA_FLAGS_EOF)

#define XDFA_SCANNER_yytext(am) ((am)->X_text)
#define XDFA_SCANNER_yytext_end(am) ((am)->X_text_end)
#define XDFA_SCANNER_putback(am, n) (((am)->X_text_end) -= (n))

#define XDFA_SCANNER_INITIALIZE(am)                              \
  do {                                                           \
    (am)->f_flags = XDFA_FLAGS_BOL;                              \
    XDFA_SCANNER_BEGIN(am, XDFA_SCANNER_SCON_INITIAL);           \
    (am)->X_text = (am)->X_text_end = NULL;                      \
    (am)->f_current = (am)->f_backup = (am)->f_pos_accepted = 0; \
  } while (0)

#define XDFA_SCANNER_READBUFFER_PTR(am) ((am)->X_input_end)
#define XDFA_SCANNER_READBUFFER_END(am) ((am)->X_buffer_end)
#define XDFA_SCANNER_READBUFFER_LEN(am) ((am)->X_buffer_end - (am)->X_input_end)

/**
 *! LALR(1) parser .....
 */
#define XDPDA_YYTERROR (1)
#define XDPDA_YYEMPTY (-2)
#define XDPDA_YYEOF (0)

#define XDPDA_CONTEXT_INIT_STACK(self, N, ssa, vsa) \
  do {                                              \
    (self)->f_yystacksize = (N);                    \
    (self)->f_yyssa = (ssa);                        \
    (self)->f_yyvsa = (vsa);                        \
  } while (0)

/**
 *!
 */
#define XDPDA_YYLVAL(self) ((self)->f_yylval)         /* $< */
#define XDPDA_YYVAL(self) ((self)->f_yyval)           /* $$ */
#define XDPDA_YYVAR(self, N) (((self)->f_yyvsp)[(N)]) /* $N */
#define XDPDA_YYOFF(self) ((self)->f_yyvsp - (self)->f_yyvsa)

#define XDPDA_RESULT_FAILED_ABORT (-5)
#define XDPDA_RESULT_FAILED_ERROR (-4)
#define XDPDA_RESULT_FAILED_SYNTAX_ERROR (-3)
#define XDPDA_RESULT_PENDING_EXTEND_STACK (-2)
#define XDPDA_RESULT_PENDING_MORE_INPUT (-1)
#define XDPDA_RESULT_ACCEPTED (0)
#define XDPDA_RESULT_REDUCE_BEGIN (1)

#define XDPDA_RESUME_INITIALIZE (-1)
#define XDPDA_RESUME_REDUCE (-2)
#define XDPDA_RESUME_EXTEND_STACK (-3)
#define XDPDA_RESUME_SYNTAX_ERROR (-4)
#define XDPDA_RESUME_YYACCEPT (-5)
#define XDPDA_RESUME_YYERROR (-6)
#define XDPDA_RESUME_YYABORT (-7)

rLANG_ABIREQUIRE(rLANG_WORLD_MAGIC == rLANG_DECLARE_MAGIC_X('r', 'L', 'A', 'N', 'G') && sizeof(int) == 4 &&
                 sizeof(double) == 8 && (sizeof(void*) == 4 || sizeof(void*) == 8) &&
                 sizeof(void*) == sizeof(uintptr_t) && sizeof(size_t) == sizeof(uintptr_t));

rLANG_DECLARE_END

#endif /* ___WTINC_BITS_BASE_H__ */

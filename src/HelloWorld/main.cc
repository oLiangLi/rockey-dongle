#include <base/base.h>
#ifndef __EMSCRIPTEN__
#include <RockeyARM/Dongle_API.h>
#endif /* __EMSCRIPTEN__ */

#if (defined(__linux__) && defined(__amd64__))  || defined(__CYGWIN__) || defined(_WIN32)
#define USING_OPENSSL_TESTING 1
#endif /* _WIN32 */

#if defined(USING_OPENSSL_TESTING) && USING_OPENSSL_TESTING
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/lhash.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sm2.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif /* USING_OPENSSL_TESTING */

rLANG_DECLARE_MACHINE

namespace {
constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("Foobar");
} // namespace ...

int Start(int argc, char* argv[]) {
  rlLOGI(TAG, "Hello RockeyARM World!");

#if defined(USING_OPENSSL_TESTING) && USING_OPENSSL_TESTING
  rlLOGI(
      TAG, "\n\n%s%s%s\n\n",  //@ third_party/TASSL-1.1.1/LICENSE
      "This product includes software developed by the OpenSSL Project\n",
      "This product includes cryptographic software written by Eric Young (eay@cryptsoft.com)\n",
      "This product includes software developed by 北京江南天安科技有限公司 TaSSL Project.(http://www.tass.com.cn/)\n");
  for (int i = 0; i <= 6; ++i) {
    rlLOGW(TAG, "V[%d]: %s", i, OpenSSL_version(i));
  }

  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
#endif /* defined(USING_OPENSSL_TESTING) && USING_OPENSSL_TESTING */

#ifndef __EMSCRIPTEN__
  int count = 0, result = Dongle_Enum(NULL, &count);
  rlLOGI(TAG, "Dongle_Enum return %x => %d", result, count);
#endif /* __EMSCRIPTEN__ */

  return 0;
}

rLANG_DECLARE_END

int main(int argc, char* argv[]) {
  return machine::Start(argc, argv);
}

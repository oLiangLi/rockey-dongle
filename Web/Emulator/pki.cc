#include <base/base.h>

#include <Interface/dongle.h>
#include <Interface/script.h>

#include <openssl/ssl.h>

rLANG_DECLARE_MACHINE

constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("j@PKI");

/**
 *! TODO: LiangLI, 实现 SSL, X509 相关操作以接入PKI系统 ...
 */

/**
 *!
 */
rLANGWASMEXPORT int Initialize() {
  rlLOGI(TAG, "\n\n%s%s%s\n\n",  //@ third_party/TASSL-1.1.1/LICENSE
         "This product includes software developed by the OpenSSL Project\n",
         "This product includes cryptographic software written by Eric Young (eay@cryptsoft.com)\n",
         "This product includes software developed by Beijing JN TASS Technology Co., Ltd. TaSSL "
         "Project.(http://www.tass.com.cn/)\n");
  for (int i = 0; i <= 6; ++i) {
    rlLOGW(TAG, "V[%d]: %s", i, OpenSSL_version(i));
  }

  SSL_library_init();
  SSL_load_error_strings();

  uint8_t buffer[128];
  FILE* fp = fopen("/dev/random", "rb");
  if (fp) {
    fread(buffer, 1, sizeof(buffer), fp);
    fclose(fp);
  }
  RAND_seed(buffer, sizeof(buffer));
  return 0;
}

rLANGWASMEXPORT void RANDSeedBytes(const void* buff, size_t size) {
  RAND_seed(buff, size);
}

rLANG_DECLARE_END

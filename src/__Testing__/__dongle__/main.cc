#include <Interface/dongle.h>
#include <Interface/mr.h>
#include <Interface/x509.h>
#include <base/base.h>

#if !defined(__RockeyARM__) && !defined(__EMULATOR__)
#include <signal.h>
#include <cstdio> /* LogLeHex 用 std::snprintf; Linux/GCC 下不会从其它头传递进来 */
#include <set>
#include <thread>
#endif /* #if !defined(__RockeyARM__) && !defined(__EMULATOR__) */

rLANG_DECLARE_MACHINE

namespace {
constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("App@T");
}

namespace dongle {

using DWORD = Dongle::DWORD;

enum class kTestingIndex : int {
  CreateDataFile = 1,

  ReadWriteDataFile,

  ReadWriteFactoryData,

  CreateRSAFile,

  RSAExec,

  SM2Exec,

  P256Exec,

  KeyExec,

  HashExec,

  Secp256K1Exec,

  ChaChaPoly,

  Sha256Test,

  Sha384Test,

  Sha512Test,

  Curve25519Test,

  Ed25519Test,

  PKeyCountDownTest,

  X509Tests,

  PrimeMRTests

};

enum class kAdminTestingIndex : int {
  FactoryReset = 1,

  SelectProductId,

};

struct Context_t {
  union {
    uint32_t argv_[4];
    uint32_t result_[4];
    uint8_t bytes_[16];
  };

  uint8_t hash_[64];
  uint32_t ts_[8];

  uint32_t seed_[8];
  uint32_t error_[8];

  PERMISSION permission_;
  DWORD realTime_, expireTime_, ticks_;

  uint8_t share_memory_1_[32];
  uint8_t share_memory_2_[32];

  DONGLE_INFO dongle_info_;
  uint8_t bytes[64];
};
/* ---- X509Tests 证书通道 ---- */

/*! 证书 DER 由 host/模拟器写入 dashboard[0, 4KB)(factory dataFile 0xFFFF 匿名可写区),
 *! 测试内经 ReadDataFile 加载到证书区 = InOutBuf[kX509CertOffset, 1024)(Context_t 恰 360B,
 *! 编译期断言);blob 布局 [u16 leaf_len][u16 ca_len][leaf DER][ca DER] */
constexpr uint32_t kX509CertOffset = 360;
rLANG_ABIREQUIRE(sizeof(Context_t) == kX509CertOffset);

#if !defined(__RockeyARM__)
/*! X509Tests 内置证书(TASSL/BabaSSL 生成, X509_verify 交叉验证; 固件 rodata 必须为空,
 *! 不参与编译, 真机证书经 dashboard 通道由 host 写入设备 dataFile):
 *!  - kX509CertsP256: P256 CA(自签 v3, BC+KU critical) + 叶(CA 签 v3, KU critical), SHA256
 *!  - kX509CertsSM2 : SM2 CA/叶(同上), SM3
 *!  - kX509CertsRSA : RSA2048 自签 CA(v1 无扩展, 最小化体积), SHA256
 *! 统一有效期 2020-01-01 ~ 2030-01-01(GeneralizedTime);叶 issuer 指向 CA 名(自签判定负例用) */

static const uint8_t kX509CertsP256[610] = {
    0x2C, 0x01, 0x32, 0x01, 0x30, 0x82, 0x01, 0x28, 0x30, 0x81, 0xCF, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02,
    0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x18, 0x31, 0x0A, 0x30, 0x08, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x0C, 0x01, 0x4C, 0x31, 0x0A, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x01, 0x50,
    0x30, 0x22, 0x18, 0x0F, 0x32, 0x30, 0x32, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A,
    0x18, 0x0F, 0x32, 0x30, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x30, 0x0C,
    0x31, 0x0A, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x01, 0x4C, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    0x04, 0xA0, 0x4F, 0x8B, 0x42, 0x4C, 0xBF, 0x9C, 0x27, 0xB3, 0x12, 0x0E, 0xE4, 0xB9, 0x56, 0xF2, 0x51, 0x27, 0x7E,
    0x7E, 0x76, 0x73, 0x50, 0x74, 0x84, 0x20, 0x74, 0x47, 0x4C, 0x22, 0x0A, 0x9D, 0xAE, 0x74, 0xDA, 0x28, 0xF9, 0x37,
    0x02, 0xED, 0x7C, 0xD5, 0x53, 0x5C, 0xC3, 0xD4, 0x56, 0xBD, 0xD7, 0x45, 0xC1, 0xB0, 0x31, 0x35, 0x24, 0x07, 0x64,
    0xAA, 0x3B, 0x18, 0x24, 0x5C, 0x33, 0x8F, 0x04, 0xA3, 0x12, 0x30, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F,
    0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04,
    0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x28, 0x57, 0x2C, 0x23, 0xC3, 0x10, 0x5E, 0xCF, 0x68, 0xD1,
    0x40, 0xD6, 0x6A, 0x32, 0x6C, 0xEA, 0x73, 0xA7, 0x93, 0x45, 0x05, 0xDB, 0x5D, 0x88, 0x31, 0x46, 0x5A, 0x75, 0xA5,
    0x56, 0x1D, 0xC1, 0x02, 0x21, 0x00, 0xCD, 0x12, 0x53, 0xEF, 0xFB, 0x01, 0xC0, 0x9A, 0x4C, 0xCB, 0xBE, 0xDC, 0x16,
    0x28, 0xD7, 0xC9, 0xB1, 0x79, 0xFA, 0x98, 0x61, 0x25, 0xF6, 0x0B, 0x0A, 0xA5, 0x77, 0xE5, 0x33, 0xD5, 0xE4, 0xFD,
    0x30, 0x82, 0x01, 0x2E, 0x30, 0x81, 0xD4, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x0A, 0x06, 0x08,
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x0C, 0x31, 0x0A, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x0C, 0x01, 0x50, 0x30, 0x22, 0x18, 0x0F, 0x32, 0x30, 0x32, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x5A, 0x18, 0x0F, 0x32, 0x30, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x5A, 0x30, 0x0C, 0x31, 0x0A, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x01, 0x50, 0x30, 0x59, 0x30, 0x13,
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
    0x03, 0x42, 0x00, 0x04, 0x09, 0x39, 0x02, 0x41, 0xF8, 0x4B, 0x49, 0x85, 0xD1, 0xE7, 0x76, 0x4D, 0x60, 0xCD, 0x98,
    0xF9, 0x3D, 0x43, 0x8B, 0x8E, 0x22, 0x7C, 0xC1, 0x93, 0xE9, 0xE5, 0xBB, 0x0F, 0xAE, 0x06, 0x36, 0xBE, 0x8A, 0x1D,
    0x52, 0x0A, 0xAB, 0x3D, 0x4A, 0xBD, 0x27, 0x74, 0x0E, 0xC4, 0x3A, 0xE0, 0xA9, 0xBB, 0xD0, 0x2D, 0x9F, 0xBB, 0x98,
    0xBF, 0x64, 0x33, 0x74, 0x0A, 0xCF, 0xBE, 0xAD, 0x38, 0x52, 0xE8, 0xA3, 0x23, 0x30, 0x21, 0x30, 0x0F, 0x06, 0x03,
    0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D,
    0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
    0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0xA6, 0xD9, 0x78, 0x3C, 0x83, 0x40, 0x4A, 0x6F,
    0xB9, 0x87, 0x7D, 0x9D, 0x4B, 0x0A, 0x43, 0x70, 0x4B, 0xB7, 0x1F, 0xCA, 0xB5, 0x92, 0x0D, 0xCA, 0xC1, 0x64, 0xDD,
    0x2E, 0x8D, 0xF1, 0xA4, 0xA4, 0x02, 0x21, 0x00, 0xD7, 0xC4, 0x0C, 0xB0, 0x69, 0xC9, 0x75, 0x8F, 0x77, 0x77, 0x51,
    0xDA, 0x34, 0xAD, 0x13, 0x84, 0x5B, 0xE5, 0x12, 0x7D, 0x3C, 0xC8, 0x6E, 0x49, 0x07, 0x06, 0x76, 0x66, 0x0E, 0xDF,
    0x9E, 0x39,
};

static const uint8_t kX509CertsSM2[609] = {
    0x2C, 0x01, 0x31, 0x01, 0x30, 0x82, 0x01, 0x28, 0x30, 0x81, 0xCF, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02,
    0x30, 0x0A, 0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x75, 0x30, 0x18, 0x31, 0x0A, 0x30, 0x08, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x0C, 0x01, 0x4D, 0x31, 0x0A, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x01, 0x53,
    0x30, 0x22, 0x18, 0x0F, 0x32, 0x30, 0x32, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A,
    0x18, 0x0F, 0x32, 0x30, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x30, 0x0C,
    0x31, 0x0A, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x01, 0x4D, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D, 0x03, 0x42, 0x00,
    0x04, 0x99, 0xAE, 0xCA, 0x8B, 0x12, 0x23, 0xB5, 0x74, 0x4F, 0xCF, 0x79, 0xCB, 0xE1, 0x0C, 0x65, 0xDA, 0xC3, 0x53,
    0x31, 0xDE, 0x35, 0xD1, 0x9C, 0x36, 0xB6, 0x09, 0x48, 0x65, 0xCA, 0xA8, 0xAF, 0xB2, 0xE4, 0x41, 0xAF, 0x4B, 0x83,
    0x31, 0xFD, 0x4C, 0x03, 0xF3, 0x0C, 0x6C, 0x28, 0x5E, 0x62, 0x3B, 0x1C, 0x6B, 0x1F, 0x4D, 0x35, 0x06, 0x99, 0xD1,
    0x0D, 0xF9, 0x7B, 0xE9, 0xE7, 0x36, 0x28, 0xBD, 0xA3, 0x12, 0x30, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F,
    0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01,
    0x83, 0x75, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x7C, 0x60, 0x6E, 0xED, 0x33, 0x22, 0x9C, 0x99, 0x5F, 0xE4,
    0xBA, 0x70, 0x8F, 0xA5, 0xFD, 0x4C, 0xA6, 0x27, 0xC4, 0x32, 0xFF, 0x26, 0x70, 0xE2, 0xF6, 0xE3, 0xE4, 0xE2, 0x90,
    0x6A, 0xBF, 0x56, 0x02, 0x21, 0x00, 0xEE, 0x99, 0xF9, 0xEB, 0xB9, 0x6A, 0x65, 0xD5, 0xD9, 0x5B, 0xC2, 0x24, 0x90,
    0x82, 0xE5, 0x26, 0x7B, 0xD9, 0xC2, 0xF1, 0x70, 0x73, 0x8B, 0x27, 0x7C, 0x32, 0x0B, 0x1A, 0xF7, 0x5A, 0x2C, 0x1D,
    0x30, 0x82, 0x01, 0x2D, 0x30, 0x81, 0xD4, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x0A, 0x06, 0x08,
    0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x75, 0x30, 0x0C, 0x31, 0x0A, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x0C, 0x01, 0x53, 0x30, 0x22, 0x18, 0x0F, 0x32, 0x30, 0x32, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x5A, 0x18, 0x0F, 0x32, 0x30, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x5A, 0x30, 0x0C, 0x31, 0x0A, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x01, 0x53, 0x30, 0x59, 0x30, 0x13,
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D,
    0x03, 0x42, 0x00, 0x04, 0x4B, 0x73, 0xC5, 0xF1, 0x21, 0xA4, 0x56, 0x86, 0x23, 0x5C, 0x5B, 0xB9, 0x47, 0xF3, 0x81,
    0xB0, 0xFC, 0x7F, 0xE8, 0x4B, 0xFB, 0xE8, 0x97, 0x38, 0xAF, 0x16, 0x71, 0xAE, 0xFB, 0xAC, 0x1B, 0x07, 0xD2, 0x2B,
    0x75, 0x16, 0xED, 0x6F, 0x05, 0x85, 0x32, 0xD4, 0x40, 0x71, 0xD9, 0x64, 0xE7, 0xE1, 0xA7, 0xE0, 0x33, 0x5F, 0xE5,
    0x92, 0xE2, 0x7D, 0x2B, 0x9D, 0x54, 0x96, 0x44, 0x09, 0x6B, 0xBB, 0xA3, 0x23, 0x30, 0x21, 0x30, 0x0F, 0x06, 0x03,
    0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D,
    0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55,
    0x01, 0x83, 0x75, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0xC2, 0xAB, 0xB2, 0x9E, 0xB6, 0x81, 0xBC, 0x0A,
    0xB8, 0xD1, 0xE9, 0xF3, 0x73, 0x0D, 0x9E, 0xA8, 0x3F, 0xBA, 0xFF, 0x36, 0x29, 0x67, 0xCE, 0x11, 0x60, 0x9D, 0x99,
    0xD9, 0xA9, 0x77, 0xEF, 0x2E, 0x02, 0x20, 0x4E, 0xCE, 0x41, 0x82, 0xEC, 0xC4, 0x2C, 0x37, 0x18, 0x59, 0x9B, 0xBC,
    0x87, 0xD9, 0xC4, 0xE0, 0xEA, 0x61, 0xAD, 0xAC, 0x1F, 0xFB, 0xD4, 0x71, 0x7D, 0xA8, 0xD3, 0x47, 0x82, 0x8E, 0xA1,
    0xB2,
};

static const uint8_t kX509CertsRSA[664] = {
    0x94, 0x02, 0x00, 0x00, 0x30, 0x82, 0x02, 0x90, 0x30, 0x82, 0x01, 0x78, 0x02, 0x01, 0x01, 0x30, 0x0D, 0x06, 0x09,
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x0C, 0x31, 0x0A, 0x30, 0x08, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0C, 0x01, 0x52, 0x30, 0x22, 0x18, 0x0F, 0x32, 0x30, 0x32, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x18, 0x0F, 0x32, 0x30, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x5A, 0x30, 0x0C, 0x31, 0x0A, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x01, 0x52, 0x30,
    0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03,
    0x82, 0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00, 0xCE, 0x28, 0xAA, 0x16, 0xEF, 0x60,
    0x37, 0xEA, 0xB9, 0x1A, 0x7E, 0xA6, 0x8B, 0xDB, 0x96, 0x37, 0x81, 0x0B, 0x64, 0xF5, 0x2A, 0xF2, 0xF3, 0xD5, 0x3E,
    0x97, 0x81, 0xA7, 0x2B, 0x77, 0xF1, 0xB2, 0x94, 0xE9, 0x5D, 0x63, 0x9D, 0xE6, 0x23, 0xAA, 0xF5, 0x67, 0xBD, 0x27,
    0xB2, 0x58, 0x29, 0x84, 0x35, 0x92, 0x4E, 0x48, 0x77, 0x8B, 0xDF, 0x85, 0x0B, 0x75, 0x53, 0xFE, 0x8C, 0x7A, 0x19,
    0xD9, 0x71, 0x13, 0xD4, 0xA1, 0x59, 0xAD, 0x62, 0x79, 0x26, 0x1E, 0xF8, 0x04, 0x79, 0x5B, 0x86, 0x35, 0x11, 0xAA,
    0xD0, 0xAF, 0xC1, 0x54, 0xD9, 0x23, 0xF0, 0x8F, 0x46, 0x53, 0xA5, 0x8B, 0xDA, 0x19, 0x48, 0xF3, 0x72, 0x3A, 0xF9,
    0x4D, 0x89, 0x1E, 0xC2, 0xC1, 0xE7, 0xA0, 0x64, 0x81, 0x77, 0x42, 0xA1, 0x73, 0x93, 0x8C, 0x94, 0x14, 0xE9, 0xE9,
    0x00, 0x41, 0xE6, 0x20, 0xE2, 0x53, 0xE7, 0xA3, 0xCC, 0x26, 0x35, 0x2C, 0x52, 0x91, 0xA1, 0x34, 0xFF, 0x73, 0x24,
    0xA3, 0xA6, 0x00, 0x61, 0x8F, 0x31, 0x32, 0x8E, 0x4C, 0xE4, 0x20, 0x11, 0x26, 0xC7, 0xD8, 0x07, 0x14, 0xCC, 0x58,
    0x3C, 0xD1, 0x07, 0xB9, 0xED, 0x63, 0xDE, 0x7A, 0x25, 0x08, 0x2E, 0x62, 0xD7, 0xAE, 0x06, 0xBC, 0xC7, 0x41, 0x14,
    0x5B, 0x1F, 0xDC, 0x1F, 0xB3, 0xC5, 0x21, 0xF0, 0x6D, 0x16, 0x1E, 0x4F, 0xA3, 0x35, 0xC2, 0xD9, 0x0F, 0xB7, 0xD7,
    0x9F, 0x6C, 0x20, 0x2D, 0x5E, 0x72, 0xC7, 0xFB, 0xFE, 0x4C, 0x99, 0xF9, 0xF7, 0xD1, 0x47, 0x3D, 0xBB, 0x9B, 0x7D,
    0xA3, 0x41, 0x79, 0x27, 0x40, 0x8A, 0x6E, 0xA4, 0xB4, 0x13, 0xE3, 0x01, 0x59, 0xC2, 0xF9, 0x05, 0xB0, 0xDD, 0xB6,
    0x19, 0xE7, 0x06, 0x72, 0xA1, 0x45, 0x1C, 0x42, 0xA3, 0x92, 0x13, 0x74, 0x97, 0x10, 0x84, 0xF0, 0x75, 0xAA, 0x69,
    0xBE, 0xD0, 0xB9, 0x02, 0x03, 0x01, 0x00, 0x01, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
    0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x45, 0xFD, 0xC6, 0x81, 0x8A, 0x98, 0xBF, 0x22, 0x59, 0xF9,
    0x66, 0xAB, 0xB1, 0xFB, 0x00, 0xE3, 0x5E, 0xC2, 0x43, 0x1F, 0x95, 0xDC, 0x55, 0xAD, 0x92, 0x09, 0x2D, 0x1F, 0x2E,
    0x6D, 0x95, 0x2A, 0x40, 0x0A, 0x6D, 0x01, 0xD8, 0x7A, 0x6C, 0x9D, 0xD7, 0x6E, 0xB4, 0x33, 0xCF, 0x7F, 0x7D, 0xF5,
    0xE2, 0x3E, 0x7F, 0x19, 0x56, 0xD5, 0x16, 0xF3, 0xB0, 0xEC, 0x98, 0xA8, 0x18, 0xDA, 0xF5, 0x8D, 0x45, 0xCD, 0x54,
    0xAC, 0x0E, 0x9A, 0x3D, 0x02, 0x5B, 0x36, 0xE6, 0x66, 0x7D, 0xAF, 0xAA, 0x8D, 0x22, 0x4C, 0xBD, 0xA5, 0x05, 0x39,
    0x62, 0xC4, 0xF9, 0x48, 0xC1, 0x2F, 0xE5, 0x50, 0xFF, 0xE4, 0x89, 0x80, 0x99, 0x94, 0xF0, 0xD8, 0x66, 0x77, 0xDF,
    0x26, 0xDE, 0x9E, 0x74, 0xA3, 0x44, 0xA5, 0xB9, 0x32, 0x31, 0x43, 0x0A, 0x6A, 0xBD, 0xBD, 0xFF, 0x0D, 0x37, 0x4A,
    0x6B, 0xBE, 0x35, 0xCB, 0x01, 0xB6, 0xFC, 0x01, 0x6F, 0x01, 0x57, 0xE8, 0x84, 0x20, 0xC4, 0xF0, 0x6D, 0xDF, 0xEF,
    0x15, 0xD8, 0x3B, 0x6B, 0x3B, 0x32, 0x7A, 0x8B, 0x32, 0x4D, 0x42, 0xDD, 0x89, 0x17, 0x95, 0xF7, 0xAD, 0xA4, 0x70,
    0xC5, 0xEB, 0x38, 0x36, 0xF5, 0x9E, 0x03, 0xDA, 0x7A, 0xB8, 0x8D, 0x98, 0x01, 0x23, 0x60, 0xF2, 0x04, 0xB4, 0x79,
    0xC6, 0x45, 0x2E, 0x38, 0x30, 0x50, 0xF7, 0xCA, 0x83, 0x29, 0xC9, 0xB7, 0x81, 0x1B, 0x57, 0x84, 0xB1, 0x17, 0x8B,
    0xEA, 0x4E, 0x64, 0x6E, 0x4C, 0x85, 0x81, 0x4D, 0x62, 0x3F, 0x8F, 0xCC, 0x75, 0x2B, 0x0E, 0x4E, 0x7C, 0x98, 0x2E,
    0x2F, 0x3B, 0x37, 0xF9, 0x95, 0xEE, 0x22, 0xAC, 0x6A, 0x52, 0x55, 0xD5, 0x97, 0x36, 0x3F, 0x11, 0x53, 0x14, 0xD1,
    0xC4, 0xF1, 0x5B, 0xF7, 0xCD, 0x1D, 0x95, 0x35, 0x0A, 0xF2, 0xA1, 0x74, 0xF4, 0xF6, 0x0F, 0xC5, 0x1D, 0xFC,
};

static_assert(sizeof(kX509CertsP256) <= 1024 - kX509CertOffset, "kX509CertsP256 blob too large");
static_assert(sizeof(kX509CertsSM2) <= 1024 - kX509CertOffset, "kX509CertsSM2 blob too large");
static_assert(sizeof(kX509CertsRSA) <= 1024 - kX509CertOffset, "kX509CertsRSA blob too large");

/*! 子模式(argv_[1]):0/其他 = P256 链(缺省), 1 = SM2 链, 2 = RSA2048 自签 CA */
static void WriteX509Certs(Dongle& rockey, const Context_t* Context) {
  const uint8_t* blob = kX509CertsP256;
  size_t size = sizeof(kX509CertsP256);
  if (Context->argv_[1] == 1) {
    blob = kX509CertsSM2;
    size = sizeof(kX509CertsSM2);
  } else if (Context->argv_[1] == 2) {
    blob = kX509CertsRSA;
    size = sizeof(kX509CertsRSA);
  }
  /* 写入 dashboard[0, 4KB)(factory dataFile 0xFFFF 匿名可写区,
   * 与 Initialize.dongle 的 kOffsetX509Chain 约定同源), 设备端测试经 ReadDataFile 加载 */
  if (0 != rockey.WriteDataFile(Dongle::kFactoryDataFileId, 0, blob, size))
    rlLOGE(TAG, "X509Tests: WriteDataFile(dashboard) = %d/%08x", -1, rockey.GetLastError());
}
#endif /* __RockeyARM__ */

#if !defined(__RockeyARM__) && !defined(__EMULATOR__)
int AdminTesting_FactoryReset(RockeyARM& rockey, Context_t* Context, void* ExtendBuf) {
  int error = 0;
  rlLOGI(TAG, "... %s ...", __FUNCTION__);

  int result = rockey.FactoryReset();
  rlLOGI(TAG, "rockey.FactoryReset %d/%08x", result, rockey.GetLastError());
  if (result < 0)
    ++error;

  return error;
}

static int ExitSelectProductId = 0;
#ifdef _WIN32
BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
  if (fdwCtrlType == CTRL_C_EVENT) {
    rlLOGW(TAG, "CtrlHandler Ctrl+C %d", ++ExitSelectProductId);
    return TRUE;
  }
  return FALSE;
}
#endif /* _WIN32 */
int AdminTesting_SelectProductId(RockeyARM& rockey, Context_t* Context, void* ExtendBuf) {
  signal(SIGINT, [](int) { rlLOGW(TAG, "SIGINT %d", ++ExitSelectProductId); });
#ifdef _WIN32
  SetConsoleCtrlHandler(CtrlHandler, TRUE);
#endif /* _WIN32 */
  const char* keyWords[] = {"rLANG", "ALPHA", "ATOMC", "MAGIC", "POWER", "BRAVE", "BRAVO", "MARVY", "RAMAN",
                            "World", "Admin", "Cloud", "@User", "@Root", "wheel", "@sudo", "@unit", "robot"};

  std::set<uint32_t> keyWordsMagic;
  for (auto word : keyWords) {
    char copy[10] = "";
    strncpy(copy, word, 6);
    for (int i = 0; i < 32; ++i) {
      for (int j = 0; j < 5; ++j) {
        if (i & (1 << j))
          copy[j] = toupper(copy[j]);
        else
          copy[j] = tolower(copy[j]);
      }

      const uint32_t magic = rLANG_DECLARE_MAGIC_Xs(copy) & 0xFFFFFF03;

      for (int i = 0; i < (1 << 6); ++i) {
        char check[10];
        const auto v = magic + 4 * i;
        rLANG_DECLARE_MAGIC_Vs(v, check);
        DONGLE_VERIFY(0 == memcmp(copy, check, 4));
        keyWordsMagic.emplace(v);
      }
    }
  }
  {
    int index = 0;
    rlLOGI(TAG, ">>>> keyWordsMagic size: %zd", keyWordsMagic.size());
    for (const auto& magic : keyWordsMagic) {
      DONGLE_VERIFY(3 == (magic & 3));
      if ((index & 0x3FFF) == (rand() & 0x3FFF)) {
        char string_magic[10];
        rLANG_DECLARE_MAGIC_Vs(magic, string_magic);
        rlLOGI(TAG, "keyWordsMagic[%d/%zd] : %08X/%s", index, keyWordsMagic.size(), magic, string_magic);
      }
      ++index;
    }
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(1000));

  int error = 0;
  char filename[100], admin[32], prodId[32];
  rlLOGI(TAG, "... %s ...", __FUNCTION__);
  int A = Context->argv_[0], B = Context->argv_[1], C = Context->argv_[2], D = Context->argv_[3];
  if (B == 0)
    std::ignore = rockey.RandBytes((uint8_t*)&B, sizeof(B));
  if (C == 0)
    std::ignore = rockey.RandBytes((uint8_t*)&C, sizeof(C));
  if (D == 0)
    std::ignore = rockey.RandBytes((uint8_t*)&D, sizeof(D));

  sprintf(filename, ".bin/.select-product-id-%08x-%08x-%08x-%08x.log", A, B, C, D);
  const char* const kWorldMagicFile = ".bin/magic-product-id.log";

  FILE* magicFile = fopen(kWorldMagicFile, "a");
  if (!magicFile) {
    rlLOGE(TAG, "Can't open %s for append, errno %d", kWorldMagicFile, errno);
    exit(42);
  }

  FILE* fp = fopen(filename, "a");
  if (!fp) {
    rlLOGE(TAG, "Can't open %s for append, errno %d", filename, errno);
    exit(42);
  }

  auto WriteLog = [&](FILE* fp, const void* data, size_t size, const char* fmt, ...) {
    constexpr uint32_t TAG = rLANG_DECLARE_MAGIC_Xs("PRD@G");
    const size_t kSizeBuffer = 64 * 1024;
    char buffer[kSizeBuffer * 2];

    DONGLE_VERIFY(!data || size < 1024);

    va_list ap;
    va_start(ap, fmt);
    size_t len = vsprintf(buffer, fmt, ap);
    DONGLE_VERIFY(len > 0 && len < kSizeBuffer);
    va_end(ap);

    rlLOGXI(TAG, data, size, "%s", buffer);

    buffer[len++] = '\n';
    if (data && size > 0) {
      memcpy(&buffer[len], "DATA$:", 6);
      len += 6;
      len += rl_HEX_Write(&buffer[len], (const uint8_t*)data, (int)size);
      buffer[len++] = '\n';
    }

    buffer[len++] = '\n';
    size_t write_size = fwrite(buffer, 1, len, fp);
    fflush(fp);

    if (write_size == len)
      return 0;

    rlLOGW(TAG, "WriteLog Error %zd => %zd", len, write_size);
    return -EFAULT;
  };

  int validWords = 0;
  uint32_t chacha20_state_[16] = {(uint32_t)A, (uint32_t)B, (uint32_t)C, (uint32_t)D};
  std::this_thread::sleep_for(std::chrono::milliseconds(2000));
  const uint64_t tick_start = rLANG_GetTickCount();

  for (int loop = 0; ExitSelectProductId < 10; ++loop) {
    uint8_t stream[64];
    chacha20_state_[12] = loop;

    rlCryptoChaCha20Block(chacha20_state_, stream);
    if (WriteLog(fp, stream, 64, "Prepare GenUniqueKey %08X/%.2lf", loop,
                 1000. * loop / (rLANG_GetTickCount() - tick_start)) < 0)
      exit(5);

    int result = rockey.GenUniqueKey(stream, sizeof(stream), prodId, admin);
    if (result < 0)
      exit(6);
    if (WriteLog(fp, nullptr, 0, "GenUniqueKey prodId: %s, AdminPIN: %s", prodId, admin) < 0)
      exit(5);

    result = rockey.ChangePIN(PERMISSION::kAdministrator, admin, "FFFFFFFFFFFFFFFF", 255);
    if (result < 0)
      exit(7);
    uint32_t pid = (uint32_t)strtoul(prodId, nullptr, 16);
    if (keyWordsMagic.find(pid | 3) != keyWordsMagic.end()) {
      ++validWords;
      char magic_tags[10];
      rLANG_DECLARE_MAGIC_Vs(pid, magic_tags);
      WriteLog(magicFile, stream, sizeof(stream), "%d) GenUniqueKey %08X/%s prodId: %s, Admin: %s", validWords, pid,
               magic_tags, prodId, admin);
      WriteLog(fp, stream, sizeof(stream), "%d) GenUniqueKey %08X/%s prodId: %s, Admin: %s", validWords, pid,
               magic_tags, prodId, admin);
    }

#if 0
    rlLOGI(TAG, ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
    //std::this_thread::sleep_for(std::chrono::milliseconds(100));

    result = rockey.Open(0);
    if (result < 0)
      exit(8);
#endif

    result = rockey.VerifyPIN(PERMISSION::kAdministrator, nullptr, nullptr);
    if (result < 0)
      exit(9);
  }

  return error;
}
#endif /* RockeyARM */

int Testing_CreateDataFile(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  int error = 0;

  Context->result_[3] = rLANG_WORLD_MAGIC;

  rlLOGI(TAG, "Testing ... %s ...", __FUNCTION__);
  for (int id = 1; id <= 3; ++id) {
    if (0 != rockey.DeleteFile(SECRET_STORAGE_TYPE::kData, id)) {
      Context->error_[id - 1] = rockey.GetLastError();
      ++error;
    }
  }

  if (0 != rockey.CreateDataFile(1, 256, PERMISSION::kAdministrator, PERMISSION::kAdministrator)) {
    Context->error_[3] = rockey.GetLastError();
    ++error;
  }

  if (0 != rockey.CreateDataFile(2, 256, PERMISSION::kNormal, PERMISSION::kNormal)) {
    Context->error_[4] = rockey.GetLastError();
    ++error;
  }

  if (0 != rockey.CreateDataFile(3, 256, PERMISSION::kAnonymous, PERMISSION::kAnonymous)) {
    Context->error_[5] = rockey.GetLastError();
    ++error;
  }

  Context->result_[2] = rLANG_ATOMC_WORLD_MAGIC;

  return error;
}

int Testing_ReadWriteDataFile(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  int error = 0, counter = 0;
  uint32_t state[16];
  uint8_t stream[64], verify[64];
  memset(state, 0, sizeof(state));
  memcpy(state, Context->argv_, sizeof(Context->argv_));

  Context->result_[3] = rLANG_WORLD_MAGIC;

  rlLOGI(TAG, "Testing ... %s ...", __FUNCTION__);

  for (int id = 1; id <= 3; ++id) {
    for (int off = 0; off < 256; off += 64) {
      rlLOGI(TAG, "Write File %d %d", id, off);
      state[12] = counter++;
      rlCryptoChaCha20Block(state, stream);
      if (0 != rockey.WriteDataFile(id, off, stream, sizeof(stream))) {
        Context->error_[7] = rockey.GetLastError();
        ++error;
      }
    }
  }

  counter = 0;
  for (int id = 1; id <= 3; ++id) {
    for (int off = 0; off < 256; off += 64) {
      rlLOGI(TAG, "Read File %d %d", id, off);
      state[12] = counter++;
      rlCryptoChaCha20Block(state, verify);
      if (0 != rockey.ReadDataFile(id, off, stream, sizeof(stream))) {
        Context->error_[6] = rockey.GetLastError();
        ++error;
      }
      if (0 != memcmp(stream, verify, sizeof(verify)))
        ++error;
    }
  }

  Context->result_[2] = rLANG_ATOMC_WORLD_MAGIC;

  return error;
}

int Testing_ReadWriteFactoryData(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  int error = 0, counter = 0;
  uint32_t state[16];
  uint8_t stream[64], verify[64];
  memset(state, 0, sizeof(state));
  memcpy(state, Context->argv_, sizeof(Context->argv_));

  Context->result_[3] = rLANG_WORLD_MAGIC;

  rlLOGI(TAG, "Testing ... %s ...", __FUNCTION__);

  for (int off = 0; off < 8192; off += 64) {
    rlLOGI(TAG, "Write File %x %d", Dongle::kFactoryDataFileId, off);
    state[12] = counter++;
    rlCryptoChaCha20Block(state, stream);
    if (0 != rockey.WriteDataFile(Dongle::kFactoryDataFileId, off, stream, sizeof(stream))) {
      Context->error_[7] = rockey.GetLastError();
      ++error;
    }
  }

  counter = 0;
  for (int off = 0; off < 8192; off += 64) {
    rlLOGI(TAG, "Read File %x %d", Dongle::kFactoryDataFileId, off);
    state[12] = counter++;
    rlCryptoChaCha20Block(state, verify);
    if (0 != rockey.ReadDataFile(Dongle::kFactoryDataFileId, off, stream, sizeof(stream))) {
      Context->error_[6] = rockey.GetLastError();
      ++error;
    }
    if (0 != memcmp(stream, verify, sizeof(verify)))
      ++error;
  }

  Context->result_[2] = rLANG_ATOMC_WORLD_MAGIC;

  return error;
}

int Testing_CreateRSAFile(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  int error = 0;

  Context->result_[3] = rLANG_WORLD_MAGIC;

  rlLOGI(TAG, "Testing ... %s ...", __FUNCTION__);

  for (int id = 100; id <= 102; ++id) {
    if (rockey.DeleteFile(SECRET_STORAGE_TYPE::kRSA, id) < 0) {
      rlLOGE(TAG, "rockey.DeleteFile kRSA %d Error", id);
      Context->error_[id - 100] = rockey.GetLastError();
      ++error;
    }
  }

  if (rockey.CreatePKEYFile(SECRET_STORAGE_TYPE::kRSA, 2048, 100,
                            PKEY_LICENCE{}.SetPermission(PERMISSION::kAdministrator)) < 0) {
    ++error;
    Context->error_[4] = rockey.GetLastError();
    rlLOGE(TAG, "rockey.CreatePKEYFile 100 Error");
  }
  if (rockey.CreatePKEYFile(SECRET_STORAGE_TYPE::kRSA, 2048, 101, PKEY_LICENCE{}.SetPermission(PERMISSION::kNormal)) <
      0) {
    ++error;
    Context->error_[5] = rockey.GetLastError();
    rlLOGE(TAG, "rockey.CreatePKEYFile 101 Error");
  }
  if (rockey.CreatePKEYFile(SECRET_STORAGE_TYPE::kRSA, 2048, 102,
                            PKEY_LICENCE{}.SetPermission(PERMISSION::kAnonymous)) < 0) {
    ++error;
    Context->error_[6] = rockey.GetLastError();
    rlLOGE(TAG, "rockey.CreatePKEYFile 102 Error");
  }

  Context->result_[2] = rLANG_ATOMC_WORLD_MAGIC;

  return error;
}

int Testing_RSAExec(Dongle& rockey, Context_t* Context_, void* ExtendBuf) {
  struct RSAExecContext : public Context_t {
    uint8_t prikey_[256];
    uint8_t pubkey_[256];
  };
  RSAExecContext* Context = static_cast<RSAExecContext*>(Context_);
  memset(Context->prikey_, 0, 256);
  memset(Context->pubkey_, 0, 256);

  int error = 0;
  uint8_t input[128], output[256], verify[256];

#if defined(__EMULATOR__)
  constexpr int kTestLoop = 100;
#else  /* __EMULATOR__ */
  constexpr int kTestLoop = 2;
#endif /* __EMULATOR__ */

  for (int i = 0; i < kTestLoop; ++i) {
    size_t szOut = 256;
    uint32_t modules = 0;
    if (rockey.GenerateRSA(100, &modules, Context->pubkey_, Context->prikey_) < 0) {
      rlLOGE(TAG, "rockey.GenerateRSA 100 Error");
      return 123;
    }

    rlLOGXI(TAG, Context->pubkey_, 256, "rockey.GenerateRSA %x", modules);

    rlLOGI(TAG, "RSA.Test.loop %d => %d", i, error);
    std::ignore = rockey.RandBytes(input, sizeof(input));

    szOut = sizeof(input);
    memcpy(output, input, sizeof(input));
    if (rockey.RSAPrivate(100, output, &szOut, true) < 0) {
      rlLOGE(TAG, "rockey.RSAPrivate sign error");
      ++error;
    } else {
      memcpy(verify, output, szOut);
      if (rockey.RSAPublic(2048, modules, Context->pubkey_, verify, &szOut, false) < 0) {
        rlLOGE(TAG, "rockey.RSAPublic verify error");
        ++error;
      } else {
        DONGLE_VERIFY(szOut == sizeof(input) && 0 == memcmp(input, verify, sizeof(input)));
      }
    }

    if (rockey.ImportRSA(102, 2048, modules, Context->pubkey_, Context->prikey_) < 0) {
      rlLOGE(TAG, "rockey.ImportRSA 102 Error");
      return 234;
    }

    szOut = sizeof(input);
    memcpy(output, input, sizeof(input));
    if (rockey.RSAPublic(2048, modules, Context->pubkey_, output, &szOut, true) < 0) {
      rlLOGE(TAG, "rockey.RSAPublic encrypt error");
      ++error;
    } else {
      DONGLE_VERIFY(szOut == 256);
      memcpy(verify, output, szOut);

      if (rockey.RSAPrivate(102, verify, &szOut, false) < 0) {
        rlLOGE(TAG, "rockey.RSAPrivate decrypt 102 error");
        ++error;
      } else {
        DONGLE_VERIFY(szOut == sizeof(input) && 0 == memcmp(input, verify, sizeof(input)));
      }

      szOut = 256;
      if (rockey.RSAPrivate(2048, modules, Context->pubkey_, Context->prikey_, output, &szOut, false) < 0) {
        rlLOGE(TAG, "rockey.RSAPrivate decrypt error");
        ++error;
      } else {
        DONGLE_VERIFY(szOut == sizeof(input) && 0 == memcmp(input, output, sizeof(input)));
      }
    }
  }

  return error;
}

int Testing_SM2Exec(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  int error = 0;

#if defined(__EMULATOR__)
  constexpr int kTestLoop = 100;
#else  /* __EMULATOR__ */
  constexpr int kTestLoop = 2;
#endif /* __EMULATOR__ */
  for (int loop = 0; loop < kTestLoop; ++loop) {
    rlLOGI(TAG, "Testing_SM2Exec %d/%d => %d", loop, kTestLoop, error);
    if (rockey.DeleteFile(SECRET_STORAGE_TYPE::kSM2, 0x8100) < 0) {
      ++error;
      Context->error_[0] = rockey.GetLastError();
    }

    if (rockey.DeleteFile(SECRET_STORAGE_TYPE::kSM2, 0x8101) < 0) {
      ++error;
      Context->error_[1] = rockey.GetLastError();
    }

    if (rockey.CreatePKEYFile(SECRET_STORAGE_TYPE::kSM2, 256, 0x8100) < 0) {
      ++error;
      Context->error_[2] = rockey.GetLastError();
    }

    if (rockey.CreatePKEYFile(SECRET_STORAGE_TYPE::kSM2, 256, 0x8101) < 0) {
      ++error;
      Context->error_[3] = rockey.GetLastError();
    }

    uint8_t X[32], Y[32], K[32], H[32], R[32], S[32];
    DWORD tick0 = 0, tick1 = 0, tick2 = 0, tick3 = 0, tick4 = 0, tick5 = 0;
    rockey.GetTickCount(&tick0);

    for (int i = 0; i < 5; ++i) {
      if (rockey.GenerateSM2(0x8100, X, Y, K)) {
        ++error;
        Context->error_[4] = rockey.GetLastError();
        return 111;
      } else {
        rlLOGXI(TAG, X, 32, "SM2.X");
        rlLOGXI(TAG, Y, 32, "SM2.Y");
        rlLOGXI(TAG, K, 32, "SM2.K");
      }

      rockey.GetTickCount(&tick1);
      if (rockey.CheckPointOnCurveSM2(X, Y) < 0) {
        ++error;
        rlLOGE(TAG, "rockey.CheckPointOnCurveSM2 Error ...");
      }
      rockey.GetTickCount(&tick2);
      X[0] ^= 1;
      if (rockey.CheckPointOnCurveSM2(X, Y) >= 0) {
        ++error;
        rlLOGE(TAG, "rockey.CheckPointOnCurveSM2 Error ...");
      }
      X[0] ^= 1;
      rockey.GetTickCount(&tick3);
      rockey.DecompressPointSM2(S, X, Y[31] % 2 == 1);
      rockey.GetTickCount(&tick4);

      Context->ts_[0] = tick1;
      Context->ts_[1] = tick2;
      Context->ts_[2] = tick3;
      Context->ts_[3] = tick4;

      if (0 != memcmp(Y, S, 32)) {
        rlLOGXW(TAG, Y, 32, "DecompressPointSM2 Error!");
        rlLOGXW(TAG, S, 32, "DecompressPointSM2 Error!");
        ++error;
      }
    }
    rockey.GetTickCount(&tick5);
    Context->ts_[5] = tick5 - tick0;
    Context->ts_[6] = tick0;
    Context->ts_[7] = tick5;

    for (int i = 0; i < 2; ++i) {
      std::ignore = rockey.RandBytes(H, 32);
      if (rockey.SM2Sign(0x8100, H, R, S) < 0 || rockey.SM2Verify(X, Y, H, R, S) < 0 ||
          rockey.SM2Sign(K, H, R, S) < 0 || rockey.SM2Verify(X, Y, H, R, S) < 0) {
        ++error;
        Context->error_[5] = rockey.GetLastError();
      }
    }

    for (int i = 0; i < 2; ++i) {
      if (rockey.ImportSM2(0x8101, K) < 0) {
        ++error;
        Context->error_[6] = rockey.GetLastError();
      }
    }

    for (int i = 0; i < 2; ++i) {
      if (rockey.SM2Sign(0x8101, H, R, S) < 0 || rockey.SM2Verify(X, Y, H, R, S) < 0 ||
          rockey.SM2Sign(K, H, R, S) < 0 || rockey.SM2Verify(X, Y, H, R, S) < 0) {
        ++error;
        Context->error_[7] = rockey.GetLastError();
      }
    }

#if 1
    for (int i = 0; i < 2; ++i) {
      S[0] ^= 1;
      if (rockey.SM2Verify(X, Y, H, R, S) >= 0)
        ++error;
      S[0] ^= 1;
    }
#endif

    for (int i = 0; i < 2; ++i) {
#if 1
      X[0] ^= 1;
      if (rockey.SM2Verify(X, Y, H, R, S) >= 0)
        ++error;
      X[0] ^= 1;

      H[0] ^= 1;
      if (rockey.SM2Verify(X, Y, H, R, S) >= 0)
        ++error;
      H[0] ^= 1;

      DONGLE_VERIFY(rockey.SM2Verify(X, Y, H, R, S) >= 0);
#endif
    }

    uint8_t VV[32];
    size_t szVV = 32;
    uint8_t sm2_cipher_[128];
    memset(sm2_cipher_, 0xEE, sizeof(sm2_cipher_));

#if 1
    for (int i = 0; i < 3; ++i) {
      X[0] ^= 1;
      if (rockey.CheckPointOnCurveSM2(X, Y) >= 0)
        ++error;
      X[0] ^= 1;
    }
#endif

    uint8_t CK[32];
    std::ignore = rockey.RandBytes(H, 32);
    if (rockey.SM2Encrypt(X, Y, H, 16, sm2_cipher_) < 0) {
      ++error;
      rlLOGXI(TAG, sm2_cipher_, sizeof(sm2_cipher_), "sm2_cipher_.encrypt.16");
    } else if (rockey.CheckPointOnCurveSM2(sm2_cipher_, sm2_cipher_ + 32) < 0) {
      ++error;
      rlLOGI(TAG, "CheckPointOnCurveSM2.sm2.cipher Error ....");
    }

    if (rockey.DecompressPointSM2(CK, sm2_cipher_, sm2_cipher_[63] % 2) < 0 || 0 != memcmp(CK, sm2_cipher_ + 32, 32)) {
      ++error;
      rlLOGI(TAG, "DecompressPointSM2.sm2.cipher Error ....");
    }

    szVV = 32;
    if (rockey.SM2Decrypt(0x8101, sm2_cipher_, 96 + 16, VV, &szVV) < 0 || szVV != 16 || 0 != memcmp(VV, H, 16)) {
      ++error;
      rlLOGW(TAG, "sm2_cipher_.decrypt.16 error");
    }

    std::ignore = rockey.RandBytes(H, 32);
    if (rockey.SM2Encrypt(X, Y, H, 10, sm2_cipher_) < 0) {
      ++error;
      rlLOGXI(TAG, sm2_cipher_, sizeof(sm2_cipher_), "sm2_cipher_.encrypt.16");
    } else if (rockey.CheckPointOnCurveSM2(sm2_cipher_, sm2_cipher_ + 32) < 0) {
      ++error;
      rlLOGI(TAG, "CheckPointOnCurveSM2.sm2.cipher Error ....");
    }

    if (rockey.DecompressPointSM2(CK, sm2_cipher_, sm2_cipher_[63] % 2) < 0 || 0 != memcmp(CK, sm2_cipher_ + 32, 32)) {
      ++error;
      rlLOGI(TAG, "DecompressPointSM2.sm2.cipher Error ....");
    }

    szVV = 32;
    if (rockey.SM2Decrypt(K, sm2_cipher_, 96 + 10, VV, &szVV) < 0 || szVV != 10 || 0 != memcmp(VV, H, 10)) {
      ++error;
      rlLOGXI(TAG, sm2_cipher_, sizeof(sm2_cipher_), "sm2_cipher_.decrypt.16");
    }

    if (rockey.SM2Encrypt(X, Y, H, 32, sm2_cipher_) < 0) {
      ++error;
      rlLOGXI(TAG, sm2_cipher_, sizeof(sm2_cipher_), "sm2_cipher_");
    } else if (rockey.CheckPointOnCurveSM2(sm2_cipher_, sm2_cipher_ + 32) < 0) {
      ++error;
      rlLOGI(TAG, "CheckPointOnCurveSM2.sm2.cipher Error ....");
    }

    if (rockey.DecompressPointSM2(CK, sm2_cipher_, sm2_cipher_[63] % 2) < 0 || 0 != memcmp(CK, sm2_cipher_ + 32, 32)) {
      ++error;
      rlLOGI(TAG, "DecompressPointSM2.sm2.cipher Error ....");
    }

    szVV = 32;
    Context->result_[3] = rockey.SM2Decrypt(K, sm2_cipher_, 96 + 32, VV, &szVV);
    if (Context->result_[3] < 0 || szVV != 32 || 0 != memcmp(VV, H, 32)) {
      ++error;
    }

#if 1
    K[0] ^= 1;
    DONGLE_VERIFY(rockey.SM2Decrypt(K, sm2_cipher_, 96 + 32, VV, &szVV) < 0);
    K[0] ^= 1;

    sm2_cipher_[0] ^= 1;
    DONGLE_VERIFY(rockey.SM2Decrypt(K, sm2_cipher_, 96 + 32, VV, &szVV) < 0);
    sm2_cipher_[0] ^= 1;

    sm2_cipher_[64] ^= 1;
    DONGLE_VERIFY(rockey.SM2Decrypt(K, sm2_cipher_, 96 + 32, VV, &szVV) < 0);
    sm2_cipher_[64] ^= 1;

    DONGLE_VERIFY(rockey.SM2Decrypt(K, sm2_cipher_, 96 + 32, VV, &szVV) >= 0);
#endif

    memset(VV, 0, sizeof(VV));
    if (rockey.SM2Decrypt(0x8101, sm2_cipher_, 96 + 32, VV, &szVV) < 0) {
      ++error;
      rlLOGW(TAG, "SM2Decrypt 0x8101 Error %08X", Context->result_[2] = rockey.GetLastError());
    } else {
      DONGLE_VERIFY(szVV == 32 && 0 == memcmp(VV, H, 32));
    }
  }

  return error;
}

int Testing_P256Exec(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  int error = 0;

#if defined(__EMULATOR__)
  constexpr int kTestLoop = 100;
#else  /* __EMULATOR__ */
  constexpr int kTestLoop = 2;
#endif /* __EMULATOR__ */

  for (int loop = 0; loop < kTestLoop; ++loop) {
    rlLOGI(TAG, "Testing_P256Exec %d/%d => %d", loop, kTestLoop, error);

    if (rockey.DeleteFile(SECRET_STORAGE_TYPE::kP256, 0x100) < 0) {
      ++error;
      Context->error_[0] = rockey.GetLastError();
    }

    if (rockey.DeleteFile(SECRET_STORAGE_TYPE::kP256, 0x101) < 0) {
      ++error;
      Context->error_[1] = rockey.GetLastError();
    }

    if (rockey.CreatePKEYFile(SECRET_STORAGE_TYPE::kP256, 256, 0x100) < 0) {
      ++error;
      Context->error_[2] = rockey.GetLastError();
    }

    if (rockey.CreatePKEYFile(SECRET_STORAGE_TYPE::kP256, 256, 0x101) < 0) {
      ++error;
      Context->error_[3] = rockey.GetLastError();
    }

    uint8_t X[32], Y[32], K[32], H[32], R[32], S[32];
    for (int i = 0; i < 2; ++i) {
      if (rockey.GenerateP256(0x100, X, Y, K)) {
        ++error;
        Context->error_[4] = rockey.GetLastError();
        return 111;
      } else {
        rlLOGXI(TAG, X, 32, "P256.X");
        rlLOGXI(TAG, Y, 32, "P256.Y");
        rlLOGXI(TAG, K, 32, "P256.K");
      }

      if (rockey.ComputePubkeyPrime256v1(R, S, K) < 0 || 0 != memcmp(X, R, 32) || 0 != memcmp(Y, S, 32)) {
        ++error;
        rlLOGE(TAG, "ComputePubkeyPrime256v1 Error ...");
      } else {
        rlLOGXI(TAG, R, 32, "P256.X");
        rlLOGXI(TAG, S, 32, "P256.Y");
      }

      if (rockey.CheckPointOnCurvePrime256v1(X, Y) < 0) {
        ++error;
        rlLOGE(TAG, "CheckPointOnCurvePrime256v1 Error ...");
      }

      X[0] ^= 1;
      if (rockey.CheckPointOnCurvePrime256v1(X, Y) >= 0) {
        ++error;
        rlLOGE(TAG, "CheckPointOnCurvePrime256v1 Error ...");
      }
      X[0] ^= 1;

      uint8_t V[32];
      if (rockey.DecompressPointPrime256v1(V, X, Y[31] % 2 != 0) < 0 || 0 != memcmp(V, Y, 32)) {
        ++error;
        rlLOGXE(TAG, V, 32, "DecompressPointPrime256v1 Error ...");
      }

      std::ignore = rockey.RandBytes(H, 32);
      if (rockey.SignMessagePrime256v1(K, H, R, S) < 0) {
        ++error;
        rlLOGE(TAG, "SignMessagePrime256v1 Error ...");
      }

      if (rockey.P256Verify(X, Y, H, R, S) < 0) {
        ++error;
        rlLOGE(TAG, "SignMessagePrime256v1/P256Verify Error ...");
      }

      if (rockey.VerifySignPrime256v1(X, Y, H, R, S) < 0) {
        ++error;
        rlLOGE(TAG, "VerifySignPrime256v1 Error ...");
      }

      R[0] ^= 1;
      if (rockey.VerifySignPrime256v1(X, Y, H, R, S) >= 0) {
        ++error;
        rlLOGE(TAG, "VerifySignPrime256v1 Error ...");
      }
      R[0] ^= 1;

      uint8_t K2[32], X2[32], Y2[32];
      if (rockey.GenerateKeyPairPrime256v1(X2, Y2, K2) < 0) {
        ++error;
        rlLOGE(TAG, "GenerateKeyPairPrime256v1 Error ...");
      }

      uint8_t SECRET1[32], SECRET2[32];
      if (rockey.ComputeSecretPrime256v1(SECRET1, X, Y, K2) < 0) {
        ++error;
        rlLOGE(TAG, "ComputeSecretPrime256v1 Error ...");
      }

      if (rockey.ComputeSecretPrime256v1(SECRET2, X2, Y2, K) < 0) {
        ++error;
        rlLOGE(TAG, "ComputeSecretPrime256v1 Error ...");
      }

      if (0 != memcmp(SECRET1, SECRET2, 32)) {
        ++error;
        rlLOGE(TAG, "0 != memcmp(SECRET1, SECRET2, 32)");
        rlLOGXE(TAG, SECRET1, 32, "SECRET1");
        rlLOGXE(TAG, SECRET2, 32, "SECRET2");
      } else {
        rlLOGXI(TAG, SECRET1, 32, "ComputeSecretPrime256v1 OK");
      }
    }

    std::ignore = rockey.RandBytes(H, 32);
    if (rockey.P256Sign(0x100, H, R, S) < 0 || rockey.P256Verify(X, Y, H, R, S) < 0 ||
        rockey.P256Sign(K, H, R, S) < 0 || rockey.P256Verify(X, Y, H, R, S) < 0) {
      ++error;
      Context->error_[5] = rockey.GetLastError();
    }

    if (rockey.GenerateKeyPairPrime256v1(X, Y, K) < 0) {
      ++error;
      rlLOGE(TAG, "GenerateKeyPairPrime256v1 ... 2 Error ...");
    }

    if (rockey.ImportP256(0x101, K) < 0) {
      ++error;
      Context->error_[6] = rockey.GetLastError();
    }

    if (rockey.P256Sign(0x101, H, R, S) < 0 || rockey.P256Verify(X, Y, H, R, S) < 0 ||
        rockey.P256Sign(K, H, R, S) < 0 || rockey.P256Verify(X, Y, H, R, S) < 0) {
      ++error;
      Context->error_[7] = rockey.GetLastError();
    }

#if 1
    S[0] ^= 1;
    if (rockey.P256Verify(X, Y, H, R, S) >= 0)
      ++error;
    S[0] ^= 1;

    H[0] ^= 1;
    if (rockey.P256Verify(X, Y, H, R, S) >= 0)
      ++error;
    H[0] ^= 1;
#endif

#if 1
    X[0] ^= 1;
    if (rockey.P256Verify(X, Y, H, R, S) >= 0)
      ++error;
    X[0] ^= 1;

    DONGLE_VERIFY(rockey.P256Verify(X, Y, H, R, S) >= 0);
#endif
  }

  return error;
}

int Testing_KeyExec(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  int error = 0;
  uint8_t K[16], input[64], cipher[64], verify[64];

#if defined(__EMULATOR__)
  constexpr int kTestLoop = 1000;
#else  /* __EMULATOR__ */
  constexpr int kTestLoop = 2;
#endif /* __EMULATOR__ */

  for (int loop = 0; loop < kTestLoop; ++loop) {
    rlLOGI(TAG, "Testing_KeyExec %d/%d %d", loop, kTestLoop, error);

    if (rockey.DeleteFile(SECRET_STORAGE_TYPE::kTDES, 8) < 0)
      ++error;

    if (rockey.DeleteFile(SECRET_STORAGE_TYPE::kSM4, 9) < 0)
      ++error;

    if (rockey.CreateKeyFile(8, PERMISSION::kAdministrator, SECRET_STORAGE_TYPE::kTDES) < 0)
      ++error;

    if (rockey.CreateKeyFile(9, PERMISSION::kAdministrator, SECRET_STORAGE_TYPE::kSM4) < 0)
      ++error;

    if (rockey.RandBytes(K, sizeof(K)) < 0)
      ++error;

    if (rockey.RandBytes(input, sizeof(input)) < 0)
      ++error;

    memcpy(cipher, input, sizeof(input));
    if (rockey.SM4ECB(K, cipher, sizeof(input), true) < 0)
      ++error;

    memcpy(verify, cipher, sizeof(cipher));
    if (rockey.SM4ECB(K, verify, sizeof(input), false) < 0)
      ++error;

    if (0 != memcmp(input, verify, sizeof(input)))
      ++error;

    if (rockey.RandBytes(K, sizeof(K)) < 0)
      ++error;

    if (rockey.RandBytes(input, sizeof(input)) < 0)
      ++error;

    memcpy(cipher, input, sizeof(input));
    if (rockey.TDESECB(K, cipher, sizeof(input), true) < 0)
      ++error;

    memcpy(verify, cipher, sizeof(cipher));
    if (rockey.TDESECB(K, verify, sizeof(input), false) < 0)
      ++error;

    if (0 != memcmp(input, verify, sizeof(input)))
      ++error;

    if (rockey.RandBytes(K, sizeof(K)) < 0)
      ++error;

    if (rockey.WriteKeyFile(8, K, 16, SECRET_STORAGE_TYPE::kTDES) < 0)
      ++error;

    if (rockey.RandBytes(input, sizeof(input)) < 0)
      ++error;

    memcpy(cipher, input, sizeof(input));
    if (rockey.TDESECB(8, cipher, sizeof(cipher), true) < 0)
      ++error;

    memcpy(verify, cipher, sizeof(input));
    if (rockey.TDESECB(K, verify, sizeof(verify), false) < 0)
      ++error;

    memcpy(cipher, input, sizeof(input));
    if (rockey.TDESECB(K, cipher, sizeof(cipher), true) < 0)
      ++error;

    memcpy(verify, cipher, sizeof(input));
    if (rockey.TDESECB(8, verify, sizeof(verify), false) < 0)
      ++error;

    if (0 != memcmp(input, verify, sizeof(input)))
      ++error;

    if (rockey.RandBytes(K, sizeof(K)) < 0)
      ++error;
    if (rockey.WriteKeyFile(9, K, 16, SECRET_STORAGE_TYPE::kSM4) < 0)
      ++error;

    if (rockey.RandBytes(input, sizeof(input)) < 0)
      ++error;
    memcpy(cipher, input, sizeof(input));
    if (rockey.SM4ECB(9, cipher, sizeof(cipher), true) < 0)
      ++error;

    memcpy(verify, cipher, sizeof(cipher));
    if (rockey.SM4ECB(K, verify, sizeof(verify), false) < 0)
      ++error;

    if (rockey.RandBytes(input, sizeof(input)) < 0)
      ++error;
    memcpy(cipher, input, sizeof(input));
    if (rockey.SM4ECB(K, cipher, sizeof(cipher), true) < 0)
      ++error;

    memcpy(verify, cipher, sizeof(cipher));
    if (rockey.SM4ECB(9, verify, sizeof(verify), false) < 0)
      ++error;
  }

  return error;
}

int Testing_HashExec(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  int error = 0;
  uint8_t sha1[20];
  uint8_t sm3[32];
  uint8_t input[100];

#if defined(__EMULATOR__)
  constexpr int kTestLoop = 100000;
#else  /* __EMULATOR__ */
  constexpr int kTestLoop = 2;
#endif /* __EMULATOR__ */

  for (int loop = 0; loop < kTestLoop; ++loop) {
    rlLOGI(TAG, "Testing_HashExec %d/%d %d", loop, kTestLoop, error);

    for (int i = 1; i <= 10; ++i) {
      if (rockey.RandBytes(input, sizeof(input)) < 0)
        ++error;

      if (rockey.SHA1(input, i * 10, sha1) < 0)
        ++error;

      if (rockey.SM3(input, i * 10, sm3) < 0)
        ++error;

#if !defined(X_BUILD_native)
      auto SM3 = [](const unsigned char* d, size_t n, unsigned char* md) {
        SM3_CTX ctx;
        sm3_init(&ctx);
        sm3_update(&ctx, d, n);
        sm3_final(md, &ctx);
      };

      // input[0] ^= 1;
      uint8_t v_sha1[20], v_sm3[32];
      SHA1(input, i * 10, v_sha1);
      SM3(input, i * 10, v_sm3);

      if (0 != memcmp(v_sha1, sha1, sizeof(sha1)))
        ++error;
      if (0 != memcmp(v_sm3, sm3, sizeof(sm3)))
        ++error;
#endif /* X_BUILD_native */
    }
  }

  return error;
}

int Testing_Secp256K1Exec(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  int error = 0;
  uint8_t X1[32], Y1[32], K1[32], V1[32];
  uint8_t X2[32], Y2[32], K2[32], V2[32];

#if defined(__EMULATOR__)
  constexpr int kTestLoop = 100;
#else  /* __EMULATOR__ */
  constexpr int kTestLoop = 2;
#endif /* __EMULATOR__ */

  for (int loop = 0; loop < kTestLoop; ++loop) {
    rlLOGI(TAG, "Testing_Secp256K1Exec %d/%d %d", loop, kTestLoop, error);

    for (int i = 0; i < 2; ++i) {
      if (rockey.GenerateKeyPairSecp256k1(X1, Y1, K1) < 0) {
        ++error;
        rlLOGE(TAG, "GenerateKeyPairSecp256k1..1 Error ...");
      }
      if (rockey.ComputePubkeySecp256k1(X2, Y2, K1) < 0 || 0 != memcmp(X1, X2, 32) || 0 != memcmp(Y1, Y2, 32)) {
        ++error;
        rlLOGE(TAG, "ComputePubkeySecp256k1 ..1 Error ...");
      } else {
        rlLOGXI(TAG, X1, 32, "Secp256k1.X");
        rlLOGXI(TAG, Y1, 32, "Secp256k1.Y");
      }
      if (rockey.GenerateKeyPairSecp256k1(X2, Y2, K2) < 0) {
        ++error;
        rlLOGE(TAG, "GenerateKeyPairSecp256k1..2 Error ...");
      }
      if (rockey.CheckPointOnCurveSecp256k1(X1, Y1) < 0) {
        ++error;
        rlLOGE(TAG, "CheckPointOnCurveSecp256k1 Error ...");
      }
      X1[0] ^= 1;
      if (rockey.CheckPointOnCurveSecp256k1(X1, Y1) >= 0) {
        ++error;
        rlLOGE(TAG, "CheckPointOnCurveSecp256k1 Error ...");
      }
      X1[0] ^= 1;

      if (rockey.ComputeSecretSecp256k1(V1, X1, Y1, K2) < 0) {
        ++error;
        rlLOGE(TAG, "ComputeSecretSecp256k1 .. 1 Error ...");
      }
      if (rockey.ComputeSecretSecp256k1(V2, X2, Y2, K1) < 0) {
        ++error;
        rlLOGE(TAG, "ComputeSecretSecp256k1 .. 2 Error ...");
      }

      if (0 != memcmp(V1, V2, 32)) {
        ++error;
        rlLOGE(TAG, "0 != memcmp(V1, V2, 32)");
      } else {
        rlLOGXI(TAG, V1, 32, "ComputeSecretSecp256k1 OK");
      }

      uint8_t H[32], R[32], S[32];
      if (rockey.RandBytes(H, 32) < 0) {
        ++error;
        rlLOGE(TAG, "RandBytes 32 Error ...");
      }

      if (rockey.SignMessageSecp256k1(K1, H, R, S) < 0) {
        ++error;
        rlLOGE(TAG, "SignMessageSecp256k1 Error ...");
      }

      R[0] ^= 1;
      if (rockey.VerifySignSecp256k1(X1, Y1, H, R, S) >= 0) {
        ++error;
        rlLOGE(TAG, "VerifySignSecp256k1 ... 1 Error ...");
      }
      R[0] ^= 1;

      H[0] ^= 1;
      if (rockey.VerifySignSecp256k1(X1, Y1, H, R, S) >= 0) {
        ++error;
        rlLOGE(TAG, "VerifySignSecp256k1 ... 1 Error ...");
      }
      H[0] ^= 1;

      if (rockey.VerifySignSecp256k1(X1, Y1, H, R, S) < 0) {
        ++error;
        rlLOGE(TAG, "VerifySignSecp256k1 ... 1 Error ...");
      }
    }
  }

  return error;
}

/**
 *! ChaCha20-Poly1305 的 **AAD 路径**测试(RFC 8439 §2.8.2 标准向量 + 篡改负例 + 宿主对拍)。
 *! 背景: `rlCryptoChaChaPolyUpdateAAd` 此前只在 `rlCryptoRandBytes` 内部被用到, 脚本侧的
 *! ExChaChaPolySeal/Open 不支持 AAD(与 JS/world 的 CipherAEAD.Seal(input,nonce,aad) 不一致);
 *! 本用例用于确认 AAD 在**设备端**与 host/OpenSSL 完全一致。
 */
int Testing_ChaChaPolyAad(Dongle& rockey, void* work) {
  int error = 0;

  /*! 工作区用调用方给的 1KB(设备端就是 ExtendBuf): 本用例曾把 ~1.4KB 缓冲区放在栈上,
   *! 叠加 Testing_ChaChaPoly 的 784B 帧后超过设备 2032B 栈预算(静态栈检查超 392-496B),
   *! 表现为"只在 ukey 上卡死/异常" —— 设备端任何大缓冲都必须走 ExtendBuf/InOutBuf。 */
  uint8_t* const w = static_cast<uint8_t*>(work);
  uint8_t* const plain = w;         /* data_len */
  uint8_t* const ct_ok = w + 128;   /* data_len + 16 */
  uint8_t* const ct_tmp = w + 256;  /* data_len + 16 */
  uint8_t* const scratch = w + 384; /* data_len + 16 */
  const size_t data_len = 97;

  /* ---- 1) 运行期自洽性测试(所有平台, 包括 ukey 设备端) ----
   *! 这里刻意不使用任何静态常量: 固件的 `.rodata` 必须为空(链路脚本 ASSERT)。
   *! 判据(足以证明"AAD 真的参与了认证"):
   *!   a) 密文与 AAD 无关(三条路径的密文必须相同);
   *!   b) AAD 不同 ⇒ tag 必须不同;有/无 AAD ⇒ tag 必须不同;
   *!   c) 用正确 AAD Open 成功并还原明文;用错误/缺失 AAD Open 必须失败。 */
  {
    uint8_t key[32], nonce[12], aad_ok[32], aad_bad[32];
    size_t size;

    std::ignore = rockey.RandBytes(key, sizeof(key));
    std::ignore = rockey.RandBytes(nonce, sizeof(nonce));
    std::ignore = rockey.RandBytes(aad_ok, sizeof(aad_ok));
    std::ignore = rockey.RandBytes(plain, data_len);
    memcpy(aad_bad, aad_ok, sizeof(aad_bad));
    aad_bad[sizeof(aad_bad) - 1] ^= 0x01; /* 只差 1 bit */

    /* a) 带 AAD(正确) —— 结果留在 ct_ok 供后面 Open 用 */
    memcpy(scratch, plain, data_len);
    size = data_len;
    if (rockey.CHACHAPOLY_Seal(key, nonce, scratch, &size, aad_ok, sizeof(aad_ok)) < 0 || size != data_len + 16) {
      ++error;
      rlLOGE(TAG, "ChaChaPolyAad: Seal(aad_ok) 失败");
    } else {
      memcpy(ct_ok, scratch, data_len + 16);
    }

    /* a) 带 AAD(错误, 只差 1 bit) */
    memcpy(scratch, plain, data_len);
    size = data_len;
    if (rockey.CHACHAPOLY_Seal(key, nonce, scratch, &size, aad_bad, sizeof(aad_bad)) < 0) {
      ++error;
      rlLOGE(TAG, "ChaChaPolyAad: Seal(aad_bad) 失败");
    } else {
      memcpy(ct_tmp, scratch, data_len + 16);
    }
    /* a) 密文与 AAD 无关;b) tag 必须随 AAD 变化 */
    if (0 != memcmp(ct_ok, ct_tmp, data_len)) {
      ++error;
      rlLOGE(TAG, "ChaChaPolyAad: 密文随 AAD 变化(AAD 不应影响密钥流)");
    }
    if (0 == memcmp(ct_ok + data_len, ct_tmp + data_len, 16)) {
      ++error;
      rlLOGE(TAG, "ChaChaPolyAad: AAD 改变但 tag 未变 ⇒ AAD 未参与认证");
    }

    /* a/b) 不带 AAD: 密文相同、tag 必须不同 */
    memcpy(scratch, plain, data_len);
    size = data_len;
    if (rockey.CHACHAPOLY_Seal(key, nonce, scratch, &size) < 0) {
      ++error;
      rlLOGE(TAG, "ChaChaPolyAad: Seal(no aad) 失败");
    } else {
      if (0 != memcmp(ct_ok, scratch, data_len)) {
        ++error;
        rlLOGE(TAG, "ChaChaPolyAad: 有/无 AAD 的密文不一致");
      }
      if (0 == memcmp(ct_ok + data_len, scratch + data_len, 16)) {
        ++error;
        rlLOGE(TAG, "ChaChaPolyAad: 有无 AAD 的 tag 相同 ⇒ AAD 未参与认证");
      }
    }

    /* c) 正确 AAD: Open 成功且明文还原 */
    memcpy(scratch, ct_ok, data_len + 16);
    size = data_len + 16;
    if (rockey.CHACHAPOLY_Open(key, nonce, scratch, &size, aad_ok, sizeof(aad_ok)) < 0) {
      ++error;
      rlLOGE(TAG, "ChaChaPolyAad: Open(aad_ok) 失败");
    } else if (size != data_len || 0 != memcmp(scratch, plain, data_len)) {
      ++error;
      rlLOGE(TAG, "ChaChaPolyAad: Open(aad_ok) 明文不一致");
    }

    /* c) 错误 AAD / 缺失 AAD: 必须被拒绝 */
    memcpy(scratch, ct_ok, data_len + 16);
    size = data_len + 16;
    if (rockey.CHACHAPOLY_Open(key, nonce, scratch, &size, aad_bad, sizeof(aad_bad)) >= 0) {
      ++error;
      rlLOGE(TAG, "ChaChaPolyAad: Open(aad_bad) 未被拒绝");
    }
    memcpy(scratch, ct_ok, data_len + 16);
    size = data_len + 16;
    if (rockey.CHACHAPOLY_Open(key, nonce, scratch, &size) >= 0) {
      ++error;
      rlLOGE(TAG, "ChaChaPolyAad: Open(no aad) 未被拒绝");
    }
  }

#if !defined(__RockeyARM__)
  /* ---- 2) RFC 8439 §2.8.2 标准向量 + 3) OpenSSL 对拍(仅宿主/模拟器) ----
   *! 设备端不编这段: 下面的 `static const` 向量会进 .rodata, 而固件要求 .rodata 为空。 */
  {
    /* RFC 8439 §2.8.2: AEAD_CHACHA20_POLY1305, AAD = 50515253c0c1c2c3c4c5c6c7 */
    static const uint8_t kKey[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    };
    static const uint8_t kNonce[12] = {0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47};
    static const uint8_t kAad[12] = {0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7};
    static const uint8_t kPlain[114] = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c, 0x65,
        0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x20,
        0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63, 0x6f, 0x75, 0x6c,
        0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20,
        0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x66,
        0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72, 0x65, 0x65, 0x6e, 0x20,
        0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69, 0x74, 0x2e,
    };
    static const uint8_t kCipher[114] = {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2, 0xa4,
        0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe,
        0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde,
        0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f,
        0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4, 0xfa,
        0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b,
        0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16,
    };
    static const uint8_t kTag[16] = {0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
                                     0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91};
    /* 同参数但不带 AAD(OpenSSL 实测): 用来证明"AAD 确实改变了 tag" */
    static const uint8_t kTagNoAad[16] = {0x6a, 0x23, 0xa4, 0x68, 0x1f, 0xd5, 0x94, 0x56,
                                          0xae, 0xa1, 0xd2, 0x9f, 0x82, 0x47, 0x72, 0x16};

    uint8_t buffer[sizeof(kPlain) + 16];
    uint8_t bad_aad[sizeof(kAad)];
    size_t size;

    /* 2) Seal + AAD → 密文与 tag 必须与 RFC 逐字节一致 */
    memcpy(buffer, kPlain, sizeof(kPlain));
    size = sizeof(kPlain);
    if (rockey.CHACHAPOLY_Seal(kKey, kNonce, buffer, &size, kAad, sizeof(kAad)) < 0) {
      ++error;
      rlLOGE(TAG, "ChaChaPolyAad: Seal failed");
    } else if (size != sizeof(kPlain) + 16) {
      ++error;
      rlLOGE(TAG, "ChaChaPolyAad: Seal size %d != %d", (int)size, (int)sizeof(kPlain) + 16);
    } else {
      if (0 != memcmp(buffer, kCipher, sizeof(kCipher))) {
        ++error;
        rlLOGE(TAG, "ChaChaPolyAad: ciphertext mismatch");
      }
      if (0 != memcmp(buffer + sizeof(kPlain), kTag, sizeof(kTag))) {
        ++error;
        rlLOGXI(TAG, buffer + sizeof(kPlain), 16, "ChaChaPolyAad: tag mismatch");
      }
    }

    /* 2) Open + AAD → 还原明文 */
    size = sizeof(kPlain) + 16;
    if (rockey.CHACHAPOLY_Open(kKey, kNonce, buffer, &size, kAad, sizeof(kAad)) < 0) {
      ++error;
      rlLOGE(TAG, "ChaChaPolyAad: Open failed");
    } else if (size != sizeof(kPlain) || 0 != memcmp(buffer, kPlain, sizeof(kPlain))) {
      ++error;
      rlLOGE(TAG, "ChaChaPolyAad: Open plaintext mismatch");
    }

    /* 2) 篡改 AAD → Open 必须失败 */
    memcpy(bad_aad, kAad, sizeof(kAad));
    bad_aad[0] ^= 0x01;
    memcpy(buffer, kCipher, sizeof(kCipher));
    memcpy(buffer + sizeof(kPlain), kTag, sizeof(kTag));
    size = sizeof(kPlain) + 16;
    if (rockey.CHACHAPOLY_Open(kKey, kNonce, buffer, &size, bad_aad, sizeof(bad_aad)) >= 0) {
      ++error;
      rlLOGE(TAG, "ChaChaPolyAad: tampered AAD 未被拒绝");
    }

    /* 2) 不带 AAD 的 tag 必须等于 OpenSSL 值且不同于带 AAD 的 tag */
    memcpy(buffer, kPlain, sizeof(kPlain));
    size = sizeof(kPlain);
    if (rockey.CHACHAPOLY_Seal(kKey, kNonce, buffer, &size) < 0) {
      ++error;
      rlLOGE(TAG, "ChaChaPolyAad: Seal(no aad) failed");
    } else if (0 != memcmp(buffer + sizeof(kPlain), kTagNoAad, sizeof(kTagNoAad))) {
      ++error;
      rlLOGXI(TAG, buffer + sizeof(kPlain), 16, "ChaChaPolyAad: no-aad tag mismatch");
    }
  }

  /* 3) host: 随机对拍 OpenSSL EVP_chacha20_poly1305(覆盖多种 AAD 长度)
   *! 注意: 两条路径必须喂**同一份明文** —— 曾误把 EVP 加密后的密文再交给 Seal(等于二次加密)。 */
  {
    static const int kAadLens[] = {0, 1, 15, 16, 17, 32, 63, 64};
    for (int k = 0; k < (int)(sizeof(kAadLens) / sizeof(kAadLens[0])); ++k) {
      const int aad_len = kAadLens[k];
      const int len = 1 + (k * 37) % 200;
      uint8_t plain2[200 + 16], check[200 + 16], mine[200 + 16];
      uint8_t key[32], nonce[12], aad[64];
      std::ignore = rockey.RandBytes(key, sizeof(key));
      std::ignore = rockey.RandBytes(nonce, sizeof(nonce));
      std::ignore = rockey.RandBytes(aad, sizeof(aad));
      std::ignore = rockey.RandBytes(plain2, (size_t)len);

      /* OpenSSL 参考实现 */
      memcpy(check, plain2, (size_t)len);
      int out_size = (int)sizeof(check), mac_size = 16;
      EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
      DONGLE_VERIFY(ctx && EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key, nonce) == 1);
      if (aad_len)
        DONGLE_VERIFY(EVP_EncryptUpdate(ctx, nullptr, &out_size, aad, aad_len) == 1);
      DONGLE_VERIFY(EVP_EncryptUpdate(ctx, check, &out_size, check, len) == 1);
      DONGLE_VERIFY(out_size == len);
      DONGLE_VERIFY(EVP_EncryptFinal_ex(ctx, check + out_size, &mac_size) == 1 && mac_size == 0);
      DONGLE_VERIFY(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, check + len) == 1);
      EVP_CIPHER_CTX_free(ctx);

      /* 我们的实现: 同一明文 + 同一 AAD ⇒ 密文与 tag 必须逐字节相同 */
      memcpy(mine, plain2, (size_t)len);
      size_t size2 = (size_t)len;
      if (rockey.CHACHAPOLY_Seal(key, nonce, mine, &size2, aad_len ? aad : nullptr, (size_t)aad_len) < 0) {
        ++error;
        rlLOGE(TAG, "ChaChaPolyAad(host): Seal aad=%d failed", aad_len);
      } else if (0 != memcmp(mine, check, (size_t)len + 16)) {
        ++error;
        rlLOGE(TAG, "ChaChaPolyAad(host): mismatch aad=%d data=%d", aad_len, len);
      }
    }
  }
#endif /* !__RockeyARM__ */

  rlLOGI(TAG, "Testing_ChaChaPolyAad error = %d", error);
  return error;
}

int Testing_ChaChaPoly(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  int error = 0;
  uint32_t state[16];

  error += Testing_ChaChaPolyAad(rockey, ExtendBuf); /* 大缓冲走 ExtendBuf, 避免顶爆设备 2KB 栈 */

#if defined(__EMULATOR__)
  constexpr int kTestLoop = 10000;
#else  /* __EMULATOR__ */
  constexpr int kTestLoop = 2;
#endif /* __EMULATOR__ */

  for (int loop = 0; loop < kTestLoop; ++loop) {
    rlLOGI(TAG, "Testing_ChaChaPoly %d/%d %d", loop, kTestLoop, error);

    std::ignore = rockey.RandBytes(reinterpret_cast<uint8_t*>(state), sizeof(state));

    for (int i = 0; i < 10; ++i) {
      uint8_t sm3[32], verify[32];
      uint8_t key[64];
      uint8_t buffer[512 + 16];

#if !defined(X_BUILD_native)
      uint8_t check_[1024];
#endif /* X_BUILD_native */

      std::ignore = rockey.RandBytes(key, sizeof(key));
      for (int off = 0; off < 512; off += 64, ++state[12])
        rlCryptoChaCha20Block(state, &buffer[off]);

      size_t size = 1 + state[0] % 512, size_origin = size;
      if (rockey.SM3(buffer, size, sm3) < 0)
        ++error;

#if !defined(X_BUILD_native)
      {
        int out_size = 1024, mac_size = 16;
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        DONGLE_VERIFY(ctx && EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key, key + 32) == 1);
        DONGLE_VERIFY(EVP_EncryptUpdate(ctx, check_, &out_size, buffer, (int)size) == 1);
        DONGLE_VERIFY((int)size == out_size);
        DONGLE_VERIFY(EVP_EncryptFinal_ex(ctx, check_ + out_size, &mac_size) == 1);
        DONGLE_VERIFY(mac_size == 0);
        mac_size = 16;
        DONGLE_VERIFY(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, check_ + out_size) == 1);
        EVP_CIPHER_CTX_free(ctx);
      }
#endif /* X_BUILD_native */

      if (rockey.CHACHAPOLY_Seal(key, key + 32, buffer, &size) < 0)
        ++error;

      if (size != size_origin + 16)
        ++error;

#if !defined(X_BUILD_native)
      {
        int out_size = 1024, mac_size = 16;
        DONGLE_VERIFY(0 == memcmp(buffer, check_, size));

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        DONGLE_VERIFY(ctx && EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key, key + 32) == 1);
        DONGLE_VERIFY(EVP_DecryptUpdate(ctx, check_, &out_size, buffer, (int)size - 16) == 1);
        DONGLE_VERIFY(out_size == (int)size - 16);
        DONGLE_VERIFY(EVP_DecryptFinal_ex(ctx, check_ + out_size, &mac_size) == 1 && mac_size == 0);
        DONGLE_VERIFY(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, check_ + out_size) == 1);
        EVP_CIPHER_CTX_free(ctx);
      }
#endif /* X_BUILD_native */

      if (rockey.CHACHAPOLY_Open(key, key + 32, buffer, &size) < 0)
        ++error;

      if (size_origin != size)
        ++error;

#if !defined(X_BUILD_native)
      DONGLE_VERIFY(0 == memcmp(buffer, check_, size));
#endif /* X_BUILD_native */

      if (rockey.SM3(buffer, size, verify) < 0)
        ++error;

      if (0 != memcmp(sm3, verify, 32))
        ++error;
    }
  }

  return error;
}

int Testing_Sha256Test(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  if (rockey.SHA256(Context->argv_, sizeof(Context->argv_), Context->hash_) < 0)
    return 1;
  return 0;
}

int Testing_Sha384Test(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  if (rockey.SHA384(Context->argv_, sizeof(Context->argv_), Context->hash_) < 0)
    return 1;
  return 0;
}

int Testing_Sha512Test(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  if (rockey.SHA512(Context->argv_, sizeof(Context->argv_), Context->hash_) < 0)
    return 1;
  return 0;
}

int Testing_Curve25519Test(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  int error = 0;

#if defined(__EMULATOR__)
  constexpr int kTestLoop = 10000;
#else  /* __EMULATOR__ */
  constexpr int kTestLoop = 5;
#endif /* __EMULATOR__ */

  for (int i = 0; i < kTestLoop; ++i) {
    rlLOGI(TAG, "Testing_Curve25519Test %d/%d %d", i, kTestLoop, error);

    uint8_t pub1[32], pub2[32], pkey1[32], pkey2[32], sec1[32], sec2[32];
    if (rockey.GenerateKeyPairCurve25519(pub1, pkey1) < 0) {
      Context->error_[0] = 0x1111;
      ++error;
    }

    if (rockey.RandBytes(pkey2, 32) < 0) {
      Context->error_[1] = 0x2222;
      ++error;
    }

    if (rockey.RandBytes(sec1, 32) < 0) {
      Context->error_[2] = 0x3333;
      ++error;
    }

    if (rockey.ComputePubkeyCurve25519(pub2, pkey2) < 0) {
      Context->error_[3] = 0x4444;
      ++error;
    }

    if (rockey.ComputeSecretCurve25519(sec1, pkey1, pub2) < 0) {
      Context->error_[4] = 0x5555;
      ++error;
    }

    if (rockey.ComputeSecretCurve25519(sec2, pkey2, pub1) < 0) {
      Context->error_[5] = 0x6666;
      ++error;
    }

    if (0 != memcmp(sec1, sec2, 32)) {
      Context->error_[6] = 0x7777;
      ++error;
    } else {
      rlLOGXI(TAG, sec1, 32, "ComputeSecretCurve25519");
    }

#if !defined(__RockeyARM__)
    uint8_t chkpub1[32], chkpub2[32], chksec[32];
    rlCryptoX25519Pubkey(chkpub1, pkey1);
    rlCryptoX25519Pubkey(chkpub2, pkey2);
    if (0 != memcmp(pub1, chkpub1, 32))
      ++error;
    if (0 != memcmp(pub2, chkpub2, 32))
      ++error;
    rlCryptoX25519(chksec, pkey1, chkpub2);
    if (0 != memcmp(sec1, chksec, 32))
      ++error;
#endif /* __RockeyARM__ */
  }

  return error;
}

int Testing_Ed25519Test(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  int error = 0;

#if defined(__EMULATOR__)
  constexpr int kTestLoop = 1000;
#else  /* __EMULATOR__ */
  constexpr int kTestLoop = 2;
#endif /* __EMULATOR__ */

  for (int i = 0; i < kTestLoop; ++i) {
    rlLOGI(TAG, "Testing_Ed25519Test %d/%d %d", i, kTestLoop, error);

    uint8_t pubkey[32], prikey[32], sign[64], message[64];
    if (rockey.GenerateKeyPairEd25519(ExtendBuf, pubkey, prikey) < 0)
      ++error;

    if (rockey.ComputePubkeyEd25519(ExtendBuf, message, prikey) < 0)
      ++error;

    if (0 != memcmp(message, pubkey, 32))
      ++error;

    if (rockey.RandBytes(message, sizeof(message)) < 0)
      ++error;

    if (rockey.SignMessageEd25519(ExtendBuf, sign, message, sizeof(message), pubkey, prikey) < 0)
      ++error;

    if (0 != rockey.VerifySignEd25519(ExtendBuf, message, sizeof(message), sign, pubkey))
      ++error;
  }

  return error;
}

int Testing_PKeyCountDownTest(Dongle& rockey, Context_t* Context_, void* ExtendBuf) {
  struct TestingContext : Context_t {
    uint8_t z_hash[32];
    uint8_t rsa_sign[256];
    uint32_t rsa_modules;

    uint8_t sm2_pubkey[64];
    uint8_t sm2_sign[64];

    uint8_t p256_pubkey[64];
    uint8_t p256_sign[64];
  };

  rlLOGI(TAG, "size Context : %zd", sizeof(TestingContext));

  int error = 0;
  auto* Context = (TestingContext*)Context_;

  if (Context_->argv_[1]) {
    PKEY_LICENCE licence;
    licence.SetGlobalDecrease(true).SetLimit(10);
    for (int i = 1; i <= 4; ++i) {
      rockey.DeleteFile(SECRET_STORAGE_TYPE::kP256, i);
      rockey.DeleteFile(SECRET_STORAGE_TYPE::kSM2, i);
      rockey.DeleteFile(SECRET_STORAGE_TYPE::kRSA, i);
    }

    if (rockey.CreatePKEYFile(SECRET_STORAGE_TYPE::kSM2, 256, 1, licence) < 0)
      ++error;
    if (rockey.CreatePKEYFile(SECRET_STORAGE_TYPE::kP256, 256, 2, licence) < 0)
      ++error;
    if (rockey.CreatePKEYFile(SECRET_STORAGE_TYPE::kRSA, 2048, 3, licence) < 0)
      ++error;
    if (rockey.GenerateSM2(1, &Context->sm2_pubkey[0], &Context->sm2_pubkey[32]) < 0)
      ++error;
    if (rockey.GenerateP256(2, &Context->p256_pubkey[0], &Context->p256_pubkey[32]) < 0)
      ++error;
    if (rockey.GenerateRSA(3, &Context->rsa_modules, Context->rsa_sign) < 0)
      ++error;
  }

  std::ignore = rockey.RandBytes(Context->z_hash, sizeof(Context->z_hash));
  if (rockey.SM2Sign(1, Context->z_hash, &Context->sm2_sign[0], &Context->sm2_sign[32]) < 0)
    ++error;
  if (rockey.P256Sign(2, Context->z_hash, &Context->p256_sign[0], &Context->p256_sign[32]) < 0)
    ++error;
  size_t size = 32;
  if (rockey.RSAPrivate(3, Context->z_hash, &size, true) < 0)
    ++error;

  return error;
}

/*! X509Tests(index 18):X509 证书验签原语真机测试。
 *! 证书 DER 在进入测试前由 host/模拟器(WriteX509Certs)写入 dashboard[0, 4KB)
 *! (factory dataFile 0xFFFF 匿名可写区), 测试内三平台统一经 ReadDataFile 加载到
 *! InOutBuf[kX509CertOffset, 1024):
 *!   [u16 leaf_len][u16 ca_len][leaf DER][ca DER]
 *! 子模式(argv_[1]):0/缺省 = P256 链 | 1 = SM2 链 | 2 = RSA2048 自签 CA(单证书)
 *! 覆盖:严格 DER 解析、时间警告位(固定 epoch, 不取设备 RTC)、SPKI 公钥提取(按证书
 *!       自身算法分派)、扩展遍历、链验签/自签根、篡改负例(CA 公钥/叶签名)、
 *!       尾随字节与空/超长证书拒绝。
 *! 设备端注意:COS rsa_pub 就地覆写签名区, 单证书 RSA 负例需栈上备份(与 master.cc
 *!       OpManager_VerifyWorldPublic 栈上 world 同款思路);ExtendBuf 为 FTRX 暂存区,
 *!       不可跨 COS 调用保数据, work 区(304B)仅在单次 X509VerifySignature 内有效。 */
int Testing_X509Tests(Dongle& rockey, Context_t* Context, void* ExtendBuf) {
  int error = 0;
  uint8_t* work = static_cast<uint8_t*>(ExtendBuf);

  Context->result_[3] = rLANG_WORLD_MAGIC;

  uint8_t* certs = reinterpret_cast<uint8_t*>(Context) + kX509CertOffset;
  if (0 != rockey.ReadDataFile(Dongle::kFactoryDataFileId, 0, certs, 1024 - kX509CertOffset)) {
    rlLOGE(TAG, "X509Tests: ReadDataFile(dashboard) = %d/%08x", -1, rockey.GetLastError());
    return 1;
  }

  const uint16_t leaf_len = static_cast<uint16_t>(certs[0]) | (static_cast<uint16_t>(certs[1]) << 8);
  const uint16_t ca_len = static_cast<uint16_t>(certs[2]) | (static_cast<uint16_t>(certs[3]) << 8);
  const uint8_t* leaf = certs + 4;
  const uint8_t* ca = leaf + leaf_len;

  rlLOGI(TAG, "Testing ... %s ...", __FUNCTION__);
  rlLOGI(TAG, "X509Tests leaf_len=%u ca_len=%u", leaf_len, ca_len);

  if (leaf_len == 0 || static_cast<uint32_t>(leaf_len) + static_cast<uint32_t>(ca_len) + 4 > 1024 - kX509CertOffset) {
    rlLOGE(TAG, "X509Tests: invalid cert blob leaf=%u ca=%u", leaf_len, ca_len);
    return 1;
  }

  /* 严格 DER 解析 + 签名算法分类 */
  X509View lv = {}, cv = {};
  int r = X509Parse(&lv, leaf, leaf_len);
  if (0 != r) {
    rlLOGE(TAG, "X509Tests: X509Parse(leaf) = %d", r);
    Context->error_[0] = static_cast<uint32_t>(-r);
    return 1;
  }
  if (ca_len != 0) {
    r = X509Parse(&cv, ca, ca_len);
    if (0 != r) {
      rlLOGE(TAG, "X509Tests: X509Parse(ca) = %d", r);
      Context->error_[1] = static_cast<uint32_t>(-r);
      return 1;
    }
  }
  if (lv.sig_type == kX509SigUnknown || (ca_len != 0 && cv.sig_type == kX509SigUnknown)) {
    rlLOGE(TAG, "X509Tests: unknown sig type");
    ++error;
  }
  rlLOGI(TAG, "X509Tests sig_type=%d ext_count leaf=%d ca=%d", lv.sig_type, lv.ext_count,
         ca_len != 0 ? cv.ext_count : -1);

  /* 时间警告位(设备 RTC 不可靠, 固定 epoch):
   * 2025-06-01 窗口内 → OK;2035-01-01 → After;2015-01-01 → Before */
  {
    X509View tv = lv;
    X509CheckTime(&tv, leaf, leaf_len, 1748736000ULL);
    if (tv.time_flags != kX509TimeOK) {
      rlLOGE(TAG, "X509Tests: in-window time flags %d", tv.time_flags);
      ++error;
    }
    X509CheckTime(&tv, leaf, leaf_len, 2051222400ULL);
    if (0 == (tv.time_flags & kX509TimeAfter)) {
      rlLOGE(TAG, "X509Tests: expired cert no warning");
      ++error;
    }
    X509CheckTime(&tv, leaf, leaf_len, 1420070400ULL);
    if (0 == (tv.time_flags & kX509TimeBefore)) {
      rlLOGE(TAG, "X509Tests: not-yet-valid cert no warning");
      ++error;
    }
  }

  /* SPKI 公钥提取(按证书自身算法分派, 与签名算法无关);
   * 输出到 ExtendBuf(仅在本次检查内使用, 不跨 COS 调用) */
  {
    const uint8_t* pk_cert = (ca_len != 0) ? ca : leaf;
    const size_t pk_len = (ca_len != 0) ? ca_len : leaf_len;
    uint8_t* pub = work + 304;
    size_t size_pub = 0;
    uint8_t sig_type_pub = 0;
    r = X509GetPublicKey(pk_cert, pk_len, pub, &size_pub, &sig_type_pub);
    if (0 != r) {
      rlLOGE(TAG, "X509Tests: X509GetPublicKey = %d", r);
      ++error;
    } else if (sig_type_pub == kX509SigRSA_SHA256) {
      /* RSA 输出 [e:uint32 LE][N:256B 大端], e = 65537 */
      if (size_pub != 260 || pub[0] != 0x01 || pub[1] != 0x00 || pub[2] != 0x01 || pub[3] != 0x00) {
        rlLOGE(TAG, "X509Tests: RSA pubkey size/e mismatch %zu", size_pub);
        ++error;
      }
    } else if (sig_type_pub == kX509SigP256_SHA256 || sig_type_pub == kX509SigSM2_SM3) {
      if (size_pub != 64) {
        rlLOGE(TAG, "X509Tests: EC pubkey size mismatch %zu", size_pub);
        ++error;
      }
    } else {
      rlLOGE(TAG, "X509Tests: unexpected pubkey sig_type %d", sig_type_pub);
      ++error;
    }
  }

  /* 扩展遍历:链模式叶 1 个(KeyUsage critical)、CA 2 个(BasicConstraints+KeyUsage 均 critical);
   * RSA v1 单证书无扩展 */
  if (ca_len != 0) {
    if (lv.ext_count != 1 || cv.ext_count != 2) {
      rlLOGE(TAG, "X509Tests: ext count leaf=%d ca=%d", lv.ext_count, cv.ext_count);
      ++error;
    }
    {
      uint8_t iter = 0;
      X509Ext ext;
      while (1 == X509ExtNext(&lv, leaf, leaf_len, &ext, &iter)) {
        if (!X509OID_KeyUsage(leaf + ext.off_oid, ext.len_oid) || !ext.critical) {
          rlLOGE(TAG, "X509Tests: leaf ext not critical KeyUsage");
          ++error;
        }
      }
    }
    {
      uint8_t iter = 0;
      X509Ext ext;
      int found_bc = 0;
      while (1 == X509ExtNext(&cv, ca, ca_len, &ext, &iter)) {
        if (X509OID_BasicConstraints(ca + ext.off_oid, ext.len_oid)) {
          found_bc = 1;
          if (!ext.critical) {
            rlLOGE(TAG, "X509Tests: BasicConstraints not critical");
            ++error;
          }
        } else if (X509OID_KeyUsage(ca + ext.off_oid, ext.len_oid)) {
          if (!ext.critical) {
            rlLOGE(TAG, "X509Tests: KeyUsage not critical");
            ++error;
          }
        } else {
          rlLOGE(TAG, "X509Tests: unexpected ca ext");
          ++error;
        }
      }
      if (found_bc != 1) {
        rlLOGE(TAG, "X509Tests: BasicConstraints missing");
        ++error;
      }
    }
  } else if (lv.ext_count != 0) {
    rlLOGE(TAG, "X509Tests: v1 cert has extensions?!");
    ++error;
  }

  /* 链验签(链模式)或自签根(单证书模式) */
  if (ca_len != 0) {
    /* 负例 1:叶证书当自签根 → issuer(CA 名)≠subject(叶名), 验签前置拒绝, 不触 COS */
    r = X509VerifySelfSigned(&rockey, leaf, leaf_len, work, 304);
    if (r >= 0) {
      rlLOGE(TAG, "X509Tests: leaf accepted as self-signed!");
      ++error;
    }

    /* 负例 2:篡改 CA 公钥(X 字节)→ 验签失败(EC 验签不覆写签名区) */
    uint8_t* pk_tamper = const_cast<uint8_t*>(ca) + cv.off_spki_pub + 20;
    *pk_tamper ^= 1;
    r = X509VerifySignature(&rockey, leaf, leaf_len, ca, ca_len, work, 304);
    if (r >= 0) {
      rlLOGE(TAG, "X509Tests: tampered CA pubkey accepted!");
      ++error;
    }
    *pk_tamper ^= 1;

    /* 负例 3:篡改叶签名首字节 → 验签失败 */
    uint8_t* sig_leaf = const_cast<uint8_t*>(leaf) + lv.off_signature;
    sig_leaf[0] ^= 1;
    r = X509VerifySignature(&rockey, leaf, leaf_len, ca, ca_len, work, 304);
    if (r >= 0) {
      rlLOGE(TAG, "X509Tests: tampered leaf signature accepted!");
      ++error;
    }
    sig_leaf[0] ^= 1;

    /* 正例:链验签 + 自签根 */
    if (0 != X509VerifySignature(&rockey, leaf, leaf_len, ca, ca_len, work, 304)) {
      rlLOGE(TAG, "X509Tests: chain verify failed");
      ++error;
    }
    if (0 != X509VerifySelfSigned(&rockey, ca, ca_len, work, 304)) {
      rlLOGE(TAG, "X509Tests: self-signed CA verify failed");
      ++error;
    }
  } else {
    /* RSA2048 自签 CA(单证书):COS rsa_pub 就地覆写签名区, 负例前先栈上备份 */
    uint8_t sig_backup[256];
    if (lv.len_signature > sizeof(sig_backup)) {
      rlLOGE(TAG, "X509Tests: RSA sig too large %u", lv.len_signature);
      return error + 1;
    }
    uint8_t* sig_cert = const_cast<uint8_t*>(leaf) + lv.off_signature;
    memcpy(sig_backup, sig_cert, lv.len_signature);

    /* 负例 1:篡改模数 N 字节 → 自签验签失败(rsa_pub 覆写签名区, 随后恢复) */
    uint8_t* pk_tamper = const_cast<uint8_t*>(leaf) + lv.off_spki_pub + 20;
    *pk_tamper ^= 1;
    r = X509VerifySelfSigned(&rockey, leaf, leaf_len, work, 304);
    if (r >= 0) {
      rlLOGE(TAG, "X509Tests: tampered RSA modulus accepted!");
      ++error;
    }
    *pk_tamper ^= 1;
    memcpy(sig_cert, sig_backup, lv.len_signature);

    /* 负例 2:篡改签名首字节 → 验签失败(覆写后从备份恢复) */
    sig_cert[0] ^= 1;
    r = X509VerifySelfSigned(&rockey, leaf, leaf_len, work, 304);
    if (r >= 0) {
      rlLOGE(TAG, "X509Tests: tampered RSA signature accepted!");
      ++error;
    }
    memcpy(sig_cert, sig_backup, lv.len_signature);

    /* 正例:自签验签 */
    if (0 != X509VerifySelfSigned(&rockey, leaf, leaf_len, work, 304)) {
      rlLOGE(TAG, "X509Tests: RSA self-signed verify failed");
      ++error;
    }
  }

  /* 严格 DER:尾随字节拒绝(链模式用 ca 首字节作尾随;单证书模式 blob 恰好占满证书区, 跳过) */
  if (ca_len != 0) {
    X509View tv;
    if (0 == X509Parse(&tv, leaf, static_cast<size_t>(leaf_len) + 1)) {
      rlLOGE(TAG, "X509Tests: trailing byte accepted!");
      ++error;
    }
  }

  /* 空证书/超长证书拒绝 */
  {
    X509View tv;
    if (-EINVAL != X509Parse(&tv, nullptr, 0)) {
      rlLOGE(TAG, "X509Tests: null cert not rejected");
      ++error;
    }
    if (-E2BIG != X509Parse(&tv, leaf, 1025)) {
      rlLOGE(TAG, "X509Tests: oversize cert not rejected");
      ++error;
    }
  }

  Context->result_[2] = rLANG_ATOMC_WORLD_MAGIC;

  rlLOGI(TAG, "X509Tests total error = %d", error);
  return error;
}

#if !defined(__RockeyARM__) && !defined(__EMULATOR__)
/*! 用 OpenSSL 独立验证一对 RSA 素因子 p/q(小端字节): 素性 + gcd(e,p-1)=1 + p≠q + n 位宽 + d 存在 */
static int VerifyRsaPrimePair(const uint8_t* pbuf, const uint8_t* qbuf, int bits, const char* label) {
  BIGNUM* p = BN_lebin2bn(pbuf, bits / 8, nullptr);
  BIGNUM* q = BN_lebin2bn(qbuf, bits / 8, nullptr);
  BN_CTX* bnctx = BN_CTX_new();
  BIGNUM* e = BN_new();
  BIGNUM* pm1 = BN_new();
  BIGNUM* qm1 = BN_new();
  BIGNUM* g1 = BN_new();
  BIGNUM* g2 = BN_new();
  BIGNUM* lcm = BN_new();
  BIGNUM* n = BN_new();
  BIGNUM* d = BN_new();
  std::ignore = BN_set_word(e, 65537);
  std::ignore = BN_sub_word(BN_copy(pm1, p), 1);
  std::ignore = BN_sub_word(BN_copy(qm1, q), 1);
  std::ignore = BN_gcd(g1, e, pm1, bnctx);
  std::ignore = BN_gcd(g2, e, qm1, bnctx);
  const int prime_p = BN_is_prime_ex(p, 64, bnctx, nullptr);
  const int prime_q = BN_is_prime_ex(q, 64, bnctx, nullptr);
  const int gcd_ok = BN_is_one(g1) && BN_is_one(g2);
  const int distinct = (BN_cmp(p, q) != 0);
  std::ignore = BN_mul(n, p, q, bnctx);
  std::ignore = BN_mul(lcm, pm1, qm1, bnctx); /* e 与 pm1/qm1 互素 ⇒ 与乘积互素, 逆元存在 */
  const int d_ok = (nullptr != BN_mod_inverse(d, e, lcm, bnctx));
  const int ok = prime_p && prime_q && gcd_ok && distinct && d_ok;
  rlLOGI(TAG, "%s RSA%d verify: prime_p=%d prime_q=%d gcd(e,p-1)=1:%d distinct=%d bits(n)=%d d_ok=%d ok=%d", label,
         bits * 2, prime_p, prime_q, gcd_ok, distinct, BN_num_bits(n), d_ok, ok);
  rlLOGI(TAG, "%s p = %s", label, BN_bn2hex(p));
  rlLOGI(TAG, "%s q = %s", label, BN_bn2hex(q));
  BN_free(p);
  BN_free(q);
  BN_free(e);
  BN_free(pm1);
  BN_free(qm1);
  BN_free(g1);
  BN_free(g2);
  BN_free(lcm);
  BN_free(n);
  BN_free(d);
  BN_CTX_free(bnctx);
  return ok;
}

/*! 小端字节序 hex 直出(与设备 dashboard 存储顺序一致, 便于外部工具复现同一对素数) */
static void LogLeHex(const char* tag, const char* what, const uint8_t* buf, int n) {
  char line[2 * 192 + 1];
  for (int i = 0; i < n; ++i)
    std::snprintf(&line[2 * i], 3, "%02x", buf[i]);
  line[2 * n] = '\0';
  rlLOGI(TAG, "%s %s(le,%dB)=%s", tag, what, n, line);
}

/*! 长跑进度读回(dashboard 测试用进度区): 设备内 GetTickCount 不自走, 时长只能由 host 墙钟换算。
 *! 同一偏移在生成模式下是 GenResult(见 mr.h), 这里按 magic 自动区分并顺带验证 p/q。 */
static void ReadMRProgress(Dongle& rockey, const char* tag) {
  /* 同一偏移(4096)在不同模式下含义不同: 长跑 Progress / 生成 GenResult, 用 union 复用 32B */
  union {
    MillerRabinContext::Progress p;
    MillerRabinContext::GenResult g;
  } u{};
  const int rc = rockey.ReadDataFile(Dongle::kFactoryDataFileId, MillerRabinContext::kProgressOffset, &u, sizeof(u));
  if (u.g.magic == MillerRabinContext::kMagicGenDone) {
    const uint64_t probes_p = ((uint64_t)u.g.probes_p_hi << 32) | u.g.probes_p_lo;
    const uint64_t probes_q = ((uint64_t)u.g.probes_q_hi << 32) | u.g.probes_q_lo;
    rlLOGI(TAG, "%s dashboard[%u] rc=%d magic=%08x(MGen) bits=%u rounds=%u ok=%u probes_p=%llu probes_q=%llu", tag,
           MillerRabinContext::kProgressOffset, rc, u.g.magic, u.g.bits, u.g.rounds, u.g.ok,
           (unsigned long long)probes_p, (unsigned long long)probes_q);
    if ((u.g.ok & 3u) == 3u && (u.g.bits == 1024 || u.g.bits == 1536)) {
      uint8_t pbuf[192] = {0}, qbuf[192] = {0}, spbuf[192] = {0}, sqbuf[192] = {0};
      const int nbytes = (int)u.g.bits / 8;
      const int r1 = rockey.ReadDataFile(Dongle::kFactoryDataFileId, MillerRabinContext::kGenPOffset, pbuf, nbytes);
      const int r2 = rockey.ReadDataFile(Dongle::kFactoryDataFileId, MillerRabinContext::kGenQOffset, qbuf, nbytes);
      const int r3 =
          rockey.ReadDataFile(Dongle::kFactoryDataFileId, MillerRabinContext::kGenSeedPOffset, spbuf, nbytes);
      const int r4 =
          rockey.ReadDataFile(Dongle::kFactoryDataFileId, MillerRabinContext::kGenSeedQOffset, sqbuf, nbytes);
      rlLOGI(TAG, "%s read p/q/seeds rc=%d/%d/%d/%d", tag, r1, r2, r3, r4);
      if (0 == r3 && 0 == r4) {
        /* 小端 hex 直出: 可直接喂 Build/tools/sbin/rsa-prime-repro.cjs 独立复现同一对素数 */
        LogLeHex(tag, "seed_p", spbuf, nbytes);
        LogLeHex(tag, "seed_q", sqbuf, nbytes);
      }
      if (0 == r1 && 0 == r2) {
        LogLeHex(tag, "p", pbuf, nbytes);
        LogLeHex(tag, "q", qbuf, nbytes);
        std::ignore = VerifyRsaPrimePair(pbuf, qbuf, (int)u.g.bits, tag);
      }
    }
    return;
  }
  const uint64_t units = ((uint64_t)u.p.units_hi << 32) | (uint64_t)u.p.units_lo;
  const char* kind = u.p.magic == MillerRabinContext::kMagicDone
                         ? "done"
                         : (u.p.magic == MillerRabinContext::kMagicAlive
                                ? "alive"
                                : (u.p.magic == MillerRabinContext::kMagicStart ? "start" : "stale/empty"));
  rlLOGI(TAG, "%s dashboard[%u] rc=%d magic=%08x(%s) seq=%u units=%llu beats=%u checksum=%08x writeRc=%d", tag,
         MillerRabinContext::kProgressOffset, rc, u.p.magic, kind, u.p.seq, (unsigned long long)units, u.p.beats,
         u.p.checksum, (int)u.p.result);
}
#endif /* !__RockeyARM__ && !__EMULATOR__ */

int Testing_PrimeMRTests(Dongle& rockey, void* Context, void* ExtendBuf) {
  int result = 0;
  memset(ExtendBuf, 0, 1024);

  auto* MR = static_cast<MillerRabinContext*>(ExtendBuf);
  MR->InitSmallBases();
  MR->SetDongle(&rockey); /* 设备侧 KickWDG 需要 COS 句柄(SetLEDState/GetTickCount) */

  /* 候选工作区放 InOut[384, 772): Context_t 恰 360B, 且不越 1024 处的 GuardBytes。
   *! 旧写法 (BN*)Context + 2 在 k=48(BN=388B) 时会盖掉 GuardBytes → 假栈溢出惩罚 */
  auto* Val = reinterpret_cast<MillerRabinContext::BN*>(static_cast<uint8_t*>(Context) + 384);

  /* argv_[1]=mode(0=随机/1=素数/2=半素数/3=RSA 素数生成/4=长跑耐久/5=读 dashboard 进度),
   * argv_[2]=MR 基轮数或 64 位参数的低 32 位, argv_[3]=64 位参数的高 32 位(host 按 hex 解析) */
  const int mode = (int)(reinterpret_cast<Context_t*>(Context)->argv_[1] & 0xff);

  /* argv_[2]=MR 基轮数(1..16, 测试时可只跑前几轮缩短设备端耗时; 缺省 16) */
  int mr_rounds = (int)(reinterpret_cast<Context_t*>(Context)->argv_[2] & 0xff);
  if (mr_rounds < 1 || mr_rounds > MillerRabinContext::kMaxRounds)
    mr_rounds = MillerRabinContext::kMaxRounds;

  if (mode == 5) {
#if !defined(__RockeyARM__) && !defined(__EMULATOR__)
    /* 独立进程可随时调用(不触发 ExecuteExeFile), 用于长跑期间观察进度 */
    ReadMRProgress(rockey, "mode5");
    exit(0);
#else
    return 0;
#endif
  }

  if (mode == 4) {
    /* 设备内长跑(定工作量 + KickWDG), 期间周期把进度写到 dashboard;
     * 即使被看门狗复位, host 也能从 dashboard 读回最后一次进度 → 最大连续执行时间 */
    [[maybe_unused]] const uint64_t iters = ((uint64_t)reinterpret_cast<Context_t*>(Context)->argv_[3] << 32) |
                                            (uint64_t)reinterpret_cast<Context_t*>(Context)->argv_[2];
    rockey.SetLEDState(LED_STATE::kBlink);
#if defined(__RockeyARM__)
    rlLOGI(TAG, "Endurance enter: iters=%llu", (unsigned long long)iters);
    const uint32_t checksum = MR->Endurance(iters);
    Context_t* ctx = reinterpret_cast<Context_t*>(Context);
    ctx->result_[0] = checksum;
    ctx->result_[1] = MR->Heartbeats();
    ctx->result_[2] = (uint32_t)iters;
    ctx->result_[3] = (uint32_t)(iters >> 32);
    rlLOGI(TAG, "Endurance leave: checksum=%08x beats=%u", checksum, MR->Heartbeats());
#elif !defined(__EMULATOR__)
    MillerRabinContext::Progress zero{};
    std::ignore = rockey.WriteDataFile(Dongle::kFactoryDataFileId, MillerRabinContext::kProgressOffset, &zero,
                                       sizeof(zero)); /* 先清掉上一次的记录 */
    rlLOGI(TAG, "Endurance(host): 触发设备内长跑 iters=%llu", (unsigned long long)iters);
    auto start = rLANG_GetTickCount();
    int main_result = 0;
    const int exec_result = static_cast<RockeyARM*>(&rockey)->ExecuteExeFile(Context, 1024, &main_result);
    auto end = rLANG_GetTickCount();
    rlLOGI(TAG, "Endurance(host): ExecuteExeFile result=%d mainRet=%d in %lld ms", exec_result, main_result,
           static_cast<long long>(end - start));
    Context_t* rctx = reinterpret_cast<Context_t*>(Context);
    const uint64_t req_iters = ((uint64_t)rctx->result_[3] << 32) | (uint64_t)rctx->result_[2];
    rlLOGI(TAG, "Endurance(host): checksum=%08x beats=%u reqIters=%llu (%.3f us/unit)", rctx->result_[0],
           rctx->result_[1], (unsigned long long)req_iters,
           req_iters ? static_cast<double>(end - start) * 1000.0 / static_cast<double>(req_iters) : 0.0);
    ReadMRProgress(rockey, "mode4");
    exit(0); /* 不走后续通用尾部: 进度已经读回并打印 */
#else
    return 0; /* 模拟器: 长跑/进度落盘不适用 */
#endif /* __RockeyARM__ */
    return 0;
  }

  if (mode == 3) {
    /* RSA 素数生成(设备内单指令完成): argv_[2] = 位宽选择(0=1024, 非 0=1536),
     * argv_[3] = MR 轮数(0 → kMaxRounds)。结果全部落到 dashboard 测试区
     * (状态 GenResult / p / q / 种子), 见 MillerRabinContext 里的偏移定义。 */
    const uint32_t sel_bits = reinterpret_cast<Context_t*>(Context)->argv_[2] & 0xff;
    [[maybe_unused]] const int gen_bits = sel_bits ? 1536 : 1024;
    int gen_rounds = (int)(reinterpret_cast<Context_t*>(Context)->argv_[3] & 0xff);
    if (gen_rounds < 1 || gen_rounds > MillerRabinContext::kMaxRounds)
      gen_rounds = MillerRabinContext::kMaxRounds;
    [[maybe_unused]] constexpr uint64_t kGenMaxProbes = 1000000; /* 安全上限: 期望探测数 ≈ ln(2^bits)/2 */

#if defined(__RockeyARM__)
    /* 工作区放 InOut(设备运行时内存, 不占栈): Context_t 恰 360B, 从 384B 起用 1 个 BN */
    uint8_t* inout = reinterpret_cast<uint8_t*>(Context);
    auto* W = reinterpret_cast<MillerRabinContext::BN*>(inout + 384);
    MillerRabinContext::GenResult st{};
    st.magic = MillerRabinContext::kMagicGenDone;
    st.bits = (uint32_t)gen_bits;
    st.rounds = (uint32_t)gen_rounds;
    rockey.SetLEDState(LED_STATE::kBlink);

    for (int which = 0; which < 2; ++which) {
      const uint32_t seed_off = which ? MillerRabinContext::kGenSeedQOffset : MillerRabinContext::kGenSeedPOffset;
      const uint32_t out_off = which ? MillerRabinContext::kGenQOffset : MillerRabinContext::kGenPOffset;
      W->clear();
      const int rr = rockey.RandBytes(reinterpret_cast<uint8_t*>(&W->v[0]), (size_t)gen_bits / 8);
      if (0 != rr) {
        rlLOGI(TAG, "GenPrime: RandBytes(%d) = %d", which, rr);
        break;
      }
      std::ignore = rockey.WriteDataFile(Dongle::kFactoryDataFileId, seed_off, &W->v[0], (size_t)gen_bits / 8);
      uint64_t probes = 0;
      const int hit = MR->FindPrime(*W, gen_bits, gen_rounds, kGenMaxProbes, probes, (uint32_t)(which + 1));
      const uint32_t bit = which ? 2u : 1u;
      if (hit > 0) {
        st.ok |= bit;
        std::ignore = rockey.WriteDataFile(Dongle::kFactoryDataFileId, out_off, &W->v[0], (size_t)gen_bits / 8);
      }
      if (which) {
        st.probes_q_lo = (uint32_t)probes;
        st.probes_q_hi = (uint32_t)(probes >> 32);
      } else {
        st.probes_p_lo = (uint32_t)probes;
        st.probes_p_hi = (uint32_t)(probes >> 32);
      }
      rlLOGI(TAG, "GenPrime %d: hit=%d probes=%llu", which, hit, (unsigned long long)probes);
    }
    /* 状态最后写: dashboard 上出现 kMagicGenDone 即"生成流程已结束" */
    std::ignore =
        rockey.WriteDataFile(Dongle::kFactoryDataFileId, MillerRabinContext::kGenStatusOffset, &st, sizeof(st));
    rlLOGI(TAG, "GenPrime done: ok=%u bits=%u rounds=%u", st.ok, st.bits, st.rounds);
#elif !defined(__EMULATOR__)
    auto gen_start = rLANG_GetTickCount();
    int main_result = 0;
    const int exec_result = static_cast<RockeyARM*>(&rockey)->ExecuteExeFile(Context, 1024, &main_result);
    auto gen_end = rLANG_GetTickCount();
    MillerRabinContext::GenResult st{};
    uint8_t pbuf[192] = {0}, qbuf[192] = {0};
    std::ignore =
        rockey.ReadDataFile(Dongle::kFactoryDataFileId, MillerRabinContext::kGenStatusOffset, &st, sizeof(st));
    if (st.bits == 1024 || st.bits == 1536) {
      std::ignore = rockey.ReadDataFile(Dongle::kFactoryDataFileId, MillerRabinContext::kGenPOffset, pbuf, st.bits / 8);
      std::ignore = rockey.ReadDataFile(Dongle::kFactoryDataFileId, MillerRabinContext::kGenQOffset, qbuf, st.bits / 8);
    }
    const uint64_t probes_p = ((uint64_t)st.probes_p_hi << 32) | st.probes_p_lo;
    const uint64_t probes_q = ((uint64_t)st.probes_q_hi << 32) | st.probes_q_lo;
    rlLOGI(TAG, "GenPrime(host): ExecuteExeFile=%d mainRet=%d in %lld ms", exec_result, main_result,
           static_cast<long long>(gen_end - gen_start));
    rlLOGI(TAG, "GenPrime(host): magic=%08x bits=%u rounds=%u ok=%u probes_p=%llu probes_q=%llu", st.magic, st.bits,
           st.rounds, st.ok, (unsigned long long)probes_p, (unsigned long long)probes_q);

    int ok = 0;
    if (st.magic == MillerRabinContext::kMagicGenDone && (st.ok & 3u) == 3u) {
      ok = VerifyRsaPrimePair(pbuf, qbuf, (int)st.bits, "mode3");
    } else {
      rlLOGE(TAG, "GenPrime(host): 生成未完成(magic=%08x ok=%u)", st.magic, st.ok);
    }
    exit(ok ? 0 : 1);
#else
    return 0; /* 模拟器: RSA 素数生成(设备内/OpenSSL 复核)不适用 */
#endif /* __RockeyARM__ */
    return 0;
  }

#if !defined(__EMULATOR__) && !defined(__RockeyARM__)
  Val->clear(); /* 等价 memset + n=0, 但不会触发 GCC -Wclass-memaccess(BN 有默认成员初始化) */

  Val->clear();
  Val->n = 32;
  /* argv_[1]: 0=随机奇数(多为合数); 1=注入 1024 位素数; 2=注入半素数 p*q(无小因子合数) */
  if (mode == 2) {
    /* 两个 512 位素数之积 → 1024 位合数且无 ≤1000 小因子(验证 Montgomery 判合路径) */
    BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();
    BIGNUM* m = BN_new();
    BN_CTX* bnctx = BN_CTX_new();
    BN_generate_prime_ex(p, 512, 0, nullptr, nullptr, nullptr);
    BN_generate_prime_ex(q, 512, 0, nullptr, nullptr, nullptr);
    BN_mul(m, p, q, bnctx);
    BN_bn2lebinpad(m, reinterpret_cast<unsigned char*>(&Val->v[0]), 32 * 4);
    BN_CTX_free(bnctx);
    BN_free(p);
    BN_free(q);
    BN_free(m);
    Val->v[0] |= 1;
  } else if (mode == 1) {
    BIGNUM* bp = BN_new();
    BN_generate_prime_ex(bp, 1024, 0, nullptr, nullptr, nullptr);
    BN_bn2lebinpad(bp, reinterpret_cast<unsigned char*>(&Val->v[0]), 32 * 4);
    BN_free(bp);
    Val->v[0] |= 1;
  } else {
    std::ignore = rockey.RandBytes((uint8_t*)&Val->v[0], 32);
    Val->v[0] |= 1;
    Val->v[31] &= 0x7fffffff;
    Val->v[31] |= 0x40000000;
  }

  BIGNUM* bn = BN_new();
  std::ignore = BN_set_word(bn, Val->v[Val->n - 1]);
  for (int i = Val->n - 2; i >= 0; --i) {
    std::ignore = BN_lshift(bn, bn, 32);
    std::ignore = BN_add_word(bn, Val->v[i]);
  }
  result = BN_is_prime_ex(bn, 0, nullptr, nullptr);
  BN_free(bn);

  rlLOGI(TAG, "BN_is_prime_ex %d (mode=%d, hostTrialDivide=%d)", result, mode, MR->TrialDivide(*Val) ? 1 : 0);
#endif /* !__EMULATOR__ && !__RockeyARM__ */

  rockey.SetLEDState(LED_STATE::kOff);
  MR->KickWDG();

  result = MR->IsPrimeMRW(*Val, mr_rounds);

  rlLOGI(TAG, "IsPrimeMRW %d (rounds=%d)", result, mr_rounds);

#if !defined(__EMULATOR__) && !defined(__RockeyARM__)
  // HOST + RockeyARM 需要共享当前的 Context, 我们必须手动执行 ...
  int main_result = 0;
  int exec_result = static_cast<RockeyARM*>(&rockey)->ExecuteExeFile(Context, 1024, &main_result);
  rlLOGI(TAG, "ExecuteExeFile result: %d %d %d", result, main_result, exec_result);

  exit(10086 - result);
#endif /* !__EMULATOR__ && !__RockeyARM__ */

  return result;
}

int Start(void* InOutBuf, void* ExtendBuf) {
  const int kSizeGuardBytes = 16;
  Context_t* Context = (Context_t*)InOutBuf;
  uint8_t* GuardBytes = static_cast<uint8_t*>(InOutBuf) + 1024;
  memset(GuardBytes, 0xCC, kSizeGuardBytes);

  int result = 0, result2 = 0, index = (Context->argv_[0] & 0xFF);

#if defined(__EMULATOR__)
  const char* const kTestingDongleFile = ".foobar-dongle.bin";
  const char* const kTestingDongleSecret = "1234567812345678";
  Emulator rockey(Context->permission_);

  if (rockey.Open(kTestingDongleFile, kTestingDongleSecret) < 0)
    rockey.Create(kTestingDongleSecret);

#elif !defined(__RockeyARM__)
  Context_t CopyContext = *Context;

  RockeyARM rockey;
  DONGLE_INFO dongle_info[64];

  /* 多设备: WT_RKEY_DEVICE 选择 Enum 索引(默认 0), 与 WT_APP_DONGLE 同款 env 模式 */
  const char* rkey_dev = getenv("WT_RKEY_DEVICE");
  const int dev_index = rkey_dev ? atoi(rkey_dev) : 0;

  result = rockey.Enum(dongle_info);
  rlLOGI(TAG, "rockey.Enum return %d/%08x", result, rockey.GetLastError());

  for (int i = 0; i < result; ++i) {
    rlLOGXI(TAG, &dongle_info[i], sizeof(DONGLE_INFO), "rockey.Enum %d/%d", i + 1, result);
  }

  result = rockey.Open(dev_index);
  rlLOGI(TAG, "rockey.Open return %d/%08x", result, rockey.GetLastError());

  result = rockey.ResetState();
  rlLOGI(TAG, "rockey.ResetState return %d/%08x", result, rockey.GetLastError());

  result = rockey.RandBytes(Context->bytes, sizeof(Context->bytes));
  rlLOGI(TAG, "rockey.RandBytes return %d/%08X", result, rockey.GetLastError());

  if (Context->permission_ != PERMISSION::kAnonymous) {
    result = rockey.VerifyPIN(Context->permission_, nullptr, nullptr);
    rlLOGI(TAG, "rockey.VerifyPIN %d/%08X", result, rockey.GetLastError());
  }

  if (Context->permission_ == PERMISSION::kAdministrator) {
    if ((0xF0 & index) == 0xF0) {
      index &= 0x0F;

#define DONGLE_RUN_ADMINTESTING(Name)                                 \
  do {                                                                \
    if (index == static_cast<int>(kAdminTestingIndex::Name)) {        \
      rlLOGI(TAG, "===== DONGLE_RUN_ADMINTESTING: %s ===== ", #Name); \
      result2 = AdminTesting_##Name(rockey, Context, ExtendBuf);      \
    }                                                                 \
  } while (0)

      DONGLE_RUN_ADMINTESTING(FactoryReset);
      DONGLE_RUN_ADMINTESTING(SelectProductId);

      result += result2;
      rlLOGXI(TAG, Context, sizeof(Context_t), "rockey AdminTest.%d return %d/%08x", result, result2,
              rockey.GetLastError());
      return result;
    }

    char pid[20] = "", admin[20] = "";
    result = rockey.GenUniqueKey("10086", 5, pid, admin);
    rlLOGI(TAG, "rockey.GenUniqueKey %d/%08x %s %s", result, rockey.GetLastError(), pid, admin);

    result = rockey.ChangePIN(PERMISSION::kAdministrator, admin, "FFFFFFFFFFFFFFFF", 255);
    rlLOGI(TAG, "rockey.ChangePIN %d/%08x", result, rockey.GetLastError());

    result = rockey.Open(dev_index);
    rlLOGI(TAG, "rockey.Open return %d/%08x", result, rockey.GetLastError());

    result = rockey.VerifyPIN(PERMISSION::kAdministrator, nullptr, nullptr);
    rlLOGI(TAG, "rockey.VerifyPIN %d/%08X", result, rockey.GetLastError());

    result = rockey.SetUserID(rLANG_WORLD_MAGIC);
    rlLOGI(TAG, "rockey.SetUserID %d/%08x", result, rockey.GetLastError());
  }

  result = rockey.LimitSeedCount(-1);
  rlLOGI(TAG, "rockey.LimitSeedCount %d/%08x", result, rockey.GetLastError());

  result = rockey.SetExpireTime(10000);
  rlLOGI(TAG, "rockey.SetExpireTime %d/%08x", result, rockey.GetLastError());

  result = rockey.ChangePIN(PERMISSION::kNormal, "12345678", "12345678", 10);
  rlLOGI(TAG, "rockey.ChangePIN %d/%08x", result, rockey.GetLastError());

  result = rockey.ChangePIN(PERMISSION::kAdministrator, "FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", 255);
  rlLOGI(TAG, "rockey.ChangePIN %d/%08x", result, rockey.GetLastError());

  result = rockey.ResetUserPIN("FFFFFFFFFFFFFFFF");
  rlLOGI(TAG, "rockey.ResetUserPIN %d/%08x", result, rockey.GetLastError());

  const char* app_dongle = getenv("WT_APP_DONGLE");
  if (app_dongle) {
    uint8_t app_[64 * 1024];
    FILE* fp = fopen(app_dongle, "rb");
    if (!fp) {
      rlLOGE(TAG, "Can't open %s for read!", app_dongle);
    } else {
      size_t size = fread(app_, 1, sizeof(app_), fp);
      fclose(fp);

      if (size < 64 || size >= 0xFFFF) {
        rlLOGE(TAG, "Invalid %s app.size %zd", app_dongle, size);
      } else {
        result = rockey.UpdateExeFile(app_, size);
        rlLOGI(TAG, "rockey.UpdateExeFile %s %d/%08X", app_dongle, result, rockey.GetLastError());
      }
    }
  }

  if (!rockey.Ready())
    exit(1);
#else  // __RockeyARM__

  Dongle rockey;

#endif  // __RockeyARM__

#if !defined(__RockeyARM__)
  /* X509Tests:进入测试前把内置证书写入 dashboard[0, 4KB)(factory dataFile 0xFFFF
   * 匿名可写区), host 本地测试与设备端(经 ExecuteExeFile 进入)统一 ReadDataFile 加载 */
  if (index == static_cast<int>(kTestingIndex::X509Tests))
    WriteX509Certs(rockey, Context);
#endif /* __RockeyARM__ */

  {
    DONGLE_INFO dongle_info_;
    result = rockey.GetDongleInfo(&dongle_info_);
    rlLOGXI(TAG, &dongle_info_, sizeof(dongle_info_), "rockey.GetDongleInfo %d", result);
  }

  result = rockey.RandBytes(Context->bytes, sizeof(Context->bytes));
  rlLOGXI(TAG, Context->bytes, sizeof(Context->bytes), "rockey.RandBytes %d/%08x", result, rockey.GetLastError());

  /* SeedSecret 验证已删除(用户决策 2026-09-06):ukey 未初始化(PID 未设置)时该调用必然
   * 失败(F0000006),失败值经 result 流入最终退出码(10086-(-1) mod 256 = 103),干扰
   * 测试结果判定;且 Context->seed_ 无任何消费方,纯记录无意义。 */

  rockey.SetLEDState(LED_STATE::kBlink);

  rockey.GetRealTime(&Context->realTime_);
  rockey.GetExpireTime(&Context->expireTime_);
  rockey.GetTickCount(&Context->ticks_);
  rockey.GetDongleInfo(&Context->dongle_info_);
  rockey.GetPINState(&Context->permission_);

  rockey.ReadShareMemory(Context->share_memory_2_);
  rlLOGXI(TAG, Context->share_memory_2_, 32, "SharedMemroy.2");

  rockey.WriteShareMemory(&Context->bytes[32]);
  rlLOGXI(TAG, &Context->bytes[32], 32, "Context->bytes.2");

  rockey.ReadShareMemory(Context->share_memory_1_);
  rlLOGXI(TAG, Context->share_memory_1_, 32, "SharedMemroy.1");

  rlLOGXI(TAG, Context, sizeof(Context_t), "rockey Test.0 return %d/%08x", result, rockey.GetLastError());
  rockey.ClearLastError();
#define DONGLE_RUN_TESTING(Name)                                 \
  do {                                                           \
    if (index == static_cast<int>(kTestingIndex::Name)) {        \
      rlLOGI(TAG, "===== DONGLE_RUN_TESTING: %s ===== ", #Name); \
      result2 = Testing_##Name(rockey, Context, ExtendBuf);      \
    }                                                            \
  } while (0)

  DONGLE_RUN_TESTING(CreateDataFile);
  DONGLE_RUN_TESTING(ReadWriteDataFile);
  DONGLE_RUN_TESTING(ReadWriteFactoryData);
  DONGLE_RUN_TESTING(CreateRSAFile);
  DONGLE_RUN_TESTING(RSAExec);
  DONGLE_RUN_TESTING(SM2Exec);
  DONGLE_RUN_TESTING(P256Exec);
  DONGLE_RUN_TESTING(KeyExec);
  DONGLE_RUN_TESTING(HashExec);
  DONGLE_RUN_TESTING(Secp256K1Exec);
  DONGLE_RUN_TESTING(ChaChaPoly);
  DONGLE_RUN_TESTING(Sha256Test);
  DONGLE_RUN_TESTING(Sha384Test);
  DONGLE_RUN_TESTING(Sha512Test);
  DONGLE_RUN_TESTING(Curve25519Test);
  DONGLE_RUN_TESTING(Ed25519Test);
  DONGLE_RUN_TESTING(PKeyCountDownTest);
  DONGLE_RUN_TESTING(X509Tests);
  DONGLE_RUN_TESTING(PrimeMRTests);

  Context->result_[0] = result;
  Context->result_[1] = result2;
  rlLOGXI(TAG, Context, sizeof(Context_t), "rockey Test.%d return %d/%08x", index, result2, rockey.GetLastError());
  result += result2;

#if !defined(__RockeyARM__) && !defined(__EMULATOR__)
  auto start = rLANG_GetTickCount();
  int main_result = 0, result3 = rockey.ExecuteExeFile(&CopyContext, sizeof(CopyContext), &main_result);
  auto end = rLANG_GetTickCount();
  rlLOGXI(TAG, &CopyContext, sizeof(CopyContext), "rockey.ExecuteExeFile return %d, mainRet %d, %08X, in %lld ms",
          result3, main_result, rockey.GetLastError(), static_cast<long long>(end - start));
  if (result3 < 0)
    ++result;
#endif /* __RockeyARM__ */

#if 1
  for (int i = 0; i < kSizeGuardBytes; ++i) {
    if (GuardBytes[i] != 0xCC)
      result += 100;
  }
#endif

#if defined(__EMULATOR__)
  rockey.Write(kTestingDongleFile);
#endif /* __EMULATOR__ */

  std::ignore = TAG;
  return 10086 - result;
}

}  // namespace dongle

rLANG_DECLARE_END

#if !defined(__RockeyARM__)
/* host 入口: 设备固件(arm)不链接 libc 的 calloc/strtoul, 必须排除, 否则固件链接失败 */
int main(int argc, char* argv[]) {
  using namespace machine;
  using namespace machine::dongle;
#ifdef _MSC_VER
  if (argc >= 2 && 0 == strcmp("-d", argv[1])) {
    while (!::IsDebuggerPresent()) {
      rlLOGI(TAG, "Wait debugger ...");
      Sleep(1000);
    }
    ::DebugBreak();
    --argc;
    ++argv;
  }
#endif /* _MSC_VER */

  rLANG_ABIREQUIRE(sizeof(Context_t) <= 1024);
  Context_t* Context = (Context_t*)calloc(1, 3 << 10);
  uint64_t ExtendBuf[(1 << 10) / 8] = {0};

  Context->permission_ = PERMISSION::kAnonymous;
  if (argc >= 2 && '-' == argv[1][0]) {
    switch (argv[1][1]) {
      case '2':
        Context->permission_ = PERMISSION::kAdministrator;
        break;
      case '1':
        Context->permission_ = PERMISSION::kNormal;
        break;
      case '0':
        Context->permission_ = PERMISSION::kAnonymous;
        break;
    }
    --argc;
    ++argv;
  }

  for (int i = 1; i <= 4 && i < argc; ++i) {
    Context->argv_[i - 1] = strtoul(argv[i], nullptr, 16);
  }

  return Start(Context, ExtendBuf);
}
#endif /* !__RockeyARM__ */

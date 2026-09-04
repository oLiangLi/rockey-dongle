#pragma once

#ifndef __WTINC_DONGLE_X509_H__
#define __WTINC_DONGLE_X509_H__

#include "dongle.h"

namespace machine {
namespace dongle {

/*!
 * X509 证书验签原语(设备端/模拟器共享)
 *
 * 约束:证书 DER <= 1KB, 整块在调用方缓冲区(InOutBuf)内就地解析, 零拷贝。
 * 固件无 rodata/无硬件除法:OID 一律"逐字节立即数比对", 解析器不出现 / 与 %。
 * 时间检查只置警告标志不拒绝(设备实时钟不可靠)。
 * 验签全部走设备硬件/宿主 TASSL(ukey 上软件模幂/软件 ECDSA 性能不可接受)。
 */

enum X509SigType {
  kX509SigUnknown = 0,
  kX509SigRSA_SHA256 = 1,   /* sha256WithRSAEncryption (1.2.840.113549.1.1.11) */
  kX509SigP256_SHA256 = 2,  /* ecdsa-with-SHA256 (1.2.840.10045.4.3.2) */
  kX509SigSM2_SM3 = 3,      /* SM2-with-SM3 (1.2.156.10197.1.501) */
  kX509SigRSA_SHA384 = 4,   /* sha384WithRSAEncryption (1.2.840.113549.1.1.12) */
  kX509SigRSA_SHA512 = 5,   /* sha512WithRSAEncryption (1.2.840.113549.1.1.13) */
  kX509SigP256_SHA384 = 6,  /* ecdsa-with-SHA384 (1.2.840.10045.4.3.3) */
  kX509SigP256_SHA512 = 7,  /* ecdsa-with-SHA512 (1.2.840.10045.4.3.4) */
};

/*! 解析视图:所有 offset/len 相对证书 DER 起点, 就地零拷贝 */
struct X509View {
  uint16_t off_tbs;
  uint16_t len_tbs; /* 待哈希/验签主体 */
  uint16_t off_sigalg_oid;
  uint16_t len_sigalg_oid;
  uint16_t off_issuer;
  uint16_t len_issuer;
  uint16_t off_subject;
  uint16_t len_subject;
  uint16_t off_notbefore;
  uint16_t len_notbefore;
  uint16_t off_notafter;
  uint16_t len_notafter;
  uint16_t off_spki_alg_oid;
  uint16_t len_spki_alg_oid;
  uint16_t off_spki_pub;
  uint16_t len_spki_pub; /* BIT STRING 内容: RSA SEQ(INT n, INT e) 或 04||X||Y */
  uint16_t off_signature;
  uint16_t len_signature; /* BIT STRING 内容: RSA 整数或 DER ECDSA-Sig-Value SEQ(r,s) */
  uint16_t off_extensions;
  uint16_t len_extensions;
  uint8_t sig_type;
  uint8_t time_flags; /* kX509Time* 警告位 */
  uint8_t ext_count;
};

struct X509Ext {
  uint16_t off_oid;
  uint8_t len_oid;
  uint16_t off_value;
  uint16_t len_value; /* extnValue OCTET STRING 内容 */
  uint8_t critical;
};

enum {
  kX509TimeOK = 0,
  kX509TimeBefore = 1,       /* now < notBefore */
  kX509TimeAfter = 2,        /* now > notAfter */
  kX509TimeUnavailable = 4,  /* 时间无法解析/年份超出可表示范围 */
};

/*! 严格 DER 解析(拒绝 indefinite 长度/非规范编码/尾随字节/负 INTEGER), 失败返回负值 */
int X509Parse(X509View* view, const uint8_t* der, size_t size);

/*! notBefore/notAfter 与 now(Unix 秒)比较, 只写 view->time_flags 警告位, 返回 0/-errno */
int X509CheckTime(X509View* view, const uint8_t* der, size_t size, uint64_t now_epoch);

/*! 扩展遍历(零额外存储, 按 iterator 重走 DER);iterator 传入 0 起始, 返回 1=有, 0=无, <0=错 */
int X509ExtNext(const X509View* view, const uint8_t* der, size_t size, X509Ext* out, uint8_t* iterator);

/*! 用 ca_cert 的 SPKI 验证 leaf 签名(两种证书均 <=1KB DER)
 *! RSA: PKCS#1 v1.5 + SHA256/384/512 DigestInfo;P256: ECDSA + SHA256/384/512(摘要截左 256 位,
 *! FIPS 186-4 §6.4);SM2: 固定 SM3(e = SM3(Z_A||tbs) 由硬件/宿主库内部计算)。
 *! work/work_size: 工作区(OpCode 传 ExtendBuf 区域), 需 >= 304B(Sha*Ctx 各 240B + md 缓冲 64B);
 *! 哈希上下文与摘要缓冲都在 work 内做, 不落栈 */
int X509VerifySignature(Dongle* dongle, const uint8_t* leaf, size_t leaf_size, const uint8_t* ca_cert,
                        size_t ca_cert_size, void* work, size_t work_size);

/*! 链引导:issuer==subject 且用自身 SPKI 验签 */
int X509VerifySelfSigned(Dongle* dongle, const uint8_t* cert, size_t cert_size, void* work, size_t work_size);

/*! 证书 SPKI 公钥提取(脚本层可用来比锁存 CA 公钥):
 *! RSA -> out 依次为 [e:uint32 LE][N:256B 大端];EC/SM2 -> out[0..64] = X||Y */
int X509GetPublicKey(const uint8_t* der, size_t size, uint8_t* out, size_t* size_out, uint8_t* sig_type);

/* ---- OID 立即数比对(零 rodata) ---- */
bool X509OID_Sha256WithRSA(const uint8_t* oid, size_t len);
bool X509OID_Sha384WithRSA(const uint8_t* oid, size_t len);
bool X509OID_Sha512WithRSA(const uint8_t* oid, size_t len);
bool X509OID_EcdsaWithSHA256(const uint8_t* oid, size_t len);
bool X509OID_EcdsaWithSHA384(const uint8_t* oid, size_t len);
bool X509OID_EcdsaWithSHA512(const uint8_t* oid, size_t len);
bool X509OID_SM2WithSM3(const uint8_t* oid, size_t len);
bool X509OID_RSAEncryption(const uint8_t* oid, size_t len);
bool X509OID_ECPublicKey(const uint8_t* oid, size_t len);
bool X509OID_Secp256r1(const uint8_t* oid, size_t len);
bool X509OID_SM2p256v1(const uint8_t* oid, size_t len);
bool X509OID_BasicConstraints(const uint8_t* oid, size_t len);
bool X509OID_KeyUsage(const uint8_t* oid, size_t len);
bool X509OID_SAN(const uint8_t* oid, size_t len);
bool X509OID_ExtKeyUsage(const uint8_t* oid, size_t len);

}  // namespace dongle
}  // namespace machine

#endif /* __WTINC_DONGLE_X509_H__ */

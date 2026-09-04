/*!
 * X509 证书验签原语:严格 DER 解析 + RSA2048-SHA256/384/512 / P256-SHA256/384/512 / SM2-SM3 验签
 *
 * 约束(固件/模拟器共享):
 *  - 证书 DER <= 1KB, 整块就地解析, 零拷贝(offset/len 直接指向证书字节)
 *  - 无 rodata:全部常量走"逐字节立即数比对";无 / 与 %(M0 无硬件除法)
 *  - 栈纪律:本文件函数帧 <= ~320B;哈希上下文与摘要缓冲都放调用方 work 区(ExtendBuf)
 *  - 验签走设备硬件(FTRX)/宿主 TASSL;软件模幂/软件 ECDSA 不可用(ukey 性能)
 *  - 时间检查只置警告位(设备实时钟不可靠)
 */
#include <Interface/dongle.h>
#include <Interface/x509.h>
#include <base/base.h>

AGINX_DECLARE_MACHINE

namespace dongle {

namespace {

/* ---- OID 立即数比对(禁止 static const 数组:固件 rodata 必须为空) ---- */

bool oid_eq_9(const uint8_t* p, size_t n, uint8_t a0, uint8_t a1, uint8_t a2, uint8_t a3, uint8_t a4, uint8_t a5,
              uint8_t a6, uint8_t a7, uint8_t a8) {
  return n == 9 && p[0] == a0 && p[1] == a1 && p[2] == a2 && p[3] == a3 && p[4] == a4 && p[5] == a5 && p[6] == a6 &&
         p[7] == a7 && p[8] == a8;
}
bool oid_eq_8(const uint8_t* p, size_t n, uint8_t a0, uint8_t a1, uint8_t a2, uint8_t a3, uint8_t a4, uint8_t a5,
              uint8_t a6, uint8_t a7) {
  return n == 8 && p[0] == a0 && p[1] == a1 && p[2] == a2 && p[3] == a3 && p[4] == a4 && p[5] == a5 && p[6] == a6 &&
         p[7] == a7;
}
bool oid_eq_7(const uint8_t* p, size_t n, uint8_t a0, uint8_t a1, uint8_t a2, uint8_t a3, uint8_t a4, uint8_t a5,
              uint8_t a6) {
  return n == 7 && p[0] == a0 && p[1] == a1 && p[2] == a2 && p[3] == a3 && p[4] == a4 && p[5] == a5 && p[6] == a6;
}
bool oid_eq_3(const uint8_t* p, size_t n, uint8_t a0, uint8_t a1, uint8_t a2) {
  return n == 3 && p[0] == a0 && p[1] == a1 && p[2] == a2;
}

/* ---- 严格 DER 游标 ---- */

struct DerCursor {
  const uint8_t* p;
  const uint8_t* end;
};

/*! 取一个 TLV:仅定长形式;长度只用最短编码(短形或长形无前导 0);拒绝多字节 tag */
static int der_tlv(DerCursor* c, uint8_t* tag, uint16_t* len, const uint8_t** content) {
  if (c->p >= c->end)
    return -EBADMSG;
  uint8_t t = *c->p++;
  if ((t & 0x1F) == 0x1F)
    return -EBADMSG; /* 高 tag 编号在证书结构中不出现 */
  if (c->p >= c->end)
    return -EBADMSG;
  uint8_t l = *c->p++;
  size_t vlen;
  if (l < 0x80) {
    vlen = l;
  } else {
    uint8_t n = l & 0x7F;
    if (n == 0 || n > 2 || c->p + n > c->end)
      return -EBADMSG; /* 严格:1KB 证书内长度编码 <= 2 字节 */
    if (*c->p == 0)
      return -EBADMSG; /* 非规范:长形前导 0 */
    vlen = 0;
    while (n--) {
      vlen = (vlen << 8) | *c->p++;
    }
  }
  if (c->p + vlen > c->end)
    return -EBADMSG;
  *tag = t;
  *len = static_cast<uint16_t>(vlen);
  *content = c->p;
  c->p += vlen;
  return 0;
}

/*! 规范 INTEGER:正值;前导 0x00 仅允许作为符号位;右对齐填满 out_size 字节(大端) */
static int der_integer(const uint8_t* content, size_t len, uint8_t* out, size_t out_size) {
  size_t i = 0;
  if (len == 0)
    return -EBADMSG;
  if (content[0] == 0x00) {
    if (len == 1 || !(content[1] & 0x80))
      return -EBADMSG; /* 多余前导 0 */
    ++i;
  } else if (content[0] & 0x80) {
    return -EBADMSG; /* 负数(证书场景不合法) */
  }
  size_t vlen = len - i;
  if (vlen > out_size)
    return -E2BIG;
  memset(out, 0, out_size - vlen);
  memcpy(out + (out_size - vlen), content + i, vlen);
  return 0;
}

/*! 由证书字节指针构造视图游标(证书 <= 1KB, offset 用 uint16 即可) */
static int cursor_from(const uint8_t* der, size_t size, DerCursor* c) {
  if (!der)
    return -EINVAL;
  if (size == 0 || size > 1024)
    return -E2BIG;
  c->p = der;
  c->end = der + size;
  return 0;
}

static int skip_tlv(DerCursor* c) {
  uint8_t tag;
  uint16_t len;
  const uint8_t* content;
  return der_tlv(c, &tag, &len, &content);
}

/*! tbs 内的 AlgorithmIdentifier:OID + params(NULL 或 OID), 返回 OID 的绝对指针 */
static int der_algorithm_id(DerCursor* c, const uint8_t** out_oid, uint16_t* len_oid) {
  uint8_t tag;
  uint16_t len;
  const uint8_t* content;
  int r = der_tlv(c, &tag, &len, &content);
  if (0 != r || tag != 0x30)
    return -EBADMSG;

  DerCursor a = {content, content + len};
  const uint8_t* oid;
  r = der_tlv(&a, &tag, &len, &oid);
  if (0 != r || tag != 0x06)
    return -EBADMSG;
  *out_oid = oid;
  *len_oid = len;
  return 0;
}

/* ---- OID 分类 ---- */

static uint8_t classify_sigalg(const uint8_t* oid, size_t len) {
  /* 1.2.840.113549.1.1.11 sha256WithRSAEncryption */
  if (oid_eq_9(oid, len, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B))
    return kX509SigRSA_SHA256;
  /* 1.2.840.113549.1.1.12 sha384WithRSAEncryption */
  if (oid_eq_9(oid, len, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C))
    return kX509SigRSA_SHA384;
  /* 1.2.840.113549.1.1.13 sha512WithRSAEncryption */
  if (oid_eq_9(oid, len, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D))
    return kX509SigRSA_SHA512;
  /* 1.2.840.10045.4.3.2 ecdsa-with-SHA256 */
  if (oid_eq_8(oid, len, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02))
    return kX509SigP256_SHA256;
  /* 1.2.840.10045.4.3.3 ecdsa-with-SHA384 */
  if (oid_eq_8(oid, len, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03))
    return kX509SigP256_SHA384;
  /* 1.2.840.10045.4.3.4 ecdsa-with-SHA512 */
  if (oid_eq_8(oid, len, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04))
    return kX509SigP256_SHA512;
  /* 1.2.156.10197.1.501 SM2-with-SM3 */
  if (oid_eq_8(oid, len, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x75))
    return kX509SigSM2_SM3;
  return kX509SigUnknown;
}

/* ---- 时间解析(无除法;年份仅支持 [1950, 2049], 否则视为不可用) ---- */

static bool is_leap(int y) {
  if (0 != (y & 3))
    return false; /* y%4 != 0 */
  int q = 0;
  while (y >= 100) { /* y = 100*q + r, 无除法 */
    y -= 100;
    ++q;
  }
  if (y != 0)
    return true; /* y%4==0 且 y%100!=0 */
  return 0 == (q & 3); /* 整除 100:看 400 */
}

static int days_before_month(int m /* 1..12 */) {
  int d = 0;
  if (m > 1) d += 31;
  if (m > 2) d += 28;
  if (m > 3) d += 31;
  if (m > 4) d += 30;
  if (m > 5) d += 31;
  if (m > 6) d += 30;
  if (m > 7) d += 31;
  if (m > 8) d += 31;
  if (m > 9) d += 30;
  if (m > 10) d += 31;
  if (m > 11) d += 30;
  return d;
}

/*! 解析 UTCTime(13B "YYMMDDHHMMSSZ")或 GeneralizedTime(15B "YYYYMMDDHHMMSSZ")为 Unix 秒。
 *! 返回值 0=成功;年份/月日非法返回负值。 */
static int64_t parse_time(const uint8_t* s, size_t len) {
  if (len != 13 && len != 15)
    return -1;
  size_t i = 0;
  int year;
  if (len == 13) {
    year = (s[0] - '0') * 10 + (s[1] - '0');
    year += (year >= 50) ? 1900 : 2000;
    i = 2;
  } else {
    year = ((s[0] - '0') * 1000) + ((s[1] - '0') * 100) + ((s[2] - '0') * 10) + (s[3] - '0');
    i = 4;
  }
  if (year < 1950 || year > 2049)
    return -1;
  int mon = (s[i] - '0') * 10 + (s[i + 1] - '0');
  int day = (s[i + 2] - '0') * 10 + (s[i + 3] - '0');
  int hh = (s[i + 4] - '0') * 10 + (s[i + 5] - '0');
  int mi = (s[i + 6] - '0') * 10 + (s[i + 7] - '0');
  int ss = (s[i + 8] - '0') * 10 + (s[i + 9] - '0');
  if (s[i + 10] != 'Z')
    return -1;
  if (mon < 1 || mon > 12 || day < 1 || day > 31 || hh > 23 || mi > 59 || ss > 60)
    return -1;

  int64_t days = 0;
  for (int yy = 1970; yy < year; ++yy) {
    days += is_leap(yy) ? 366 : 365;
  }
  days += days_before_month(mon);
  if (mon > 2 && is_leap(year))
    days += 1;
  days += day - 1;

  return (((days * 24) + hh) * 60 + mi) * 60 + ss;
}

/* ---- 验签路径内部 ---- */

static int spki_rsa(const X509View* view, const uint8_t* ca_cert, const uint8_t** out_n, size_t* out_n_len,
                    uint32_t* out_e) {
  /* SPKI 内容 = SEQUENCE { INTEGER n, INTEGER e } */
  DerCursor c = {ca_cert + view->off_spki_pub, ca_cert + view->off_spki_pub + view->len_spki_pub};
  uint8_t tag;
  uint16_t len;
  const uint8_t* content;
  int r = der_tlv(&c, &tag, &len, &content);
  if (0 != r || tag != 0x30)
    return -EBADMSG;

  DerCursor a = {content, content + len};
  const uint8_t* n;
  r = der_tlv(&a, &tag, &len, &n);
  if (0 != r || tag != 0x02)
    return -EBADMSG;
  /* 模数归一化:去掉符号位前导 0x00, 必须正好 256B(2048 位) */
  if (len == 257 && n[0] == 0x00 && (n[1] & 0x80)) {
    ++n;
    --len;
  }
  if (len != 256)
    return -EBADMSG;
  *out_n = n;
  *out_n_len = 256;

  const uint8_t* e;
  r = der_tlv(&a, &tag, &len, &e);
  if (0 != r || tag != 0x02 || len == 0 || len > 4)
    return -EBADMSG;
  if (e[0] & 0x80)
    return -EBADMSG;
  uint32_t ev = 0;
  for (uint16_t i = 0; i < len; ++i) {
    ev = (ev << 8) | e[i];
  }
  *out_e = ev;
  return 0;
}

static int spki_ec(const X509View* view, const uint8_t* ca_cert, const uint8_t** out_x, const uint8_t** out_y) {
  /* SPKI 内容 = 04 || X(32B) || Y(32B), 拒绝压缩点 */
  if (view->len_spki_pub != 65)
    return -EBADMSG;
  const uint8_t* p = ca_cert + view->off_spki_pub;
  if (p[0] != 0x04)
    return -EBADMSG;
  *out_x = p + 1;
  *out_y = p + 33;
  return 0;
}

static int sig_ecdsa(const X509View* view, const uint8_t* leaf, uint8_t r[32], uint8_t s[32]) {
  /* 签名内容 = DER ECDSA-Sig-Value SEQUENCE { INTEGER r, INTEGER s } */
  DerCursor c = {leaf + view->off_signature, leaf + view->off_signature + view->len_signature};
  uint8_t tag;
  uint16_t len;
  const uint8_t* content;
  int ret = der_tlv(&c, &tag, &len, &content);
  if (0 != ret || tag != 0x30)
    return -EBADMSG;

  DerCursor a = {content, content + len};
  const uint8_t* rp;
  ret = der_tlv(&a, &tag, &len, &rp);
  if (0 != ret || tag != 0x02)
    return -EBADMSG;
  ret = der_integer(rp, len, r, 32);
  if (0 != ret)
    return ret;

  const uint8_t* sp;
  ret = der_tlv(&a, &tag, &len, &sp);
  if (0 != ret || tag != 0x02 || a.p != a.end)
    return -EBADMSG;
  return der_integer(sp, len, s, 32);
}

static int sig_rsa(const X509View* view, const uint8_t* leaf, const uint8_t** out_sig) {
  /* 签名内容 = RSA 签名字节串(256B 或带符号位前导 0x00 的 257B), 就地使用 */
  const uint8_t* p = leaf + view->off_signature;
  if (view->len_signature == 257 && p[0] == 0x00 && (p[1] & 0x80)) {
    ++p;
  } else if (view->len_signature != 256) {
    return -EBADMSG;
  }
  *out_sig = p;
  return 0;
}

}  // namespace

/* ---- 公共 OID 比对 ---- */

bool X509OID_Sha256WithRSA(const uint8_t* oid, size_t len) {
  return oid_eq_9(oid, len, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B);
}
bool X509OID_Sha384WithRSA(const uint8_t* oid, size_t len) {
  return oid_eq_9(oid, len, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C);
}
bool X509OID_Sha512WithRSA(const uint8_t* oid, size_t len) {
  return oid_eq_9(oid, len, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D);
}
bool X509OID_EcdsaWithSHA256(const uint8_t* oid, size_t len) {
  return oid_eq_8(oid, len, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02);
}
bool X509OID_EcdsaWithSHA384(const uint8_t* oid, size_t len) {
  return oid_eq_8(oid, len, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03);
}
bool X509OID_EcdsaWithSHA512(const uint8_t* oid, size_t len) {
  return oid_eq_8(oid, len, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04);
}
bool X509OID_SM2WithSM3(const uint8_t* oid, size_t len) {
  return oid_eq_8(oid, len, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x75);
}
bool X509OID_RSAEncryption(const uint8_t* oid, size_t len) {
  return oid_eq_9(oid, len, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01);
}
bool X509OID_ECPublicKey(const uint8_t* oid, size_t len) {
  return oid_eq_7(oid, len, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01);
}
bool X509OID_Secp256r1(const uint8_t* oid, size_t len) {
  return oid_eq_8(oid, len, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07);
}
bool X509OID_SM2p256v1(const uint8_t* oid, size_t len) {
  return oid_eq_8(oid, len, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D);
}
bool X509OID_BasicConstraints(const uint8_t* oid, size_t len) {
  return oid_eq_3(oid, len, 0x55, 0x1D, 0x13);
}
bool X509OID_KeyUsage(const uint8_t* oid, size_t len) {
  return oid_eq_3(oid, len, 0x55, 0x1D, 0x0F);
}
bool X509OID_SAN(const uint8_t* oid, size_t len) {
  return oid_eq_3(oid, len, 0x55, 0x1D, 0x11);
}
bool X509OID_ExtKeyUsage(const uint8_t* oid, size_t len) {
  return oid_eq_3(oid, len, 0x55, 0x1D, 0x25);
}

/* ---- 解析 ---- */

int X509Parse(X509View* view, const uint8_t* der, size_t size) {
  if (!view)
    return -EINVAL;
  memset(view, 0, sizeof(*view));
  view->sig_type = kX509SigUnknown;

  DerCursor c;
  int r = cursor_from(der, size, &c);
  if (0 != r)
    return r;

  /* 顶层: SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue } */
  uint8_t tag;
  uint16_t len;
  const uint8_t* content;
  r = der_tlv(&c, &tag, &len, &content);
  if (0 != r || tag != 0x30)
    return -EBADMSG;
  DerCursor top = {content, content + len};

  /* tbsCertificate:签名覆盖"含 SEQUENCE 头的完整 tbs DER", 故 off/len 从头部字节起算 */
  const uint8_t* tbs_hdr = top.p;
  const uint8_t* tbs;
  r = der_tlv(&top, &tag, &len, &tbs);
  if (0 != r || tag != 0x30)
    return -EBADMSG;
  uint16_t len_tbs_content = len;
  view->off_tbs = static_cast<uint16_t>(tbs_hdr - der);
  view->len_tbs = static_cast<uint16_t>((tbs + len) - tbs_hdr);

  /* signatureAlgorithm */
  const uint8_t* alg;
  r = der_tlv(&top, &tag, &len, &alg);
  if (0 != r || tag != 0x30)
    return -EBADMSG;
  uint16_t len_alg = len;

  /* signatureValue BIT STRING */
  const uint8_t* sigv;
  r = der_tlv(&top, &tag, &len, &sigv);
  if (0 != r || tag != 0x03 || top.p != top.end)
    return -EBADMSG;
  if (len < 1 || sigv[0] != 0)
    return -EBADMSG; /* 未用位必须为 0 */
  view->off_signature = static_cast<uint16_t>(sigv + 1 - der);
  view->len_signature = static_cast<uint16_t>(len - 1);

  /* 外层 AlgorithmIdentifier: OID + params */
  DerCursor a = {alg, alg + len_alg};
  const uint8_t* oid;
  r = der_tlv(&a, &tag, &len, &oid);
  if (0 != r || tag != 0x06)
    return -EBADMSG;
  view->off_sigalg_oid = static_cast<uint16_t>(oid - der);
  view->len_sigalg_oid = len;
  view->sig_type = classify_sigalg(oid, len);

  /* ---- tbs 内部 ---- */
  /* 注意:view->len_tbs 含 SEQ 头, 内容游标须用内容长度 */
  DerCursor t = {tbs, tbs + len_tbs_content};
  int version = 0;
  bool has_version = false;

  /* version [0] EXPLICIT(可选) */
  const uint8_t* peek_tbs = t.p;
  if (peek_tbs < t.end && *peek_tbs == 0xA0) {
    r = der_tlv(&t, &tag, &len, &content);
    if (0 != r || tag != 0xA0)
      return -EBADMSG;
    DerCursor v = {content, content + len};
    const uint8_t* vi;
    uint16_t vlen;
    r = der_tlv(&v, &tag, &vlen, &vi);
    if (0 != r || tag != 0x02 || vlen != 1 || v.p != v.end)
      return -EBADMSG;
    version = vi[0];
    has_version = true;
  }

  /* serialNumber INTEGER(结构即可) */
  r = skip_tlv(&t);
  if (0 != r)
    return r;

  /* tbs 内 signatureAlgorithm:必须与外层一致 */
  const uint8_t* inner_oid;
  uint16_t inner_len;
  r = der_algorithm_id(&t, &inner_oid, &inner_len);
  if (0 != r)
    return r;
  if (inner_len != view->len_sigalg_oid || 0 != memcmp(inner_oid, der + view->off_sigalg_oid, inner_len))
    return -EBADMSG;

  /* issuer */
  const uint8_t* issuer;
  r = der_tlv(&t, &tag, &len, &issuer);
  if (0 != r || tag != 0x30)
    return -EBADMSG;
  view->off_issuer = static_cast<uint16_t>(issuer - der);
  view->len_issuer = len;

  /* validity SEQUENCE { notBefore Time, notAfter Time } */
  const uint8_t* validity;
  r = der_tlv(&t, &tag, &len, &validity);
  if (0 != r || tag != 0x30)
    return -EBADMSG;
  {
    DerCursor v = {validity, validity + len};
    const uint8_t* tb;
    uint16_t tbl;
    r = der_tlv(&v, &tag, &tbl, &tb);
    if (0 != r || (tag != 0x17 && tag != 0x18))
      return -EBADMSG;
    view->off_notbefore = static_cast<uint16_t>(tb - der);
    view->len_notbefore = tbl;
    const uint8_t* ta;
    r = der_tlv(&v, &tag, &tbl, &ta);
    if (0 != r || (tag != 0x17 && tag != 0x18) || v.p != v.end)
      return -EBADMSG;
    view->off_notafter = static_cast<uint16_t>(ta - der);
    view->len_notafter = tbl;
  }

  /* subject */
  const uint8_t* subject;
  r = der_tlv(&t, &tag, &len, &subject);
  if (0 != r || tag != 0x30)
    return -EBADMSG;
  view->off_subject = static_cast<uint16_t>(subject - der);
  view->len_subject = len;

  /* SPKI SEQUENCE { AlgorithmIdentifier, subjectPublicKey BIT STRING } */
  const uint8_t* spki;
  r = der_tlv(&t, &tag, &len, &spki);
  if (0 != r || tag != 0x30)
    return -EBADMSG;
  {
    DerCursor s = {spki, spki + len};
    const uint8_t* aid;
    uint16_t aid_len;
    r = der_tlv(&s, &tag, &aid_len, &aid);
    if (0 != r || tag != 0x30)
      return -EBADMSG;
    DerCursor ai = {aid, aid + aid_len};
    const uint8_t* aoid;
    uint16_t aoid_len;
    r = der_tlv(&ai, &tag, &aoid_len, &aoid);
    if (0 != r || tag != 0x06)
      return -EBADMSG;
    view->off_spki_alg_oid = static_cast<uint16_t>(aoid - der);
    view->len_spki_alg_oid = aoid_len;

    const uint8_t* keybits;
    uint16_t kb_len;
    r = der_tlv(&s, &tag, &kb_len, &keybits);
    if (0 != r || tag != 0x03 || s.p != s.end)
      return -EBADMSG;
    if (kb_len < 1 || keybits[0] != 0)
      return -EBADMSG;
    view->off_spki_pub = static_cast<uint16_t>(keybits + 1 - der);
    view->len_spki_pub = static_cast<uint16_t>(kb_len - 1);
  }

  /* issuerUID [1] / subjectUID [2](均可选, 直接跳过) */
  if (t.p < t.end && *t.p == 0x81) {
    r = skip_tlv(&t);
    if (0 != r)
      return r;
  }
  if (t.p < t.end && *t.p == 0x82) {
    r = skip_tlv(&t);
    if (0 != r)
      return r;
  }

  /* extensions [3] EXPLICIT(可选) */
  if (t.p < t.end && *t.p == 0xA3) {
    r = der_tlv(&t, &tag, &len, &content);
    if (0 != r || tag != 0xA3)
      return -EBADMSG;
    DerCursor e = {content, content + len};
    const uint8_t* exts;
    uint16_t exts_len;
    r = der_tlv(&e, &tag, &exts_len, &exts);
    if (0 != r || tag != 0x30 || e.p != e.end)
      return -EBADMSG;
    view->off_extensions = static_cast<uint16_t>(exts - der);
    view->len_extensions = exts_len;

    /* 计数 + 结构校验 */
    DerCursor w = {exts, exts + exts_len};
    while (w.p < w.end) {
      const uint8_t* ext;
      uint16_t ext_len;
      r = der_tlv(&w, &tag, &ext_len, &ext);
      if (0 != r || tag != 0x30)
        return -EBADMSG;
      DerCursor x = {ext, ext + ext_len};
      r = skip_tlv(&x); /* OID */
      if (0 != r)
        return r;
      if (x.p < x.end && *x.p == 0x01) { /* critical BOOLEAN DEFAULT FALSE */
        const uint8_t* bv;
        uint16_t bl;
        r = der_tlv(&x, &tag, &bl, &bv);
        if (0 != r || tag != 0x01 || bl != 1 || (bv[0] != 0x00 && bv[0] != 0xFF))
          return -EBADMSG; /* 严格 DER:TRUE 必须为 0xFF */
      }
      const uint8_t* ev;
      uint16_t el;
      r = der_tlv(&x, &tag, &el, &ev);
      if (0 != r || tag != 0x04 || x.p != x.end)
        return -EBADMSG;
      ++view->ext_count;
      if (view->ext_count == 0)
        return -E2BIG;
    }
  }

  /* 严格:v3 证书(带 extensions)必须显式给出 version=2 */
  if (view->ext_count != 0 && (!has_version || version != 2))
    return -EBADMSG;
  if (t.p != t.end)
    return -EBADMSG;
  if (top.p != top.end || c.p != c.end)
    return -EBADMSG; /* 尾随字节拒绝 */

  return 0;
}

/* ---- 时间检查 ---- */

int X509CheckTime(X509View* view, const uint8_t* der, size_t size, uint64_t now_epoch) {
  if (!view)
    return -EINVAL;
  view->time_flags = kX509TimeOK;

  int64_t nb = parse_time(der + view->off_notbefore, view->len_notbefore);
  int64_t na = parse_time(der + view->off_notafter, view->len_notafter);
  if (nb < 0 || na < 0) {
    view->time_flags = kX509TimeUnavailable;
    return 0;
  }

  if (static_cast<int64_t>(now_epoch) < nb)
    view->time_flags |= kX509TimeBefore;
  if (static_cast<int64_t>(now_epoch) > na)
    view->time_flags |= kX509TimeAfter;
  return 0;
}

/* ---- 扩展遍历 ---- */

int X509ExtNext(const X509View* view, const uint8_t* der, size_t size, X509Ext* out, uint8_t* iterator) {
  if (!view || !out || !iterator || 0 == view->ext_count)
    return 0;
  if (*iterator >= view->ext_count)
    return 0;

  uint8_t index = 0;
  DerCursor w = {der + view->off_extensions, der + view->off_extensions + view->len_extensions};
  while (w.p < w.end) {
    uint8_t tag;
    uint16_t len;
    const uint8_t* content;
    int r = der_tlv(&w, &tag, &len, &content);
    if (0 != r || tag != 0x30)
      return -EBADMSG;
    if (index == *iterator) {
      DerCursor x = {content, content + len};
      const uint8_t* oid;
      uint16_t oid_len;
      r = der_tlv(&x, &tag, &oid_len, &oid);
      if (0 != r || tag != 0x06)
        return -EBADMSG;
      out->off_oid = static_cast<uint16_t>(oid - der);
      out->len_oid = static_cast<uint8_t>(oid_len);
      out->critical = 0;
      if (x.p < x.end && *x.p == 0x01) {
        const uint8_t* bv;
        uint16_t bl;
        r = der_tlv(&x, &tag, &bl, &bv);
        if (0 != r || tag != 0x01 || bl != 1)
          return -EBADMSG;
        out->critical = (bv[0] == 0xFF) ? 1 : 0;
      }
      const uint8_t* ev;
      uint16_t el;
      r = der_tlv(&x, &tag, &el, &ev);
      if (0 != r || tag != 0x04)
        return -EBADMSG;
      out->off_value = static_cast<uint16_t>(ev - der);
      out->len_value = el;
      ++*iterator;
      return 1;
    }
    ++index;
  }
  return -EBADMSG;
}

/* ---- 验签 ---- */

/*! 按签名算法取摘要字节数(仅 RSA/P256 需本地哈希;SM2 摘要由硬件/宿主库按 GM/T 0003 内部计算)。
 *! 固件禁用 switch(会生成 rodata 跳表, 违反链接脚本 rodata 为空), 一律 if 链。 */
static int sig_digest_len(uint8_t sig_type) {
  if (kX509SigRSA_SHA384 == sig_type || kX509SigP256_SHA384 == sig_type)
    return Dongle::kX509DigestSHA384;
  if (kX509SigRSA_SHA512 == sig_type || kX509SigP256_SHA512 == sig_type)
    return Dongle::kX509DigestSHA512;
  return Dongle::kX509DigestSHA256;
}

/*! 计算 tbs 摘要:哈希上下文放 work[0..240), 摘要缓冲放 work[240..304), 不落栈;
 *! 三种 Sha*Ctx 均为 240B(同一 rlCryptoShaCtx), work 布局与算法无关。
 *! 成功返回 0(摘要经 out_md 传出, 长度由 sig_type 决定), work_size 不足返回 -ENOBUFS。 */
static int x509_hash_tbs(void* work, size_t work_size, uint8_t sig_type, const uint8_t* tbs, size_t len,
                         const uint8_t** out_md) {
  if (work_size < sizeof(Sha512Ctx) + Dongle::kX509DigestSHA512)
    return -ENOBUFS;
  uint8_t* base = static_cast<uint8_t*>(work);
  uint8_t* md = base + sizeof(Sha512Ctx);
  int dlen = sig_digest_len(sig_type);
  if (Dongle::kX509DigestSHA384 == dlen) {
    reinterpret_cast<Sha384Ctx*>(base)->Init().Update(tbs, len).Final(md);
  } else if (Dongle::kX509DigestSHA512 == dlen) {
    reinterpret_cast<Sha512Ctx*>(base)->Init().Update(tbs, len).Final(md);
  } else {
    reinterpret_cast<Sha256Ctx*>(base)->Init().Update(tbs, len).Final(md);
  }
  *out_md = md;
  return 0;
}

int X509VerifySignature(Dongle* dongle, const uint8_t* leaf, size_t leaf_size, const uint8_t* ca_cert,
                        size_t ca_cert_size, void* work, size_t work_size) {
  if (!dongle || !leaf || !ca_cert || !work)
    return -EINVAL;
  if (work_size < sizeof(Sha512Ctx) + Dongle::kX509DigestSHA512)
    return -ENOBUFS;

  X509View lv;
  X509View cv;
  int r = X509Parse(&lv, leaf, leaf_size);
  if (0 != r)
    return r;
  r = X509Parse(&cv, ca_cert, ca_cert_size);
  if (0 != r)
    return r;

  if (kX509SigRSA_SHA256 == lv.sig_type || kX509SigRSA_SHA384 == lv.sig_type || kX509SigRSA_SHA512 == lv.sig_type) {
    /* CA 的 SPKI 必须是 rsaEncryption */
    const uint8_t* ca_alg = ca_cert + cv.off_spki_alg_oid;
    if (!X509OID_RSAEncryption(ca_alg, cv.len_spki_alg_oid))
      return -EBADMSG;

    const uint8_t* n;
    size_t n_len;
    uint32_t e;
    r = spki_rsa(&cv, ca_cert, &n, &n_len, &e);
    if (0 != r)
      return r;

    const uint8_t* sig;
    r = sig_rsa(&lv, leaf, &sig);
    if (0 != r)
      return r;

    const uint8_t* md;
    r = x509_hash_tbs(work, work_size, lv.sig_type, leaf + lv.off_tbs, lv.len_tbs, &md);
    if (0 != r)
      return r;

    /* 设备端会就地覆写 signature 区域(rsa_pub 输入输出共用, master.cc 同款);
     * 证书本体在 InOutBuf 暂存区, 覆写无害;指针不指向 work(ExtendBuf) */
    return dongle->RSAVerifyPkcs1(2048, e, n, sig_digest_len(lv.sig_type), md, const_cast<uint8_t*>(sig));
  }

  if (kX509SigP256_SHA256 == lv.sig_type || kX509SigP256_SHA384 == lv.sig_type || kX509SigP256_SHA512 == lv.sig_type) {
    const uint8_t* ca_alg = ca_cert + cv.off_spki_alg_oid;
    if (!X509OID_ECPublicKey(ca_alg, cv.len_spki_alg_oid))
      return -EBADMSG;

    const uint8_t* x;
    const uint8_t* y;
    r = spki_ec(&cv, ca_cert, &x, &y);
    if (0 != r)
      return r;

    uint8_t rr[32];
    uint8_t ss[32];
    r = sig_ecdsa(&lv, leaf, rr, ss);
    if (0 != r)
      return r;

    const uint8_t* md;
    r = x509_hash_tbs(work, work_size, lv.sig_type, leaf + lv.off_tbs, lv.len_tbs, &md);
    if (0 != r)
      return r;

    if (0 != dongle->CheckPointOnCurvePrime256v1(x, y))
      return -EFAULT;
    /* FIPS 186-4 §6.4:SHA-384/512 摘要长于阶位宽(256), 取左 256 位作 e;
     * P256Verify 固定收 32B 摘要, md 的首 32B 即左 256 位 */
    return dongle->P256Verify(x, y, md, rr, ss);
  }

  if (kX509SigSM2_SM3 == lv.sig_type) {
    const uint8_t* ca_alg = ca_cert + cv.off_spki_alg_oid;
    if (!X509OID_ECPublicKey(ca_alg, cv.len_spki_alg_oid))
      return -EBADMSG;

    const uint8_t* x;
    const uint8_t* y;
    r = spki_ec(&cv, ca_cert, &x, &y);
    if (0 != r)
      return r;

    uint8_t rr[32];
    uint8_t ss[32];
    r = sig_ecdsa(&lv, leaf, rr, ss);
    if (0 != r)
      return r;

    if (0 != dongle->CheckPointOnCurveSM2(x, y))
      return -EFAULT;
    /* 设备 COS/TASSL 均按 GM/T 0003 内部计算 e = SM3(Z_A || M),
     * 此处传原始 tbsCertificate(指针在 InOutBuf, 不被 FTRX 暂存区影响) */
    return dongle->SM2VerifyMessage(x, y, leaf + lv.off_tbs, lv.len_tbs, rr, ss);
  }

  return -ENOTSUP;
}

int X509VerifySelfSigned(Dongle* dongle, const uint8_t* cert, size_t cert_size, void* work, size_t work_size) {
  if (!dongle || !cert)
    return -EINVAL;
  X509View view;
  int r = X509Parse(&view, cert, cert_size);
  if (0 != r)
    return r;
  if (view.len_issuer != view.len_subject || 0 != memcmp(cert + view.off_issuer, cert + view.off_subject, view.len_issuer))
    return -EBADMSG;
  return X509VerifySignature(dongle, cert, cert_size, cert, cert_size, work, work_size);
}

/* ---- 公钥提取 ---- */

int X509GetPublicKey(const uint8_t* der, size_t size, uint8_t* out, size_t* size_out, uint8_t* sig_type) {
  if (!der || !out || !size_out || !sig_type)
    return -EINVAL;
  X509View view;
  int r = X509Parse(&view, der, size);
  if (0 != r)
    return r;

  /* 按证书自身 SPKI 算法分派(与签名算法无关:叶证书密钥类型可与签发者签名算法不同) */
  const uint8_t* alg = der + view.off_spki_alg_oid;
  if (X509OID_RSAEncryption(alg, view.len_spki_alg_oid)) {
    const uint8_t* n;
    size_t n_len;
    uint32_t e;
    r = spki_rsa(&view, der, &n, &n_len, &e);
    if (0 != r)
      return r;
    /* 与 WorldPublic RSA 槽位同构: [e:uint32 LE][N:256B 大端] */
    out[0] = static_cast<uint8_t>(e);
    out[1] = static_cast<uint8_t>(e >> 8);
    out[2] = static_cast<uint8_t>(e >> 16);
    out[3] = static_cast<uint8_t>(e >> 24);
    memcpy(out + 4, n, 256);
    *size_out = 260;
  } else if (X509OID_ECPublicKey(alg, view.len_spki_alg_oid)) {
    const uint8_t* x;
    const uint8_t* y;
    r = spki_ec(&view, der, &x, &y);
    if (0 != r)
      return r;
    memcpy(out, x, 32);
    memcpy(out + 32, y, 32);
    *size_out = 64;
  } else {
    return -ENOTSUP;
  }

  *sig_type = view.sig_type;
  return 0;
}

}  // namespace dongle

AGINX_DECLARE_END

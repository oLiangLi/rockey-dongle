#pragma once

#ifndef __WTINC_DONGLE_SCRIPT_H__
#define __WTINC_DONGLE_SCRIPT_H__

#include "dongle.h"

#ifndef SIGQUIT
#define SIGQUIT 3
#endif /* SIGQUIT */

#ifndef SIGILL
#define SIGILL 4
#endif /* SIGILL  */

#ifndef SIGTRAP
#define SIGTRAP 5
#endif /* SIGTRAP */

#ifndef SIGSEGV
#define SIGSEGV 11
#endif /* SIGSEGV */

#ifndef SIGKILL
#define SIGKILL 9
#endif /* SIGKILL */

#ifndef SIGABRT
#define SIGABRT 6
#endif /* SIGABRT */

#ifndef SIGFPE
#define SIGFPE 8
#endif /* SIGFPE */

rLANG_DECLARE_MACHINE

/**
 *! v1.1
 */
#define rLANG_DONGLE_VERSION_MAJOR 1
#define rLANG_DONGLE_VERSION_MINOR 1

namespace dongle {
namespace script {

///
/// dongle.script.VM
///   0) 由于可用内存太小不支持子函数调用
///   1) op.code  定义为16位, 最大text.size定义为100*2==200字节
///   2) op.stack 定义为32位, op.stack的最大深度定义为16*4=64字节
///   3) data 段长度为1KB, 与输入输出共用
///
struct VM_t {
  VM_t(Dongle* dongle, void* data, void* buffer);

  VM_t(const VM_t&) = delete;
  VM_t& operator=(const VM_t&) = delete;

  int Initialize(const void* text, int szText, int szOut);
  int Execute();

  template <typename T>
  T LoadMM(int addr) {
    if (addr < 0 || addr >= kSizeData || addr % sizeof(T) != 0) {
      zero_ = SIGSEGV;
      return 0;
    }
    return (static_cast<T*>(data_))[addr / sizeof(T)];
  }

  template <typename T>
  int StoreMM(int addr, int32_t value) {
    if (addr < 0 || addr >= kSizeData || addr % sizeof(T) != 0)
      return zero_ = SIGSEGV;
    static_cast<T*>(data_)[addr / sizeof(T)] = value;
    return 0;
  }

  int OpLoadValue(int32_t value);
  int OpAddValue(int32_t value);
  void* OpCheckMM(int32_t addr, int32_t size);

  int OpFuncBasic(uint16_t op, int argc, int32_t argv[]);
  int OpFuncDataFile(uint16_t op, int argc, int32_t argv[]);
  int OpFuncRSA(uint16_t op, int argc, int32_t argv[]);
  int OpFuncP256(uint16_t op, int argc, int32_t argv[]);
  int OpFuncSM2(uint16_t op, int argc, int32_t argv[]);
  int OpFuncDigest(uint16_t op, int argc, int32_t argv[]);
  int OpFuncSM4(uint16_t op, int argc, int32_t argv[]);
  int OpFuncTDES(uint16_t op, int argc, int32_t argv[]);
  int OpFuncChaChaPoly(uint16_t op, int argc, int32_t argv[]);

  int OpSecp256k1(uint16_t op, int argc, int32_t argv[]);
  int OpCurve25519(uint16_t op, int argc, int32_t argv[]);
  int OpEd25519(uint16_t op, int argc, int32_t argv[]);

  static constexpr int kSizeData = 1024;
  static constexpr int kSizeCode = 100;
  static constexpr int kSizeStack = 16;
  static constexpr int kCyclesLimit = 0x01000000;
  static constexpr int kUserFileID = 1000; /* .LT. kUserFileID for Admin */

  /**
   *! KeyId == 1, 2, 3 的密钥正常用于签名, 从未导出私钥, 由于无法备份私钥, 不应该用于数据加密 ...
   */
  static constexpr int kKeyIdGlobalSM2ECDSA = 1;  /* SM2/PKI-Login/Local-Encrypt */
  static constexpr int kKeyIdGlobalP256ECDSA = 2; /* P256/PKI-Local-Admin */
  static constexpr int kKeyIdGlobalRSA2048 = 3;   /* RSA/PKI-Cloud-Login  */

  /**
   *! KeyId == 4 的SM2密钥, 正常只能用于加解密, 只有管理员权限允许用于签名 ...
   */
  static constexpr int kKeyIdGlobalSM2ECIES = 4; /* SM2/PKI-Encrypt/Text-Verify */

  uint16_t text_[kSizeCode];
  int32_t stack_[kSizeStack];
  Dongle* const dongle_;
  void* const data_;
  void* const buffer_;
  PERMISSION valid_permission_ = PERMISSION::kAnonymous;

  int zero_ = SIGABRT;
  int cycles_ = kCyclesLimit;
  uint16_t kSizeOutput = 0;
  uint8_t nstk_ = 0;
  uint8_t pc_ = 0;
};

/**
 *! 第一次运行脚本, 由于 RSA2048-MASTER-KEY (id=3) 未建立, ScriptText只能以明文进行调用 ...
 */
struct WorldCreateHeader {
  uint32_t zero_;
  uint32_t world_magic_;
  uint32_t create_magic_;
  uint32_t target_magic_;

  static constexpr uint32_t kMagicCreate = 0x0D214153;  // rLANG_DECLARE_MAGIC_Xs("CREAT");
  static constexpr uint32_t kMagicWorld = 0x5CF48C13;   // rLANG_DECLARE_MAGIC_Xs("WORLD");
};

rLANG_ABIREQUIRE(WorldCreateHeader::kMagicCreate == rLANG_DECLARE_MAGIC_Xs("CREAT"));
rLANG_ABIREQUIRE(WorldCreateHeader::kMagicWorld == rLANG_DECLARE_MAGIC_Xs("WORLD"));

/**
 *! 在主密钥生成以后, ScriptText 必须加密到 RSA2048-MASTER-KEY ...
 */
struct ScriptText {
  uint32_t file_magic_;  // if (file_magic_ == kAdminFileMagic) PERMISSION::kAdminstrator require ...
  uint8_t ver_major_;
  uint8_t ver_minor_;
  uint16_t size_public_;
  uint16_t script_[script::VM_t::kSizeCode];
  uint8_t nonce_[16];
  uint8_t check_[16];                                      // ChaCha20Poly.Open(data + check) ...
  static constexpr uint32_t kAdminFileMagic = 0x0443493B;  // rLANG_DECLARE_MAGIC_Xs("ADMIN");
};
rLANG_ABIREQUIRE(ScriptText::kAdminFileMagic == rLANG_DECLARE_MAGIC_Xs("ADMIN"));
rLANG_ABIREQUIRE(sizeof(WorldCreateHeader) == 16 && sizeof(ScriptText) == 240);

/**
 *! 全局的密钥信息保存在数据文件偏移 7KB 的位置, 大小为 1024 ...
 */
struct WorldPublic {
  struct Header {
    /*     0 */ uint32_t world_magic_;     // rLANG_WORLD_MAGIC
    /*     4 */ uint32_t category_magic_;  // rLANG_DECLARE_MAGIC_Xs("pub@k") || rLANG_DECLARE_MAGIC_Xs("adm@k")
    /*     8 */ uint32_t reserved_0_;      // Reserved, must == 0 ...
    /*    12 */ uint32_t reserved_1_;      // Reserved, must == 0 ...
    /*    16 */ uint8_t ver_major_;        // rLANG_DONGLE_VERSION_MAJOR ...
    /*    17 */ uint8_t ver_minor_;        // rLANG_DONGLE_VERSION_MINOR ...
    /*    18 */ uint16_t siz_public_;      // sizeof(WorldPublic) == 1024 ...
  };

  /*     0 */ Header header_;
  /*    20 */ uint8_t dongle_sm2ecdsa_pubkey_[64];
  /*    84 */ uint8_t dongle_secp256r1_pubkey_[64];
  /*   148 */ uint8_t dongle_rsa2048_pubkey_[260];
  /*   408 */ uint8_t dongle_sm2ecies_pubkey_[64];

  /*   472 */ uint8_t dongle_nonce_1_[32];  // Dongle choice 32B RandBytes ...
  /*   504 */ DONGLE_INFO dongle_info_;     // verify dongle device ...
  /*   544 */ uint8_t dongle_nonce_2_[32];  // Admin choice 32B RandBytes ...

  /*   576 */ uint8_t dongle_sm2ecies_sign_[64];   // sm2(4).sign(SM3(0...offsetof($$))) ...
  /*   640 */ uint8_t dongle_rsa2048_sign_[256];   // rsa(3).sign(SHA256(0...offsetof($$))) ...
  /*   896 */ uint8_t dongle_secp256r1_sign_[64];  // p256(2).sign(SHA256(0...offsetof($$))) ...
  /*   960 */ uint8_t dongle_sm2ecdsa_sign_[64];   // sm2(1).sign(SM3(0...offsetof($$))) ...

  /**
   *!
   */
  static constexpr uint32_t kCategoryHeaderMagicPublic = 0xC35880AF; // public domain ...
  static constexpr uint32_t kCategoryHeaderMagicAdmin = 0x864B40AF; // admin domain ...

  /**
   *! ... Dongle 全局状态(1024字节)保存在 &kData[kOffsetDataFile] ...
   */
  static constexpr size_t kOffsetDataFile = 7 * 1024;

  static constexpr int kFileSM2ECDSA = 1;
  static constexpr int kFileSECP256r1 = 2;
  static constexpr int kFileRSA2048 = 3;
  static constexpr int kFileSM2ECIES = 4;

  static constexpr size_t kOffsetPubkey_SM2ECDSA = 20;
  static constexpr size_t kOffsetPubkey_Secp256r1 = 84;
  static constexpr size_t kOffsetPubkey_RSA2048 = 148;
  static constexpr size_t kOffsetPubkey_SM2ECIES = 408;

  static constexpr size_t kOffsetDongleNonce1 = 472;
  static constexpr size_t kOffsetDongleInfo = 504;
  static constexpr size_t kOffsetDongleNonce2 = 544;

  static constexpr size_t kOffsetSign_SM2ECIES = 576;
  static constexpr size_t kOffsetSign_RSA2048 = 640;
  static constexpr size_t kOffsetSign_Secp256r1 = 896;
  static constexpr size_t kOffsetSign_SM2ECDSA = 960;
  static constexpr size_t kSizePublic = 1024;
};

rLANG_ABIREQUIRE(WorldPublic::kCategoryHeaderMagicPublic == rLANG_DECLARE_MAGIC_Xs("pub@k"));
rLANG_ABIREQUIRE(WorldPublic::kCategoryHeaderMagicAdmin == rLANG_DECLARE_MAGIC_Xs("adm@k"));

rLANG_ABIREQUIRE(WorldPublic::kFileSM2ECDSA == VM_t::kKeyIdGlobalSM2ECDSA);
rLANG_ABIREQUIRE(WorldPublic::kFileSECP256r1 == VM_t::kKeyIdGlobalP256ECDSA);
rLANG_ABIREQUIRE(WorldPublic::kFileRSA2048 == VM_t::kKeyIdGlobalRSA2048);
rLANG_ABIREQUIRE(WorldPublic::kFileSM2ECIES == VM_t::kKeyIdGlobalSM2ECIES);

rLANG_ABIREQUIRE(WorldPublic::kOffsetPubkey_SM2ECDSA == offsetof(WorldPublic, dongle_sm2ecdsa_pubkey_));
rLANG_ABIREQUIRE(WorldPublic::kOffsetPubkey_Secp256r1 == offsetof(WorldPublic, dongle_secp256r1_pubkey_));
rLANG_ABIREQUIRE(WorldPublic::kOffsetPubkey_RSA2048 == offsetof(WorldPublic, dongle_rsa2048_pubkey_));
rLANG_ABIREQUIRE(WorldPublic::kOffsetPubkey_SM2ECIES == offsetof(WorldPublic, dongle_sm2ecies_pubkey_));

rLANG_ABIREQUIRE(WorldPublic::kOffsetDongleNonce1 == offsetof(WorldPublic, dongle_nonce_1_));
rLANG_ABIREQUIRE(WorldPublic::kOffsetDongleInfo == offsetof(WorldPublic, dongle_info_));
rLANG_ABIREQUIRE(WorldPublic::kOffsetDongleNonce2 == offsetof(WorldPublic, dongle_nonce_2_));

rLANG_ABIREQUIRE(WorldPublic::kOffsetSign_SM2ECIES == offsetof(WorldPublic, dongle_sm2ecies_sign_));
rLANG_ABIREQUIRE(WorldPublic::kOffsetSign_RSA2048 == offsetof(WorldPublic, dongle_rsa2048_sign_));
rLANG_ABIREQUIRE(WorldPublic::kOffsetSign_Secp256r1 == offsetof(WorldPublic, dongle_secp256r1_sign_));
rLANG_ABIREQUIRE(WorldPublic::kOffsetSign_SM2ECDSA == offsetof(WorldPublic, dongle_sm2ecdsa_sign_));
rLANG_ABIREQUIRE(WorldPublic::kSizePublic == sizeof(WorldPublic) && 1024 == sizeof(WorldPublic));

/**
 *!
 */
rLANGEXPORT int rLANGAPI RockeyTrustExecutePrepare(VM_t& vm, void* InOutBuf /* 1024 */, void* ExtendBuf);

enum class OpCode : uint16_t {
  /**
   *! MASK: 0x0FFF
   */
  kLoadMUI = 0xF000,  // op.stack.push((op&0x0FFF) << 12)
  kAddMUI = 0xE000,   // op.stack.top += ((op&0x0FFF) << 12)

  kLoadUI = 0xD000,  // op.stack.push(op&0x0FFF)
  kLoadNI = 0xC000,  // op.stack.push(-1 - (op&0xFFF))
  kAddUI = 0xB000,   // op.stack.top += (op&0x0FFF)

  /**
   *! MASK: 0x03FF
   */
  kLoadI8 = 0xA000,    // op.stack.push(*(int8_t*)(op&0x3FF))
  kLoadU8 = 0xA400,    // op.stack.push(*(uint8_t*)(op&0x3FF))
  kLoadI16 = 0xA800,   // op.stack.push(*(int16_t*)(op&0x3FF))
  kLoadU16 = 0xAC00,   // op.stack.push(*(uint16_t*)(op&0x3FF))
  kLoadI32 = 0x9000,   // op.stack.push(*(int32_t*)(op&0x3FF))
  kStoreI8 = 0x9400,   // *(int8_t*)(op&0x3FF) = op.stack.pop
  kStoreI16 = 0x9800,  // *(int16_t*)(op&0x3FF) = op.stack.pop
  kStoreI32 = 0x9C00,  // *(int32_t*)(op&0x3FF) = op.stack.pop

  /**
   *! MASK: 0x00FF
   */
  kLoadHUI = 0x8000,  // op.stack.push((op&0xFF) << 24)
  kLoadMNI = 0x8100,  // op.stack.push((-1 - (op&0xFF) << 12)

  kJmp = 0x8200,   // pc += (int8_t)(op&0x00FF)
  kJmpF = 0x8300,  // if(!op.stack.pop) pc += (int8_t)(op&0x00FF)
  kJmpT = 0x8400,  // if(op.stack.pop) pc += (int8_t)(op&0x00FF)

  kSltI = 0x8500,  // op.stack.top = op.stack.top < (int8_t)(op & 0x00FF)
  kOrI = 0x8600,   // op.stack.top = op.stack.top | (int8_t)(op & 0x00FF)
  kXorI = 0x8700,  // op.stack.top = op.stack.top ^ (int8_t)(op & 0x00FF)
  kAndI = 0x8800,  // op.stack.top = op.stack.top & (int8_t)(op & 0x00FF)
  kSllI = 0x8900,  // op.stack.top = op.stack.top << (op&0x1F)
  kSrlI = 0x8a00,  // op.stack.top = op.stack.top >>> (op&0x1F)
  kSraI = 0x8b00,  // op.stack.top = op.stack.top >> (op&0x1F)
  kSubI = 0x8c00,  // op.stack.top = op.stack.top - (op&0x00FF)
  kMulI = 0x8d00,  // op.stack.top = op.stack.top * (int8_t)(op & 0x00FF)
  kDivI = 0x8e00,  // op.stack.top = op.stack.top / (int8_t)(op & 0x00FF)
  kModI = 0x8f00,  // op.stack.top = op.stack.top % (int8_t)(op & 0x00FF)

  /**
   *!
   */
  kInv = 0,      // abort()
  kDup = 0x0D,   // argc = 0, value = op.stack.top
  kNop = 0x0E,   // op.stack.pop(...argc), value = 0
  kExit = 0x0F,  // exit(argc ? argv[argc-1] : 0)

  /**
   *! argc == 1
   */
  kLoadXI8 = 0x10,  // value = *(int8_t*)(op.stack.pop)
  kLoadXU8,         // value = *(uint8_t*)(op.stack.pop)
  kLoadXI16,        // value = *(int16_t*)(op.stack.pop)
  kLoadXU16,        // value = *(uint16_t*)(op.stack.pop)
  kLoadXI32,        // value = *(int32_t*)(op.stack.pop)

  /**
   *! argc == 2
   */
  kStoreXI8,   // addr = op.stack.pop; *(int8_t*)addr  = value = op.stack.pop
  kStoreXI16,  // addr = op.stack.pop; *(int16_t*)addr = value = op.stack.pop
  kStoreXI32,  // addr = op.stack.pop; *(int32_t*)addr = value = op.stack.pop

  /**
   *! argc == 2
   */
  kEQ = 0x20,  // (a, b) = op.stack.pop(...2), value = (a == b)
  kNE,         // (a, b) = op.stack.pop(...2), value = (a != b)
  kLT,         // (a, b) = op.stack.pop(...2), value = (a <  b)
  kLE,         // (a, b) = op.stack.pop(...2), value = (a <= b)
  kGT,         // (a, b) = op.stack.pop(...2), value = (a >  b)
  kGE,         // (a, b) = op.stack.pop(...2), value = (a >= b)

  /**
   *! argc == 1
   */
  kNot,       // a = op.stack.pop, value = !value
  kBitNot,    // a = op.stack.pop, value = ~value
  kNegative,  // a = op.stack.pop, value = -value

  /**
   *! argc == 2
   */
  kAdd = 0x30,  // (a, b) = op.stack.pop(...2), value = (a + b)
  kSub,         // (a, b) = op.stack.pop(...2), value = (a - b)
  kMul,         // (a, b) = op.stack.pop(...2), value = (a * b)
  kDiv,         // (a, b) = op.stack.pop(...2), value = (a / b)
  kMod,         // (a, b) = op.stack.pop(...2), value = (a % b)
  kSll,         // (a, b) = op.stack.pop(...2), value = (a << b)
  kSrl,         // (a, b) = op.stack.pop(...2), value = (a >>> b)
  kSra,         // (a, b) = op.stack.pop(...2), value = (a >> b)
  kXor,         // (a, b) = op.stack.pop(...2), value = (a ^ b)
  kOr,          // (a, b) = op.stack.pop(...2), value = (a | b)
  kAnd,         // (a, b) = op.stack.pop(...2), value = (a & b)

  /**
   *!
   */
  kMemset = 0x40,  // argc : 3, value = memset(addr, value, size)
  kMemcpy,         // argc : 3, value = memcpy(addr, source, size)
  kMemcmp,         // argc : 3, value = memcmp(s1, s2, size)

  /**
   *!
   */
  kValidPINState = 0x100,  // argc : 0, value = ValidPINState()
  kRandBytes,              // argc : 2, value = RandBytes(addr : u8[bytes], bytes)
  kSecretBytes,            // argc : 1, value = SecretBytes(addr : u8[16])
  kReadDongleInfo,         // argc : 1, value = ReadDongleInfo(addr:DONGLE_INFO)
  kLEDControl,             // argc : 1, value = LEDControl(state:LED_STATE)
  kReadSharedMemory,       // argc : 1, value = ReadSharedMemory(buffer:u8[32])
  kWriteSharedMemory,      // argc : 1, value = WriteSharedMemory(buffer:u8[32])

  /**
   *!
   */
  kDeleteDataFile = 0x120,  // argc : 1, value = DeleteDataFile(id)
  kCreateDataFile,          // argc : 2...4, value = CreateDataFile(id, size, rPerm=kAnonymous, wPerm=kAnonymous)
  kWriteDataFile,           // argc : 4, value = WriteDataFile(id, offset, addr, size)
  kReadDataFile,            // argc : 4, value = ReadDataFile(id, offset, addr, size)

  /**
   *!
   */
  kDeleteRSAFile = 0x140,  // argc : 1, value = DeleteRSAFile(id)
  kCreateRSAFile,          // argc : 1...5, value = CreateRSAFile(id, [kAnonymous], [-1], global:false, logout:false)
  kGenerateRSA,            // argc : 2...3, value = GenerateRSA(id, pubkey[260], pkey[256]:nullptr)
  kImportRSA,              // argc : 3, value = ImportRSA(id, pubkey[260], pkey[256])
  kRSAPrivateDecrypt,      // argc : 2, value = RSAPrivateDecrypt(id, cipher_and_text[256])
  kRSAPrivateEncrypt,      // argc : 3, value = RSAPrivateEncrypt(id, buffer[len/256], len)
  kExRSAPrivateDecrypt,    // argc : 3, value = ExRSAPrivateDecrypt(public[260], private[256], cipher_and_text[256])
  kExRSAPrivateEncrypt,    // argc : 4, value = ExRSAPrivateEncrypt(public[260], private[256],buffer[len/256], len)
  kExRSAPublicEncrypt,     // argc : 3, value = ExRSAPublicEncrypt(public[260], buffer[len/256], len)
  kExRSAPublicDecrypt,     // argc : 2, value = ExRSAPublicDecrypt(public[260], buffer[256])

  /**
   *!
   */
  kDeleteP256File = 0x160,   // argc : 1, value = DeleteP256File(id)
  kCreateP256File,           // argc : 1...5, value = CreateP256File(id, [kAnonymous], [-1], global:false, logout:false)
  kGenerateP256,             // argc : 2...3, value = GenerateP256(id, pubkey[64], pkey[32]:nullptr)
  kImportP256,               // argc : 2, value = ImportP256(id, private[32])
  kP256Sign,                 // argc : 3, value = P256Sign(id, hash[32], sign[64])
  kExP256CheckPointOnCurve,  // argc : 1, value = ExP256CheckPointOnCurve(in_XY[64])
  kExP256DecompressPoint,    // argc : 3, value = ExP256DecompressPoint(yOdd, X[32], out_Y[32])
  kExP256ComputePubkey,      // argc : 2, value = ExP256ComputePubkey(private[32], out_XY[64])
  kExP256GenerateKeyPair,    // argc : 2, value = ExP256GenerateKeyPair(out_private[32], out_XY[64])
  kExP256Sign,               // argc : 3, value = ExP256Sign(private[32], hash[32], out_sign[64])
  kExP256Verify,             // argc : 3, value = ExP256Verify(hash, XY[64], sign[64])
  kExP256ComputeSecret,      // argc : 3, value = ExP256ComputeSecret(private[32], XY[64], out_secret[32])

  /**
   *!
   */
  kDeleteSM2File = 0x180,   // argc : 1, value = DeleteSM2File(id)
  kCreateSM2File,           // argc : 1...5, value = CreateSM2File(id, [kAnonymous], [-1], global:false, logout:false)
  kGenerateSM2,             // argc : 2...3, value = GenerateSM2(id, pubkey[64], pkey[32]:nullptr)
  kImportSM2,               // argc : 2, value = ImportSM2(id, pkey[32])
  kSM2Sign,                 // argc : 3, value = SM2Sign(id, hash[32], sign[64])
  kSM2Decrypt,              // argc : 3, value = SM2Decrypt(id, cipher_and_text[size], size)
  kExSM2CheckPointOnCurve,  // argc : 1, value = ExSM2CheckPointOnCurve(in_XY[64])
  kExSM2DecompressPoint,    // argc : 3, value = ExSM2DecompressPoint(yOdd, X[32], out_Y[32])
  kExSM2Sign,               // argc : 3, value = ExSM2Sign(private[32], hash[32], out_sign[64])
  kExSM2Verify,             // argc : 3, value = ExSM2Verify(hash, XY[64], sign[64])
  kExSM2Decrypt,            // argc : 3, value = ExSM2Decrypt(private[32], cipher_and_text[size], size)
  kExSM2Encrypt,            // argc : 3, value = ExSM2Encrypt(XY[64], text_and_cipher[size+96], size)

  /**
   *!
   */
  kDigestSHA1 = 0x1A0,  // argc : 3, value = DigestSHA1(input[len], len, out_digest[20])
  kDigestSM3,           // argc : 3, value = DigestSM3(input[len], len, out_digest[32])
  kExDigestSHA256,      // argc : 3, value = ExDigestSHA256(input[len], len, out_digest[32])
  kExDigestSHA384,      // argc : 3, value = ExDigestSHA384(input[len], len, out_digest[48])
  kExDigestSHA512,      // argc : 3, value = ExDigestSHA512(input[len], len, out_digest[64])

  /**
   *!
   */
  kDeleteSM4File = 0x1C0,  // argc : 1, value = DeleteSM4File(id)
  kCreateSM4File,          // argc : 1...2, value = CreateSM4File(id, perm=kAnonymous)
  kWriteSM4File,           // argc : 2, value = WriteSM4File(id, key[16])
  kSM4ECBEncrypt,          // argc : 3, value = SM4ECBEncrypt(id, buffer, size)
  kSM4ECBDecrypt,          // argc : 3, value = SM4ECBDecrypt(id, buffer, size)
  kExSM4ECBEncrypt,        // argc : 3, value = SM4ECBEncrypt(key[16], buffer, size)
  kExSM4ECBDecrypt,        // argc : 3, value = SM4ECBDecrypt(key[16], buffer, size)

  /**
   *!
   */
  kDeleteTDESFile = 0x1C8,  // argc : 1, value = DeleteTDESFile(id)
  kCreateTDESFile,          // argc : 1...2, value = CreateTDESFile(id, perm=kAnonymous)
  kWriteTDESFile,           // argc : 2, value = WriteTDESFile(id, key[16])
  kTDESECBEncrypt,          // argc : 3, value = TDESECBEncrypt(id, buffer, size)
  kTDESECBDecrypt,          // argc : 3, value = TDESECBDecrypt(id, buffer, size)
  kExTDESECBEncrypt,        // argc : 3, value = TDESECBEncrypt(key[16], buffer, size)
  kExTDESECBDecrypt,        // argc : 3, value = TDESECBDecrypt(key[16], buffer, size)

  /**
   *!
   */
  kExChaChaPolySeal = 0x1E0,  // argc : 4, value = ExChaChaPolySeal(key[32], nonce[12], buffer[len+16], len)
  kExChaChaPolyOpen,          // argc : 4, value = ExChaChaPolyOpen(key[32], nonce[12], buffer[len], len)

  /**
   *!
   */
  kExSecp256K1CheckPointOnCurve = 0x200,  // argc : 1, value = ExSecp256K1CheckPointOnCurve(XY[64])
  kExSecp256K1DecompressPoint,            // argc : 3, value = ExSecp256K1DecompressPoint(yOdd, X[32], out_Y[32])
  kExSecp256K1ComputePubkey,              // argc : 2, value = ExSecp256K1ComputePubkey(private[32], out_XY[64])
  kExSecp256K1GenerateKeyPair,            // argc : 2, value = ExSecp256K1GenerateKeyPair(out_private[32], out_XY[64])
  kExSecp256K1Sign,                       // argc : 3, value = ExSecp256K1Sign(private[32], hash[32], sign[64])
  kExSecp256K1Verify,                     // argc : 3, value = ExSecp256K1Verify(hash[32], XY[64], sign[64])
  kExSecp256K1ComputeSecret,              // argc : 3, value = ExSecp256K1ComputeSecret(private[32], XY[64], secret[32])

  /**
   *!
   */
  kExCurve25519ComputePubkey = 0x220,  // argc : 2, value = ExCurve25519ComputePubkey(private[32], out_pubkey[32])
  kExCurve25519GenerateKeyPair,        // argc : 2, value = ExCurve25519GenerateKeyPair(out_private[32], out_pubkey[32])
  kExCurve25519ComputeSecret,  // argc : 3, value = ExCurve25519ComputeSecret(private[32], pubkey[32], secret[32])

  /**
   *!
   */
  kExEd25519ComputePubkey = 0x230,  // argc : 2, value = ExEd25519ComputePubkey(private[32], out_pubkey[32])
  kExEd25519GenerateKeyPair,        // argc : 2, value = ExEd25519GenerateKeyPair(private[32], out_pubkey[32])
  kExEd25519Sign,                   // argc : 5, value = ExEd25519Sign(pubkey[32], pkey[32], m[len], len, sign[64])
  kExEd25519Verify,                 // argc : 4, value = ExEd25519Verify(pubkey[32], sign[64], m[len], len)
};

}  // namespace script
}  // namespace dongle

rLANG_DECLARE_END

#endif /* __WTINC_DONGLE_SCRIPT_H__ */

#pragma once

#ifndef __WTINC_DONGLE_APP_H__
#define __WTINC_DONGLE_APP_H__

#include <Interface/dongle.h>
#include <Interface/script.h>
#include <base/base.h>

rLANG_DECLARE_MACHINE

/**
 *! v1.1
 */
#define rLANG_DONGLE_VERSION_MAJOR 1
#define rLANG_DONGLE_VERSION_MINOR 1

namespace dongle {

/**
 *! 第一次运行脚本, 由于 RSA2048-MASTER-KEY 未建立, DongleScriptText只能以明文进行调用 ...
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
 *!
 */
struct DongleScriptText {
  uint32_t file_magic_;  // if (file_magic_ == kAdminFileMagic) PERMISSION::kAdminstrator require ...
  uint8_t ver_major_;
  uint8_t ver_minor_;
  uint16_t size_public_;
  uint16_t script_[script::VM_t::kSizeCode];
  uint8_t nonce_[16];
  uint8_t check_[16];                                      // ChaCha20Poly.Open(data + check) ...
  static constexpr uint32_t kAdminFileMagic = 0x0443493B;  // rLANG_DECLARE_MAGIC_Xs("ADMIN");
};
rLANG_ABIREQUIRE(240 == sizeof(DongleScriptText) && 16 == sizeof(WorldCreateHeader));
rLANG_ABIREQUIRE(DongleScriptText::kAdminFileMagic == rLANG_DECLARE_MAGIC_Xs("ADMIN"));

/**
 *!
 */
struct DonglePublicHeader {
  uint32_t world_magic_;     // rLANG_WORLD_MAGIC
  uint32_t category_magic_;  // rLANG_DECLARE_MAGIC_Xs("pub@k")
  uint32_t reserved_0_;      // Reserved, must == 0 ...
  uint32_t reserved_1_;      // Reserved, must == 0 ...
  uint8_t ver_major_;        // rLANG_DONGLE_VERSION_MAJOR ...
  uint8_t ver_minor_;        // rLANG_DONGLE_VERSION_MINOR ...
  uint16_t siz_public_;      // sizeof(DonglePublic) == 1024 ...

  static constexpr uint32_t kCategory_MAGIC = 0xC35880AF;  // rLANG_DECLARE_MAGIC_Xs("pub@k")
};
struct DonglePublic {
  DonglePublicHeader header_;

  /**! id=[1,2,3] 的三个私钥在dongle中生成, 从未导出私钥, 由于无法备份私钥, 通常不应该用于数据加密 */
  uint8_t dongle_sm2ecdsa_pubkey_[64];  // id == 1, pki-login, 在ukey中生成, 用于SM2签名证书, 也用于加密本地敏感信息 ...
  uint8_t dongle_secp256r1_pubkey_[64];  // id == 2, local admin authentication, 在ukey中生成, 用于本地管理员验证 ...
  uint8_t dongle_rsa2048_pubkey_[260];  // id == 3, cloud amdin login, 在ukey中生成, 用于云端登录的严格验证 ...

  /**! id=[4] 的私钥是从外部导入的, 通常只应该用于文件加密以及dongle本身的初始化和升级 */
  uint8_t dongle_sm2ecies_pubkey_[64];  // id == 4, efs-master-key, 理论上由外部导入, 用于SM2加密证书与 SM2(1)
                                        // 同时用于pki-login ... 同时用于加密云端保存的文件,
                                        // 运行时由该秘钥签名的代码具有管理员权限 ...
  uint8_t dongle_nonce_1_[32];        // Dongle choice 32 bytes RandBytes ...
  DONGLE_INFO dongle_info_;           // verify dongle device ...
  uint8_t dongle_nonce_2_[32];        // Admin choice 32 bytes RandBytes ...
  uint8_t dongle_sm2ecies_sign_[64];  // sm2(4).sign(SM3(0...offsetof($$))) ...

  /***/
  uint8_t dongle_rsa2048_sign_[256];   // rsa(3).sign(SHA256(0...offsetof($$))) ...
  uint8_t dongle_secp256r1_sign_[64];  // p256(2).sign(SHA256(0...offsetof($$))) ...
  uint8_t dongle_sm2ecdsa_sign_[64];   // sm2(1).sign(SM3(0...offsetof($$))) ...

  /**
   *! ... Dongle 全局状态(1024字节)保存在 &kData[kOffsetDonglePublic] ...
   */
  static constexpr size_t kOffsetDonglePublic = 7 * 1024;

  /**!*/
  static constexpr int kFileSM2ECDSA = 1;
  static constexpr int kFileSECP256r1 = 2;
  static constexpr int kFileRSA2048 = 3;
  static constexpr int kFileSM2ECIES = 4;

  /**!*/
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

/**! */
rLANG_ABIREQUIRE(DonglePublicHeader::kCategory_MAGIC == rLANG_DECLARE_MAGIC_Xs("pub@k"));

/**! */
rLANG_ABIREQUIRE(DonglePublic::kOffsetPubkey_SM2ECDSA == offsetof(DonglePublic, dongle_sm2ecdsa_pubkey_));
rLANG_ABIREQUIRE(DonglePublic::kOffsetPubkey_Secp256r1 == offsetof(DonglePublic, dongle_secp256r1_pubkey_));
rLANG_ABIREQUIRE(DonglePublic::kOffsetPubkey_RSA2048 == offsetof(DonglePublic, dongle_rsa2048_pubkey_));
rLANG_ABIREQUIRE(DonglePublic::kOffsetPubkey_SM2ECIES == offsetof(DonglePublic, dongle_sm2ecies_pubkey_));

rLANG_ABIREQUIRE(DonglePublic::kOffsetDongleNonce1 == offsetof(DonglePublic, dongle_nonce_1_));
rLANG_ABIREQUIRE(DonglePublic::kOffsetDongleInfo == offsetof(DonglePublic, dongle_info_));
rLANG_ABIREQUIRE(DonglePublic::kOffsetDongleNonce2 == offsetof(DonglePublic, dongle_nonce_2_));

rLANG_ABIREQUIRE(DonglePublic::kOffsetSign_SM2ECIES == offsetof(DonglePublic, dongle_sm2ecies_sign_));
rLANG_ABIREQUIRE(DonglePublic::kOffsetSign_RSA2048 == offsetof(DonglePublic, dongle_rsa2048_sign_));
rLANG_ABIREQUIRE(DonglePublic::kOffsetSign_Secp256r1 == offsetof(DonglePublic, dongle_secp256r1_sign_));
rLANG_ABIREQUIRE(DonglePublic::kOffsetSign_SM2ECDSA == offsetof(DonglePublic, dongle_sm2ecdsa_sign_));
rLANG_ABIREQUIRE(DonglePublic::kSizePublic == sizeof(DonglePublic));

}  // namespace dongle

rLANG_DECLARE_END

#endif /* __WTINC_DONGLE_APP_H__*/

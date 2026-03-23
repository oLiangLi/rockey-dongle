#include <base/base.h>

#include <Interface/dongle.h>
#include <Interface/script.h>

#include <openssl/ssl.h>
#include <new>
rLANG_DECLARE_MACHINE

namespace dongle {

rLANGWASMEXPORT size_t EmuSize() {
  return sizeof(Emulator);
}

rLANGWASMEXPORT Emulator* EmuNew(void* memory, PERMISSION permission) {
  return new (memory) Emulator(permission);
}

rLANGWASMEXPORT void EmuClear(Emulator* emu) {
  emu->~Emulator();
}

rLANGWASMEXPORT int EmuCreate(Emulator* emu, const uint8_t master_secret[64], uint32_t uid, int loop) {
  return emu->Create(master_secret, uid, loop);
}

rLANGWASMEXPORT int EmuOpen(Emulator* emu, const uint8_t master_secret[64], int loop) {
  return emu->Open("V", master_secret, loop);
}

rLANGWASMEXPORT int EmuClose(Emulator* emu) {
  return emu->Close();
}

rLANGWASMEXPORT int EmuWrite(Emulator* dongle) {
  return dongle->Write("V");
}

/**
 *!
 */
rLANGWASMEXPORT int EmuExecv(Dongle* dongle, uint8_t InOutBuf[1024]) {
  constexpr int kSizeExtend = 3 * 1024;
  uint64_t ExtendBuf[kSizeExtend / 8] = {0};

  script::VM_t vm(dongle, InOutBuf, &ExtendBuf[0]);
  int result = script::RockeyTrustExecutePrepare(vm, InOutBuf, ExtendBuf);

  if (0 == result)
    result = vm.Execute();
  memset(ExtendBuf, 0, sizeof(ExtendBuf));

  if (0 == result && vm.kSizeOutput < 1024) {
    dongle->RandBytes((uint8_t*)InOutBuf + vm.kSizeOutput, 1024 - vm.kSizeOutput);
  }

  if (0 != result) {
    memset(InOutBuf, 0, 1024);
  }

  return result;
}

rLANGWASMEXPORT int EmuGetDongleInfo(Dongle* dongle, DONGLE_INFO* info) {
  return dongle->GetDongleInfo(info);
}

rLANGWASMEXPORT int EmuGetPINState(Dongle* dongle, PERMISSION* state) {
  return dongle->GetPINState(state);
}

rLANGWASMEXPORT int EmuSetLEDState(Dongle* dongle, LED_STATE state) {
  return dongle->SetLEDState(state);
}

rLANGWASMEXPORT int EmuReadShareMemory(Dongle* dongle, uint8_t buffer[32]) {
  return dongle->ReadShareMemory(buffer);
}

rLANGWASMEXPORT int EmuWriteShareMemory(Dongle* dongle, const uint8_t buffer[32]) {
  return dongle->WriteShareMemory(buffer);
}

rLANGWASMEXPORT int EmuDeleteFile(Dongle* dongle, SECRET_STORAGE_TYPE type, int id) {
  return dongle->DeleteFile(type, id);
}

rLANGWASMEXPORT int EmuCreateDataFile(Dongle* dongle, int id, size_t size) {
  return dongle->CreateDataFile(id, size, PERMISSION::kAnonymous, PERMISSION::kAnonymous);
}

rLANGWASMEXPORT int EmuWriteDataFile(Dongle* dongle, int id, size_t offset, const void* buffer, size_t size) {
  return dongle->WriteDataFile(id, offset, buffer, size);
}

rLANGWASMEXPORT int EmuReadDataFile(Dongle* dongle, int id, size_t offset, void* buffer, size_t size) {
  return dongle->ReadDataFile(id, offset, buffer, size);
}

rLANGWASMEXPORT int EmuCreatePKEYFile(Dongle* dongle, SECRET_STORAGE_TYPE type, int bits, int id) {
  return dongle->CreatePKEYFile(type, bits, id);
}

rLANGWASMEXPORT int EmuGenerateRSA(Dongle* dongle, int id, uint32_t* modulus, uint8_t public_[], uint8_t* private_) {
  return dongle->GenerateRSA(id, modulus, public_, private_);
}

rLANGWASMEXPORT int EmuImportRSA(Dongle* dongle,
                                 int id,
                                 int bits,
                                 uint32_t modules,
                                 const uint8_t public_[],
                                 const uint8_t private_[]) {
  return dongle->ImportRSA(id, bits, modules, public_, private_);
}

rLANGWASMEXPORT int EmuGenerateP256(Dongle* dongle, int id, uint8_t X[32], uint8_t Y[32], uint8_t* private_) {
  return dongle->GenerateP256(id, X, Y, private_);
}

rLANGWASMEXPORT int EmuImportP256(Dongle* dongle, int id, const uint8_t K[32]) {
  return dongle->ImportP256(id, K);
}

rLANGWASMEXPORT int EmuGenerateSM2(Dongle* dongle, int id, uint8_t X[32], uint8_t Y[32], uint8_t* private_) {
  return dongle->GenerateSM2(id, X, Y, private_);
}

rLANGWASMEXPORT int EmuImportSM2(Dongle* dongle, int id, const uint8_t K[32]) {
  return dongle->ImportSM2(id, K);
}

rLANGWASMEXPORT int EmuCreateKeyFile(Dongle* dongle, int id, SECRET_STORAGE_TYPE type) {
  return dongle->CreateKeyFile(id, PERMISSION::kAnonymous, type);
}

rLANGWASMEXPORT int EmuWriteKeyFile(Dongle* dongle, int id, const void* buffer, size_t size, SECRET_STORAGE_TYPE type) {
  return dongle->WriteKeyFile(id, buffer, size, type);
}

rLANGWASMEXPORT int EmuRSAPrivate(Dongle* dongle,
                                  int id,
                                  uint8_t buffer[] /* length_is(*size_buffer), max_size(bits/8) */,
                                  size_t* size_buffer,
                                  bool encrypt) {
  return dongle->RSAPrivate(id, buffer, size_buffer, encrypt);
}

rLANGWASMEXPORT int EmuRSAPrivateEx(Dongle* dongle,
                                    int bits,
                                    uint32_t modules,
                                    const uint8_t public_[],
                                    const uint8_t private_[],
                                    uint8_t buffer[] /* length_is(*size_buffer), max_size(bits/8) */,
                                    size_t* size_buffer,
                                    bool encrypt) {
  return dongle->RSAPrivate(bits, modules, public_, private_, buffer, size_buffer, encrypt);
}

rLANGWASMEXPORT int EmuRSAPublic(Dongle* dongle,
                                 int bits,
                                 uint32_t modules,
                                 const uint8_t public_[],
                                 uint8_t buffer[] /* length_is(*size_buffer), max_size(bits/8) */,
                                 size_t* size_buffer,
                                 bool encrypt) {
  return dongle->RSAPublic(bits, modules, public_, buffer, size_buffer, encrypt);
}

rLANGWASMEXPORT int EmuP256Sign(Dongle* dongle, int id, const uint8_t hash[32], uint8_t R[32], uint8_t S[32]) {
  return dongle->P256Sign(id, hash, R, S);
}

rLANGWASMEXPORT int EmuP256SignEx(Dongle* dongle,
                                  const uint8_t private_[32],
                                  const uint8_t hash[32],
                                  uint8_t R[32],
                                  uint8_t S[32]) {
  return dongle->P256Sign(private_, hash, R, S);
}

rLANGWASMEXPORT int EmuP256Verify(Dongle* dongle,
                                  const uint8_t X[32],
                                  const uint8_t Y[32],
                                  const uint8_t hash[32],
                                  const uint8_t R[32],
                                  const uint8_t S[32]) {
  return dongle->P256Verify(X, Y, hash, R, S);
}

rLANGWASMEXPORT int EmuSM2Sign(Dongle* dongle, int id, const uint8_t hash[32], uint8_t R[32], uint8_t S[32]) {
  return dongle->SM2Sign(id, hash, R, S);
}

rLANGWASMEXPORT int EmuSM2SignEx(Dongle* dongle,
                                 const uint8_t private_[32],
                                 const uint8_t hash[32],
                                 uint8_t R[32],
                                 uint8_t S[32]) {
  return dongle->SM2Sign(private_, hash, R, S);
}

rLANGWASMEXPORT int EmuSM2Verify(Dongle* dongle,
                                 const uint8_t X[32],
                                 const uint8_t Y[32],
                                 const uint8_t hash[32],
                                 const uint8_t R[32],
                                 const uint8_t S[32]) {
  return dongle->SM2Verify(X, Y, hash, R, S);
}

rLANGWASMEXPORT int EmuSM2Decrypt(Dongle* dongle,
                                  int id,
                                  const uint8_t cipher[],
                                  size_t size_cipher,
                                  uint8_t text[],
                                  size_t* size_text) {
  return dongle->SM2Decrypt(id, cipher, size_cipher, text, size_text);
}

rLANGWASMEXPORT int EmuSM2DecryptEx(Dongle* dongle,
                                    const uint8_t private_[32],
                                    const uint8_t cipher[],
                                    size_t size_cipher,
                                    uint8_t text[],
                                    size_t* size_text) {
  return dongle->SM2Decrypt(private_, cipher, size_cipher, text, size_text);
}

rLANGWASMEXPORT int EmuSM2Encrypt(Dongle* dongle,
                                  const uint8_t X[32],
                                  const uint8_t Y[32],
                                  const uint8_t text[],
                                  size_t size_text,
                                  uint8_t cipher[]) {
  return dongle->SM2Encrypt(X, Y, text, size_text, cipher);
}

rLANGWASMEXPORT int EmuSM3(Dongle* dongle, const void* input, size_t size, uint8_t md[32]) {
  return dongle->SM3(input, size, md);
}

rLANGWASMEXPORT int EmuTDESECB(Dongle* dongle, int id, uint8_t* buffer, size_t size, bool encrypt) {
  return dongle->TDESECB(id, buffer, size, encrypt);
}

rLANGWASMEXPORT int EmuTDESECBEx(Dongle* dongle, const uint8_t key[16], uint8_t* buffer, size_t size, bool encrypt) {
  return dongle->TDESECB(key, buffer, size, encrypt);
}

rLANGWASMEXPORT int EmuSM4ECB(Dongle* dongle, int id, uint8_t* buffer, size_t size, bool encrypt) {
  return dongle->SM4ECB(id, buffer, size, encrypt);
}

rLANGWASMEXPORT int EmuSM4ECBEx(Dongle* dongle, const uint8_t key[16], uint8_t* buffer, size_t size, bool encrypt) {
  return dongle->SM4ECB(key, buffer, size, encrypt);
}

/**
 *! SM2
 */
rLANGWASMEXPORT int EmuCheckPointOnCurveSM2(Dongle* dongle, const uint8_t X[32], const uint8_t Y[32]) {
  return dongle->CheckPointOnCurveSM2(X, Y);
}

rLANGWASMEXPORT int EmuDecompressPointSM2(Dongle* dongle, uint8_t Y[32], const uint8_t X[32], bool Yodd) {
  return dongle->DecompressPointSM2(Y, X, Yodd);
}

/**
 *! P-256
 */
rLANGWASMEXPORT int EmuCheckPointOnCurvePrime256v1(Dongle* dongle, const uint8_t X[32], const uint8_t Y[32]) {
  return dongle->CheckPointOnCurvePrime256v1(X, Y);
}
rLANGWASMEXPORT int EmuDecompressPointPrime256v1(Dongle* dongle, uint8_t Y[32], const uint8_t X[32], bool Yodd) {
  return dongle->DecompressPointPrime256v1(Y, X, Yodd);
}
rLANGWASMEXPORT int EmuComputePubkeyPrime256v1(Dongle* dongle, uint8_t X[32], uint8_t Y[32], const uint8_t K[32]) {
  return dongle->ComputePubkeyPrime256v1(X, Y, K);
}
rLANGWASMEXPORT int EmuGenerateKeyPairPrime256v1(Dongle* dongle, uint8_t X[32], uint8_t Y[32], uint8_t K[32]) {
  return dongle->GenerateKeyPairPrime256v1(X, Y, K);
}
rLANGWASMEXPORT int EmuComputeSecretPrime256v1(Dongle* dongle,
                                               uint8_t secret[32],
                                               const uint8_t X[32],
                                               const uint8_t Y[32],
                                               const uint8_t K[32]) {
  return dongle->ComputeSecretPrime256v1(secret, X, Y, K);
}
rLANGWASMEXPORT int EmuSignMessagePrime256v1(Dongle* dongle,
                                             const uint8_t K[32],
                                             const uint8_t H[32],
                                             uint8_t R[32],
                                             uint8_t S[32]) {
  return dongle->SignMessagePrime256v1(K, H, R, S);
}
rLANGWASMEXPORT int EmuVerifySignPrime256v1(Dongle* dongle,
                                            const uint8_t X[32],
                                            const uint8_t Y[32],
                                            const uint8_t H[32],
                                            const uint8_t R[32],
                                            const uint8_t S[32]) {
  return dongle->VerifySignPrime256v1(X, Y, H, R, S);
}

/**
 *! Secp256k1
 */
rLANGWASMEXPORT int EmuCheckPointOnCurveSecp256k1(Dongle* dongle, const uint8_t X[32], const uint8_t Y[32]) {
  return dongle->CheckPointOnCurveSecp256k1(X, Y);
}
rLANGWASMEXPORT int EmuDecompressPointSecp256k1(Dongle* dongle, uint8_t Y[32], const uint8_t X[32], bool Yodd) {
  return dongle->DecompressPointSecp256k1(Y, X, Yodd);
}
rLANGWASMEXPORT int EmuComputePubkeySecp256k1(Dongle* dongle, uint8_t X[32], uint8_t Y[32], const uint8_t K[32]) {
  return dongle->ComputePubkeySecp256k1(X, Y, K);
}
rLANGWASMEXPORT int EmuGenerateKeyPairSecp256k1(Dongle* dongle, uint8_t X[32], uint8_t Y[32], uint8_t K[32]) {
  return dongle->GenerateKeyPairSecp256k1(X, Y, K);
}
rLANGWASMEXPORT int EmuComputeSecretSecp256k1(Dongle* dongle,
                                              uint8_t secret[32],
                                              const uint8_t X[32],
                                              const uint8_t Y[32],
                                              const uint8_t K[32]) {
  return dongle->ComputeSecretSecp256k1(secret, X, Y, K);
}
rLANGWASMEXPORT int EmuSignMessageSecp256k1(Dongle* dongle,
                                            const uint8_t K[32],
                                            const uint8_t H[32],
                                            uint8_t R[32],
                                            uint8_t S[32]) {
  return dongle->SignMessageSecp256k1(K, H, R, S);
}
rLANGWASMEXPORT int EmuVerifySignSecp256k1(Dongle* dongle,
                                           const uint8_t X[32],
                                           const uint8_t Y[32],
                                           const uint8_t H[32],
                                           const uint8_t R[32],
                                           const uint8_t S[32]) {
  return dongle->VerifySignSecp256k1(X, Y, H, R, S);
}

}  // namespace dongle

rLANG_DECLARE_END

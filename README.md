# Rockey-dongle 在 Rockey-ARM 上实现了一套常用的密码学套件, 可以在 dongle 中比较安全的执行自定义的代码

## Rockey-ARM 硬件支持的非对称加密算法

- RSA 最大支持我们也只使用 RSA2048
- Secp256r1 ECDSA, 不支持压缩格式
- SM2 ECDSA/ECIES, 不支持压缩格式(加密时好像没有检查公钥是否有效), 在移植 uECC 的时候顺便补齐了压缩格式的支持和有效性检查

## Rockey-ARM 硬件支持的对称加密算法

- TDES
- SM4

## Rockey-ARM 硬件支持的散列算法

- SHA1
- SM3

## 移植的额外支持的非对称加密算法, 额外移植的算法速度很慢, 应该优先使用硬件自带的

- X25519
- Ed25519, 由于 RockeyARM 可用内存略小, 有轻微的堆栈溢出而覆盖 InOutBuf 底部
- Secp256r1 ECDSA/ECDH, 支持压缩格式
- Secp256k1 ECDSA/ECDH, 支持压缩格式

## 移植的额外支持的对称加密算法, ROM 空间有点不够了, AES 就不加了

- CHACHA20/POLY1305

## 移植的额外支持的散列算法

- SHA256
- SHA384
- SHA512

## 剩下的工作

- 还有 10K 左右的空间, 实现一个自定义的简单脚本解释器用于执行自定义的代码

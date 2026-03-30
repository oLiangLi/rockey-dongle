# Rockey-dongle 在 Rockey-ARM 上实现了一套常用的密码学套件, 可以在 dongle 中比较安全的执行自定义的代码

## 如何编译程序 ...
- make -j8 && make foobar -j8 && make dongle -j8 && make wasm -j8 && npm run release ...
- 程序每次编译时都会使用一些私有的常数使得每次编译的版本是不兼容的 (特别是操作 MASTER_SECRET 时)...
- 不同版本的 jsCrypto.js 无法解密保存的 MASTER_SECRET, 如果模拟器需要依赖该功能, 一定记得保存生成模拟器时的 jsCrypto.js 文件 ...
- 刷入真实 RockeyARM 设备每次都应该刷入不同密码学常数的版本(每次都应该先 make dongle -j8 成功编译之后再写入固件) ...

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

## 实现了一个简单的脚本语言

- 不支持函数调用
- opstk 只有16个字大小
- 代码最多100个半字长度
- 当前的parse不支持 break, continue, switch...case


## 剩下的工作

- 更多的脚本单元测试 ...





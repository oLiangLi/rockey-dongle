# 这里记录整个 MKEY 的生成过程

## 生成系统初始化相关的 gpg 密钥对
- 在受信任的设备上运行:  gpg --generate-key && gpg --export -a > pubkey.asc
- 这次uKey初始化使用的 gpg 公钥保存为 mkey/cipher/pubkey.asc, id: 9F7E6E5B34545A7D1031A79BC489989197876293
- 之后的命令都在项目根目录下运行, 并 export PKEY=9F7E6E5B34545A7D1031A79BC489989197876293
- 生成的临时文件都存放在 .bin/arm-RockeyARM-native-release
```shell

export PKEY=9F7E6E5B34545A7D1031A79BC489989197876293

rm -rfv $MTEMP/*

```

## 生成64字节的种子码 sec.bin
```shell

##
## 生成64字节种子码, 并加密到 mkey/cipher/sec.asc
##
cat << XXEOF | node | gpg -e -a -r $PKEY | tee mkey/cipher/sec.asc
const fs = require('fs');
const crypto = require('crypto');
const mkey = crypto.getRandomValues(Buffer.alloc(64));
fs.writeFileSync(".bin/arm-RockeyARM-native-release/sec.bin", mkey);
process.stdout.write(mkey.toString('hex') + '\n');
XXEOF

##
## 查看生成的 sec.bin 文件并与 gpg 解密后的结果对比确认相符
##
node -e 'console.log(fs.readFileSync(".bin/arm-RockeyARM-native-release/sec.bin").toString("hex"))' && cat mkey/cipher/sec.asc | gpg -d

```



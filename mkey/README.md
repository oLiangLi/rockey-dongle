# 这里记录整个 MKEY 的生成过程

## 生成系统初始化相关的 gpg 密钥对
- 在受信任的设备上运行:  gpg --generate-key && gpg --export -a > pubkey.asc
- 这次uKey初始化使用的 gpg 公钥保存为 mkey/cipher/pubkey.asc, id: 9F7E6E5B34545A7D1031A79BC489989197876293
- 之后的命令都在项目根目录下运行, 并 export PKEY=9F7E6E5B34545A7D1031A79BC489989197876293
- 生成的临时文件都存放在 .bin/arm-RockeyARM-native-release
```shell

export PKEY=9F7E6E5B34545A7D1031A79BC489989197876293

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

## 初始化 K0, K1, K2, K3, 初始后删除sec.bin文件, 运行 Initialize.dongle 脚本, 生成基本参数记录
- 每次写入uKey前执行下列命令, 然后通过网页 factory 指令完成系统初始化 ...
``` shell

##
## 生成一个新的随机加密参数的 .bin/arm-RockeyARM-native-release/RockeyTrust.bin 文件
##
make dongle -j8

```
- jsEmulator: ffba338b-c54b3f6401f2d630, EnTrust: /7ozi8VLP2QB8tYw4s8BAOLLdMqnhYnT8Q1XcCjy2r1HLjBNIgsFd6uTQAZxWOyjVR3zqWImF0K0KZRasPS6xhWoqynsI8jBEaBXCFYtGIc=
- K0: 00000000-f9ea114b7e024e42, EnTrust: AAAAAPnqEUt+Ak5CTDOiADPTyfai9Vdi3aO91xrQBycOp4cIcyiD3NKj+A639xRDKtisH93ktfHbFRX9bsJpGgsQWIj3Ix4GM3YfmE72LTI=
- K1: 00000000-f96a124b7f024042, EnTrust: AAAAAPlqEkt/AkBCMW+0AJRYrfFxTRBrLjeIlf1jKU1GcnUqmCcnqsbaI1Vpu/a2yntJWjysoxPVLdult0XP6lXEATkZw2UenVlcIutWAmg=
- K2: 00000000-e886100b600b21a2, EnTrust: AAAAAOiGEAtgCyGiUnVEANVwFmadF1yHqknhoFUO6pfcTwETvJ1a8VkTV1mcJJL2NYyM5tKUQAjsXeagcUQttVdFgBPJfRdlBtP536Ab/0M=
- K3: 00000000-e886100b610b22a2, EnTrust: AAAAAOiGEAthCyKiHCTYAMKbOvdoXXEvr1mYIiCtSq08ZnPQRDt6Uh/gsBf5659G+62gQ+X3MtpcuexhmiY6DILkODMJivsSVZeK3yjwpq8=

## EnTrust 使用之上五组参数, 运行 EnTrust.dongle 脚本, 生成系统托管信息, 生成的参数记录
- jsEmulator: ffba338b-c54b3f6401f2d630
```json
[

{
  "category": 217369919,
  "SM2ECDSA": "4st0yqeFidPxDVdwKPLavUcuME0iCwV3q5NABnFY7KNVHfOpYiYXQrQplFqw9LrGFairKewjyMERoFcIVi0Yhw==",
  "P256ECDSA": "5zUgV1Dt3xUT8HL4FdW/TcDogIIBs2Pr1okkZG3ijP1trl5Wu0x9vrzTaip9NZ0rp3mJq9YFbfulujyEPIxkwA==",
  "RSA2048": "AQABALwA5rLZqOb5FpW8SjYdNGuixRiq8/IwHfIGPfoUxhtRW/iIXjqgTw/nzZRbvlzvHMIhXk71fMaUIfJ6DgkTF8EFurvvEpQMIIhRYHrnSQoD1G0rLB4PFJ5pTPdc9YPr/EIwA0eSNYI8EUg1e7G6ObB5RexmdvCVZDMRnK1ocr3T6i2KzULcir77IRytTs6FU9gKg9IEJIKMMmjezSS2xlEV2E94/4bT40Na7FSvN9lqdLmUWSocpiiKBM3sJ8PLYBh5bzHSwLLZH8GLH2vTObf0d/c2ZJr0tB9aAQrLpirN/6z0f9vI738hiP9X3n4h3NGDnGEKcNngQU4NsXiSpXE=",
  "SM2ECIES": "0C5gk5/kR+nZ1skUjtEv1sSntc8//G9PhXUgSh0Yq+uQ2Eyz4H3nPCO7ZYZG22tAbtqjrbkiBnK3nN8rcogb/Q==",
  "nonce_local": "m0CRoh+kBpCjGmr0kpPr7nRZqYxVZ97/81oAi/0r7NY=",
  "dongle": {
    "id": "ffba338b-c54b3f6401f2d630",
    "pid": "0xfb2b641d",
    "uid": "0x00010086",
    "type": "0x14d54c07",
    "birthday": "2026-03-31 05:36:23",
    "agent": "0xffffffff",
    "version": "0x00000101"
  },
  "nonce_admin": "NSMzFxSlm/0/LqyGOE2EKoiA44f6euFjxt6gdd+AfS4=",
  "EnTrust": [
    "e2cf01",
    "/7ozi8VLP2QB8tYw4s8BAOLLdMqnhYnT8Q1XcCjy2r1HLjBNIgsFd6uTQAZxWOyjVR3zqWImF0K0KZRasPS6xhWoqynsI8jBEaBXCFYtGIc="
  ]
},

[
  {
    "hid": "00000000-f9ea114b7e024e42",
    "kid": "4c33a2",
    "cipher": "lZgr9LEHWHjlsPrC/QHzZCPd78XXesw22xlGZ0OTq0y9bPSa8g0Px/GaxGMGSYCIwuFnTk9SvUc4297CxpzmYaoD0WeT38aDjmqQQvzkSGaYHfKUlvXmfcDfwQLmq6gznXQXnGlqnVtGdpEKyqp769zMvIMALuMb/oylMAt50pU="
  },
  {
    "hid": "00000000-f96a124b7f024042",
    "kid": "316fb4",
    "cipher": "D/62xZGC0iJMjr0hK6hsYt3AfGFFsmOknCQaXm0x8xb2y9rlz6V5icr2ELap5YI8srcaGiQY0DX9XbPQh1UjHRaw0RjundPEdn4IuKhviF2qpsRLVA9P8Mzn9up3DotkaTBZJe1uhmW0FAJlwA89MR0x4KXf9T1MDKvmHRCUd8k="
  },
  {
    "hid": "00000000-e886100b600b21a2",
    "kid": "527544",
    "cipher": "E8BkKk3d/cNKwHH5IvKOzJ1845afN3JomJiQ54Dt0YMSNi5nnCOUmziCOff7nU7b4XP70RAARh3bau+d1B24Y8T5NSjG73ozSVj24uEnqQWUclDXN73FQH1hGc+TaOqlpkRhR7+NTLm+HoRiJlHa+E5Q3L01te9ED6OVvl997TA="
  },
  {
    "hid": "00000000-e886100b610b22a2",
    "kid": "1c24d8",
    "cipher": "TTuUjNN11njTh7ybGUezl7yeJSsOniqiLfpDi5KUfCZkPlsP9ZhCIpWB9CoI3VOKxR1PSFkGFP67YRM7dVZyMlDzDPnmKacko/sNiHv2Dlgs4QM+6NX2DxSV1jH7pagj/XjlY409CwVfIoL/1OPsPuOyazONA+QSv78ksjUeAUI="
  },
  {
    "hid": "ffba338b-c54b3f6401f2d630",
    "kid": "e2cf01",
    "cipher": "Qifl2h2sT5XQqTpr2u8ecME0jj05rRdHjXNRvFX9NkRC1YrsTMiXzBtKDlRPgDxmmTpvBuGz8R0VkpQGz+T3wjTcb2fqgcdpVsg/V7KS7KQjPwhbrX/SkSP/Rg5pzzGD8OBq3Rq3sfhmUxEzipC8KX6XSXFZu7bNhI/7g6ByZUI="
  }
]

]

```

- K0: 00000000-f9ea114b7e024e42
```json
[
{
  "category": 217369919,
  "SM2ECDSA": "M9PJ9qL1V2Ldo73XGtAHJw6nhwhzKIPc0qP4Drf3FEMq2Kwf3eS18dsVFf1uwmkaCxBYiPcjHgYzdh+YTvYtMg==",
  "P256ECDSA": "KovHYYrngycPQBYNXh8R0Uw3s+aFmRwaN28nbCRlH2LQ5q0K5wxAlrWqR8aFc9nVv3AoJ1i3Eo8XD0jxXI0Q+A==",
  "RSA2048": "AQABANb3RG2af9Xy1gi+3pctFXTjikPbQJdIYKT4dHSreMwtfPrMhZkCKy/wMrXW+qbATJT/H0Nn4DHB+eNkdBGkIEEPQnjmM3TrnPqjuixrmQ1/+/BQ8Jx9vISZhgwiESKzpB4d8bpPrpYjSACsa6hq2esSOloR60gzpronrUnMI1iJ9gF7OS62Tv8kHecB2eacHaCjfkXhsFvbj77tLoO7n6s7oni59XGORG78Aw242BrPwNDAvv0lFdCnc0j+VmoOKlWR1p/2hDHjydFK9SBTEB6wl00B8PS/LwUJunNwa1wJgW/SxX2YRMBdoT/g/Koyoobm2epUScoOPh6fFnNO86E=",
  "SM2ECIES": "vktSA8UNryJfE1f8jeb0bOhLHMWzrcX68NQZ3nbSJSjN8C5lBxkXsNvS9NwrgaVyQqvwn374PMrgmD7PbjaWLw==",
  "nonce_local": "21FfztwxsDU7b6EhK5nlDQXl1T/iAgO2H3FNmIPUe70=",
  "dongle": {
    "id": "00000000-f9ea114b7e024e42",
    "pid": "0x4f1ea776",
    "uid": "0x00000000",
    "type": "0x000000ff",
    "birthday": "2024-11-26 17:57:35",
    "agent": "0xffffffff",
    "version": "0x00000222"
  },
  "nonce_admin": "NSMzFxSlm/0/LqyGOE2EKoiA44f6euFjxt6gdd+AfS4=",
  "EnTrust": [
    "4c33a2",
    "AAAAAPnqEUt+Ak5CTDOiADPTyfai9Vdi3aO91xrQBycOp4cIcyiD3NKj+A639xRDKtisH93ktfHbFRX9bsJpGgsQWIj3Ix4GM3YfmE72LTI="
  ]
},
[
  {
    "hid": "00000000-f9ea114b7e024e42",
    "kid": "4c33a2",
    "cipher": "9OkShRCzHGlHSXkXcYPcsEj/4VltqcyhcdW9Q7h0WqXeVjIHn9yRH9wwgunxJJt/jTYZJDyItRatRJb8e7Wmjg0o1mvGV6niaiHgrS+DEEUApHZ1XA9AacInwV9pWmy2RZesJlkmUaFReNUd5oVYg23EVJwoXHoUAUWRlmal8c8="
  },
  {
    "hid": "00000000-f96a124b7f024042",
    "kid": "316fb4",
    "cipher": "Kruw9CBBhKTzAaPSwxKcBxBVP9qTaWCrPOreZ+vCudMwt/O6Vo9vp36HDKJ4YuveDRzSulShPyOQFZ6Tf29QGZiAdMSUOQmyJDH+5p4iPRH/ce7LfhXcYL6iJ2743zekB89b1YfboucIVrlFkeXARadRsf1iRaLYrsqe1IpQDWA="
  },
  {
    "hid": "00000000-e886100b600b21a2",
    "kid": "527544",
    "cipher": "NjNqEqu4lbMKs22UMAGI5UBaAUxV/cejkBGRCVb+7abZnfif8M/TTEspicHgcRQ+VtGlc81BWWrj0iPqV97Fup2y+YXQmDo0PVVmjXYVNIv26U+ks0ZRjeQZb7PLiQB2cIhQ7J+zdYalZ1d1ZD44Rhsl/9LyjDQiND3gpbre6OE="
  },
  {
    "hid": "00000000-e886100b610b22a2",
    "kid": "1c24d8",
    "cipher": "u3RjcQoyR5wgRH3c4Tr22MGaSeatvFFndU3ywpy8jNNWq/qlBaZbJAEFmLeaWQhztOP7riBeURGxj4OHdC/qrMSJ414TMutUGKg1gd1eJ28FLIVC3OXWLsNBM0KoKgu0/Ztik7XT7DTUwM1qcdxYYUK5hR3ZymCA0HL4N3M/wLo="
  },
  {
    "hid": "ffba338b-c54b3f6401f2d630",
    "kid": "e2cf01",
    "cipher": "hybC+k9dGXcnue9dfBynfy5A/8+hJCSvKC1aDBFQg/AtlGN7Iy3TklAKZUcIX9NEVFMHFti2c2xRg3opbevWZ8mSBpJrqP/tw1X53ZRF7vUQCFU3X/NhJTT//PFE6HFdQHv86Kbhhc/r2FSRyBgDGUfVWN4FonxIv5WYN5fouQA="
  }
]
]
```

- K1: 00000000-f96a124b7f024042
```json
[
{
  "category": 217369919,
  "SM2ECDSA": "lFit8XFNEGsuN4iV/WMpTUZydSqYJyeqxtojVWm79rbKe0laPKyjE9Ut26W3Rc/qVcQBORnDZR6dWVwi61YCaA==",
  "P256ECDSA": "NzYCh9FJS+dNFJg4CSCDpnNPaUzCJqkTijvgHO4s6xkXvhofyoO0rgPEWsGzoB/gi0e67EAAwBXuE9R14e6B5g==",
  "RSA2048": "AQABAMgaLK/hPZZGcdeUTvzOn0t6EITTsnkVvAjJA392LDzjiYe/eVGGbhzJwZMbYqdU0DJx1/F+wcWwG5paEWTCL2rMpI9HiVK2Yr4Vwkx442g/h4DHyEoXhk6WdxtzCDJnovXeyep3Xwxw2CJ7EHdgKcpGLO+VADYLdKboiJS4CnyWM587KP84ARgnRYAew4yRRgToBVAowcyEXOHY/mUMmc+GfsGIolqsxE7s+nxBOEY77jGqRF7Wp6BbO/XwxnF08MSzMXVScSZb8zcbmDPonCi+YUF4bo8Yhlv/GpTG0RoN+XI2UhFb3A1iiU0WIFJL9MwAOYumTQLQ6rbGLL2OCNU=",
  "SM2ECIES": "SvWdnp4D+m7wtAvZ2r7SW7u2ju4DsDW8CQLQ0MMx+R3IxT6+iZe6fmkLj6jlXiWS4BTGistTbwZsjUWxIkkVzQ==",
  "nonce_local": "W9U2XEp4MSKKV17fhnmVfPlyTsmB7ZsI0CtVshXc81w=",
  "dongle": {
    "id": "00000000-f96a124b7f024042",
    "pid": "0x4f1ea776",
    "uid": "0x00000001",
    "type": "0x000000ff",
    "birthday": "2024-11-26 17:57:36",
    "agent": "0xffffffff",
    "version": "0x00000222"
  },
  "nonce_admin": "NSMzFxSlm/0/LqyGOE2EKoiA44f6euFjxt6gdd+AfS4=",
  "EnTrust": [
    "316fb4",
    "AAAAAPlqEkt/AkBCMW+0AJRYrfFxTRBrLjeIlf1jKU1GcnUqmCcnqsbaI1Vpu/a2yntJWjysoxPVLdult0XP6lXEATkZw2UenVlcIutWAmg="
  ]
},

[
  {
    "hid": "00000000-f9ea114b7e024e42",
    "kid": "4c33a2",
    "cipher": "84zY0goUxEdx72gIhQLLaPwCZ1zDO8LfMno05wvWqdL8wzUhyUEbjj7bVJjjGEPR4h0lsc8PA2Vfj53THDl48NOkcj9WGqXtrK51Bq+B+qbCIoGeLvX5TQN685Yn6wpcYGIj8QyZ182U2HdF3BdgUM3OXNOTeqYKxsoMyqbYYB8="
  },
  {
    "hid": "00000000-f96a124b7f024042",
    "kid": "316fb4",
    "cipher": "OxV4jhpl6+Jj/CEm7/OjbhSWIY0+nAr6/Nui75Iek0sGiOQXHfZIo3sHdEkYypvsc1xxkxCRCqUUV9g//31LhfIlSdcQ5Bv7tJ+BW2rf74E1qH48n5r+whkfnBj3cpqDELvz4lfsuD4fLj9FJtFDuztcziiXwFIcRXElipOONAE="
  },
  {
    "hid": "00000000-e886100b600b21a2",
    "kid": "527544",
    "cipher": "85atxWIZ4i6qE0gE+PgtiNPLiEAsAQ+2Fv9ThwewOHRwSX9oVWgcOJfZVDxcd3G2wkmmZCRt//jd3IJFe7Wc373zuiCNvpgjNZRfMdysdOxgLJF4K0lwE9R5zfwrFkfHQh8aqo9ZvJnTgqiPWXYtwRd9Yf9/X9JRJkvI5YT1+J0="
  },
  {
    "hid": "00000000-e886100b610b22a2",
    "kid": "1c24d8",
    "cipher": "yhDsT/CZkRGchX30PMq1PQr5fVEeMUACTt2wNhYANQ9oZIa7oUeZBsy/9R/MN7mz2/rSml4AvSxWXJo/4fCTDZJsPyZ10cD+7Y7sPO7DJdiS/AX+tO8Nd9lmBIOeNtnrvqWEYTCkzNyv0PDcZnGZr+SW5YM0kDtEEB3fvPo25uM="
  },
  {
    "hid": "ffba338b-c54b3f6401f2d630",
    "kid": "e2cf01",
    "cipher": "IvtPOyQy5W4lJewRZCF22LvhYeKvuQT50teYdGHR5Youm20wYXGV8KpMMtKJWPHazGBLLXyFYzqOaUJFznRW9bdL0Mu7YFsoVo9BEe2xvkY2r6UQ/gbkeFafx/91Lb2Qu+ap1aXmQ3SsuyabCopKW4V2wcpW4qR+AjEav30zRnk="
  }
]
]
```

- K2: 00000000-e886100b600b21a2
```json
[
{
  "category": 217369919,
  "SM2ECDSA": "1XAWZp0XXIeqSeGgVQ7ql9xPARO8nVrxWRNXWZwkkvY1jIzm0pRACOxd5qBxRC21V0WAE8l9F2UG0/nfoBv/Qw==",
  "P256ECDSA": "18q5r77HTAtWT7tXJs9nbBhF+hOrywLzSAmIzbq+xNWi3+tbe+61MD14Sv5WsL+1Q7dt/cpVIi1avqkPJxS3/Q==",
  "RSA2048": "AQABAMPvcShiRpKqXqiMJlcGX0jB2WUteA44NpSOo7guM8hk0DGgzmxO+D/vcqdxvC8TbKMmaNtJ6y58zBUNgVAcyCg2hCGckofzmGsI5tFITuqWqKE4dX7vrOJFdqdiwwYNnoisjiyCoDqX0HSXmMi0LaX5xhslaeZwINnMyTUwQZEM6ln5g8BzC+2EbxL1XzixI7Q48fzz6QkTRHwKPO9US3uDluiV9yI6yxEu18QTyaqWBujr/lQTqw5NnzPvkxBqnSj1Pb6G0dCgcqtsuKj65KFrYKcK7HE5dKknH5X0XcpDdkazC2mTwEYl2VvvBr+UGyxH5qRjIAJDUsgfkATKeAM=",
  "SM2ECIES": "2VqrOjtQGsZR2ZeYHcbNCkY16FzoGKCW6vruTyhY/LnJEGAdcp+jlnrTe8zq7yHyz8IOInFtcDdk9ewGPqmZZA==",
  "nonce_local": "BK/EEnqGYoFnclV/4UpW7r6u9pmYufXPuRvpfcB/pCE=",
  "dongle": {
    "id": "00000000-e886100b600b21a2",
    "pid": "0x4f1ea776",
    "uid": "0x00000002",
    "type": "0x000000ff",
    "birthday": "2024-11-01 09:40:33",
    "agent": "0xffffffff",
    "version": "0x00000222"
  },
  "nonce_admin": "NSMzFxSlm/0/LqyGOE2EKoiA44f6euFjxt6gdd+AfS4=",
  "EnTrust": [
    "527544",
    "AAAAAOiGEAtgCyGiUnVEANVwFmadF1yHqknhoFUO6pfcTwETvJ1a8VkTV1mcJJL2NYyM5tKUQAjsXeagcUQttVdFgBPJfRdlBtP536Ab/0M="
  ]
},
[
  {
    "hid": "00000000-f9ea114b7e024e42",
    "kid": "4c33a2",
    "cipher": "3/wh0vtAdmp/hktK68R2G/buG+dzspJTHVhHGZj6TXdS2Iq9Jgvci30tkMMyYq8tBRTf6J8BCC+4qHUVfq/DX3Lw815sWZV6VQ/wiUc3pSqDIqJMqctj6BeHyvCeljGbK+vlwrO3PMEnpvuoxySSwTx+5RrQkSKj5ydzaf5G7cw="
  },
  {
    "hid": "00000000-f96a124b7f024042",
    "kid": "316fb4",
    "cipher": "FgLgj+3fHh4AgwizOQdwTsleGe5KsRMJISHsduPM57hNifSh+w9DsnwquNAM1bQISGu7/39KWnXcxRKx40S0lMLZwWUhb/ItsH2jUCDP8g7WXb9+SRAtBaWsOwO9UkXwSXracBRwWeDIBldKfOAi/0DjX5hZtRTFcs32vLDaS8E="
  },
  {
    "hid": "00000000-e886100b600b21a2",
    "kid": "527544",
    "cipher": "bXPVxuFs8OtQGkMzRGFdxp8NfFZfODLpt4NXj3JvXoTEmZJxoCdf13rJz9cUbl3RmQ7QTK4dZXuVnlGcQ0OwOmPHxE0L6HK4NP4s5dKO6+RFkPGv+Tw0HD5EsXWC7yioGXda+/LzUx0fGkusmKlf/fZLr8/oV+1ZH43xvHElf0I="
  },
  {
    "hid": "00000000-e886100b610b22a2",
    "kid": "1c24d8",
    "cipher": "qZWDElmxKV/ShWXA4jw6D7R0Hx1fYn6od17ZLn7go9lUlHGR1tUy0I/MfSPexs4LDX2CrFy2mRl1HfjuR4Iwoo7rFpvU9yBwVj+ecjdTscWO2XKN91CrG1yNibjgjgCyDaRI74UHyQXzJ1MNVZUwvYmuAa6IqYibghIlMkhiqt0="
  },
  {
    "hid": "ffba338b-c54b3f6401f2d630",
    "kid": "e2cf01",
    "cipher": "iBTnDsidCPmKD70TOaO6LEKchXrk9FJncXl+4dZ5ByDzlW72PLmtJBZi4gfXkG3toHCwPYmZegbqvkn0ewqZkTZdnRbs4gPb8FNwUmPbFkR3HnS1GsVPHv8wX8d3/4zn5S+mDemG0C9Wdwo3sNDnzWoV3QynHzaLL7+AvE3Jf54="
  }
]
]
```

- K3: 00000000-e886100b610b22a2
```json
[
{
  "category": 217369919,
  "SM2ECDSA": "wps692hdcS+vWZgiIK1KrTxmc9BEO3pSH+CwF/nrn0b7raBD5fcy2ly57GGaJjoMguQ4MwmK+xJVl4rfKPCmrw==",
  "P256ECDSA": "I8os43HEi/cjaX+jj35Le8rKcAxvzTff9bloJALCC54eupnc+BNptnhhHtNPXVd/Wx4Di1RWzpfc92BQXCUrvA==",
  "RSA2048": "AQABAJJ3B+UTXwQoGqbI67SXUQ+c8uBZI/kX0XFdj4lmQ/oWqBzqI68GhzqI82LbFBx1inBz5yBAL5d7genOmyL067MrZFRdTcfNMYBJTVUYlxdcv16E5rBk4MNFopj0pOaWAHA4c8mgw9zyRf6LSJvkN3HXUo0qDvs2+njY1K38T/CjjFTR0SFUo0ids5lSkjmctXzkXfJvqH9kE06gHeMfQNXj3zDP7QZVhF0FwXylBJ2yorQfUFR9ZkU6lvq4BlXBZrjCC2kWxEAaFFhyt9RQcI0msVwgt5s+rl8JKE1bXzcRegY80dXJS/ayVP/t0XQsH7OdlXSI3mG7uqiKkkMRIYc=",
  "SM2ECIES": "iBHNmRpHM1zhLwYfWW83T5BxR/uOWWyIt5WocqalQeasD6RsV2HjAaNIsBzeO+ZlgNKSVeHBSaYaCM7V2iyxwg==",
  "nonce_local": "9mL6LtDVYdtzS0sG6PJwb3Im4BSX1m6lTqtvPhoojH4=",
  "dongle": {
    "id": "00000000-e886100b610b22a2",
    "pid": "0x4f1ea776",
    "uid": "0x00000003",
    "type": "0x000000ff",
    "birthday": "2024-11-01 09:40:33",
    "agent": "0xffffffff",
    "version": "0x00000222"
  },
  "nonce_admin": "NSMzFxSlm/0/LqyGOE2EKoiA44f6euFjxt6gdd+AfS4=",
  "EnTrust": [
    "1c24d8",
    "AAAAAOiGEAthCyKiHCTYAMKbOvdoXXEvr1mYIiCtSq08ZnPQRDt6Uh/gsBf5659G+62gQ+X3MtpcuexhmiY6DILkODMJivsSVZeK3yjwpq8="
  ]
},
[
  {
    "hid": "00000000-f9ea114b7e024e42",
    "kid": "4c33a2",
    "cipher": "Unr6wA63dOGdPXPRo5+LTJMrksSPEQ0S8tfHVNMQlZezTJ25335Cb+oug0y187KvAF1SHAYNt6IpKGksn7n6UX3jyOLlJ7LIqKp39Ebj9ZGT4n7bh5LcciaZkurKTR9LyDtTudB0ocaeh+nGFibSLvtqHF88mASrgduaGDqKfgA="
  },
  {
    "hid": "00000000-f96a124b7f024042",
    "kid": "316fb4",
    "cipher": "yYAFkZuh8gDkTSRAnTAUuskYLgCGvi48zuVr2+bTR86yOgNQRT2w0eDtMbeHWAvoWxlKSBGNESPOnStDkoG8ZpZTourLtJ90ceRqf2/uWf54pAqLhmz7o7luL+XVCW6ES9fzYQgsJiwqXecWnvMFmA8rRaFZPVolOTSjHXiV/gg="
  },
  {
    "hid": "00000000-e886100b600b21a2",
    "kid": "527544",
    "cipher": "VZuzeq0JfGcxTssOJVhHrjEqepAPjeUNcwt2Na5CklPAnx85AxstZdjZJ4so/4QKaXAbcwdwwM3gDEyRtGlzYzqLXfRgVIgUZ7spkcaof4GH8CX8/9VQpatNzVg6T7e9gi+hc0stuBiSPCHMbNyxnwGhF8d+Y7iyPpJGqSjsZYY="
  },
  {
    "hid": "00000000-e886100b610b22a2",
    "kid": "1c24d8",
    "cipher": "w1Zq51NZ285YcHWjtdh7Ku4W6Ie3q0AsSHr573Vp+byXOYXBF/LuECyhNfa0QP4Ri7EKA97UFwKW/FcCyiPvZfD5OnsGgX3X7AyQJmHbEv/HSh/L9h04yKOZlQBTMRxtPJaYCIB5ns4fstz9u4nZER7ljrBHnYvXJsxWV6d5Nmg="
  },
  {
    "hid": "ffba338b-c54b3f6401f2d630",
    "kid": "e2cf01",
    "cipher": "T3I+EaeiiBYRxHWT6Y9IiQsc+Z3/DkYZ520cBomJkFvsuR5GR4bBFdn0lUzz4l7CLvA5EDY2/ud+TBGzYIV7XpWE+FjI4wWr4sEwm4vCwFxu/kQPy/6ngLdfPhTGZFJ9CgTibQbDQc43G459V7BC5cVap58hkFMg86SgO6cH4ik="
  }
]
]
```

## 准备导出 MASTER_SECRET, 运行脚本 MasterExport.dongle 脚本
- K0: 00000000-f9ea114b7e024e42
```json
{
  "rLANG_Ed25519_Pubkey": "wEEFasc+9erXEUDt9zY/3TyIy203NRO+3+mPT3NRIrQ=",
  "rLANG__X25519_Pubkey": "WldXwpzbk1Apg+dvzyzXWgPDbd28nz4Xc+dpeZOW42w=",
  "rLANG_Ed25519_SIGN": "bwvOfmgZhC370rvGeGtZcfw3THuuw/tRZTwQacMrrYKNlm/ncU9fJ1FgX8sKJvYQV79FpWBmDdS0kmnpNm9vAg=="
}
```

- K1: 00000000-f96a124b7f024042
```json
{
  "rLANG_Ed25519_Pubkey": "XM3tm65cS8ikzwxftrR3vS5PtuDHHLr2RzvzTi46z7c=",
  "rLANG__X25519_Pubkey": "dcpbK4i+7j9faWwmkMBJvu5VwsTCmGf+ehkk6hvPIFc=",
  "rLANG_Ed25519_SIGN": "P8SLo+ZjlNj86OXiLitOE9PuC3xD4qSqfTBO7qDPM1W0H59JP87JGD+fcp6kOS0GG58tUSUaFHi+ml9S3egJAw=="
}
```

- K2: 00000000-e886100b600b21a2
```json
{
  "rLANG_Ed25519_Pubkey": "2uX5SaW7O5q6PF3BFJkjsRRPxfhFbKY7av6OYP6k77Q=",
  "rLANG__X25519_Pubkey": "4Kd6n5KFYxhK4Ea+bgEUM1aphYwPQAp/gKIeBp0Aghw=",
  "rLANG_Ed25519_SIGN": "mOGMKpMPfbPdCagvALg483PFH0KymdX0tPN5TTeB2SbZGsjqOCiLcD4AGJ4Dz4yr5pkqkE9kcaq/giDjT/a0DQ=="
}
```

- K3: 00000000-e886100b610b22a2
```json
{
  "rLANG_Ed25519_Pubkey": "0p4TKclxlQUSfT7+9pUCUmVxuywMoDd6Rc26z1vBXc0=",
  "rLANG__X25519_Pubkey": "pOWet7H9rIn7xLxLobU0OTlq1zHzYuX58JPGYhz00g0=",
  "rLANG_Ed25519_SIGN": "fP9eMxBuGyhM0mhF+nNB7877MA7Yc3zWWDjLwsoUScEAjoWV4k0NR2x29H5n+mCjqxwlbD5yYU+zGzGJQThJAw=="
}
```

## 验证 jsEmulator 是否能够代理执行uKey相关的Admin脚本, Admin模式执行HelloWorld.dongle, 测试通过后锁定 K0/K1/K2/K3

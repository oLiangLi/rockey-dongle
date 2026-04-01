## E0 初始化过程

- 生成新的 sec.bin 和固件 RockeyTrust.bin, 并使用factory初始化uKey 
- 执行 mkey/signed-script/Bootstrap/Bootstrap-INIT-0x10000-747a7d077f1a-2026-04-01T02_16_16.047Z.dongle.program
- 执行 mkey/signed-script/Bootstrap/Bootstrap-EnTrust-LiangLI-ed37a18e36b4-2026-04-01T02_18_23.548Z.dongle.program
- 执行 lock 锁定uKey ...
- 初始化完成后系统参数为:
```json
[
 {
  "category": 3277357231,
  "SM2ECDSA": "WMAfChO+8ghubljWzhalCwdiZVeS1kbJbQbBRN+dWQVeIlPTrgIfeQJG/4Pb3N3DfOi3p9moLueH8jXeWUAzgw==",
  "P256ECDSA": "mxbyH3os1zU6GA6UPI9Kg6BI9LCfjgXmPmOPMd8y9NK/0T3RNcUkBgl12te5bQJu5OIH8NB8t/g7ODXcEnucig==",
  "RSA2048": "AQABALrZZUaFvc67vEIB7PVxLrKxxiWOYkT9OiSXcyNTw7Rb8owMrOYapRUgqsHv4LRRO6dpsvk5LnEC7Ja5fb7xK6g52ZqdL+Z7QMHyD6Vk6vQZYHB/nK98q+fgbooN2Wy/iExCJQhMOD1QmtIaetBfJs3C63TnA4AT3iCcSebTjWkg/mfxvZs57WmLnnabnc/E0321nSSKaYbqvljH/UJGOBzieq11PbKD9XtWULmePz1CJHiE7rqijJtlrznrWcQHAWq2s6MiydBGEp1ZaTgYVnrANgYvGb4iIhBj4GPKpCZ3+qeYGKYEaC5fvASgpOhD5q4YjtEZHAZ/88XUvu9wmzc=",
  "SM2ECIES": "IOBQ7ZN2Yk52x7cGX0/zIWYjreeTILk2GVHaJcLXpB2ttXa/9U4kAwvvZdab8EOzyIdkxqf34YRTuQY4HIKn2Q==",
  "nonce_local": "tXdrYkVsr+7S8SvZIVR8RWiZjJO+D4ig5Hv+2E+d968=",
  "dongle": {
    "id": "00000000-f66a164b4c024842",
    "pid": "0xef38d3c7",
    "uid": "0x000000e0",
    "type": "0x000000ff",
    "birthday": "2024-11-26 17:54:44",
    "agent": "0xffffffff",
    "version": "0x00000222"
  },
  "nonce_admin": "wCpQzk5kj0UkC9OkwfXVm7jsUxMmtNEurS6zctbYdFk=",
  "EnTrust": [
    "53c511",
    "AAAAAPZqFktMAkhCU8URAFjAHwoTvvIIbm5Y1s4WpQsHYmVXktZGyW0GwUTfnVkFXiJT064CH3kCRv+D29zdw3zot6fZqC7nh/I13llAM4M="
  ]
},
[
  {
    "hid": "ffba338b-c54b3f6401f2d630",
    "kid": "e2cf01",
    "cipher": "SI9blmdpRBKBqAlpXffpcj24Ofg+CYxzwoMHWKheTSRMtqpIra0/lbB6rv8jiv1AgiGazQYm4mnTal8c0AJOou4Wr0nP86bpAzd4Vq2RCmLE0YLeLwkjkFWbtKbnT4pSrxpu5LOz579+VnDsVCxpOv9fSGstc/TlzjWmE4zEBV0="
  },
  {
    "hid": "00000000-f9ea114b7e024e42",
    "kid": "4c33a2",
    "cipher": "e27+zf2fmpBNWDx2kwCphtFnbfUFxRWyOE8310hbTW0YbL5mC3LNWfg54Mb1dnkb5XYv2MRXF0QpZG8bZ/oR3BiNwDwVbM1UgXiRTzlVIPPtcdT/uECkLt8OgaxcZSlXP6/vkPMhQVWfHOkDRnSkQ1KdSV3jieufNo+VICLxtpA="
  },
  {
    "hid": "00000000-f96a124b7f024042",
    "kid": "316fb4",
    "cipher": "olUVMLAmJsoswFn6swvIahjmyaApWFSB09WsMuz1PxBCApbE82yoqCb6xm5FlRoVXuGGA2nBBue/DfWtNPAtgiVDODvYrglUeZBrNHdDQbOBZuxvudxkmeDazbk53hqZhFTbCDfc65Fxu6rbPFwyRFAhccJAo8qV8rMkYjPM7cU="
  },
  {
    "hid": "00000000-e886100b600b21a2",
    "kid": "527544",
    "cipher": "QYLU4GrEGbgWUVTo2r9AOu9QO8bcFAHPeJYWrisPhMa57Z1u54w4IBmeKhBVG+bgW27OGTtZrV3g98cGknuIRaCS7KlS2QxxcG+PJrjuPJYK6ixd1XR3gPogatgO539cvjOZAFziQF6M2++zUK06KVNxLl2++eSAmA36pRNNG6U="
  },
  {
    "hid": "00000000-e886100b610b22a2",
    "kid": "1c24d8",
    "cipher": "5zjqh2xW1deOVR2P1M+0XZgv0Ei3FIVygFfG9wCbqS/OixrtZGonLXa6ASvEecxSjXfmKuyAvQKL12FvFJmtv002EoOveSHpkXgmHKf29Eh+hw343NF/HvhUXWPnPi15msAn+wIsFh9BZLEYUbjhXnseMXGSJRWyaqkPsp73tME="
  }
]
]
```

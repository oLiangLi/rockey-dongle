
## 工作uKey的初始化 W0 (00000000-e886180b670b14a2)...
- 重新生成一个不同的sec.bin, 我们让每次生成的uKey都使用不同 pid, 因此不需要备份这个文件
```shell
node -e "fs.writeFileSync('.bin/arm-RockeyARM-native-release/sec.bin', crypto.getRandomValues(Buffer.alloc(64)))"
```
- make dongle -j8 重新生成一份特定参数的 uKey 固件 ...
- 按需要执行 Initialize.dongle + EnTrust.dongle 脚本 ...
- 测试可以托管执行代码以后锁定 W0 ...
- 执行完成以后的系统参数为:
```json
[
{
  "category": 2253078703,
  "SM2ECDSA": "QIyaSpC3oK5QmYkp+Hie8ccJso0puCjPmq9vYgZ6nWZizurKxzgFoBjajQXI06fxbKgrNN+ZxnfZaxGb5mrrtA==",
  "P256ECDSA": "IvAq2Kp+xPUtnMsKxa6rQ4+rswjeErXU2XqIPfX3CDovBPknwI1CZQKcovDEgvnlsaOjK05XV9ObqBzJZ9lukg==",
  "RSA2048": "AQABAM/sqkC7rfgeCL14i38j8JRtevcRENQBAYfWtr1R1QzSRjAelFrP1h9OU2FJJQsUeCM/sGex/cHzqoa1TYfHsjIfv+OMn1ntg79+AFRj/q2XRin1yo9/X5AbkXeeCZgzoIl7jrf7kIDRHXpBsuPZ7Q7lvXsCLFLgxrKOuR2Quw/sCTBG6Egxf59tpNFwAsBa17TBNkHnzZ5U9/JJmDoMzj+zLrjLbCArXRhN4QGv4LhJAyMd88+hcli2iipt0TsJygBLdENwXAHEFWJ8/kYViS19LznPgZM55NpVB6+zPB3t6peN+5EvdKMB54TKFL3XX+IjXp3AgIVDQ5nbICWLkPc=",
  "SM2ECIES": "iGMjPIjuhG49Y7cJrfPZfnmueM2fOapvMvVZx2c099Ta+N4/yFf3lbKszXL9S7clRpCs61Rs0BI6z8m3RRKDxg==",
  "nonce_local": "dDeHCVjp01fTMkKYHnqyWV47J/0T0rYnU9SCUPkH8dU=",
  "dongle": {
    "id": "00000000-e886180b670b14a2",
    "pid": "0x8741fdd3",
    "uid": "0x00010086",
    "type": "0x000000ff",
    "birthday": "2024-11-01 09:40:49",
    "agent": "0xffffffff",
    "version": "0x00000222"
  },
  "nonce_admin": "RuLM2HjqLNrcjuFB+SbnjUKynDWJbzmfPL5KPadDRdE=",
  "EnTrust": [
    "3cc5ea",
    "AAAAAOiGGAtnCxSiPMXqAECMmkqQt6CuUJmJKfh4nvHHCbKNKbgoz5qvb2IGep1mYs7qysc4BaAY2o0FyNOn8WyoKzTfmcZ32WsRm+Zq67Q="
  ]
},
[
  {
    "hid": "ffba338b-c54b3f6401f2d630",
    "kid": "e2cf01",
    "cipher": "24M2SDtHARPSIX8zfNt+w43yqzRG9Ir5xASJBNqjxcy9RcrlE8wq7SfdhCKmPglro72FEwwgSniHjKP9eMoPHeW6Cyr+dO6Hg0JA9JmJwl4eL9YM4qOrUEJTZ+Jsg/ORj6KnD84I8LwG+1CA1DEuV5xo75sP4jgWkV+561NIg70="
  },
  {
    "hid": "00000000-f9ea114b7e024e42",
    "kid": "4c33a2",
    "cipher": "GRhMNQJO/qMRAC9ykYIUjZmYhD328gTwPwW2Diywen5p17iL3re+WG8Eau/AR4v5mDHESgp25FQTFWZ22XEqNQWDhlZ7kth+IodY/gqh/Bm3S+PVeIJMorBVj4/X/b+aRbZnpv120W1pPhgMw2ooefuhHJWQ0rwhdIefb+/tmjQ="
  },
  {
    "hid": "00000000-f96a124b7f024042",
    "kid": "316fb4",
    "cipher": "wz+uXgz6ticNi609GG2dJH2fy4A6+UR0BrwsODzBxcncnisE6KadjgWFfu72pN1gVgn2MAu8zD6YIyG5Qi2k3CWhXS1aH8N/BG9bVFIVujkJew45jExF5qb7dQp//zOXXQ86WdaXW15CH9W9dcAktaj7i2D6GzLaRuskSvQVdXA="
  },
  {
    "hid": "00000000-e886100b600b21a2",
    "kid": "527544",
    "cipher": "47yE5KBA9UHwpM96r0TRwJbuv0vcBnCPrBX7FyDG0bWbaJ669b+K+6q+SrU7B+/kwoLdj8qzolgK9tSJcauPpN8HTyXJGMEoftmpE1xIy6bDMMoW03MgAQc4Y0PV5JQjBKDCnUfZB6KrYLrR0bwKk6Yf44M951i3qV+61g7TcCQ="
  },
  {
    "hid": "00000000-e886100b610b22a2",
    "kid": "1c24d8",
    "cipher": "8m8YtHi3qkRO7ENl0T6RXsIw/uCukXlYmLYaigcbTvpmKqY21Z9dSgjqt5UBYnLQkplYqIAhHmLV7py1BPO1yKoTRxM/45NQ9vhfuenegIaYhcry4QBqlhGoqxTIuEWT1q98kgzvJIe1WZTHx4Lx3FG47pfE/yDDpI2CEQMztgU="
  }
]
]
```

## 准备导入 MASTER_SECRET ...
- K0/K1/K2/K3 对 EXCHANGE_PREV_MASTER_SECRET.dongle 脚本签名, 完成准备工作 ...
- 对各个签名文件导出执行脚本, 参数按下面的列表选择
K0: WldXwpzbk1Apg+dvzyzXWgPDbd28nz4Xc+dpeZOW42w=
K1: dcpbK4i+7j9faWwmkMBJvu5VwsTCmGf+ehkk6hvPIFc=
K2: 4Kd6n5KFYxhK4Ea+bgEUM1aphYwPQAp/gKIeBp0Aghw=
K3: pOWet7H9rIn7xLxLobU0OTlq1zHzYuX58JPGYhz00g0=
RSA: AQABAM/sqkC7rfgeCL14i38j8JRtevcRENQBAYfWtr1R1QzSRjAelFrP1h9OU2FJJQsUeCM/sGex/cHzqoa1TYfHsjIfv+OMn1ntg79+AFRj/q2XRin1yo9/X5AbkXeeCZgzoIl7jrf7kIDRHXpBsuPZ7Q7lvXsCLFLgxrKOuR2Quw/sCTBG6Egxf59tpNFwAsBa17TBNkHnzZ5U9/JJmDoMzj+zLrjLbCArXRhN4QGv4LhJAyMd88+hcli2iipt0TsJygBLdENwXAHEFWJ8/kYViS19LznPgZM55NpVB6+zPB3t6peN+5EvdKMB54TKFL3XX+IjXp3AgIVDQ5nbICWLkPc=

## W0 (00000000-e886180b670b14a2) 导入后结果记录为:
```json
{
  "rLANG_DONGLE_ID_0": "AAAAAPnqEUt+Ak5C////AA==",
  "rLANG_DONGLE_ID_1": "AAAAAOiGEAtgCyGi////AQ==",
  "rLANG_DONGLE_ID_2": "AAAAAOiGEAthCyKi////Ag==",
  "rLANG_DONGLE_ID_3": "AAAAAOiGEAtgCyGi////Aw==",
  "rLANG_DONGLE_ID_4": "AAAAAOiGEAthCyKi////BA==",
  "rLANG_DONGLE_ID_5": "AAAAAOiGEAthCyKi////BQ==",
  "rLANG_MASTER_SECRET_FINGERPRINT": "5ywyb0S7AcA="
}
```


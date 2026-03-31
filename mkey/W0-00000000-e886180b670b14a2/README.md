
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

## 验证导入的 MASTER_SECRET 正常工作, 使用 MASTER_SIGNATURE.dongle 脚本验证 ...
- 参数选择 INPUT: FFFF[64], SEEDS: FFFF[64], TYPES: 0xC8C04E1F, 输出结果为:
```json
{
  "rLANG_ED25519_Pubkey": "cK12PZ4LhzP0Ay53ijRdeyu5A18jQOVJmWe9PljiUAk=",
  "rLANG_SEEDS_HASH": "W4o0YmydXFY=",
  "rLANG_INPUT_HASH": "W4o0YmydXFY=",
  "rLANG_SIGNATURE": "kyh9b3VaUIb2szW3aCIoARG5YkTWE6Xt6D1DY4SgNLA0Bodmh7sBHtu5cROnvA4rfpwVL8k8uyCwcLzZ7qNSBg=="
}
```
- 参数选择 INPUT: ZERO[64], SEEDS: FFFF[64], TYPES: 0xC8C04E1F, 输出结果为:
```json
{
  "rLANG_ED25519_Pubkey": "cK12PZ4LhzP0Ay53ijRdeyu5A18jQOVJmWe9PljiUAk=",
  "rLANG_SEEDS_HASH": "W4o0YmydXFY=",
  "rLANG_INPUT_HASH": "RrWFcb5BaFw=",
  "rLANG_SIGNATURE": "17YcGgWgv38hV7HkmZ+eoC1bX24iA2gjgX432KbO90WTip5FpILPO3BnQoJy3l7ugntcwmgmPWPzHYv7vRRsCg=="
}
```

## 使用 T0 () 验证 MASTER_SECRET 是否正确生效
- 按需要执行 Initialize.dongle + EnTrust.dongle 脚本 ...
- 执行完成以后的系统参数为:
```json
[
{
  "category": 3277357231,
  "SM2ECDSA": "ZoG7UNBkSTIgjNYfltLBXJuLHaAbtrj2cR65f/XnWa0399LratdD77puNKg8TuFEItO0hNrnzAqZ91j3Jzw+mQ==",
  "P256ECDSA": "RBmTW1D7BkbaZiZqOrxUHydMxoBPrzt0DDP26r9qIFIfhQaG1JqQG20EH71r0cJTHfSg3dUWKEbtJZDXef+BLw==",
  "RSA2048": "AQABALtL+2zMSENGYzoHwH5wnkywKAEEMmHf6x5iDfTyzvdMKHEYzCp9OQa8CPotxUu83ZikhVJ9WzyB9nvaGkuFExZZzYD6E4J84SYse4kS9d/2SR7d6SZILhxSVgBkt7nUErW09vcMGP+MieAUioErsrbWOSbD7OGdk0bcy5LLXlZXnwFifII3w27u4/2jW5ICUCx+jgREt5FRrih/ahcgFfdYGA8SDqNN3Rvr/na4Rrb7G2ziRorO8Eay8bA8jzvXGQ0dDxlWJvRxdh/stp1UlRqOQ3pVOyIg0fOzdrKLePJuclkQF2CXCGQODKTq/F5Yv5Ut1IWjqQuiOmZN8Wlifik=",
  "SM2ECIES": "BUElL39sV+U/0lMj5Lgfj+EKgeAcZNhcuhU1DBln1DrRJVFmKT9JGEKQ1VKSGomSxxsayhnD6Uw3Avprrg5z6Q==",
  "nonce_local": "MrajY1biY4/Atb0wI9V7CkdRvsJQ8Pxve0c9ZoqkP5A=",
  "dongle": {
    "id": "00000000-ef6a125b02094d42",
    "pid": "0x32a95933",
    "uid": "0x00008848",
    "type": "0x000000ff",
    "birthday": "2024-11-26 19:47:36",
    "agent": "0xffffffff",
    "version": "0x00000222"
  },
  "nonce_admin": "xUkDmVfZjXJU6uTMYZM88Inddvkbusnl9+TBkFtLSs4=",
  "EnTrust": [
    "3b829b",
    "AAAAAO9qElsCCU1CO4KbAGaBu1DQZEkyIIzWH5bSwVybix2gG7a49nEeuX/151mtN/fS62rXQ++6bjSoPE7hRCLTtITa58wKmfdY9yc8Ppk="
  ]
},
[
  {
    "hid": "ffba338b-c54b3f6401f2d630",
    "kid": "e2cf01",
    "cipher": "bjfySiYynPNK5dL3uPKJRaV7M4m0J4AU2Fm2kPWtNSHgSgQghFuu9/HAGhJW627iG2j8evVbrr4fEvqRMwqtp5eTS0quEFoAuVYLFHYfrjiFscnX52t8DxU1ujjvakFaVo/ZnbmPby96uytd06jwJGB5KyLpszRqcGtZHTkEtTY="
  },
  {
    "hid": "00000000-f9ea114b7e024e42",
    "kid": "4c33a2",
    "cipher": "6xkL2WCw/Dx/aojXaaaCAFYz/m1SUvgwENIgvmfaaxqfZSxxaCULyRHbPiaM+Sw5VONavh/xKrgCy3Yurh0qIYAZ+970l3dUAXM+BtNcnRPE/AjW06WDKjkhB62gLI9dMD0RL3UY5ReOQkuPZ0Y5Hr8q2MQVxVdPfD2BvjhmhJM="
  },
  null,
  null,
  null
]
]
```
- 使用 K1/K2/K3 对 EXCHANGE_PREV_MASTER_SECRET.dongle 脚本签名

- 对各个签名文件导出执行脚本, 参数按下面的列表选择
K0: WldXwpzbk1Apg+dvzyzXWgPDbd28nz4Xc+dpeZOW42w=
K1: dcpbK4i+7j9faWwmkMBJvu5VwsTCmGf+ehkk6hvPIFc=
K2: 4Kd6n5KFYxhK4Ea+bgEUM1aphYwPQAp/gKIeBp0Aghw=
K3: pOWet7H9rIn7xLxLobU0OTlq1zHzYuX58JPGYhz00g0=
RSA: AQABALtL+2zMSENGYzoHwH5wnkywKAEEMmHf6x5iDfTyzvdMKHEYzCp9OQa8CPotxUu83ZikhVJ9WzyB9nvaGkuFExZZzYD6E4J84SYse4kS9d/2SR7d6SZILhxSVgBkt7nUErW09vcMGP+MieAUioErsrbWOSbD7OGdk0bcy5LLXlZXnwFifII3w27u4/2jW5ICUCx+jgREt5FRrih/ahcgFfdYGA8SDqNN3Rvr/na4Rrb7G2ziRorO8Eay8bA8jzvXGQ0dDxlWJvRxdh/stp1UlRqOQ3pVOyIg0fOzdrKLePJuclkQF2CXCGQODKTq/F5Yv5Ut1IWjqQuiOmZN8Wlifik=

### T0 (00000000-ef6a125b02094d42) 导入后结果记录为:
```json
{
  "rLANG_DONGLE_ID_0": "AAAAAPlqEkt/AkBC////AA==",
  "rLANG_DONGLE_ID_1": "AAAAAOiGEAtgCyGi////AQ==",
  "rLANG_DONGLE_ID_2": "AAAAAOiGEAthCyKi////Ag==",
  "rLANG_DONGLE_ID_3": "AAAAAPlqEkt/AkBC////Aw==",
  "rLANG_DONGLE_ID_4": "AAAAAPlqEkt/AkBC////BA==",
  "rLANG_DONGLE_ID_5": "AAAAAOiGEAtgCyGi////BQ==",
  "rLANG_MASTER_SECRET_FINGERPRINT": "5ywyb0S7AcA="
}
```

### T0 (00000000-ef6a125b02094d42) 验证导入的 MASTER_SECRET 正常工作, 使用 MASTER_SIGNATURE.dongle 脚本验证 ...
- 参数选择 INPUT: FFFF[64], SEEDS: FFFF[64], TYPES: 0xC8C04E1F, 输出结果为:
```json
{
  "rLANG_ED25519_Pubkey": "cK12PZ4LhzP0Ay53ijRdeyu5A18jQOVJmWe9PljiUAk=",
  "rLANG_SEEDS_HASH": "W4o0YmydXFY=",
  "rLANG_INPUT_HASH": "W4o0YmydXFY=",
  "rLANG_SIGNATURE": "kyh9b3VaUIb2szW3aCIoARG5YkTWE6Xt6D1DY4SgNLA0Bodmh7sBHtu5cROnvA4rfpwVL8k8uyCwcLzZ7qNSBg=="
}
```

- 参数选择 INPUT: ZERO[64], SEEDS: FFFF[64], TYPES: 0xC8C04E1F, 输出结果为:
```json
{
  "rLANG_ED25519_Pubkey": "cK12PZ4LhzP0Ay53ijRdeyu5A18jQOVJmWe9PljiUAk=",
  "rLANG_SEEDS_HASH": "W4o0YmydXFY=",
  "rLANG_INPUT_HASH": "RrWFcb5BaFw=",
  "rLANG_SIGNATURE": "17YcGgWgv38hV7HkmZ+eoC1bX24iA2gjgX432KbO90WTip5FpILPO3BnQoJy3l7ugntcwmgmPWPzHYv7vRRsCg=="
}
```

### 经过验证, MASTER_SECRET 基本功能正常, 然后对T0重新做初始化

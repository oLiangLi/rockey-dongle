## 管理员 u-key (A0-00000000-e886180b670b14a2) 的初始化 
- 重新初始化 A0 ...
- 执行 Bootstrap-Admin + Bootstrap-EnTrust-Null 脚本 ...
- 初始化后 A0 系统参数为:
```json
[  
{
  "category": 2253078703,
  "SM2ECDSA": "to+6WresZCKHvnsZYyYqDXwNWr0j2ZEvX6yMGGhIYCnBd4XKrTxzUvaYwr0vOtdP4Vd26mR0VR+0aRJJtEqDtw==",
  "P256ECDSA": "eycsZEk+T7N5DrQ50TZKAq8G3EDyN1c8r6NXA4KhgxYsyMubRCKSILQ4a7PSQdx/uTSsRNssdzm52UM9CO85Rg==",
  "RSA2048": "AQABAPWTVJrsmMj7POOnP5KCV9zsGtSM0Qq5sCwZpiJHHef2bSIfHfZAVIwo5l/cpHYXpSVgUmuMXnab3bRchkyrOh52E1Xr8XEpqs+jZ3zPZvoyVYdkpqRt1RMuZzpNN2x9Vx1ImibCJ5gg8aDZGvzaKV2HqlqR7KXMqwZDjg9M5qcvlOL1MhN1g/pyMWaV6wuYcbeDz9eQiQI05iXWaKmtFos0Hx3lLCnNG9qm1zzeVufKFR7qMwveRT3BPF5oIA66r7FbzWUsj6l1CK6A+kK6YZfb74HEqpt1CsX0jCtaqbEp8NGRAqEcsoHFF17PC3xlAGlwr6gr4DYEtDmSP+R9H98=",
  "SM2ECIES": "iCoC/tzxFGfQBLd3ArrWx9Zk0y+JH53SvTeeV3ZYYS6Hpb4WlXN8iGsvoBB4ykwrCZj606YObCJdRxvVuUqxcw==",
  "nonce_local": "XI/kycQaCptqwaP+VA+WweK8Pvwukf4vN2BbsGcAYEQ=",
  "dongle": {
    "id": "00000000-e886180b670b14a2",
    "pid": "0x587908e4",
    "uid": "0x000000a0",
    "type": "0x000000ff",
    "birthday": "2024-11-01 09:40:49",
    "agent": "0xffffffff",
    "version": "0x00000222"
  },
  "nonce_admin": "wMqKLmQk4KjbM2kEzNoFQlj0R/MpkK4x1HRjIJIeVJ8=",
  "EnTrust": [
    "ae2d88",
    "AAAAAOiGGAtnCxSiri2IALaPulq3rGQih757GWMmKg18DVq9I9mRL1+sjBhoSGApwXeFyq08c1L2mMK9LzrXT+FXdupkdFUftGkSSbRKg7c="
  ]
},
[
  null,
  null,
  null,
  null,
  null
]
]
```

## 在新的RockeyTest 测试页面下加载 ./mkey/signed-script/K0-K1-K2-K3/Export-RockeyARM-K0-K1-K2-K3.json 文件, 按下列参数准备好 K0/K1/K2/K3 需要执行的脚本文件:
K0: WldXwpzbk1Apg+dvzyzXWgPDbd28nz4Xc+dpeZOW42w=
K1: dcpbK4i+7j9faWwmkMBJvu5VwsTCmGf+ehkk6hvPIFc=
K2: 4Kd6n5KFYxhK4Ea+bgEUM1aphYwPQAp/gKIeBp0Aghw=
K3: pOWet7H9rIn7xLxLobU0OTlq1zHzYuX58JPGYhz00g0=
RSA: AQABAPWTVJrsmMj7POOnP5KCV9zsGtSM0Qq5sCwZpiJHHef2bSIfHfZAVIwo5l/cpHYXpSVgUmuMXnab3bRchkyrOh52E1Xr8XEpqs+jZ3zPZvoyVYdkpqRt1RMuZzpNN2x9Vx1ImibCJ5gg8aDZGvzaKV2HqlqR7KXMqwZDjg9M5qcvlOL1MhN1g/pyMWaV6wuYcbeDz9eQiQI05iXWaKmtFos0Hx3lLCnNG9qm1zzeVufKFR7qMwveRT3BPF5oIA66r7FbzWUsj6l1CK6A+kK6YZfb74HEqpt1CsX0jCtaqbEp8NGRAqEcsoHFF17PC3xlAGlwr6gr4DYEtDmSP+R9H98=

## 导入 MASTER-SECRET 结果如下(与之前的指纹相符):
- 在签署 EXPORT_SESSION_KEY 脚本文件后, 锁定 A0
```json
{
  "rLANG_DONGLE_ID_0": "AAAAAPnqEUt+Ak5C////AA==",
  "rLANG_DONGLE_ID_1": "AAAAAPnqEUt+Ak5C////AQ==",
  "rLANG_DONGLE_ID_2": "AAAAAPnqEUt+Ak5C////Ag==",
  "rLANG_DONGLE_ID_3": "AAAAAPlqEkt/AkBC////Aw==",
  "rLANG_DONGLE_ID_4": "AAAAAPlqEkt/AkBC////BA==",
  "rLANG_DONGLE_ID_5": "AAAAAOiGEAthCyKi////BQ==",
  "rLANG_MASTER_SECRET_FINGERPRINT": "5ywyb0S7AcA="
}
```

## 向 T0 导入 SESSION-KEY 测试结果:
- T0 重新初始化后的参数:
```json
{
  "rLANG_Ed25519_Pubkey": "9xLui0aUwgWx3VTc57gsDMv4TkEs6TW2+VwTsG8IcQU=",
  "rLANG_CV25519_Pubkey": "YOlAPkhbw9XoZif83EQXz+fu75xwbpVALlPWMQzmLnc=",
  "rLANG_Ed25519_SIGN": "uWZnFQIX409FpHU5aBcZzzZilzNR7vYLXfIoc71vyXl4EjHN8tg5PJDjQ89ilrEn3nj8onxpu2Mrq2DfABs8Aw=="
}
```
- 导入后的结果为(与E0的结果相符):
```json
{
  "rLANG_ROOT_Pubkey": "QKjfVaATYFL/7BbpDYiMUfVZ+ly1gYZZgWtFSYvWR2g=",
  "rLANG_INPUT_Message": "SGVsbG8gd29ybGQhAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "rLANG_SESSION_Pubkey": "eo0aeu5WJaJPiCRp4MwCJxqVsgUNSfaDqS/2lb4xJjs=",
  "rLANG_WORLD_MAGIC": 3368046111,
  "rLANG_INPUT_SESSION_Type": 1,
  "rLANG_INPUT_Category": 3277357231,
  "rLANG_INPUT_NotBefore": 2282,
  "rLANG_INPUT_NotAfter": 2465,
  "rLANG_ROOT_Signature": "QChrxh+Xyv89QnYc8TQoeqzC3NtqB+Aqh+pKZfuxZlUJC9/289DIAJyHJlJqZpklaZ8KhFts59OBL16FI40iDw=="
}
```
- 测试签名的结果验证无误(m="fN7Z5SYFnJPYSJZJ9XGRgyCuAk9A3i4p23q0rcdi+k5Q6TI3INPxb0KKsllYJRUZLzPU2YWuJYyTtsQQdu76mQ=="):
```json
{
  "rLANG_ROOT_Pubkey": "QKjfVaATYFL/7BbpDYiMUfVZ+ly1gYZZgWtFSYvWR2g=",
  "rLANG_INPUT_Message": "SGVsbG8gd29ybGQhAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "rLANG_SESSION_Pubkey": "eo0aeu5WJaJPiCRp4MwCJxqVsgUNSfaDqS/2lb4xJjs=",
  "rLANG_WORLD_MAGIC": 3368046111,
  "rLANG_INPUT_SESSION_Type": 1,
  "rLANG_INPUT_Category": 3277357231,
  "rLANG_INPUT_NotBefore": 2282,
  "rLANG_INPUT_NotAfter": 2465,
  "rLANG_ROOT_Signature": "QChrxh+Xyv89QnYc8TQoeqzC3NtqB+Aqh+pKZfuxZlUJC9/289DIAJyHJlJqZpklaZ8KhFts59OBL16FI40iDw==",
  "rLANG_SESSION_Signature": "ctXjcwe3S8QbIZgK+8gPg4by0EX+mWRNxBX57zLyekbFw5KTURNcU6HtomaSGRg5ck9oVKDUWXmBVBJMKPY/DQ=="
}
```
- 验证无误后重置 T0

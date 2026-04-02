## E0 初始化过程, 按SESSION-KEY的要求, 重新初始化为 EnTrust-Null 模式 ...

- 重新初始化 E0 ...
- 执行 Bootstrap-INIT + Bootstrap-EnTrust-Null 脚本 ...
- 初始化后 E0 系统参数为:
```json
[
{
  "category": 3277357231,
  "SM2ECDSA": "ZPRTrxPdPLIz2v/nRrbQ6eOgOM/rRRDUjEZHLMdCwb7Zt2ze12os3qo6OnYErUNgH6xuBH78d4L7UDUKc/jrCg==",
  "P256ECDSA": "QTP3PJ99nH9zQ8T9g/+xSFbijqLA7Y4FE+kwc/K4vmjhcK94dolZBA5u/QcvCca7I55DOlHjecLDyp2lnx0k9A==",
  "RSA2048": "AQABAJec+xIU/7SjKmj5Q07/L5ik9lFIdi6J8RJ+waLS39NY0ZbWZEQBBpeHSmgPpq/FSa282k3eI+pVRIxdJgGI/JU9Q0YfyiNlu1bkvEpahRzUIqSxQJc8a3PdgonHA6mwVJKNeecMGT3RK7kABgZufHFBmRBuuqRvMY/NktMOGMw2wo+oOQAb79tEVv6qX6Nf6VY5s8zz3S3ZeqSTadIs5G5fqS2TzgErrnM5BEFLzO+jjGCtE6XggCx1fYbZk9k3CkF423kqb3nUu0+XkIkrRdeh/GLcMxzrxulc2GrTAYo5UJPp9qnIfdSTse76ZngoSIpF713v2ED9Wzkgv0EOoZE=",
  "SM2ECIES": "e5/d6V+AqEk+DyMfNCZVl/OU4f9pZQdWN+G9fLVd880zftbEbZSi+ykp+eNgFFyAnwU7aDzRBz2wePU4vdLIxg==",
  "nonce_local": "EjSts7CCM7wXtE8ICUOzBx/LQsks55qxgWlSpOo8uj8=",
  "dongle": {
    "id": "00000000-f66a164b4c024842",
    "pid": "0xa6403823",
    "uid": "0x000000e0",
    "type": "0x000000ff",
    "birthday": "2024-11-26 17:54:44",
    "agent": "0xffffffff",
    "version": "0x00000222"
  },
  "nonce_admin": "wCpQzk5kj0UkC9OkwfXVm7jsUxMmtNEurS6zctbYdFk=",
  "EnTrust": [
    "6ce55e",
    "AAAAAPZqFktMAkhCbOVeAGT0U68T3TyyM9r/50a20OnjoDjP60UQ1IxGRyzHQsG+2bds3tdqLN6qOjp2BK1DYB+sbgR+/HeC+1A1CnP46wo="
  ]
},
[
  null,
  null,
  null,
  null,
  null
],
{
  "rLANG_Ed25519_Pubkey": "mn29WtENFlE8CE0tAYixopXlS9idy8V4KBHZNlfRsD8=",
  "rLANG__X25519_Pubkey": "Xc8CysYeqxd/OBDrI/1B31HYBAD3qE3od3iZfxF/RAI=",
  "rLANG_Ed25519_SIGN": "NEw7QXOtu+bfqvJFpRQn7GCwdBV9gxRoDbotMvxmNbATh6TWjYoCIRKklp4M67MYiPGeGTu/pJbyA0KBteXkDg=="
}
]
```


## 从 W0 导入 1,2,3,4 共4组SESSION-KEY, 对全0的数据签名验证结果如下:
```text

======================== 0x1 ========================
  1) v_ROOT_Pubkey    : QKjfVaATYFL/7BbpDYiMUfVZ+ly1gYZZgWtFSYvWR2g=
  2) v_Message        : LiangLI-E0-00..-f66a164b4c024842
  3) v_SESSION_Pubkey : cKPuM+04+fXnDg0jozVm+eQGyGdDFNzjT++P0RSZ4IE=
  4) v_WORLD_MAGIC    : 0xC8C04E1F
  5) v_SESSION_Type   : 0x1
  6) v_Category       : 0x864B40AF
  7) v_NotBefore      : 2026-04-01T00:00:00.000Z
  8) v_NotAfter       : 2027-01-01T00:00:00.000Z


======================== 0x2 ========================
  1) v_ROOT_Pubkey    : QKjfVaATYFL/7BbpDYiMUfVZ+ly1gYZZgWtFSYvWR2g=
  2) v_Message        : LiangLI-E0-00..-f66a164b4c024842
  3) v_SESSION_Pubkey : +T8dALASOLy5tJYD921XVWUm2L3LZ7+No+r8a5SqYDg=
  4) v_WORLD_MAGIC    : 0xC8C04E1F
  5) v_SESSION_Type   : 0x2
  6) v_Category       : 0x864B40AF
  7) v_NotBefore      : 2026-04-01T00:00:00.000Z
  8) v_NotAfter       : 2027-01-01T00:00:00.000Z


======================== 0x3 ========================
  1) v_ROOT_Pubkey    : QKjfVaATYFL/7BbpDYiMUfVZ+ly1gYZZgWtFSYvWR2g=
  2) v_Message        : LiangLI-E0-00..-f66a164b4c024842
  3) v_SESSION_Pubkey : jEEtSGTK4XgbDsy2huZvuMyyCy3njtwQcFthy13X478=
  4) v_WORLD_MAGIC    : 0xC8C04E1F
  5) v_SESSION_Type   : 0x3
  6) v_Category       : 0x864B40AF
  7) v_NotBefore      : 2026-04-01T00:00:00.000Z
  8) v_NotAfter       : 2027-01-01T00:00:00.000Z


======================== 0x4 ========================
  1) v_ROOT_Pubkey    : QKjfVaATYFL/7BbpDYiMUfVZ+ly1gYZZgWtFSYvWR2g=
  2) v_Message        : LiangLI-E0-00..-f66a164b4c024842
  3) v_SESSION_Pubkey : Cr5bs8uaE7+aHDMoEOvF9b8JZa6Ndpd+tsVj+jMeocg=
  4) v_WORLD_MAGIC    : 0xC8C04E1F
  5) v_SESSION_Type   : 0x4
  6) v_Category       : 0x864B40AF
  7) v_NotBefore      : 2026-04-01T00:00:00.000Z
  8) v_NotAfter       : 2027-01-01T00:00:00.000Z

```

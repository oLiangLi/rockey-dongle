## E1 初始化过程,  初始化为 EnTrust-Null 模式 ...
- 导入 SESSION-KEY, 签署 SESSION_KEY_SIGNATURE 后锁定 u-key ...
```json
[
{
  "category": 3277357231,
  "SM2ECDSA": "pcM+xjKXBlnOArCX5IP02cYHBUSkihj5eoGeYkiOunG8HASlsl88q4NiKQDUdQ4EM6rgrYNQhXcqgeRh17uTcg==",
  "P256ECDSA": "yekvbi7BrDER7SZf+0lIifF2v/745OVAEnOMgtd2gw1k2lMS4ILtRCN2uR7PLQlyA3uAlLJp3HtalfIBlL0dQw==",
  "RSA2048": "AQABANVWa2d/9nICoTlj9PcdmygRpwffdhZsuk7el557jEK4sTrimA2irNAPj5td+QYqhlGk0bluQly0+yhr240baTt2QRGgPeKX3cjYXsBkxqmugmFoEzEV78vMsr8wJXYTaei/6fuIT4zEo5d40IxEOX7TVikeelcc+Pt9q4dOPDS37E2bESfHD66I5t50VDyZI/3CaDqqeQyDWi77LAbudxVpTPWwo1NXcwlzyHYlKKeaE/BElLnNrmihWshW0DJrm+WQf/ivIWTiivm8S4qlsnnopadgt/bHYVXCnbaMiQtxFjV59ptEq7TdzU/i0Iz3FJNjD29NAiAf8wYpOAlHGiM=",
  "SM2ECIES": "6WppnrqsyWu2I3fYPPrCOVlX0Mjd9OOdrJQVIIMhDqN/ZYrsR+1EhmcBgSHEHPx3OVwtReDRnQZxtGaAR0F/Cg==",
  "nonce_local": "vUJmu4x4OFbz+jiJrWHkIaoPxXYWtJXmhwvJ8SRXBms=",
  "dongle": {
    "id": "00000000-f66a164b4a024542",
    "pid": "0xa5e5087d",
    "uid": "0x000000e1",
    "type": "0x000000ff",
    "birthday": "2024-11-26 17:54:44",
    "agent": "0xffffffff",
    "version": "0x00000222"
  },
  "nonce_admin": "wCpQzk5kj0UkC9OkwfXVm7jsUxMmtNEurS6zctbYdFk=",
  "EnTrust": [
    "32a32d",
    "AAAAAPZqFktKAkVCMqMtAKXDPsYylwZZzgKwl+SD9NnGBwVEpIoY+XqBnmJIjrpxvBwEpbJfPKuDYikA1HUOBDOq4K2DUIV3KoHkYde7k3I="
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
- 锁定 u-key 记录
```text
-----BEGIN PGP MESSAGE-----

hF4D0x6ByAWYN4USAQdAB8wdp6ychzmi0HEiHXw50AsH18Wcq/8Se7Xa5thZZBAw
Wh8dHPkNGmam1gp4FxRQvsXAWvVaH5oYW/KbsEDZ1eymwsaNbF+BFDjbeD24Z90w
1OkBCQIQuJiovIBvalrP5c4l2gN1le3AccXiQDCJWgvEFeaUdbT2Y7uxbhDA1O7p
Ay5uCLJSAb0rzZj4ntXHPXqRq7Wld1Tkzd6ZSJ/DTvW+ash1+zIC8GnRyRzWwavD
6Yz6gnJGSCvwAYo8QLAKm6HWPR3NIN0wioVSubfkU1LLo/+JosZFAgG/noLn9y+4
qCdzgnRTywfslIXp/NMVMmSkNRpSD8m88DEsNu3jRHdpi0bMfAaq/efwjUmXom/u
UHmNx3edoLySwlt4NH8WW8JlY9A0fCDcq9PIeZuNKPsPuOnzK+k5wd4eGeRTX/nh
Y/KTU7mT6yU7zEaIsEC+YEsFGs0RcWcGe4HJGKDzeeEJI8AftGOd1okVSPuLgabu
wo5BIOeG0ULngKJK6S5dZMXsXW6ZXh2XurCwv1KWY8u5IKIh0Wnj4D5vOPn4p6hA
d7vCQl7tA8vAlJbRvypm+H02pl3nQ24yApEr/j0xgol8isKHEKXerWN+waFH7rst
7+B070bXl5+zF6LGNgySmkEDhhNKqUGezF09bRf1adGS+nwNBSWZdgMpbDOd0PhC
oaAFd+v2YQiz2t/y76VNBeXCoW25LYv3q3RTSNjiodX364X9liqAppcoFD2DSFwp
HbYu8bPq3dkuTuhAIjIUsbSdRy/lQ08x2BcXsHOYVvNZVC/GV2xou0r2aY8iPE8E
ass+oNvFOc97HTg0UhzUKftYmtP7X/0r52z+mvDkzqMO6w==
=RzV8
-----END PGP MESSAGE-----
```


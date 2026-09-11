#include "../base.h"

rLANG_DECLARE_MACHINE

rLANGEXPORT int rLANGAPI rl_HEX_Read(uint8_t* zOUT, const char* zIN, int zLEN) {
  uint8_t* p = zOUT;
  if (zLEN < 0) {
    zLEN = (int)strlen(zIN);
  }

  while (zLEN >= 2) {
    int c1 = *zIN++;
    int c2 = *zIN++;
    c1 = (c1 >= '0' && c1 <= '9') ? c1 - '0' : (c1 >= 'A' && c1 <= 'F') ? c1 - ('A' - 10) : c1 - ('a' - 10);
    c2 = (c2 >= '0' && c2 <= '9') ? c2 - '0' : (c2 >= 'A' && c2 <= 'F') ? c2 - ('A' - 10) : c2 - ('a' - 10);
    *p++ = (uint8_t)((c1 << 4) | c2);

    zLEN -= 2;
  }

  return (int)(p - zOUT);
}

rLANGEXPORT int rLANGAPI rl_HEX_Write(char* zOUT, const uint8_t* zIN, int zLEN) {
  char* p = zOUT;
  while (zLEN--) {
    int c = *zIN++;
    int x = c >> 4;
    c &= 0x0F;

    *p++ = (char)(x < 10 ? '0' + x : 'A' - 10 + x);
    *p++ = (char)(c < 10 ? '0' + c : 'A' - 10 + c);
  }
  *p = 0;

  return (int)(p - zOUT);
}
rLANGEXPORT int rLANGAPI rl_BASE64_Read(uint8_t* zOUT, const char* zIN, int zLEN) {
  static const int8_t z64v[] = {-1, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
                                -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, 62,
                                -2, -2, -2, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -2, -2, -2, -1, -2, -2, -2, 0,
                                1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                                23, 24, 25, -2, -2, -2, -2, -2, -2, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
                                39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -2, -2, -2, -2, -2};

  int c[4], n = 0, x;
  uint8_t* p = zOUT;

  /*
   *! C-04 关闭(设计决策): zLEN<0 的 strlen 模式与现状退出条件一致 ——
   *! 循环在读到 NUL(x=0 → z64v[0]=-1)或 '=' 时终止, 恢复 strlen 转换
   *! 不改变任何行为。真正的边界修法是给 zOUT 传入容量, 但调用端保证
   *! 输入 NUL 终止且输出缓冲足够, 无需引入接口变更。
  if (zLEN < 0)
    zLEN = (int)strlen(zIN);
    */

  for (;;) {
    if (0 == zLEN--) {
      x = 0;
    } else {
      x = *zIN++;
    }

    if (0 == (x & 0x80)) {
      x = z64v[x];

      if rLANG_LIKELY (x >= 0) {
        c[n] = x;
        if (++n == 4) {
          n = 0;

          *p++ = (uint8_t)((c[0] << 2) | (c[1] >> 4));
          *p++ = (uint8_t)((c[1] << 4) | (c[2] >> 2));
          *p++ = (uint8_t)((c[2] << 6) | c[3]);
        }
      } else if (-1 == x) {
        if (3 == n) {
          *p++ = (uint8_t)((c[0] << 2) | (c[1] >> 4));
          *p++ = (uint8_t)((c[1] << 4) | (c[2] >> 2));
        } else if (2 == n) {
          *p++ = (uint8_t)((c[0] << 2) | (c[1] >> 4));
        }

        /* ignore 1 == n, invalid base64 encode ... */
        return (int)(p - zOUT);
      }
      /* ignore invalid base64 character */
    }
    /* ignore invalid base64 character */
  }
}
rLANGEXPORT int rLANGAPI rl_BASE64_Write(char* zOUT, const uint8_t* zIN, int zLEN) {
  int i1, i2, i3;
  char* p = zOUT;
  const char* const ccB64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  while (zLEN >= 3) {
    i1 = *zIN++;
    i2 = *zIN++;
    i3 = *zIN++;

    *p++ = ccB64[i1 >> 2];
    *p++ = ccB64[0x3F & ((i1 << 4) | (i2 >> 4))];
    *p++ = ccB64[0x3F & ((i2 << 2) | (i3 >> 6))];
    *p++ = ccB64[0x3F & i3];

    zLEN -= 3;
  }

  if (zLEN == 2) {
    i1 = *zIN++;
    i2 = *zIN++;
    *p++ = ccB64[i1 >> 2];
    *p++ = ccB64[0x3F & ((i1 << 4) | (i2 >> 4))];
    *p++ = ccB64[0x3F & (i2 << 2)];
    *p++ = '=';
  } else if (zLEN == 1) {
    i1 = *zIN++;
    *p++ = ccB64[i1 >> 2];
    *p++ = ccB64[0x3F & (i1 << 4)];
    *p++ = '=';
    *p++ = '=';
  }
  *p = 0;

  return (int)(p - zOUT);
}

rLANGEXPORT int rLANGAPI rl_BASE64Url_Read(uint8_t* zOUT, const char* zIN, int zLEN) {
  static const int8_t z64v[] = {-1, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
                                -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
                                -2, 62, -2, -2, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -2, -2, -2, -1, -2, -2, -2, 0,
                                1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                                23, 24, 25, -2, -2, -2, -2, 63, -2, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
                                39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -2, -2, -2, -2, -2};

  int c[4], n = 0, x;
  uint8_t* p = zOUT;

  /*
   *! C-04 关闭(设计决策): 同 rl_BASE64_Read —— strlen 模式与现状
   *! 退出条件一致(NUL/'=' 终止), 无需恢复转换; zOUT 容量由调用端保证。
  if (zLEN < 0)
    zLEN = (int)strlen(zIN);
    */

  for (;;) {
    if (0 == zLEN--) {
      x = 0;
    } else {
      x = *zIN++;
    }

    if (0 == (x & 0x80)) {
      x = z64v[x];

      if rLANG_LIKELY (x >= 0) {
        c[n] = x;
        if (++n == 4) {
          n = 0;

          *p++ = (uint8_t)((c[0] << 2) | (c[1] >> 4));
          *p++ = (uint8_t)((c[1] << 4) | (c[2] >> 2));
          *p++ = (uint8_t)((c[2] << 6) | c[3]);
        }
      } else if (-1 == x) {
        if (3 == n) {
          *p++ = (uint8_t)((c[0] << 2) | (c[1] >> 4));
          *p++ = (uint8_t)((c[1] << 4) | (c[2] >> 2));
        } else if (2 == n) {
          *p++ = (uint8_t)((c[0] << 2) | (c[1] >> 4));
        }

        /* ignore 1 == n, invalid base64 encode ... */
        return (int)(p - zOUT);
      }
      /* ignore invalid base64 character */
    }
    /* ignore invalid base64 character */
  }
}
rLANGEXPORT int rLANGAPI rl_BASE64Url_Write(char* zOUT, const uint8_t* zIN, int zLEN) {
  int i1, i2, i3;
  char* p = zOUT;
  const char* const ccB64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

  while (zLEN >= 3) {
    i1 = *zIN++;
    i2 = *zIN++;
    i3 = *zIN++;

    *p++ = ccB64[i1 >> 2];
    *p++ = ccB64[0x3F & ((i1 << 4) | (i2 >> 4))];
    *p++ = ccB64[0x3F & ((i2 << 2) | (i3 >> 6))];
    *p++ = ccB64[0x3F & i3];

    zLEN -= 3;
  }

  if (zLEN == 2) {
    i1 = *zIN++;
    i2 = *zIN++;
    *p++ = ccB64[i1 >> 2];
    *p++ = ccB64[0x3F & ((i1 << 4) | (i2 >> 4))];
    *p++ = ccB64[0x3F & (i2 << 2)];
    *p++ = '=';
  } else if (zLEN == 1) {
    i1 = *zIN++;
    *p++ = ccB64[i1 >> 2];
    *p++ = ccB64[0x3F & (i1 << 4)];
    *p++ = '=';
    *p++ = '=';
  }
  *p = 0;

  return (int)(p - zOUT);
}


/**
 *! CRC8/16/32 单字节步进(并入自上游 ccae27ad 等)。调用方自行串接:
 *!   crc = rlCrc16(0, byte0) ... / 首次传初值(如 0 或 0xFFFF, 取决于目标规范)。
 *!
 *! 默认查表(快); 定义 **rLANG_CONFIG_ENABLE_LIMIT_WORLD** 时改用无表逐位实现 ——
 *! 该宏表示"本产物是在 ukey 内运行的程序", 受限世界不允许 .rodata(设备固件要求
 *! .rodata 必须为空, 且 flash 预算紧张), 故不能携带 256B/512B 的 CRC 表。
 *! 两条路径逐位等价(多项式: CRC8 LSB-first 0x8C(=0x31 反射), CRC16 MSB-first 0x1021,
 *! CRC32 反射 0xEDB88320)。
 */
#if defined(rLANG_CONFIG_ENABLE_LIMIT_WORLD)

rLANGEXPORT uint8_t rLANGAPI rlCrc8(uint8_t crc, uint8_t cc) {
  uint8_t c = (uint8_t)(crc ^ cc);

  for (int i = 0; i < 8; ++i)
    c = (c & 1u) ? (uint8_t)((c >> 1) ^ 0x8Cu) : (uint8_t)(c >> 1);
  return c;
}

rLANGEXPORT uint16_t rLANGAPI rlCrc16(uint16_t crc, uint8_t cc) {
  /* 表项 = MSB-first 8 步(i << 8), 因此这里必须先把索引放到高字节 */
  uint16_t c = (uint16_t)((uint16_t)((crc >> 8) ^ cc) << 8);

  for (int i = 0; i < 8; ++i)
    c = (c & 0x8000u) ? (uint16_t)((c << 1) ^ 0x1021u) : (uint16_t)(c << 1);
  return (uint16_t)((uint16_t)(crc << 8) ^ c);
}

rLANGEXPORT uint32_t rLANGAPI rlCrc32(uint32_t crc, uint8_t cc) {
  crc = ~crc;
  for (int half = 0; half < 2; ++half) {
    crc ^= (uint32_t)((half ? (cc >> 4) : cc) & 0x0Fu);
    for (int i = 0; i < 4; ++i)
      crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
  }
  return ~crc;
}

#else /* rLANG_CONFIG_ENABLE_LIMIT_WORLD */

rLANGEXPORT uint8_t rLANGAPI rlCrc8(uint8_t crc, uint8_t cc) {
  static const uint8_t rl_CRC8_Table[256] = {
      0x00, 0x5e, 0xbc, 0xe2, 0x61, 0x3f, 0xdd, 0x83, 0xc2, 0x9c, 0x7e, 0x20, 0xa3, 0xfd, 0x1f, 0x41, 0x9d, 0xc3, 0x21,
      0x7f, 0xfc, 0xa2, 0x40, 0x1e, 0x5f, 0x01, 0xe3, 0xbd, 0x3e, 0x60, 0x82, 0xdc, 0x23, 0x7d, 0x9f, 0xc1, 0x42, 0x1c,
      0xfe, 0xa0, 0xe1, 0xbf, 0x5d, 0x03, 0x80, 0xde, 0x3c, 0x62, 0xbe, 0xe0, 0x02, 0x5c, 0xdf, 0x81, 0x63, 0x3d, 0x7c,
      0x22, 0xc0, 0x9e, 0x1d, 0x43, 0xa1, 0xff, 0x46, 0x18, 0xfa, 0xa4, 0x27, 0x79, 0x9b, 0xc5, 0x84, 0xda, 0x38, 0x66,
      0xe5, 0xbb, 0x59, 0x07, 0xdb, 0x85, 0x67, 0x39, 0xba, 0xe4, 0x06, 0x58, 0x19, 0x47, 0xa5, 0xfb, 0x78, 0x26, 0xc4,
      0x9a, 0x65, 0x3b, 0xd9, 0x87, 0x04, 0x5a, 0xb8, 0xe6, 0xa7, 0xf9, 0x1b, 0x45, 0xc6, 0x98, 0x7a, 0x24, 0xf8, 0xa6,
      0x44, 0x1a, 0x99, 0xc7, 0x25, 0x7b, 0x3a, 0x64, 0x86, 0xd8, 0x5b, 0x05, 0xe7, 0xb9, 0x8c, 0xd2, 0x30, 0x6e, 0xed,
      0xb3, 0x51, 0x0f, 0x4e, 0x10, 0xf2, 0xac, 0x2f, 0x71, 0x93, 0xcd, 0x11, 0x4f, 0xad, 0xf3, 0x70, 0x2e, 0xcc, 0x92,
      0xd3, 0x8d, 0x6f, 0x31, 0xb2, 0xec, 0x0e, 0x50, 0xaf, 0xf1, 0x13, 0x4d, 0xce, 0x90, 0x72, 0x2c, 0x6d, 0x33, 0xd1,
      0x8f, 0x0c, 0x52, 0xb0, 0xee, 0x32, 0x6c, 0x8e, 0xd0, 0x53, 0x0d, 0xef, 0xb1, 0xf0, 0xae, 0x4c, 0x12, 0x91, 0xcf,
      0x2d, 0x73, 0xca, 0x94, 0x76, 0x28, 0xab, 0xf5, 0x17, 0x49, 0x08, 0x56, 0xb4, 0xea, 0x69, 0x37, 0xd5, 0x8b, 0x57,
      0x09, 0xeb, 0xb5, 0x36, 0x68, 0x8a, 0xd4, 0x95, 0xcb, 0x29, 0x77, 0xf4, 0xaa, 0x48, 0x16, 0xe9, 0xb7, 0x55, 0x0b,
      0x88, 0xd6, 0x34, 0x6a, 0x2b, 0x75, 0x97, 0xc9, 0x4a, 0x14, 0xf6, 0xa8, 0x74, 0x2a, 0xc8, 0x96, 0x15, 0x4b, 0xa9,
      0xf7, 0xb6, 0xe8, 0x0a, 0x54, 0xd7, 0x89, 0x6b, 0x35};

  return rl_CRC8_Table[crc ^ cc];
}

rLANGEXPORT uint16_t rLANGAPI rlCrc16(uint16_t crc, uint8_t cc) {
  static const uint16_t rl_CRC16_Table[256] = {
      0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7, 0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad,
      0xe1ce, 0xf1ef, 0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6, 0x9339, 0x8318, 0xb37b, 0xa35a,
      0xd3bd, 0xc39c, 0xf3ff, 0xe3de, 0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485, 0xa56a, 0xb54b,
      0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d, 0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
      0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc, 0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861,
      0x2802, 0x3823, 0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b, 0x5af5, 0x4ad4, 0x7ab7, 0x6a96,
      0x1a71, 0x0a50, 0x3a33, 0x2a12, 0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a, 0x6ca6, 0x7c87,
      0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41, 0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
      0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70, 0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a,
      0x9f59, 0x8f78, 0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f, 0x1080, 0x00a1, 0x30c2, 0x20e3,
      0x5004, 0x4025, 0x7046, 0x6067, 0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e, 0x02b1, 0x1290,
      0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256, 0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
      0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405, 0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e,
      0xc71d, 0xd73c, 0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634, 0xd94c, 0xc96d, 0xf90e, 0xe92f,
      0x99c8, 0x89e9, 0xb98a, 0xa9ab, 0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3, 0xcb7d, 0xdb5c,
      0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a, 0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
      0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9, 0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83,
      0x1ce0, 0x0cc1, 0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8, 0x6e17, 0x7e36, 0x4e55, 0x5e74,
      0x2e93, 0x3eb2, 0x0ed1, 0x1ef0};

  return ((uint16_t)((crc << 8) ^ rl_CRC16_Table[(crc >> 8) ^ cc]));
}

rLANGEXPORT uint32_t rLANGAPI rlCrc32(uint32_t crc, uint8_t cc) {
  static const uint32_t rl_CRC32_Table[16] = {0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac, 0x76dc4190, 0x6b6b51f4,
                                              0x4db26158, 0x5005713c, 0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
                                              0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c};

  crc = ~crc;
  crc = (crc >> 4) ^ rl_CRC32_Table[(crc & 0xF) ^ (cc & 0xF)];
  crc = (crc >> 4) ^ rl_CRC32_Table[(crc & 0xF) ^ (cc >> 4)];
  return ~crc;
}

#endif /* rLANG_CONFIG_ENABLE_LIMIT_WORLD */

rLANG_DECLARE_END

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


rLANG_DECLARE_END

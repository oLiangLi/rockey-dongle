#include <Interface/dongle.h>
#include <base/base.h>

rLANG_DECLARE_MACHINE

namespace dongle {

#ifndef __RockeyARM__
int Dongle::SHA256(const void* input, size_t size, uint8_t md[32]) {
  rlCryptoShaCtx ctx;
  rlCryptoSha256CtxInit(&ctx);
  rlCryptoSha256CtxUpdate(&ctx, input, (int)size);
  rlCryptoSha256CtxFinal(&ctx, md);
  return 0;
}
#else  /* __RockeyARM__ */

// SHA256 ...
namespace sha256 {
// SHA256_DBL_INT_ADD treats two unsigned int a and b as one 64-bit integer and
// adds c to it
#define SHA256_DBL_INT_ADD(a, b, c) \
  do {                              \
    if (a > 0xffffffff - (c))       \
      ++b;                          \
    a += c;                         \
  } while (0)
#define SHA256_ROTLEFT(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define SHA256_ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (32 - (b))))

#define SHA256_CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_EP0(x) (SHA256_ROTRIGHT(x, 2) ^ SHA256_ROTRIGHT(x, 13) ^ SHA256_ROTRIGHT(x, 22))
#define SHA256_EP1(x) (SHA256_ROTRIGHT(x, 6) ^ SHA256_ROTRIGHT(x, 11) ^ SHA256_ROTRIGHT(x, 25))
#define SHA256_SIG0(x) (SHA256_ROTRIGHT(x, 7) ^ SHA256_ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SHA256_SIG1(x) (SHA256_ROTRIGHT(x, 17) ^ SHA256_ROTRIGHT(x, 19) ^ ((x) >> 10))

struct SHA256_CTX {
  uint8_t data[64];
  uint32_t datalen;
  uint32_t bitlen[2];
  uint32_t state[8];
};
rLANG_ABIREQUIRE(sizeof(SHA256_CTX) + sizeof(uintptr_t) <= sizeof(rlCryptoShaCtx));

/*
static const uint32_t sha256__k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
  */

#define get_sha256_kX(ii, a0, a1, a2, a3, a4, a5, a6, a7) \
  static uint32_t get_sha256_kX_##ii(int i) {             \
    if (i == 0)                                           \
      return a0;                                          \
    if (i == 1)                                           \
      return a1;                                          \
    if (i == 2)                                           \
      return a2;                                          \
    if (i == 3)                                           \
      return a3;                                          \
    if (i == 4)                                           \
      return a4;                                          \
    if (i == 5)                                           \
      return a5;                                          \
    if (i == 6)                                           \
      return a6;                                          \
    return a7;                                            \
  }

get_sha256_kX(0, 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5)
get_sha256_kX(1, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174)
get_sha256_kX(2, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da)
get_sha256_kX(3, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967)
get_sha256_kX(4, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85)
get_sha256_kX(5, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070)
get_sha256_kX(6, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3)
get_sha256_kX(7, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2)

uint32_t get_sha256_k(size_t i) {
  int x = i & 7;

  i >>= 3;
  if (i == 0)
    return get_sha256_kX_0(x);

  if (i == 1)
    return get_sha256_kX_1(x);

  if (i == 2)
    return get_sha256_kX_2(x);

  if (i == 3)
    return get_sha256_kX_3(x);

  if (i == 4)
    return get_sha256_kX_4(x);

  if (i == 5)
    return get_sha256_kX_5(x);

  if (i == 6)
    return get_sha256_kX_6(x);

  return get_sha256_kX_7(x);
}

struct Sha256_K {
  uint32_t operator[](size_t i) const { return get_sha256_k(i); }
} sha256__k;

static void internal_sha256_transform(SHA256_CTX* ctx, uint8_t data[]) {
  uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

  for (i = 0, j = 0; i < 16; ++i, j += 4) {
    m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
  }
  for (; i < 64; ++i) {
    m[i] = SHA256_SIG1(m[i - 2]) + m[i - 7] + SHA256_SIG0(m[i - 15]) + m[i - 16];
  }

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

  for (i = 0; i < 64; ++i) {
    t1 = h + SHA256_EP1(e) + SHA256_CH(e, f, g) + sha256__k[i] + m[i];
    t2 = SHA256_EP0(a) + SHA256_MAJ(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

void internal_sha256_init(SHA256_CTX* ctx) {
  ctx->datalen = 0;
  ctx->bitlen[0] = 0;
  ctx->bitlen[1] = 0;
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
}
void internal_sha256_update(SHA256_CTX* ctx, const uint8_t* data, int len) {
  int i, ii = 0x3F & ctx->datalen;

  for (i = 0; i < len; ++i) {
    ctx->data[ii++] = data[i];
    if (ii == 64) {
      internal_sha256_transform(ctx, ctx->data);
      SHA256_DBL_INT_ADD(ctx->bitlen[0], ctx->bitlen[1], 512);
      ii = 0;
    }
  }
  ctx->datalen = ii;
}

void internal_sha256_final(SHA256_CTX* ctx, uint8_t hash[32]) {
  int ii = 0x3F & ctx->datalen;

  // Pad whatever data is left in the buffer.
  if (ii < 56) {
    ctx->data[ii++] = 0x80;
    while (ii < 56) {
      ctx->data[ii++] = 0x00;
    }
  } else {
    ctx->data[ii++] = 0x80;
    while (ii < 64) {
      ctx->data[ii++] = 0x00;
    }
    internal_sha256_transform(ctx, ctx->data);
    memset(ctx->data, 0, 56);
  }

  // Append to the padding the total message's length in bits and transform.
  SHA256_DBL_INT_ADD(ctx->bitlen[0], ctx->bitlen[1], ctx->datalen * 8);
  ctx->data[63] = (uint8_t)ctx->bitlen[0];
  ctx->data[62] = (uint8_t)(ctx->bitlen[0] >> 8);
  ctx->data[61] = (uint8_t)(ctx->bitlen[0] >> 16);
  ctx->data[60] = (uint8_t)(ctx->bitlen[0] >> 24);
  ctx->data[59] = (uint8_t)ctx->bitlen[1];
  ctx->data[58] = (uint8_t)(ctx->bitlen[1] >> 8);
  ctx->data[57] = (uint8_t)(ctx->bitlen[1] >> 16);
  ctx->data[56] = (uint8_t)(ctx->bitlen[1] >> 24);
  internal_sha256_transform(ctx, ctx->data);

  // Since this implementation uses little endian byte ordering and SHA uses big
  // endian, reverse all the bytes when copying the final state to the output
  // hash.
  for (int i = 0; i < 4; ++i) {
    hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
  }
}

} // namespace sha256

int Dongle::SHA256(const void* input, size_t size, uint8_t md[32]) {
  sha256::SHA256_CTX ctx;
  sha256::internal_sha256_init(&ctx);
  sha256::internal_sha256_update(&ctx, static_cast<const uint8_t*>(input), (int)size);
  sha256::internal_sha256_final(&ctx, md);
  return 0;
}

#endif /* __RockeyARM__ */

} // namespace dongle

rLANG_DECLARE_END

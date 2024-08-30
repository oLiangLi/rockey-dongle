#include <base/base.h>

rLANG_DECLARE_MACHINE

rLANGIMPORT void rLANGAPI __aeabi_memcpy(void* r0, const void* r1, size_t r2);
rLANGIMPORT void rLANGAPI __aeabi_memset(void* r0, size_t r1, int r2);

rLANGEXPORT void* rLANGAPI memcpy(void* dest, const void* src, size_t n) {
  __aeabi_memcpy(dest, src, n);
  return dest;
}

rLANGEXPORT void* rLANGAPI memset(void* s, int c, size_t n) {
  __aeabi_memset(s, n, c);
  return s;
}

rLANGEXPORT int rLANGAPI memcmp(const void* s1, const void* s2, size_t n) {
  const uint8_t* p1 = s1;
  const uint8_t* p2 = s2;

  while (n--) {
    int a = *p1++;
    int b = *p2++;
    int r = a - b;
    if (0 != r)
      return r;
  }

  return 0;
}

rLANG_DECLARE_END

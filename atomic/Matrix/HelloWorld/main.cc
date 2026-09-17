#include <base/base.h>

rLANG_DECLARE_MACHINE

rLANGEXPORT void MatrixExecv() {
  for (int i = 0;; ++i) {
    rlLOGI(rLANG_ATOMC_WORLD_MAGIC, "Hello atomic world! %d %ld %lld %f %lf %LF\n", i, 0x55aa55aal,
           0x66778899aabbccddll, 1.234f, 3.14159, 2.718L);
  }
}

rLANG_DECLARE_END

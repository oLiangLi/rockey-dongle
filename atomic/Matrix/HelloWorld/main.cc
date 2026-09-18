#include <base/base.h>

#include <atomic/op_GATE/hyper/hyper.h>

rLANG_DECLARE_MACHINE

rLANGEXPORT int MatrixExecv() {
  for (int i = 0; i < 10; ++i) {
    size_t size = 0;
    rlLOGI(rLANG_ATOMC_WORLD_MAGIC, "Hello atomic world! %d %n %ld %lld %f %lf %LF", i, &size, 0x55aa55aal,
           0x66778899aabbccddll, 1.234f, 3.14159, 2.718L);
    rlLOGX(rLANG_ATOMC_WORLD_MAGIC, "Hello atomic world: %d %zd", i, size);
  }
  return 0;
}

rLANG_DECLARE_END

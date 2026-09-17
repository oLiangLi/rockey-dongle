#include <base/base.h>

/**
 *! 这个文件每次都会重新生成, 可以编译一些依赖 rLANG_WORLD_SEED_* 的函数进library ...
 */
#include "../gen/op_GATE_manifest.h"

/**
 *!
 */
#include "../hyper/hyper.h"


rLANG_DECLARE_MACHINE

/**
 *!
 */
rLANGEXPORT int rLANGAPI rLANG_op_GATE_HyperCountGate(void) {
  return op_GATE__kExportCount;
}
rLANGEXPORT const char* rLANGAPI rLANG_op_GATE_HyperWorldId(void) {
  return op_GATE__kWorldId;
}
rLANGEXPORT const op_GATE_export_t* rLANG_op_GATE_HyperExports(void) {
  return op_GATE__kExports;
}

/**
 *!
 */
#ifdef rLANG_CONFIG_ENABLE_ATOMC_WORLD
rLANGEXPORT void rLANG_op_GATE_Initialize(void) {
  auto* op_GATE = reinterpret_cast<decltype(rLANG_op_GATE_HyperInitialize)*>(4 * rLANG_START_ATOMIC_HYPER_GATE);
  (*op_GATE)(op_GATE__kWorldId, op_GATE__kExportCount);
}
#else  /* rLANG_CONFIG_ENABLE_ATOMC_WORLD */
rLANGEXPORT int rLANGAPI rLANG_op_GATE_HyperInitialize(const char* worldId, int gates) {
  if (gates != op_GATE__kExportCount) {
    rlLOGX(rLANG_ATOMC_WORLD_MAGIC, "HyperCountGate mismatch %d / %d", gates, op_GATE__kExportCount);
    return -EFAULT;
  }
  if (0 != strcmp(worldId, op_GATE__kWorldId)) {
    rlLOGX(rLANG_ATOMC_WORLD_MAGIC, "HyperWorldId mismatch %s / %s", op_GATE__kWorldId, worldId);
    return -EFAULT;
  }
  return 0;
}
#endif /* rLANG_CONFIG_ENABLE_ATOMC_WORLD */

rLANG_DECLARE_END

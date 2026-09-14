#pragma once

#include <Interface/aginx.h>
#include <Interface/dongle.h>
#include <Interface/mr.h>
#include <Interface/modexp.h>

AGINX_DECLARE_MACHINE

namespace dongle {

/**
 *! 设备内生成 RSA 私钥(2048 / 3072), 并直接写成 RsaModexp::KeyBlob('RSAK') 落进数据文件 ——
 *! 全程不经过 host, 生成完即可用 ExRSAKeyCheck / ExRSACrtModExp。
 *
 *! 为什么必须"一条指令内在设备里跑完": 种子由 host 用 KDF(MASTER.SECRET, nonce, kType!=0) 派生
 *! (见 ai-doc/rsa-root-ca-generation-2026-09-11.md), 若把候选序列交给 host 逐个判定, host 自己
 *! 就能推出 p/q ⇒ "同一种子 ⇒ 同一私钥"的托管属性不成立。
 *
 *! 生成流程(与 tools/rockey/LIMIT/sbin/rsa-prime-repro.cjs 逐位对齐, 该工具已在真机验证过
 *! "同一种子 ⇒ 逐字节相同的 p/q"):
 *!   ①p: 把 seed_p 当候选起点(小端, 最高位/最低位置 1) ⇒ +2 搜索: 试除 3..1000 奇数,
 *!     幸存者做 16 基 Miller-Rabin(全程 Montgomery 域), 每 32 次平方一次看门狗心跳;
 *!   ②q: 同样用 seed_q; p/q 一命中就落进 blob 的 P/Q 字段;
 *!   ③n = p*q;  e = 65537;  d = (1 + k*(p-1)(q-1))/e(k ≡ -((p-1)(q-1))^{-1} mod e);
 *!     dmp1 = d mod (p-1);  dmq1 = d mod (q-1);  iqmp = q^{p-2} mod p(Fermat, p 为素数);
 *!   ④最后写 KeyBlob header(magic 'RSAK') —— **magic 最后写**, 半成品可按 magic 识别。
 *
 *! d 为什么可以用 (p-1)(q-1) 而不是 lcm: 任何满足 e*d ≡ 1 (mod (p-1)(q-1)) 的 d 都满足
 *! e*d ≡ 1 (mod lcm(p-1,q-1)), 且 d < (p-1)(q-1) < n 恰好落在 blob 的全宽字段里; 这样设备端
 *! 不需要 3072 位模逆, 只需一次"小指数 e 求逆 + 小除数长除"(见 .cc 里的实现说明)。
 *
 *! 内存: 全部工作区由调用方给(Arena 1024B, 设备侧 = ExtendBuf), 栈上只有小局部量与几个临时标量;
 *!       峰值占用 968B。素数搜索是本工程最深栈路径之一(1536 位 MR ≈1.9KB),
 *!       因此**调用方必须用尽量浅的栈帧**调用本函数。
 */
class RsaKeyGen {
 public:
  /**
   *! 生成工作区: 设备侧直接指向 1KB 的 ExtendBuf(`vm.buffer_`), 内部布局对调用方不透明。
   */
  struct Arena {
    uint32_t limb[256]; /* 256 × 4 = 1024B */
  };
  rLANG_ABIREQUIRE(sizeof(Arena) == 1024);

  /** 固定的公开指数 */
  static constexpr uint32_t kE = 65537;

  /** 单个素数的探测上限(期望值 ≈ ln(2^bits)/2): 超限即判失败 —— 绝不无限搜索 */
  static constexpr uint64_t kMaxProbes = 1000000;

  /** 支持的总位数: 3072(素因子 1536 位, 上限)/ 2048(素因子 1024 位, 下限) */
  static constexpr int kMinBits = 2048;
  static constexpr int kMaxBits = 3072;

  /** 种子块字节数 = 2 × (bits/16): seed_p || seed_q(小端), 与 dashboard 落盘同序 */
  static constexpr int SeedSize(int bits) { return bits / 8; }

  /**
   *! 生成并以 KeyBlob('RSAK') 写入 dongle 数据文件 [keyOffset, keyOffset + TotalSize(bits))。
   *! seed: 指向 SeedSize(bits) 字节的种子块(seed_p || seed_q, 小端, 原地不被修改)。
   *! rounds: Miller-Rabin 轮数, 越界取 MillerRabinContext::kMaxRounds(16)。
   *! 返回 0 成功; 负值为错误码(-EINVAL 参数/-EIO 读写失败/-ERANGE 搜索超限)。
   */
  static int Generate(Dongle& dongle,
                      int keyFile,
                      uint32_t keyOffset,
                      const uint8_t* seed,
                      int bits,
                      int rounds,
                      Arena& arena);
};

}  // namespace dongle

AGINX_DECLARE_END

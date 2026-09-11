// 注意: 本脚本不加 #! shebang(Windows 下会报错), 用 node xxx.cjs 调用。
/**
 * rsa-prime-repro.cjs —— 独立复现设备端(ukey 内)的确定性素数搜索, 用于验证
 * ROOT CA 方案的核心承诺: **同一种子 ⇒ 同一对素数**(任何持有 MASTER.SECRET 的一方可复现)。
 *
 * 算法与 Interface/mr.{h,cc} 逐位对齐:
 *   1) 种子(bits/8 字节小端) 定型: bit0 |= 1(奇数), bit(bits-1) |= 1(严格 bits 位);
 *   2) 每次候选先小素数试除(d = 3..999 的所有奇数, 命中即合数);
 *   3) 存活者做 Miller-Rabin, 基依次取 [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53], 最多 rounds 个;
 *   4) 否则候选 +2 继续; 计数 probes。
 * (设备端 Montgomery 只影响速度, 不影响判定; 复现只需要同一判定顺序。)
 *
 * 用法:
 *   node Build/tools/LIMIT/sbin/rsa-prime-repro.cjs --seed <小端hex> --bits 1024|1536 [--rounds 16]
 *                                            [--expect <小端hex>] [--selftest]
 *   --expect 给出设备 dashboard 里读回的 p/q(小端 hex)时可做逐字节比对。
 *   种子/期望值都按设备 dashboard 的小端字节序书写(即 ReadDataFile 出来的顺序)。
 */
const BASES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53];

function parseArgs(argv) {
  const out = { bits: 1024, rounds: 16, seed: null, expect: null, selftest: false };
  for (let i = 0; i < argv.length; ++i) {
    const a = argv[i];
    if (a === "--seed") out.seed = argv[++i];
    else if (a === "--bits") out.bits = Number(argv[++i]);
    else if (a === "--rounds") out.rounds = Number(argv[++i]);
    else if (a === "--expect") out.expect = argv[++i];
    else if (a === "--selftest") out.selftest = true;
    else throw new Error(`未知参数 ${a}`);
  }
  return out;
}

/** 小端 hex(设备字节序) → BigInt */
function leHexToBig(hex) {
  const clean = hex.replace(/[^0-9a-fA-F]/g, "");
  if (clean.length % 2) throw new Error("hex 长度必须是偶数");
  let v = 0n;
  for (let i = clean.length / 2 - 1; i >= 0; --i) v = (v << 8n) | BigInt(parseInt(clean.substr(i * 2, 2), 16));
  return v;
}

/** BigInt → 小端 hex(定长字节数, 便于与设备比对) */
function bigToLeHex(v, bytes) {
  let s = "";
  for (let i = 0; i < bytes; ++i) {
    s += (v & 0xffn).toString(16).padStart(2, "0");
    v >>= 8n;
  }
  return s;
}

const bigToBeHex = (v) => v.toString(16).toUpperCase();

function modPow(base, exp, mod) {
  let r = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) r = (r * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return r;
}

/** d = n-1 = d*2^s; 对基 a 做一轮强伪素数测试, 返回 true = 可能是素数 */
function isStrongProbablePrime(n, a) {
  if (n % a === 0n) return n === a;
  let d = n - 1n;
  let s = 0n;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    ++s;
  }
  let x = modPow(a, d, n);
  if (x === 1n || x === n - 1n) return true;
  for (let i = 1n; i < s; ++i) {
    x = (x * x) % n;
    if (x === n - 1n) return true;
    if (x === 1n) return false;
  }
  return false;
}

/** 与设备 TrialDivide 一致: 3..999 的所有奇数流式求余 */
function trialDivide(n) {
  for (let d = 3n; d <= 999n; d += 2n) if (n % d === 0n) return true;
  return false;
}

function isPrimeLikeDevice(n, rounds) {
  if ((n & 1n) === 0n) return false;
  if (trialDivide(n)) return false;
  const m = Math.min(rounds, BASES.length);
  for (let r = 0; r < m; ++r) if (!isStrongProbablePrime(n, BigInt(BASES[r]))) return false;
  return true;
}

/** 与设备 FindPrime 一致: 候选定型后 +2 搜索; 返回 { prime, probes } */
function findPrimeFromSeed(seedBig, bits, rounds, maxProbes = 1000000) {
  let cand = seedBig | 1n | (1n << BigInt(bits - 1));
  const limit = 1n << BigInt(bits);
  for (let probes = 0; probes <= maxProbes; ++probes) {
    if (isPrimeLikeDevice(cand, rounds)) return { prime: cand, probes };
    cand += 2n;
    if (cand >= limit) return { prime: null, probes, overflow: true };
  }
  return { prime: null, probes: maxProbes, overflow: false };
}

function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.selftest) {
    // 自检: 128 位随机种子找素数, 再用 64 个随机基独立复核素性
    const bits = 128;
    const bytes = bits / 8;
    let seed = 0n;
    for (let i = 0; i < bytes; ++i) seed |= BigInt(Math.floor(Math.random() * 256)) << BigInt(8 * i);
    const t0 = Date.now();
    const { prime, probes } = findPrimeFromSeed(seed, bits, 16);
    if (!prime) throw new Error("selftest: 未找到素数");
    let ok = true;
    for (let k = 0; k < 64; ++k) {
      const a = 2n + BigInt(Math.floor(Math.random() * 1e6));
      if (!isStrongProbablePrime(prime, a)) ok = false;
    }
    console.log(
      `[selftest] bits=${bits} probes=${probes} ms=${Date.now() - t0} independent64RandomBases=${ok ? "PASS" : "FAIL"}`,
    );
    console.log(`[selftest] seed(le)=${bigToLeHex(seed, bytes)}`);
    console.log(`[selftest] prime(be)=${bigToBeHex(prime)}`);
    process.exit(ok ? 0 : 1);
  }

  if (!args.seed) {
    console.error("用法: node rsa-prime-repro.cjs --seed <小端hex> --bits 1024|1536 [--rounds 16] [--expect <小端hex>] [--selftest]");
    process.exit(2);
  }
  const bytes = args.bits / 8;
  const seed = leHexToBig(args.seed);
  const t0 = Date.now();
  const { prime, probes, overflow } = findPrimeFromSeed(seed, args.bits, args.rounds);
  const ms = Date.now() - t0;
  if (!prime) {
    console.error(`[repro] FAIL: probes=${probes} overflow=${!!overflow}`);
    process.exit(1);
  }
  const le = bigToLeHex(prime, bytes);
  console.log(`[repro] bits=${args.bits} rounds=${args.rounds} probes=${probes} ms=${ms}`);
  console.log(`[repro] prime(be)=${bigToBeHex(prime)}`);
  console.log(`[repro] prime(le)=${le}`);
  if (args.expect) {
    const same = le.toLowerCase() === args.expect.toLowerCase().replace(/[^0-9a-fA-F]/g, "");
    console.log(`[repro] matchDashboard=${same ? "YES" : "NO"}`);
    process.exit(same ? 0 : 1);
  }
}

main();

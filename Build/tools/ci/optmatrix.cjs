#!/usr/bin/env node
/*! 优化级别矩阵向量门禁(Build/tools/ci/optmatrix.cjs, make test-optmatrix)
 *! 对 -O0..-O3(默认)逐个: clean + 重建**宿主平台** release(X4C_RELEASE_CFLAGS/CXXFLAGS 覆盖),
 *! 然后运行密码学自测程序断言:
 *!   __Testing__{25519,aes,sha256,micro_ecc,dongle}__ => 退出码 10086(项目"0 错"约定;
 *!     **POSIX 退出码是 8 位, 10086 & 0xFF = 102, 故 Windows 认 10086、Linux/macOS 认 102**);
 *!   __Testing__{x509,x509import}__                  => 退出码 0 且输出含 "total error = 0";
 *! 结束恢复默认构建。可用环境 OPTMATRIX_OPTS="-O0 -O3" 精简子集; CI_SKIP_HEAVY=1 时打印跳过。
 *! 平台无关: 默认按宿主判定(Windows/Cygwin => windows 且产物带 .exe, 否则 linux 无扩展名),
 *!   可用 OPMATRIX_PLATFORM=windows|linux|aarch64-linux|foobar 覆盖, JOBS 覆盖并行度,
 *!   MAKE 覆盖 make 程序, CI_STRICT=1 时"平台不支持/程序缺失"也算失败。
 *! 板级: X4C_BOARD 决定用真机(空)还是模拟器世界(foobar)。Windows 缺省空(与既有行为一致);
 *!   其它宿主缺省 **foobar** —— 真机路径在无 ukey 的 Linux/WSL 上必然失败(Dongle_Enum F0000001),
 *!   模拟器板同样编译全部密码学源码, 因此矩阵在任意平台都可跑; 需要真机时显式
 *!   OPMATRIX_BOARD=none(等价空)并接上设备。
 */
"use strict";
const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..", "..", "..");
const opts = (process.env.OPTMATRIX_OPTS || "-O0 -O1 -O2 -O3").trim().split(/\s+/);
const strict = process.env.CI_STRICT === "1";
if (process.env.CI_SKIP_HEAVY === "1") {
  console.log("[optmatrix] CI_SKIP_HEAVY=1 跳过(需要 clean+全量重建 ×" + opts.length + ")");
  process.exit(0);
}

/** 宿主平台 → make 目标名(wORLD_CONFIG 同名目标: windows/linux/aarch64-linux/foobar) */
function hostPlatform() {
  if (process.env.OPMATRIX_PLATFORM) return process.env.OPMATRIX_PLATFORM;
  if (process.platform === "win32") return "windows";
  return process.arch === "arm64" ? "aarch64-linux" : "linux";
}
const platform = hostPlatform();
const exeSuffix = platform.startsWith("windows") ? ".exe" : "";
const makeCmd = process.env.MAKE || "make";
const jobs = process.env.JOBS || "8";
const isWin = process.platform === "win32";
/** 板级: Windows 缺省无板(真机/SDK 模拟器, 与既有行为一致); 其它宿主缺省 foobar(模拟器世界, 无需设备) */
const board =
  process.env.OPMATRIX_BOARD !== undefined
    ? process.env.OPMATRIX_BOARD === "none"
      ? ""
      : process.env.OPMATRIX_BOARD
    : isWin
      ? ""
      : "foobar";

/** 产物目录: 先按 arch[-board]-platform-release 探测, 再退化为扫描 .bin */
function resolveDir() {
  const archs = ["amd64", "aarch64"];
  const tail = `${board ? "-" + board : ""}-${platform}-release`;
  const cands = archs.map((a) => `.bin/${a}${tail}`);
  const hit = cands.find((d) => fs.existsSync(path.join(root, d)));
  if (hit) return hit;
  const bin = path.join(root, ".bin");
  const scan = fs.existsSync(bin)
    ? fs
        .readdirSync(bin)
        .filter((d) => d.endsWith(tail) && (board || !/-foobar-/.test(d)))
        .map((d) => `.bin/${d}`)
    : [];
  return scan[0] || cands[0];
}

/** 直接 spawn make(不经 shell/cd), 避免平台相关路径; Windows 下用 shell 以便解析 make.exe/cmd */
function makeRun(args) {
  const r = spawnSync(makeCmd, args, {
    cwd: root,
    encoding: "utf8",
    timeout: 3600 * 1000,
    shell: isWin,
  });
  const out = ((r.stdout || "") + (r.stderr || "")).split(/\r?\n/).filter(Boolean).slice(-6).join("\n  ");
  return { ok: r.status === 0 && !r.error, status: r.status, error: r.error, out };
}

const CRYPTO_EXES = ["__Testing__25519__", "__Testing__aes__", "__Testing__sha256__", "__Testing__micro_ecc__", "__Testing__dongle__"];
const X_EXES = ["__Testing__x509__", "__Testing__x509import__"];

/** 项目约定"0 错"退出码 = 10086;POSIX 退出码只有 8 位(10086 & 0xFF = 102),
 *  因此 Linux/macOS 上必须同时接受 102, 否则会把通过当成失败(旧的 Windows-only 判据)。 */
const kPassExact = 10086;
const kPassPosix = 10086 & 0xff; // 102
const isPass = (status) => status === kPassExact || (!isWin && status === kPassPosix);

function runExe(exe) {
  const r = spawnSync(exe, [], { cwd: root, encoding: "utf8", timeout: 600000 });
  const out = (r.stdout || "") + (r.stderr || "");
  return { status: r.status, out, tail: out.split(/\r?\n/).filter(Boolean).slice(-3).join(" ") };
}

console.log(
  `[optmatrix] platform=${platform} board=${board || "(无/真机)"} dir=${resolveDir()} opts=${opts.join(" ")} jobs=${jobs}`,
);
const probe = makeRun(["--version"]);
if (!probe.ok) {
  const msg = `[optmatrix] 找不到可用的 make(当前 ${makeCmd})${probe.error ? ": " + probe.error.message : ""}`;
  if (strict) {
    console.error(msg);
    process.exit(1);
  }
  console.log(msg + " —— 跳过(CI_STRICT=1 时失败)");
  process.exit(0);
}

/** 带板级参数的 make 调用(X4C_BOARD 通过命令行变量传递给子 make) */
const makeArgs = (args) => (board ? [...args, `X4C_BOARD=${board}`] : args);

let failed = 0;
let dir = resolveDir();
for (const opt of opts) {
  const cf = `-DNDEBUG ${opt}`;
  console.log(`[optmatrix] === ${opt} === clean+rebuild(${platform}${board ? ", board=" + board : ""})...`);
  let r = makeRun(makeArgs([`clean-${platform}`]));
  if (!r.ok) {
    console.log(`[optmatrix] clean fail rc=${r.status}\n  ${r.out}`);
    failed = 1;
    break;
  }
  r = makeRun(makeArgs([platform, `-j${jobs}`, `X4C_RELEASE_CFLAGS=${cf}`, `X4C_RELEASE_CXXFLAGS=${cf}`]));
  if (!r.ok) {
    console.log(`[optmatrix] FAIL ${opt}: 构建失败\n  ${r.out}`);
    failed = 1;
    continue;
  }
  dir = resolveDir();
  let ok = true;
  let missing = 0;
  for (const n of CRYPTO_EXES) {
    const exe = path.join(root, dir, n + exeSuffix);
    if (!fs.existsSync(exe)) { console.log(`[optmatrix] FAIL ${opt}: 缺 ${dir}/${n}${exeSuffix}`); ok = false; missing++; continue; }
    const rr = runExe(exe);
    if (!isPass(rr.status)) {
      console.log(`[optmatrix] FAIL ${opt} ${n}: exit=${rr.status}(需 ${kPassExact}${isWin ? "" : ` 或 ${kPassPosix}`})\n  ${rr.out.slice(0, 200)}`);
      ok = false;
    }
  }
  for (const n of X_EXES) {
    const exe = path.join(root, dir, n + exeSuffix);
    if (!fs.existsSync(exe)) { console.log(`[optmatrix] FAIL ${opt}: 缺 ${dir}/${n}${exeSuffix}`); ok = false; missing++; continue; }
    const rr = runExe(exe);
    const summary = /total error = 0/.test(rr.out);
    if (rr.status !== 0 || !summary) {
      console.log(`[optmatrix] FAIL ${opt} ${n}: exit=${rr.status} summary0=${summary}\n  tail: ${rr.tail.slice(0, 300)}`);
      ok = false;
    }
  }
  if (missing && strict) ok = false;
  console.log(`[optmatrix] ${ok ? "PASS" : "FAIL"} ${opt}`);
  if (!ok) failed = 1;
}

console.log(`[optmatrix] 恢复默认(release)构建 ...`);
makeRun(makeArgs([`clean-${platform}`]));
makeRun(makeArgs([platform, `-j${jobs}`]));
console.log(`[optmatrix] done failed=${failed}`);
process.exit(failed ? 1 : 0);

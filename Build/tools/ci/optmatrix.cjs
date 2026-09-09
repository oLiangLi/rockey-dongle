#!/usr/bin/env node
/*! 优化级别矩阵向量门禁(Build/tools/ci/optmatrix.cjs, make test-optmatrix)
 *! 对 -O0..-O3(默认)逐个: clean + 重建 windows release(X4C_RELEASE_CFLAGS/CXXFLAGS 覆盖)
 *! 然后运行密码学自测 exe 断言:
 *!   __Testing__{25519,aes,sha256,micro_ecc,dongle}__ => 退出码 10086(项目"0 错"约定);
 *!   __Testing__{x509,x509import}__                  => 退出码 0 且输出含 "total error = 0";
 *! 结束恢复默认构建。可用环境 OPTMATRIX_OPTS="-O0 -O3" 精简子集; CI_SKIP_HEAVY=1 时打印跳过。
 */
"use strict";
const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..", "..", "..");
const opts = (process.env.OPTMATRIX_OPTS || "-O0 -O1 -O2 -O3").trim().split(/\s+/);
if (process.env.CI_SKIP_HEAVY === "1") {
  console.log("[optmatrix] CI_SKIP_HEAVY=1 跳过(需要 clean+全量重建 ×" + opts.length + ")");
  process.exit(0);
}

const sh = (cmd) => {
  const r = spawnSync("bash", ["-lc", cmd], { cwd: root, encoding: "utf8", timeout: 3600 * 1000 });
  return { ok: r.status === 0 && !r.error, status: r.status, out: ((r.stdout || "") + (r.stderr || "")).split(/\r?\n/).filter(Boolean).slice(-6).join("\n  ") };
};

const CRYPTO_EXES = ["__Testing__25519__", "__Testing__aes__", "__Testing__sha256__", "__Testing__micro_ecc__", "__Testing__dongle__"];
const X_EXES = ["__Testing__x509__", "__Testing__x509import__"];

function runExes(exe) {
  const r = spawnSync(exe, [], { cwd: root, encoding: "utf8", timeout: 600000 });
  return { status: r.status, out: ((r.stdout || "") + (r.stderr || "")), tail: ((r.stdout || "") + (r.stderr || "")).split(/\r?\n/).filter(Boolean).slice(-3).join(" ") };
}

let failed = 0;
const dir = ".bin/amd64-windows-release";
for (const opt of opts) {
  const flag = opt.startsWith("/") ? opt : opt;
  const cf = `-DNDEBUG ${flag}`;
  console.log(`[optmatrix] === ${opt} === clean+rebuild...`);
  let r = sh("cd /cygdrive/x/MyWork/RockeyDongle && make clean-windows >/dev/null 2>&1");
  if (!r.ok) { console.log(`[optmatrix] clean fail rc=${r.status}`); failed = 1; break; }
  r = sh(`cd /cygdrive/x/MyWork/RockeyDongle && make windows -j8 X4C_RELEASE_CFLAGS='${cf}' X4C_RELEASE_CXXFLAGS='${cf}' >/dev/null 2>&1`);
  if (!r.ok) {
    console.log(`[optmatrix] FAIL ${opt}: 构建失败\n  ${r.out}`);
    failed = 1;
    continue;
  }
  let ok = true;
  for (const n of CRYPTO_EXES) {
    const exe = path.join(root, dir, n + ".exe");
    if (!fs.existsSync(exe)) { console.log(`[optmatrix] FAIL ${opt}: 缺 ${n}.exe`); ok = false; continue; }
    const rr = runExes(exe);
    if (rr.status !== 10086) {
      console.log(`[optmatrix] FAIL ${opt} ${n}: exit=${rr.status}(需 10086)\n  ${rr.out.slice(0, 200)}`);
      ok = false;
    }
  }
  for (const n of X_EXES) {
    const exe = path.join(root, dir, n + ".exe");
    if (!fs.existsSync(exe)) { console.log(`[optmatrix] FAIL ${opt}: 缺 ${n}.exe`); ok = false; continue; }
    const rr = runExes(exe);
    const summary = /total error = 0/.test(rr.out);
    if (rr.status !== 0 || !summary) {
      console.log(`[optmatrix] FAIL ${opt} ${n}: exit=${rr.status} summary0=${summary}\n  tail: ${rr.tail.slice(0, 300)}`);
      ok = false;
    }
  }
  console.log(`[optmatrix] ${ok ? "PASS" : "FAIL"} ${opt}`);
  if (!ok) failed = 1;
}

console.log(`[optmatrix] 恢复默认(release)构建 ...`);
sh("cd /cygdrive/x/MyWork/RockeyDongle && make clean-windows >/dev/null 2>&1 && make windows -j8 >/dev/null 2>&1");
console.log(`[optmatrix] done failed=${failed}`);
process.exit(failed ? 1 : 0);

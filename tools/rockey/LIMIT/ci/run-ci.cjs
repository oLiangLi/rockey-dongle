#!/usr/bin/env node
/*! 统一 CI 快速回归入口(tools/rockey/LIMIT/ci/run-ci.cjs)
 *! 默认只跑进程内 JS 模拟器回归(jsuite 子集/emuadmin/mkey/skey/corpus),
 *! 不依赖真实 ukey 与 SDK;如需严格模式设 CI_STRICT=1(前置缺失即失败)。
 *! 全量(平台自测 exe/优化矩阵)由 make ci-full / test-optmatrix 提供(见 Makefile)。
 */
"use strict";
const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..", "..", "..", "..");
const harness = path.join(root, "Web", "Agent", "Tests", "__Testing_dongle.cjs");
const js = ["jsWorld.js", "jsCrypto.js"].map((f) => path.join(root, "Web", "Agent", "Tests", "js", f));
const strict = process.env.CI_STRICT === "1";
const quick = process.env.CI_QUICK !== "0";
const logDir = path.join(root, ".bin", "ci-log");
let failed = 0;

function run(name, args, opts = {}) {
  const env = { ...process.env, ...(opts.env || {}) };
  const r = spawnSync(process.execPath, args, { cwd: root, encoding: "utf8", env, timeout: opts.timeout || 1200000 });
  const ok = r.status === 0 && !r.error;
  console.log(`[ci] ${ok ? "PASS" : "FAIL"} ${name}${r.status === null ? " (timeout/killed)" : ""}`);
  if (!ok) {
    ++failed;
    const tail = ((r.stdout || "") + (r.stderr || "")).split(/\r?\n/).filter(Boolean).slice(-14).join("\n  ");
    if (tail) console.log(`[ci]   ...${tail}`);
  }
  return r;
}

const missing = js.filter((f) => !fs.existsSync(f));
if (missing.length) {
  const msg = `[ci] 前置缺失: ${missing.join(", ")} → 先执行 make wasm && make jsWrapper`;
  if (strict) {
    console.error(msg);
    process.exit(1);
  }
  console.log(msg + " (CI_STRICT=1 时失败; 当前跳过)");
  process.exit(0);
}

console.log(`[ci] root=${root} quick=${quick} strict=${strict}`);

// 1) jsuite: 每台 Initialize(bootstrap) + CI&CD NORMAL 全集
const range = quick ? "0-3" : "0-7";
run("jsuite(EMU_RANGE=" + range + ")", [harness, "jsuite"], { env: { EMU_RANGE: range } });

// 2) mkey: MASTER.SECRET 四保管者+导入 双三元组确定性
run("mkey", [harness, "mkey"]);

// 3) skey: SESSION-KEY 签发→导入→会话签名 验签
run("skey", [harness, "skey"]);

// 4) emuadmin: licence 递减耗尽(进程内 Admin-1000, ~999)
run("emuadmin(licence)", [harness, "emuadmin", "0"]);

// 5) corpus: 编译器/词法边界语料(H-07 负立即数等)
run("corpus", [harness, "corpus"]);

// 5b) pkeyself: RockeySign/RockeyDecrypt 接线冒烟(X509 CA 所需原语)
run("pkeyself", [harness, "pkeyself", "0"]);

// 5c) x509ext: X509 v3 扩展构建器 DER 冒烟
run("x509ext", [harness, "x509ext", "0"]);

// 5d) worldevent: "完美 (NaN) 世界事件"看门狗(以提交 hash 为 nonce 的判据, 见 js/jsWorldEvent.js)
//     判据 Magic=(H0*256+H1)&((1<<kBits)-1) == 42; reserve ⇒ 命中即保留完美词缀 ⇒ Perfect()=NaN。
//     要求整个历史触发 <= 1 次(>1 时 worldevent audit 退出码非 0 ⇒ 本项 FAIL), 命中时打印醒目通知。
{
  const kBits = process.env.CI_WORLDEVENT_KBITS || "18";
  /* RKEY_WORLDEVENT_GIT=1 ⇒ 命中时把世界事件写进 README.md 与 git log(用户要求: 尽可能多的地方留痕);
   * RKEY_WORLDEVENT_CI=1  ⇒ **完美事件时允许世界线分裂**(建 world_limit_* 与 world_atomic_* 两条主世界分支) */
  const r = run(`worldevent(kBits=${kBits}, reserve)`, [harness, "worldevent", "audit", kBits, "reserve"], {
    env: {
      RKEY_WORLDEVENT_GIT: process.env.CI_WORLDEVENT_GIT || "1",
      RKEY_WORLDEVENT_CI: process.env.CI_WORLDEVENT_CI || "1",
    },
  });
  /* 命中"世界事件"时**无论 PASS/FAIL 都回显**通知(用户要求: 命中即通知) */
  const hit = ((r.stdout || "") + (r.stderr || ""))
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => /世界事件|完美事件|世界线分裂|world_(limit|atomic)_/.test(l));
  for (const l of hit) console.log(`[ci]   ${l}`);
}

// G) 四条门控(用户 2026-09-14 指定, 实现见 gates.cjs 头注释):
//    G1 gpg 密钥状态 / G2 明文无被禁 trailer 字面量 / G3 提交签名全部有效 / G4 aginx.h 署名
//    注: G1/G3 找不到可用 gpg 时**计为失败**(gpg 缺失时 %G? 会把已签名提交也报成 N ⇒ 假绿), 不 skip。
failed += require("./gates.cjs").runGates();

// H) atomic (RV32IM 解释器世界) 的宿主侧检查 —— **默认跳过**(用户 2026-09-18 定: 挂在 make ci 但默认跳过;
//    实现与理由见 tools/rockey/ATOMC/ci/atomic-tests.cjs 头注释):
//    显式执行: `make test-atomic` 或 `CI_ATOMIC=1 node tools/rockey/ATOMC/ci/atomic-tests.cjs`。
//    ⚠ 环境缺编译器时 runner 自己输出 SKIP 并返回 0(实测本机 Cygwin 的 g++ 起不来),
//      所以这里"PASS"里也包含"因环境缺失而跳过"这一情形 —— 明细在该 runner 的输出里。
if (process.env.CI_ATOMIC === "1") {
  run("atomic(VM_t 解释器/exit 门/实例化)", [path.join(root, "tools", "rockey", "ATOMC", "ci", "atomic-tests.cjs"), "--force"]);
} else {
  console.log("[ci] 跳过 atomic(默认跳过; CI_ATOMIC=1 或 `make test-atomic` 强制执行)");
}

// 6) TRNG 失败注入自测(需平台构建;缺失则提示)
const platDir = platformDirOf();
const trngfailName = isWindowsDir(platDir) ? "__Testing__trngfail__.exe" : "__Testing__trngfail__";
const trngfail = path.join(root, ".bin", platDir, trngfailName);
if (fs.existsSync(trngfail)) {
  const r = spawnSync(trngfail, [], { cwd: root, encoding: "utf8", timeout: 120000 });
  const ok = r.status === 0 && !r.error;
  console.log(`[ci] ${ok ? "PASS" : "FAIL"} trngfail${r.status === null ? " (timeout)" : ""}`);
  if (!ok) {
    ++failed;
    const tail = ((r.stdout || "") + (r.stderr || "")).split(/\r?\n/).filter(Boolean).slice(-8).join("\n  ");
    if (tail) console.log(`[ci]   ...${tail}`);
  }
} else {
  const buildCmd = isWindowsDir(platDir) ? "make windows" : "make linux";
  const m = `[ci] 跳过 trngfail: 未构建(${path.relative(root, trngfail)}), 先 ${buildCmd}`;
  if (strict) {
    console.error(m);
    failed = failed + 1;
  } else {
    console.log(m);
  }
}

function isWindowsDir(dir) {
  return /windows/.test(dir || "");
}

function platformDirOf() {
  // 宿主架构 + 平台前缀(amd64/aarch64 × windows/linux), 使 aarch64 宿主也能找到自己的产物目录
  const arch = process.arch === "arm64" ? "aarch64" : process.arch === "x64" ? "amd64" : process.arch;
  const host = process.platform === "win32" ? "windows" : "linux";
  const dirs = fs.existsSync(path.join(root, ".bin"))
    ? fs.readdirSync(path.join(root, ".bin")).filter((d) => /^(amd64|aarch64)-/.test(d))
    : [];
  const want = process.env.CI_PLATFORM;
  if (want && dirs.includes(want)) return want;
  // 优先"本机架构 + 宿主平台", 其次宿主平台, 再退回任一 windows/linux 产物
  return (
    dirs.find((d) => d.startsWith(`${arch}-${host}-`)) ||
    dirs.find((d) => new RegExp(`-${host}-release$`).test(d)) ||
    dirs.find((d) => /windows-release$/.test(d)) ||
    dirs.find((d) => /linux-release$/.test(d)) ||
    dirs[0] ||
    ""
  );
}

fs.mkdirSync(logDir, { recursive: true });
const logFile = path.join(logDir, `ci-${new Date().toISOString().replace(/[:T]/g, "-").slice(0, 19)}.log`);
fs.writeFileSync(logFile, `ci quick: ${failed ? "FAILED" : "OK"} (failed=${failed})\n`);
console.log(`[ci] done failed=${failed} log=${logFile}`);
process.exit(failed ? 1 : 0);

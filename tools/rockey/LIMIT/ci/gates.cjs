#!/usr/bin/env node
/*! 四条 CI 门控 G1..G4(tools/rockey/LIMIT/ci/gates.cjs)
 *! 用户 2026-09-14 指定; 由 run-ci.cjs 在同一次快速回归里调用, 也可单独运行:
 *!   node tools/rockey/LIMIT/ci/gates.cjs
 *!
 *!   G1 gpg 密钥状态        —— 本机钥匙串必须恰为指定的两把主钥(指纹/uid/算法/用途/未过期 + 有私钥与加密子钥)
 *!   G2 明文无被禁 trailer  —— 跟踪文件与本仓提交信息中不得出现该 trailer(历史 8 条在册白名单内)
 *!   G3 提交签名全部有效    —— 带签名的提交必须为 Good(在册的 1 条不可本地校验提交除外)
 *!   G4 aginx.h 署名        —— Interface/aginx.h 的署名行必须存在且恰出现一次(草案占位不得残留)
 *!
 *! 关键设计 —— **gpg 缺失即失败, 不 skip**: 实测 gpg 不可用时 `git log --format=%G?` 会把**已签名**的提交
 *! 也报成 `N`, 从而制造"签名全部有效"的假绿。故 G1/G3 找不到可用 gpg 时**计为失败**并给出修复指引
 *! (`RKEY_GPG=<路径>` 或 `git config gpg.program <路径>`), 绝不静默通过。
 *! 范围: G2 扫父仓 + Build 子模块(我们的 fork 工具); base 子模块属上游, 不纳入(其改动不受本仓控制)。
 */
"use strict";
const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..", "..", "..", "..");

/* 被禁 trailer 字面量: 由片段拼出, 使本文件自身不含该字面量(G2 会扫到它自己) */
const BANNED_TRAILER = ["co", "authored", "by"].join("-");

/* 在册历史(用户 2026-09-11 决定: 不回填历史): 2026-09-03~07 的 8 条提交信息含该 trailer */
const TRAILER_ALLOWLIST = new Set([
  "56b8990787089d9612819b0268ee2b0ee2f88c9e",
  "1ac7e8200ac1cf60835b479e7a10e495d1649f6a",
  "d3ec2435f5ed3e359e54ad42c5662eabe5a90cfb",
  "e3c7283f271089010994b8098d08ff0cffe141af",
  "31f41fe7aa301dd62ec90ed724ac31d1162a3c58",
  "bc2d8853667c020480372c6113e3632c0d9e49c3",
  "46e259d53a181af82c392f29b13166c76c86e71b",
  "208257fed5dbda027d0efb04c8050e9918ed9bfc",
]);

/* 在册的"签名不可本地校验"提交(用户 2026-09-14 决定不改写历史): 2024-08-30 由 Gitee 代提交
 * (committer=noreply@gitee.com), 签名钥 63A71EA590E6E55E5ADED924173E9B9CA92EEF8F(RSA) 不在本地
 * 钥匙串 ⇒ gpg 报 "Can't check signature: No public key"(git 记为 E)。导入该上游公钥后可删除本条。 */
const SIGNATURE_EXCEPTIONS = new Map([
  ["8719021c55c17a7b8e49eae370e462458f46a30e", "2024-08-30 Gitee 代提交, 本地缺上游 RSA 公钥 63A71EA5…"],
]);

/* 期望的 gpg 主钥(用户 2026-09-14 给出的清单): 指纹 + 算法/长度 + uid; 另要求存在私钥 */
const EXPECTED_KEYS = [
  { fpr: "9F7E6E5B34545A7D1031A79BC489989197876293", bits: 3072, algo: "1", uid: "LiangLI <admin@rlang.xyz>" },
  { fpr: "B9C754FC4ABDFD3150593856BCE591B95E51D027", bits: 255, algo: "22", uid: "LiangLI <liangl79@gmail.com>" },
];

/* aginx.h 署名行(用户 2026-09-14 给定的最终文本): 必须恰出现一次 */
const AGINX_SIGNATURE =
  /感谢他对我在学习AI编程的启蒙阶段给与的帮助,\s*Assisted-by:\s*Claude Code \+ GLM 5\.3 \+ deepseek-v4-flash/g;
const AGINX_TODO = /TODO: 待用户提供文本|TODO: 待用户提供签名文本/;

let failures = 0;
function pass(name, details = []) {
  console.log(`[ci] PASS ${name}`);
  for (const d of details) console.log(`[ci]   ${d}`);
}
function fail(name, details = []) {
  ++failures;
  console.log(`[ci] FAIL ${name}`);
  for (const d of details) console.log(`[ci]   ${d}`);
}

function git(dir, args, opts = {}) {
  return spawnSync("git", ["-C", dir, ...args], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
    timeout: opts.timeout || 600000,
    ...opts,
  });
}

/* 定位可用的 gpg: RKEY_GPG > git gpg.program > PATH(gpg/gpg2) > Windows 常见安装路径。
 * 逐个用 `--version` 实跑探测 —— PATH 上可能是坏掉的 Cygwin gpg(实测 CreateFileMapping 拒绝)。 */
function resolveGpg() {
  const cands = [];
  if (process.env.RKEY_GPG) cands.push(process.env.RKEY_GPG);
  const cfg = git(root, ["config", "--get", "gpg.program"]);
  if (cfg.status === 0 && (cfg.stdout || "").trim()) cands.push(cfg.stdout.trim());
  cands.push("gpg", "gpg2");
  if (process.platform === "win32") {
    const pf = process.env.ProgramFiles || "C:\\Program Files";
    const pf86 = process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)";
    cands.push(path.join(pf, "Git", "usr", "bin", "gpg.exe"));
    cands.push(path.join(pf86, "GnuPG", "bin", "gpg.exe"));
    if (process.env.LOCALAPPDATA) cands.push(path.join(process.env.LOCALAPPDATA, "Programs", "GnuPG", "bin", "gpg.exe"));
  }
  for (const c of cands) {
    if (!c) continue;
    const r = spawnSync(c, ["--version"], { encoding: "utf8", timeout: 30000 });
    if (r.status === 0 && /GnuPG/i.test(r.stdout || "")) return c;
  }
  return null;
}

function gpgColons(gpg, listArg) {
  const r = spawnSync(gpg, ["--with-colons", "--fixed-list-mode", listArg], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, timeout: 60000 });
  if (r.status !== 0) return null;
  return parseColons(r.stdout || "");
}

/* 解析 gpg --with-colons: 以主钥指纹为键(pub/sec 各自一份) */
function parseColons(text) {
  const records = [];
  let cur = null;
  let lastSub = null;
  let lastWasPrimary = false;
  for (const line of text.split(/\r?\n/)) {
    if (!line) continue;
    const f = line.split(":");
    switch (f[0]) {
      case "pub":
      case "sec":
        cur = { type: f[0], validity: f[1], bits: +f[2], algo: f[3], created: +f[5], expires: +f[6], caps: f[11] || "", uid: "", fpr: "", subs: [] };
        lastSub = null;
        lastWasPrimary = true;
        records.push(cur);
        break;
      case "sub":
      case "ssb":
        lastSub = { type: f[0], bits: +f[2], algo: f[3], expires: +f[6], caps: f[11] || "", fpr: "" };
        lastWasPrimary = false;
        if (cur) cur.subs.push(lastSub);
        break;
      case "fpr":
        if (lastWasPrimary && cur) cur.fpr = f[9];
        else if (lastSub) lastSub.fpr = f[9];
        break;
      case "uid":
        if (cur && !cur.uid) cur.uid = f[9];
        break;
      default:
        break;
    }
  }
  const byFpr = new Map();
  for (const v of records) if (v.fpr) byFpr.set(v.fpr, v);
  return byFpr;
}

function fmtExpiry(rec) {
  return rec && rec.expires ? new Date(rec.expires * 1000).toISOString().slice(0, 10) : "(无)";
}

/* G1: 本机钥匙串必须恰为用户指定的两把主钥 */
function gate1GpgKeys(gpg) {
  const name = "G1 gpg 密钥状态";
  if (!gpg) {
    return fail(name, [
      "找不到可用 gpg ⇒ 无法确认密钥状态(按设计**计为失败**, 不 skip)",
      "修复: 设 RKEY_GPG=<gpg 路径>, 或 git config gpg.program <路径>",
      "提示: Git 自带的 gpg 通常位于 C:\\Program Files\\Git\\usr\\bin\\gpg.exe",
    ]);
  }
  const pub = gpgColons(gpg, "--list-keys");
  const sec = gpgColons(gpg, "--list-secret-keys");
  if (!pub || !sec) return fail(name, ["gpg --list-keys / --list-secret-keys 执行失败"]);

  const now = Math.floor(Date.now() / 1000);
  const problems = [];
  const ok = [];
  for (const want of EXPECTED_KEYS) {
    const tag = want.fpr.slice(-8);
    const mine = [];
    const p = pub.get(want.fpr);
    const s = sec.get(want.fpr);
    if (!p) {
      problems.push(`${tag} 公钥缺失(不在钥匙串)`);
      continue;
    }
    if (p.bits !== want.bits || p.algo !== want.algo) mine.push(`${tag} 算法/长度不符: 实测 ${p.algo}/${p.bits}, 期望 ${want.algo}/${want.bits}`);
    if (!p.uid.includes(want.uid)) mine.push(`${tag} uid 不符: 实测 ${p.uid || "(无)"}, 期望 ${want.uid}`);
    if (!/s/i.test(p.caps) || !/c/i.test(p.caps)) mine.push(`${tag} 主钥用途缺 SC: 实测 ${p.caps}`);
    if (!p.expires || p.expires <= now) mine.push(`${tag} 主钥已过期或未设有效期: ${fmtExpiry(p)}`);
    if (!p.subs.some((x) => /e/i.test(x.caps) && x.expires > now)) mine.push(`${tag} 缺未过期的 [E] 加密子钥`);
    if (!s) mine.push(`${tag} 私钥缺失(--list-secret-keys 无此指纹)`);
    else if (!s.expires || s.expires <= now) mine.push(`${tag} 私钥已过期: ${fmtExpiry(s)}`);
    if (mine.length) problems.push(...mine);
    else ok.push(`${tag} ${p.algo}/${p.bits} ${p.uid} 到期 ${fmtExpiry(p)} 私钥✓ SC✓ E子钥✓`);
  }
  if (problems.length) fail(name, [...problems, `gpg = ${gpg}`]);
  else pass(name, [...ok, `gpg = ${gpg}`]);
}

/* G2: 跟踪文件 + 提交信息中不得出现被禁 trailer 字面量(在册历史除外) */
function gate2BannedTrailer() {
  const name = "G2 明文无被禁 trailer 字面量";
  const problems = [];
  for (const { dir, label } of [
    { dir: root, label: "本仓" },
    { dir: path.join(root, "Build"), label: "Build 子模块" },
  ]) {
    if (!fs.existsSync(dir)) {
      problems.push(`${label} 路径不存在: ${dir}`);
      continue;
    }
    const g = git(dir, ["grep", "-i", "-I", "-l", "-e", BANNED_TRAILER]);
    if (g.status === 0) problems.push(`${label} 跟踪文件命中: ${(g.stdout || "").trim().split(/\r?\n/).join(", ")}`);
    else if (g.status !== 1) problems.push(`${label} git grep 异常(status=${g.status})`);

    const lg = git(dir, ["log", "--all", "--format=%H%x1f%B%x1e"]);
    if (lg.status !== 0) {
      problems.push(`${label} git log 异常`);
      continue;
    }
    const hits = [];
    for (const rec of (lg.stdout || "").split("\x1e")) {
      const sep = rec.indexOf("\x1f");
      if (sep < 0) continue;
      const hash = rec.slice(0, sep).trim();
      if (!/^[0-9a-f]{40}$/.test(hash)) continue;
      if (!rec.slice(sep + 1).toLowerCase().includes(BANNED_TRAILER)) continue;
      if (dir === root && TRAILER_ALLOWLIST.has(hash)) continue;
      hits.push(hash.slice(0, 12));
    }
    if (hits.length) problems.push(`${label} 提交信息命中(非在册): ${hits.join(", ")}`);
  }
  if (problems.length) fail(name, problems);
  else
    pass(name, [
      `在册历史: ${TRAILER_ALLOWLIST.size} 条(2026-09-03~07, 用户决定保留不动)`,
      "扫描范围: 本仓 + Build 子模块的跟踪文件与提交信息(base 属上游, 不纳入)",
    ]);
}

/* G3: 凡带签名的提交必须为 Good; 并防"gpg 缺失 ⇒ 全 N"的假绿 */
function signedHeaderCount() {
  const list = git(root, ["log", "--all", "--format=%H"]);
  if (list.status !== 0) return -1;
  const hashes = (list.stdout || "").split(/\r?\n/).filter(Boolean);
  if (!hashes.length) return 0;
  const batch = git(root, ["cat-file", "--batch"], { input: hashes.join("\n") + "\n" });
  if (batch.status !== 0) return -1;
  return ((batch.stdout || "").match(/^gpgsig /gm) || []).length;
}

function gate3Signatures(gpg) {
  const name = "G3 提交签名全部有效";
  if (!gpg) {
    return fail(name, [
      "找不到可用 gpg ⇒ 无法校验签名(按设计**计为失败**, 不 skip)",
      "原因: gpg 缺失时 `git log --format=%G?` 会把已签名的提交也报成 N ⇒ 假绿",
      "修复: 设 RKEY_GPG=<gpg 路径>, 或 git config gpg.program <路径>",
    ]);
  }
  const r = git(root, ["-c", `gpg.program=${gpg}`, "log", "--all", "--format=%H%x1f%G?%x1f%GS%x1e"]);
  if (r.status !== 0) return fail(name, [`git log --format=%G? 失败: ${(r.stderr || "").trim().slice(0, 200)}`]);

  const tally = {};
  const bad = [];
  for (const rec of (r.stdout || "").split("\x1e")) {
    const f = rec.split("\x1f");
    if (!/^[0-9a-f]{40}$/.test((f[0] || "").trim())) continue;
    const hash = f[0].trim();
    const code = (f[1] || "").trim();
    tally[code] = (tally[code] || 0) + 1;
    if (code === "G" || code === "N") continue;
    if (SIGNATURE_EXCEPTIONS.has(hash)) continue;
    bad.push(`${hash.slice(0, 12)} ${code} ${(f[2] || "").trim().slice(0, 60)}`);
  }

  const classified = Object.entries(tally).reduce((a, [k, v]) => (k === "N" ? a : a + v), 0);
  const headers = signedHeaderCount();
  const problems = bad.map((b) => `签名不合法/不可校验: ${b}`);
  if (headers >= 0 && headers > classified) {
    problems.push(`gpg 未真正校验: 带 gpgsig 头部的提交 ${headers} 条 > %G? 判为有签名的 ${classified} 条 ⇒ 结果不可信`);
  }
  const detail = [
    `tally: ${Object.entries(tally).sort().map(([k, v]) => `${k}=${v}`).join(" ")}`,
    `在册不可校验: ${SIGNATURE_EXCEPTIONS.size} 条(2024-08-30 Gitee 代提交, 本地缺上游公钥; 导入后可移除)`,
  ];
  if (problems.length) fail(name, [...problems, ...detail]);
  else pass(name, detail);
}

/* G4: aginx.h 署名行必须恰出现一次, 且宏对两分支齐备 */
function gate4AginxSignature() {
  const name = "G4 aginx.h 署名";
  const rel = path.join("Interface", "aginx.h");
  const p = path.join(root, rel);
  if (!fs.existsSync(p)) return fail(name, [`缺失: ${rel}`]);
  const text = fs.readFileSync(p, "utf8");
  const n = (text.match(AGINX_SIGNATURE) || []).length;
  const problems = [];
  if (n !== 1) problems.push(`署名行出现 ${n} 次(应为恰 1 次)`);
  if (AGINX_TODO.test(text)) problems.push("草案占位残留: TODO: 待用户提供签名文本");
  if (!text.includes("#define AGINX_DECLARE_MACHINE namespace machine {")) problems.push("缺 C++ 分支: #define AGINX_DECLARE_MACHINE namespace machine {");
  if (!text.includes("#define AGINX_DECLARE_END }")) problems.push("缺 C++ 分支: #define AGINX_DECLARE_END }");
  if (!/^#define AGINX_DECLARE_MACHINE$/m.test(text)) problems.push("缺 C 分支空定义: #define AGINX_DECLARE_MACHINE");
  if (!/^#define AGINX_DECLARE_END$/m.test(text)) problems.push("缺 C 分支空定义: #define AGINX_DECLARE_END");
  if (problems.length) fail(name, problems);
  else pass(name, [`署名行 1 次; 宏对 C++/C 两分支齐备(${rel})`]);
}

function runGates({ quietHeader = false } = {}) {
  failures = 0;
  if (!quietHeader) console.log("[ci] 门控 G1..G4(用户 2026-09-14 指定)");
  const gpg = resolveGpg();
  console.log(`[ci]   gpg = ${gpg || "(未找到可用 gpg)"}`);
  gate1GpgKeys(gpg);
  gate2BannedTrailer();
  gate3Signatures(gpg);
  gate4AginxSignature();
  return failures;
}

module.exports = { runGates, resolveGpg };

if (require.main === module) process.exit(runGates({}) ? 1 : 0);

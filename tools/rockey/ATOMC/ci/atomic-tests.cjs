#!/usr/bin/env node
/*! atomic (RV32IM 解释器世界) 的**宿主侧**检查运行器 —— tools/rockey/ATOMC/ci/atomic-tests.cjs
 *
 *! 为什么需要它: `atomic/tests/` 里的检查**不属于任何构建产物**(它们检查的是 VM_t 的语义),
 *! 早先只有 AI 文档里手抄的命令行 ⇒ 只会在有人记得的时候才跑。本文件把这些命令行固化成一条:
 *
 *!   node tools/rockey/ATOMC/ci/atomic-tests.cjs      (= make test-atomic, **强制执行**)
 *
 *! 覆盖的检查 (四个纯宿主检查; 都不需要 rv32im 交叉工具链):
 *!   ① atomic/tests/instantiate.cc        —— 语法期: 显式实例化 ⇒ 逼编译器检查 VM_t 全部成员函数体
 *!                                           (g++ 与 clang++ **各跑一次**; 编译器的 optimize 属性差异就在这里露头)
 *!   ② atomic/tests/interpreter-smoke.cc   —— 运行期: 真 VM_t 上**十规程 97 处 CHECK** (含 exit GATE 判别;
 *!                                           2026-09-18 门号公式由钳制改取模折叠后同步更新 + 新增 128 门号全可达)
 *!   ③ atomic/tests/gate-exit-compat.cc    —— 运行期: exit 门**两端常量/算术相容** (18 用例 + 折叠性质与均匀性)
 *!   ④ atomic/tests/exit-gate-map.cc       —— 运行期: 门号映射的**规范与性质** (值域/周期 128/全可达/严格均匀;
 *!                                           2026-09-18 用户改版"取模折叠"后新增; 见文件头"第三份副本"的取舍)
 *!
 *! 不在本运行器里 (各有前置条件, 见 atomic/tests/README.md):
 *!   - atomic/ai-doc/checks/varargs/    需要 **rv32im-atomic-rockey 交叉工具链** (真 guest ELF 端到端)
 *!   - atomic/doc/isa-check.cc          被编进 atomic 库, 但"运行它"要一个宿主板级; 尚未接线
 *
 *! 跳过语义 (用户 2026-09-18 定: "挂在 make ci 但默认跳过"):
 *!   - **默认跳过** (除非 CI_ATOMIC=1 或命令行 --force) —— 因为 make ci 会被 .githooks 在每次
 *!     squash merge/提交后自动跑, 不该每次都去编 C++;
 *!   - 显式 `make test-atomic` 会带上 CI_ATOMIC=1 ⇒ 用户主动调用时**永远真跑**, 不受默认值影响;
 *!   - 要改成"make ci 默认就跑": 把下面 DEFAULT_SKIP 置 false (一行)。
 *!
 *! **环境缺失算跳过, 不算失败** (与 gates.cjs 的 G1/G3 "fail-closed" 相反, 这是**有意**的):
 *!   本机的 Cygwin 就实测过 g++ 根本起不来 (`*** fatal error - CreateFileMapping ..., Win32 error 5.`)
 *!   ⇒ 判定"跑不了"时必须给出**可见的** SKIP 与原因, 绝不静默变绿也不误报红。
 *
 *! 退出码: 0 = 无失败 (含跳过); 1 = 有检查真的失败; 2 = 用法错误。
 */
"use strict";

const { spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const root = path.resolve(__dirname, "..", "..", "..", "..");
const testsDir = path.join(root, "atomic", "tests");
const includeDirs = [root, path.join(root, "atomic", "include")];

/* 用户裁定: 挂在 make ci 但默认跳过。要改成默认执行: 把这里改成 false。 */
const DEFAULT_SKIP = true;

const argv = process.argv.slice(2);
if (argv.includes("-h") || argv.includes("--help")) {
  console.log("用法: node tools/rockey/ATOMC/ci/atomic-tests.cjs [--force] [--list] [--cc=<编译器>] [--keep]");
  console.log("  --force      强制执行 (等价 CI_ATOMIC=1)");
  console.log("  --list       只列出检查清单与前置条件");
  console.log("  --cc=<cc>    指定宿主 C++ 编译器 (缺省按 g++ → clang++ 探测)");
  console.log("  --keep       保留编译出的临时可执行文件 (调试用)");
  process.exit(0);
}
const force = argv.includes("--force") || process.env.CI_ATOMIC === "1";
const listOnly = argv.includes("--list");
const keep = argv.includes("--keep");
const ccOverride = (argv.find((a) => a.startsWith("--cc=")) || "").slice(5);

const commonFlags = ["-std=c++17", "-Wall", "-Werror", ...includeDirs.map((d) => `-I${d}`)];

/* ---------------- 小工具 ---------------- */

/* 编译器"起不来"的判据: 没能正常退出, 或输出里带运行时崩溃的痕迹。
 * ⚠ 实测 (本机 Cygwin): `g++ --version` 会以 `*** fatal error - CreateFileMapping ..., Win32 error 5.`
 * 结束 —— 那是环境坏了, 不是我们的代码有问题。 */
function looksLikeBrokenEnv(r) {
  const text = `${r.stdout || ""}\n${r.stderr || ""}`;
  if (r.error) return `${r.error.code || r.error.message}`;
  if (r.signal) return `signal ${r.signal}`;
  if (r.status === null) return "进程未能正常结束";
  if (/\*\*\* fatal error|CreateFileMapping|Permission denied|command not found|No such file or directory/i.test(text))
    return text.trim().split(/\r?\n/)[0].slice(0, 160);
  return null;
}

function run(cmd, args, opts = {}) {
  return spawnSync(cmd, args, {
    cwd: opts.cwd || root,
    encoding: "utf8",
    timeout: opts.timeout || 900000,
    maxBuffer: 64 * 1024 * 1024,
  });
}

let failures = 0;
let skipped = 0;
let passed = 0;
const usedCompilers = new Set();

function pass(name, details = []) {
  ++passed;
  console.log(`[atomic-ci] PASS ${name}`);
  for (const d of details) console.log(`[atomic-ci]   ${d}`);
}
function fail(name, details = []) {
  ++failures;
  console.log(`[atomic-ci] FAIL ${name}`);
  for (const d of details) console.log(`[atomic-ci]   ${d}`);
}
function skip(name, why, howto = []) {
  ++skipped;
  console.log(`[atomic-ci] SKIP ${name} —— ${why}`);
  for (const h of howto) console.log(`[atomic-ci]   ${h}`);
}

/* 探测可用的宿主 C++ 编译器 (实跑 `--version`, 不信任 PATH 上存在即可用) */
function resolveCompilers() {
  if (ccOverride) return [ccOverride];
  const cands = [];
  if (process.env.ATOMIC_HOST_CXX) cands.push(process.env.ATOMIC_HOST_CXX);
  cands.push("g++", "clang++", "c++");
  if (process.platform === "win32") {
    /* Cygwin / Git-Bash 常见的绝对路径 (PATH 上未必有) */
    for (const p of ["C:\\cygwin64\\bin\\g++.exe", "C:\\cygwin\\bin\\g++.exe"])
      if (fs.existsSync(p)) cands.push(p);
  }
  const out = [];
  for (const c of cands) {
    const r = run(c, ["--version"]);
    const broken = looksLikeBrokenEnv(r);
    if (r.status === 0 && !broken) out.push({ cc: c, note: (r.stdout || "").split(/\r?\n/)[0].trim() });
    else if (broken) console.log(`[atomic-ci]   探测 ${c}: 不可用 (${broken})`);
  }
  return out;
}

/* 编一个 TU 到临时 exe; 返回 { status: "ok"|"env"|"error", exe?, notes: [] } */
function buildExe(cc, tu, extra = []) {
  const exe = path.join(os.tmpdir(), `atomic-ci-${path.basename(tu, ".cc")}-${process.pid}${process.platform === "win32" ? ".exe" : ""}`);
  const r = run(cc, [...commonFlags, ...extra, "-o", exe, path.join(testsDir, tu)]);
  const broken = looksLikeBrokenEnv(r);
  if (broken || (r.status !== 0 && !(r.stderr || "").trim() && !r.error && !r.signal)) {
    /* 编译器自己起不来/崩了 (而不是我们的代码有问题): broken 已指明原因;
       后一种情形是"非零退出但连一行诊断都没有" —— 正常编译器报错一定带诊断 ⇒ 判为环境问题 */
    try { fs.rmSync(exe, { force: true }); } catch (_) { /* ignore */ }
    return { status: "env", notes: [`${cc}: ${broken || "无诊断输出但返回 " + r.status}`] };
  }
  if (r.status !== 0) {
    const diag = `${r.stdout || ""}${r.stderr || ""}`.trim().split(/\r?\n/).slice(0, 12);
    try { fs.rmSync(exe, { force: true }); } catch (_) { /* ignore */ }
    return { status: "error", notes: diag };
  }
  return { status: "ok", exe };
}

function cleanup(exe) {
  if (keep || !exe) return;
  try { fs.rmSync(exe, { force: true }); } catch (_) { /* ignore */ }
}

/* ---------------- 检查清单 ---------------- */

const checks = [
  {
    name: "instantiate (语法期: VM_t 全部成员函数体)",
    file: "instantiate.cc",
    kind: "syntax", // 每个可用编译器各跑一次
    why: "宿主 C++ 编译器不可用 (g++/clang++; 可用 ATOMIC_HOST_CXX 或 --cc= 指定)",
    howto: ["本文件同时充当 clang++ 的 `optimize` 属性 (GCC 专属) 差异探针, 所以两个编译器都要跑"],
  },
  {
    name: "interpreter-smoke (运行期: 十规程 97 处 CHECK)",
    file: "interpreter-smoke.cc",
    kind: "run",
    why: "需要一个能编译+链接+运行的宿主 C++ 编译器",
    howto: [],
  },
  {
    name: "gate-exit-compat (运行期: exit 门两端相容 + 折叠均匀性)",
    file: "gate-exit-compat.cc",
    kind: "run",
    why: "需要一个能编译+链接+运行的宿主 C++ 编译器",
    howto: [],
  },
  {
    name: "exit-gate-map (运行期: 门号映射规范: 值域/周期/全可达/均匀)",
    file: "exit-gate-map.cc",
    kind: "run",
    why: "需要一个能编译+链接+运行的宿主 C++ 编译器",
    howto: ["门号公式 2026-09-18 由钳制改为取模折叠 (v & 0x7f) - 64; 改公式时本文件(第三份副本)必须同步"],
  },
];

/* ---------------- 主流程 ---------------- */

console.log(`[atomic-ci] root=${root}`);
if (!fs.existsSync(testsDir)) {
  console.error(`[atomic-ci] 缺检查目录: ${testsDir}`);
  process.exit(1);
}

if (listOnly) {
  for (const c of checks) console.log(`[atomic-ci]   ${c.file}  ${c.kind === "run" ? "(编+链接+运行)" : "(仅语法)"}`);
  console.log("[atomic-ci]   不在本运行器: ai-doc/checks/varargs (需 rv32im 交叉工具链), doc/isa-check.cc (尚未接线)");
  process.exit(0);
}

if (!force && DEFAULT_SKIP) {
  skip("全部 atomic 检查", "默认跳过 (用户 2026-09-18 定: 挂在 make ci 但默认跳过)");
  console.log("[atomic-ci]   强制执行: make test-atomic   或 CI_ATOMIC=1 node tools/rockey/ATOMC/ci/atomic-tests.cjs");
  console.log("[atomic-ci] 小结: PASS=0 FAIL=0 SKIP=1");
  process.exit(0);
}

const compilers = resolveCompilers();
if (!compilers.length) {
  const why = ccOverride
    ? `指定的编译器不可用: ${ccOverride}`
    : "PATH 上没有可用的 g++/clang++/c++ (或用 --cc=<编译器> / ATOMIC_HOST_CXX 指定)";
  for (const c of checks) skip(c.name, why, c.howto);
  console.log(`[atomic-ci] 小结: PASS=0 FAIL=0 SKIP=${skipped} (环境缺失 ⇒ 跳过, 不算失败)`);
  process.exit(0);
}

/* syntax 类: 每个编译器各跑一遍 (本文件的用意之一就是同时看 GCC 与 clang) */
for (const c of checks.filter((x) => x.kind === "syntax")) {
  const notes = [];
  let hardFail = false;
  let brokeCount = 0;
  for (const { cc, note } of compilers) {
    const r = run(cc, [...commonFlags, "-fsyntax-only", path.join(testsDir, c.file)]);
    const broken = looksLikeBrokenEnv(r);
    if (broken) {
      ++brokeCount;
      notes.push(`${cc} (${note}): 不可用 —— ${broken}`);
      continue;
    }
    usedCompilers.add(cc);
    if (r.status !== 0) {
      hardFail = true;
      fail(`${c.name} [${cc}]`, `${r.stdout || ""}${r.stderr || ""}`.trim().split(/\r?\n/).slice(0, 12));
      continue;
    }
    notes.push(`${cc} (${note}) ✓`);
  }
  if (hardFail) continue; /* 已按编译器逐个报错 */
  if (brokeCount === compilers.length) skip(c.name, "所有候选编译器都不可用", notes);
  else pass(c.name, notes);
}

/* run 类: 用**第一个能编过**的编译器编+链接+运行。
 * 编译失败 ⇒ 直接失败 (不换编译器重试: `-Wall -Werror` 下这是真的代码/头问题);
 * 编译器起不来 (env) ⇒ 试下一个; 全都不行 ⇒ 跳过。 */
for (const c of checks.filter((x) => x.kind === "run")) {
  const notes = [];
  let done = false;
  for (const { cc, note } of compilers) {
    const b = buildExe(cc, c.file);
    if (b.status === "env") {
      notes.push(`${cc}: 不可用 —— ${b.notes.join(" ")}`);
      continue;
    }
    if (b.status === "error") {
      fail(c.name, [`${cc} (${note}) 编译失败:`, ...b.notes]);
      done = true;
      break;
    }
    usedCompilers.add(cc);
    const r = run(b.exe, []);
    const broken = looksLikeBrokenEnv(r);
    cleanup(b.exe);
    if (broken) {
      notes.push(`${cc}: 编译成功但**运行**失败 —— ${broken}`);
      continue;
    }
    const tail = ((r.stdout || "") + (r.stderr || "")).trim().split(/\r?\n/);
    if (r.status !== 0) {
      fail(c.name, [
        `${cc} (${note}) 运行返回 ${r.status} (非 0)`,
        ...tail.filter(Boolean).slice(-14).map((l) => `  ${l}`),
      ]);
      done = true;
      break;
    }
    pass(c.name, [`${cc} (${note})`, ...tail.filter(Boolean).slice(-6).map((l) => `  ${l}`)]);
    done = true;
    break;
  }
  if (!done) skip(c.name, "没有任何编译器能编+跑", notes);
}

console.log(
  `[atomic-ci] 小结: PASS=${passed} FAIL=${failures} SKIP=${skipped}` +
    (usedCompilers.size ? ` (编译器: ${[...usedCompilers].join(", ")})` : "")
);
console.log("[atomic-ci] 未覆盖: varargs 端到端 (需 rv32im 交叉工具链) / doc/isa-check.cc (尚未接线)");
process.exit(failures ? 1 : 0);

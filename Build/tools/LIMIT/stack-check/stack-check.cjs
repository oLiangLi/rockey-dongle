/**
 *! 固件调用栈深度静态检查工具
 *!
 *! 原理: 编译期 -fstack-usage 产物(.su, 每函数栈帧大小) + objdump -dr 的
 *!       R_ARM_THM_CALL/R_ARM_CALL(调用)与 R_ARM_THM_JUMP24/R_ARM_JUMP24(尾调用)
 *!       重定位还原调用图, 从 app_entry 出发做全路径 DFS, 求最大栈深度与超预算路径。
 *!
 *! 预算: 2032B = 0x68000BF0(start.s Vector[0] 初始 SP) - 0x68000400(InOutBuf 顶界),
 *!       栈向下生长越过该界将静默覆写 InOutBuf 输入区(无 MPU 保护)。
 *!
 *! 豁免: OpExecute_* / OpManager_* 作为"路径终点"处理 —— 前者执行后程序立即退出,
 *!       后者为系统初始化专用(运行后设备身份变更, 运行时不包含敏感信息),
 *!       两者子树的栈深不受预算约束; 但它们的被调函数在其他路径上仍正常计入。
 *!
 *! 用法: node stack-check.cjs [选项] [map文件]    (需先 make dongle)
 *! 选项: --budget=N   栈预算字节数(默认 2032)
 *!       --exempt=P,P 豁免终点的函数名模式, 逗号分隔(默认 OpExecute,OpManager; 空串=禁用)
 *!       --top=N      最多显示 N 条违规路径(默认 10)
 *!       --prefix=S   工具链前缀(默认 arm-none-eabi-)
 *! 退出码: 0=无违规  10=存在超预算路径  2=用法/输入错误
 */
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

/* ------------------------------------------------------------------ */
/* 参数解析                                                            */
/* ------------------------------------------------------------------ */
const args = process.argv.slice(2);
let mapFile = null;
let budget = 2032;
let exemptPatterns = ["OpExecute", "OpManager"];
let topN = 10;
let prefix = "arm-none-eabi-";

for (let i = 0; i < args.length; ++i) {
  const a = args[i];
  if (a.startsWith("--budget=")) budget = parseInt(a.slice(9), 10);
  else if (a.startsWith("--exempt=")) exemptPatterns = a.slice(9) === "" ? [] : a.slice(9).split(",");
  else if (a.startsWith("--top=")) topN = parseInt(a.slice(6), 10);
  else if (a.startsWith("--prefix=")) prefix = a.slice(9);
  else if (a.startsWith("--")) usageError(`未知选项 ${a}`);
  else if (mapFile === null) mapFile = a;
  else usageError("多余的参数");
}

/* map 定位: 默认完整固件(含脚本 VM)的链接图 */
if (mapFile === null)
  mapFile = path.join(__dirname, "..", "..", "..", "..", ".bin", ".obj", "arm-RockeyARM-native-release", "RockeyTrust.map");
mapFile = path.resolve(mapFile);
if (!fs.existsSync(mapFile)) {
  console.error(`[stack-check] 找不到 map 文件: ${mapFile}\n               请先执行 make dongle`);
  process.exit(2);
}
const repoRoot = path.resolve(path.dirname(mapFile), "..", "..", "..");

/* ------------------------------------------------------------------ */
/* 1. 从 map 提取链接对象                                              */
/* ------------------------------------------------------------------ */
/* Windows/cygwin 链接器生成的 map 用 '\' 分隔路径, 先归一化为 '/' 再匹配 */
const mapText = fs.readFileSync(mapFile, "utf8").replace(/\\/g, "/");
const objSet = new Set();
for (const m of mapText.matchAll(/(\.\/\.bin\/\.obj\/[^ )]+\.o)/g)) {
  const p = path.resolve(repoRoot, m[1]);
  if (fs.existsSync(p)) objSet.add(p);
}
/* ./​.bin/.lib/<conf>/libXXX.a(member.o) → .bin/.obj/<conf>/XXX/member.o */
for (const m of mapText.matchAll(/\.\/\.bin\/\.lib\/([^ /)]+)\/lib([A-Za-z0-9_]+)\.a\(([^)]+\.o)\)/g)) {
  const p = path.join(repoRoot, ".bin", ".obj", m[1], m[2], m[3]);
  if (fs.existsSync(p)) objSet.add(p);
}
const objects = [...objSet].sort();

/* ------------------------------------------------------------------ */
/* 2. 解析 .su 帧表                                                    */
/*    行格式: file:line:col:签名\t大小\t类型                           */
/*    注意 file 可能含冒号(Windows 盘符), 用贪婪匹配取最后两组数字      */
/* ------------------------------------------------------------------ */
const suEntries = []; /* { sig, size } */
let suSkipped = 0;
for (const obj of objects) {
  const su = obj.replace(/\.o$/, ".su");
  if (!fs.existsSync(su)) continue; /* 汇编对象无 .su */
  for (const line of fs.readFileSync(su, "utf8").split("\n")) {
    const t = line.split("\t");
    if (t.length !== 3) continue;
    const m = /^(.*):(\d+):(\d+):(.*)$/.exec(t[0]);
    if (!m) continue;
    const size = parseInt(t[1], 10);
    if (!Number.isFinite(size)) {
      ++suSkipped; /* "dynamic"(alloca) —— 本工程不存在, 出现即人工核查 */
      continue;
    }
    suEntries.push({ sig: m[4], size });
  }
}

/* ------------------------------------------------------------------ */
/* 3. objdump -dr 提取调用边(重定位类型即边类型, 不解析指令)            */
/* ------------------------------------------------------------------ */
const edges = new Set(); /* "caller\x00callee" */
const nodes = new Set();
for (const obj of objects) {
  const out = spawnSync(`${prefix}objdump`, ["-dr", obj], { maxBuffer: 64 * 1024 * 1024 });
  if (out.status !== 0) {
    console.error(`[stack-check] objdump 失败: ${obj}`);
    process.exit(2);
  }
  let cur = "";
  for (const line of out.stdout.toString().split("\n")) {
    let m = /^([0-9a-f]+) <([^>]+)>:/.exec(line);
    if (m) {
      cur = m[2];
      continue;
    }
    m = /^\s*[0-9a-f]+:\s+R_ARM_(THM_)?(CALL|JUMP24)\s+(\S+)/.exec(line);
    if (m && cur) {
      const tgt = m[3].replace(/[-+][0-9].*$/, "");
      /* symbol+0x.. 为函数内跳转(循环/跳转表), 非调用 */
      if (!cur || !tgt || cur === tgt || cur.includes("+0x") || tgt.includes("+0x")) continue;
      edges.add(cur + "\x00" + tgt);
      nodes.add(cur);
      nodes.add(tgt);
    }
  }
}

/* ------------------------------------------------------------------ */
/* 4. 反修饰 + 帧匹配                                                  */
/*    .su 签名用源码类型(uint8_t/int32_t), c++filt 输出规范类型        */
/*    (unsigned char/long) —— 用 "名字(" 锚定包含 + 参数个数区分重载   */
/* ------------------------------------------------------------------ */
const nodeList = [...nodes].sort();
const demangled = {};
if (nodeList.length) {
  const out = spawnSync(`${prefix}c++filt`, { input: nodeList.join("\n"), maxBuffer: 16 * 1024 * 1024 });
  if (out.status !== 0) {
    console.error("[stack-check] c++filt 失败");
    process.exit(2);
  }
  const lines = out.stdout.toString().split("\n");
  for (let i = 0; i < nodeList.length; ++i)
    demangled[nodeList[i]] = (lines[i] || nodeList[i]).replace(/\(anonymous namespace\)/g, "{anonymous}");
}

/* 名字前缀 + 顶层参数个数(lambda 取 '::{lambda' 之前) */
function parseNameArity(d) {
  const body = d.includes("::{lambda") ? d.split("::{lambda")[0] : d;
  const i = body.indexOf("(");
  if (i < 0) return { name: body, arity: 0 };
  const name = body.slice(0, i);
  let depth = 0;
  let j = i;
  for (; j < body.length; ++j) {
    if (body[j] === "(") ++depth;
    else if (body[j] === ")") {
      if (--depth === 0) break;
    }
  }
  const params = body.slice(i + 1, j).trim();
  if (!params) return { name, arity: 0 };
  let cnt = 0;
  let pd = 0;
  for (const ch of params) {
    if (ch === "<" || ch === "(") ++pd;
    else if (ch === ">" || ch === ")") pd = Math.max(0, pd - 1);
    else if (ch === "," && pd === 0) ++cnt;
  }
  return { name, arity: cnt + 1 };
}

const suArity = suEntries.map((e) => parseNameArity(e.sig).arity);
const FRAME = {};
const unknownNodes = [];
for (const n of nodeList) {
  const { name, arity } = parseNameArity(demangled[n]);
  if (!name) {
    unknownNodes.push(n);
    continue;
  }
  const anchor = name + "(";
  let best = null;
  for (let i = 0; i < suEntries.length; ++i)
    if (suEntries[i].sig.includes(anchor) && suArity[i] === arity)
      best = best === null ? suEntries[i].size : Math.max(best, suEntries[i].size);
  if (best === null) unknownNodes.push(n);
  else FRAME[n] = best;
}

/* ------------------------------------------------------------------ */
/* 5. DFS: 最大深度 + 超预算路径                                       */
/* ------------------------------------------------------------------ */
const calls = new Map();
for (const key of edges) {
  const [a, b] = key.split("\x00");
  if (!calls.has(a)) calls.set(a, new Set());
  calls.get(a).add(b);
}

const isExempt = exemptPatterns.length
  ? (n) => exemptPatterns.some((p) => demangled[n].includes(p))
  : () => false;

function scan(useExempt) {
  const exempt = useExempt ? isExempt : () => false;
  const best = { depth: -1, path: [] };
  const violations = [];
  const onPath = new Set();
  const pathStack = [];
  function dfs(node, depth) {
    if (depth > best.depth) {
      best.depth = depth;
      best.path = pathStack.slice();
    }
    let leaf = true;
    for (const nxt of calls.get(node) || []) {
      if (onPath.has(nxt) || exempt(nxt)) continue;
      leaf = false;
      onPath.add(nxt);
      pathStack.push([nxt, FRAME[nxt] || 0]);
      dfs(nxt, depth + (FRAME[nxt] || 0));
      pathStack.pop();
      onPath.delete(nxt);
    }
    /* 路径叶节点(所有后继在环上或被豁免)且超预算 → 违规; 含未知帧的路径打标记 */
    if (leaf && depth > budget)
      violations.push({ depth, path: pathStack.slice(), unknown: pathStack.some(([n]) => !(n in FRAME)) });
  }
  onPath.add("app_entry");
  pathStack.push(["app_entry", FRAME["app_entry"] || 0]);
  dfs("app_entry", FRAME["app_entry"] || 0);
  return { best, violations };
}

/* ------------------------------------------------------------------ */
/* 6. 输出                                                             */
/* ------------------------------------------------------------------ */
function showPath(p) {
  for (const [n, sz] of p) {
    const d = demangled[n] || n;
    const short = (d.includes("::{lambda") ? d.split("::{lambda")[0] : d).split("(")[0];
    console.log(`    ${sz >= 0 ? "+" + String(sz).padStart(5) : "    ?"}  ${short}${n in FRAME ? "" : "  [帧未知,按0]"}`);
  }
}

const steady = scan(true);
const full = scan(false);

console.log(`栈深度检查: ${path.basename(mapFile)}`);
console.log(`  对象 ${objects.length} | 函数 ${nodeList.length} | 调用边 ${edges.size} | 帧匹配 ${Object.keys(FRAME).length}(未匹配 ${unknownNodes.length} 按帧0计${suSkipped ? `, .su 跳过 ${suSkipped}` : ""})`);
console.log(`  预算 ${budget}B | 豁免终点: ${exemptPatterns.join(",") || "(无)"}`);
console.log("");
console.log(`稳态最大深度(排除豁免): ${steady.best.depth}B  余量 ${budget - steady.best.depth}B`);
showPath(steady.best.path);
console.log("");
console.log(`全量最大深度(含豁免路径, 信息参考): ${full.best.depth}B`);
console.log("");

const dedupLeaf = new Set();
const shown = [];
for (const v of [...steady.violations].sort((x, y) => y.depth - x.depth)) {
  const leaf = v.path[v.path.length - 1][0];
  if (dedupLeaf.has(leaf)) continue;
  dedupLeaf.add(leaf);
  shown.push(v);
}
console.log(`稳态超预算路径(>${budget}B): ${steady.violations.length} 条${steady.violations.length ? `, 按终点去重 ${shown.length} 条` : ""}`);
for (const v of shown.slice(0, topN)) {
  console.log(`  --- ${v.depth}B (超 ${v.depth - budget}B)${v.unknown ? "  ⚠ 含未知帧, 结果可能低估" : ""} ---`);
  showPath(v.path);
}
if (steady.violations.some((v) => v.unknown)) console.log("  ⚠ 部分路径含未知帧对象(多为 aeabi/libc 汇编例程), 数值为下界");

process.exit(steady.violations.length ? 10 : 0);

function usageError(msg) {
  console.error(`[stack-check] ${msg}\n用法: node stack-check.cjs [--budget=N] [--exempt=P,P] [--top=N] [--prefix=S] [map文件]`);
  process.exit(2);
}

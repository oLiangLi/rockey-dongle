#!/usr/bin/env node
/*
 * gen.cjs —— 从 op_GATE 清单生成: guest 桩(.S) + 视图头(.h) + manifest
 *
 * 设计依据 (2026-09-17 用户裁定):
 *   - 门号两级:  pc 给"导出槽位" (jalr x0, op_GATE_<lib>__kIndex*4(zero));  t0 给组内条目号
 *   - **槽位由洗牌分配**:  用 Makefile 传来的 **4 个 32 位随机数** 做 Fisher-Yates 洗牌,
 *       在 [64, 511] 里给每个导出挑一个槽位;  [-512, -65] **留给用户私有实现**, 本工具不分配
 *   - **每次编译都重新生成** ⇒ 不追求跨编译兼容, 因此没有锁定/兼容性检查
 *   - **文件名稳定** (不含 sha1):  op_GATE_<lib>.h / op_GATE_<lib>.S
 *       —— 手写封装函数要 #include 它们, 名字里带哈希会很难写
 *   - YAML **不描述原型** (原型确定, host 从 VM_t::hart_t 读参数)
 *   - 变参门由**手写桩**内部造 va_list (清单里标 stub: hand, 本工具不生成其代码)
 *
 * 用法:
 *   node gen.cjs <list/*.yaml ...> --world-seed="0x...,0x...,0x...,0x..." [--out <dir>]
 *
 * 产物:
 *   gen/op_GATE_<lib>.S        guest 桩 (尾部调用形态; hand 形态只留占位注释)
 *   gen/op_GATE_<lib>.h        kIndex + kCount + 条目 enum + sha1 + 名字表
 *   gen/op_GATE_manifest.h     汇总 (host 分发/校验用) + 世界指纹
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const TAG = 'op-gate-export/1';                 // 摘要的格式标签 (参与哈希的首行)
const SLOT_LO = 64, SLOT_HI = 511;              // 我们自己的槽位区间 [64, 511] (0x0100-0x07FF)
const USER_LO = -512, USER_HI = -65;            // 用户私有实现的区间 (本工具不分配)
const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

/* ------------------------------------------------------------------ *
 * 极简 YAML 子集解析 (严格: 不认识的语法直接报错, 以此保证清单格式规范)
 * ------------------------------------------------------------------ */
function stripComment(s) {
  let inS = false, inD = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "'" && !inD) inS = !inS;
    else if (c === '"' && !inS) inD = !inD;
    else if (c === '#' && !inS && !inD && (i === 0 || /\s/.test(s[i - 1]))) return s.slice(0, i);
  }
  return s;
}

function parseYaml(text, file) {
  const root = {};
  const err = (n, msg) => { throw new Error(`${file}:${n + 1}: ${msg}`); };
  const scalar = (s) => {
    s = s.trim();
    if (s === '') return null;
    if ((s[0] === '"' && s.endsWith('"')) || (s[0] === "'" && s.endsWith("'"))) return s.slice(1, -1);
    if (s === 'null' || s === '~') return null;
    if (/^-?\d+$/.test(s)) return parseInt(s, 10);
    return s;
  };
  const flowMap = (s, n) => {                       // { name: x, stub: hand }
    const out = {};
    const body = s.trim().replace(/^\{/, '').replace(/\}$/, '');
    if (body.trim() === '') return out;
    for (const part of body.split(',')) {
      const i = part.indexOf(':');
      if (i < 0) err(n, `flow 映射里缺 ':' : ${part}`);
      out[part.slice(0, i).trim()] = scalar(part.slice(i + 1));
    }
    return out;
  };

  const frames = [{ indent: -1, parent: null, key: null, container: root, isSeq: false }];
  const ensure = (f, wantSeq, n) => {
    if (f.container === null) {
      f.container = wantSeq ? [] : {};
      f.isSeq = wantSeq;
      f.parent[f.key] = f.container;
    } else if (f.isSeq !== wantSeq) {
      err(n, wantSeq ? `'${f.key}' 已作为映射使用, 却出现序列项`
                     : `'${f.key}' 已作为序列使用, 却出现 'key: value'`);
    }
    return f.container;
  };

  text.split(/\r?\n/).forEach((raw, n) => {
    const line = stripComment(raw);
    if (line.trim() === '') return;
    const indent = line.match(/^\s*/)[0].length;
    const body = line.trim();

    while (frames.length > 1 && frames[frames.length - 1].indent >= indent) frames.pop();
    const f = frames[frames.length - 1];

    if (body.startsWith('- ') || body === '-') {
      const seq = ensure(f, true, n);
      const item = body.slice(1).trim();
      seq.push(item.startsWith('{') ? flowMap(item, n) : scalar(item));
      return;
    }

    const m = body.match(/^([^:]+):\s*(.*)$/);
    if (!m) err(n, `无法解析: ${body}`);
    const map = ensure(f, false, n);
    const key = m[1].trim().replace(/^["']|["']$/g, '');
    const rest = m[2].trim();
    if (rest === '') {
      frames.push({ indent, parent: map, key, container: null, isSeq: false });  // 类型待定
    } else {
      map[key] = rest.startsWith('{') ? flowMap(rest, n) : scalar(rest);
    }
  });
  return root;
}

/* ------------------------------------------------------------------ *
 * 读取清单 -> 导出集合
 *   形态 A:  <library>: { kIndex?: N, list: [name | {name, stub}] }
 *   形态 B:  library: <name> ; list: [...]
 * ------------------------------------------------------------------ */
function loadExports(file) {
  const doc = parseYaml(fs.readFileSync(file, 'utf8'), file);
  const out = [];

  const readList = (lib, node, where) => {
    if (!node || typeof node !== 'object' || !Array.isArray(node.list))
      throw new Error(`${where}: 组 '${lib}' 缺少 list`);
    const entries = node.list.map((it, i) => {
      const e = (typeof it === 'object' && it !== null) ? it : { name: it };
      if (!e.name || typeof e.name !== 'string') throw new Error(`${where}: '${lib}' 第 ${i} 项缺少 name`);
      const stub = e.stub || 'tail';
      if (stub !== 'tail' && stub !== 'hand') throw new Error(`${where}: '${lib}'.${e.name}: stub 只能是 tail|hand`);
      return { name: e.name, stub };
    });
    out.push({ library: lib, entries, file: where, pinned: (node.kIndex === undefined ? null : node.kIndex) });
  };

  if (typeof doc.library === 'string' && Array.isArray(doc.list)) {
    readList(doc.library, doc, file);
    return out;
  }
  for (const [k, v] of Object.entries(doc)) {
    if (k === 'name' || k === 'version' || k === 'schema') continue;   // 文件级元数据
    if (v && typeof v === 'object' && Array.isArray(v.list)) readList(k, v, file);
  }
  if (!out.length) throw new Error(`${file}: 没找到任何导出组`);
  return out;
}

/* ------------------------------ 内容摘要 (仅为记录/指纹, 不参与文件名) ------------------------------ */
function exportId(library, entries) {
  const canon = TAG + '\n' + library + '\n' + entries.map((e) => e.name).join('\n') + '\n';
  return crypto.createHash('sha1').update(canon, 'utf8').digest('hex');   // 40 hex = 20 字节
}

/* ------------------------------ 洗牌分配 kIndex ------------------------------ */
function parseSeeds(s) {
  const parts = String(s == null ? '' : s).split(',').map((x) => x.trim()).filter((x) => x.length);
  if (parts.length !== 4) throw new Error(`--world-seed 需要 4 个 32 位随机数 (逗号分隔), 实际 ${parts.length} 个`);
  return parts.map((p) => {
    const v = Number(p);
    if (!Number.isInteger(v) || v < 0 || v > 0xFFFFFFFF) throw new Error(`--world-seed 里的值不合法: ${p}`);
    return v >>> 0;
  });
}

/* xorshift128: 四个 32 位状态全部用上, 确定性且无依赖 */
function makeRng(seeds) {
  let [x, y, z, w] = seeds;
  if ((x | y | z | w) === 0) x = 0x9E3779B9;      // 全 0 会退化
  return function next32() {
    const t = (x ^ (x << 11)) >>> 0;
    x = y; y = z; z = w;
    w = (w ^ (w >>> 19) ^ (t ^ (t >>> 8))) >>> 0;
    return w >>> 0;
  };
}

/* Fisher-Yates 洗牌 [64, 511], 按"库名字典序"取槽位
   —— 用库名排序而不是命令行顺序, 这样同一个 Makefile 换文件顺序也不会改变分配 */
function assignSlots(exps, seeds) {
  const libs = exps.filter((e) => e.pinned === null).map((e) => e.library).sort();
  const slots = [];
  for (let k = SLOT_LO; k <= SLOT_HI; k++) slots.push(k);
  if (libs.length > slots.length)
    throw new Error(`导出组太多: ${libs.length} 组 > 可用槽位 ${slots.length} 个 ([${SLOT_LO}, ${SLOT_HI}])`);
  const rnd = makeRng(seeds);
  for (let i = slots.length - 1; i > 0; i--) {
    const j = rnd() % (i + 1);
    const t = slots[i]; slots[i] = slots[j]; slots[j] = t;
  }
  const map = new Map();
  for (let i = 0; i < libs.length; i++) map.set(libs[i], slots[i]);
  return map;
}

function inWindow(k) {
  return (k >= SLOT_LO && k <= SLOT_HI) || (k >= USER_LO && k <= USER_HI);
}

function validate(exp, seenLib, seenId) {
  if (!NAME_RE.test(exp.library)) throw new Error(`库名不是合法 C 标识符: ${exp.library}`);
  if (seenLib.has(exp.library)) throw new Error(`库名重复: ${exp.library}`);
  seenLib.add(exp.library);
  const names = new Set();
  exp.entries.forEach((e, i) => {
    if (!NAME_RE.test(e.name)) throw new Error(`${exp.library}: 函数名不是合法 C 标识符: ${e.name}`);
    if (names.has(e.name)) throw new Error(`${exp.library}: 函数名重复: ${e.name} (第 ${i} 项)`);
    names.add(e.name);
  });
  exp.id = exportId(exp.library, exp.entries);
  if (seenId.has(exp.id)) throw new Error(`SHA1 撞车/重复: ${exp.id} (${exp.library} 与 ${seenId.get(exp.id)})`);
  seenId.set(exp.id, exp.library);
  if (exp.pinned !== null && !inWindow(exp.pinned))
    throw new Error(`${exp.library}: 显式 kIndex ${exp.pinned} 不在 [${SLOT_LO},${SLOT_HI}] ∪ [${USER_HI === -65 ? USER_LO : USER_LO},${USER_HI}] 内`);
}

/* ------------------------------ 生成 ------------------------------ */
function emitStub(exp) {
  const L = exp.library, K = `op_GATE_${L}__kIndex`;
  const lines = [];
  lines.push(`/* 由 op_GATE/tools/gen.cjs 生成, 请勿手改 ... */`);
  lines.push(`/* export : ${L}   sha1: ${exp.id}   kIndex: ${exp.kIndex}   条目: ${exp.entries.length} */`);
  lines.push(``);
  lines.push(`#define ${K} ${exp.kIndex}   /* 本次编译由 4 个随机数洗牌分配; [${USER_LO}, ${USER_HI}] 留给用户私有实现 */`);
  lines.push(`#if (${K} < ${SLOT_LO}) || (${K} > ${SLOT_HI})`);
  lines.push(`#error "${K} 超出 [${SLOT_LO}, ${SLOT_HI}] (JALR 12 位立即数所限; 用户私有实现请勿走本生成器)"`);
  lines.push(`#endif`);
  lines.push(``);
  exp.entries.forEach((e, i) => {
    if (e.stub === 'hand') {
      lines.push(`/* t0 == ${i} : ${e.name}  ->**手写桩** (例如变参门: 内部造 va_list 后再普通调用), 本文件不生成代码 */`);
      lines.push(``);
      return;
    }
    /* 注意: 带名字的段必须用 .section 形式; `.text.<name>` 那种写法被汇编器当作
       "子段号" 语法 (Error: unknown pseudo-op: `.text.foo.bar'), 实测踩过 ... */
    lines.push(`\t.section\t.text.${e.name}.${exp.id.slice(0, 12)},"ax",@progbits`);
    lines.push(`\t.align\t2`);
    lines.push(`\t.globl\t${e.name}`);
    lines.push(`\t.type\t${e.name}, @function`);
    lines.push(`${e.name}:`);
    lines.push(`\tli\tt0, ${i}`);
    lines.push(`\tjalr\tx0, ${K}*4(zero)`);
    lines.push(`\t.size\t${e.name}, .-${e.name}`);
    lines.push(``);
  });
  return lines.join('\n') + '\n';
}

function emitHeader(exp) {
  const L = exp.library, g = `op_GATE_${L}`;
  const lines = [];
  lines.push(`/* 由 op_GATE/tools/gen.cjs 生成, 请勿手改 ... */`);
  lines.push(`#ifndef __WTINC_${g}__H__`);
  lines.push(`#define __WTINC_${g}__H__`);
  lines.push(``);
  lines.push(`#define ${g}__kIndex      ${exp.kIndex}   /* 本次编译洗牌得到的槽位 (pc/4); 由桩里的 jalr 使用 */`);
  lines.push(`#define ${g}__kCount      ${exp.entries.length}   /* = 最大 t0 + 1; host 用它做上界校验 */`);
  lines.push(`#define ${g}__kLibrary    "${L}"`);
  lines.push(`#define ${g}__kIdSha1     "${exp.id}"   /* 导出内容摘要 (仅记录; 每次编译重新生成, 不追求跨编译兼容) */`);
  lines.push(``);
  lines.push(`/* 组内条目号 = 桩里 li t0, N 的 N (顺序即本次编译的 ABI) */`);
  lines.push(`enum {`);
  exp.entries.forEach((e, i) => {
    lines.push(`  ${g}__k_${e.name} = ${i},${e.stub === 'hand' ? '   /* 手写桩 */' : ''}`);
  });
  lines.push(`};`);
  lines.push(``);
  lines.push(`/* host 侧诊断/绑定用的名字表 (下标 = t0) */`);
  lines.push(`static const char* const ${g}__kEntryNames[${exp.entries.length}] __attribute__((unused)) = {`);
  exp.entries.forEach((e) => lines.push(`  "${e.name}",`));
  lines.push(`};`);
  lines.push(``);
  lines.push(`#endif /* __WTINC_${g}__H__ */`);
  return lines.join('\n') + '\n';
}

/* 世界指纹: 覆盖"这组随机数 + 每个导出的槽位分配" —— host 与 guest 必须一致 */
function worldId(exps, seeds) {
  const body = exps.map((e) => `${e.library}:${e.kIndex}`).sort().join('\n');
  return crypto.createHash('sha1')
    .update(`op-gate-world/1\n${seeds.map((s) => '0x' + s.toString(16).padStart(8, '0')).join(',')}\n${body}\n`, 'utf8')
    .digest('hex');
}

function emitManifest(exps, wid) {
  const lines = [];
  lines.push(`/* 由 op_GATE/tools/gen.cjs 生成, 请勿手改 ... */`);
  lines.push(`#ifndef __WTINC_OP_GATE_MANIFEST_H__`);
  lines.push(`#define __WTINC_OP_GATE_MANIFEST_H__`);
  lines.push(``);
  lines.push(`#include <atomic/op_GATE/hyper/hyper.h>`);
  lines.push(``);
  exps.forEach((e) => lines.push(`#include "op_GATE_${e.library}.h"`));
  lines.push(``);
  lines.push(`#define op_GATE__kExportCount ${exps.length}`);
  lines.push(`#define op_GATE__kWorldId     "${wid}"   /* 世界指纹: 随机数 + 槽位分配 */`);
  lines.push(``);
  lines.push(`static const op_GATE_export_t op_GATE__kExports[${exps.length}] __attribute__((unused)) = {`);
  exps.forEach((e) => {
    const g = `op_GATE_${e.library}`;
    lines.push(`  { ${g}__kLibrary, ${g}__kIndex, ${g}__kCount, ${g}__kIdSha1, ${g}__kEntryNames },`);
  });
  lines.push(`};`);
  lines.push(``);
  lines.push(`#endif /* __WTINC_OP_GATE_MANIFEST_H__ */`);
  return lines.join('\n') + '\n';
}

/* ------------------------------ main ------------------------------ */
function main(argv) {
  const files = [], args = argv.slice(2);
  let outDir = path.join(__dirname, '..', 'gen');
  let seedStr = null;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--out') outDir = path.resolve(args[++i]);
    else if (args[i].startsWith('--world-seed')) {
      seedStr = args[i].includes('=') ? args[i].slice(args[i].indexOf('=') + 1) : args[++i];
    } else if (args[i] === '--help' || args[i] === '-h') {
      console.log('用法: node gen.cjs <list/*.yaml ...> --world-seed="0x…,0x…,0x…,0x…" [--out <dir>]');
      return 0;
    } else files.push(args[i]);
  }
  if (!files.length) { console.error('✗ 需要至少一个清单文件'); return 2; }

  const exps = [];
  try {
    for (const f of files) exps.push(...loadExports(f));
  } catch (e) { console.error('✗ 清单解析失败: ' + e.message); return 2; }

  let seeds = null;
  try {
    if (exps.some((e) => e.pinned === null)) seeds = parseSeeds(seedStr);   // 有需要分配的组就必须给随机数
  } catch (e) { console.error('✗ ' + e.message); return 2; }

  const seenLib = new Set(), seenId = new Map();
  try {
    for (const e of exps) validate(e, seenLib, seenId);
    if (seeds) {
      const map = assignSlots(exps, seeds);
      for (const e of exps) e.kIndex = (e.pinned === null) ? map.get(e.library) : e.pinned;
    } else {
      for (const e of exps) e.kIndex = e.pinned;
    }
    const used = new Map();
    for (const e of exps) {
      if (used.has(e.kIndex)) throw new Error(`kIndex ${e.kIndex} 被 '${e.library}' 与 '${used.get(e.kIndex)}' 同时占用`);
      used.set(e.kIndex, e.library);
    }
  } catch (e) { console.error('✗ 清单校验/分配失败: ' + e.message); return 2; }

  const wid = worldId(exps, seeds || [0, 0, 0, 0]);
  fs.mkdirSync(outDir, { recursive: true });
  for (const e of exps) {
    fs.writeFileSync(path.join(outDir, `op_GATE_${e.library}.S`), emitStub(e));
    fs.writeFileSync(path.join(outDir, `op_GATE_${e.library}.h`), emitHeader(e));
  }
  fs.writeFileSync(path.join(outDir, 'op_GATE_manifest.h'), emitManifest(exps, wid));

  console.log(`✓ 生成 ${exps.length} 个导出 -> ${outDir}`);
  console.log(`  world-seed: ${seeds ? seeds.map((s) => '0x' + s.toString(16).padStart(8, '0')).join(',') : '(无)'}`);
  console.log('');
  console.log('  库名         kIndex  条目  手写桩  sha1 (前 12)');
  for (const e of [...exps].sort((a, b) => a.kIndex - b.kIndex)) {
    const hand = e.entries.filter((x) => x.stub === 'hand').length;
    console.log(`  ${e.library.padEnd(12)} ${String(e.kIndex).padStart(5)}  ${String(e.entries.length).padStart(4)}  ${String(hand).padStart(5)}   ${e.id.slice(0, 12)}`);
  }
  console.log('');
  console.log(`  world id: ${wid}`);
  return 0;
}

process.exit(main(process.argv));

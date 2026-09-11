/**
 *! opcode.cjs — 以 Interface/script.h 的 enum class OpCode 为唯一事实源, 生成:
 *!   Web/Script/lib/opcode.ts  = OpCode enum + TypeFuncCall + AllFunc
 *! AllFunc 成员规则: 行内注释带 "argc :" 的功能指令 ∪ 语义特例 {kInv:0..0, kExit:0..1};
 *! min/max 取自注释的 argc(支持 N、N...M、N/M)。
 *!
 *! 该文件在 .gitignore 中忽略, 由 make jsWrapper / npm run gen:opcode 在构建期生成。
 *! 用法: node Build/tools/LIMIT/script/opcode.cjs [--dry-run]
 */

const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..", "..", "..", "..");
const kHeader = path.join(root, "Interface", "script.h");
const kOpcodeTs = path.join(root, "Web", "Script", "lib", "opcode.ts");
const dryRun = process.argv.includes("--dry-run");
const BOM = "\uFEFF";

const read = (f) => fs.readFileSync(f, "utf8");

/* ---------------- C++ enum 解析 ---------------- */
function cleanComment(s) {
  return s
    .replace(/^\/\*+/, "")
    .replace(/\*\/\s*$/, "")
    .replace(/^\*/, "")
    .replace(/^!/, "")
    .trim();
}

function parseEnum(body) {
  const groups = [];
  const all = [];
  let cur = 0;
  let pendingDoc = null;
  let curG = null;
  const openGroup = (doc) => {
    curG = { doc: doc || null, items: [] };
    groups.push(curG);
  };
  for (const raw of body.split("\n")) {
    const line = raw.replace(/\r$/, "");
    const t = line.trim();
    if (!t) continue;
    if (t.startsWith("/*") || t.startsWith("*")) {
      const seg = t.replace(/^\/\*+/, "");
      const end = seg.indexOf("*/");
      const text = cleanComment(end >= 0 ? seg.slice(0, end) : seg);
      pendingDoc = (pendingDoc === null ? text : (pendingDoc + " " + text)).trim() || null;
      continue;
    }
    if (/^};/.test(t)) break;
    const m = /^(k[A-Za-z0-9_]+)\s*(=\s*(0[xX][0-9a-fA-F]+|\d+))?\s*,?\s*(.*)$/.exec(t);
    if (!m) continue;
    if (pendingDoc !== null || curG === null) openGroup(pendingDoc);
    pendingDoc = null;
    let comment = "";
    let marker = "//";
    const rest = m[4] || "";
    const c = rest.search("//");
    if (c >= 0) {
      marker = rest.startsWith("///") ? "///" : "//";
      comment = rest.slice(c + marker.length).trim();
    }
    const explicit = !!m[2];
    if (explicit) {
      const v = m[3];
      cur = /^0x/i.test(v) ? parseInt(v, 16) : parseInt(v, 10);
    }
    const item = { name: m[1], explicit, value: cur, hex: explicit ? m[3].toLowerCase() : "", comment, marker };
    curG.items.push(item);
    all.push(item);
    cur += 1;
  }
  return { groups, all };
}

/* argc 解析: "argc : 3" / "argc : 2...4" / "argc : 1/2" */
function argcFromComment(c) {
  let m = /argc\s*:\s*(\d+)\s*(?:\.{2,3}|…|\/)\s*(\d+)/.exec(c);
  if (m) return { min: +m[1], max: +m[2] };
  m = /argc\s*:\s*(\d+)/.exec(c);
  return m ? { min: +m[1], max: +m[1] } : null;
}

const headerText = read(kHeader);
const enumStart = headerText.indexOf("enum class OpCode");
if (enumStart < 0) {
  console.error("[opcode] Interface/script.h: 找不到 enum class OpCode");
  process.exit(2);
}
const bodyStart = headerText.indexOf("{", enumStart);
const body = headerText.slice(bodyStart + 1, headerText.indexOf("};", enumStart));
const { groups, all: opcodes } = parseEnum(body);
if (!opcodes.length) {
  console.error("[opcode] OpCode 解析为空");
  process.exit(2);
}

/* AllFunc 成员: argc 注释 ∪ 语义特例 */
const specialMinMax = { kInv: { min: 0, max: 0 }, kExit: { min: 0, max: 1 } };
const funcs = [];
for (const o of opcodes) {
  if (specialMinMax[o.name]) {
    funcs.push({ name: o.name, ...specialMinMax[o.name] });
    continue;
  }
  const argc = argcFromComment(o.comment);
  if (argc) funcs.push({ name: o.name, min: argc.min, max: argc.max });
}

/* ---------------- 生成 opcode.ts ---------------- */
const lines = [
  "/**",
  " *! AUTO-GENERATED from Interface/script.h (enum class OpCode) by Build/tools/LIMIT/script/opcode.cjs. 请勿手工编辑.",
  " *! 修改请改 script.h 后运行: node Build/tools/LIMIT/script/opcode.cjs (或 make jsWrapper)",
  " */",
  "export const enum OpCode {",
];
for (const g of groups) {
  if (g.doc) lines.push("", "  /**", ...g.doc.split(" ").map((l) => "   *" + (l ? " " + l : "")), "   */");
  for (const o of g.items) {
    let e = "  " + o.name;
    if (o.explicit) e += " = " + o.hex;
    e += ",";
    if (o.comment) e += " " + o.marker + " " + o.comment;
    lines.push(e);
  }
}
lines.push("}");
lines.push("");
lines.push("export type TypeFuncCall = {");
lines.push("  name: string;");
lines.push("  min: number;");
lines.push("  max: number;");
lines.push("  op: number;");
lines.push("};");
lines.push("");
lines.push("export const AllFunc: TypeFuncCall[] = [");
for (const f of funcs) {
  lines.push("  {", `    name: "${f.name}",`, `    min: ${f.min},`, `    max: ${f.max},`, `    op: OpCode.${f.name},`, "  },");
}
lines.push("];");
const text = lines.join("\n") + "\n";

if (dryRun) {
  console.log(`[opcode] opcode.ts: 将生成 OpCode=${opcodes.length}, AllFunc=${funcs.length}`);
} else {
  fs.writeFileSync(kOpcodeTs, BOM + text, "utf8");
  console.log(`[opcode] opcode.ts: 已生成 OpCode=${opcodes.length}, AllFunc=${funcs.length}`);
}

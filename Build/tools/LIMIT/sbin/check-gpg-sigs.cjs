// 注意: 本脚本不加 #! shebang(Windows 下会报错), 用 node xxx.cjs 调用。
/**
 * check-gpg-sigs.cjs —— 检查一组 OpenPGP 文件(.asc/.gpg/.sig/.pgp)是否**完整**,
 * 并对分离签名做真实验签(可选)。
 *
 * 设计要点:
 *   1) **完整性**(本工具的硬指标, 纯 JS 不依赖 gpg):
 *      - armor 结构: BEGIN/END 是否配对、base64 是否合法、CRC24 是否匹配、有无尾随垃圾;
 *      - 包结构: 逐个 OpenPGP 包的长度字段是否自洽、有没有超出文件末尾(截断)。
 *   2) **分类**: 签名 / 加密 / 公钥块 / 其他数据。**加密文件按用户要求跳过**。
 *   3) **验签**(有 gpg 时): 用临时 GNUPGHOME 导入目录里的公钥块, 再 `gpg --verify`;
 *      分离签名会自动去找同名数据文件(去掉 .asc/.sig/.gpg/.pgp 后缀)。
 *
 * 用法:
 *   node Build/tools/LIMIT/sbin/check-gpg-sigs.cjs [目录=mkey] [选项]
 *     --no-verify        只做结构与分类检查, 不调用 gpg
 *     --gpg <path>       指定 gpg 可执行文件(缺省自动探测)
 *     --keyring <file>   额外导入的公钥块(可重复; 缺省自动收集目录下所有 PUBLIC KEY BLOCK)
 *     --json             以 JSON 输出
 *     --quiet            只打印有问题/需要注意的条目
 *     --keep-home        保留临时 GNUPGHOME(调试)
 *     --selftest         自检: 人为弄坏签名文件, 确认截断/缺 END/坏 CRC 都能被抓出来
 *     --dump <file>      打印某文件的 armor 与 OpenPGP 包结构(排查用)
 *   退出码: 0 = 无致命问题; 1 = 存在"签名文件不完整/截断"或"验签失败(BADSIG)"; 2 = 参数/环境错误。
 *
 * 环境提示(本机实测):
 *   - cygwin 的 C:\cygwin64\bin\gpg.exe **无法从 Windows 直接 exec**("系统无法执行指定的程序"),
 *     缺省探测顺序会命中 **Git 自带的 gpg**(C:\Program Files\Git\usr\bin\gpg.exe, GnuPG 2.4.8)✓;
 *   - Git 版 gpg 是 MSYS 程序, `--homedir` 必须给**相对路径**(绝对 Windows 路径会被拼到 CWD 后面),
 *     本工具固定用相对目录 `.bin/gpg-check-home`。
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const EXT = new Set([".asc", ".gpg", ".sig", ".pgp"]);

/* ---------------------------------------------------------------- 参数 */
function parseArgs(argv) {
  const o = {
    dir: "mkey",
    verify: true,
    gpg: null,
    keyrings: [],
    json: false,
    quiet: false,
    keepHome: false,
    selftest: false,
  };
  const rest = [];
  for (let i = 0; i < argv.length; ++i) {
    const a = argv[i];
    if (a === "--no-verify") o.verify = false;
    else if (a === "--gpg") o.gpg = argv[++i];
    else if (a === "--keyring") o.keyrings.push(argv[++i]);
    else if (a === "--json") o.json = true;
    else if (a === "--quiet") o.quiet = true;
    else if (a === "--keep-home") o.keepHome = true;
    else if (a === "--selftest") o.selftest = true;
    else if (a === "--dump") o.dump = argv[++i];
    else if (a.startsWith("--")) throw new Error(`未知选项 ${a}`);
    else rest.push(a);
  }
  if (rest.length) o.dir = rest[0];
  return o;
}

/* ------------------------------------------------------------ 基础工具 */
const CRC24_INIT = 0xb704ce;
const CRC24_POLY = 0x1864cfb;
function crc24(buf) {
  let crc = CRC24_INIT;
  for (const b of buf) {
    crc ^= b << 16;
    for (let i = 0; i < 8; ++i) {
      crc <<= 1;
      if (crc & 0x1000000) crc ^= CRC24_POLY;
    }
  }
  return crc & 0xffffff;
}

function b64decodeStrict(text) {
  const clean = text.replace(/[\s\r\n]/g, "");
  if (/[^A-Za-z0-9+/=]/.test(clean)) return { ok: false, reason: "base64 含非法字符" };
  if (clean.length % 4 !== 0) return { ok: false, reason: `base64 长度非 4 的倍数(${clean.length})` };
  const pad = (clean.match(/=+$/) || [""])[0].length;
  if (pad > 2) return { ok: false, reason: "base64 填充异常" };
  const body = clean.slice(0, clean.length - pad);
  if (/=/.test(body)) return { ok: false, reason: "base64 中部出现填充符" };
  return { ok: true, buf: Buffer.from(clean, "base64") };
}

/** 解析 armor 文本; 返回 {type, bodyBuf, problems[]} */
function parseArmor(text) {
  const problems = [];
  const begin = /^-----BEGIN ([^-]+)-----\r?\n/m.exec(text);
  if (!begin) return { problems: ["缺少 BEGIN 行(不是 armor 文本?)"] };
  const type = begin[1].trim();
  const endRe = new RegExp(`^-----END ${type.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}-----\\s*$`, "m");
  const end = endRe.exec(text);
  if (!end) problems.push(`缺少匹配的 END 行(期望 -----END ${type}-----)`);

  const afterBegin = text.slice(begin.index + begin[0].length, end ? end.index : text.length);
  const lines = afterBegin.split(/\r?\n/);
  const bodyLines = [];
  let crcLine = null;
  let sawBlank = false;
  for (const line of lines) {
    if (!sawBlank && line.trim() === "") {
      sawBlank = true; /* armor 头与正文之间的空行 */
      continue;
    }
    if (!sawBlank) continue; /* armor 头(Version/Comment 等) */
    const t = line.trim();
    if (t === "") continue;
    if (/^=/.test(t)) {
      crcLine = t.slice(1);
      continue;
    }
    bodyLines.push(t);
  }
  const dec = b64decodeStrict(bodyLines.join(""));
  if (!dec.ok) problems.push(dec.reason);

  if (crcLine !== null && dec.ok) {
    const want = /^[A-Za-z0-9+/]{4}$/.test(crcLine) ? Buffer.from(crcLine, "base64").readUIntBE(0, 3) : null;
    if (want === null) problems.push(`CRC24 行格式异常(${crcLine})`);
    else {
      const got = crc24(dec.buf);
      if (got !== want) problems.push(`CRC24 不匹配(文件 ${want.toString(16)}, 实算 ${got.toString(16)})`);
    }
  }
  if (end) {
    const tail = text.slice(end.index + end[0].length);
    if (tail.trim() !== "") problems.push("END 行之后还有非空内容(尾随垃圾)");
  }
  return { type, bodyBuf: dec.ok ? dec.buf : null, problems, hasCrc: crcLine !== null };
}

/** 走一遍 OpenPGP 包: 返回 {packets:[{tag,len,partial}], truncated} */
function walkPackets(buf) {
  const packets = [];
  let off = 0;
  let truncated = false;
  while (off < buf.length) {
    const ctb = buf[off];
    if ((ctb & 0x80) === 0) {
      truncated = true; /* 不是包起始 → 结构坏了 */
      break;
    }
    const newFormat = (ctb & 0x40) !== 0;
    const tag = newFormat ? ctb & 0x3f : (ctb >> 2) & 0x0f;
    let p = off + 1;
    let len = 0;
    let partial = false;
    let ok = true;
    let end = p; /* 包体末尾的绝对偏移(必须显式跟踪: partial 链里分块是边走边消费的) */
    if (newFormat) {
      /* 长度可能是 "部分长度" 链(RFC4880 §4.2.2.4): partial octet + 数据块, 再接下一个人长度
       * octet……直到最后一个非 partial 长度。 */
      for (;;) {
        const o1 = buf[p];
        if (o1 === undefined) {
          ok = false;
          break;
        }
        if (o1 < 192) {
          len += o1;
          p += 1;
          end = p + o1;
          break;
        }
        if (o1 < 224) {
          const o2 = buf[p + 1];
          if (o2 === undefined) {
            ok = false;
            break;
          }
          const l = ((o1 - 192) << 8) + o2 + 192;
          len += l;
          p += 2;
          end = p + l;
          break;
        }
        if (o1 === 255) {
          if (p + 4 >= buf.length) {
            ok = false;
            break;
          }
          const l = buf.readUInt32BE(p + 1);
          len += l;
          p += 5;
          end = p + l;
          break;
        }
        partial = true;
        const chunk = 1 << (o1 & 0x1f);
        p += 1;
        if (p + chunk > buf.length) {
          ok = false;
          end = p + chunk;
          break;
        }
        len += chunk;
        p += chunk;
        end = p;
      }
    } else {
      const lt = ctb & 3;
      if (lt === 0) {
        len = buf[p];
        p += 1;
      } else if (lt === 1) {
        len = buf.readUInt16BE(p);
        p += 2;
      } else if (lt === 2) {
        len = buf.readUInt32BE(p);
        p += 4;
      } else {
        len = buf.length - p; /* indeterminate: 到文件末尾 */
      }
      if (len === undefined || Number.isNaN(len)) {
        ok = false;
      }
      end = p + len;
    }
    if (!ok || end > buf.length) {
      truncated = true;
      packets.push({ tag, len, partial, at: off, overrun: Math.max(0, end - buf.length) });
      break;
    }
    packets.push({ tag, len, partial, at: off });
    off = end;
  }
  return { packets, truncated, end: off };
}

const TAG = {
  1: "PKESK(加密会话密钥)",
  2: "Signature",
  3: "SKESK(对称加密会话密钥)",
  4: "One-Pass Signature",
  5: "Secret-Key",
  6: "Public-Key",
  7: "Secret-Subkey",
  8: "Compressed Data",
  9: "Sym-Encrypted Data",
  11: "Literal Data",
  14: "Public-Subkey",
  18: "Sym-Encrypted+MDC",
  19: "MDC",
};
const ENC_TAGS = new Set([1, 3, 9, 18]);
const KEY_TAGS = new Set([5, 6, 7, 14]);
const SIG_TAGS = new Set([2, 4]);

function classify(filePath) {
  const raw = fs.readFileSync(filePath);
  const text = raw.toString("latin1");
  const isArmor = /-----BEGIN [^-]+-----/.test(text);
  const res = { file: filePath, armored: isArmor, problems: [], tags: [], kind: "unknown" };

  let body = raw;
  if (isArmor) {
    const a = parseArmor(text);
    res.armorType = a.type;
    res.problems.push(...a.problems);
    res.crc = a.hasCrc;
    if (!a.bodyBuf) {
      res.truncated = true;
      return res;
    }
    body = a.bodyBuf;
  }
  const w = walkPackets(body);
  res.packets = w.packets.map((p) => (TAG[p.tag] ? `${p.tag}:${TAG[p.tag]}` : `${p.tag}`));
  res.tags = [...new Set(w.packets.map((p) => p.tag))];
  res.truncated = res.truncated || w.truncated;
  if (w.truncated) res.problems.push("包结构不完整(长度超出文件末尾或包起始字节非法)");

  const hasEnc = res.tags.some((t) => ENC_TAGS.has(t));
  const hasKey = res.tags.some((t) => KEY_TAGS.has(t));
  const hasSig = res.tags.some((t) => SIG_TAGS.has(t));
  const hasLiteral = res.tags.includes(11);
  if (hasEnc) res.kind = "encrypted";
  else if (hasKey) res.kind = "key";
  else if (hasSig) res.kind = hasLiteral ? "signed-message" : "signature";
  else if (hasLiteral) res.kind = "data";
  res.complete = res.problems.length === 0;
  return res;
}

/* ------------------------------------------------------------- gpg 支持 */
function findGpg(explicit) {
  if (explicit) {
    const r = spawnSync(explicit, ["--version"], { encoding: "utf8" });
    if (r.status === 0 && /GnuPG/.test(r.stdout || "")) return explicit;
    throw new Error(`指定的 gpg 不可用: ${explicit}`);
  }
  const cands = [
    process.env.GPG_PATH,
    "gpg",
    "C:/Program Files/Git/usr/bin/gpg.exe",
    "C:/Program Files (x86)/Git/usr/bin/gpg.exe",
  ].filter(Boolean);
  for (const c of cands) {
    const r = spawnSync(c, ["--version"], { encoding: "utf8" });
    if (r.status === 0 && /GnuPG/.test(r.stdout || "")) return c;
  }
  return null;
}

function listFiles(dir) {
  const out = [];
  const walk = (d) => {
    let ents = [];
    try {
      ents = fs.readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of ents) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (EXT.has(path.extname(e.name).toLowerCase())) out.push(p);
    }
  };
  walk(dir);
  return out.sort();
}

function collectKeyrings(files, explicit) {
  if (explicit.length) return explicit;
  return files.filter((f) => {
    try {
      return /-----BEGIN PGP PUBLIC KEY BLOCK-----/.test(fs.readFileSync(f, "latin1"));
    } catch {
      return false;
    }
  });
}

function verifyWithGpg(gpg, home, sigFile, dataFile) {
  const args = ["--batch", "--no-tty", "--homedir", home, "--status-fd", "1", "--verify", sigFile];
  if (dataFile) args.push(dataFile);
  const r = spawnSync(gpg, args, { encoding: "utf8", cwd: process.cwd() });
  const status = `${r.stdout || ""}\n${r.stderr || ""}`;
  const grab = (k) => {
    const m = new RegExp(`\\[GNUPG:\\] ${k} (.*)`).exec(status);
    return m ? m[1].trim() : null;
  };
  return {
    good: grab("GOODSIG"),
    valid: grab("VALIDSIG"),
    bad: grab("BADSIG"),
    err: grab("ERRSIG"),
    noPub: grab("NO_PUBKEY"),
    exp: grab("EXPKEYSIG"),
    rev: grab("REVKEYSIG"),
    rc: r.status,
  };
}

/**
 * 自检: 把第一个签名文件人为弄坏(截断/缺 END/坏 CRC/正文改 1 字节),
 * 确认"不完整"都能被抓出来 —— 否则工具本身不可信。
 */
function selftest(dir) {
  const files = listFiles(dir).filter((f) => classify(f).kind === "signature");
  if (!files.length) {
    console.error("[selftest] 目录里没有签名文件可供自检");
    return 2;
  }
  const src = files[0];
  const text = fs.readFileSync(src, "latin1");
  const lines = text.split(/\r?\n/);
  const endIdx = lines.findIndex((l) => /^-----END /.test(l));
  const bodyIdx = lines.findIndex((l) => /^[A-Za-z0-9+/]{20,}=*$/.test(l.trim()));
  const crcIdx = lines.findIndex((l) => /^=[A-Za-z0-9+/]{4}\s*$/.test(l));
  const tmp = path.join(".bin", "gpg-selftest");
  fs.rmSync(tmp, { recursive: true, force: true });
  fs.mkdirSync(tmp, { recursive: true });

  const variants = [];
  variants.push({
    name: "cut-body(截掉后半段正文与 END)",
    text: lines.slice(0, Math.max(bodyIdx + 1, Math.floor(lines.length * 0.6))).join("\n"),
  });
  variants.push({
    name: "no-end(只删 END 行)",
    text: lines.filter((_, i) => i !== endIdx).join("\n"),
  });
  if (crcIdx >= 0) {
    const bad = lines.slice();
    bad[crcIdx] = bad[crcIdx].replace(/=([A-Za-z0-9+/])/, (m, c) => "=" + (c === "A" ? "B" : "A"));
    variants.push({ name: "bad-crc24(改 CRC 行 1 字符)", text: bad.join("\n") });
  }
  if (bodyIdx >= 0) {
    const bad = lines.slice();
    const l = bad[bodyIdx];
    bad[bodyIdx] = l.replace(/[A-Za-z0-9+/]/, (c) => (c === "A" ? "B" : "A"));
    variants.push({ name: "body-flip(正文改 1 字符 → CRC 应报警)", text: bad.join("\n") });
  }

  console.log(`[selftest] 原始文件: ${src}`);
  let fail = 0;
  const clean = classify(src);
  const cleanOk = clean.problems.length === 0;
  console.log(`[selftest] ${cleanOk ? "PASS" : "FAIL"}  原始文件应无问题: ${clean.problems.join("; ") || "无"}`);
  if (!cleanOk) ++fail;

  for (const v of variants) {
    const p = path.join(tmp, `variant-${variants.indexOf(v)}.asc`);
    fs.writeFileSync(p, v.text, "latin1");
    const r = classify(p);
    const ok = r.problems.length > 0 || r.truncated;
    console.log(
      `[selftest] ${ok ? "PASS" : "FAIL"}  ${v.name}: ${ok ? r.problems.join("; ") || "包结构截断" : "**未被检出**"}`,
    );
    if (!ok) ++fail;
  }
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`[selftest] 结论: ${fail === 0 ? "全部 PASS" : `${fail} 项 FAIL`}`);
  return fail === 0 ? 0 : 1;
}

/* ------------------------------------------------------------------ 主 */
function main() {
  const o = parseArgs(process.argv.slice(2));
  if (!fs.existsSync(o.dir)) {
    console.error(`[check-gpg-sigs] 目录不存在: ${o.dir}`);
    process.exit(2);
  }
  if (o.selftest) process.exit(selftest(o.dir));
  if (o.dump) {
    const raw = fs.readFileSync(o.dump);
    const text = raw.toString("latin1");
    const armored = /-----BEGIN [^-]+-----/.test(text);
    const a = armored ? parseArmor(text) : null;
    const body = armored ? a.bodyBuf : raw;
    console.log(`[dump] ${o.dump} armored=${armored} armorType=${a ? a.type : "-"} bodyBytes=${body ? body.length : 0}`);
    if (a) console.log(`[dump] armor problems: ${a.problems.join("; ") || "无"} crc=${a.hasCrc}`);
    if (body) {
      const w = walkPackets(body);
      for (const p of w.packets)
        console.log(`  off=${p.at} tag=${p.tag}${TAG[p.tag] ? "(" + TAG[p.tag] + ")" : ""} len=${p.len} partial=${!!p.partial}`);
      console.log(`[dump] walked=${w.end}/${body.length} truncated=${w.truncated}`);
      if (w.end < body.length)
        console.log(`[dump] 未消费尾部 ${body.length - w.end}B: ${body.slice(w.end, w.end + 32).toString("hex")}`);
    }
    process.exit(0);
  }
  const files = listFiles(o.dir);
  if (!files.length) {
    console.error(`[check-gpg-sigs] ${o.dir} 下没有 .asc/.gpg/.sig/.pgp 文件`);
    process.exit(2);
  }

  let gpg = null;
  let home = null;
  let importedKeys = 0;
  let keyringFiles = [];
  if (o.verify) {
    gpg = findGpg(o.gpg);
    if (gpg) {
      home = path.join(".bin", "gpg-check-home");
      fs.mkdirSync(home, { recursive: true });
      keyringFiles = collectKeyrings(files, o.keyrings);
      for (const kr of keyringFiles) {
        const imp = spawnSync(gpg, ["--batch", "--no-tty", "--homedir", home, "--import", kr], { encoding: "utf8" });
        const txt = `${imp.stdout || ""}${imp.stderr || ""}`;
        importedKeys += (txt.match(/public key .* imported/g) || []).length;
        if (imp.status !== 0) console.error(`[check-gpg-sigs] 导入公钥块失败: ${kr}`);
      }
    }
  }

  const results = [];
  for (const f of files) {
    const r = classify(f);
    r.verify = null;
    if (r.kind === "encrypted") {
      r.status = "skip-encrypted";
    } else if (r.kind === "signature" || r.kind === "signed-message") {
      if (!r.complete) {
        r.status = "INCOMPLETE";
      } else if (!o.verify || !gpg) {
        r.status = "structure-ok(未验签)";
      } else {
        let dataFile = null;
        if (r.kind === "signature") {
          const base = f.replace(/\.(asc|sig|gpg|pgp)$/i, "");
          if (fs.existsSync(base)) dataFile = base;
        }
        if (r.kind === "signature" && !dataFile) {
          r.status = "structure-ok(未找到被签数据, 无法验签)";
        } else {
          r.verify = verifyWithGpg(gpg, home, f, dataFile);
          if (r.verify.good || r.verify.valid) r.status = "VERIFIED";
          else if (r.verify.bad) r.status = "BADSIG";
          else if (r.verify.noPub || r.verify.err) r.status = "no-pubkey";
          else r.status = "verify-error";
        }
      }
    } else if (r.kind === "key") {
      r.status = r.complete ? "key-block(structure-ok)" : "key-block(INCOMPLETE)";
    } else {
      r.status = r.complete ? "other(structure-ok)" : "other(INCOMPLETE)";
    }
    results.push(r);
  }

  if (!o.keepHome && home) {
    try {
      fs.rmSync(home, { recursive: true, force: true });
    } catch {
      /* 临时目录残留无妨 */
    }
  }

  if (o.json) {
    console.log(JSON.stringify({ dir: o.dir, gpg, results }, null, 1));
  } else {
    const pad = Math.max(...results.map((r) => r.file.length));
    console.log(`[check-gpg-sigs] 目录=${o.dir} 文件=${results.length} gpg=${gpg || "(未找到, 仅结构检查)"}`);
    if (o.verify && gpg)
      console.log(
        `[check-gpg-sigs] 公钥块=${keyringFiles.length ? keyringFiles.join(", ") : "(无)"} 导入公钥=${importedKeys}` +
          `${importedKeys === 0 ? " —— 外部签名会报 no-pubkey, 可用 --keyring <公钥块> 指定" : ""}`,
      );
    for (const r of results) {
      const flag = r.status.startsWith("VERIFIED") || r.status.includes("structure-ok") || r.status === "skip-encrypted";
      if (o.quiet && flag) continue;
      console.log(
        `${r.status.padEnd(38)} ${r.file.padEnd(pad)}  ${r.armorType || "(binary)"} ` +
          `packets=[${r.tags.join(",")}]${r.verify && r.verify.good ? `  signer=${r.verify.good}` : ""}`,
      );
      for (const p of r.problems) console.log(`${" ".repeat(38)} ${r.file}: ${p}`);
    }
    const tally = {};
    for (const r of results) tally[r.status] = (tally[r.status] || 0) + 1;
    console.log(`[check-gpg-sigs] 汇总: ${Object.entries(tally).map(([k, v]) => `${k}×${v}`).join(", ")}`);
  }

  const fatal = results.filter(
    (r) =>
      (r.kind === "signature" || r.kind === "signed-message") &&
      (!r.complete || r.status === "BADSIG" || r.status === "verify-error"),
  );
  process.exit(fatal.length ? 1 : 0);
}

try {
  main();
} catch (e) {
  console.error(`[check-gpg-sigs] ${e.message}`);
  process.exit(2);
}

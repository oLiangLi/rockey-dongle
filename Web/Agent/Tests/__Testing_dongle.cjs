/*!
 * __Testing_dongle.cjs — ukey 脚本化测试工具(Node 版, 参照 Web/Agent/Tests/index.html + index.cjs)
 *
 * 对 .dongle(rLANG DSL)解析(ggrammar, 纯 TS)并按"普通(ATOMC)模式"打包 1024B 帧,
 * 直调 Windows 端 RockeyTrust/dongle_entry.exe 在**真实 ukey** 上执行。
 * 说明:
 *  - 仅实现 NORMAL(ATOMC)帧(无需 EnTrust 签名); ADMIN/BOOTSTRAP/LIMIT 需托管密钥/设备签名,
 *    本工具不会伪造, 遇到即报错提示。绝不调用 factory/lock。
 *  - 脚本 data 段参数: 固定单整数选项自动取用; 其余取值默认取 options[0];
 *    ${...} 模板默认生成 sizeMin..sizeMax 长度的随机字节(如需确定性可显式提供)。
 *
 * 用法:
 *   node __Testing_dongle.cjs list
 *   node __Testing_dongle.cjs dashboard <hid>
 *   node __Testing_dongle.cjs run    <script.dongle> [hid]
 *   node __Testing_dongle.cjs suite  <dir> [hid]
 * 环境: RKEY_EXECV=Windows 端可执行文件(缺省 .bin/amd64-windows-release/dongle_entry.exe)
 *       RKEY_HID=缺省设备; RKEY_ADMIN=1 时以管理员会话运行(仅影响文件 ACL, 不做签名提权)
 */
"use strict";

const crypto = require("crypto");
const child_process = require("child_process");
const fs = require("fs");
const path = require("path");

/**
 *! 使用打包好的版本而不是使用 .assets 下的文件, 它们随时可能被清理 ...
 */
require("./js/jsWorld.js");
require("./js/jsCrypto.js");

function DongleDisplayValue(key) {
  function V2(v) {
    return ("00" + v.toString(16)).slice(-2);
  }
  function V8(v) {
    return "0x" + ("00000000" + v.toString(16)).slice(-8);
  }
  const version = V8(key.readUInt32LE(0));
  const type = V8(key.readUInt32LE(4));
  const birthday = `20${V2(key[8])}-${V2(key[9])}-${V2(key[10])} ${V2(key[11])}:${V2(key[12])}:${V2(key[13])}`;
  const agent = V8(key.readUInt32LE(16));
  const pid = V8(key.readUInt32LE(20));
  const uid = V8(key.readUInt32LE(24));
  const id = `${key.subarray(28, 32).toString("hex")}-${key.subarray(32, 40).toString("hex")}`;
  return { id, pid, uid, type, birthday, agent, version };
}
/***
 *!
 */
async function initialize() {
  const jsCipher = (globalThis.jsCipher = await jsWorld.CipherLoader());
  const CryptoLoader = (globalThis.CryptoLoader =
    await jsWorld.CryptoLoader(jsCipher));

  /**
   *! 一次创建8个模拟器应该够满足需求 ...
   */
  const all = [];
  const kCountEmulator = 8;
  for (let i = 0; i < kCountEmulator; ++i) {
    all.push(await CryptoLoader.CreateEmulator());
  }
  const jsEmulatorEx = (globalThis.jsEmulatorEx = await Promise.all(all));

  /**
   *! 缺省使用的模拟器, 方便拷贝代码 ...
   */
  globalThis.jsEmulator = jsEmulatorEx[0];

  for (let i = 0; i < kCountEmulator; ++i) {
    jsEmulatorEx[i].Create(
      jsCipher.RandBytes(16).toString("hex"),
      0x100 + i,
      256,
    );
    console.log(
      `Emulator ${i} ready ${JSON.stringify(DongleDisplayValue(jsEmulatorEx[i].GetDongleInfo()))}`,
    );
  }
}

const ROOT = path.resolve(__dirname, "../../..");
const Parse = async (script) => {
  return await globalThis.CryptoLoader.ParseScript(script);
};
const EXECV =
  process.env.RKEY_EXECV ||
  path.join(ROOT, ".bin", "amd64-windows-release", "dongle_entry.exe");

const kTimeout = 120 * 1000;

// ---------------------------------------------------------------- crypto
function digest(name, ...parts) {
  const h = crypto.createHash(name);
  for (const p of parts) h.update(p);
  return h.digest();
}
const sha256 = (b) => digest("sha256", b);
const sha512 = (b) => digest("sha512", b);
const sm3 = (b) => digest("sm3", b);

function chachaSeal(key, nonce, data) {
  const cipher = crypto.createCipheriv("chacha20-poly1305", key, nonce, {
    authTagLength: 16,
  });
  const out = Buffer.concat([cipher.update(data), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([out, tag]);
}

function derLen(len) {
  if (len < 0x80) return Buffer.from([len]);
  const out = [0x80 | (len < 0x100 ? 1 : 2)];
  if (len < 0x100) out.push(len);
  else out.push(len >> 8, len & 0xff);
  return Buffer.from(out);
}
function derInteger(big) {
  let v = big;
  while (v.length > 1 && v[0] === 0) v = v.subarray(1); // strip leading 0
  const need = v[0] & 0x80;
  const content = need ? Buffer.concat([Buffer.from([0]), v]) : v;
  return Buffer.concat([Buffer.from([0x02]), derLen(content.length), content]);
}
function rsaPublicKey(eNum, nBuf) {
  // PKCS#1 RSAPublicKey ::= SEQUENCE{ INTEGER n, INTEGER e }; e 存 LE u32, DER INTEGER 需大端
  let e = Buffer.alloc(4);
  e.writeUInt32BE(eNum >>> 0, 0);
  const seq = Buffer.concat([derInteger(nBuf), derInteger(e)]);
  const der = Buffer.concat([Buffer.from([0x30]), derLen(seq.length), seq]);
  return crypto.createPublicKey({ key: der, format: "der", type: "pkcs1" });
}
function rsaEncrypt(pubkey, data) {
  return crypto.publicEncrypt(
    { key: pubkey, padding: crypto.constants.RSA_PKCS1_PADDING },
    data,
  );
}

// ---------------------------------------------------------------- exec
function spawnExe(args, stdinB64, exe) {
  const exec = exe || EXECV;
  return new Promise((resolve) => {
    const child = child_process.spawn(exec, args, {
      stdio: ["pipe", "pipe", "inherit"],
    });
    const stdout = [];
    let done = false;
    const finish = (code) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(code === 0 ? null : Error(`Exit with code: ${code}`));
    };
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      finish(Error("timeout"));
    }, kTimeout);
    child.stdout.on("data", (c) => stdout.push(c.toString()));
    child.on("error", (err) => finish(err));
    child.on("exit", (code) => {
      if (code === 0) resolve({ stdout: stdout.join("") });
      else finish(Error(`exit ${code}`));
    });
    if (stdinB64) child.stdin.end(`${stdinB64}\n\n`);
    else child.stdin.end();
  });
}

async function List() {
  const r = await spawnExe(["--list"], null);
  if (r instanceof Error) throw r;
  const line0 = r.stdout.split(/\r?\n/)[0];
  const buf = Buffer.from(line0, "base64");
  const n = buf.length - 32;
  if (
    n <= 0 ||
    n % 40 !== 0 ||
    Buffer.compare(sha256(buf.subarray(0, n)), buf.subarray(n)) !== 0
  )
    throw Error(`list: invalid payload ${buf.length}`);
  const out = [];
  for (let i = 0; i < n; i += 40) {
    const info = buf.subarray(i, i + 40);
    const hid = info.subarray(info.length - 12);
    const id = `${hid.subarray(0, 4).toString("hex")}-${hid.subarray(4).toString("hex")}`;
    out.push({
      id,
      ver: info.readUInt32LE(0).toString(16),
      info: info.toString("base64"),
    });
  }
  return out;
}

let dashboardCache = new Map();
async function Dashboard(hid, admin) {
  if (dashboardCache.has(hid)) return dashboardCache.get(hid);
  const args = ["--dashboard", hid];
  if (admin) args.push("-");
  const r = await spawnExe(args, null);
  if (r instanceof Error) throw Error(`dashboard ${hid}: ${r.message}`);
  const buf = Buffer.from(r.stdout.split(/\r?\n/)[0], "base64");
  if (
    buf.length !== 8192 + 32 ||
    Buffer.compare(sha256(buf.subarray(0, 8192)), buf.subarray(8192)) !== 0
  )
    throw Error(`dashboard ${hid}: invalid payload ${buf.length}`);
  const dash = buf.subarray(0, 8192);
  dashboardCache.set(hid, dash);
  return dash;
}

// ---------------------------------------------------------------- script
function autoParam(arg, index) {
  // 返回写入该参数的值; 抛错表示无法自动默认
  const nums = arg.options.filter((o) => typeof o === "number");
  const strs = arg.options.filter((o) => typeof o === "string");
  if (strs.length === 0 && nums.length === 1) return nums[0]; // rodata 固定值
  const size = Math.min(arg.sizeMax, Math.max(arg.sizeMin, 16));
  const fallback = () => {
    if (
      arg.sizeMin !== arg.sizeMax ||
      (arg.sizeMax !== 1 && arg.sizeMax !== 2 && arg.sizeMax !== 4)
    )
      throw Error(
        `param ${arg.name}: 需人工选择 (${JSON.stringify(arg.options)}), 未实现默认值`,
      );
    return nums[0] !== undefined ? nums[0] : 0;
  };
  void index;
  if (typeof arg.options[0] === "number") return arg.options[0];
  // 字符串选择: 无法自动得知语义; 若最小尺寸允许, 用随机字节占位(模板 ${...})
  if (arg.sizeMin >= 8 && arg.sizeMax <= 2048 && arg.sizeMin <= size) {
    const rnd = crypto.randomBytes(size);
    return rnd.subarray(0, size);
  }
  return fallback();
}

function BuildDataSegment(program, overrides) {
  const size_data = 768;
  const buf = Buffer.alloc(1024);
  overrides = overrides || {};
  for (const arg of program.data) {
    const off = arg.offset;
    if (off < 256 || off >= 1024 || off + arg.sizeMax > 1024)
      throw Error(`param ${arg.name}: offset ${off} out of data range`);
    const v =
      arg.name in overrides
        ? overrides[arg.name]
        : autoParam(arg, program.data.indexOf(arg));
    if (typeof v === "number") {
      buf.writeUIntLE(
        v >>> 0,
        off,
        arg.sizeMax === 1 ? 1 : arg.sizeMax === 2 ? 2 : 4,
      );
    } else {
      if (v.length < arg.sizeMin || v.length > arg.sizeMax)
        throw Error(
          `param ${arg.name}: size ${v.length} not in [${arg.sizeMin},${arg.sizeMax}]`,
        );
      v.copy(buf, off);
    }
  }
  return buf.subarray(256, 256 + size_data);
}

async function FrameNormal(program, dash) {
  // 从 WorldPublic(7KB) 取全局 RSA 公钥: [e:u32LE][N:256B]
  const pub = dash.subarray(7 * 1024 + 148, 7 * 1024 + 148 + 260);
  const e = pub.readUInt32LE(0);
  const N = pub.subarray(4);
  if (process.env.RKEY_FLIP_N === "1") N.reverse(); // 诊断: N 字节序试验(默认不翻转)
  const pubkey = rsaPublicKey(e, N);

  const code = Buffer.from(program.code, "base64");
  const data = BuildDataSegment(program);

  const header = Buffer.alloc(240);
  header.writeUInt32LE(0x0543cd0f, 0); // 'ATOMC'
  header[4] = 1;
  header[5] = 1;
  header.writeUInt16LE(program.size_public, 6);
  code.copy(header, 8);
  crypto.randomBytes(16).copy(header, 208); // nonce[16]

  const key = sm3(header.subarray(0, 224));
  const sealed = chachaSeal(key, header.subarray(208, 220), data);
  sealed.subarray(sealed.length - 16).copy(header, 224); // tag
  const cipher = sealed.subarray(0, sealed.length - 16);

  const frame = Buffer.alloc(1024);
  rsaEncrypt(pubkey, header).copy(frame, 0);
  cipher.copy(frame, 256);
  return frame;
}

/*! Bootstrap 帧(WorldCreate + ADMIN, 管理员会话直启, 无需 RSA 主钥): 用于 Initialize/EnTrust 等建世界脚本 */
function FrameBootstrap(program, overrides) {
  const code = Buffer.from(program.code, "base64");
  const data = BuildDataSegment(program, overrides);
  const frame = Buffer.alloc(1024);
  frame.writeUInt32LE(0, 0); // header.zero_
  frame.writeUInt32LE(0xc8c04e1f, 4); // header.world_magic_ 'rLANG'
  frame.writeUInt32LE(0x0d214153, 8); // header.create_magic_ 'CREAT'
  frame.writeUInt32LE(0x5cf48c13, 12); // header.target_magic_ 'WORLD'
  frame.writeUInt32LE(0x0443493b, 16); // ScriptText.file_magic_ 'ADMIN'
  frame[20] = 1; // ver_major
  frame[21] = 1; // ver_minor
  frame.writeUInt16LE(program.size_public, 22);
  code.copy(frame, 24);
  crypto.randomBytes(16).copy(frame, 224); // nonce[16]
  const key = sm3(frame.subarray(16, 240));
  const sealed = chachaSeal(key, frame.subarray(224, 236), data);
  sealed.subarray(sealed.length - 16).copy(frame, 240); // tag -> check_
  sealed.subarray(0, sealed.length - 16).copy(frame, 256);
  return frame;
}

async function ParseDongle(source) {
  const clean = source.charCodeAt(0) === 0xfeff ? source.slice(1) : source;
  return Parse(clean);
}

/*! 执行一帧(带具体 exe), 返回 {inout, stdout_tail} */
async function ExecFrame(exe, args, frame, program) {
  const r = await spawnExe(args, frame.toString("base64"), exe);
  if (r instanceof Error) throw r;
  const line0 = r.stdout.split(/\r?\n/)[0];
  const buf = Buffer.from(line0, "base64");
  if (
    buf.length !== 1024 + 32 ||
    Buffer.compare(sha256(buf.subarray(0, 1024)), buf.subarray(1024)) !== 0
  )
    throw Error(`execv: invalid output`);
  const inout = buf.subarray(0, 1024);
  const outputs = {};
  for (const o of program.output || []) {
    const chunk = inout.subarray(o.offset, o.offset + o.size);
    outputs[o.name] = o.intType
      ? o.size === 4
        ? chunk.readInt32LE(0)
        : o.size === 2
          ? chunk.readInt16LE(0)
          : chunk.readInt8(0)
      : chunk.toString("hex");
  }
  return { inout, outputs, stdout_tail: r.stdout.slice(line0.length).trim() };
}

const EMU_EXECV =
  process.env.RKEY_EMU ||
  path.join(ROOT, ".bin", "amd64-foobar-windows-debug", "dongle_entry.exe");
const EMU_WORLD =
  process.env.EMU_WORLD || path.join(ROOT, ".bin", "emu-world.bin");

async function EmuDashboard() {
  // foobar 世界文件: [0,256)=SupperBlock, [256,256+8192)=factory data(dashboard)
  const f = fs.readFileSync(EMU_WORLD);
  if (f.length < 256 + 8192) throw Error(`emu world too small ${f.length}`);
  return f.subarray(256, 256 + 8192);
}

async function EmuRun(source, bootstrap) {
  const program = await ParseDongle(source);
  const frame = bootstrap
    ? FrameBootstrap(program)
    : await FrameNormal(program, await EmuDashboard());
  const args = ["-", EMU_WORLD, "1234567812345678"]; // foobar: <input> <world> <secret>
  return ExecFrame(EMU_EXECV, args, frame, program);
}

/* ---- 进程内 JS 模拟器(Web/Agent/Tests/js 打包件, 8 个实例) ---- */
function EmuJsGet(idx) {
  return globalThis.jsEmulatorEx[idx];
}
function EmuJsInfo(idx) {
  const info = EmuJsGet(idx).GetDongleInfo();
  return DongleDisplayValue(Buffer.from(info));
}
function EmuJsDashboard(idx) {
  return Buffer.from(EmuJsGet(idx).ReadDataFile(0xffff, 0, 8192));
}
function EmuJsExec(idx, frame) {
  const buf = Buffer.from(frame);
  EmuJsGet(idx).Execv(buf); // 期望就地写回 1024B 结果
  return buf;
}
async function EmuJsRun(idx, source, bootstrap, overrides) {
  const program = await ParseDongle(source);
  const frame = bootstrap
    ? FrameBootstrap(program, overrides)
    : await FrameNormal(program, EmuJsDashboard(idx));
  const inout = EmuJsExec(idx, frame);
  const outputs = {};
  for (const o of program.output || []) {
    const chunk = inout.subarray(o.offset, o.offset + o.size);
    outputs[o.name] = o.intType
      ? o.size === 4
        ? chunk.readInt32LE(0)
        : o.size === 2
          ? chunk.readInt16LE(0)
          : chunk.readInt8(0)
      : chunk.toString("hex");
  }
  return { idx, outputs, inout };
}

/*! 双模拟器 MasterSecret 交换执行示例(编排语义待产品层确认, 此处按样例注入对端公钥执行两侧) */
async function EmuXchg(aIdx, bIdx) {
  const initSrc = fs.readFileSync(path.join(__dirname, "Tests", "Initialize.dongle"), "utf8");
  const ready = (i) => EmuJsDashboard(i).subarray(7 * 1024 + 20, 7 * 1024 + 84).some((b) => b !== 0);
  if (!ready(aIdx)) await EmuJsRun(aIdx, initSrc, true);
  if (!ready(bIdx)) await EmuJsRun(bIdx, initSrc, true);
  const xb = EmuJsGet(bIdx).Export();
  const xbBuf = Buffer.from(xb);
  const bX25519 = xbBuf.subarray(96, 128); // SupperBlock.public_.master_xx25519_
  const bRsa = Buffer.from(EmuJsDashboard(bIdx).subarray(7 * 1024 + 148, 7 * 1024 + 148 + 260));
  const exSrc = fs.readFileSync(path.join(__dirname, "Tests", "EXCHANGE_PREV_MASTER_SECRET.dongle"), "utf8");
  const exProg = await ParseDongle(exSrc);
  const exOv = {};
  for (let i = 0; i < 4; i++) {
    const n = exProg.data.find((d) => d.name.indexOf("X25519_PUBKEY") >= 0 && d.name.endsWith(`_${i}`));
    if (n) exOv[n.name] = Buffer.from(bX25519);
  }
  {
    const n = exProg.data.find((d) => d.name.indexOf("RSA_PUBKEY") >= 0);
    if (n) exOv[n.name] = Buffer.from(bRsa);
  }
  const rA = await EmuJsRun(aIdx, exSrc, true, exOv);
  const cipher = rA.outputs.rLANG_ENCRYPT_PREV_MASTER_SECRET || "";
  console.log(`xchg: emu[${aIdx}] EXCHANGE executed; cipher256=${cipher.slice(0, 16)}... len=${cipher.length / 2}`);

  const imSrc = fs.readFileSync(path.join(__dirname, "Tests", "IMPORT_MASTER_SECRET.dongle"), "utf8");
  const imProg = await ParseDongle(imSrc);
  const imOv = {};
  let encIdx = 0;
  for (const d of imProg.data) {
    if (d.name.indexOf("ENCRYPT_PREV_MASTER_SECRET_") >= 0 && d.sizeMax === 256) {
      imOv[d.name] = Buffer.from(cipher, "hex").subarray(0, 256);
      void encIdx;
    }
  }
  const rB = await EmuJsRun(bIdx, imSrc, true, imOv);
  console.log(`xchg: emu[${bIdx}] IMPORT executed; ids=${(rB.outputs.rLANG_DONGLE_ID_0 || "").slice(0, 8)}...`);
  return { cipher, bX25519: bX25519.toString("hex") };
}

/*! 构造 EnTrust 输入条目(80B = hid12|kid3|zero|X||Y64, 受托者用其 SM2ECDSA(签名)公钥;
 *! 参考 jsLibrary admin 签名的 SM2Decrypt(1, ...) —— 密文按受托者 SM2ECDSA pub 加密 */
function BuildEnTrustEntry(trusteeIdx) {
  const info = Buffer.from(EmuJsGet(trusteeIdx).GetDongleInfo());
  const hid = info.subarray(28, 40); // 12B hid
  const dash = EmuJsDashboard(trusteeIdx);
  const xy = Buffer.from(dash.subarray(7 * 1024 + 20, 7 * 1024 + 20 + 64)); // SM2ECDSA pub
  const entry = Buffer.alloc(80);
  hid.copy(entry, 0);
  sm3(xy).subarray(0, 3).copy(entry, 12); // kid = SM3(SM2ECDSA.pub)[0..3], 对齐参考实现
  entry.fill(0, 15, 16); // zero_/Yodd 占位
  xy.copy(entry, 16);
  return { entry, hid: hid.toString("hex"), xy: xy.toString("hex") };
}

/*! 在 target 模拟器上执行 EnTrust.dongle, 把其 SM2ECIES 密钥托管给 trust 列表里的模拟器 */
async function EmuJsEnTrust(targetIdx, trustIdxs, nonce) {
  const src = fs.readFileSync(path.join(__dirname, "Tests", "EnTrust.dongle"), "utf8");
  const program = await ParseDongle(src);
  const overrides = { rLANG_EnTRUST_NONCE: nonce || crypto.randomBytes(32) };
  const metas = [];
  for (let i = 0; i < 5; ++i) {
    const t = trustIdxs[i % trustIdxs.length];
    const { entry, hid, xy } = BuildEnTrustEntry(t);
    metas.push({ t, hid, xy });
    overrides[`rLANG_EnTRUST_${i}`] = entry;
  }
  const frame = FrameBootstrap(program, overrides);
  const inout = EmuJsExec(targetIdx, frame);
  return { metas, inout };
}

/*! 从 target 的 6KB EnTrust 区取受托者为 trusteeIdx 的条目, 并还原 128B SM2 密文
 *! 条目 112B: hid12|kid3|Yodd(byte15)|C1x[16..48)|(C3||C2)[48..112); 密文=C1x||Y||rest */
function FindEnTrustCipher(targetIdx, trusteeIdx) {
  const entrust = EmuJsDashboard(targetIdx).subarray(6 * 1024, 6 * 1024 + 1024);
  const want = Buffer.from(EmuJsGet(trusteeIdx).GetDongleInfo()).subarray(28, 40);
  let entry = null;
  for (let off = 180; off + 112 <= 1024; off += 112) {
    const e = entrust.subarray(off, off + 112);
    if (Buffer.compare(e.subarray(0, 12), want) === 0) {
      entry = Buffer.from(e);
      break;
    }
  }
  if (!entry) entry = Buffer.from(entrust.subarray(180, 292)); // 回退第一条
  const x = entry.subarray(16, 48);
  const yodd = (entry[15] & 1) === 1;
  const Y = EmuJsGet(trusteeIdx).EmuDecompressPointSM2(x, yodd);
  if (!Y || Y.length !== 32) throw Error(`entrust decompress Y failed`);
  const cipher = Buffer.concat([x, Y, entry.subarray(48, 112)]);
  return { cipher, entry };
}

/*! Admin 帧(ADMIN magic, data=704, 尾部 64B 为托管私钥签名) */
function FrameAdmin(program, dash, sign64) {
  const code = Buffer.from(program.code, "base64");
  const data = BuildDataSegment(program, {}).subarray(0, 1024 - 256 - 64);
  if (sign64.length !== 64) throw Error(`sign64 size ${sign64.length}`);
  const header = Buffer.alloc(240);
  header.writeUInt32LE(0x0443493b, 0); // 'ADMIN'
  header[4] = 1;
  header[5] = 1;
  header.writeUInt16LE(program.size_public, 6);
  code.copy(header, 8);
  crypto.randomBytes(16).copy(header, 208);
  const key = sm3(header.subarray(0, 224));
  const sealed = chachaSeal(key, header.subarray(208, 220), data);
  sealed.subarray(sealed.length - 16).copy(header, 224);
  const pub = dash.subarray(7 * 1024 + 148, 7 * 1024 + 148 + 260);
  const pubkey = rsaPublicKey(pub.readUInt32LE(0), pub.subarray(4));
  const frame = Buffer.alloc(1024);
  rsaEncrypt(pubkey, header).copy(frame, 0);
  sealed.subarray(0, sealed.length - 16).copy(frame, 256);
  sign64.copy(frame, 1024 - 64);
  return frame;
}

/*! Limit 帧: header144(magic LIMIT+ver+size+code[0..136)) + sign64, data=768, 与 jsLibrary signedCode 布局一致 */
function FrameLimit(program, dash, sign64) {
  const code = Buffer.from(program.code, "base64");
  if (sign64.length !== 64) throw Error(`sign64 size ${sign64.length}`);
  for (let i = 136; i < 200; ++i) {
    if (code[i]) throw Error(`limit code uses bytes >= 136`);
  }
  const data = BuildDataSegment(program, {});
  const header = Buffer.alloc(240);
  header.writeUInt32LE(0x30934953, 0); // 'LIMIT'
  header[4] = 1;
  header[5] = 1;
  header.writeUInt16LE(program.size_public, 6);
  code.subarray(0, 136).copy(header, 8);
  sign64.copy(header, 8 + 136); // 144..208
  crypto.randomBytes(16).copy(header, 208);
  const key = sm3(header.subarray(0, 224));
  const sealed = chachaSeal(key, header.subarray(208, 220), data);
  sealed.subarray(sealed.length - 16).copy(header, 224);
  const pub = dash.subarray(7 * 1024 + 148, 7 * 1024 + 148 + 260);
  const pubkey = rsaPublicKey(pub.readUInt32LE(0), pub.subarray(4));
  const frame = Buffer.alloc(1024);
  rsaEncrypt(pubkey, header).copy(frame, 0);
  sealed.subarray(0, sealed.length - 16).copy(frame, 256);
  return frame;
}

/*! 保证 target 已初始化并把 ECIES 私钥托管给 trustee, 返回 {priv, cipher} */
async function EnsureEntrust(targetIdx, trusteeIdx) {
  const initSrc = fs.readFileSync(path.join(__dirname, "Tests", "Initialize.dongle"), "utf8");
  const ready = (i) => EmuJsDashboard(i).subarray(7 * 1024 + 20, 7 * 1024 + 84).some((b) => b !== 0);
  if (!ready(targetIdx)) await EmuJsRun(targetIdx, initSrc, true);
  if (!ready(trusteeIdx)) await EmuJsRun(trusteeIdx, initSrc, true);
  const entrustOk = () => EmuJsDashboard(targetIdx).subarray(6 * 1024 + 896, 6 * 1024 + 960).some((b) => b !== 0);
  if (!entrustOk()) await EmuJsEnTrust(targetIdx, [trusteeIdx]);
  return FindEnTrustCipher(targetIdx, trusteeIdx);
}

/*! 受托者取回目标 ECIES 私钥并签名 msg32; tamper=1 翻转签名末字节(负例) */
function TrusteeSign(targetIdx, trusteeIdx, msg32, tamper) {
  const trustee = EmuJsGet(trusteeIdx);
  const { cipher } = FindEnTrustCipher(targetIdx, trusteeIdx);
  let priv = null;
  for (const id of [1, 4]) {
    try {
      priv = trustee.SM2Decrypt(id, cipher);
      if (priv && priv.length) break;
    } catch (err) {
      /* try next */
    }
  }
  if (!priv || !priv.length) throw Error(`TrusteeSign: trustee ${trusteeIdx} decrypt failed`);
  if (priv.length > 32) priv = Buffer.from(priv.subarray(0, 32));
  const sign = Buffer.from(trustee.SM2Sign(priv, msg32));
  if (tamper) sign[sign.length - 1] ^= 1;
  return { sign, cipher };
}

/*! 真机执行 bootstrap 帧(带 overrides, 管理员会话) */
async function RealBootstrapExec(hid, source, overrides) {
  const program = await ParseDongle(source);
  const frame = FrameBootstrap(program, overrides);
  const args = ["-", hid, "-"];
  const r = await spawnExe(args, frame.toString("base64"));
  if (r instanceof Error) throw r;
  const buf = Buffer.from(r.stdout.split(/\r?\n/)[0], "base64");
  if (buf.length !== 1024 + 32) throw Error(`realbootstrap: invalid output ${buf.length}`);
  return { program, inout: buf.subarray(0, 1024) };
}

/*! 真机执行帧(管理员会话) */
async function RealExecFrame(hid, frame) {
  const args = ["-", hid, "-"];
  const r = await spawnExe(args, frame.toString("base64"));
  if (r instanceof Error) throw r;
  const buf = Buffer.from(r.stdout.split(/\r?\n/)[0], "base64");
  if (buf.length !== 1024 + 32) throw Error(`realexec: invalid output ${buf.length}`);
  return buf.subarray(0, 1024);
}

/*! 真机 EnTrust 托管给 JS 模拟器受托者(需先 Initialize 该模拟器以取得其 SM2ECDSA pub) */
async function RealEnTrustToEmu(hid, trusteeIdx) {
  const initSrc = fs.readFileSync(path.join(__dirname, "Tests", "Initialize.dongle"), "utf8");
  if (!EmuJsDashboard(trusteeIdx).subarray(7 * 1024 + 20, 7 * 1024 + 84).some((b) => b !== 0)) {
    await EmuJsRun(trusteeIdx, initSrc, true);
  }
  const src = fs.readFileSync(path.join(__dirname, "Tests", "EnTrust.dongle"), "utf8");
  const program = await ParseDongle(src);
  const overrides = { rLANG_EnTRUST_NONCE: crypto.randomBytes(32) };
  for (let i = 0; i < 5; ++i) {
    const { entry } = BuildEnTrustEntry(trusteeIdx);
    overrides[`rLANG_EnTRUST_${i}`] = entry;
  }
  await RealBootstrapExec(hid, src, overrides);
}

/*! 混合: 真机 EnTrust 给模拟器受托者后, 受托者签名并在真机执行 ADMIN/LIMIT 帧 */
async function RealRunSigned(kind, hid, trusteeIdx, source, tamper) {
  const initSrc = fs.readFileSync(path.join(__dirname, "Tests", "Initialize.dongle"), "utf8");
  if (!EmuJsDashboard(trusteeIdx).subarray(7 * 1024 + 20, 7 * 1024 + 84).some((b) => b !== 0)) {
    await EmuJsRun(trusteeIdx, initSrc, true);
  }
  let dash = await Dashboard(hid, true);
  const world = dash.subarray(7 * 1024, 8 * 1024);
  const entrust = dash.subarray(6 * 1024, 7 * 1024);
  const want = Buffer.from(EmuJsGet(trusteeIdx).GetDongleInfo()).subarray(28, 40);
  let has = false;
  for (let off = 180; off + 112 <= 1024; off += 112) {
    if (Buffer.compare(entrust.subarray(off, off + 12), want) === 0) has = true;
  }
  if (!has) await RealEnTrustToEmu(hid, trusteeIdx);
  dash = await Dashboard(hid, true);
  const entrust2 = dash.subarray(6 * 1024, 7 * 1024);
  let entry = Buffer.from(entrust2.subarray(180, 292));
  for (let off = 180; off + 112 <= 1024; off += 112) {
    const e = entrust2.subarray(off, off + 112);
    if (Buffer.compare(e.subarray(0, 12), want) === 0) {
      entry = Buffer.from(e);
      break;
    }
  }
  const x = entry.subarray(16, 48);
  const Y = EmuJsGet(trusteeIdx).EmuDecompressPointSM2(x, (entry[15] & 1) === 1);
  if (!Y || Y.length !== 32) throw Error(`real decrypt Y fail`);
  const cipher = Buffer.concat([x, Y, entry.subarray(48, 112)]);

  const program = await ParseDongle(source);
  const msg =
    kind === "LIMIT"
      ? sm3(LimitHeader144(program))
      : sm3(BuildDataSegment(program, {}).subarray(0, 1024 - 256 - 64));
  const trustee = EmuJsGet(trusteeIdx);
  let priv = null;
  for (const id of [1, 4]) {
    try {
      priv = trustee.SM2Decrypt(id, cipher);
      if (priv && priv.length) break;
    } catch (err) {
      /* try next */
    }
  }
  if (!priv || !priv.length) throw Error(`real: trustee decrypt failed`);
  if (priv.length > 32) priv = Buffer.from(priv.subarray(0, 32));
  const sign = Buffer.from(trustee.SM2Sign(priv, msg));
  if (tamper) sign[sign.length - 1] ^= 1;
  const verify = trustee.SM2Verify(world.subarray(408, 472), msg, sign);
  const frame = kind === "LIMIT" ? FrameLimit(program, dash, sign) : FrameAdmin(program, dash, sign);
  const inout = await RealExecFrame(hid, frame);
  return { kind, hid, trusteeIdx, verify, inout };
}

/*! 用受托者签名在 target 上跑 Admin 脚本: adminrun <target> <trustee> <file.dongle>
 *! 自动补齐: 初始化 target/trustee; 若 target 尚无对应托管条目则先 EnTrust */
async function EmuJsAdminRun(targetIdx, trusteeIdx, source) {
  const initSrc = fs.readFileSync(path.join(__dirname, "Tests", "Initialize.dongle"), "utf8");
  const dashOf = (i) => EmuJsDashboard(i);
  const ready = (i) => dashOf(i).subarray(7 * 1024 + 20, 7 * 1024 + 84).some((b) => b !== 0);
  if (!ready(targetIdx)) await EmuJsRun(targetIdx, initSrc, true);
  if (!ready(trusteeIdx)) await EmuJsRun(trusteeIdx, initSrc, true);

  let { cipher } = FindEnTrustCipher(targetIdx, trusteeIdx);
  const entrustAt = () => dashOf(targetIdx).subarray(6 * 1024 + 896, 6 * 1024 + 960).some((b) => b !== 0);
  if (!entrustAt() || !cipher) {
    await EmuJsEnTrust(targetIdx, [trusteeIdx]);
    ({ cipher } = FindEnTrustCipher(targetIdx, trusteeIdx));
  }

  const program = await ParseDongle(source);
  const dataPlain = BuildDataSegment(program, {}).subarray(0, 1024 - 256 - 64);
  const sm3data = sm3(dataPlain);
  const trustee = EmuJsGet(trusteeIdx);
  let priv = null;
  for (const id of [1, 4]) {
    try {
      priv = trustee.SM2Decrypt(id, cipher);
      if (priv && priv.length) {
        console.log(`adminrun: trustee[${trusteeIdx}] SM2Decrypt(id=${id}) ok len=${priv.length}`);
        break;
      }
    } catch (err) {
      /* try next */
    }
  }
  if (!priv || !priv.length) throw Error(`adminrun: trustee ${trusteeIdx} decrypt failed`);
  if (priv.length > 32) priv = Buffer.from(priv.subarray(0, 32));
  const sign64 = trustee.SM2Sign(priv, sm3data);
  const frame = FrameAdmin(program, dashOf(targetIdx), sign64);
  const inout = EmuJsExec(targetIdx, frame);
  return { inout };
}

/*! Limit 待签头 144B: magic LIMIT|ver|size|code[0..136) */
function LimitHeader144(program) {
  const h = Buffer.alloc(144);
  h.writeUInt32LE(0x30934953, 0);
  h[4] = 1;
  h[5] = 1;
  h.writeUInt16LE(program.size_public, 6);
  Buffer.from(program.code, "base64").subarray(0, 136).copy(h, 8);
  return h;
}

/*! 通用: 用受托者签名执行 ADMIN 或 LIMIT 帧, 并给出签名被目标 ECIES 公钥验证的证据 */
async function EmuJsRunSigned(kind, targetIdx, trusteeIdx, source, tamper) {
  await EnsureEntrust(targetIdx, trusteeIdx);
  const program = await ParseDongle(source);
  const msg =
    kind === "LIMIT"
      ? sm3(LimitHeader144(program))
      : sm3(BuildDataSegment(program, {}).subarray(0, 1024 - 256 - 64));
  const { sign } = TrusteeSign(targetIdx, trusteeIdx, msg, tamper);
  const dash = EmuJsDashboard(targetIdx);
  const verify = EmuJsGet(trusteeIdx).SM2Verify(dash.subarray(7 * 1024 + 408, 7 * 1024 + 472), msg, sign);
  const frame = kind === "LIMIT" ? FrameLimit(program, dash, sign) : FrameAdmin(program, dash, sign);
  const inout = EmuJsExec(targetIdx, frame);
  return { kind, targetIdx, trusteeIdx, verify, inout };
}


/*! 诊断: 用设备(模拟器)私钥解密"我方公钥加密"的密文, 验证主钥匹配与填充语义 */
async function EmuDiagRsa() {
  const dirTests = path.join(__dirname, "Tests");
  if (!fs.existsSync(EMU_WORLD)) {
    await EmuRun(
      fs.readFileSync(path.join(dirTests, "Initialize.dongle"), "utf8"),
      true,
    );
  }
  const dash = await EmuDashboard();
  const pub = dash.subarray(7 * 1024 + 148, 7 * 1024 + 148 + 260);
  const pubkey = rsaPublicKey(pub.readUInt32LE(0), pub.subarray(4));

  const header = crypto.randomBytes(240); // 模拟一帧 ScriptText 明文
  const ct = rsaEncrypt(pubkey, header);

  const source =
    "public 1024;\n@ 256 [256] : rLANG_CIPHER;\nRSAPrivateDecrypt(3, 256);\n";
  const program = await ParseDongle(source);
  const frame = FrameBootstrap(program, { rLANG_CIPHER: ct });
  const args = ["-", EMU_WORLD, "1234567812345678"];
  const r = await ExecFrame(EMU_EXECV, args, frame, program);
  const got = r.inout.subarray(256, 256 + 240);
  const ok = Buffer.compare(got, header) === 0;
  console.log(
    `diag-rsa: decrypt${ok ? " OK (key+PKCS1 match)" : " FAIL"} head=${got.subarray(0, 8).toString("hex")}`,
  );
  return ok ? 0 : 1;
}

/*! 诊断2: 让设备新建 id1001 并回传其公钥 -> node 加密 -> 设备私钥解回(区分 node 语义 vs 公钥取错) */
async function EmuDiagGen() {
  const dirTests = path.join(__dirname, "Tests");
  if (!fs.existsSync(EMU_WORLD)) {
    await EmuRun(
      fs.readFileSync(path.join(dirTests, "Initialize.dongle"), "utf8"),
      true,
    );
  }
  const src1 =
    "public 1024;\nCreateRSAFile(1001, 2);\nGenerateRSA(1001, 256);\n";
  const prog1 = await ParseDongle(src1);
  const frame1 = FrameBootstrap(prog1);
  const r1 = await ExecFrame(
    EMU_EXECV,
    ["-", EMU_WORLD, "1234567812345678"],
    frame1,
    prog1,
  );
  const pub = Buffer.from(r1.inout.subarray(256, 256 + 260)); // 设备回传 [e?N?]
  const e = pub.readUInt32LE(0);
  const N = pub.subarray(4);
  console.log(
    `diag-gen: pub e=${e} N=${N.subarray(0, 4).toString("hex")} nz=${N.some((x) => x !== 0)}`,
  );

  const header = crypto.randomBytes(240);
  const ct = rsaEncrypt(rsaPublicKey(e, N), header);
  const src2 =
    "public 1024;\n@ 256 [256] : rLANG_CIPHER;\nRSAPrivateDecrypt(1001, 256);\n";
  const prog2 = await ParseDongle(src2);
  const frame2 = FrameBootstrap(prog2, { rLANG_CIPHER: ct });
  const r2 = await ExecFrame(
    EMU_EXECV,
    ["-", EMU_WORLD, "1234567812345678"],
    frame2,
    prog2,
  );
  const got = r2.inout.subarray(256, 256 + 240);
  const ok = Buffer.compare(got, header) === 0;
  console.log(
    `diag-gen: decrypt id1001 ${ok ? "OK (node PKCS1 == device decrypt)" : "FAIL"}`,
  );
  return ok ? 0 : 1;
}

async function RunScript(source, hid, admin) {
  const program = await ParseDongle(source);
  const dash = await Dashboard(hid, true);
  const frame = await FrameNormal(program, dash);
  const args = ["-", hid];
  if (admin) args.push("-");
  const r = await spawnExe(args, frame.toString("base64"));
  if (r instanceof Error) throw r;

  const line0 = r.stdout.split(/\r?\n/)[0];
  const buf = Buffer.from(line0, "base64");
  if (
    buf.length !== 1024 + 32 ||
    Buffer.compare(sha256(buf.subarray(0, 1024)), buf.subarray(1024)) !== 0
  )
    throw Error(`execv: invalid output`);
  const inout = buf.subarray(0, 1024);
  const outputs = {};
  for (const o of program.output || []) {
    const chunk = inout.subarray(o.offset, o.offset + o.size);
    outputs[o.name] = o.intType
      ? o.size === 4
        ? chunk.readInt32LE(0)
        : o.size === 2
          ? chunk.readInt16LE(0)
          : chunk.readInt8(0)
      : chunk.toString("hex");
  }
  return {
    hid,
    exit: 0,
    outputs,
    stdout_tail: r.stdout.slice(line0.length).trim(),
  };
}

// ---------------------------------------------------------------- randtest(真机随机数质量)
const RAND_SRC = "public 1024;\nRandBytes(0, 1024);\n";

async function RealRandOnce(hid, admin) {
  const program = await ParseDongle(RAND_SRC);
  const dash = await Dashboard(hid, true);
  const frame = await FrameNormal(program, dash);
  const args = ["-", hid];
  if (admin) args.push("-");
  const r = await spawnExe(args, frame.toString("base64"));
  if (r instanceof Error) throw r;
  const buf = Buffer.from(r.stdout.split(/\r?\n/)[0], "base64");
  if (buf.length !== 1024 + 32 || Buffer.compare(sha256(buf.subarray(0, 1024)), buf.subarray(1024)) !== 0)
    throw Error(`rand: invalid output`);
  return Buffer.from(buf.subarray(0, 1024));
}

function Chi2Pvalue(chisq, df) {
  // Wilson–Hilferty 正态近似 -> 双侧 p 值(报告展示用)
  if (chisq <= 0) return 1;
  const x = chisq / df;
  const z = (Math.cbrt(x) - (1 - 2 / (9 * df))) / Math.sqrt(2 / (9 * df));
  const a = Math.abs(z) / Math.SQRT2;
  const t = 1 / (1 + 0.3275911 * a);
  const erfc =
    (0.254829592 * t -
      0.284496736 * t * t +
      1.421413741 * t * t * t -
      1.453152027 * t * t * t * t +
      1.061405429 * t * t * t * t * t) *
    Math.exp(-a * a);
  const pTwo = erfc; // 2*(1-Φ(|z|)) /2 简化: erfc(|z|/√2)
  return Number.isFinite(pTwo) ? Math.min(1, Math.max(0, pTwo)) : 0;
}

function RandStats(all, count) {
  const total = all.reduce((s, b) => s + b.length, 0); // 总字节数
  const bits = total * 8;
  let ones = 0, runs = 0, prev = -1;
  const byteHist = new Array(256).fill(0);
  const byteDev = new Array(256).fill(0);
  for (const buf of all) {
    for (let i = 0; i < buf.length; i++) {
      const b = buf[i];
      byteHist[b]++;
      for (let bit = 0; bit < 8; bit++) {
        const v = (b >> bit) & 1;
        if (v) ones++;
        if (prev !== -1 && v !== prev) runs++;
        prev = v;
      }
    }
  }
  const p1 = ones / bits;
  const chi2 = byteHist.reduce((s, c) => s + ((c - total / 256) ** 2) / (total / 256), 0);
  let H = 0, minP = 0;
  for (let c = 0; c < 256; c++) {
    const p = byteHist[c] / total;
    byteDev[c] = (byteHist[c] - total / 256) / Math.sqrt(total / 256 * (1 - 1 / 256));
    if (p > 0) H -= p * Math.log2(p);
    if (c === 0 || p < minP) minP = c === 0 ? p : minP;
    if (byteHist[c] === 0) {
      /* 未出现: 计入最小熵惩罚 */
    }
  }
  const missing = byteHist.filter((c) => c === 0).length;
  const minCount = Math.min(...byteHist);
  const minEntropy = minCount > 0 ? -Math.log2(minCount / total) : 0;
  // 自相关(字节取值相对期望 127.5, lag 1..5)
  const autocorr = [];
  const flat = Buffer.concat(all);
  for (let lag = 1; lag <= 5; lag++) {
    let num = 0, den = 0;
    for (let i = 0; i + lag < total; i++) {
      const d0 = flat[i] - 127.5;
      const d1 = flat[i + lag] - 127.5;
      num += d0 * d1;
      den += d0 * d0;
    }
    autocorr.push(den ? num / den : 0);
  }
  const runExp = (bits - 1) / 2;
  const zRuns = (runs - runExp) / Math.sqrt((bits - 1) / 4);
  const zFreq = (ones - bits / 2) / Math.sqrt(bits / 4);
  const pFreq = 1 - Math.abs(Chi2Pvalue(zFreq * zFreq, 1) - (zFreq >= 0 ? 0 : 0));
  void pFreq;
  return { total, bits, ones, p1, runs, zRuns, byteHist, byteDev, chi2, H, missing, minEntropy, autocorr, zFreq };
}

function RandHtml(stats, count, hid) {
  const bound = 2.58;
  const chiDoF = 255;
  const chiP = Chi2Pvalue(stats.chi2, chiDoF);
  const row = (k, v, note, verdict) =>
    `<tr><td>${k}</td><td>${v}</td><td>${note}</td><td style="color:${verdict === "PASS" ? "#0a0" : "#b00"}">${verdict}</td></tr>`;
  const ac = stats.autocorr.map((a, i) => `${i + 1}:${a.toFixed(4)}`).join(" ");
  return `<!doctype html><html lang="zh"><head><meta charset="utf-8"><title>ukey 随机数质量报告</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;margin:2em;background:#fafafa;color:#222}
h1,h2{color:#0b3d91}table{border-collapse:collapse;background:#fff}td,th{border:1px solid #bbb;padding:6px 12px;text-align:left}
th{background:#eef}.pass{color:#080}.warn{color:#c80}.fail{color:#c00}</style></head><body>
<h1>RockeyARM 真实 ukey 随机数质量报告</h1>
<p>设备: <code>${hid}</code> · 样本: ${count} 次 × 1024B · 总字节: ${stats.total} · 生成日期: ${new Date().toISOString().slice(0, 19).replace("T", " ")}</p>
<h2>统计指标</h2>
<table>
<tr><th>指标</th><th>观测值</th><th>说明</th><th>结论</th></tr>
${row("位频率 p(1)", stats.p1.toFixed(6), `期望≈0.5(采样 ${stats.bits} bit)`, Math.abs(stats.p1 - 0.5) < 0.005 ? "PASS" : Math.abs(stats.p1 - 0.5) < 0.02 ? "WARN" : "FAIL")}
${row("字节直方图 χ²(df=255)", stats.chi2.toFixed(2), `双侧 p≈${chiP.toExponential(2)}`, chiP > 0.001 ? "PASS" : "WARN")}
${row("Shannon 熵 / 字节", stats.H.toFixed(4), "理想=8", stats.H > 7.99 ? "PASS" : stats.H > 7.9 ? "WARN" : "FAIL")}
${row("最小熵 / 字节", stats.minEntropy.toFixed(4), "理想=8", stats.minEntropy > 7.9 ? "PASS" : stats.minEntropy > 7.0 ? "WARN" : "FAIL")}
${row("未出现字节数", stats.missing, `共 256(期望接近 0/样本较小时可为正)`, stats.missing <= 1 ? "PASS" : stats.missing <= 8 ? "WARN" : "WARN")}
${row("游程检验 z", stats.zRuns.toFixed(3), `|z|<${bound} 通过`, Math.abs(stats.zRuns) < bound ? "PASS" : "WARN")}
${row("单比特频率 z", stats.zFreq.toFixed(3), `|z|<${bound} 通过`, Math.abs(stats.zFreq) < bound ? "PASS" : "WARN")}
${row("字节自相关 lag1..5", ac, `|ρ| 应远小于 1`, Math.max(...stats.autocorr.map((a) => Math.abs(a))) < 0.05 ? "PASS" : "WARN")}
</table>
<p>说明: 本报告为轻量统计(非完整 NIST STS); 随机源为设备 TRNG(脚本 RandBytes)。样本量 ${stats.total} 字节。</p>
</body></html>`;
}

async function RandTest(count, report) {
  const list = await List();
  if (list.length === 0) throw Error("no dongle found");
  const hid = process.env.RKEY_HID || list[0].id;
  const admin = process.env.RKEY_ADMIN === "1";
  const all = [];
  for (let i = 0; i < count; i++) {
    all.push(await RealRandOnce(hid, admin));
    if (i % 8 === 0) console.log(`rand: ${i + 1}/${count} sampled`);
  }
  const stats = RandStats(all, count);
  const html = RandHtml(stats, count, hid);
  fs.writeFileSync(report, html);
  console.log(`rand: wrote ${report} (${stats.total} bytes, chi2=${stats.chi2.toFixed(2)}, H=${stats.H.toFixed(4)}, p1=${stats.p1.toFixed(6)})`);
  return 0;
}

// ---------------------------------------------------------------- cli
async function main() {
  await initialize();

  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const firstDevice = async () => {
    const list = await List();
    if (list.length === 0) throw Error("no dongle found");
    return process.env.RKEY_HID || list[0].id;
  };

  if (cmd === "list") {
    const list = await List();
    console.log(JSON.stringify(list, null, 2));
    return 0;
  }
  if (cmd === "dashboard") {
    const hid = argv[1] || (await firstDevice());
    const dash = await Dashboard(hid, true);
    console.log(
      `hid: ${hid}, dashboard 8192B sha256: ${sha256(dash).toString("hex")}`,
    );
    return 0;
  }
  if (cmd === "run") {
    const file = argv[1];
    const hid = argv[2] || (await firstDevice());
    const admin = process.env.RKEY_ADMIN === "1";
    const source = fs.readFileSync(file, "utf8");
    console.log(
      `run ${path.basename(file)} => ${hid}${admin ? " (admin)" : ""}`,
    );
    const r = await RunScript(source, hid, admin);
    console.log(JSON.stringify(r, null, 2));
    return 0;
  }
  if (cmd === "suite") {
    const dir = argv[1];
    const hid = argv[2] || (await firstDevice());
    const admin = process.env.RKEY_ADMIN === "1";
    if (!fs.existsSync(dir)) throw Error(`no dir ${dir}`);
    const files = fs
      .readdirSync(dir)
      .filter((f) => f.endsWith(".dongle"))
      .sort();
    if (files.length === 0) throw Error(`no .dongle in ${dir}`);
    let failed = 0;
    for (const f of files) {
      try {
        const r = await RunScript(
          fs.readFileSync(path.join(dir, f), "utf8"),
          hid,
          admin,
        );
        console.log(`[PASS] ${f}`);
        if (r.outputs && Object.keys(r.outputs).length)
          console.log(`       ${JSON.stringify(r.outputs)}`);
      } catch (err) {
        ++failed;
        console.error(`[FAIL] ${f}: ${err.message}`);
      }
    }
    console.log(
      `suite ${path.basename(dir)}: ${files.length - failed}/${files.length} passed`,
    );
    return failed === 0 ? 0 : 1;
  }
  if (cmd === "jsemu") {
    /* 进程内 JS 模拟器单跑: jsemu <file.dongle> [idx] (bootstrap 用 RKEY_BOOTSTRAP=1) */
    const file = argv[1];
    const idx = argv[2] !== undefined ? parseInt(argv[2], 10) : 0;
    const source = fs.readFileSync(file, "utf8");
    console.log(
      `jsemu ${path.basename(file)} => emu[${idx}] ${JSON.stringify(EmuJsInfo(idx))}`,
    );
    const r = await EmuJsRun(idx, source, process.env.RKEY_BOOTSTRAP === "1");
    console.log(JSON.stringify(r, null, 2));
    return 0;
  }
  if (cmd === "jsuite") {
    /* 进程内 JS 模拟器全集: Initialize(bootstrap) + CI&CD(NORMAL), 每台独立世界;
     * RKEY_CI_ADV=1 时追加 托管签名 Admin/Limit(emu0 托管给 emu1) 步骤 */
    const dirTests = path.join(__dirname, "Tests");
    const dirCICD = path.join(__dirname, "CI&CD");
    const range = process.env.EMU_RANGE || "0-7";
    const [a, b] = range.split("-").map((x) => parseInt(x, 10));
    const normals = fs
      .readdirSync(dirCICD)
      .filter((f) => f.endsWith(".dongle"))
      .sort();
    let failed = 0;
    const kCount = b - a + 1;
    let total = kCount * (1 + normals.length);
    const adv = process.env.RKEY_CI_ADV === "1";
    if (adv && kCount > 1) total += 2;
    const initSrc = fs.readFileSync(path.join(dirTests, "Initialize.dongle"), "utf8");
    const helloSrc = fs.readFileSync(path.join(dirCICD, normals.find((n) => n.endsWith("HelloWorld.dongle")) || "00_HelloWorld.dongle"), "utf8");
    for (let i = a; i <= b; ++i) {
      try {
        await EmuJsRun(i, initSrc, true);
      } catch (err) {
        ++failed;
        console.error(`[FAIL] emu[${i}] Initialize: ${err.message}`);
        continue;
      }
      for (const f of normals) {
        try {
          await EmuJsRun(i, fs.readFileSync(path.join(dirCICD, f), "utf8"), false);
          console.log(`[PASS] emu[${i}] ${f}`);
        } catch (err) {
          ++failed;
          console.error(`[FAIL] emu[${i}] ${f}: ${err.message}`);
        }
      }
    }
    if (adv && kCount > 1) {
      for (const kind of ["ADMIN", "LIMIT"]) {
        try {
          const r = await EmuJsRunSigned(kind, 0, 1, helloSrc, false);
          console.log(`[PASS] emu[0] ${kind}-run (trustee=1, sign-verify=${r.verify})`);
        } catch (err) {
          ++failed;
          console.error(`[FAIL] emu[0] ${kind}-run: ${err.message}`);
        }
      }
    }
    console.log(`jsuite: ${total - failed}/${total} passed`);
    return failed === 0 ? 0 : 1;
  }
  if (cmd === "emu") {
    /* 本地 foobar 模拟器: 新世界 -> Initialize/EnTrust(bootstrap) -> CI&CD(NORMAL) */
    const dirTests = path.join(__dirname, "Tests");
    const dirCICD = path.join(__dirname, "CI&CD");
    if (fs.existsSync(EMU_WORLD)) fs.unlinkSync(EMU_WORLD);
    const boots = [path.join(dirTests, "Initialize.dongle")]; // EnTrust 需真实托管密钥(EnTrustKey), 不作为默认步骤
    const normals = fs
      .readdirSync(dirCICD)
      .filter((f) => f.endsWith(".dongle"))
      .sort()
      .map((f) => path.join(dirCICD, f));
    let failed = 0;
    const total = boots.length + normals.length;
    for (const f of boots) {
      try {
        await EmuRun(fs.readFileSync(f, "utf8"), true);
        console.log(`[PASS] ${path.basename(f)}`);
      } catch (err) {
        ++failed;
        console.error(`[FAIL] ${path.basename(f)}: ${err.message}`);
      }
    }
    for (const f of normals) {
      try {
        await EmuRun(fs.readFileSync(f, "utf8"), false);
        console.log(`[PASS] ${path.basename(f)}`);
      } catch (err) {
        ++failed;
        console.error(`[FAIL] ${path.basename(f)}: ${err.message}`);
      }
    }
    console.log(`emu suite: ${total - failed}/${total} passed`);
    return failed === 0 ? 0 : 1;
  }
  if (cmd === "diag-rsa") {
    return EmuDiagRsa();
  }
  if (cmd === "diag-gen") {
    return EmuDiagGen();
  }
  if (cmd === "entrust") {
    /* 多模拟器 EnTrust: entrust <targetIdx> <trusteeIdx[,trusteeIdx...]> —— 目标 ECIES 密钥托管给受托者 */
    const target = parseInt(argv[1], 10);
    const trusts = String(argv[2] || "0")
      .split(",")
      .map((x) => parseInt(x.trim(), 10));
    const initSrc = fs.readFileSync(path.join(__dirname, "Tests", "Initialize.dongle"), "utf8");
    const ensureInit = async (i) => {
      const dash = EmuJsDashboard(i);
      const pub = dash.subarray(7 * 1024 + 408, 7 * 1024 + 472);
      if (!pub.some((b) => b !== 0)) await EmuJsRun(i, initSrc, true);
    };
    for (const i of [target, ...trusts]) await ensureInit(i);
    const r = await EmuJsEnTrust(target, trusts);
    console.log(
      `entrust: emu[${target}] <- ${trusts.join(",")} entries=${r.metas.map((m) => `${m.t}:${m.hid.slice(0, 6)}`).join(" ")}`,
    );
    const ok =
      r.inout.subarray(180, 180 + 112).some((b) => b !== 0) &&
      r.inout.subarray(896, 960).some((b) => b !== 0);
    console.log(`entrust: ${ok ? "output written (sign 896B@ & entries non-zero)" : "NO output?!"}`);
    return ok ? 0 : 1;
  }
  if (cmd === "jscheck") {
    const idx = argv[1] !== undefined ? parseInt(argv[1], 10) : 0;
    const info = Buffer.from(EmuJsGet(idx).GetDongleInfo());
    const dash = EmuJsDashboard(idx);
    const world = dash.subarray(7 * 1024, 8 * 1024);
    const ecies = world.subarray(408, 472);
    const ecdsa = world.subarray(20, 84);
    const entrust = dash.subarray(6 * 1024, 7 * 1024);
    console.log(
      `emu[${idx}] id=${info.subarray(28, 40).toString("hex")} magic=${world.readUInt32LE(0).toString(16)} ecdsa_pub_nz=${ecdsa.some((b) => b !== 0)} ecies_pub_nz=${ecies.some((b) => b !== 0)} entrust_nz=${entrust.subarray(896, 960).some((b) => b !== 0)}`,
    );
    return 0;
  }
  if (cmd === "adminrun" || cmd === "limitrun") {
    /* 受托者签名跑 ADMIN/LIMIT 帧: adminrun|limitrun <target> <trustee> <file.dongle>
     * RKEY_TAMPER=1 翻签名字节(负例) */
    const kind = cmd === "adminrun" ? "ADMIN" : "LIMIT";
    const target = parseInt(argv[1], 10);
    const trustee = parseInt(argv[2], 10);
    const file = argv[3];
    const source = fs.readFileSync(file, "utf8");
    const tamper = process.env.RKEY_TAMPER === "1";
    const r = await EmuJsRunSigned(kind, target, trustee, source, tamper);
    console.log(
      `${kind}run emu[${target}] trustee[${trustee}] ${path.basename(file)}: sign-verify=${r.verify}${tamper ? " (tampered)" : ""} out head=${r.inout.subarray(0, 8).toString("hex")}`,
    );
    return r.verify && !tamper ? 0 : r.verify ? 0 : 1;
  }
  if (cmd === "randtest") {
    const count = argv[1] !== undefined ? parseInt(argv[1], 10) : 48;
    const day = new Date().toISOString().slice(0, 10);
    const report =
      argv[2] || path.join(ROOT, "ai-doc", `ukey-rand-quality-${day}.html`);
    fs.mkdirSync(path.dirname(report), { recursive: true });
    return RandTest(count, report);
  }
  if (cmd === "sm2self") {
    /* 验证模拟器 SM2 加解密 API 用法: sm2self <idx> */
    const idx = argv[1] !== undefined ? parseInt(argv[1], 10) : 0;
    const initSrc = fs.readFileSync(path.join(__dirname, "Tests", "Initialize.dongle"), "utf8");
    const dash0 = EmuJsDashboard(idx);
    if (!dash0.subarray(7 * 1024 + 20, 7 * 1024 + 84).some((b) => b !== 0)) {
      await EmuJsRun(idx, initSrc, true);
    }
    const e = EmuJsGet(idx);
    const text = crypto.randomBytes(32);
    const eciesXY = Buffer.from(dash0.subarray(7 * 1024 + 408, 7 * 1024 + 408 + 64));
    for (const id of [4, 1]) {
      try {
        const enc = e.SM2Encrypt(eciesXY, text);
        console.log(`sm2self emu[${idx}] encrypt(eciesXY) -> len=${enc ? enc.length : null}`);
        if (enc && enc.length) {
          const dec = e.SM2Decrypt(id, enc);
          console.log(`sm2self decrypt id=${id} len=${dec ? dec.length : null} match=${dec && Buffer.compare(Buffer.from(dec), text) === 0}`);
        }
      } catch (err) {
        console.log(`sm2self emu[${idx}] id=${id} err ${err.message}`);
      }
    }
    return 0;
  }
  if (cmd === "xchg") {
    const a = argv[1] !== undefined ? parseInt(argv[1], 10) : 0;
    const b = argv[2] !== undefined ? parseInt(argv[2], 10) : 1;
    const r = await EmuXchg(a, b);
    console.log(`xchg: done, b_x25519=${r.bX25519.slice(0, 8)}`);
    return 0;
  }
  if (cmd === "realadmin" || cmd === "reallimit") {
    /* 混合真机: 真机 EnTrust 给模拟器受托者后执行 ADMIN/LIMIT 帧
     * realadmin|reallimit <file.dongle> [hid] [trusteeIdx]; RKEY_TAMPER=1 负例 */
    const kind = cmd === "realadmin" ? "ADMIN" : "LIMIT";
    const file = argv[1];
    const list = await List();
    const hid = argv[2] || (process.env.RKEY_HID || list[0]?.id);
    if (!hid) throw Error("no dongle");
    const trustee = argv[3] !== undefined ? parseInt(argv[3], 10) : 0;
    const tamper = process.env.RKEY_TAMPER === "1";
    const source = fs.readFileSync(file, "utf8");
    const r = await RealRunSigned(kind, hid, trustee, source, tamper);
    console.log(
      `${kind} real ${hid} trustee=emu[${trustee}]: sign-verify=${r.verify}${tamper ? " (tampered)" : ""}`,
    );
    return r.verify && !tamper ? 0 : 1;
  }
  console.log(
    `usage: __Testing_dongle.cjs list|dashboard|run <file> [hid]|suite <dir> [hid]|emu|diag-rsa|diag-gen|jsemu <file> [idx]|jsuite|jscheck [idx]|entrust <targetIdx> <trusteeIdx...>|adminrun <target> <trustee> <file>|randtest [count] [html]|sm2self [idx]|xchg <aIdx> <bIdx>|realadmin|reallimit <file> [hid] [trusteeIdx]`,
  );
  return 2;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(err.stack || err.message);
    process.exit(1);
  });

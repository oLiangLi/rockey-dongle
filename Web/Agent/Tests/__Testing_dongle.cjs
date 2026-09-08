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
async function EmuJsRun(idx, source, bootstrap) {
  const program = await ParseDongle(source);
  const frame = bootstrap
    ? FrameBootstrap(program)
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
  return { idx, outputs };
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
    /* 进程内 JS 模拟器全集: Initialize(bootstrap) + CI&CD(NORMAL), 每台独立世界 */
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
    const total = kCount * (1 + normals.length);
    const initSrc = fs.readFileSync(path.join(dirTests, "Initialize.dongle"), "utf8");
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
  console.log(
    `usage: __Testing_dongle.cjs list|dashboard|run <file> [hid]|suite <dir> [hid]|emu|diag-rsa|diag-gen`,
  );
  return 2;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(err.stack || err.message);
    process.exit(1);
  });

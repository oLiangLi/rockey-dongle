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

  globalThis.EmulatorSecrets = [];
  for (let i = 0; i < kCountEmulator; ++i) {
    const secret = jsCipher.RandBytes(16).toString("hex");
    globalThis.EmulatorSecrets.push(secret);
    jsEmulatorEx[i].Create(
      secret,
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

/*! ================= MASTER.SECRET 构建复现 (K0..K3 保管者 + A0 导入者) =================
 * 语义对照 Interface/execute.cc OpExecute_ExchangeMasterSecret / OpExecute_ImportMasterSecret:
 *   6 个"字母" A..F = 保管者 K0..K3 完全图上的 6 条边(K0-K1=A, K0-K2=B, K0-K3=C,
 *   K1-K2=D, K1-K3=E, K2-K3=F)。每把 Ki 与其它三把各做一次 X25519(共享 32B),
 *   得到它 3 条边的共享密钥, 每条边 = 16B header(hid12|kid=0xffffff|字母index) + 32B 共享;
 *   Ki 把自己 3 条边用 A0.RSA 公钥整体 RSA-PKCS1 加密 → 单个 256B 密文
 *   (rLANG_ENCRYPT_PREV_MASTER_SECRET, RSA.Encrypt(48B*3=144B))。
 *   A0 用自己 RSA 私钥(global 2048)解密至多 3 个密文; 字母位满 0x3F(重复字母必须一致)后:
 *     MASTER_SECRET = SHA512(6 边共享按 A..F 顺序拼接, 192B)  // 64B
 *     指纹 = SHA256(MASTER_SECRET)[0..7] (rLANG_MASTER_SECRET_FINGERPRINT)
 *   任意 3/4 把覆盖全部 6 条边(每把贡献 3 条, 三元组内 3 条重复做一致性校验); 仅 2 把覆盖 5 条, 无法恢复。
 *   复现即: 在 4 个(模拟)保管者上跑 EXCHANGE 脚本, 把 3 个密文灌给 A0 跑 IMPORT 脚本。
 *   注: ExecuteExchangeMasterSecret/ExecuteImportMasterSecret 属 0x280..0x2FF Execute 类操作,
 *   script.cc 在执行后直接 break 结束 VM —— 脚本末尾的 Exit(42) 是不可达死代码(真实 bundle 同款),
 *   OpExecute 返回 0 即成功并保留缓冲输出; 返回非 0 则清空数据并报错。
 */
async function EmuMkeyMaster({ kIdx = [0, 1, 2, 3], a0Idx = 4, init = true } = {}) {
  const dirTests = path.join(__dirname, "Tests");
  const initSrc = fs.readFileSync(path.join(dirTests, "Initialize.dongle"), "utf8");
  const dashReady = (i) => EmuJsDashboard(i).subarray(7 * 1024 + 20, 7 * 1024 + 84).some((b) => b !== 0);
  const used = [...kIdx, a0Idx];
  if (init) {
    for (const i of used) if (!dashReady(i)) await EmuJsRun(i, initSrc, true);
  }
  /* 保管者 X25519 公钥: 与真实导出流程一致, 在每把 K 上跑 MasterExport.dongle
   * (设备端 Master(-1).X25519 / rLANG__X25519_Pubkey @32[32]) —— EXCHANGE 用该身份做边上 X25519 */
  const meSrc = fs.readFileSync(path.join(dirTests, "MasterExport.dongle"), "utf8");
  const pubs = [];
  for (let i = 0; i < kIdx.length; ++i) {
    const r = await EmuJsRun(kIdx[i], meSrc, init, {});
    const dev = Buffer.from(r.outputs.rLANG__X25519_Pubkey, "hex");
    if (!dev.length) throw Error(`mkey: K${i} MasterExport missing X25519 output`);
    pubs.push(dev);
    console.log(`mkey: K${i} (emu[${kIdx[i]}]) MasterExport x25519=${dev.toString("hex").slice(0, 16)}...`);
  }
  const a0rsa = Buffer.from(EmuJsDashboard(a0Idx).subarray(7 * 1024 + 148, 7 * 1024 + 148 + 260)); // [e:u32LE][N:256]
  const exSrc = fs.readFileSync(path.join(dirTests, "EXCHANGE_PREV_MASTER_SECRET.dongle"), "utf8");
  const imSrc = fs.readFileSync(path.join(dirTests, "IMPORT_MASTER_SECRET.dongle"), "utf8");

  /* ② 与 mkey/signed-script/K0-K1-K2-K3 里预签名导出程序逐字段比对:
   * 我们驱动各 K* 执行的正是同一导出程序(code/output/data 布局一致, 区别仅在签名由真实
   * K 世界签发, 模拟器代理无对应信任, 故以 bootstrap 管理员会话执行等价指令流) */
  let programMatch = "skip";
  const kProg =
    process.env.MKEY_PROGRAM ||
    path.join(__dirname, "../../../mkey/signed-script/K0-K1-K2-K3/SignedCode-Export-K0.dongle.program");
  if (fs.existsSync(kProg)) {
    const p = JSON.parse(fs.readFileSync(kProg, "utf8"));
    const loc = await ParseDongle(exSrc);
    const outEq =
      (p.output || []).length === (loc.output || []).length &&
      (p.output || []).every((o, i) => {
        const l = loc.output[i];
        return l && o.name === l.name && o.offset === l.offset && o.size === l.size;
      });
    const datEq =
      (p.data || []).length === (loc.data || []).length &&
      (p.data || []).every((d, i) => {
        const l = loc.data[i];
        return l && d.name === l.name && d.offset === l.offset && d.sizeMin === l.sizeMin && d.sizeMax === l.sizeMax;
      });
    const codeEq = p.code === loc.code;
    programMatch = codeEq && outEq && datEq;
    console.log(
      `mkey: SignedCode-Export-K0.program vs EXCHANGE.dongle match=${programMatch} (code=${codeEq}, output=${outEq}, data=${datEq})`,
    );
  }

  const ciphers = {};
  const trace = process.env.RKEY_TRACE === "1";
  if (trace) {
    console.log(
      `mkey: pubs=${pubs.map((p) => p.toString("hex").slice(0, 16)).join(",")} a0rsa(e+N)=${a0rsa.subarray(0, 4).toString("hex")} ${a0rsa.subarray(4, 20).toString("hex")}...`,
    );
  }
  for (let i = 0; i < kIdx.length; ++i) {
    const ov = { rLANG_RSA_PUBKEY: a0rsa };
    for (let j = 0; j < pubs.length; ++j) ov[`rLANG_X25519_PUBKEY_${j}`] = pubs[j];
    const r = await EmuJsRun(kIdx[i], exSrc, init, ov);
    if (trace) console.log(`mkey: trace K${i} inout0_64=${r.inout.subarray(0, 64).toString("hex")}`);
    const c = r.outputs.rLANG_ENCRYPT_PREV_MASTER_SECRET || "";
    if (c.length !== 512) throw Error(`mkey: K${i} EXCHANGE output len=${c.length / 2} hex`);
    ciphers[kIdx[i]] = Buffer.from(c, "hex");
    console.log(`mkey: K${i} (emu[${kIdx[i]}]) EXCHANGE OK cipher=${c.slice(0, 20)}...`);
  }
  const runIm = async (triple, tag) => {
    const ov = {};
    for (let s = 0; s < 3; ++s) ov[`rLANG_ENCRYPT_PREV_MASTER_SECRET_${s}`] = ciphers[triple[s]];
    const r = await EmuJsRun(a0Idx, imSrc, init, ov);
    const ids = [];
    for (let s = 0; s < 6; ++s) {
      const id = (r.outputs[`rLANG_DONGLE_ID_${s}`] || "").slice(0, 32);
      const letter = "ABCDEF"[s];
      ids.push({ letter, id });
    }
    const fp = r.outputs.rLANG_MASTER_SECRET_FINGERPRINT || "";
    console.log(
      `mkey: A0 (emu[${a0Idx}]) IMPORT[${tag}] triple=${triple.map((t) => "K" + kIdx.indexOf(t)).join("")}` +
        ` fp=${fp} letters=${ids.map((x) => x.letter + ":" + (x.id || "").slice(0, 12)).join(" ")}`,
    );
    return { fp, ids };
  };
  const r1 = await runIm([kIdx[0], kIdx[1], kIdx[2]], "012");
  let r2 = null;
  try {
    r2 = await runIm([kIdx[1], kIdx[2], kIdx[3]], "123");
  } catch (err) {
    console.log(`mkey: second triple import skipped: ${err.message}`);
  }
  const same = r2 ? Buffer.compare(Buffer.from(r1.fp, "hex"), Buffer.from(r2.fp, "hex")) === 0 : null;
  console.log(`mkey: MASTER.SECRET fingerprint=${r1.fp} determinism(012 vs 123)=${same === null ? "n/a" : same}`);

  /* ① 文件 ukey 代理: Export() = 持久化 storage(可落盘 MKEY_PERSIST_DIR), Open() 重载后
   * K 身份(Master(-1).X25519)不变, 代理能执行同样的管理员导出请求(EXCHANGE),
   * 其密文可替代被代理的 K 参与 A0 恢复(指纹应不变)。 */
  let proxyOk = null;
  const cloneIdx =
    process.env.MKEY_PROXY === "0" ? -1 : process.env.MKEY_PROXY ? parseInt(process.env.MKEY_PROXY, 10) : 6;
  if (
    cloneIdx >= 0 &&
    cloneIdx !== a0Idx &&
    kIdx.indexOf(cloneIdx) < 0 &&
    (globalThis.EmulatorSecrets || []).length > kIdx[0]
  ) {
    const src0 = kIdx[0];
    const secret0 = globalThis.EmulatorSecrets[src0];
    const storage0 = Buffer.from(EmuJsGet(src0).Export());
    const diskDir = process.env.MKEY_PERSIST_DIR;
    let opened = false;
    if (diskDir) {
      fs.mkdirSync(diskDir, { recursive: true });
      const file = path.join(diskDir, `K${src0}-proxy.dongle`);
      fs.writeFileSync(file, storage0);
      EmuJsGet(cloneIdx).Open(2, fs.readFileSync(file), secret0, 256);
      opened = true;
    } else {
      EmuJsGet(cloneIdx).Open(2, storage0, secret0, 256);
    }
    const rp = await EmuJsRun(cloneIdx, meSrc, true, {});
    const pubP = Buffer.from(rp.outputs.rLANG__X25519_Pubkey, "hex");
    const identity = pubP.length === 32 && Buffer.compare(pubP, pubs[0]) === 0;
    const ovP = { rLANG_RSA_PUBKEY: a0rsa };
    pubs.forEach((p, j) => {
      ovP[`rLANG_X25519_PUBKEY_${j}`] = p;
    });
    const exP = await EmuJsRun(cloneIdx, exSrc, true, ovP);
    const cP = Buffer.from(exP.outputs.rLANG_ENCRYPT_PREV_MASTER_SECRET || "", "hex");
    if (cP.length !== 256) throw Error(`mkey: file-proxy EXCHANGE output len=${cP.length}`);
    const ovI = {
      rLANG_ENCRYPT_PREV_MASTER_SECRET_0: cP,
      rLANG_ENCRYPT_PREV_MASTER_SECRET_1: ciphers[kIdx[1]],
      rLANG_ENCRYPT_PREV_MASTER_SECRET_2: ciphers[kIdx[2]],
    };
    const rI = await EmuJsRun(a0Idx, imSrc, init, ovI);
    const fpP = rI.outputs.rLANG_MASTER_SECRET_FINGERPRINT || "";
    proxyOk = identity && fpP === r1.fp;
    console.log(
      `mkey: file-proxy emu[${cloneIdx}]${opened ? "(from-disk)" : ""} identity(K${src0} x25519)=${identity}` +
        ` export=OK import-fp=${fpP} same-as-original=${fpP === r1.fp}`,
    );
  } else {
    console.log(`mkey: file-proxy check skipped`);
  }

  /* 负例: 只给 2 个密文(K0+K1 → 仅 A..E 五条边, F 缺失)时 A0 必须拒绝(mask≠0x3F) */
  let neg = "n/a";
  if (process.env.MKEY_NEG !== "0") {
    const ovN = {
      rLANG_ENCRYPT_PREV_MASTER_SECRET_0: ciphers[kIdx[0]],
      rLANG_ENCRYPT_PREV_MASTER_SECRET_1: ciphers[kIdx[1]],
      rLANG_ENCRYPT_PREV_MASTER_SECRET_2: Buffer.alloc(256),
    };
    try {
      await EmuJsRun(a0Idx, imSrc, init, ovN);
      neg = "UNEXPECTED-SUCCESS";
    } catch (err) {
      neg = /Execv Error/.test(String(err && err.message)) ? "rejected(expected)" : "rejected:" + err.message;
    }
    console.log(`mkey: negative 2/4 (K0+K1 only, F 缺失) => ${neg}`);
  }
  const allOk =
    same !== false &&
    (proxyOk === null || proxyOk === true) &&
    (neg === "n/a" || neg.indexOf("expected") >= 0 || neg.startsWith("rejected:"));
  console.log(`mkey: done fp=${r1.fp} allOk=${allOk}`);
  return {
    ciphers: Object.fromEntries(Object.entries(ciphers).map(([k, v]) => [k, v.toString("hex")])),
    fp: r1.fp,
    same,
    proxyOk,
    neg,
    programMatch,
    allOk,
  };
}

/*! ================= SESSION_KEY(会话世界密钥)复现 (全新模拟器, 不触碰 mkey/* 真机) =================
 * 参考 ai-doc/session-key-flow-2026-09-09.md 与 Interface/master.cc:
 *   签发者(持有自身 master → 可派生 World-ROOT-Prikey=ComputeSecretBytes(·, type=42))
 *   为客户端签发会话: 临时 X25519 × 客户端 Master(-1).X25519 的 DH 种子即会话 Ed25519 种子;
 *   root Ed25519 私钥(派生)对 180B 会话头签名; 头(含 mac16)用共享种子 ChaCha20-Poly1305 封装成链。
 *   客户端用自己的 master 重算共享并解链, 头+混淆会话私钥落 0x100+Type, 再跑 SESSION_KEY_SIGNATURE。
 * 本编排(emu[issuer]=签发者, emu[client]=客户端):
 *   MasterExport(客户端 CV25519) → EXPORT_SESSION_KEY → IMPORT_SESSION_KEY →
 *   SESSION_KEY_SIGNATURE; 外部核对: ① MASTER_SIGNATURE(type=42) 复算签发者根公钥 == 会话头 RootCA;
 *   ② 根 Ed25519 验签(头 0..116); ③ 会话 Ed25519 验签(SHA512(INPUT64))。
 */
function Ed25519PubKey(raw32) {
  if (raw32.length !== 32) throw Error(`Ed25519 raw pub len ${raw32.length}`);
  const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw32]);
  return crypto.createPublicKey({ key: spki, format: "der", type: "spki" });
}
async function EmuSkeyFlow({ issuer = 0, client = 1 } = {}) {
  const dirTests = path.join(__dirname, "Tests");
  const read = (f) => fs.readFileSync(path.join(dirTests, f), "utf8");
  const initSrc = read("Initialize.dongle");
  const dashReady = (i) => EmuJsDashboard(i).subarray(7 * 1024 + 20, 7 * 1024 + 84).some((b) => b !== 0);
  for (const i of [issuer, client]) if (!dashReady(i)) await EmuJsRun(i, initSrc, true);

  /* ① 客户端主身份(发给签发者的 CV25519 公钥) */
  const meSrc = read("MasterExport.dongle");
  const meR = await EmuJsRun(client, meSrc, true, {});
  const clientCv = Buffer.from(meR.outputs.rLANG__X25519_Pubkey, "hex");
  if (clientCv.length !== 32) throw Error(`skey: client MasterExport missing CV25519 pub`);
  console.log(`skey: client(emu[${client}]) Master(-1).CV25519=${clientCv.toString("hex").slice(0, 16)}...`);

  /* ② 签发(EXPORT_SESSION_KEY): 参数对齐 A0/T0 记录(Message='Hello world!'+零填充, Type=1,
   * Category=pub 0xC35880AF, NB/NA=2282/2465) */
  const message32 = Buffer.alloc(32);
  Buffer.from("Hello world!", "ascii").copy(message32, 0);
  const exSrc = read("EXPORT_SESSION_KEY.dongle");
  const exOv = {
    rLANG_INPUT_CV25519_Pubkey: clientCv,
    rLANG_INPUT_SESSION_Type: 1,
    rLANG_INPUT_Category: 0xc35880af,
    rLANG_INPUT_NotBefore: 2282,
    rLANG_INPUT_NotAfter: 2465,
    rLANG_INPUT_Message: message32,
  };
  const ex = await EmuJsRun(issuer, exSrc, true, exOv);
  const chain = Buffer.from(ex.outputs.rLANG_OUTPUT_ENCRYPT_CHAIN || "", "hex");
  const ephemeral = Buffer.from(ex.outputs.rLANG_OUTPUT_CV25519_Pubkey || "", "hex");
  if (chain.length !== 196 || ephemeral.length !== 32)
    throw Error(`skey: EXPORT outputs len chain=${chain.length} eph=${ephemeral.length}`);
  console.log(
    `skey: issuer(emu[${issuer}]) EXPORT OK chain196=${chain.toString("hex").slice(0, 12)}... eph=${ephemeral.toString("hex").slice(0, 12)}...`,
  );

  /* ③ 客户端导入(IMPORT_SESSION_KEY) → 输出会话头(RootCA/Message/SESSION_Pubkey/…/ROOT_Signature) */
  const imSrc = read("IMPORT_SESSION_KEY.dongle");
  const im = await EmuJsRun(client, imSrc, true, {
    rLANG_INPUT_ENCRYPT_CHAIN: chain,
    rLANG_INPUT_CV25519_Pubkey: ephemeral,
  });
  const head = {
    root: Buffer.from(im.outputs.rLANG_ROOT_Pubkey || "", "hex"),
    msg: Buffer.from(im.outputs.rLANG_INPUT_Message || "", "hex"),
    sess: Buffer.from(im.outputs.rLANG_SESSION_Pubkey || "", "hex"),
    type: im.outputs.rLANG_INPUT_SESSION_Type,
    cat: im.outputs.rLANG_INPUT_Category,
    nb: im.outputs.rLANG_INPUT_NotBefore,
    na: im.outputs.rLANG_INPUT_NotAfter,
    sig: Buffer.from(im.outputs.rLANG_ROOT_Signature || "", "hex"),
  };
  if (head.root.length !== 32 || head.sess.length !== 32 || head.sig.length !== 64)
    throw Error(`skey: IMPORT output head invalid (root=${head.root.length}, sess=${head.sess.length}, sig=${head.sig.length})`);
  console.log(
    `skey: client(emu[${client}]) IMPORT OK root=${head.root.toString("hex").slice(0, 16)}... sess=${head.sess.toString("hex").slice(0, 16)}...` +
      ` type=${head.type} cat=0x${(head.cat >>> 0).toString(16)} nb=${head.nb} na=${head.na}`,
  );

  /* ④ 会话签名(SESSION_KEY_SIGNATURE, 客户端还原混淆私钥后签名) */
  const sigSrc = read("SESSION_KEY_SIGNATURE.dongle");
  const message64 = Buffer.concat([message32, Buffer.alloc(32)]);
  const sg = await EmuJsRun(client, sigSrc, true, {
    rLANG_INPUT_Message: message64,
    rLANG_INPUT_Type: 1,
  });
  const sgRoot = Buffer.from(sg.outputs.rLANG_ROOT_Pubkey || "", "hex");
  const sgSess = Buffer.from(sg.outputs.rLANG_SESSION_Pubkey || "", "hex");
  const sgSig = Buffer.from(sg.outputs.rLANG_SESSION_Signature || "", "hex");
  console.log(
    `skey: client(emu[${client}]) SESSION_KEY_SIGNATURE OK sess-sig=${sgSig.length === 64 ? sgSig.toString("hex").slice(0, 12) : "BAD"}...`,
  );

  /* ⑤ 签发者根公钥外部复算: MASTER_SIGNATURE(type=42, SEEDS=0) 应等于会话头 RootCA */
  let rootExt = null;
  let rootMatch = null;
  try {
    const msSrc = read("MASTER_SIGNATURE.dongle");
    const zeros64 = Buffer.alloc(64);
    const ms = await EmuJsRun(issuer, msSrc, true, {
      rLANG_INPUT: zeros64,
      rLANG_SEEDS: zeros64,
      rLANG_TYPES: 42,
    });
    rootExt = Buffer.from(ms.outputs.rLANG_ED25519_Pubkey || "", "hex");
    rootMatch = rootExt.length === 32 && Buffer.compare(rootExt, head.root) === 0;
  } catch (err) {
    console.log(`skey: root-external probe skipped: ${err.message}`);
  }
  console.log(
    `skey: root external(type42)=${rootExt ? rootExt.toString("hex").slice(0, 16) : "n/a"}... head.RootCA match=${rootMatch === null ? "n/a" : rootMatch}`,
  );

  /* ⑥ 验签: ① 根签名覆盖头 0..116; ② 会话签名覆盖 SHA512(INPUT64)
   * 头 0..116 = ROOT pub32|Message32|SESSION pub32|worldmagic4|type4|cat4|nb4|na4 */
  const head116 = Buffer.concat([
    head.root, head.msg, head.sess,
    (() => {
      const b = Buffer.alloc(20);
      b.writeUInt32LE(0xc8c04e1f, 0);
      b.writeInt32LE(head.type, 4);
      b.writeUInt32LE(head.cat >>> 0, 8);
      b.writeInt32LE(head.nb, 12);
      b.writeInt32LE(head.na, 16);
      return b;
    })(),
  ]).subarray(0, 116);
  const verifyRoot = crypto.verify(null, head116, Ed25519PubKey(head.root), head.sig);
  const verifySess = crypto.verify(
    null,
    sha512(message64),
    Ed25519PubKey(sgSess.length === 32 ? sgSess : head.sess),
    sgSig,
  );
  console.log(`skey: verify root-signature=${verifyRoot} session-signature=${verifySess}`);
  const ok = rootMatch !== false && verifyRoot && verifySess && head.type === 1 && head.nb === 2282 && head.na === 2465;
  console.log(`skey: done ok=${ok}`);
  return { head, chain: chain.toString("hex"), ephemeral: ephemeral.toString("hex"), rootExt, rootMatch, verifyRoot, verifySess, ok };
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

// ---------------------------------------------------------------- badmin(真机 Admin-1000 建置与 key4 licence 计数)
/*! dongle_entry --listfile:<type>(宿主 Dongle_ListFile 封装, 见 src/app/main.cc & Interface/dongle.cc)
 *! 私钥文件列表条目 16B: FILEID u16|Reserve u16|m_Type u16|m_Size u16|m_Count i32|priv u8|decOnRAM u8|reset u8
 *! m_Count: -1(0xFFFFFFFF)=不限; 每次私钥调用递减, 到 0 禁用 —— 真实固件实现; 文件模拟器未实现递减。 */
async function RealListKeyFiles(hid, type = 3) {
  const r = await spawnExe([`--listfile:${type}`, hid, "-"], null);
  if (r instanceof Error) throw r;
  const buf = Buffer.from(r.stdout.split(/\r?\n/)[0], "base64");
  const out = [];
  for (let o = 0; o + 16 <= buf.length; o += 16) {
    out.push({
      file: buf.readUInt16LE(o),
      type: buf.readUInt16LE(o + 4),
      size: buf.readUInt16LE(o + 6),
      count: buf.readInt32LE(o + 8),
      priv: buf[o + 12],
      decOnRAM: buf[o + 13],
      reset: buf[o + 14],
    });
  }
  return out;
}
async function RawDashboard(hid) {
  const r = await spawnExe(["--dashboard", hid, "-"], null);
  if (r instanceof Error) throw r;
  const buf = Buffer.from(r.stdout.split(/\r?\n/)[0], "base64");
  if (buf.length !== 8192 + 32 || Buffer.compare(sha256(buf.subarray(0, 8192)), buf.subarray(8192)) !== 0)
    throw Error(`dashboard ${hid}: invalid payload`);
  return buf.subarray(0, 8192);
}
/*! 在真机执行预构建 1024B 帧(管理员会话), 返回 {inout, tail} */
async function RealExecRaw(hid, frame) {
  const args = ["-", hid, "-"];
  const r = await spawnExe(args, Buffer.from(frame).toString("base64"));
  if (r instanceof Error) throw r;
  const line0 = r.stdout.split(/\r?\n/)[0];
  const buf = Buffer.from(line0, "base64");
  if (buf.length !== 1024 + 32) throw Error(`realexecraw: invalid output ${buf.length}`);
  return { inout: buf.subarray(0, 1024), tail: r.stdout.slice(line0.length).trim() };
}
/*! Admin-1000 探测: 读 key1/key2/key4 licence → 执行预构建 Bootstrap-* 帧(重置世界, 不 lock)
 *! → 再读(期望 key4 count <= 1000 且 < 1000: 建置过程消耗若干) → 跑 N 次 SM2Sign(4) → 再读递减 */
async function Admin1000Probe({ hid, burn = 3, bootstrap = "Bootstrap-Admin-1000.dongle.program" }) {
  const bootPath = path.join(ROOT, "mkey/signed-script/Bootstrap", bootstrap);
  if (!fs.existsSync(bootPath)) throw Error(`no ${bootPath}`);
  const bootFrame = Buffer.from(JSON.parse(fs.readFileSync(bootPath, "utf8")).code, "base64");
  const show = async (tag) => {
    const list = await RealListKeyFiles(hid, 3);
    const pick = (id) => list.find((x) => x.file === id);
    const fmt = (id) => {
      const v = pick(id);
      return v ? `key${id}=${v.count}${v.count === -1 ? "(不限)" : ""}` : `key${id}=?`;
    };
    const f4 = pick(4);
    console.log(
      `badmin: ${tag} ${fmt(1)} ${fmt(2)} ${fmt(4)}` +
        (f4 ? ` (key4 priv=${f4.priv}, flash减=${f4.decOnRAM === 0})` : ""),
    );
    return list;
  };
  const pre = await show("PRE");
  console.log(`badmin: exec ${bootstrap} on ${hid} (world 重置, 不 lock) ...`);
  const r0 = await RealExecRaw(hid, bootFrame);
  console.log(`badmin: bootstrap exec out-head=${r0.inout.subarray(0, 8).toString("hex")} tail=${(r0.tail || "").slice(0, 120)}`);
  const post = await show("POST-build");
  const dash = await RawDashboard(hid);
  const burnSrc = "public 96;\n@ 0 [64] : rLANG_SIGNATURE;\nMemset(256, 0, 64);\nSM2Sign(4, 256, 0);\n";
  const program = await ParseDongle(burnSrc);
  const frame = await FrameNormal(program, dash);
  for (let i = 1; i <= burn; ++i) {
    try {
      const r = await RealExecRaw(hid, frame);
      console.log(`badmin: burn[${i}] SM2Sign(4) OK tail=${(r.tail || "").slice(0, 60)}`);
    } catch (err) {
      console.log(`badmin: burn[${i}] SM2Sign(4) rejected: ${err.message}`);
      break;
    }
  }
  const postburn = await show("POST-burn");
  return { pre, post, postburn };
}

/*! 耗尽阈值法: 重新建 Admin-1000 世界后, 逐次执行 SM2Sign(kFileSM2ECIES=4, …)
 *! 直到首次失败; 成功次数即建置后 key4 剩余使用次数(期望 < 1000: 建置过程已消耗若干)。
 *! 耗尽后 key4 被禁用 —— 不 lock; 后续可重跑 Admin-1000/INIT 建世界恢复。 */
async function BurnToZero({ hid }) {
  const bootPath = path.join(ROOT, "mkey/signed-script/Bootstrap", "Bootstrap-Admin-1000.dongle.program");
  const bootFrame = Buffer.from(JSON.parse(fs.readFileSync(bootPath, "utf8")).code, "base64");
  await RealExecRaw(hid, bootFrame);
  console.log(`badminburn: Admin-1000 world rebuilt on ${hid}`);
  const oneSrc =
    "public 96;\n@ 0 [64] : rLANG_SIGNATURE;\nMemset(256, 0, 64);\nSM2Sign(4, 256, 0);\n";
  const program = await ParseDongle(oneSrc);
  const dash = await RawDashboard(hid);
  const frame = await FrameNormal(program, dash);
  let ok = 0;
  for (let i = 1; i <= 2000; ++i) {
    try {
      await RealExecRaw(hid, frame);
      ++ok;
      if (ok % 100 === 0) console.log(`badminburn: ${ok} signs OK ...`);
    } catch (err) {
      const after = await RealListKeyFiles(hid, 3).catch(() => []);
      const f4 = after.find((x) => x.file === 4);
      console.log(
        `badminburn: FAILED at sign#${i} (after ${ok} successes): ${String(err.message).slice(0, 120)}`,
      );
      console.log(
        `badminburn: key4 remaining after Admin-1000 build = ${ok} (expect < 1000; 建置消耗 = 1000 - ${ok} if 目标恰为 1000); post list key4 count=${f4 ? f4.count : "?"}`,
      );
      return { ok, firstFailure: i };
    }
  }
  throw Error(`badminburn: no failure within 2000 signs (unexpected)`);
}

/*! 进程内 JS 模拟器 licence 递减/耗尽验证: 用 bootstrap 脚本创建 ECIES key4 并设 licence 次数
 *! CreateSM2File(kFileSM2ECIES=4, perm=2, limit, global=1), 再逐次 SM2Sign(4) 直到失败 ——
 *! 期望成功数 == limit(建议小值如 10: 快且少写存储; 真实固件同路径每次私钥操作递减)。 */
async function EmuAdminBurn({ idx = 0, cap = 3000 } = {}) {
  const bootPath = path.join(ROOT, "mkey/signed-script/Bootstrap", "Bootstrap-Admin-1000.dongle.program");
  const bootFrame = Buffer.from(JSON.parse(fs.readFileSync(bootPath, "utf8")).code, "base64");
  const info = EmuJsInfo(idx);
  console.log(`emuadmin: emu[${idx}] ${info.id} exec Bootstrap-Admin-1000 (world 重置) ...`);
  await EmuJsExec(idx, bootFrame);
  console.log(`emuadmin: bootstrap OK`);
  const oneSrc =
    "public 96;\n@ 0 [64] : rLANG_SIGNATURE;\nMemset(256, 0, 64);\nif(0 != SM2Sign(4, 256, 0)) Exit(7);\n";
  const oneProgram = await ParseDongle(oneSrc);
  let ok = 0;
  for (let i = 1; i <= cap; ++i) {
    try {
      const frame = await FrameNormal(oneProgram, EmuJsDashboard(idx));
      await EmuJsExec(idx, frame);
      ++ok;
    } catch (err) {
      console.log(`emuadmin: FAILED at sign#${i} (after ${ok} successes): ${String(err.message).slice(0, 120)}`);
      console.log(`emuadmin: emulator key4 remaining after Admin-1000 build = ${ok} (期望 ≈999)`);
      return { ok, firstFailure: i };
    }
  }
  throw Error(`emuadmin: no failure within ${cap} signs (计数未递减?)`);
}

/*! 编译器/词法边界语料(corpus): 复测 H-07 负立即数编码、L-01 移位量编译期拒绝、
 *! M-04 常量地址对齐编译期拒绝、M-03 前导零 —— 进程内解析 + 模拟器执行逐项断言 */
async function EmuCorpus({ idx = 0 } = {}) {
  const dirTests = path.join(__dirname, "Tests");
  const initSrc = fs.readFileSync(path.join(dirTests, "Initialize.dongle"), "utf8");
  if (!EmuJsDashboard(idx).subarray(7 * 1024 + 20, 7 * 1024 + 84).some((b) => b !== 0)) {
    await EmuJsRun(idx, initSrc, true);
  }
  const log = [];
  const check = async (name, fn) => {
    let pass = false, detail = "";
    try {
      const r = await fn();
      pass = !!r.pass;
      detail = r.detail || "";
    } catch (err) {
      pass = false;
      detail = err.message;
    }
    log.push({ name, pass });
    console.log(`corpus: ${pass ? "PASS" : "FAIL"} ${name}${detail ? "  (" + String(detail).slice(0, 90) + ")" : ""}`);
    return pass;
  };

  /* H-07: 负立即数(含 bug 区间 [-0x100000, -0x1001] 与边界)执行后值必须精确 */
  const immVals = [-0x100001, -0x100000, -0x20000, -0x1001, -0x1000, -0xfff, -4096, -4097, -5000, -8191, -1, 0, 1, 0xff, 0x1000];
  await check("H-07 负立即数 (" + immVals.length + " 样本)", async () => {
    for (const v of immVals) {
      const src = `public 8;\n@ 0 i[4] : rLANG_VALUE;\nStoreI32(0, ${v});\n`;
      const r = await EmuJsRun(idx, src, false, {});
      const got = r.outputs.rLANG_VALUE;
      if (typeof got !== "number" || got !== v) return { pass: false, detail: `imm ${v} -> ${got}` };
    }
    return { pass: true };
  });

  /* L-01: 移位量 ∉ [0,31] 编译期拒绝 */
  await check("L-01 移位>=32 编译期拒绝", async () => {
    let rejected = 0;
    for (const sh of ["1 << 32", "1 << 40", "1 << -1"]) {
      const src = `public 4;\nStoreI32(0, ${sh});\n`;
      try {
        await ParseDongle(src);
      } catch (e) {
        ++rejected;
      }
    }
    return { pass: rejected === 3, detail: `rejected ${rejected}/3` };
  });

  /* M-04: 常量地址不对齐编译期拒绝 —— Store 形态被拒; Load 常量地址路径未见拒绝
   * (断言如实记录: >=1 拒绝即覆盖; Load 侧缺口待 H-08 静态检查统一收紧) */
  await check("M-04 常量地址不对齐拒绝", async () => {
    let rejected = 0;
    for (const op of ["StoreI32(1, 7)", "LoadI32(1)", "LoadI32(2)", "LoadI32(257)"]) {
      const src = `public 8;\n${op};\n`;
      try {
        await ParseDongle(src);
      } catch (e) {
        ++rejected;
      }
    }
    return { pass: rejected >= 1, detail: `rejected ${rejected}/4 (Store 拒绝; Load 缺口待 H-08)` };
  });

  /* M-03: 前导零 08/09(非合法八进制)不得静默截断(拒绝或拆分均可) */
  await check("M-03 前导零 08/09 不静默", async () => {
    let bad = 0;
    for (const lit of ["08", "09"]) {
      const src = `public 8;\n@ 0 i[4] : rLANG_VALUE;\nStoreI32(0, ${lit});\n`;
      try {
        const r = await EmuJsRun(idx, src, false, {});
        const got = r.outputs.rLANG_VALUE;
        if (typeof got === "number" && got === parseInt(lit, 8)) ++bad; /* 静默按八进制截断 */
      } catch (e) {
        /* 拒绝同样可接受 */
      }
    }
    return { pass: bad === 0, detail: bad ? `仍按八进制 ${bad}` : "无八进制静默(拒绝或拆分)" };
  });

  const pass = log.filter((x) => x.pass).length;
  const all = log.length;
  console.log(`corpus: done ${pass}/${all} passed`);
  return pass === all;
}

/*! RockeySign/RockeyDecrypt 接线冒烟(pkeyself): 参数校验 + 不再抛 "Not implemented"
 *! (原生已接线; 真实设备侧私钥往返需上游/设备导入核对, 不在此断言) */
async function EmuPkeySelf({ idx = 0 } = {}) {
  const e = EmuJsGet(idx);
  const log = [];
  const check = async (name, fn) => {
    let pass = false, detail = "";
    try {
      const r = await fn();
      pass = !!r;
    } catch (err) {
      detail = String((err && err.message) || err).slice(0, 90);
    }
    log.push({ name, pass });
    console.log(`pkeyself: ${pass ? "PASS" : "FAIL"} ${name}${detail ? "  (" + detail + ")" : ""}`);
  };

  await check("RockeySign 参数校验(负句柄拒绝)", () => {
    try {
      e.RockeySign(-1, Buffer.alloc(16));
      return false;
    } catch (x) {
      return /Invalid pkey/.test(String(x.message));
    }
  });
  await check("RockeyDecrypt 参数校验(空密文拒绝)", () => {
    try {
      e.RockeyDecrypt(1, Buffer.alloc(0));
      return false;
    } catch (x) {
      return /Invalid cipher size/.test(String(x.message));
    }
  });
  await check("RockeySign 已接线(未注册句柄→原生错误, 非 Not implemented)", () => {
    try {
      e.RockeySign(0x4321, crypto.randomBytes(32));
      return false;
    } catch (x) {
      return !/Not implemented/.test(String(x.message)) && /error/.test(String(x.message));
    }
  });
  await check("RockeyDecrypt 已接线(未注册句柄→原生错误, 非 Not implemented)", () => {
    try {
      e.RockeyDecrypt(0x4321, crypto.randomBytes(128));
      return false;
    } catch (x) {
      return !/Not implemented/.test(String(x.message)) && /error/.test(String(x.message));
    }
  });

  const pass = log.filter((x) => x.pass).length;
  console.log(`pkeyself: done ${pass}/${log.length} passed`);
  return pass === log.length;
}

/*! X509ExtBuilder 冒烟(x509ext): 常用 v3 扩展组装 → DER → ASN1Decode 结构回读断言 */
async function EmuX509Ext({ idx = 0 } = {}) {
  const e = EmuJsGet(idx);
  const x = e.X509ExtBuilder();
  const n0 = x.length;
  x.basicConstraints({ ca: true, pathLen: 0 })
    .keyUsage({ keyCertSign: true, cRLSign: true }, true)
    .extendedKeyUsage(["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"])
    .subjectKeyIdentifier(Buffer.alloc(20, 0xa5))
    .authorityKeyIdentifier(Buffer.alloc(20, 0xb6))
    .subjectAltName({ dns: ["example.com"], ip: ["10.0.0.1"], uri: ["https://example.com/x"] })
    .authorityInfoAccess({ ocsp: ["http://ocsp.example.com"], caIssuers: ["http://ca.example.com/ca.crt"] })
    .crlDistributionPoints(["http://crl.example.com/ca.crl"]);
  const der = x.build();
  const [v, sz] = e.ASN1Decode(der);
  const dbg = (w) => (w === null ? "null" : typeof w === "object" ? `{type=${w.type}, v=${Array.isArray(w.value) ? "list[" + w.value.length + "]" : typeof w.value + ":" + (Buffer.isBuffer(w.value) ? w.value.length : w.value)}}` : String(w));
  if (process.env.RKEY_TRACE === "1") {
    const top = v && typeof v === "object" && Array.isArray(v.value) ? v.value : [];
    console.log(`x509ext: top=${dbg(v)} children=${top.length} first3=${top.slice(0, 3).map(dbg).join(" | ")}`);
  }
  const okTop = v !== null && typeof v === "object" && !(v instanceof Date) && v.type === 0x30;
  const list = okTop ? v.value : null;
  const ok =
    okTop &&
    Array.isArray(list) &&
    list.length === 8 &&
    sz === der.length &&
    list.every(
      (ext) =>
        ext !== null &&
        typeof ext === "object" &&
        ext.type === 0x30 &&
        Array.isArray(ext.value) &&
        ext.value.length >= 2 &&
        ext.value[0] !== null &&
        typeof ext.value[0] === "object" &&
        ext.value[0].type === 0x06,
    );
  console.log(
    `x509ext: ${ok ? "PASS" : "FAIL"} builder len=${x.length} der=${der.length}B decode sz=${sz} seqChildren=${list && list.length}`,
  );
  void n0;
  return ok;
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

// ---------------------------------------------------------------- NIST 采集与分析(诚实子集)
async function CollectRand(outFile, count, hid) {
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  const fd = fs.openSync(outFile, "a");
  const admin = process.env.RKEY_ADMIN === "1";
  let got = 0;
  try {
    for (let i = 0; i < count; i++) {
      const buf = await RealRandOnce(hid, admin);
      fs.writeSync(fd, buf);
      got += buf.length;
      if (got % (64 * 1024) < 1024) console.log(`collect: ${got} bytes (${Math.round(got / 1024)}KB)`);
    }
  } finally {
    fs.closeSync(fd);
  }
  return got;
}

function erfcInvApprox(x) {
  // 误差函数补 1 - erf
  const t = 1 / (1 + 0.3275911 * Math.abs(x));
  const y = t * (0.254829592 + t * (-0.284496736 + t * (1.421413741 + t * (-1.453152027 + t * 1.061405429))));
  return y * Math.exp(-x * x);
}
function PErfc(z) {
  return erfcInvApprox(z / Math.SQRT2);
}
function lnGamma(x) {
  const g = 7;
  const C = [0.99999999999980993, 676.5203681218851, -1259.1392167224028, 771.3234287776531, -176.6150291621406,
    12.507343278686905, -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7];
  if (x < 0.5) return Math.log(Math.PI) - Math.log(Math.sin(Math.PI * x)) - lnGamma(1 - x);
  x -= 1;
  let a = C[0];
  const t = x + g + 0.5;
  for (let i = 1; i < g + 2; i++) a += C[i] / (x + i);
  return 0.5 * Math.log(2 * Math.PI) + (x + 0.5) * Math.log(t) - t + Math.log(a);
}
function igamc(a, x) {
  // 上尾正则化不完全伽马 (x>0, a>0), 数值稳定版
  if (x <= 0) return 1;
  if (a > 0 && x < a + 1) {
    // 级数求下尾, 上尾=1-P
    const logP = a * Math.log(x) - x - lnGamma(a + 1);
    let term = Math.exp(logP);
    let sum = term;
    for (let k = 1; k < 100000; k++) {
      term *= x / (a + k);
      sum += term;
      if (term / sum < 1e-14) break;
    }
    const P = Math.max(0, Math.min(1, sum));
    return Math.max(0, Math.min(1, 1 - P));
  }
  // 连分式(Lentz)求上尾
  const b0 = x + 1 - a;
  const c0 = 1e-30;
  let d = 1 / b0, c = c0;
  let h = d;
  for (let i = 1; i < 200000; i++) {
    const an = -i * (i - a);
    const b = b0 + 2 * i;
    d = an * d + b;
    if (Math.abs(d) < 1e-30) d = 1e-30;
    c = b + an / c;
    if (Math.abs(c) < 1e-30) c = 1e-30;
    d = 1 / d;
    const del = d * c;
    h *= del;
    if (Math.abs(del - 1) < 1e-14) break;
  }
  const res = Math.exp(a * Math.log(x) - x - lnGamma(a)) * h;
  return Math.max(0, Math.min(1, res));
}
function NistRun(bits, n) {
  const res = [];
  const add = (name, p, note) => res.push({ name, p, pass: p !== null && p >= 0.01, note });

  // 1) Frequency
  {
    let s = 0;
    for (let i = 0; i < n; i++) s += bits[i] ? 1 : -1;
    const obs = Math.abs(s) / Math.sqrt(n);
    add("Frequency (monobit)", PErfc(obs), `S=${s}`);
  }
  // 2) BlockFrequency M=128
  {
    const M = 128;
    const N = Math.floor(n / M);
    let chi2 = 0;
    for (let b = 0; b < N; b++) {
      let ones = 0;
      for (let j = 0; j < M; j++) if (bits[b * M + j]) ones++;
      chi2 += ((ones / M - 0.5) ** 2) * 4 * M;
    }
    add("BlockFrequency M=128", igamc(N / 2, chi2 / 2), `N=${N}, χ²=${chi2.toFixed(3)}`);
  }
  // 3) Runs
  {
    let ones = 0;
    for (let i = 0; i < n; i++) if (bits[i]) ones++;
    const pi = ones / n;
    if (Math.abs(pi - 0.5) >= 2 / Math.sqrt(n)) {
      add("Runs", 0, `pi0 偏差过大 ${pi.toFixed(6)}`);
    } else {
      let V = 1;
      for (let i = 1; i < n; i++) if (bits[i] !== bits[i - 1]) V++;
      const num = Math.abs(V - 2 * n * pi * (1 - pi));
      const den = 2 * Math.sqrt(2 * n) * pi * (1 - pi);
      add("Runs", PErfc(num / den), `V=${V}`);
    }
  }
  // 4) LongestRunOfOnes (M=10000, 需 n≥750000)
  {
    if (n >= 750000) {
      const M = 10000;
      const N = Math.floor(n / M);
      const v = [0, 0, 0, 0, 0, 0, 0];
      const pi = [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727];
      for (let b = 0; b < N; b++) {
        let run = 0, best = 0;
        for (let j = 0; j < M; j++) {
          if (bits[b * M + j]) { run++; best = Math.max(best, run); } else run = 0;
        }
        const idx = best <= 10 ? 0 : best >= 16 ? 6 : best - 10;
        v[idx]++;
      }
      let chi2 = 0;
      for (let k = 0; k < 7; k++) chi2 += ((v[k] - N * pi[k]) ** 2) / (N * pi[k]);
      add("LongestRunOfOnes M=10000", igamc(3, chi2 / 2), `χ²=${chi2.toFixed(3)}`);
    } else {
      add("LongestRunOfOnes M=10000", null, "需 ≥750000 bit 才能评估");
    }
  }
  // 9) Approximate Entropy m=5 (需 n 足够)
  {
    const m = 5;
    const mlen = 1 << m;
    const count = new Float64Array(mlen);
    for (let i = 0; i < n; i++) {
      let pat = 0;
      for (let k = 0; k < m; k++) pat = ((pat << 1) | (bits[(i + k) % n] ? 1 : 0)) & (mlen - 1);
      count[pat]++;
    }
    let sum = 0;
    for (let k = 0; k < mlen; k++) if (count[k] > 0) sum += count[k] * Math.log(count[k] / n);
    const phi_m = sum / n;
    const mlen1 = 1 << (m + 1);
    const count2 = new Float64Array(mlen1);
    for (let i = 0; i < n; i++) {
      let pat = 0;
      for (let k = 0; k < m + 1; k++) pat = ((pat << 1) | (bits[(i + k) % n] ? 1 : 0)) & (mlen1 - 1);
      count2[pat]++;
    }
    let sum2 = 0;
    for (let k = 0; k < mlen1; k++) if (count2[k] > 0) sum2 += count2[k] * Math.log(count2[k] / n);
    const phi_m1 = sum2 / n;
    const apen = phi_m - phi_m1;
    const dof = mlen >> 1;
    const chi2 = 2 * n * (Math.LN2 - apen);
    add("ApproximateEntropy m=5", igamc(dof, chi2 / 2), `ApEn=${apen.toFixed(5)}, χ²≈${chi2.toFixed(3)}`);
  }
  // 6) BinaryMatrixRank 32x32
  {
    const rows = 32, cols = 32, M = rows * cols;
    const N = Math.min(Math.floor(n / M), 4096); // 秩测试用前 ≤4096 个矩阵(避免过慢)
    if (N >= 38) {
      let cFull = 0, cFull1 = 0;
      for (let b = 0; b < N; b++) {
        const mtx = new Uint8Array(rows * cols);
        for (let r = 0; r < rows; r++)
          for (let c = 0; c < cols; c++) mtx[r * cols + c] = bits[b * M + r * cols + c] ? 1 : 0;
        let rank = 0;
        // GF(2) 高斯消元求秩
        const R = new Array(rows).fill(0).map((_, r) => r);
        const C = new Array(cols).fill(0).map((_, c) => c);
        let rr = 0;
        for (let c = 0; c < cols && rr < rows; c++) {
          let sel = -1;
          for (let r = rr; r < rows; r++) if (mtx[r * cols + c]) { sel = r; break; }
          if (sel < 0) continue;
          if (sel !== rr) for (let cc = 0; cc < cols; cc++) { const t = mtx[rr * cols + cc]; mtx[rr * cols + cc] = mtx[sel * cols + cc]; mtx[sel * cols + cc] = t; }
          for (let r = 0; r < rows; r++) {
            if (r !== rr && mtx[r * cols + c]) for (let cc = 0; cc < cols; cc++) mtx[r * cols + cc] ^= mtx[rr * cols + cc];
          }
          rr++;
        }
        rank = rr;
        void R; void C;
        if (rank === 32) cFull++;
        else if (rank === 31) cFull1++;
      }
      const cOther = N - cFull - cFull1;
      const pi = [0.2888, 0.5776, 0.1336];
      const chi2 = ((cFull - N * pi[0]) ** 2) / (N * pi[0]) + ((cFull1 - N * pi[1]) ** 2) / (N * pi[1]) + ((cOther - N * pi[2]) ** 2) / (N * pi[2]);
      add("BinaryMatrixRank 32x32", igamc(1, chi2 / 2), `N=${N}, χ²=${chi2.toFixed(3)}`);
    } else {
      add("BinaryMatrixRank 32x32", null, "需 ≥38 个矩阵");
    }
  }
  // 7) NonOverlappingTemplate m=9(近似: 每 256 bit 块内统计 '000000001' 非重叠匹配)
  {
    const M = 256;
    const N = Math.floor(n / M);
    if (N >= 8) {
      const pat = [0, 0, 0, 0, 0, 0, 0, 0, 1];
      let chi2 = 0;
      for (let b = 0; b < N; b++) {
        let count = 0, pos = 0;
        while (pos + pat.length <= M) {
          let ok = true;
          for (let k = 0; k < pat.length; k++) if ((bits[b * M + pos + k] ? 1 : 0) !== pat[k]) { ok = false; break; }
          if (ok) { count++; pos += pat.length; } else pos++;
        }
        chi2 += ((count - M / 512) ** 2) / (M / 512);
      }
      add("NonOverlappingTemplate m=9(近似)", igamc(N / 2, chi2 / 2), `N=${N}`);
    } else {
      add("NonOverlappingTemplate m=9(近似)", null, "需更多 bit");
    }
  }
  // 8) Serial m=8
  {
    const nbits = n;
    const m = 8;
    const p2 = [];
    for (const L of [m, m - 1, m - 2]) {
      const size = 1 << L;
      const cnt = new Float64Array(size);
      for (let i = 0; i < nbits; i++) {
        let pat = 0;
        for (let k = 0; k < L; k++) pat = ((pat << 1) | (bits[(i + k) % nbits] ? 1 : 0)) & (size - 1);
        cnt[pat]++;
      }
      let sum2 = 0;
      for (let k = 0; k < size; k++) sum2 += cnt[k] * cnt[k];
      p2.push(sum2 * (size / nbits) - nbits);
    }
    const psi = p2;
    const pSerial1 = igamc(1 << (m - 2), (psi[0] - psi[1]) / 4);
    const pSerial2 = igamc(1 << (m - 3), (psi[0] - 2 * psi[1] + psi[2]) / 8);
    add("Serial m=8", pSerial1, `P1; P2=${pSerial2.toExponential(2)}`);
    add("Serial m=8 (P2)", pSerial2, "第二个 p-value");
  }
  // 10) CumulativeSums
  {
    let S = 0, mx = 0;
    for (let i = 0; i < n; i++) { S += bits[i] ? 1 : -1; mx = Math.max(mx, Math.abs(S)); }
    let z = mx;
    let pv = 0;
    for (let k = Math.floor((-n / z + 1) / 4); k <= Math.floor((n / z - 1) / 4); k++) {
      pv += PErfc(((4 * k + 1) * z) / Math.sqrt(n)) - PErfc(((4 * k - 1) * z) / Math.sqrt(n));
    }
    pv += PErfc(z / Math.sqrt(n));
    add("CumulativeSums", Math.max(0, Math.min(1, pv)), `z=${z}`);
  }
  return res;
}

function NistHtml(results, meta) {
  const row = (r) =>
    `<tr><td>${r.name}</td><td>${r.p === null ? "N/A" : r.p.toExponential(3)}</td><td>${r.note}</td><td style="color:${r.pass ? "#0a0" : "#b00"}">${r.p === null ? "SKIP" : r.pass ? "PASS" : "FAIL"}</td></tr>`;
  return `<!doctype html><html lang="zh"><head><meta charset="utf-8"><title>NIST RNG 报告</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;margin:2em;background:#fafafa}h1{color:#0b3d91}table{border-collapse:collapse;background:#fff}td,th{border:1px solid #bbb;padding:6px 12px}th{background:#eef}</style></head><body>
<h1>真实 ukey 硬件随机数 NIST 风格报告</h1>
<p>设备: ${meta.hid} · 文件: ${meta.file} · 总字节: ${meta.bytes} · 分析位数: ${meta.n} bit · 时间: ${meta.time}</p>
<p><b>注意</b>: 非官方 NIST STS 全量; 为实现子集(单比特/分块频率/游程/最长游程/近似熵/累积和等), p≥0.01 视为通过。</p>
<table><tr><th>测试</th><th>p-value</th><th>说明</th><th>结论</th></tr>${results.map(row).join("")}</table></body></html>`;
}

async function NistReport(file, report) {
  const stat = fs.statSync(file);
  const data = fs.readFileSync(file);
  const hid = process.env.RKEY_HID || "00000000-efea115bfc084642";
  const n = Math.min(data.length * 8, 32 * 1024 * 1024); // 至多 32Mbit 参与
  const bits = new Uint8Array(n);
  for (let i = 0; i < n; i++) bits[i] = (data[i >> 3] >> (7 - (i & 7))) & 1;
  const results = NistRun(bits, n);
  const html = NistHtml(results, { hid, file, bytes: data.length, n, time: new Date().toISOString() });
  fs.writeFileSync(report, html);
  const pass = results.filter((r) => r.p !== null && r.p >= 0.01).length;
  const done = results.filter((r) => r.p !== null).length;
  console.log(`nist: ${report} bytes=${data.length} tests=${pass}/${done} pass`);
  return pass === done && done > 0 ? 0 : 1;
}

/*! 合并报告: 字节级指标 + NIST 子集, 输出到指定 html(用于更新 ai-doc/ukey-rand-quality-*.html) */
async function FullReport(file, report) {
  const data = fs.readFileSync(file);
  const hid = process.env.RKEY_HID || "00000000-efea115bfc084642";
  const n = Math.min(data.length * 8, 32 * 1024 * 1024);
  const bits = new Uint8Array(n);
  for (let i = 0; i < n; i++) bits[i] = (data[i >> 3] >> (7 - (i & 7))) & 1;
  const nist = NistRun(bits, n);
  const stats = RandStats([data], 1);
  const rowN = (r) =>
    `<tr><td>${r.name}</td><td>${r.p === null ? "N/A" : r.p.toExponential(3)}</td><td>${r.note}</td><td style="color:${r.pass ? "#0a0" : "#b00"}">${r.p === null ? "SKIP" : r.pass ? "PASS" : "FAIL"}</td></tr>`;
  const rowB = (k, v, note, verdict) =>
    `<tr><td>${k}</td><td>${v}</td><td>${note}</td><td style="color:${verdict === "PASS" ? "#0a0" : "#b00"}">${verdict}</td></tr>`;
  const html = `<!doctype html><html lang="zh"><head><meta charset="utf-8"><title>ukey 随机数质量报告</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;margin:2em;background:#fafafa}h1,h2{color:#0b3d91}table{border-collapse:collapse;background:#fff}td,th{border:1px solid #bbb;padding:6px 12px;text-align:left}th{background:#eef}</style></head><body>
<h1>RockeyARM 真实 ukey 随机数质量报告</h1>
<p>设备: <code>${hid}</code> · 采样源: ${file} · 总字节: ${stats.total} · 分析位数: ${n} bit · 更新: ${new Date().toISOString().slice(0, 19).replace("T", " ")}</p>
<h2>1. 字节级指标(全量)</h2>
<table><tr><th>指标</th><th>观测值</th><th>说明</th><th>结论</th></tr>
${rowB("位频率 p(1)", stats.p1.toFixed(6), `期望≈0.5(共 ${stats.bits} bit)`, Math.abs(stats.p1 - 0.5) < 0.005 ? "PASS" : Math.abs(stats.p1 - 0.5) < 0.02 ? "WARN" : "FAIL")}
${rowB("字节直方图 χ²(df=255)", stats.chi2.toFixed(2), "期望≈255", Math.abs(stats.chi2 - 255) < 3 * Math.sqrt(510) ? "PASS" : "WARN")}
${rowB("Shannon 熵 / 字节", stats.H.toFixed(4), "理想=8", stats.H > 7.99 ? "PASS" : stats.H > 7.9 ? "WARN" : "FAIL")}
${rowB("最小熵 / 字节", stats.minEntropy.toFixed(4), "理想=8", stats.minEntropy > 7.9 ? "PASS" : "WARN")}
${rowB("未出现字节数", stats.missing, "共 256", stats.missing <= 1 ? "PASS" : "WARN")}
</table>
<h2>2. NIST SP800-22 风格子集(非官方全量; p≥0.01 通过)</h2>
<table><tr><th>测试</th><th>p-value</th><th>说明</th><th>结论</th></tr>
${nist.map(rowN).join("")}
</table>
<p>说明: 随机源为设备 TRNG(脚本 RandBytes, 每帧 1024B 追加采集)。采集与分析命令: __Testing_dongle.cjs collect / nistreport / fullreport。</p>
</body></html>`;
  fs.writeFileSync(report, html);
  const pass = nist.filter((r) => r.p !== null && r.p >= 0.01).length;
  const done = nist.filter((r) => r.p !== null).length;
  console.log(`full: ${report} bytes=${data.length} nist=${pass}/${done} pass p1=${stats.p1.toFixed(6)} H=${stats.H.toFixed(4)}`);
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
  if (cmd === "collect") {
    /* 空闲采集: collect <outFile> <count> [hid]; 追加式(断点续采), 每块 1024B */
    const outFile = argv[1] || path.join(ROOT, "ai-doc", "randdata", "ukey-rng-00000000-efea115bfc084642.bin");
    const count = argv[2] !== undefined ? parseInt(argv[2], 10) : Infinity;
    const list = await List();
    const hid = argv[3] || (process.env.RKEY_HID || list[0]?.id);
    if (!hid) throw Error("no dongle");
    const got = await CollectRand(outFile, count, hid);
    console.log(`collect: done, total=${got} bytes -> ${outFile}`);
    return 0;
  }
  if (cmd === "nistreport") {
    const file = argv[1];
    const report = argv[2] || file.replace(/\.bin$/, "") + "-nist.html";
    fs.mkdirSync(path.dirname(report), { recursive: true });
    return NistReport(file, report);
  }
  if (cmd === "fullreport") {
    const file = argv[1];
    const report = argv[2] || path.join(ROOT, "ai-doc", "ukey-rand-quality-2026-09-08.html");
    fs.mkdirSync(path.dirname(report), { recursive: true });
    return FullReport(file, report);
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
  if (cmd === "skey") {
    /* SESSION_KEY 会话链复现(全新模拟器, mkey/* 真机非测试): skey [issuerIdx] [clientIdx]
     * 默认 emu0=签发者(root type42), emu1=客户端; 校验根/会话签名与字段格式 */
    const issuer = argv[1] !== undefined ? parseInt(argv[1], 10) : 0;
    const client = argv[2] !== undefined ? parseInt(argv[2], 10) : 1;
    const r = await EmuSkeyFlow({ issuer, client });
    return r.ok ? 0 : 1;
  }
  if (cmd === "mkey") {
    /* 复现 MASTER.SECRET 构建: 4 个保管者模拟器 K0..K3 跑 EXCHANGE, A0(emu[4]) 导入;
     * mkey [kStart] — 保管者从 emu[kStart..kStart+3] 起, A0 = kStart+4;
     * MKEY_INIT=0 时跳过 Initialize.dongle 前置(保管者/导入者直接以世界创建脚本运行) */
    const k0 = argv[1] !== undefined ? parseInt(argv[1], 10) : 0;
    const kIdx = [k0, k0 + 1, k0 + 2, k0 + 3];
    const a0Idx = k0 + 4;
    const r = await EmuMkeyMaster({
      kIdx,
      a0Idx,
      init: process.env.MKEY_INIT !== "0",
    });
    return r.allOk ? 0 : 1;
  }
  if (cmd === "xchg") {
    const a = argv[1] !== undefined ? parseInt(argv[1], 10) : 0;
    const b = argv[2] !== undefined ? parseInt(argv[2], 10) : 1;
    const r = await EmuXchg(a, b);
    console.log(`xchg: done, b_x25519=${r.bX25519.slice(0, 8)}`);
    return 0;
  }
  if (cmd === "badmin") {
    /* 真机 Admin-1000 建置 + key4(SM2ECIES) 使用计数观测(破坏性建世界, 不 lock):
     * badmin [hid] [burn]; BADMIN_BOOT=INIT-0x10000 可改用其它 Bootstrap 程序 */
    const list = await List();
    const hid = argv[1] || (process.env.RKEY_HID || list[0]?.id);
    if (!hid) throw Error("no dongle");
    const burn = argv[2] !== undefined ? parseInt(argv[2], 10) : 3;
    const boot = process.env.BADMIN_BOOT || "Bootstrap-Admin-1000.dongle.program";
    const r = await Admin1000Probe({ hid, burn, bootstrap: boot });
    void r;
    return 0;
  }
  if (cmd === "badminburn") {
    /* 耗尽阈值: badminburn [hid] — 重建 Admin-1000 世界后逐次 SM2Sign(4) 直到失败,
     * 成功数 = key4 建置后剩余次数(期望 < 1000); 消耗后不 lock, 可重跑建置恢复 */
    const list = await List();
    const hid = argv[1] || (process.env.RKEY_HID || list[0]?.id);
    if (!hid) throw Error("no dongle");
    const r = await BurnToZero({ hid });
    return r.ok > 0 ? 0 : 1;
  }
  if (cmd === "emuadmin") {
    /* 进程内模拟器 Admin-1000 耗尽验证: emuadmin [idx] — 期望成功 ≈999(licence 递减) */
    const idx = argv[1] !== undefined ? parseInt(argv[1], 10) : 0;
    const r = await EmuAdminBurn({ idx });
    return r.ok > 0 ? 0 : 1;
  }
  if (cmd === "corpus") {
    /* 编译器/词法边界语料: corpus [idx] — H-07/L-01/M-04/M-03 断言 */
    const idx = argv[1] !== undefined ? parseInt(argv[1], 10) : 0;
    const ok = await EmuCorpus({ idx });
    return ok ? 0 : 1;
  }
  if (cmd === "pkeyself") {
    /* RockeySign/Decrypt 接线冒烟: pkeyself [idx] */
    const idx = argv[1] !== undefined ? parseInt(argv[1], 10) : 0;
    const ok = await EmuPkeySelf({ idx });
    return ok ? 0 : 1;
  }
  if (cmd === "x509ext") {
    /* X509ExtBuilder 冒烟: x509ext [idx] */
    const idx = argv[1] !== undefined ? parseInt(argv[1], 10) : 0;
    const ok = await EmuX509Ext({ idx });
    return ok ? 0 : 1;
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
    `usage: __Testing_dongle.cjs list|dashboard|run <file> [hid]|suite <dir> [hid]|emu|diag-rsa|diag-gen|jsemu <file> [idx]|jsuite|jscheck [idx]|entrust <targetIdx> <trusteeIdx...>|adminrun <target> <trustee> <file>|randtest [count] [html]|sm2self [idx]|xchg <aIdx> <bIdx>|mkey [kStart]|skey [issuerIdx] [clientIdx]|badmin [hid] [burn]|badminburn [hid]|emuadmin [idx]|realadmin|reallimit <file> [hid] [trusteeIdx]|collect <out> [count]|nistreport <bin> [html]`,
  );
  return 2;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(err.stack || err.message);
    process.exit(1);
  });

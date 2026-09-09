import { integer, Addr, CipherSuiteV0 } from "../../World.js";
import * as jsCryptoText from "../../Assembly/Emulator_wasm.js";
import * as jsScript from "../../Script/index.js";

Object.defineProperty(globalThis.jsWorld, "CryptoLoader", {
  value: CryptoLoader,
  writable: false,
  enumerable: false,
  configurable: false,
});

export const enum PERMISSION {
  kAnonymous,
  kNormal,
  kAdministrator,
}
export const enum LED_STATE {
  kOff,
  kOn,
  kBlink,
}
export const enum SECRET_STORAGE_TYPE {
  kData,
  kRSA,
  kP256,
  kSM2,
  kSM4,
  kTDES,
}

const kErrno_ENOENT = 44,
  kErrno_ENOMEM = 48,
  kErrno_EACCES = 2,
  kErrno_ESPIPE = 70,
  kErrno_EROFS = 69;

const kFileID_null = 8848,
  kFileID_Config = 10001,
  kFileID_Random = 10086;

/** ABI.Check */
console.assert(
  PERMISSION.kAnonymous === 0 &&
    PERMISSION.kNormal === 1 &&
    PERMISSION.kAdministrator === 2,
);
console.assert(
  LED_STATE.kOff === 0 && LED_STATE.kOn === 1 && LED_STATE.kBlink === 2,
);
console.assert(
  SECRET_STORAGE_TYPE.kData === 0 &&
    SECRET_STORAGE_TYPE.kRSA === 1 &&
    SECRET_STORAGE_TYPE.kP256 === 2 &&
    SECRET_STORAGE_TYPE.kSM2 === 3 &&
    SECRET_STORAGE_TYPE.kSM4 === 4 &&
    SECRET_STORAGE_TYPE.kTDES === 5,
);
console.assert(kErrno_ENOENT === 44 && kErrno_ENOMEM == 48);

/**
 *!
 */
export type ASN1Value =
  | null /// V_ASN1_NULL ...
  | boolean /// V_ASN1_BOOLEAN ...
  | integer /// V_ASN1_INTEGER, unsigned, [0, 0x7fffffff] ...
  | bigint /// V_ASN1_INTEGER, unsigned ...
  | Date /// V_ASN1_UTCTIME | V_ASN1_GENERALIZEDTIME ...
  | { type: integer; value: string | Buffer | ASN1Value[] };

/**
 *!
 */
export const enum V_ASN1 {
  EOC = 0,
  BOOLEAN = 1,
  INTEGER = 2,
  BIT_STRING = 3,
  OCTET_STRING = 4,
  NULL = 5,
  OBJECT = 6,
  OBJECT_DESCRIPTOR = 7,
  EXTERNAL = 8,
  REAL = 9,
  ENUMERATED = 10,
  UTF8STRING = 12,
  SEQUENCE = 16,
  SET = 17,
  NUMERICSTRING = 18,
  PRINTABLESTRING = 19,
  T61STRING = 20,
  TELETEXSTRING = 20,
  VIDEOTEXSTRING = 21,
  IA5STRING = 22,
  UTCTIME = 23,
  GENERALIZEDTIME = 24,
  GRAPHICSTRING = 25,
  ISO64STRING = 26,
  VISIBLESTRING = 26,
  GENERALSTRING = 27,
  UNIVERSALSTRING = 28,
  BMPSTRING = 30,
}

export interface X509ExtBuilder {
  readonly length: integer;
  clear(): X509ExtBuilder;
  /** 通用追加(oid 点分; value=扩展值内容 DER 的 ASN1Value, 自动 OCTET STRING 包裹) */
  add(oid: string, value: ASN1Value, critical?: boolean): X509ExtBuilder;
  keyUsage(bits: Record<string, boolean>, critical?: boolean): X509ExtBuilder;
  extendedKeyUsage(oids: string[], critical?: boolean): X509ExtBuilder;
  basicConstraints(
    opts: { ca?: boolean; pathLen?: integer },
    critical?: boolean,
  ): X509ExtBuilder;
  subjectAltName(
    names: {
      dns?: string[];
      ip?: string[];
      uri?: string[];
      email?: string[];
      rid?: string[];
      dirName?: ASN1Value;
    },
    critical?: boolean,
  ): X509ExtBuilder;
  subjectKeyIdentifier(keyid: Buffer | string, critical?: boolean): X509ExtBuilder;
  authorityKeyIdentifier(keyid: Buffer | string, critical?: boolean): X509ExtBuilder;
  authorityInfoAccess(
    opts: { ocsp?: string[]; caIssuers?: string[] },
    critical?: boolean,
  ): X509ExtBuilder;
  crlDistributionPoints(urls: string[], critical?: boolean): X509ExtBuilder;
  extensionsValue(): ASN1Value;
  build(): Buffer;
}

export interface RockeyPKEY {
  Sign(dgst: Buffer, result: Buffer): integer;
  Decrypt(cipher: Buffer, result: Buffer): integer;
}

export interface RockeyEmulator {
  RANDSeedBytes(v: any): void;

  Export(): Buffer;
  Create(secret: string | Buffer, uid: integer, loop: integer): void; /// perm == PERMISSION.kAdministrator
  Open(
    perm: PERMISSION,
    storage: Buffer,
    secret: string | Buffer,
    loop: integer,
  ): void;

  Execv(InOutBuffer: Buffer): void;

  GetDongleInfo(): Buffer;
  GetPINState(): PERMISSION;
  SetPermission(perm: PERMISSION): void;
  SetLEDState(state: LED_STATE): void;

  ReadShareMemory(): Buffer;
  WriteShareMemory(buffer: Buffer): void;

  DeleteFile(type: SECRET_STORAGE_TYPE, id: integer): boolean;
  CreateDataFile(id: integer, size: integer): void;
  WriteDataFile(id: integer, off: integer, buffer: Buffer): void;
  ReadDataFile(id: integer, off: integer, size: integer): Buffer;

  CreatePKEYFile(type: SECRET_STORAGE_TYPE, bits: integer, id: integer): void;
  GenerateRSA(id: integer, export_private: boolean): Buffer; /// [ modulus.LE[4], exponent[256] ] || [ modulus.LE[4], exponent[256], private_key[256] ]
  ImportRSA(id: integer, pkey: Buffer): void;

  GenerateP256(id: integer, export_private: boolean): Buffer; /// [ X[32], Y[32] ] || [ X[32], Y[32], K[32] ]
  ImportP256(id: integer, private_key: Buffer): void; /// private_key : Buffer[32] || Buffer[96]

  GenerateSM2(id: integer, export_private: boolean): Buffer; /// [ X[32], Y[32] ] || [ X[32], Y[32], K[32] ]
  ImportSM2(id: integer, private_key: Buffer): void; /// private_key : Buffer[32] || Buffer[96]

  CreateKeyFile(id: integer, type: SECRET_STORAGE_TYPE): void;
  WriteKeyFile(id: integer, type: SECRET_STORAGE_TYPE, key: Buffer): void;

  RSAPrivate(key: integer | Buffer, input: Buffer, encrypt: boolean): Buffer;
  RSAPublic(
    modulus: integer,
    exponent: Buffer,
    input: Buffer,
    encrypt: boolean,
  ): Buffer;

  P256Sign(key: integer | Buffer, hash: Buffer): Buffer;
  P256Verify(point: Buffer, hash: Buffer, sign: Buffer): boolean;

  SM2Sign(key: integer | Buffer, hash: Buffer): Buffer;
  SM2Verify(point: Buffer, hash: Buffer, sign: Buffer): boolean;

  SM2Decrypt(key: integer | Buffer, cipher: Buffer): Buffer;
  SM2Encrypt(point: Buffer, plain: Buffer): Buffer;

  SM3(message: Buffer): Buffer;
  SM4ECB(key: integer | Buffer, input: Buffer, encrypt: boolean): Buffer;

  CheckPointOnCurveSM2(point: Buffer): boolean;
  EmuDecompressPointSM2(X: Buffer, Yodd: boolean): Buffer;

  CheckPointOnCurvePrime256v1(point: Buffer): boolean;
  DecompressPointPrime256v1(X: Buffer, Yodd: boolean): Buffer;
  ComputePubkeyPrime256v1(privateKey: Buffer): Buffer;
  GenerateKeyPairPrime256v1(): Buffer; /// [ X[32], Y[32], K[32] ] ...
  ComputeSecretPrime256v1(point: Buffer, privateKey: Buffer): Buffer;
  SignMessagePrime256v1(hash: Buffer, privateKey: Buffer): Buffer;
  VerifySignPrime256v1(point: Buffer, hash: Buffer, sign: Buffer): boolean;

  CheckPointOnCurveSecp256k1(point: Buffer): boolean;
  DecompressPointSecp256k1(X: Buffer, Yodd: boolean): Buffer;
  ComputePubkeySecp256k1(privateKey: Buffer): Buffer;
  GenerateKeyPairSecp256k1(): Buffer; /// [ X[32], Y[32], K[32] ] ...
  ComputeSecretSecp256k1(point: Buffer, privateKey: Buffer): Buffer;
  SignMessageSecp256k1(hash: Buffer, privateKey: Buffer): Buffer;
  VerifySignSecp256k1(point: Buffer, hash: Buffer, sign: Buffer): boolean;

  RockeyClear(pkey: integer): integer;
  RockeyCreateRSA(
    pkey: integer,
    provider: RockeyPKEY,
    E: integer,
    N: Buffer,
  ): integer;
  RockeyCreateP256(pkey: integer, provider: RockeyPKEY, point: Buffer): integer;
  RockeyCreateSM2(pkey: integer, provider: RockeyPKEY, point: Buffer): integer;

  RockeySign(pkey: integer, hash: Buffer): Buffer;
  RockeyDecrypt(pkey: integer, cipher: Buffer): Buffer;

  ASN1Decode(input: Buffer): [value: ASN1Value, size: integer];
  ASN1Encode(value: ASN1Value): Buffer;

  /** X509 v3 扩展构建器(每次返回新实例; 见 X509ExtBuilder 接口) */
  X509ExtBuilder(): X509ExtBuilder;
}

interface Native0_ {
  _initialize(): void;
  emscripten_stack_get_current(): integer;
  _emscripten_stack_restore(add: integer): void;
  _emscripten_stack_alloc(size: integer): Addr;

  Initialize(): integer;
  RANDSeedBytes(buff: Addr, size: integer): void;
  MemoryManager(p: Addr, size: integer): Addr;

  EmuSize(): integer;
  EmuNew(mem: Addr, perm: PERMISSION): Addr;
  EmuClear(thiz: Addr): void;

  EmuCreate(
    thiz: Addr,
    master_secret: Addr,
    uid: integer,
    loop: integer,
  ): integer;
  EmuOpen(thiz: Addr, master_secret: Addr, loop: integer): integer;
  EmuClose(thiz: Addr): integer;
  EmuWrite(thiz: Addr): integer;

  EmuExecv(thiz: Addr, InOutBuf: Addr): integer;
  EmuGetDongleInfo(thiz: Addr, info: Addr): integer;
  EmuGetPINState(thiz: Addr, state: Addr): integer;
  EmuSetPermission(thiz: Addr, perm: integer): integer;
  EmuSetLEDState(thiz: Addr, state: Addr): integer;

  EmuReadShareMemory(thiz: Addr, buffer: Addr): integer;
  EmuWriteShareMemory(thiz: Addr, buffer: Addr): integer;

  EmuDeleteFile(thiz: Addr, type: integer, id: integer): integer;
  EmuCreateDataFile(thiz: Addr, id: integer, size: integer): integer;
  EmuWriteDataFile(
    thiz: Addr,
    id: integer,
    offset: integer,
    buffer: Addr,
    size: integer,
  ): integer;
  EmuReadDataFile(
    thiz: Addr,
    id: integer,
    offset: integer,
    buffer: Addr,
    size: integer,
  ): integer;
  EmuCreatePKEYFile(
    thiz: Addr,
    type: SECRET_STORAGE_TYPE,
    bits: integer,
    id: integer,
  ): integer;
  EmuGenerateRSA(
    thiz: Addr,
    id: integer,
    modulus: Addr,
    exponent: Addr,
    private_key: Addr,
  ): integer;
  EmuImportRSA(
    thiz: Addr,
    id: integer,
    modulus: integer,
    exponent: Addr,
    private_key: Addr,
  ): integer;
  EmuGenerateP256(thiz: Addr, id: integer, X: Addr, Y: Addr, K: Addr): integer;
  EmuImportP256(thiz: Addr, id: integer, K: Addr): integer;

  EmuGenerateSM2(thiz: Addr, id: integer, X: Addr, Y: Addr, K: Addr): integer;
  EmuImportSM2(thiz: Addr, id: integer, K: Addr): integer;

  EmuCreateKeyFile(thiz: Addr, id: integer, type: SECRET_STORAGE_TYPE): integer;
  EmuWriteKeyFile(
    thiz: Addr,
    id: integer,
    buffer: Addr,
    size: integer,
    type: SECRET_STORAGE_TYPE,
  ): integer;

  EmuRSAPrivate(
    thiz: Addr,
    id: integer,
    buffer: Addr,
    size: Addr,
    encrypt: boolean,
  ): integer;
  EmuRSAPrivateEx(
    thiz: Addr,
    bits: integer,
    modulus: integer,
    exponent: Addr,
    private_key: Addr,
    buffer: Addr,
    size: Addr,
    encrypt: boolean,
  ): integer;
  EmuRSAPublic(
    thiz: Addr,
    bits: integer,
    modulus: integer,
    exponent: Addr,
    buffer: Addr,
    size: Addr,
    encrypt: boolean,
  ): integer;

  EmuP256Sign(thiz: Addr, id: integer, hash: Addr, R: Addr, S: Addr): integer;
  EmuP256SignEx(thiz: Addr, K: Addr, hash: Addr, R: Addr, S: Addr): integer;
  EmuP256Verify(
    thiz: Addr,
    X: Addr,
    Y: Addr,
    hash: Addr,
    R: Addr,
    S: Addr,
  ): integer;

  EmuSM2Sign(thiz: Addr, id: integer, hash: Addr, R: Addr, S: Addr): integer;
  EmuSM2SignEx(thiz: Addr, K: Addr, hash: Addr, R: Addr, S: Addr): integer;
  EmuSM2Verify(
    thiz: Addr,
    X: Addr,
    Y: Addr,
    hash: Addr,
    R: Addr,
    S: Addr,
  ): integer;

  EmuSM2Decrypt(
    thiz: Addr,
    id: integer,
    cipher: Addr,
    size_cipher: integer,
    text: Addr,
    size_text: Addr,
  ): integer;

  EmuSM2DecryptEx(
    thiz: Addr,
    K: Addr,
    cipher: Addr,
    size_cipher: integer,
    text: Addr,
    size_text: Addr,
  ): integer;

  EmuSM2Encrypt(
    thiz: Addr,
    X: Addr,
    Y: Addr,
    text: Addr,
    size_text: integer,
    cipher: Addr,
  ): integer;

  EmuSM3(thiz: Addr, input: Addr, size: integer, md: Addr): integer;

  EmuTDESECB(
    thiz: Addr,
    id: integer,
    buffer: Addr,
    size: integer,
    encrypt: boolean,
  ): integer;

  EmuTDESECBEx(
    thiz: Addr,
    key: Addr,
    buffer: Addr,
    size: integer,
    encrypt: boolean,
  ): integer;

  EmuSM4ECB(
    thiz: Addr,
    id: integer,
    buffer: Addr,
    size: integer,
    encrypt: boolean,
  ): integer;

  EmuSM4ECBEx(
    thiz: Addr,
    key: Addr,
    buffer: Addr,
    size: integer,
    encrypt: boolean,
  ): integer;

  EmuCheckPointOnCurveSM2(thiz: Addr, X: Addr, Y: Addr): integer;
  EmuDecompressPointSM2(thiz: Addr, Y: Addr, X: Addr, Yodd: boolean): integer;

  EmuCheckPointOnCurvePrime256v1(thiz: Addr, X: Addr, Y: Addr): integer;
  EmuDecompressPointPrime256v1(
    thiz: Addr,
    Y: Addr,
    X: Addr,
    Yodd: boolean,
  ): integer;

  EmuComputePubkeyPrime256v1(thiz: Addr, X: Addr, Y: Addr, K: Addr): integer;
  EmuGenerateKeyPairPrime256v1(thiz: Addr, X: Addr, Y: Addr, K: Addr): integer;
  EmuComputeSecretPrime256v1(
    thiz: Addr,
    secret: Addr,
    X: Addr,
    Y: Addr,
    K: Addr,
  ): integer;
  EmuSignMessagePrime256v1(
    thiz: Addr,
    K: Addr,
    H: Addr,
    R: Addr,
    S: Addr,
  ): integer;

  EmuVerifySignPrime256v1(
    thiz: Addr,
    X: Addr,
    Y: Addr,
    H: Addr,
    R: Addr,
    S: Addr,
  ): integer;

  EmuCheckPointOnCurveSecp256k1(thiz: Addr, X: Addr, Y: Addr): integer;
  EmuDecompressPointSecp256k1(
    thiz: Addr,
    Y: Addr,
    X: Addr,
    Yodd: boolean,
  ): integer;

  EmuComputePubkeySecp256k1(thiz: Addr, X: Addr, Y: Addr, K: Addr): integer;
  EmuGenerateKeyPairSecp256k1(thiz: Addr, X: Addr, Y: Addr, K: Addr): integer;
  EmuComputeSecretSecp256k1(
    thiz: Addr,
    secret: Addr,
    X: Addr,
    Y: Addr,
    K: Addr,
  ): integer;
  EmuSignMessageSecp256k1(
    thiz: Addr,
    K: Addr,
    H: Addr,
    R: Addr,
    S: Addr,
  ): integer;

  EmuVerifySignSecp256k1(
    thiz: Addr,
    X: Addr,
    Y: Addr,
    H: Addr,
    R: Addr,
    S: Addr,
  ): integer;

  RockeyPKEY_Clear(pkey: integer): integer;
  RockeyPKEY_CreateRSA(
    pkey: integer,
    E: integer,
    N: Addr,
    nlen: integer,
  ): integer;

  RockeyPKEY_CreateP256(pkey: integer, X: Addr, Y: Addr): integer;
  RockeyPKEY_CreateSM2(pkey: integer, X: Addr, Y: Addr): integer;

  RockeyPKEY_SignEx(
    pkey: integer,
    dgst: Addr,
    dlen: integer,
    sig: Addr,
    siglen: integer,
  ): integer;
  RockeyPKEY_DecryptEx(
    pkey: integer,
    out: Addr,
    outlen: integer,
    cipher: Addr,
    cipherlen: integer,
  ): integer;
}

export type CreateEmulatorOption = {
  UpdateLEDState?: (led: LED_STATE) => void;
  LogWriteMessage?: (level: integer, message: string) => void;
  OpensslConfig?: string;
};

/**
 *! console.info/console.warning/... 会记录调用栈帧, 这不是很合适 ...
 */
function default_logWrite(level: integer, message: string) {
  switch (level) {
    case 0:
      console.error(`%c${message}`, "color: purple");
      break;
    case 1:
      console.error(`%c${message}`, "color: red");
      break;
    case 2:
      console.warn(`%c${message}`, "color: darkorange");
      break;
    case 3:
      console.info(`%c${message}`, "color: blue");
      break;
    default:
      console.log(`%c${message}`, "color: dimgray");
      break;
  }
}

type LogEntry = {
  logWrite: typeof default_logWrite;
  level: integer;
  message: string;
};
const global_logs = <LogEntry[]>[];
setInterval(() => {
  for (const { logWrite, level, message } of global_logs) {
    logWrite(level, message);
  }
  global_logs.length = 0;
}, 200);

export async function CryptoLoader(jsCipher: CipherSuiteV0) {
  const wasmModule_ = await WebAssembly.compile(jsCryptoText.Assets());
  async function ParseScript(script: string) {
    return await jsScript.Parse(script);
  }

  function ASN1Decode(input: Buffer): [value: ASN1Value, size: integer] {
    function ToDate(type: integer, value: Buffer): Date {
      function get2(off: integer) {
        return (value[off] - 0x30) * 10 + value[off + 1] - 0x30;
      }
      function get4(off: integer) {
        let r = 0;
        for (let i = 0; i < 4; ++i) r = r * 10 + value[off + i] - 0x30;
        return r;
      }

      const vlen = value.length - 1;
      let error = 0;
      if (0x5a !== value[vlen]) {
        ++error;
      }
      for (let i = 0; i < vlen; ++i) {
        if (value[i] < 0x30 || value[i] > 0x39) ++error;
      }

      if (error || (type === 23 && vlen !== 12) || (type === 24 && vlen !== 14))
        throw jsCipher.Annihilus_(`Invalid ASN1 Date ${error} ${type} ${vlen}`);

      const year = (() => {
        if (type === 23) {
          /// [1950, 2149]
          const v = get2(0);
          if (v <= 49) return 2000 + v;
          return 1900 + v;
        }
        return get4(0);
      })();

      value = value.subarray(vlen - 10);
      const month = get2(0);
      const mday = get2(2);
      const hour = get2(4);
      const minute = get2(6);
      const second = get2(8);

      const result = new Date(
        Date.UTC(year, month - 1, mday, hour, minute, second),
      );

      if (
        year !== result.getUTCFullYear() ||
        month !== result.getUTCMonth() + 1 ||
        mday !== result.getUTCDate() ||
        hour !== result.getUTCHours() ||
        minute !== result.getUTCMinutes() ||
        second !== result.getUTCSeconds()
      )
        throw jsCipher.Annihilus_(
          `Invalid date [${year}-${month}-${mday} ${hour}:${minute}:${second}] !== ${result.toISOString()}`,
        );

      return result;
    }

    let off = 0;
    let asn1: ASN1Value = null;

    const type = input[off++];
    const length = (function () {
      let len = input[off++];
      if (len & 0x80) {
        len &= 0x7f;
        off += len;
        len = parseInt(input.subarray(2, 2 + len).toString("hex"), 16);
      }
      return len;
    })();
    const value = input.subarray(off, off + length);
    off += length;

    if (off > input.length)
      throw jsCipher.Annihilus_(
        `ASN1Decode: Invalid input ${off} / ${input.length}`,
      );

    switch (type) {
      case V_ASN1.BOOLEAN:
        asn1 = length === 1 && value[0] !== 0;
        break;

      case V_ASN1.INTEGER:
        asn1 = BigInt(`0x${value.toString("hex")}`);
        if (asn1 >= 0 && asn1 <= 0x7fffffffn) asn1 = Number(asn1);
        break;

      case V_ASN1.NULL:
        break;

      case V_ASN1.UTF8STRING:
      case V_ASN1.NUMERICSTRING:
      case V_ASN1.PRINTABLESTRING:
      case V_ASN1.IA5STRING:
      case V_ASN1.VISIBLESTRING:
        asn1 = { type, value: value.toString() };
        break;

      case V_ASN1.UTCTIME:
      case V_ASN1.GENERALIZEDTIME:
        asn1 = ToDate(type, value);
        break;

      default:
        if ((type >= 0x30 && type <= 0x31) || (type >= 0xa0 && type <= 0xa1)) {
          let off = 0;
          const vlen = value.length;
          const list = <ASN1Value[]>[];
          asn1 = { type, value: list };

          while (off < vlen) {
            const [v, sz] = ASN1Decode(value.subarray(off));
            off += sz;
            list.push(v);
          }
        } else {
          asn1 = { type, value };
        }
        break;
    }

    return [asn1, off];
  }

  function ASN1Encode(value: ASN1Value): Buffer {
    let sizeLeft = 2 ** 24;
    const result = <Buffer[]>[];

    function push(v: Buffer | Array<integer>) {
      sizeLeft -= v.length;
      if (sizeLeft < 0) throw jsCipher.Annihilus_("ASN1Encode: too large");
      if (Array.isArray(v)) result.push(Buffer.from(v));
      else result.push(v);
    }

    function enc_int(v: bigint) {
      if (v < 0) v = -v; /// unsigned only ...

      let buf: Buffer;
      const s = v.toString(16);
      const sz = s.length;

      if (sz & 1) {
        buf = Buffer.alloc(1 + (sz >>> 1));
        buf[0] = parseInt(s[0], 16);
        Buffer.from(s.slice(1), "hex").copy(buf, 1);
      } else if (s[0] >= "8") {
        buf = Buffer.alloc(1 + (sz >>> 1));
        Buffer.from(s, "hex").copy(buf, 1);
      } else {
        buf = Buffer.from(s, "hex");
      }

      enc_buf(buf, V_ASN1.INTEGER);
    }

    function enc_len(len: integer, type: integer): Buffer {
      if (len < 0x80) return Buffer.from([type, len]);
      else if (len <= 0xff) return Buffer.from([type, 0x81, len]);
      else if (len <= 0xffff)
        return Buffer.from([type, 0x82, len >>> 8, len & 0xff]);
      else if (len <= 0xffffff)
        return Buffer.from([
          type,
          0x83,
          len >>> 16,
          (len >>> 8) & 0xff,
          len & 0xff,
        ]);
      else throw jsCipher.Annihilus_(`length > 0xffffff`);
    }
    function enc_buf(v: Buffer, type: integer) {
      push(enc_len(v.length, type));
      push(v);
    }

    function enc_date(v: Date) {
      let off = 0;
      const year = v.getUTCFullYear();
      const type =
        year >= 1950 && year < 2050 ? V_ASN1.UTCTIME : V_ASN1.GENERALIZEDTIME;
      const buf = Buffer.alloc(type == V_ASN1.UTCTIME ? 13 : 15);
      function i2(v: integer) {
        buf[off++] = (0x30 + v / 10) | 0;
        buf[off++] = 0x30 + (v % 10);
      }

      if (year >= 1950 && year < 2050) {
        i2(year % 100);
      } else if (year >= 0 && year <= 9999) {
        i2((year / 100) | 0);
        i2(year % 100);
      } else {
        throw jsCipher.Annihilus_(`Invalid date: ${v.toISOString()}`);
      }

      i2(v.getUTCMonth() + 1);
      i2(v.getUTCDate());
      i2(v.getUTCHours());
      i2(v.getUTCMinutes());
      i2(v.getUTCSeconds());
      buf[off++] = 0x5a; /// 'Z'

      enc_buf(buf, type);
    }

    function enc_list(list: ASN1Value[], type: integer) {
      let size = 0;
      const off = result.length++;

      sizeLeft -= 6; /// max, ignore error ...
      for (const value of list) enc(value);
      for (const value of result.slice(off + 1)) size += value.length;
      result[off] = enc_len(size, type);
    }

    function enc(value: ASN1Value) {
      switch (typeof value) {
        case "boolean":
          push(Buffer.from([V_ASN1.BOOLEAN, 0x01, value ? 0xff : 0x00]));
          break;

        case "number":
          enc_int(BigInt(value | 0));
          break;

        case "bigint":
          enc_int(value);
          break;

        case "object":
          if (value == null) {
            push(Buffer.from([V_ASN1.NULL, 0x00]));
          } else if (value instanceof Date) {
            enc_date(value);
          } else {
            const type = value.type | 0;
            const v = value.value;

            if (Array.isArray(v)) enc_list(v, type);
            else if (typeof v === "string") enc_buf(Buffer.from(v), type);
            else if (v instanceof Buffer) enc_buf(v, type);
            else throw jsCipher.Annihilus_(`Invalid value ${v}, type ${type}`);
          }
          break;

        default:
          throw jsCipher.Annihilus_(`Invalid ASN1.value ${value}!`);
      }
    }

    enc(value);

    return Buffer.concat(result);
  }

  // ================================================================ X509 v3 扩展构建器
  /*! X509 v3 常用扩展的 Web 端 DER 构建(供签发 CA/证书时嵌入原生
   *! RockeyPKEY_SignRootCA / RockeyPKEY_X509ReqFrom / RockeyPKEY_SignX509 的 extensions 参数)。
   *! 用法:
   *!   const ext = emulator.X509ExtBuilder();
   *!   ext.basicConstraints({ ca: true, pathLen: 0 })
   *!      .keyUsage({ keyCertSign: true, cRLSign: true })
   *!      .subjectAltName({ dns: ["example.com"], ip: ["10.0.0.1"] })
   *!      .subjectKeyIdentifier("9F43...")  // 或 .authorityKeyIdentifier(...)
   *!      .extendedKeyUsage(["1.3.6.1.5.5.7.3.1"])
   *!      .authorityInfoAccess({ ocsp: ["http://ocsp.example.com"] })
   *!      .crlDistributionPoints(["http://crl.example.com/ca.crl"])
   *!   const der = ext.build();   // SEQUENCE OF Extension(DER), 可直接嵌入
   *!   ext.clear();               // 复用实例
   *! 通用方法 .add(oid, value, critical=false) 可加任意扩展(value = 扩展值内容 DER 的 ASN1Value)。
   */
  function encodeOid(oid: string): Buffer {
    if (!/^[0-2](\.\d+)+$/.test(oid)) throw jsCipher.Annihilus_(`Invalid OID ${oid}`);
    const parts = oid.split(".").map((x) => parseInt(x, 10));
    if (parts[1] > 39 && parts[0] <= 1)
      throw jsCipher.Annihilus_(`Invalid OID ${oid} (second arc >39)`);
    const out: number[] = [];
    const push128 = (n: number) => {
      const tmp = [n & 0x7f];
      n >>>= 7;
      while (n > 0) {
        tmp.unshift((n & 0x7f) | 0x80);
        n >>>= 7;
      }
      out.push(...tmp);
    };
    push128(parts[0] * 40 + parts[1]);
    for (let i = 2; i < parts.length; ++i) push128(parts[i]);
    return Buffer.from(out);
  }
  const OID = (oid: string): ASN1Value => ({ type: V_ASN1.OBJECT, value: encodeOid(oid) });
  const OID_TEXT = {
    keyUsage: "2.5.29.15",
    extKeyUsage: "2.5.29.37",
    basicConstraints: "2.5.29.19",
    subjectAltName: "2.5.29.17",
    subjectKeyId: "2.5.29.14",
    authorityKeyId: "2.5.29.35",
    crlDistributionPoints: "2.5.29.31",
    aia: "1.3.6.1.5.5.7.1.1",
    aiaOcsp: "1.3.6.1.5.5.7.48.1",
    aiaCaIssuers: "1.3.6.1.5.5.7.48.2",
  };

  class X509ExtBuilderImpl {
    private readonly items: { oid: string; critical: boolean; value: ASN1Value }[] = [];

    get length(): integer {
      return this.items.length;
    }
    clear(): X509ExtBuilderImpl {
      this.items.length = 0;
      return this;
    }

    /** 通用: 追加任意扩展(oid = 点分 OID; value = 扩展值内容, 会自动 OCTET STRING 包裹) */
    add(oid: string, value: ASN1Value, critical: boolean = false): X509ExtBuilderImpl {
      encodeOid(oid); // 校验
      this.items.push({ oid, critical, value });
      return this;
    }

    /** KeyUsage(critical 惯例为 true); bits 键: digitalSignature/nonRepudiation/keyEncipherment/
     * dataEncipherment/keyAgreement/keyCertSign/cRLSign/encipherOnly/decipherOnly */
    keyUsage(bits: Record<string, boolean>, critical: boolean = true): X509ExtBuilderImpl {
      const order = ["digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
        "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"];
      let maxBit = -1;
      const set: boolean[] = new Array(order.length).fill(false);
      for (let i = 0; i < order.length; ++i)
        if ((bits as Record<string, boolean>)[order[i]]) {
          set[i] = true;
          maxBit = Math.max(maxBit, i);
        }
      if (maxBit < 0) throw jsCipher.Annihilus_(`keyUsage: no bits set`);
      const nbytes = (maxBit >> 3) + 1;
      const content = Buffer.alloc(1 + nbytes);
      for (let i = 0; i <= maxBit; ++i)
        if (set[i]) content[1 + (i >> 3)] |= 0x80 >> (i & 7);
      content[0] = nbytes * 8 - (maxBit + 1); // 未用位
      return this.add(OID_TEXT.keyUsage, { type: V_ASN1.BIT_STRING, value: content }, critical);
    }

    /** ExtendedKeyUsage: SEQUENCE OF OID */
    extendedKeyUsage(oids: string[], critical: boolean = false): X509ExtBuilderImpl {
      if (!oids.length) throw jsCipher.Annihilus_(`extendedKeyUsage: empty`);
      return this.add(OID_TEXT.extKeyUsage, { type: 0x30, value: oids.map(OID) }, critical);
    }

    /** BasicConstraints: SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen INTEGER OPTIONAL } */
    basicConstraints(opts: { ca?: boolean; pathLen?: integer }, critical: boolean = true): X509ExtBuilderImpl {
      const seq: ASN1Value[] = [];
      if (opts.ca) seq.push(true);
      if (opts.pathLen !== undefined) {
        if (opts.pathLen < 0) throw jsCipher.Annihilus_(`basicConstraints: pathLen<0`);
        seq.push(opts.pathLen);
      }
      return this.add(OID_TEXT.basicConstraints, { type: 0x30, value: seq }, critical);
    }

    /** SubjectAltName: GeneralNames(SEQUENCE OF GeneralName) */
    subjectAltName(
      names: {
        dns?: string[];
        ip?: string[];
        uri?: string[];
        email?: string[];
        rid?: string[]; // registeredID
        dirName?: ASN1Value; // [4] EXPLICIT Name
      },
      critical: boolean = false,
    ): X509ExtBuilderImpl {
      const gn: ASN1Value[] = [];
      for (const s of names.dns || [])
        gn.push({ type: 0x82, value: Buffer.from(s, "utf8") }); // dNSName IA5String
      for (const s of names.uri || [])
        gn.push({ type: 0x86, value: Buffer.from(s, "utf8") }); // uniformResourceIdentifier
      for (const s of names.email || [])
        gn.push({ type: 0x81, value: Buffer.from(s, "utf8") }); // rfc822Name
      for (const s of names.ip || []) {
        const ip = Buffer.from(s.split(".").map(Number));
        if (ip.length !== 4) throw jsCipher.Annihilus_(`subjectAltName: ip ${s} not IPv4`);
        gn.push({ type: 0x87, value: ip });
      }
      for (const r of names.rid || []) gn.push({ type: 0x88, value: encodeOid(r) });
      if (names.dirName !== undefined)
        gn.push({ type: 0xa4, value: [names.dirName] }); // [4] EXPLICIT Name
      if (!gn.length) throw jsCipher.Annihilus_(`subjectAltName: empty`);
      return this.add(OID_TEXT.subjectAltName, { type: 0x30, value: gn }, critical);
    }

    /** SubjectKeyIdentifier: extnValue = OCTET STRING(keyid); keyid 建议 20B(SHA-1 由签发方/外部计算) */
    subjectKeyIdentifier(keyid: Buffer | string, critical: boolean = false): X509ExtBuilderImpl {
      const id = typeof keyid === "string" ? Buffer.from(keyid, "hex") : keyid;
      if (id.length === 0 || id.length > 64) throw jsCipher.Annihilus_(`subjectKeyIdentifier: bad length ${id.length}`);
      return this.add(OID_TEXT.subjectKeyId, { type: V_ASN1.OCTET_STRING, value: id }, critical);
    }

    /** AuthorityKeyIdentifier: SEQUENCE { keyIdentifier [0] IMPLICIT OCTET STRING } */
    authorityKeyIdentifier(keyid: Buffer | string, critical: boolean = false): X509ExtBuilderImpl {
      const id = typeof keyid === "string" ? Buffer.from(keyid, "hex") : keyid;
      if (id.length === 0 || id.length > 64) throw jsCipher.Annihilus_(`authorityKeyIdentifier: bad length ${id.length}`);
      return this.add(OID_TEXT.authorityKeyId,
        { type: 0x30, value: [{ type: 0x80, value: id }] }, critical);
    }

    /** AuthorityInfoAccess(AIA): 目前支持 accessMethod=OCSP/CAIssuers + URI location */
    authorityInfoAccess(
      opts: { ocsp?: string[]; caIssuers?: string[] },
      critical: boolean = false,
    ): X509ExtBuilderImpl {
      const seq: ASN1Value[] = [];
      const pushDesc = (oid: string, urls: string[]) => {
        for (const url of urls)
          seq.push({ type: 0x30, value: [OID(oid), { type: 0x86, value: Buffer.from(url, "utf8") }] });
      };
      pushDesc(OID_TEXT.aiaOcsp, opts.ocsp || []);
      pushDesc(OID_TEXT.aiaCaIssuers, opts.caIssuers || []);
      if (!seq.length) throw jsCipher.Annihilus_(`authorityInfoAccess: empty`);
      return this.add(OID_TEXT.aia, { type: 0x30, value: seq }, critical);
    }

    /** CRLDistributionPoints: DistributionPoint[fullName [0]] 逐 URL */
    crlDistributionPoints(urls: string[], critical: boolean = false): X509ExtBuilderImpl {
      if (!urls.length) throw jsCipher.Annihilus_(`crlDistributionPoints: empty`);
      const points: ASN1Value[] = urls.map((url) => ({
        type: V_ASN1.SEQUENCE,
        value: [{
          type: 0xa0, // distributionPoint [0] EXPLICIT DistributionPointName
          value: [{ type: 0x30, value: [{ type: 0x86, value: Buffer.from(url, "utf8") }] }],
        }],
      }));
      return this.add(OID_TEXT.crlDistributionPoints, { type: 0x30, value: points }, critical);
    }

    /** 全部扩展: SEQUENCE OF Extension(即 X.509 Extensions 的 DER 值) */
    extensionsValue(): ASN1Value {
      return { type: 0x30, value: this.items.map((it) => this.wrap(it)) };
    }
    private wrap(it: { oid: string; critical: boolean; value: ASN1Value }): ASN1Value {
      const seq: ASN1Value[] = [OID(it.oid)];
      if (it.critical) seq.push(true);
      seq.push({ type: V_ASN1.OCTET_STRING, value: ASN1Encode(it.value) });
      return { type: 0x30, value: seq };
    }
    /** 输出 DER(直接供原生 SignRootCA/X509ReqFrom/SignX509 的 extensions 参数) */
    build(): Buffer {
      return ASN1Encode(this.extensionsValue());
    }
  }

  async function CreateEmulator(
    option?: CreateEmulatorOption,
  ): Promise<RockeyEmulator> {
    const kSizeMemory = 128; /// 8MB
    const memory = new WebAssembly.Memory({
      initial: kSizeMemory,
      maximum: kSizeMemory,
    });

    const supperUpdateLEDState = option?.UpdateLEDState;
    const logWrite = option?.LogWriteMessage || default_logWrite;
    const defaultOpensslConfig = Buffer.from(option?.OpensslConfig || "");

    let nextImportBuffer: null | Buffer = null;
    let nextExportBuffer: null | Buffer = null;
    let offsetOpensslConfig = 0;

    const HEAP = Buffer.from(memory.buffer);
    const HEAP16 = new Int16Array(memory.buffer);
    const HEAP32 = new Int32Array(memory.buffer);
    const HEAP64 = new BigInt64Array(memory.buffer);
    const HEAPU16 = new Uint16Array(memory.buffer);
    const HEAPU32 = new Uint32Array(memory.buffer);

    console.assert(
      HEAP.buffer === memory.buffer &&
        HEAP16.buffer === memory.buffer &&
        HEAPU16.buffer === memory.buffer,
    );
    console.assert(
      HEAP32.buffer === memory.buffer &&
        HEAP64.buffer === memory.buffer &&
        HEAPU32.buffer === memory.buffer,
    );

    function jsLogWrite(level: integer, m: Addr, size: integer) {
      const message = HEAP.subarray(m, m + size).toString();
      global_logs.push({
        logWrite,
        level,
        message,
      });
      return 1;
    }

    function jsGetTickCount() {
      return Date.now();
    }

    function RAND_Bytes(buf: Addr, size: integer) {
      jsCipher.RandBytes(HEAP.subarray(buf, buf + size));
    }

    function SetDongleLEDState(thiz: Addr, state: LED_STATE) {
      if (supperUpdateLEDState) supperUpdateLEDState(state);
      return 0;
    }

    function LoadDongleFile(file: Addr, content: Addr) {
      if (
        !nextImportBuffer ||
        nextImportBuffer.length < 8192 ||
        nextImportBuffer.length > 65536
      )
        return -2; /// -ENOENT

      nextImportBuffer.copy(HEAP, content);
      return nextImportBuffer.length;
    }

    function WriteDongleFile(file: Addr, content: Addr, size: integer) {
      nextExportBuffer = Buffer.alloc(size);
      HEAP.copy(nextExportBuffer, 0, content);
      return size;
    }

    function clock_time_get(id: integer, precision: bigint, result: Addr) {
      const now = Date.now();
      HEAP64[result >>> 3] = 1000000n * BigInt(now);
      return 0;
    }

    function fd_close(fd: integer) {
      console.log(`close(${fd})`);
      if (fd === kFileID_Config) {
        offsetOpensslConfig = 0;
      }
      return 0;
    }

    function fd_write(fd: number, iov: Addr, iovcnt: number, pnum: number) {
      if (fd === 1 || fd === 2) {
        // stdout, stderr ...
        let data = [];

        for (let i = 0; i < iovcnt; ++i, iov += 8) {
          const ptr = HEAP32[iov >>> 2];
          const siz = HEAP32[(iov + 4) >>> 2];
          data.push(HEAP.subarray(ptr, ptr + siz));
        }

        const buffer = Buffer.concat(data);
        (fd === 1 ? console.log : console.warn)(
          `fd_write> ${buffer.toString()}`,
        );
        HEAP32[pnum >>> 2] = buffer.length;
        return 0;
      }

      console.log(`TODO: File.Write ${fd}`);
      HEAP32[pnum >>> 2] = 0;
      return -kErrno_EROFS;
    }

    function fd_read(fd: number, iov: Addr, iovcnt: number, pnum: number) {
      let result = 0;

      console.log(`fd_read(${fd})`);
      if (fd === kFileID_null || fd === 0) {
        for (let i = 0; i < iovcnt; ++i, iov += 8) {
          HEAP32[(iov + 4) >>> 2] = 0;
        }
        HEAP32[pnum >>> 2] = 0;
        return 0;
      }

      if (fd === kFileID_Config) {
        let offset = offsetOpensslConfig;
        let request = 0;
        for (let i = 0; i < iovcnt; ++i, iov += 8) {
          const ptr = HEAP32[iov >>> 2];
          const siz = HEAP32[(iov + 4) >>> 2];
          console.log(`  CONF> 0x${ptr.toString(16)} ${siz}`);

          request += siz;
          if (offset >= defaultOpensslConfig.length) {
            HEAP32[(iov + 4) >>> 2] = 0;
          } else {
            const sz = Math.min(siz, defaultOpensslConfig.length - offset);
            defaultOpensslConfig.copy(HEAP, ptr, offset, offset + sz);
            HEAP32[(iov + 4) >>> 2] = sz;
            offset += sz;
            result += sz;
          }
        }
        HEAP32[pnum >>> 2] = result;
        console.log(
          `fd_read ${iovcnt}> ${fd} ${offsetOpensslConfig} / ${defaultOpensslConfig.length} / ${result} / ${request}`,
        );
        offsetOpensslConfig += result;
        return 0;
      }

      if (fd === kFileID_Random) {
        for (let i = 0; i < iovcnt; ++i, iov += 8) {
          const ptr = HEAP32[iov >>> 2];
          const siz = HEAP32[(iov + 4) >>> 2];

          console.log(`  TRNG> 0x${ptr.toString(16)} ${siz}`);

          result += siz;
          jsCipher.RandBytes(HEAP.subarray(ptr, ptr + siz));
        }
        HEAP32[pnum >>> 2] = result;
        console.log(`fd_read ${iovcnt}> ${fd} ${result}`);
        return 0;
      }

      return -kErrno_EACCES;
    }

    function environ_sizes_get(penviron_count: Addr, penviron_buf_size: Addr) {
      console.log(`TODO: environ_sizes_get ...`);
      HEAPU32[penviron_count >>> 2] = 0;
      HEAPU32[penviron_buf_size >>> 2] = 0;
      return 0;
    }

    function environ_get(__environ: Addr, environ_buf: Addr) {
      console.log(`TODO: environ_get ... ${__environ} ${environ_buf}`);
      return 0;
    }

    function fd_seek(fd: number, offset: bigint, whence: number, seek: number) {
      if (fd === kFileID_Random) return 0;
      console.log(`TODO: fd_seek ... ${fd} ${offset} ${whence} ${seek}`);
      return -kErrno_ESPIPE;
    }

    const all_rockey_pkey = new Map<integer, RockeyPKEY>();

    function RockeyPKEY_Sign(
      pkey: integer,
      dgst: Addr,
      dlen: integer,
      sign: Addr,
      signlen: integer,
    ) {
      try {
        return all_rockey_pkey
          .get(pkey)!
          .Sign(
            HEAP.subarray(dgst, dgst + dlen),
            HEAP.subarray(sign, sign + signlen),
          );
      } catch (err) {
        return -2;
      }
    }

    function RockeyPKEY_Decrypt(
      pkey: integer,
      out: Addr,
      outlen: integer,
      in_: Addr,
      inlen: integer,
    ) {
      try {
        return all_rockey_pkey
          .get(pkey)!
          .Decrypt(
            HEAP.subarray(in_, in_ + inlen),
            HEAP.subarray(out, out + outlen),
          );
      } catch (err) {
        return -2;
      }
    }

    const instance = await WebAssembly.instantiate(wasmModule_, {
      rLANG: {
        jsLogWrite,
        jsGetTickCount,

        RAND_Bytes,
        SetDongleLEDState,
        LoadDongleFile,
        WriteDongleFile,

        RockeyPKEY_Sign,
        RockeyPKEY_Decrypt,
      },
      wasi_snapshot_preview1: {
        clock_time_get,
        fd_close,
        fd_write,
        fd_read,
        environ_sizes_get,
        environ_get,
        fd_seek,
      },
      env: { memory },
    });

    const {
      EmuSize,
      EmuNew,
      EmuClear,
      EmuCreate,
      EmuOpen,
      EmuWrite,
      EmuExecv,
      EmuGetDongleInfo,
      EmuGetPINState,
      EmuSetPermission,
      EmuSetLEDState,
      EmuReadShareMemory,
      EmuWriteShareMemory,
      EmuDeleteFile,
      EmuCreateDataFile,
      EmuWriteDataFile,
      EmuReadDataFile,
      EmuCreatePKEYFile,
      EmuGenerateRSA,
      EmuImportRSA,
      EmuGenerateP256,
      EmuImportP256,
      EmuGenerateSM2,
      EmuImportSM2,
      EmuCreateKeyFile,
      EmuWriteKeyFile,
      EmuRSAPrivate,
      EmuRSAPrivateEx,
      EmuRSAPublic,
      EmuP256Sign,
      EmuP256SignEx,
      EmuP256Verify,
      EmuSM2Sign,
      EmuSM2SignEx,
      EmuSM2Verify,
      EmuSM2Decrypt,
      EmuSM2DecryptEx,
      EmuSM2Encrypt,
      EmuSM3,
      EmuSM4ECB,
      EmuSM4ECBEx,
      EmuCheckPointOnCurveSM2,
      EmuDecompressPointSM2,
      EmuCheckPointOnCurvePrime256v1,
      EmuDecompressPointPrime256v1,
      EmuComputePubkeyPrime256v1,
      EmuGenerateKeyPairPrime256v1,
      EmuComputeSecretPrime256v1,
      EmuSignMessagePrime256v1,
      EmuVerifySignPrime256v1,
      EmuCheckPointOnCurveSecp256k1,
      EmuDecompressPointSecp256k1,
      EmuComputePubkeySecp256k1,
      EmuGenerateKeyPairSecp256k1,
      EmuComputeSecretSecp256k1,
      EmuSignMessageSecp256k1,
      EmuVerifySignSecp256k1,
      RockeyPKEY_Clear,
      RockeyPKEY_CreateRSA,
      RockeyPKEY_CreateP256,
      RockeyPKEY_CreateSM2,
      RockeyPKEY_SignEx,
      RockeyPKEY_DecryptEx,
      Initialize,
      RANDSeedBytes,
      MemoryManager,
      _initialize,
      _emscripten_stack_restore,
      _emscripten_stack_alloc,
      emscripten_stack_get_current,
    } = <Native0_>(<unknown>instance.exports);

    _initialize();
    Initialize();

    let instanceDongle = 0;
    const memoryDongle = MemoryManager(0, EmuSize());
    console.assert(0 !== memoryDongle);

    function CheckInstance() {
      if (!instanceDongle) throw jsCipher.Annihilus_(`NULL`);
      console.assert(instanceDongle === memoryDongle);
      return instanceDongle;
    }

    function CloneBuffer(off: integer, size: integer) {
      const result = Buffer.alloc(size);
      HEAP.copy(result, 0, off);
      return result;
    }

    function MoveBuffer(off: integer, size: integer) {
      const result = Buffer.alloc(size);
      HEAP.copy(result, 0, off);
      HEAP.fill(0, off, off + size);
      return result;
    }

    class DongleEmulator implements RockeyEmulator {
      RANDSeedBytes(v: any) {
        if (!(v instanceof Buffer)) v = Buffer.from(String(v));
        v = jsCipher.Digest("SHA256").Init().Update(v).Final();

        jsCipher.SeedBytes(v);
        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(32);
        v.copy(HEAP, frame);
        RANDSeedBytes(frame, 32);
        _emscripten_stack_restore(stack);
      }

      Export(): Buffer {
        const size = EmuWrite(CheckInstance());
        if (size !== nextExportBuffer?.length)
          throw jsCipher.Annihilus_(`Export Error ${size}`);
        const result = nextExportBuffer;
        nextExportBuffer = null;
        return result;
      }

      Create(secret: string | Buffer, uid: integer, loop: integer = 256): void {
        if (instanceDongle) {
          EmuClear(instanceDongle);
          instanceDongle = 0;
        }

        instanceDongle = EmuNew(memoryDongle, PERMISSION.kAdministrator);
        console.assert(instanceDongle === memoryDongle);

        if (typeof secret === "string") secret = Buffer.from(secret);

        const stack = emscripten_stack_get_current();
        const master_secret = _emscripten_stack_alloc(64);
        jsCipher
          .Digest("SHA512")
          .Init()
          .Update(secret)
          .Final()
          .copy(HEAP, master_secret);
        const result = EmuCreate(instanceDongle, master_secret, uid, loop);
        HEAP.fill(0, master_secret, master_secret + 64);
        _emscripten_stack_restore(stack);
        if (result < 0)
          throw jsCipher.Annihilus_(`dongle.Create Error ${result}`);
      }

      Open(
        perm: PERMISSION,
        storage: Buffer,
        secret: string | Buffer,
        loop: integer = 256,
      ): void {
        if (instanceDongle) {
          EmuClear(instanceDongle);
          instanceDongle = 0;
        }

        instanceDongle = EmuNew(memoryDongle, perm);
        console.assert(instanceDongle === memoryDongle);

        if (typeof secret === "string") secret = Buffer.from(secret);

        nextImportBuffer = storage;
        const stack = emscripten_stack_get_current();
        const master_secret = _emscripten_stack_alloc(64);
        jsCipher
          .Digest("SHA512")
          .Init()
          .Update(secret)
          .Final()
          .copy(HEAP, master_secret);
        const result = EmuOpen(instanceDongle, master_secret, loop);
        HEAP.fill(0, master_secret, master_secret + 64);
        _emscripten_stack_restore(stack);
        nextImportBuffer = null;

        if (result < 0)
          throw jsCipher.Annihilus_(`dongle.Open Error ${result}`);
      }

      Execv(InOutBuffer: Buffer): void {
        if (InOutBuffer.length !== 1024)
          throw jsCipher.Annihilus_(
            `dongle.Execv InOutBuffer.length ${InOutBuffer.length} !== 1024`,
          );

        const thiz = CheckInstance();
        const stack = emscripten_stack_get_current();
        const buffer = _emscripten_stack_alloc(1024);
        InOutBuffer.copy(HEAP, buffer);
        const result = EmuExecv(thiz, buffer);
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(`dongle.Execv Error ${result}`);

        HEAP.copy(InOutBuffer, 0, buffer);
        HEAP.fill(0, buffer, buffer + 1024);
      }

      GetDongleInfo(): Buffer {
        const thiz = CheckInstance();

        const stack = emscripten_stack_get_current();
        const buffer = _emscripten_stack_alloc(64);
        const result = EmuGetDongleInfo(thiz, buffer);
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(`dongle.GetDongleInfo Error ${result}`);
        return MoveBuffer(buffer, 40);
      }
      GetPINState(): PERMISSION {
        const thiz = CheckInstance();

        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(16);
        const result = EmuGetPINState(thiz, frame);
        _emscripten_stack_restore(stack);

        if (0 === result) return <PERMISSION>HEAP[frame];
        else throw jsCipher.Annihilus_(`dongle.GetPINState Error ${result}`);
      }

      SetLEDState(state: LED_STATE): void {
        const thiz = CheckInstance();
        const result = EmuSetLEDState(thiz, state);
        if (0 !== result)
          throw jsCipher.Annihilus_(`dongle.SetLEDState Error ${result}`);
      }

      SetPermission(perm: PERMISSION): void {
        const thiz = CheckInstance();
        const result = EmuSetPermission(thiz, <integer>perm);
        if (0 !== result)
          throw jsCipher.Annihilus_(`dongle.SetPermission Error ${result}`);
      }

      ReadShareMemory(): Buffer {
        const thiz = CheckInstance();

        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(32);
        const result = EmuReadShareMemory(thiz, frame);
        _emscripten_stack_restore(stack);

        if (0 === result) return MoveBuffer(frame, 32);
        else
          throw jsCipher.Annihilus_(`dongle.ReadShareMemory Error ${result}`);
      }

      WriteShareMemory(buffer: Buffer): void {
        if (buffer.length !== 32)
          throw jsCipher.Annihilus_(
            `dongle.WriteShareMemory Buffer.size ${buffer.length} !== 32`,
          );

        const thiz = CheckInstance();

        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(32);
        buffer.copy(HEAP, frame);
        const result = EmuWriteShareMemory(thiz, frame);
        HEAP.fill(0, frame, frame + 32);
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(`dongle.WriteShareMemory Error ${result}`);
      }

      DeleteFile(type: SECRET_STORAGE_TYPE, id: integer): boolean {
        const thiz = CheckInstance();
        const result = EmuDeleteFile(thiz, type, id);
        return 0 === result;
      }

      CreateDataFile(id: integer, size: integer): void {
        const thiz = CheckInstance();
        const result = EmuCreateDataFile(thiz, id, size);
        if (0 !== result)
          throw jsCipher.Annihilus_(
            `dongle.CreateDataFile ${id} Error ${result}`,
          );
      }

      WriteDataFile(id: integer, off: integer, buffer: Buffer): void {
        if (buffer.length < 1) return;

        if (buffer.length > 8192)
          throw jsCipher.Annihilus_(
            `dongle.WriteDataFile ${id} Size.Over ${buffer.length}`,
          );

        const thiz = CheckInstance();
        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(8192);
        buffer.copy(HEAP, frame);
        const result = EmuWriteDataFile(thiz, id, off, frame, buffer.length);
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(
            `dongle.WriteDataFile ${id} Error ${result}`,
          );
      }
      ReadDataFile(id: integer, off: integer, size: integer): Buffer {
        const thiz = CheckInstance();
        if (size < 1) return Buffer.alloc(0);
        if (size > 8192)
          throw jsCipher.Annihilus_(
            `dongle.ReadDataFile ${id} Size.Over ${size}`,
          );
        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(8192);
        const result = EmuReadDataFile(thiz, id, off, frame, size);
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(
            `dongle.ReadDataFile ${id} Error ${result}`,
          );
        else return MoveBuffer(frame, size);
      }

      CreatePKEYFile(
        type: SECRET_STORAGE_TYPE,
        bits: integer,
        id: integer,
      ): void {
        const thiz = CheckInstance();
        const result = EmuCreatePKEYFile(thiz, type, bits, id);
        if (0 !== result)
          throw jsCipher.Annihilus_(
            `dongle.WritePKEYFile ${id}/${type} Error ${result}`,
          );
      }

      GenerateRSA(id: integer, export_private: boolean): Buffer {
        /// [ modulus.LE[4], exponent[256] ] || [ modulus.LE[4], exponent[256], private_key[256] ]
        const thiz = CheckInstance();

        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(1024);
        const result = EmuGenerateRSA(
          thiz,
          id,
          frame,
          frame + 4,
          export_private ? frame + 260 : 0,
        );
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(`dongle.GenerateRSA ${id} Error ${result}`);
        else return MoveBuffer(frame, export_private ? 512 + 4 : 256 + 4);
      }
      ImportRSA(id: integer, pkey: Buffer): void {
        if (pkey.length !== 512 + 4)
          throw jsCipher.Annihilus_(
            `dongle.ImportRSA ${id} Size ${pkey.length} !== ${512 + 4}`,
          );

        const thiz = CheckInstance();
        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(1024);
        pkey.copy(HEAP, frame);
        const result = EmuImportRSA(
          thiz,
          id,
          HEAPU32[frame >>> 2],
          frame + 4,
          frame + 260,
        );
        HEAP.fill(0, frame, frame + 1024);
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(`dongle.ImportRSA ${id} Error ${result}`);
      }

      GenerateP256(id: integer, export_private: boolean): Buffer {
        /// [ X[32], Y[32] ] || [ X[32], Y[32], K[32] ]
        const thiz = CheckInstance();

        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(128);
        const result = EmuGenerateP256(
          thiz,
          id,
          frame,
          frame + 32,
          export_private ? frame + 64 : 0,
        );
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(
            `dongle.GenerateP256 ${id} Error ${result}`,
          );
        else return MoveBuffer(frame, export_private ? 96 : 64);
      }
      ImportP256(id: integer, private_key: Buffer): void {
        /// private_key : Buffer[32] || Buffer[96]

        if (private_key.length === 96) private_key = private_key.subarray(64);

        if (private_key.length !== 32)
          throw jsCipher.Annihilus_(
            `dongle.ImportP256 ${id} Size ${private_key.length} !== 32`,
          );

        const thiz = CheckInstance();
        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(128);
        private_key.copy(HEAP, frame);
        const result = EmuImportP256(thiz, id, frame);
        HEAP.fill(0, frame, frame + 32);
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(`dongle.ImportP256 ${id} Error ${result}`);
      }

      GenerateSM2(id: integer, export_private: boolean): Buffer {
        const thiz = CheckInstance();

        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(128);
        const result = EmuGenerateSM2(
          thiz,
          id,
          frame,
          frame + 32,
          export_private ? frame + 64 : 0,
        );
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(
            `dongle.EmuGenerateSM2 ${id} Error ${result}`,
          );
        else return MoveBuffer(frame, export_private ? 96 : 64);
      }

      ImportSM2(id: integer, private_key: Buffer): void {
        if (private_key.length === 96) private_key = private_key.subarray(64);

        if (private_key.length !== 32)
          throw jsCipher.Annihilus_(
            `dongle.ImportSM2 ${id} Size ${private_key.length} !== 32`,
          );

        const thiz = CheckInstance();
        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(128);
        private_key.copy(HEAP, frame);
        const result = EmuImportSM2(thiz, id, frame);
        HEAP.fill(0, frame, frame + 32);
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(`dongle.ImportSM2 ${id} Error ${result}`);
      }

      CreateKeyFile(id: integer, type: SECRET_STORAGE_TYPE): void {
        if (type !== SECRET_STORAGE_TYPE.kTDES || SECRET_STORAGE_TYPE.kSM4)
          throw jsCipher.Annihilus_(
            `dongle.CreateKeyFile ${id} invalid type ${type}`,
          );

        const thiz = CheckInstance();
        const result = EmuCreateKeyFile(thiz, id, type);
        if (0 !== result)
          throw jsCipher.Annihilus_(
            `dongle.CreateKeyFile ${id}/${type} Error ${result}`,
          );
      }

      WriteKeyFile(id: integer, type: SECRET_STORAGE_TYPE, key: Buffer): void {
        if (type !== SECRET_STORAGE_TYPE.kTDES || SECRET_STORAGE_TYPE.kSM4)
          throw jsCipher.Annihilus_(
            `dongle.WriteKeyFile ${id} invalid type ${type}`,
          );

        if (key.length !== 16)
          throw jsCipher.Annihilus_(
            `dongle.WriteKeyFile ${id}/${type} invalid size ${key.length}`,
          );

        const thiz = CheckInstance();
        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(128);
        key.copy(HEAP, frame);
        const result = EmuWriteKeyFile(thiz, id, frame, 16, type);
        HEAP.fill(0, frame, frame + 32);
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(
            `dongle.WriteKeyFile ${id}/${type} Error ${result}`,
          );
      }

      RSAPrivate(
        key: integer | Buffer,
        input: Buffer,
        encrypt: boolean,
      ): Buffer {
        const thiz = CheckInstance();

        if (encrypt) {
          if (input.length < 1 || input.length > 256 - 11)
            throw jsCipher.Annihilus_(
              `dongle.RSAPrivate.enc invalid input size ${input.length}`,
            );
        } else {
          if (input.length !== 256)
            throw jsCipher.Annihilus_(
              `dongle.RSAPrivate.dec invalid input size ${input.length}`,
            );
        }

        if (key instanceof Buffer && key.length !== 512 + 4)
          throw jsCipher.Annihilus_(
            `dongle.RSAPrivate invalid pkey size ${key.length}`,
          );

        let result: integer;
        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(2048);
        const addr_buffer = frame + 256;

        input.copy(HEAP, frame);
        HEAP32[addr_buffer >>> 2] = input.length;

        if (typeof key === "number") {
          result = EmuRSAPrivate(thiz, key, frame, addr_buffer, encrypt);
        } else {
          const addr_pkey = frame + 512;
          key.copy(HEAP, addr_pkey);
          result = EmuRSAPrivateEx(
            thiz,
            2048,
            HEAPU32[addr_pkey >>> 2],
            addr_pkey + 4,
            addr_pkey + 260,
            frame,
            addr_buffer,
            encrypt,
          );
          HEAP.fill(0, addr_pkey, addr_pkey + 520);
        }
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(
            `dongle.RSAPrivate.${encrypt ? "enc" : "dec"} Error ${result}`,
          );
        else return MoveBuffer(frame, HEAP32[addr_buffer >>> 2]);
      }

      RSAPublic(
        modulus: integer,
        exponent: Buffer,
        input: Buffer,
        encrypt: boolean,
      ): Buffer {
        const thiz = CheckInstance();

        if (encrypt) {
          if (input.length < 1 || input.length > 256 - 11)
            throw jsCipher.Annihilus_(
              `dongle.RSAPublic.enc invalid input size ${input.length}`,
            );
        } else {
          if (input.length !== 256)
            throw jsCipher.Annihilus_(
              `dongle.RSAPublic.dec invalid input size ${input.length}`,
            );
        }

        if (exponent.length !== 256)
          throw jsCipher.Annihilus_(
            `dongle.RSAPublic invalid pkey.size ${exponent.length}`,
          );

        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(2048);
        const addr_buffer = frame + 256;
        const addr_pkey = frame + 512;

        input.copy(HEAP, frame);
        exponent.copy(HEAP, addr_pkey);
        HEAP32[addr_buffer >>> 2] = input.length;
        const result = EmuRSAPublic(
          thiz,
          2048,
          modulus,
          addr_pkey,
          frame,
          addr_buffer,
          encrypt,
        );
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(
            `dongle.RSAPublic.${encrypt ? "enc" : "dec"} Error ${result}`,
          );
        else return MoveBuffer(frame, HEAP32[addr_buffer >>> 2]);
      }

      P256Sign(key: integer | Buffer, hash: Buffer): Buffer {
        const thiz = CheckInstance();

        if (hash.length !== 32)
          throw jsCipher.Annihilus_(
            `dongle.P256Sign invalid hash size ${hash.length}`,
          );

        if (key instanceof Buffer) {
          if (key.length === 96) key = key.subarray(64);
          else if (key.length !== 32)
            throw jsCipher.Annihilus_(
              `dongle.P256Sign invalid pkey size ${key.length}`,
            );
        }

        let result: integer;
        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(256);
        hash.copy(HEAP, frame);

        if (typeof key === "number") {
          result = EmuP256Sign(thiz, key, frame, frame + 32, frame + 64);
        } else {
          const addr_key = frame + 128;
          key.copy(HEAP, addr_key);
          result = EmuP256SignEx(thiz, addr_key, frame, frame + 32, frame + 64);
          HEAP.fill(0, addr_key, addr_key + 32);
        }
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(`dongle.P256Sign Error ${result}`);
        else return CloneBuffer(frame + 32, 64);
      }

      P256Verify(point: Buffer, hash: Buffer, sign: Buffer): boolean {
        const thiz = CheckInstance();

        if (point.length !== 64 || hash.length !== 32 || sign.length !== 64)
          throw jsCipher.Annihilus_(
            `dongle.P256Verify EINVAL ${point.length}/${hash.length}/${sign.length}`,
          );

        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(256);
        point.copy(HEAP, frame);
        hash.copy(HEAP, frame + 64);
        sign.copy(HEAP, frame + 128);
        const result = EmuP256Verify(
          thiz,
          frame,
          frame + 32,
          frame + 64,
          frame + 128,
          frame + 160,
        );
        _emscripten_stack_restore(stack);

        if (result < -1)
          throw jsCipher.Annihilus_(`dongle.P256Verify Error ${result}`);
        return result === 0;
      }

      SM2Sign(key: integer | Buffer, hash: Buffer): Buffer {
        const thiz = CheckInstance();

        if (hash.length !== 32)
          throw jsCipher.Annihilus_(
            `dongle.SM2Sign invalid hash size ${hash.length}`,
          );

        if (key instanceof Buffer) {
          if (key.length === 96) key = key.subarray(64);
          else if (key.length !== 32)
            throw jsCipher.Annihilus_(
              `dongle.SM2Sign invalid pkey size ${key.length}`,
            );
        }

        let result: integer;
        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(256);
        hash.copy(HEAP, frame);

        if (typeof key === "number") {
          result = EmuSM2Sign(thiz, key, frame, frame + 32, frame + 64);
        } else {
          const addr_key = frame + 128;
          key.copy(HEAP, addr_key);
          result = EmuSM2SignEx(thiz, addr_key, frame, frame + 32, frame + 64);
          HEAP.fill(0, addr_key, addr_key + 32);
        }
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(`dongle.SM2Sign Error ${result}`);
        else return CloneBuffer(frame + 32, 64);
      }

      SM2Verify(point: Buffer, hash: Buffer, sign: Buffer): boolean {
        const thiz = CheckInstance();

        if (point.length !== 64 || hash.length !== 32 || sign.length !== 64)
          throw jsCipher.Annihilus_(
            `dongle.SM2Verify EINVAL ${point.length}/${hash.length}/${sign.length}`,
          );

        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(256);
        point.copy(HEAP, frame);
        hash.copy(HEAP, frame + 64);
        sign.copy(HEAP, frame + 128);
        const result = EmuSM2Verify(
          thiz,
          frame,
          frame + 32,
          frame + 64,
          frame + 128,
          frame + 160,
        );
        _emscripten_stack_restore(stack);

        if (result < -1)
          throw jsCipher.Annihilus_(`dongle.SM2Verify Error ${result}`);
        return result === 0;
      }

      SM2Decrypt(key: integer | Buffer, cipher: Buffer): Buffer {
        const thiz = CheckInstance();

        if (key instanceof Buffer) {
          if (key.length === 96) key = key.subarray(64);
          else if (key.length !== 32)
            throw jsCipher.Annihilus_(
              `dongle.SM2Decrypt invalid pkey size ${key.length}`,
            );
        }

        if (cipher.length <= 96 || cipher.length > 1024 + 96)
          /// text.size .LE. 1024
          throw jsCipher.Annihilus_(
            `dongle.SM2Decrypt invalid cipher size ${cipher.length}`,
          );

        let result: number;
        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(4096 + 256);
        const addr_cipher = frame + 3072;
        const addr_text = frame + 2048;
        const addr_size = frame + 2000;
        const size_verify = cipher.length - 96; /// 96: X[32], Y[32], H[32] ...
        HEAPU32[addr_size >>> 2] = cipher.length;
        cipher.copy(HEAP, addr_cipher);

        if (typeof key === "number") {
          result = EmuSM2Decrypt(
            thiz,
            key,
            addr_cipher,
            cipher.length,
            addr_text,
            addr_size,
          );
        } else {
          key.copy(HEAP, frame);
          result = EmuSM2DecryptEx(
            thiz,
            frame,
            addr_cipher,
            cipher.length,
            addr_text,
            addr_size,
          );
          HEAP.fill(0, frame, frame + 32);
        }
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(`dongle.SM2Decrypt Error ${result}`);

        console.assert(HEAPU32[addr_size >>> 2] === size_verify);
        return MoveBuffer(addr_text, size_verify);
      }
      SM2Encrypt(point: Buffer, plain: Buffer): Buffer {
        const thiz = CheckInstance();

        if (point.length !== 64)
          throw jsCipher.Annihilus_(
            `dongle.SM2Encrypt invalid point size ${point.length}`,
          );

        if (plain.length < 1 || plain.length > 1024)
          throw jsCipher.Annihilus_(
            `dongle.SM2Encrypt invalid message size ${plain.length}`,
          );

        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(4096);
        const addr_text = frame + 1024;
        const addr_cipher = frame + 2048;

        point.copy(HEAP, frame);
        plain.copy(HEAP, addr_text);
        const result = EmuSM2Encrypt(
          thiz,
          frame,
          frame + 32,
          addr_text,
          plain.length,
          addr_cipher,
        );
        HEAP.fill(0, addr_text, plain.length);
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(`dongle.SM2Encrypt Error ${result}`);
        else return MoveBuffer(addr_cipher, plain.length + 96);
      }

      SM3(message: Buffer): Buffer {
        const thiz = CheckInstance();
        const size = message.length;

        if (size < 1 || size > 1024)
          throw jsCipher.Annihilus_(`dongle.SM3 invalid message size ${size}`);

        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(1024 + 32);
        message.copy(HEAP, frame);

        const addr_md = frame + 1024;
        const result = EmuSM3(thiz, frame, size, addr_md);
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(`dongle.SM3 Error ${result}`);
        else return MoveBuffer(addr_md, 32);
      }
      SM4ECB(key: integer | Buffer, input: Buffer, encrypt: boolean): Buffer {
        const thiz = CheckInstance();
        const size = input.length;

        if (key instanceof Buffer && key.length !== 16)
          throw jsCipher.Annihilus_(
            `dongle.SM4ECB invalid key size ${key.length}`,
          );

        if (size < 16 || size > 1024 || size % 16 !== 0)
          throw jsCipher.Annihilus_(
            `dongle.SM4ECB invalid message size ${size}`,
          );

        let result: number;
        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(2048);
        input.copy(HEAP, frame);

        if (typeof key === "number") {
          result = EmuSM4ECB(thiz, key, frame, size, encrypt);
        } else {
          const addr_key = frame + 1024;
          key.copy(HEAP, addr_key);
          result = EmuSM4ECBEx(thiz, addr_key, frame, size, encrypt);
          HEAP.fill(0, addr_key, addr_key + 16);
        }
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(`dongle.SM4ECB Error ${result}`);
        else return MoveBuffer(frame, size);
      }

      CheckPointOnCurveSM2(point: Buffer): boolean {
        const thiz = CheckInstance();
        if (point.length !== 64)
          throw jsCipher.Annihilus_(
            `dongle.CheckPointOnCurveSM2 invalid point size ${point.length}`,
          );
        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(64);
        point.copy(HEAP, frame);
        const result = EmuCheckPointOnCurveSM2(thiz, frame, frame + 32);
        _emscripten_stack_restore(stack);

        return 0 === result;
      }

      EmuDecompressPointSM2(X: Buffer, Yodd: boolean): Buffer {
        const thiz = CheckInstance();
        if (X.length !== 32)
          throw jsCipher.Annihilus_(
            `dongle.EmuDecompressPointSM2 invalid X size ${X.length}`,
          );

        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(64);
        X.copy(HEAP, frame + 32);
        const result = EmuDecompressPointSM2(thiz, frame, frame + 32, Yodd);
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(
            `dongle.EmuDecompressPointSM2 Error ${result}`,
          );
        else return CloneBuffer(frame, 32);
      }

      CheckPointOnCurvePrime256v1(point: Buffer): boolean {
        const thiz = CheckInstance();
        if (point.length !== 64)
          throw jsCipher.Annihilus_(
            `dongle.CheckPointOnCurvePrime256v1 invalid point size ${point.length}`,
          );
        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(64);
        point.copy(HEAP, frame);
        const result = EmuCheckPointOnCurvePrime256v1(thiz, frame, frame + 32);
        _emscripten_stack_restore(stack);

        return 0 === result;
      }

      DecompressPointPrime256v1(X: Buffer, Yodd: boolean): Buffer {
        const thiz = CheckInstance();
        if (X.length !== 32)
          throw jsCipher.Annihilus_(
            `dongle.DecompressPointPrime256v1 invalid X size ${X.length}`,
          );

        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(64);
        X.copy(HEAP, frame + 32);
        const result = EmuDecompressPointPrime256v1(
          thiz,
          frame,
          frame + 32,
          Yodd,
        );
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(
            `dongle.DecompressPointPrime256v1 Error ${result}`,
          );
        else return CloneBuffer(frame, 32);
      }

      ComputePubkeyPrime256v1(privateKey: Buffer): Buffer {
        const thiz = CheckInstance();
        if (privateKey.length === 96) privateKey = privateKey.subarray(64);
        else if (privateKey.length !== 32)
          throw jsCipher.Annihilus_(
            `dongle.ComputePubkeyPrime256v1 invalid pkey.size ${privateKey.length}`,
          );

        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(128);
        privateKey.copy(HEAP, frame + 64);
        const result = EmuComputePubkeyPrime256v1(
          thiz,
          frame,
          frame + 32,
          frame + 64,
        );
        HEAP.fill(0, frame + 64, frame + 96);
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(
            `dongle.ComputePubkeyPrime256v1 Error ${result}`,
          );
        else return MoveBuffer(frame, 64);
      }

      GenerateKeyPairPrime256v1(): Buffer {
        const thiz = CheckInstance();
        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(128);
        const result = EmuGenerateKeyPairPrime256v1(
          thiz,
          frame,
          frame + 32,
          frame + 64,
        );
        _emscripten_stack_restore(stack);
        if (0 !== result)
          throw jsCipher.Annihilus_(
            `dongle.GenerateKeyPairPrime256v1 Error ${result}`,
          );
        else return MoveBuffer(frame, 96);
      }

      ComputeSecretPrime256v1(point: Buffer, privateKey: Buffer): Buffer {
        const thiz = CheckInstance();

        if (point.length !== 64)
          throw jsCipher.Annihilus_(
            `dongle.ComputeSecretPrime256v1 invalid point.size ${point.length}`,
          );

        if (privateKey.length === 96) privateKey = privateKey.subarray(64);
        else if (privateKey.length !== 32)
          throw jsCipher.Annihilus_(
            `dongle.ComputeSecretPrime256v1 invalid pkey.size ${privateKey.length}`,
          );

        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(128);
        privateKey.copy(HEAP, frame + 32);
        point.copy(HEAP, frame + 64);
        const result = EmuComputeSecretPrime256v1(
          thiz,
          frame,
          frame + 64,
          frame + 96,
          frame + 32,
        );
        HEAP.fill(0, frame + 32, frame + 64);
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(
            `dongle.ComputeSecretPrime256v1 Error ${result}`,
          );
        else return MoveBuffer(frame, 32);
      }

      SignMessagePrime256v1(hash: Buffer, privateKey: Buffer): Buffer {
        const thiz = CheckInstance();
        if (hash.length !== 32)
          throw jsCipher.Annihilus_(
            `dongle.SignMessagePrime256v1 invalid hash.size ${hash.length}`,
          );
        if (privateKey.length === 96) privateKey = privateKey.subarray(64);
        else if (privateKey.length !== 32)
          throw jsCipher.Annihilus_(
            `dongle.SignMessagePrime256v1 invalid pkey.size ${privateKey.length}`,
          );

        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(128);
        privateKey.copy(HEAP, frame + 64);
        hash.copy(HEAP, frame + 96);
        const result = EmuSignMessagePrime256v1(
          thiz,
          frame + 64,
          frame + 96,
          frame,
          frame + 32,
        );
        HEAP.fill(0, frame + 64, frame + 96);
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(
            `dongle.SignMessagePrime256v1 Error ${result}`,
          );
        else return MoveBuffer(frame, 64);
      }

      VerifySignPrime256v1(point: Buffer, hash: Buffer, sign: Buffer): boolean {
        const thiz = CheckInstance();
        if (point.length !== 64)
          throw jsCipher.Annihilus_(
            `dongle.VerifySignPrime256v1 invalid point.size ${point.length}`,
          );
        if (hash.length !== 32)
          throw jsCipher.Annihilus_(
            `dongle.VerifySignPrime256v1 invalid hash.size ${hash.length}`,
          );
        if (sign.length !== 64)
          throw jsCipher.Annihilus_(
            `dongle.VerifySignPrime256v1 invalid sign.size ${sign.length}`,
          );
        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(256);
        point.copy(HEAP, frame);
        hash.copy(HEAP, frame + 64);
        sign.copy(HEAP, frame + 128);
        const result = EmuVerifySignPrime256v1(
          thiz,
          frame,
          frame + 32,
          frame + 64,
          frame + 128,
          frame + 160,
        );
        _emscripten_stack_restore(stack);

        return 0 === result;
      }

      CheckPointOnCurveSecp256k1(point: Buffer): boolean {
        const thiz = CheckInstance();
        if (point.length !== 64)
          throw jsCipher.Annihilus_(
            `dongle.CheckPointOnCurveSecp256k1 invalid point size ${point.length}`,
          );
        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(64);
        point.copy(HEAP, frame);
        const result = EmuCheckPointOnCurveSecp256k1(thiz, frame, frame + 32);
        _emscripten_stack_restore(stack);

        return 0 === result;
      }

      DecompressPointSecp256k1(X: Buffer, Yodd: boolean): Buffer {
        const thiz = CheckInstance();
        if (X.length !== 32)
          throw jsCipher.Annihilus_(
            `dongle.DecompressPointSecp256k1 invalid X size ${X.length}`,
          );

        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(64);
        X.copy(HEAP, frame + 32);
        const result = EmuDecompressPointSecp256k1(
          thiz,
          frame,
          frame + 32,
          Yodd,
        );
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(
            `dongle.DecompressPointSecp256k1 Error ${result}`,
          );
        else return CloneBuffer(frame, 32);
      }

      ComputePubkeySecp256k1(privateKey: Buffer): Buffer {
        const thiz = CheckInstance();
        if (privateKey.length === 96) privateKey = privateKey.subarray(64);
        else if (privateKey.length !== 32)
          throw jsCipher.Annihilus_(
            `dongle.ComputePubkeySecp256k1 invalid pkey.size ${privateKey.length}`,
          );

        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(128);
        privateKey.copy(HEAP, frame + 64);
        const result = EmuComputePubkeySecp256k1(
          thiz,
          frame,
          frame + 32,
          frame + 64,
        );
        HEAP.fill(0, frame + 64, frame + 96);
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(
            `dongle.ComputePubkeySecp256k1 Error ${result}`,
          );
        else return MoveBuffer(frame, 64);
      }

      GenerateKeyPairSecp256k1(): Buffer {
        const thiz = CheckInstance();
        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(128);
        const result = EmuGenerateKeyPairSecp256k1(
          thiz,
          frame,
          frame + 32,
          frame + 64,
        );
        _emscripten_stack_restore(stack);
        if (0 !== result)
          throw jsCipher.Annihilus_(
            `dongle.GenerateKeyPairSecp256k1 Error ${result}`,
          );
        else return MoveBuffer(frame, 96);
      }

      ComputeSecretSecp256k1(point: Buffer, privateKey: Buffer): Buffer {
        const thiz = CheckInstance();

        if (point.length !== 64)
          throw jsCipher.Annihilus_(
            `dongle.ComputeSecretSecp256k1 invalid point.size ${point.length}`,
          );

        if (privateKey.length === 96) privateKey = privateKey.subarray(64);
        else if (privateKey.length !== 32)
          throw jsCipher.Annihilus_(
            `dongle.ComputeSecretSecp256k1 invalid pkey.size ${privateKey.length}`,
          );

        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(128);
        privateKey.copy(HEAP, frame + 32);
        point.copy(HEAP, frame + 64);
        const result = EmuComputeSecretSecp256k1(
          thiz,
          frame,
          frame + 64,
          frame + 96,
          frame + 32,
        );
        HEAP.fill(0, frame + 32, frame + 64);
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(
            `dongle.ComputeSecretSecp256k1 Error ${result}`,
          );
        else return MoveBuffer(frame, 32);
      }

      SignMessageSecp256k1(hash: Buffer, privateKey: Buffer): Buffer {
        const thiz = CheckInstance();
        if (hash.length !== 32)
          throw jsCipher.Annihilus_(
            `dongle.SignMessageSecp256k1 invalid hash.size ${hash.length}`,
          );
        if (privateKey.length === 96) privateKey = privateKey.subarray(64);
        else if (privateKey.length !== 32)
          throw jsCipher.Annihilus_(
            `dongle.SignMessageSecp256k1 invalid pkey.size ${privateKey.length}`,
          );

        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(128);
        privateKey.copy(HEAP, frame + 64);
        hash.copy(HEAP, frame + 96);
        const result = EmuSignMessageSecp256k1(
          thiz,
          frame + 64,
          frame + 96,
          frame,
          frame + 32,
        );
        HEAP.fill(0, frame + 64, frame + 96);
        _emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(
            `dongle.SignMessageSecp256k1 Error ${result}`,
          );
        else return MoveBuffer(frame, 64);
      }

      VerifySignSecp256k1(point: Buffer, hash: Buffer, sign: Buffer): boolean {
        const thiz = CheckInstance();
        if (point.length !== 64)
          throw jsCipher.Annihilus_(
            `dongle.VerifySignSecp256k1 invalid point.size ${point.length}`,
          );
        if (hash.length !== 32)
          throw jsCipher.Annihilus_(
            `dongle.VerifySignSecp256k1 invalid hash.size ${hash.length}`,
          );
        if (sign.length !== 64)
          throw jsCipher.Annihilus_(
            `dongle.VerifySignSecp256k1 invalid sign.size ${sign.length}`,
          );
        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(256);
        point.copy(HEAP, frame);
        hash.copy(HEAP, frame + 64);
        sign.copy(HEAP, frame + 128);
        const result = EmuVerifySignSecp256k1(
          thiz,
          frame,
          frame + 32,
          frame + 64,
          frame + 128,
          frame + 160,
        );
        _emscripten_stack_restore(stack);

        return 0 === result;
      }

      RockeyClear(pkey: integer): integer {
        if (pkey != (pkey | 0) || pkey < 0 || pkey > 0xffff)
          throw jsCipher.Annihilus_(`Invalid pkey: ${pkey}`);
        all_rockey_pkey.delete(pkey);
        return RockeyPKEY_Clear(pkey);
      }

      RockeyCreateRSA(
        pkey: integer,
        provider: RockeyPKEY,
        E: integer,
        N: Buffer,
      ): integer {
        if (pkey != (pkey | 0) || pkey < 0 || pkey > 0xffff)
          throw jsCipher.Annihilus_(`Invalid pkey: ${pkey}`);
        if (N.length < 256 || N.length > 2048)
          throw jsCipher.Annihilus_(`Invalid N length: ${N.length}`);

        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(4096);
        N.copy(HEAP, frame);
        const result = RockeyPKEY_CreateRSA(pkey, E, frame, N.length);
        _emscripten_stack_restore(stack);

        if (result < 0)
          throw jsCipher.Annihilus_(`RockeyPKEY_CreateRSA failed: ${result}`);
        all_rockey_pkey.set(pkey, provider);
        return 0;
      }

      RockeyCreateP256(
        pkey: integer,
        provider: RockeyPKEY,
        point: Buffer,
      ): integer {
        if (pkey != (pkey | 0) || pkey < 0 || pkey > 0xffff)
          throw jsCipher.Annihilus_(`Invalid pkey: ${pkey}`);

        if (point.length != 64)
          throw jsCipher.Annihilus_(
            `Invalid P256.point length: ${point.length}`,
          );

        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(256);
        point.copy(HEAP, frame);
        const result = RockeyPKEY_CreateP256(pkey, frame, frame + 32);
        _emscripten_stack_restore(stack);

        if (result < 0)
          throw jsCipher.Annihilus_(`Invalid RockeyCreateP256: ${result}`);
        all_rockey_pkey.set(pkey, provider);
        return 0;
      }

      RockeyCreateSM2(
        pkey: integer,
        provider: RockeyPKEY,
        point: Buffer,
      ): integer {
        if (pkey != (pkey | 0) || pkey < 0 || pkey > 0xffff)
          throw jsCipher.Annihilus_(`Invalid pkey: ${pkey}`);

        if (point.length != 64)
          throw jsCipher.Annihilus_(
            `Invalid SM2.point length: ${point.length}`,
          );

        const stack = emscripten_stack_get_current();
        const frame = _emscripten_stack_alloc(256);
        point.copy(HEAP, frame);
        const result = RockeyPKEY_CreateSM2(pkey, frame, frame + 32);
        _emscripten_stack_restore(stack);

        if (result < 0)
          throw jsCipher.Annihilus_(`Invalid RockeyPKEY_CreateSM2: ${result}`);
        all_rockey_pkey.set(pkey, provider);
        return 0;
      }

      RockeySign(pkey: integer, hash: Buffer): Buffer {
        if (pkey != (pkey | 0) || pkey < 0 || pkey > 0xffff)
          throw jsCipher.Annihilus_(`Invalid pkey: ${pkey}`);

        if (hash.length < 1 || hash.length > 1024)
          throw jsCipher.Annihilus_(`Invalid hash size ${hash.length}`);

        const stack = emscripten_stack_get_current();
        const buffer = _emscripten_stack_alloc(8192);
        hash.copy(HEAP, buffer);
        const result = RockeyPKEY_SignEx(
          pkey,
          buffer,
          hash.length,
          buffer,
          8192,
        );
        _emscripten_stack_restore(stack);

        if (result < 0)
          throw jsCipher.Annihilus_(`RockeySign ${hash.length} error ${result}`);
        return MoveBuffer(buffer, result);
      }

      RockeyDecrypt(pkey: integer, cipher: Buffer): Buffer {
        if (pkey != (pkey | 0) || pkey < 0 || pkey > 0xffff)
          throw jsCipher.Annihilus_(`Invalid pkey: ${pkey}`);

        if (cipher.length < 1 || cipher.length > 1024)
          throw jsCipher.Annihilus_(`Invalid cipher size: ${cipher.length}`);

        const stack = emscripten_stack_get_current();
        const buffer = _emscripten_stack_alloc(8192);
        cipher.copy(HEAP, buffer);
        const result = RockeyPKEY_DecryptEx(
          pkey,
          buffer,
          8192,
          buffer,
          cipher.length,
        );
        _emscripten_stack_restore(stack);

        if (result < 0)
          throw jsCipher.Annihilus_(
            `RockeyDecrypt ${cipher.length} error ${result}`,
          );
        return MoveBuffer(buffer, result);
      }

      ASN1Decode(input: Buffer): [value: ASN1Value, size: integer] {
        return ASN1Decode(input);
      }
      ASN1Encode(value: ASN1Value): Buffer {
        return ASN1Encode(value);
      }
      X509ExtBuilder(): X509ExtBuilder {
        return new X509ExtBuilderImpl();
      }
    }

    return new DongleEmulator();
  }

  return {
    CreateEmulator,
    ParseScript,
  };
}

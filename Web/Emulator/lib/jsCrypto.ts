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
  SetLEDState(state: LED_STATE): void;

  ReadShareMemory(): Buffer;
  WriteShareMemory(buffer: Buffer): void;

  DeleteFile(type: SECRET_STORAGE_TYPE, id: integer): void;
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
}

export type CreateEmulatorOption = {
  UpdateLEDState?: (led: LED_STATE) => void;
  LogWriteMessage?: (level: integer, message: string) => void;
};

export async function CryptoLoader(jsCipher: CipherSuiteV0) {
  const wasmModule_ = await WebAssembly.compile(jsCryptoText.Assets());
  async function ParseScript(script: string) {
    return await jsScript.Parse(script);
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
    const supperLogWriteMessage = option?.LogWriteMessage;

    let nextImportBuffer: null | Buffer = null;
    let nextExportBuffer: null | Buffer = null;

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
      if (supperLogWriteMessage) {
        supperLogWriteMessage(level, message);
      } else {
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
      console.log(`fd_read> ${fd}`);

      let result = 0;
      if (fd === kFileID_null || fd === 0) {
        // null && stdin ...
        HEAP32[pnum >>> 2] = 0;
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

    const instance = await WebAssembly.instantiate(wasmModule_, {
      rLANG: {
        jsLogWrite,
        jsGetTickCount,

        RAND_Bytes,
        SetDongleLEDState,
        LoadDongleFile,
        WriteDongleFile,
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

    const native = <Native0_>(<unknown>instance.exports);

    native._initialize();
    native.Initialize();

    let instanceDongle = 0;
    const memoryDongle = native.MemoryManager(0, native.EmuSize());
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
        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(32);
        v.copy(HEAP, frame);
        native.RANDSeedBytes(frame, 32);
        native._emscripten_stack_restore(stack);
      }

      Export(): Buffer {
        const size = native.EmuWrite(CheckInstance());
        if (size !== nextExportBuffer?.length)
          throw jsCipher.Annihilus_(`Export Error ${size}`);
        const result = nextExportBuffer;
        nextExportBuffer = null;
        return result;
      }

      Create(secret: string | Buffer, uid: integer, loop: integer = 256): void {
        if (instanceDongle) {
          native.EmuClear(instanceDongle);
          instanceDongle = 0;
        }

        instanceDongle = native.EmuNew(memoryDongle, PERMISSION.kAdministrator);
        console.assert(instanceDongle === memoryDongle);

        if (typeof secret === "string") secret = Buffer.from(secret);

        const stack = native.emscripten_stack_get_current();
        const master_secret = native._emscripten_stack_alloc(64);
        jsCipher
          .Digest("SHA512")
          .Init()
          .Update(secret)
          .Final()
          .copy(HEAP, master_secret);
        const result = native.EmuCreate(
          instanceDongle,
          master_secret,
          uid,
          loop,
        );
        HEAP.fill(0, master_secret, master_secret + 64);
        native._emscripten_stack_restore(stack);
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
          native.EmuClear(instanceDongle);
          instanceDongle = 0;
        }

        instanceDongle = native.EmuNew(memoryDongle, perm);
        console.assert(instanceDongle === memoryDongle);

        if (typeof secret === "string") secret = Buffer.from(secret);

        nextImportBuffer = storage;
        const stack = native.emscripten_stack_get_current();
        const master_secret = native._emscripten_stack_alloc(64);
        jsCipher
          .Digest("SHA512")
          .Init()
          .Update(secret)
          .Final()
          .copy(HEAP, master_secret);
        const result = native.EmuOpen(instanceDongle, master_secret, loop);
        HEAP.fill(0, master_secret, master_secret + 64);
        native._emscripten_stack_restore(stack);
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
        const stack = native.emscripten_stack_get_current();
        const buffer = native._emscripten_stack_alloc(1024);
        InOutBuffer.copy(HEAP, buffer);
        const result = native.EmuExecv(thiz, buffer);
        native._emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(`dongle.Execv Error ${result}`);

        HEAP.copy(InOutBuffer, 0, buffer);
        HEAP.fill(0, buffer, buffer + 1024);
      }

      GetDongleInfo(): Buffer {
        const thiz = CheckInstance();

        const stack = native.emscripten_stack_get_current();
        const buffer = native._emscripten_stack_alloc(64);
        const result = native.EmuGetDongleInfo(thiz, buffer);
        native._emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(`dongle.GetDongleInfo Error ${result}`);
        return MoveBuffer(buffer, 40);
      }
      GetPINState(): PERMISSION {
        const thiz = CheckInstance();

        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(16);
        const result = native.EmuGetPINState(thiz, frame);
        native._emscripten_stack_restore(stack);

        if (0 === result) return <PERMISSION>HEAP[frame];
        else throw jsCipher.Annihilus_(`dongle.GetPINState Error ${result}`);
      }

      SetLEDState(state: LED_STATE): void {
        const thiz = CheckInstance();
        const result = native.EmuSetLEDState(thiz, state);
        if (0 !== result)
          throw jsCipher.Annihilus_(`dongle.SetLEDState Error ${result}`);
      }

      ReadShareMemory(): Buffer {
        const thiz = CheckInstance();

        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(32);
        const result = native.EmuReadShareMemory(thiz, frame);
        native._emscripten_stack_restore(stack);

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

        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(32);
        buffer.copy(HEAP, frame);
        const result = native.EmuWriteShareMemory(thiz, frame);
        HEAP.fill(0, frame, frame + 32);
        native._emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(`dongle.WriteShareMemory Error ${result}`);
      }

      DeleteFile(type: SECRET_STORAGE_TYPE, id: integer): void {
        const thiz = CheckInstance();
        const result = native.EmuDeleteFile(thiz, type, id);
        if (0 !== result)
          throw jsCipher.Annihilus_(`dongle.DeleteFile ${id} Error ${result}`);
      }

      CreateDataFile(id: integer, size: integer): void {
        const thiz = CheckInstance();
        const result = native.EmuCreateDataFile(thiz, id, size);
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
        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(8192);
        buffer.copy(HEAP, frame);
        const result = native.EmuWriteDataFile(
          thiz,
          id,
          off,
          frame,
          buffer.length,
        );
        native._emscripten_stack_restore(stack);

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
        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(8192);
        const result = native.EmuReadDataFile(thiz, id, off, frame, size);
        native._emscripten_stack_restore(stack);

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
        const result = native.EmuCreatePKEYFile(thiz, type, bits, id);
        if (0 !== result)
          throw jsCipher.Annihilus_(
            `dongle.WritePKEYFile ${id}/${type} Error ${result}`,
          );
      }

      GenerateRSA(id: integer, export_private: boolean): Buffer {
        /// [ modulus.LE[4], exponent[256] ] || [ modulus.LE[4], exponent[256], private_key[256] ]
        const thiz = CheckInstance();

        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(1024);
        const result = native.EmuGenerateRSA(
          thiz,
          id,
          frame,
          frame + 4,
          export_private ? frame + 260 : 0,
        );
        native._emscripten_stack_restore(stack);

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
        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(1024);
        pkey.copy(HEAP, frame);
        const result = native.EmuImportRSA(
          thiz,
          id,
          HEAPU32[frame >>> 2],
          frame + 4,
          frame + 260,
        );
        HEAP.fill(0, frame, frame + 1024);
        native._emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(`dongle.ImportRSA ${id} Error ${result}`);
      }

      GenerateP256(id: integer, export_private: boolean): Buffer {
        /// [ X[32], Y[32] ] || [ X[32], Y[32], K[32] ]
        const thiz = CheckInstance();

        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(128);
        const result = native.EmuGenerateP256(
          thiz,
          id,
          frame,
          frame + 32,
          export_private ? frame + 64 : 0,
        );
        native._emscripten_stack_restore(stack);

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
        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(128);
        private_key.copy(HEAP, frame);
        const result = native.EmuImportP256(thiz, id, frame);
        HEAP.fill(0, frame, frame + 32);
        native._emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(`dongle.ImportP256 ${id} Error ${result}`);
      }

      GenerateSM2(id: integer, export_private: boolean): Buffer {
        const thiz = CheckInstance();

        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(128);
        const result = native.EmuGenerateSM2(
          thiz,
          id,
          frame,
          frame + 32,
          export_private ? frame + 64 : 0,
        );
        native._emscripten_stack_restore(stack);

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
        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(128);
        private_key.copy(HEAP, frame);
        const result = native.EmuImportSM2(thiz, id, frame);
        HEAP.fill(0, frame, frame + 32);
        native._emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(`dongle.ImportSM2 ${id} Error ${result}`);
      }

      CreateKeyFile(id: integer, type: SECRET_STORAGE_TYPE): void {
        if (type !== SECRET_STORAGE_TYPE.kTDES || SECRET_STORAGE_TYPE.kSM4)
          throw jsCipher.Annihilus_(
            `dongle.CreateKeyFile ${id} invalid type ${type}`,
          );

        const thiz = CheckInstance();
        const result = native.EmuCreateKeyFile(thiz, id, type);
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
        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(128);
        key.copy(HEAP, frame);
        const result = native.EmuWriteKeyFile(thiz, id, frame, 16, type);
        HEAP.fill(0, frame, frame + 32);
        native._emscripten_stack_restore(stack);

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

        let result = 0;
        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(2048);
        const addr_buffer = frame + 256;

        input.copy(HEAP, frame);
        HEAP32[addr_buffer >>> 2] = input.length;

        if (typeof key === "number") {
          result = native.EmuRSAPrivate(thiz, key, frame, addr_buffer, encrypt);
        } else {
          const addr_pkey = frame + 512;
          key.copy(HEAP, addr_pkey);
          result = native.EmuRSAPrivateEx(
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
        native._emscripten_stack_restore(stack);

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

        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(2048);
        const addr_buffer = frame + 256;
        const addr_pkey = frame + 512;

        input.copy(HEAP, frame);
        exponent.copy(HEAP, addr_pkey);
        HEAP32[addr_buffer >>> 2] = input.length;
        const result = native.EmuRSAPublic(
          thiz,
          2048,
          modulus,
          addr_pkey,
          frame,
          addr_buffer,
          encrypt,
        );
        native._emscripten_stack_restore(stack);

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

        let result = 0;
        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(256);
        hash.copy(HEAP, frame);

        if (typeof key === "number") {
          result = native.EmuP256Sign(thiz, key, frame, frame + 32, frame + 64);
        } else {
          const addr_key = frame + 128;
          key.copy(HEAP, addr_key);
          result = native.EmuP256SignEx(
            thiz,
            addr_key,
            frame,
            frame + 32,
            frame + 64,
          );
          HEAP.fill(0, addr_key, addr_key + 32);
        }
        native._emscripten_stack_restore(stack);

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

        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(256);
        point.copy(HEAP, frame);
        hash.copy(HEAP, frame + 64);
        hash.copy(HEAP, frame + 128);
        const result = native.EmuP256Verify(
          thiz,
          frame,
          frame + 32,
          frame + 64,
          frame + 128,
          frame + 160,
        );
        native._emscripten_stack_restore(stack);

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

        let result = 0;
        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(256);
        hash.copy(HEAP, frame);

        if (typeof key === "number") {
          result = native.EmuSM2Sign(thiz, key, frame, frame + 32, frame + 64);
        } else {
          const addr_key = frame + 128;
          key.copy(HEAP, addr_key);
          result = native.EmuSM2SignEx(
            thiz,
            addr_key,
            frame,
            frame + 32,
            frame + 64,
          );
          HEAP.fill(0, addr_key, addr_key + 32);
        }
        native._emscripten_stack_restore(stack);

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

        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(256);
        point.copy(HEAP, frame);
        hash.copy(HEAP, frame + 64);
        hash.copy(HEAP, frame + 128);
        const result = native.EmuSM2Verify(
          thiz,
          frame,
          frame + 32,
          frame + 64,
          frame + 128,
          frame + 160,
        );
        native._emscripten_stack_restore(stack);

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

        let result = 0;
        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(4096 + 256);
        const addr_cipher = frame + 3072;
        const addr_text = frame + 2048;
        const addr_size = frame + 2000;
        const size_verify = cipher.length - 96; /// 96: X[32], Y[32], H[32] ...
        cipher.copy(HEAP, frame + 3072);

        if (typeof key === "number") {
          result = native.EmuSM2Decrypt(
            thiz,
            key,
            addr_cipher,
            cipher.length,
            addr_text,
            addr_size,
          );
        } else {
          key.copy(HEAP, frame);
          result = native.EmuSM2DecryptEx(
            thiz,
            frame,
            addr_cipher,
            cipher.length,
            addr_text,
            addr_size,
          );
          HEAP.fill(0, frame, frame + 32);
        }
        native._emscripten_stack_restore(stack);

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

        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(4096);
        const addr_text = frame + 1024;
        const addr_cipher = frame + 2048;

        point.copy(HEAP, frame);
        plain.copy(HEAP, addr_text);
        const result = native.EmuSM2Encrypt(
          thiz,
          frame,
          frame + 32,
          addr_text,
          plain.length,
          addr_cipher,
        );
        HEAP.fill(0, addr_text, plain.length);
        native._emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(`dongle.SM2Encrypt Error ${result}`);
        else return MoveBuffer(addr_cipher, plain.length + 96);
      }

      SM3(message: Buffer): Buffer {
        const thiz = CheckInstance();
        const size = message.length;

        if (size < 1 || size > 1024)
          throw jsCipher.Annihilus_(`dongle.SM3 invalid message size ${size}`);

        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(1024 + 32);
        message.copy(HEAP, frame);

        const addr_md = frame + 1024;
        const result = native.EmuSM3(thiz, frame, size, addr_md);
        native._emscripten_stack_restore(stack);

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

        let result = 0;
        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(2048);
        input.copy(HEAP, frame);

        if (typeof key === "number") {
          result = native.EmuSM4ECB(thiz, key, frame, size, encrypt);
        } else {
          const addr_key = frame + 1024;
          key.copy(HEAP, addr_key);
          result = native.EmuSM4ECBEx(thiz, addr_key, frame, size, encrypt);
          HEAP.fill(0, addr_key, addr_key + 16);
        }
        native._emscripten_stack_restore(stack);

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
        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(64);
        point.copy(HEAP, frame);
        const result = native.EmuCheckPointOnCurveSM2(thiz, frame, frame + 32);
        native._emscripten_stack_restore(stack);

        return 0 === result;
      }

      EmuDecompressPointSM2(X: Buffer, Yodd: boolean): Buffer {
        const thiz = CheckInstance();
        if (X.length !== 32)
          throw jsCipher.Annihilus_(
            `dongle.EmuDecompressPointSM2 invalid X size ${X.length}`,
          );

        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(64);
        X.copy(HEAP, frame + 32);
        const result = native.EmuDecompressPointSM2(
          thiz,
          frame,
          frame + 32,
          Yodd,
        );
        native._emscripten_stack_restore(stack);

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
        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(64);
        point.copy(HEAP, frame);
        const result = native.EmuCheckPointOnCurvePrime256v1(
          thiz,
          frame,
          frame + 32,
        );
        native._emscripten_stack_restore(stack);

        return 0 === result;
      }

      DecompressPointPrime256v1(X: Buffer, Yodd: boolean): Buffer {
        const thiz = CheckInstance();
        if (X.length !== 32)
          throw jsCipher.Annihilus_(
            `dongle.DecompressPointPrime256v1 invalid X size ${X.length}`,
          );

        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(64);
        X.copy(HEAP, frame + 32);
        const result = native.EmuDecompressPointPrime256v1(
          thiz,
          frame,
          frame + 32,
          Yodd,
        );
        native._emscripten_stack_restore(stack);

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

        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(128);
        privateKey.copy(HEAP, frame + 64);
        const result = native.EmuComputePubkeyPrime256v1(
          thiz,
          frame,
          frame + 32,
          frame + 64,
        );
        HEAP.fill(0, frame + 64, frame + 96);
        native._emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(
            `dongle.ComputePubkeyPrime256v1 Error ${result}`,
          );
        else return MoveBuffer(frame, 64);
      }

      GenerateKeyPairPrime256v1(): Buffer {
        const thiz = CheckInstance();
        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(128);
        const result = native.EmuGenerateKeyPairPrime256v1(
          thiz,
          frame,
          frame + 32,
          frame + 64,
        );
        native._emscripten_stack_restore(stack);
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

        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(128);
        privateKey.copy(HEAP, frame + 32);
        point.copy(HEAP, frame + 64);
        const result = native.EmuComputeSecretPrime256v1(
          thiz,
          frame,
          frame + 64,
          frame + 96,
          frame + 32,
        );
        HEAP.fill(0, frame + 32, frame + 64);
        native._emscripten_stack_restore(stack);

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

        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(128);
        privateKey.copy(HEAP, frame + 64);
        hash.copy(HEAP, frame + 96);
        const result = native.EmuSignMessagePrime256v1(
          thiz,
          frame + 64,
          frame + 96,
          frame,
          frame + 32,
        );
        HEAP.fill(0, frame + 64, frame + 96);
        native._emscripten_stack_restore(stack);

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
        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(256);
        point.copy(HEAP, frame);
        hash.copy(HEAP, frame + 64);
        sign.copy(HEAP, frame + 128);
        const result = native.EmuVerifySignPrime256v1(
          thiz,
          frame,
          frame + 32,
          frame + 64,
          frame + 128,
          frame + 160,
        );
        native._emscripten_stack_restore(stack);

        return 0 === result;
      }

      CheckPointOnCurveSecp256k1(point: Buffer): boolean {
        const thiz = CheckInstance();
        if (point.length !== 64)
          throw jsCipher.Annihilus_(
            `dongle.CheckPointOnCurveSecp256k1 invalid point size ${point.length}`,
          );
        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(64);
        point.copy(HEAP, frame);
        const result = native.EmuCheckPointOnCurveSecp256k1(
          thiz,
          frame,
          frame + 32,
        );
        native._emscripten_stack_restore(stack);

        return 0 === result;
      }

      DecompressPointSecp256k1(X: Buffer, Yodd: boolean): Buffer {
        const thiz = CheckInstance();
        if (X.length !== 32)
          throw jsCipher.Annihilus_(
            `dongle.DecompressPointSecp256k1 invalid X size ${X.length}`,
          );

        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(64);
        X.copy(HEAP, frame + 32);
        const result = native.EmuDecompressPointSecp256k1(
          thiz,
          frame,
          frame + 32,
          Yodd,
        );
        native._emscripten_stack_restore(stack);

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

        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(128);
        privateKey.copy(HEAP, frame + 64);
        const result = native.EmuComputePubkeySecp256k1(
          thiz,
          frame,
          frame + 32,
          frame + 64,
        );
        HEAP.fill(0, frame + 64, frame + 96);
        native._emscripten_stack_restore(stack);

        if (0 !== result)
          throw jsCipher.Annihilus_(
            `dongle.ComputePubkeySecp256k1 Error ${result}`,
          );
        else return MoveBuffer(frame, 64);
      }

      GenerateKeyPairSecp256k1(): Buffer {
        const thiz = CheckInstance();
        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(128);
        const result = native.EmuGenerateKeyPairSecp256k1(
          thiz,
          frame,
          frame + 32,
          frame + 64,
        );
        native._emscripten_stack_restore(stack);
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

        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(128);
        privateKey.copy(HEAP, frame + 32);
        point.copy(HEAP, frame + 64);
        const result = native.EmuComputeSecretSecp256k1(
          thiz,
          frame,
          frame + 64,
          frame + 96,
          frame + 32,
        );
        HEAP.fill(0, frame + 32, frame + 64);
        native._emscripten_stack_restore(stack);

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

        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(128);
        privateKey.copy(HEAP, frame + 64);
        hash.copy(HEAP, frame + 96);
        const result = native.EmuSignMessageSecp256k1(
          thiz,
          frame + 64,
          frame + 96,
          frame,
          frame + 32,
        );
        HEAP.fill(0, frame + 64, frame + 96);
        native._emscripten_stack_restore(stack);

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
        const stack = native.emscripten_stack_get_current();
        const frame = native._emscripten_stack_alloc(256);
        point.copy(HEAP, frame);
        hash.copy(HEAP, frame + 64);
        sign.copy(HEAP, frame + 128);
        const result = native.EmuVerifySignSecp256k1(
          thiz,
          frame,
          frame + 32,
          frame + 64,
          frame + 128,
          frame + 160,
        );
        native._emscripten_stack_restore(stack);

        return 0 === result;
      }
    }

    return new DongleEmulator();
  }

  return {
    CreateEmulator,
    ParseScript,
  };
}

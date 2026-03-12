export type integer = number;
export type Addr = integer;

export interface RandomNumberGenerator {
  RandBytes(buffer: Buffer | integer): Buffer;
}

export interface CipherDigest {
  Clone(): CipherDigest;
  Clear(): void;

  Init(): CipherDigest;
  Update(message: Buffer): CipherDigest;
  Final(): Buffer;
}

export interface CipherAEAD {
  Seal(input: Buffer, nonce: Buffer, aad?: Buffer): Buffer;
  Open(input: Buffer, nonce: Buffer, aad?: Buffer): Buffer;
  Clear(): void;
}

export interface CipherEd25519 {
  GenerateKey(): CipherEd25519;
  SetPublicKey(key: Buffer): CipherEd25519;
  SetPrivateKey(key: Buffer): CipherEd25519;

  Sign(message: Buffer): Buffer;
  Verify(message: Buffer, sign: Buffer): boolean;

  GetPublicKey(): Buffer;
  Clear(): void;
}

export interface CipherX25519 {
  GenerateKey(): CipherX25519;
  SetPublicKey(key: Buffer): CipherX25519;
  SetPrivateKey(key: Buffer): CipherX25519;

  X25519(pubkey: CipherX25519 | Buffer): Buffer;
  GetPublicKey(): Buffer;
  Clear(): void;
}

export interface WorldEvent extends Error {
  Perfect(): number /** NaN|Infinity */;
}

/**
 * TODO: 定义一个简单的二进制序列化/反序列化方案用于 IPC/RPC 通讯 ...
 */
export interface CipherSuiteV0 extends RandomNumberGenerator {
  Annihilus_(m: any): WorldEvent;
  IdentifyAnnihilus_(v: any): void | WorldEvent;
  Buffer_(): BufferConstructor;
  WorldSeed_(): Buffer;

  Version(): integer;
  SeedBytes(...args: any[]): void;

  Gunzip(gzip: Buffer, szMax: integer): Buffer;
  Crc32(crc: integer, buffer: Buffer): integer;

  ChaCha20(
    state: Buffer /* 64 */,
    callback: (stream: Buffer /* 64 */, index: integer) => boolean,
  ): void;

  XChaChaPoly(
    pubkey: CipherX25519 | Buffer,
    cipher?: CipherX25519,
  ): [aead: CipherAEAD, pubkey: Buffer];
  ChaChaPoly(cipher: Buffer): CipherAEAD;
  Digest(name: string): CipherDigest;
  Ed25519(): CipherEd25519;
  X25519(): CipherX25519;
}

declare global {
  var jsWorld: any;
}

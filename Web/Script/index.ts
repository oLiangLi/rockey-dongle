import { Context } from "./lib/grammar.js";

type _Base = {
  size_public: number; // 0 ... 1024
  encrypt?: boolean; // default=true
  logout?: boolean; // default=true
  shm?: string; // Buffer[32].toString('base64')
  import_data?: string; // Buffer[0...4096].toString('base64')
};

type _Origin = _Base & {
  origin: string; // Buffer[1024].toString('base64')
};
type _Code = _Base & {
  code: string; // Buffer[2..200].toString('base64')
  data?: string; // Buffer[0..768].toString('base64')
};

export type ExecFile = _Origin | _Code;

export const enum Magic {
  rLANG_WORLD_MAGIC = 0xc8c04e1f,
  kCategory_MAGIC = 0xc35880af,

  /**!! */
  kMagicCreate = 0x0d214153,
  kMagicWorld = 0x5cf48c13,

  /**!! */
  kAdminFileMagic = 0x0443493b
}

/**!! */
export const kOffsetDonglePublic = 7 * 1024;

/**!! */
export const kFileSM2ECDSA = 1;
export const kFileSECP256r1 = 2;
export const kFileRSA2048 = 3;
export const kFileSM2ECIES = 4;

/**! Offset.public */
export const enum Offset {
  kOffsetPubkey_SM2ECDSA = 20,
  kOffsetPubkey_Secp256r1 = 84,
  kOffsetPubkey_RSA2048 = 148,
  kOffsetPubkey_SM2ECIES = 408,

  kOffsetDongleNonce1 = 472,
  kOffsetDongleInfo = 504,
  kOffsetDongleNonce2 = 544,

  kOffsetSign_SM2ECIES = 576,
  kOffsetSign_RSA2048 = 640,
  kOffsetSign_Secp256r1 = 896,
  kOffsetSign_SM2ECDSA = 960,
  kSizePublic = 1024
}

export async function Parse(script: string) {
  const ctx = await Context.Create(script);
  if (0 !== ctx.yyparse())
    throw Error(`Parse script error line: ${ctx.yyline()}`);

  const size_public = ctx.size_public();
  const code = ctx.code();

  return {
    size_public,
    code: code.toString("base64")
  };
}

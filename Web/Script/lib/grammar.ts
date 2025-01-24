import { OpCode } from "./opcode.js";
import { Tokenize } from "./tokenize.js";
import { Assets } from "../../Assembly/Script_wasm.js";
import { Token, Action } from "../grammar/dongle.jy.js";

type integer = number;
type Addr = integer;
const assert = console.assert.bind(console);

const kPop1V = OpCode.kNop | (1 << 11);

type TypeMemoryOp = {
  name: string;
  argc: integer;
  op: [sFmt: integer, vFmt: integer];
};

const AllMemoryOp: TypeMemoryOp[] = [
  {
    name: "kLoadI8",
    argc: 1,
    op: [OpCode.kLoadI8, OpCode.kLoadXI8]
  },
  {
    name: "kLoadU8",
    argc: 1,
    op: [OpCode.kLoadU8, OpCode.kLoadXU8]
  },
  {
    name: "kLoadI16",
    argc: 1,
    op: [OpCode.kLoadI16, OpCode.kLoadXI16]
  },
  {
    name: "kLoadU16",
    argc: 1,
    op: [OpCode.kLoadU16, OpCode.kLoadXU16]
  },
  {
    name: "kLoadI32",
    argc: 1,
    op: [OpCode.kLoadI32, OpCode.kLoadXI32]
  },
  {
    name: "kStoreI8",
    argc: 2,
    op: [OpCode.kStoreI8, OpCode.kStoreXI8]
  },
  {
    name: "kStoreI16",
    argc: 2,
    op: [OpCode.kStoreI16, OpCode.kStoreXI16]
  },
  {
    name: "kStoreI32",
    argc: 2,
    op: [OpCode.kStoreI32, OpCode.kStoreXI32]
  }
];

type TypeFuncCall = {
  name: string;
  min: integer;
  max: integer;
  op: integer;
};

const AllFunc: TypeFuncCall[] = [
  {
    name: "kExit",
    min: 0,
    max: 1,
    op: OpCode.kExit
  },
  {
    name: "kMemset",
    min: 3,
    max: 3,
    op: OpCode.kMemset
  },
  {
    name: "kMemcpy",
    min: 3,
    max: 3,
    op: OpCode.kMemcpy
  },
  {
    name: "kMemcmp",
    min: 3,
    max: 3,
    op: OpCode.kMemcmp
  },
  {
    name: "kValidPINState",
    min: 0,
    max: 0,
    op: OpCode.kValidPINState
  },
  {
    name: "kRandBytes",
    min: 2,
    max: 2,
    op: OpCode.kRandBytes
  },
  {
    name: "kSecretBytes",
    min: 1,
    max: 1,
    op: OpCode.kSecretBytes
  },
  {
    name: "kReadDongleInfo",
    min: 1,
    max: 1,
    op: OpCode.kReadDongleInfo
  },
  {
    name: "kLEDControl",
    min: 1,
    max: 1,
    op: OpCode.kLEDControl
  },
  {
    name: "kReadSharedMemory",
    min: 1,
    max: 1,
    op: OpCode.kReadSharedMemory
  },
  {
    name: "kWriteSharedMemory",
    min: 1,
    max: 1,
    op: OpCode.kWriteSharedMemory
  },
  {
    name: "kDeleteDataFile",
    min: 1,
    max: 1,
    op: OpCode.kDeleteDataFile
  },
  {
    name: "kCreateDataFile",
    min: 2,
    max: 4,
    op: OpCode.kCreateDataFile
  },
  {
    name: "kWriteDataFile",
    min: 4,
    max: 4,
    op: OpCode.kWriteDataFile
  },
  {
    name: "kReadDataFile",
    min: 4,
    max: 4,
    op: OpCode.kReadDataFile
  },
  {
    name: "kDeleteRSAFile",
    min: 1,
    max: 1,
    op: OpCode.kDeleteRSAFile
  },
  {
    name: "kCreateRSAFile",
    min: 1,
    max: 5,
    op: OpCode.kCreateRSAFile
  },
  {
    name: "kGenerateRSA",
    min: 2,
    max: 3,
    op: OpCode.kGenerateRSA
  },
  {
    name: "kImportRSA",
    min: 3,
    max: 3,
    op: OpCode.kImportRSA
  },
  {
    name: "kRSAPrivateDecrypt",
    min: 2,
    max: 2,
    op: OpCode.kRSAPrivateDecrypt
  },
  {
    name: "kRSAPrivateEncrypt",
    min: 3,
    max: 3,
    op: OpCode.kRSAPrivateEncrypt
  },
  {
    name: "kExRSAPrivateDecrypt",
    min: 3,
    max: 3,
    op: OpCode.kExRSAPrivateDecrypt
  },
  {
    name: "kExRSAPrivateEncrypt",
    min: 4,
    max: 4,
    op: OpCode.kExRSAPrivateEncrypt
  },
  {
    name: "kExRSAPublicEncrypt",
    min: 3,
    max: 3,
    op: OpCode.kExRSAPublicEncrypt
  },
  {
    name: "kExRSAPublicDecrypt",
    min: 2,
    max: 2,
    op: OpCode.kExRSAPublicDecrypt
  },
  {
    name: "kDeleteP256File",
    min: 1,
    max: 1,
    op: OpCode.kDeleteP256File
  },
  {
    name: "kCreateP256File",
    min: 1,
    max: 5,
    op: OpCode.kCreateP256File
  },
  {
    name: "kGenerateP256",
    min: 2,
    max: 3,
    op: OpCode.kGenerateP256
  },
  {
    name: "kImportP256",
    min: 2,
    max: 2,
    op: OpCode.kImportP256
  },
  {
    name: "kP256Sign",
    min: 3,
    max: 3,
    op: OpCode.kP256Sign
  },
  {
    name: "kExP256CheckPointOnCurve",
    min: 1,
    max: 1,
    op: OpCode.kExP256CheckPointOnCurve
  },
  {
    name: "kExP256DecompressPoint",
    min: 3,
    max: 3,
    op: OpCode.kExP256DecompressPoint
  },
  {
    name: "kExP256ComputePubkey",
    min: 2,
    max: 2,
    op: OpCode.kExP256ComputePubkey
  },
  {
    name: "kExP256GenerateKeyPair",
    min: 2,
    max: 2,
    op: OpCode.kExP256GenerateKeyPair
  },
  {
    name: "kExP256Sign",
    min: 3,
    max: 3,
    op: OpCode.kExP256Sign
  },
  {
    name: "kExP256Verify",
    min: 3,
    max: 3,
    op: OpCode.kExP256Verify
  },
  {
    name: "kExP256ComputeSecret",
    min: 3,
    max: 3,
    op: OpCode.kExP256ComputeSecret
  },
  {
    name: "kDeleteSM2File",
    min: 1,
    max: 1,
    op: OpCode.kDeleteSM2File
  },
  {
    name: "kCreateSM2File",
    min: 1,
    max: 5,
    op: OpCode.kCreateSM2File
  },
  {
    name: "kGenerateSM2",
    min: 2,
    max: 3,
    op: OpCode.kGenerateSM2
  },
  {
    name: "kImportSM2",
    min: 2,
    max: 2,
    op: OpCode.kImportSM2
  },
  {
    name: "kSM2Sign",
    min: 3,
    max: 3,
    op: OpCode.kSM2Sign
  },
  {
    name: "kSM2Decrypt",
    min: 3,
    max: 3,
    op: OpCode.kSM2Decrypt
  },
  {
    name: "kExSM2CheckPointOnCurve",
    min: 1,
    max: 1,
    op: OpCode.kExSM2CheckPointOnCurve
  },
  {
    name: "kExSM2DecompressPoint",
    min: 3,
    max: 3,
    op: OpCode.kExSM2DecompressPoint
  },
  {
    name: "kExSM2Sign",
    min: 3,
    max: 3,
    op: OpCode.kExSM2Sign
  },
  {
    name: "kExSM2Verify",
    min: 3,
    max: 3,
    op: OpCode.kExSM2Verify
  },
  {
    name: "kExSM2Decrypt",
    min: 3,
    max: 3,
    op: OpCode.kExSM2Decrypt
  },
  {
    name: "kExSM2Encrypt",
    min: 3,
    max: 3,
    op: OpCode.kExSM2Encrypt
  },
  {
    name: "kDigestSHA1",
    min: 3,
    max: 3,
    op: OpCode.kDigestSHA1
  },
  {
    name: "kDigestSM3",
    min: 3,
    max: 3,
    op: OpCode.kDigestSM3
  },
  {
    name: "kExDigestSHA256",
    min: 3,
    max: 3,
    op: OpCode.kExDigestSHA256
  },
  {
    name: "kExDigestSHA384",
    min: 3,
    max: 3,
    op: OpCode.kExDigestSHA384
  },
  {
    name: "kExDigestSHA512",
    min: 3,
    max: 3,
    op: OpCode.kExDigestSHA512
  },
  {
    name: "kDeleteSM4File",
    min: 1,
    max: 1,
    op: OpCode.kDeleteSM4File
  },
  {
    name: "kCreateSM4File",
    min: 1,
    max: 2,
    op: OpCode.kCreateSM4File
  },
  {
    name: "kWriteSM4File",
    min: 2,
    max: 2,
    op: OpCode.kWriteSM4File
  },
  {
    name: "kSM4ECBEncrypt",
    min: 3,
    max: 3,
    op: OpCode.kSM4ECBEncrypt
  },
  {
    name: "kSM4ECBDecrypt",
    min: 3,
    max: 3,
    op: OpCode.kSM4ECBDecrypt
  },
  {
    name: "kExSM4ECBEncrypt",
    min: 3,
    max: 3,
    op: OpCode.kExSM4ECBEncrypt
  },
  {
    name: "kExSM4ECBDecrypt",
    min: 3,
    max: 3,
    op: OpCode.kExSM4ECBDecrypt
  },
  {
    name: "kDeleteTDESFile",
    min: 1,
    max: 1,
    op: OpCode.kDeleteTDESFile
  },
  {
    name: "kCreateTDESFile",
    min: 1,
    max: 2,
    op: OpCode.kCreateTDESFile
  },
  {
    name: "kWriteTDESFile",
    min: 2,
    max: 2,
    op: OpCode.kWriteTDESFile
  },
  {
    name: "kTDESECBEncrypt",
    min: 3,
    max: 3,
    op: OpCode.kTDESECBEncrypt
  },
  {
    name: "kTDESECBDecrypt",
    min: 3,
    max: 3,
    op: OpCode.kTDESECBDecrypt
  },
  {
    name: "kExTDESECBEncrypt",
    min: 3,
    max: 3,
    op: OpCode.kExTDESECBEncrypt
  },
  {
    name: "kExTDESECBDecrypt",
    min: 3,
    max: 3,
    op: OpCode.kExTDESECBDecrypt
  },
  {
    name: "kExChaChaPolySeal",
    min: 4,
    max: 4,
    op: OpCode.kExChaChaPolySeal
  },
  {
    name: "kExChaChaPolyOpen",
    min: 4,
    max: 4,
    op: OpCode.kExChaChaPolyOpen
  },
  {
    name: "kExSecp256K1CheckPointOnCurve",
    min: 1,
    max: 1,
    op: OpCode.kExSecp256K1CheckPointOnCurve
  },
  {
    name: "kExSecp256K1DecompressPoint",
    min: 3,
    max: 3,
    op: OpCode.kExSecp256K1DecompressPoint
  },
  {
    name: "kExSecp256K1ComputePubkey",
    min: 2,
    max: 2,
    op: OpCode.kExSecp256K1ComputePubkey
  },
  {
    name: "kExSecp256K1GenerateKeyPair",
    min: 2,
    max: 2,
    op: OpCode.kExSecp256K1GenerateKeyPair
  },
  {
    name: "kExSecp256K1Sign",
    min: 3,
    max: 3,
    op: OpCode.kExSecp256K1Sign
  },
  {
    name: "kExSecp256K1Verify",
    min: 3,
    max: 3,
    op: OpCode.kExSecp256K1Verify
  },
  {
    name: "kExSecp256K1ComputeSecret",
    min: 3,
    max: 3,
    op: OpCode.kExSecp256K1ComputeSecret
  },
  {
    name: "kExCurve25519ComputePubkey",
    min: 2,
    max: 2,
    op: OpCode.kExCurve25519ComputePubkey
  },
  {
    name: "kExCurve25519GenerateKeyPair",
    min: 2,
    max: 2,
    op: OpCode.kExCurve25519GenerateKeyPair
  },
  {
    name: "kExCurve25519ComputeSecret",
    min: 3,
    max: 3,
    op: OpCode.kExCurve25519ComputeSecret
  },
  {
    name: "kExEd25519ComputePubkey",
    min: 2,
    max: 2,
    op: OpCode.kExEd25519ComputePubkey
  },
  {
    name: "kExEd25519GenerateKeyPair",
    min: 2,
    max: 2,
    op: OpCode.kExEd25519GenerateKeyPair
  },
  {
    name: "kExEd25519Sign",
    min: 5,
    max: 5,
    op: OpCode.kExEd25519Sign
  },
  {
    name: "kExEd25519Verify",
    min: 4,
    max: 4,
    op: OpCode.kExEd25519Verify
  }
];

const table_memory_op = new Map<string, TypeMemoryOp>();
const table_func_call = new Map<string, TypeFuncCall>();

AllMemoryOp.forEach((value) => {
  assert(!table_memory_op.has(value.name));
  table_memory_op.set(value.name, value);
});
AllFunc.forEach((value) => {
  assert(!table_func_call.has(value.name));
  table_func_call.set(value.name, value);
});

class Statement {
  constructor() {
    this.code_ = [];
  }
  readonly code_: integer[];
}

class Expression {
  Statement(v: boolean): Statement {
    throw Error(`Pure functon call ...`);
  }
}

class MemoryLoadExpr extends Expression {
  constructor(line: integer, addr: Expression, op0: integer, op1: integer) {
    super();
    this.line_ = line;
    this.addr_ = addr;
    this.op0_ = op0;
    this.op1_ = op1;
    assert(0 == (op0 & 0x3ff));
    assert(0 == (op1 & ~0x3ff));
  }

  Statement(v: boolean): Statement {
    if (!v) return this.addr_.Statement(v);

    const result = new Statement();
    if (this.addr_ instanceof ConstExpr) {
      const addr = this.addr_.value_;
      if (addr < 0 || addr >= 1024)
        throw RangeError(`Line ${this.line_} LoadMemory ${addr} Out-of-range!`);
      result.code_.push(this.op0_ | addr);
    } else {
      result.code_.push(...this.addr_.Statement(true).code_);
      result.code_.push(this.op1_ | (1 << 11));
    }
    return result;
  }

  readonly line_: integer;
  readonly addr_: Expression;
  readonly op0_: integer;
  readonly op1_: integer;
}

class MemoryStoreExpr extends Expression {
  constructor(
    line: integer,
    addr: Expression,
    value: Expression,
    op0: integer,
    op1: integer
  ) {
    super();
    this.line_ = line;
    this.addr_ = addr;
    this.value_ = value;
    this.op0_ = op0;
    this.op1_ = op1;
    assert(0 == (op0 & 0x3ff));
    assert(0 == (op1 & ~0x3ff));
  }

  Statement(v: boolean): Statement {
    const result = new Statement();
    if (this.addr_ instanceof ConstExpr) {
      const addr = this.addr_.value_;
      if (addr < 0 || addr >= 1024)
        throw RangeError(`Line ${this.line_} LoadMemory ${addr} Out-of-range!`);
      result.code_.push(...this.value_.Statement(true).code_);
      if (v) result.code_.push(OpCode.kDup);
      result.code_.push(this.op0_ | addr);
    } else {
      result.code_.push(...this.addr_.Statement(true).code_);
      result.code_.push(...this.value_.Statement(true).code_);
      let op = this.op1_ | (2 << 11);
      if (!v) op |= 0x0400;
      result.code_.push(op);
    }

    return result;
  }

  readonly line_: integer;
  readonly addr_: Expression;
  readonly value_: Expression;
  readonly op0_: integer;
  readonly op1_: integer;
}

class ConstExpr extends Expression {
  constructor(val: integer) {
    super();
    this.value_ = val | 0;
  }

  Statement(v: boolean): Statement {
    const result = new Statement();
    if (!v) return result;

    const code = result.code_;
    if (this.value_ < 0) {
      const abs = -this.value_;

      if (abs <= 0x1000) {
        code.push(OpCode.kLoadNI | (abs - 1));
      } else if (abs <= 0x100000) {
        code.push(OpCode.kLoadMNI | ((abs >> 12) - 1));
        if (0 !== (abs & 0xfff)) code.push(OpCode.kAddUI | (abs & 0xfff));
      }
    } else {
      const abs = this.value_;

      if (abs <= 0xfff) {
        code.push(OpCode.kLoadUI | (abs & 0xfff));
      } else if (abs <= 0xffffff) {
        code.push(OpCode.kLoadMUI | (abs >> 12));
        if (0 !== (abs & 0xfff)) code.push(OpCode.kAddUI | (abs & 0xfff));
      }
    }

    if (!code.length) {
      const value = this.value_;

      const H = value >>> 24;
      const M = (value >> 12) & 0xfff;
      const L = value & 0xfff;

      code.push(OpCode.kLoadHUI | H);
      if (M) code.push(OpCode.kAddMUI | M);
      if (L) code.push(OpCode.kAddUI | L);
    }

    return result;
  }

  value_: integer;
}

class UnaryExpr extends Expression {
  constructor(expr: Expression, op: integer) {
    super();
    this.expr_ = expr;
    this.op_ = op;
  }

  Statement(v: boolean): Statement {
    const result = this.expr_.Statement(v);
    if (v) result.code_.push(this.op_ | (1 << 11));
    return result;
  }

  expr_: Expression;
  op_: integer;
}

function CheckLogicNotExpr(expr: Expression) {
  if (expr instanceof UnaryExpr && expr.op_ == OpCode.kNot) return expr.expr_;
  return void 0;
}

class CallExpr extends Expression {
  constructor(line: integer, args: Expression[], name: string, op: integer) {
    super();
    this.line_ = line;
    this.args_ = args;
    this.name_ = name;
    this.op_ = op;
    assert(0 == (op & ~0x3ff));
    assert(args.length < 16);
  }

  Statement(v: boolean): Statement {
    const result = new Statement();
    const code = result.code_;

    for (let i = 0; i < this.args_.length; ++i) {
      const arg = this.args_[i].Statement(true);
      code.push(...arg.code_);
    }

    let op = this.op_;
    if (!v) op |= 0x0400;
    op |= this.args_.length << 11;
    code.push(op);
    return result;
  }

  args_: Expression[];
  line_: integer;
  name_: string;
  op_: integer;
}

class BinaryExpr extends Expression {
  constructor(left: Expression, right: Expression, op: integer) {
    super();
    this.left_ = left;
    this.right_ = right;
    this.op_ = op;
  }

  Statement(v: boolean): Statement {
    const left = this.left_.Statement(v);
    const code = left.code_;

    if (!v) {
      code.push(...this.right_.Statement(false).code_);
    } else {
      let handle = false;
      if (this.right_ instanceof ConstExpr) {
        let value = this.right_.value_;

        switch (this.op_) {
          case OpCode.kLT:
            if (value >= -128 && value <= 127) {
              handle = true;
              code.push(OpCode.kSltI | (value & 0xff));
            }
            break;
          case OpCode.kSub:
          case OpCode.kAdd:
            if (this.op_ === OpCode.kSub) value = -value;

            if (value >= 0) {
              if (value <= 0xfff) {
                handle = true;
                code.push(OpCode.kAddUI | value);
              }
            } else {
              value = -value;
              if (value <= 0x100) {
                handle = true;
                code.push(OpCode.kSubI | (value - 1));
              }
            }
            break;
          case OpCode.kMul:
            if (value >= -128 && value <= 127) {
              handle = true;
              code.push(OpCode.kMulI | (value & 0xff));
            }
            break;
          case OpCode.kDiv:
            if (value >= -128 && value <= 127) {
              handle = true;
              code.push(OpCode.kDivI | (value & 0xff));
            }
            break;
          case OpCode.kMod:
            if (value >= -128 && value <= 127) {
              handle = true;
              code.push(OpCode.kModI | (value & 0xff));
            }
            break;
          case OpCode.kSll:
            handle = true;
            code.push(OpCode.kSllI | (value & 0x1f));
            break;
          case OpCode.kSrl:
            handle = true;
            code.push(OpCode.kSrlI | (value & 0x1f));
            break;
          case OpCode.kSra:
            handle = true;
            code.push(OpCode.kSraI | (value & 0x1f));
            break;
          case OpCode.kXor:
            if (value >= -128 && value <= 127) {
              handle = true;
              code.push(OpCode.kXorI | (value & 0xff));
            }
            break;
          case OpCode.kOr:
            if (value >= -128 && value <= 127) {
              handle = true;
              code.push(OpCode.kOrI | (value & 0xff));
            }
            break;
          case OpCode.kAnd:
            if (value >= -128 && value <= 127) {
              handle = true;
              code.push(OpCode.kAndI | (value & 0xff));
            }
            break;
        }
      }

      if (!handle) {
        code.push(...this.right_.Statement(true).code_);
        code.push(this.op_ | (2 << 11));
      }
    }
    return left;
  }

  left_: Expression;
  right_: Expression;
  op_: integer;
}
class LogicAndExpr extends Expression {
  constructor(line: integer) {
    super();
    this.list_ = [];
    this.line_ = line;
  }

  Statement(v: boolean): Statement {
    let i = 0;
    const list = <Expression[]>[];

    while (i < this.list_.length) {
      const expr = this.list_[i++];

      if (expr instanceof ConstExpr) {
        if (!expr.value_) {
          list.push(expr);
          this.list_.length = i;
          break;
        }
      } else {
        list.push(expr);
      }
    }

    while (i < this.list_.length) {
      const expr = this.list_[i++];

      if (expr instanceof ConstExpr) {
        if (!expr.value_) {
          list.push(expr);
          break;
        }
      } else {
        list.push(expr);
      }
    }

    if (1 === list.length) return list[0].Statement(v);

    const result = new Statement();
    const code = result.code_;
    if (list.length === 0) {
      if (v) {
        code.push(OpCode.kLoadUI | 1); // true
      }
    } else {
      let last = list.pop()!;
      if (!v) {
        if (last instanceof ConstExpr) {
          last = list.pop()!;
          if (!list.length) return last.Statement(false);
        }
      }

      let right = last.Statement(v).code_;
      if (v) {
        right = [kPop1V, ...right];
      }

      while (list.length) {
        if (right.length > 100)
          throw Error(`Line ${this.line_} Overly complex expressions`);

        last = list.pop()!;
        const left = last.Statement(true).code_;
        left.push(OpCode.kJmpF | (1 + right.length));
        left.push(...right);
        right = left;
      }

      if (v) code.push(OpCode.kLoadUI | 0);
      code.push(...right);
    }

    return result;
  }

  readonly list_: Expression[];
  readonly line_: integer;
}

class LogicOrExpr extends Expression {
  constructor(line: integer) {
    super();
    this.list_ = [];
    this.line_ = line;
  }

  Statement(v: boolean): Statement {
    let i = 0;
    const list = <Expression[]>[];

    while (i < this.list_.length) {
      const expr = this.list_[i++];

      if (expr instanceof ConstExpr) {
        if (expr.value_) {
          list.push(expr);
          this.list_.length = i;
          break;
        }
      } else {
        list.push(expr);
      }
    }

    while (i < this.list_.length) {
      const expr = this.list_[i++];

      if (expr instanceof ConstExpr) {
        if (expr.value_) {
          list.push(expr);
          break;
        }
      } else {
        list.push(expr);
      }
    }

    if (1 === list.length) return list[0].Statement(v);

    const result = new Statement();
    const code = result.code_;
    if (list.length === 0) {
      if (v) {
        code.push(OpCode.kLoadUI | 0); // false
      }
    } else {
      let last = list.pop()!;
      if (!v) {
        if (last instanceof ConstExpr) {
          last = list.pop()!;
          if (!list.length) return last.Statement(false);
        }
      }

      let right = last.Statement(v).code_;
      if (v) {
        right = [kPop1V, ...right];
      }

      while (list.length) {
        if (right.length > 100)
          throw Error(`Line ${this.line_} Overly complex expressions`);

        last = list.pop()!;
        const left = last.Statement(true).code_;
        left.push(OpCode.kJmpT | (1 + right.length));
        left.push(...right);
        right = left;
      }

      if (v) code.push(OpCode.kLoadUI | 1);
      code.push(...right);
    }

    return result;
  }

  list_: Expression[];
  readonly line_: integer;
}

class Arguments {
  argv_ = <Expression[]>[];
}

export type TypeGrammar =
  | void
  | null
  | boolean
  | integer
  | string
  | Statement
  | Expression
  | Arguments;

function console_error(m: string) {
  console.error(`%c${m}`, "color: red");
}
function console_warning(m: string) {
  console.warn(`%c${m}`, "color: darkorange");
}

interface Native_ {
  jsGrammar_yyLen(): integer;
  jsGrammar_yyOffset(): integer;
  jsGrammar_yyNextState(reason: integer): integer;
  _initialize(): void;
}
const kStackSize = 256;

export class Context {
  private constructor(instance: WebAssembly.Instance, script: string) {
    this.tokenize_ = new Tokenize(script);

    this.yylval_ = void 0;
    this.yyvsa_ = new Array<TypeGrammar>(kStackSize + 4);
    this.native_ = <Native_>(<unknown>instance.exports);
    this.native_._initialize();

    this.error_ = this.native_.jsGrammar_yyNextState(-1);
    console.assert(this.error_ === -1);
  }

  static async Create(script: string): Promise<Context> {
    const memory = new WebAssembly.Memory({ initial: 1, maximum: 1 });
    if (!Context.wasmModule_)
      Context.wasmModule_ = await WebAssembly.compile(Assets());

    const instance = await WebAssembly.instantiate(Context.wasmModule_, {
      env: {
        memory
      },
      rLANG: {
        jsGrammar_yyError,
        jsGrammar_yyCopyValue
      }
    });
    const grammar = new Context(instance, script);

    function jsGrammar_yyError(prefix: Addr, symbol: Addr) {
      const buffer = Buffer.from(memory.buffer);
      let prefix_end = prefix,
        symbol_end = symbol;
      while (0 !== buffer[prefix_end]) ++prefix_end;
      while (0 !== buffer[symbol_end]) ++symbol_end;
      const s_prefix = buffer.subarray(prefix, prefix_end).toString();
      const s_symbol = buffer.subarray(symbol, symbol_end).toString();
      console_error(`${s_prefix} ${s_symbol}`);
    }
    function jsGrammar_yyCopyValue(offset: integer) {
      grammar.yyvsa_[offset] = grammar.yylval_;
      grammar.yylval_ = void 0;
    }

    return grammar;
  }

  private Next(line: integer, token: integer, value?: TypeGrammar) {
    this.yyline_ = line;
    this.yylval_ = value;

    if (token < 0) {
      throw RangeError(`Line ${this.yyline_} Token ${token} .LT. 0`);
    } else if (token > Token.$MAX_TOKEN_VALUE) {
      throw RangeError(`Line ${this.yyline_} Token ${token} .GT. Max`);
    } else if (this.error_ !== -1) {
      throw Error(`Line ${this.yyline_} Invalid state ${this.error_}`);
    }

    this.error_ = this.native_.jsGrammar_yyNextState(token);
    for (;;) {
      if (this.error_ <= 0) {
        if (this.error_ < -1)
          throw Error(
            `Line ${this.yyline_} Invalid Grammar.state ${this.error_}`
          );
        return this.error_;
      }

      this.reduce_(this.error_);
      this.error_ = this.native_.jsGrammar_yyNextState(-2);
    }
  }

  yyline() {
    return this.yyline_;
  }
  yyparse() {
    for (;;) {
      const input = this.tokenize_.yylex();
      if (typeof input === "number") {
        if (0 === this.Next(this.tokenize_.line_, input)) return 0;
      } else {
        if (0 === this.Next(this.tokenize_.line_, input[0], input[1])) return 0;
      }
    }
  }

  private reduce_(rule: integer) {
    const argc = this.native_.jsGrammar_yyLen();
    const offset = this.native_.jsGrammar_yyOffset();

    let $$ = this.yyvsa_[offset + 1];
    const $ = (index: integer) => {
      console.assert(
        index >= 1 && index <= argc && offset + index < kStackSize
      );
      return this.yyvsa_[offset + index];
    };

    switch (rule) {
      case Action.AC_PUBLIC_SIZE_0:
        this.public_size_ = 0;
        break;
      case Action.AC_PUBLIC_SIZE_X:
        this.public_size_ = <integer>$(2);
        if (this.public_size_ < 0 || this.public_size_ > 1024)
          throw Error(
            `Line ${this.yyline_} invalid public size ${this.public_size_}!`
          );
        break;
      case Action.AC_CONST_STATEMENT:
        {
          const name = <string>$(1);
          const value = $(3);

          if (this.named_const_value_.has(name)) {
            throw Error(
              `Line ${this.yyline_} const value ${name} declared already!`
            );
          }

          if (value instanceof ConstExpr) {
            this.named_const_value_.set(name, value.value_);
          } else {
            throw Error(
              `Line ${this.yyline_} Name ${name} The result of the expression is not a constant`
            );
          }
        }
        break;

      case Action.AC_DECL_1:
        this.statements_.push(<Statement>$(1));
        break;

      case Action.AC_DECL_X:
        this.statements_.push(<Statement>$(2));
        break;

      case Action.AC_EMPTY_STMT:
      case Action.AC_BLOCK_EMPTY:
        $$ = new Statement();
        break;

      case Action.AC_BLOCK_DECLARE:
        $$ = $(2);
        break;

      case Action.AC_EXPRESSION_DECLARE:
        {
          const expr = <Expression>$(1);
          console.assert(expr instanceof Expression);
          $$ = expr.Statement(false);
        }
        break;

      case Action.AC_IF_STATEMENT:
        $$ = this.acIfStatement(
          <Expression>$(3),
          <Statement>$(5),
          new Statement()
        );
        break;

      case Action.AC_IF_ELSE_STATEMENT:
        $$ = this.acIfStatement(
          <Expression>$(3),
          <Statement>$(5),
          <Statement>$(7)
        );
        break;

      case Action.AC_WHILE_STATEMENT:
        $$ = this.acWhileStatement(<Expression>$(3), <Statement>$(5));
        break;

      case Action.AC_DO_WHILE_STATEMENT:
        $$ = this.acDoWhileStatement(<Statement>$(2), <Expression>$(5));
        break;

      case Action.AC_FOR_STATEMENT:
        $$ = this.acForLoopStatement(
          <null | Expression>$(3),
          <null | Expression>$(5),
          <null | Expression>$(7),
          <Statement>$(9)
        );
        break;

      case Action.AC_OPT_EXPR_NULL:
        $$ = null;
        break;

      case Action.AC_EXPR_LOGIC_OR:
        $$ = this.acLogicOrExpr(<Expression>$(1), <Expression>$(3));
        break;

      case Action.AC_EXPR_LOGIC_AND:
        $$ = this.acLogicAndExpr(<Expression>$(1), <Expression>$(3));
        break;

      case Action.AC_EXPR_BIT_OR:
        {
          const left = <Expression>$(1);
          const right = <Expression>$(3);

          if (left instanceof ConstExpr && right instanceof ConstExpr) {
            left.value_ |= right.value_;
          } else {
            $$ = new BinaryExpr(left, right, OpCode.kOr);
          }
        }
        break;

      case Action.AC_EXPR_BIT_XOR:
        {
          const left = <Expression>$(1);
          const right = <Expression>$(3);

          if (left instanceof ConstExpr && right instanceof ConstExpr) {
            left.value_ ^= right.value_;
          } else {
            $$ = new BinaryExpr(left, right, OpCode.kXor);
          }
        }
        break;

      case Action.AC_EXPR_BIT_AND:
        {
          const left = <Expression>$(1);
          const right = <Expression>$(3);

          if (left instanceof ConstExpr && right instanceof ConstExpr) {
            left.value_ &= right.value_;
          } else {
            $$ = new BinaryExpr(left, right, OpCode.kAnd);
          }
        }
        break;

      case Action.AC_EXPR_EQ:
        {
          const left = <Expression>$(1);
          const right = <Expression>$(3);

          if (left instanceof ConstExpr && right instanceof ConstExpr) {
            left.value_ = left.value_ == right.value_ ? 1 : 0;
          } else {
            $$ = new BinaryExpr(left, right, OpCode.kEQ);
          }
        }
        break;

      case Action.AC_EXPR_NE:
        {
          const left = <Expression>$(1);
          const right = <Expression>$(3);

          if (left instanceof ConstExpr && right instanceof ConstExpr) {
            left.value_ = left.value_ != right.value_ ? 1 : 0;
          } else {
            $$ = new BinaryExpr(left, right, OpCode.kNE);
          }
        }
        break;

      case Action.AC_EXPR_LE:
        {
          const left = <Expression>$(1);
          const right = <Expression>$(3);

          if (left instanceof ConstExpr && right instanceof ConstExpr) {
            left.value_ = left.value_ <= right.value_ ? 1 : 0;
          } else {
            $$ = new BinaryExpr(left, right, OpCode.kLE);
          }
        }
        break;

      case Action.AC_EXPR_GE:
        {
          const left = <Expression>$(1);
          const right = <Expression>$(3);

          if (left instanceof ConstExpr && right instanceof ConstExpr) {
            left.value_ = left.value_ >= right.value_ ? 1 : 0;
          } else {
            $$ = new BinaryExpr(left, right, OpCode.kGE);
          }
        }
        break;

      case Action.AC_EXPR_GT:
        {
          const left = <Expression>$(1);
          const right = <Expression>$(3);

          if (left instanceof ConstExpr && right instanceof ConstExpr) {
            left.value_ = left.value_ > right.value_ ? 1 : 0;
          } else {
            $$ = new BinaryExpr(left, right, OpCode.kGT);
          }
        }
        break;

      case Action.AC_EXPR_LT:
        {
          const left = <Expression>$(1);
          const right = <Expression>$(3);

          if (left instanceof ConstExpr && right instanceof ConstExpr) {
            left.value_ = left.value_ < right.value_ ? 1 : 0;
          } else {
            $$ = new BinaryExpr(left, right, OpCode.kLT);
          }
        }
        break;

      case Action.AC_EXPR_SHIFT_LEFT:
        {
          const left = <Expression>$(1);
          const right = <Expression>$(3);

          if (left instanceof ConstExpr && right instanceof ConstExpr) {
            left.value_ = left.value_ << (right.value_ & 0x1f);
          } else {
            $$ = new BinaryExpr(left, right, OpCode.kSll);
          }
        }
        break;

      case Action.AC_EXPR_SHIFT_RIGHT:
        {
          const left = <Expression>$(1);
          const right = <Expression>$(3);

          if (left instanceof ConstExpr && right instanceof ConstExpr) {
            left.value_ = left.value_ >> (right.value_ & 0x1f);
          } else {
            $$ = new BinaryExpr(left, right, OpCode.kSra);
          }
        }
        break;

      case Action.AC_EXPR_SHIFT_RIGHT_U:
        {
          const left = <Expression>$(1);
          const right = <Expression>$(3);

          if (left instanceof ConstExpr && right instanceof ConstExpr) {
            left.value_ = left.value_ >>> (right.value_ & 0x1f);
          } else {
            $$ = new BinaryExpr(left, right, OpCode.kSrl);
          }
        }
        break;

      case Action.AC_EXPR_ADD:
        {
          const left = <Expression>$(1);
          const right = <Expression>$(3);

          if (left instanceof ConstExpr && right instanceof ConstExpr) {
            left.value_ = (left.value_ + right.value_) | 0;
          } else {
            $$ = new BinaryExpr(left, right, OpCode.kAdd);
          }
        }
        break;

      case Action.AC_EXPR_SUB:
        {
          const left = <Expression>$(1);
          const right = <Expression>$(3);

          if (left instanceof ConstExpr && right instanceof ConstExpr) {
            left.value_ = (left.value_ - right.value_) | 0;
          } else {
            $$ = new BinaryExpr(left, right, OpCode.kSub);
          }
        }
        break;

      case Action.AC_EXPR_MUL:
        {
          const left = <Expression>$(1);
          const right = <Expression>$(3);

          if (left instanceof ConstExpr && right instanceof ConstExpr) {
            left.value_ = (left.value_ * right.value_) | 0;
          } else {
            $$ = new BinaryExpr(left, right, OpCode.kMul);
          }
        }
        break;

      case Action.AC_EXPR_DIV:
        {
          const left = <Expression>$(1);
          const right = <Expression>$(3);

          if (left instanceof ConstExpr && right instanceof ConstExpr) {
            if (
              0 === right.value_ ||
              (right.value_ === -1 && 0 === (left.value_ ^ 0x80000000))
            )
              throw Error(`Line ${this.yyline_} raise SIGFPE`);

            left.value_ = (left.value_ / right.value_) | 0;
          } else {
            $$ = new BinaryExpr(left, right, OpCode.kDiv);
          }
        }
        break;

      case Action.AC_EXPR_MOD:
        {
          const left = <Expression>$(1);
          const right = <Expression>$(3);

          if (left instanceof ConstExpr && right instanceof ConstExpr) {
            if (
              0 === right.value_ ||
              (right.value_ === -1 && 0 === (left.value_ ^ 0x80000000))
            )
              throw Error(`Line ${this.yyline_} raise SIGFPE`);

            left.value_ = left.value_ % right.value_ | 0;
          } else {
            $$ = new BinaryExpr(left, right, OpCode.kMod);
          }
        }
        break;

      case Action.AC_EXPR_UNARY_ADD:
        $$ = $(2);
        break;

      case Action.AC_EXPR_UNARY_SUB:
        {
          const expr = <Expression>$(2);
          if (expr instanceof ConstExpr) {
            $$ = expr;
            expr.value_ = -expr.value_ | 0;
          } else {
            $$ = new UnaryExpr(expr, OpCode.kNegative);
          }
        }
        break;

      case Action.AC_EXPR_BIT_NOT:
        {
          const expr = <Expression>$(2);
          if (expr instanceof ConstExpr) {
            $$ = expr;
            expr.value_ = ~expr.value_ | 0;
          } else {
            $$ = new UnaryExpr(expr, OpCode.kBitNot);
          }
        }
        break;

      case Action.AC_EXPR_LOGIC_NOT:
        {
          const expr = <Expression>$(2);
          if (expr instanceof ConstExpr) {
            $$ = expr;
            expr.value_ = expr.value_ ? 0 : 1;
          } else {
            $$ = new UnaryExpr(expr, OpCode.kNot);
          }
        }
        break;

      case Action.AC_PRI_EXPR_0:
        $$ = $(2);
        break;

      case Action.AC_PRI_IDEN:
        {
          const name = <string>$(1);
          const value = this.named_const_value_.get(name);
          if (typeof value !== "number")
            throw Error(
              `Line ${this.yyline_} Const value ${name} 404 Not Found!`
            );
          $$ = new ConstExpr(value);
        }
        break;

      case Action.AC_PRI_NUMBER:
        $$ = new ConstExpr(<integer>$(1));
        break;

      case Action.AC_CALL_0:
        $$ = this.acFuncCall(<string>$(1), new Arguments());
        break;

      case Action.AC_CALL_X:
        $$ = this.acFuncCall(<string>$(1), <Arguments>$(3));
        break;

      case Action.AC_ARGLIST_1:
        $$ = new Arguments();
        $$.argv_.push(<Expression>$(1));
        break;

      case Action.AC_ARGLIST_X:
        (<Arguments>$$).argv_.push(<Expression>$(3));
        break;

      default:
        break;
    }

    for (let i = 2; i <= argc; ++i) this.yyvsa_[offset + i] = void 0;
    this.yyvsa_[offset + 1] = $$;
  }

  private acIfStatement(expr: Expression, stmt: Statement, st_else: Statement) {
    let $$: Statement;
    console.assert(expr instanceof Expression);
    console.assert(stmt instanceof Statement);
    console.assert(st_else instanceof Statement);

    const logNot = CheckLogicNotExpr(expr);
    if (logNot) {
      [stmt, st_else] = [st_else, stmt];
      expr = logNot;
    }

    if (expr instanceof ConstExpr) {
      return expr.value_ ? stmt : st_else;
    }

    if (!st_else.code_.length) {
      if (!stmt.code_.length) return expr.Statement(false);
      $$ = expr.Statement(true);
      $$.code_.push(OpCode.kJmpF | (1 + stmt.code_.length));
      $$.code_.push(...stmt.code_);
    } else if (!stmt.code_.length) {
      $$ = expr.Statement(true);
      $$.code_.push(OpCode.kJmpT | (1 + st_else.code_.length));
      $$.code_.push(...st_else.code_);
    } else {
      $$ = expr.Statement(true);
      $$.code_.push(OpCode.kJmpF | (2 + stmt.code_.length));
      $$.code_.push(...stmt.code_);
      $$.code_.push(OpCode.kJmp | (1 + st_else.code_.length));
      $$.code_.push(...st_else.code_);
    }

    return $$;
  }

  private acWhileStatement(expr: Expression, stmt: Statement): Statement {
    const result = new Statement();
    const code = result.code_;
    if (expr instanceof ConstExpr) {
      if (expr.value_) {
        code.push(...stmt.code_);
        code.push(OpCode.kJmp | (0xff & -stmt.code_.length));
      }
    } else {
      const logNot = CheckLogicNotExpr(expr);
      if (logNot) {
        code.push(...logNot.Statement(true).code_);
        code.push(OpCode.kJmpT | (2 + stmt.code_.length));
      } else {
        code.push(...expr.Statement(true).code_);
        code.push(OpCode.kJmpF | (2 + stmt.code_.length));
      }

      code.push(...stmt.code_);
      code.push(OpCode.kJmp | (0xff & -code.length));
    }

    return result;
  }

  private acDoWhileStatement(stmt: Statement, expr: Expression) {
    const result = new Statement();
    const code = result.code_;

    code.push(...stmt.code_);
    if (expr instanceof ConstExpr) {
      if (expr.value_) {
        code.push(OpCode.kJmp | (0xff & -code.length));
      }
    } else {
      const logNot = CheckLogicNotExpr(expr);
      if (logNot) {
        code.push(...logNot.Statement(true).code_);
        code.push(OpCode.kJmpF | (0xff & -code.length));
      } else {
        code.push(...expr.Statement(true).code_);
        code.push(OpCode.kJmpT | (0xff & -code.length));
      }
    }
    return result;
  }

  private acForLoopStatement(
    init: null | Expression,
    expr: null | Expression,
    incl: null | Expression,
    stmt: Statement
  ) {
    if (!expr) expr = new ConstExpr(1);
    const stmt_incl = incl ? incl.Statement(false) : new Statement();

    const result = new Statement();
    const code = result.code_;
    if (init) code.push(...init.Statement(false).code_);

    const offset_begin = code.length;
    if (expr instanceof ConstExpr) {
      if (expr.value_) {
        code.push(...stmt.code_);
        code.push(...stmt_incl.code_);
        code.push(OpCode.kJmp | (0xff & -(code.length - offset_begin)));
      }
    } else {
      const logNot = CheckLogicNotExpr(expr);
      if (logNot) {
        code.push(...logNot.Statement(true).code_);
        code.push(
          OpCode.kJmpT | (2 + stmt.code_.length + stmt_incl.code_.length)
        );
      } else {
        code.push(...expr.Statement(true).code_);
        code.push(
          OpCode.kJmpF | (2 + stmt.code_.length + stmt_incl.code_.length)
        );
      }

      code.push(...stmt.code_);
      code.push(...stmt_incl.code_);
      code.push(OpCode.kJmp | (0xff & -(code.length - offset_begin)));
    }

    return result;
  }

  private acLogicAndExpr(left: Expression, right: Expression) {
    const $$ = new LogicAndExpr(this.yyline_);

    if (left instanceof LogicAndExpr) {
      $$.list_.push(...left.list_);
    } else {
      $$.list_.push(left);
    }

    if (right instanceof LogicAndExpr) {
      $$.list_.push(...right.list_);
    } else {
      $$.list_.push(right);
    }

    return $$;
  }

  private acLogicOrExpr(left: Expression, right: Expression) {
    const $$ = new LogicOrExpr(this.yyline_);

    if (left instanceof LogicOrExpr) {
      $$.list_.push(...left.list_);
    } else {
      $$.list_.push(left);
    }

    if (right instanceof LogicOrExpr) {
      $$.list_.push(...right.list_);
    } else {
      $$.list_.push(right);
    }
    return $$;
  }

  private acFuncCall(name: string, args: Arguments): Expression {
    if (table_memory_op.has(name)) {
      const entry = table_memory_op.get(name)!;
      if (entry.argc !== args.argv_.length)
        throw Error(
          `Line ${this.yyline_} MemoryOp ${name} argc ${args.argv_.length} !== ${entry.argc}`
        );
      const addr = args.argv_[0];
      assert(entry.argc === 1 || entry.argc === 2);
      if (entry.argc === 1) {
        return new MemoryLoadExpr(
          this.yyline_,
          args.argv_[0],
          entry.op[0],
          entry.op[1]
        );
      } else {
        return new MemoryStoreExpr(
          this.yyline_,
          args.argv_[0],
          args.argv_[1],
          entry.op[0],
          entry.op[1]
        );
      }
    } else if (table_func_call.has(name)) {
      const argc = args.argv_.length;
      const entry = table_func_call.get(name)!;
      if (argc < entry.min || argc > entry.max)
        throw RangeError(
          `Line ${this.yyline_} Function ${name} argc ${argc} Out-of-range [${entry.min}, ${entry.max}]`
        );
      return new CallExpr(this.yyline_, args.argv_, name, entry.op);
    } else {
      throw Error(`Line ${this.yyline_} Function ${name} 404 Not Found!`);
    }
  }

  size_public() {
    return this.public_size_;
  }

  code() {
    const code = <integer[]>[];
    for (const stmt of this.statements_) {
      code.push(...stmt.code_);
    }

    if (code.length > 100)
      throw Error(`Script code size ${code.length} .GT. 100`);
    if (code.length < 100) code.push(OpCode.kExit);

    for (const v of code) {
      if (v < 0 || v > 0xffff) throw Error(`Invalid code ${v}`);
    }

    const result = Buffer.alloc(code.length * 2);
    for (let i = 0; i < code.length; ++i) {
      result.writeUInt16LE(code[i], i * 2);
    }
    return result;
  }

  private static wasmModule_?: WebAssembly.Module;
  private readonly yyvsa_: TypeGrammar[];
  private readonly native_: Native_;
  private readonly tokenize_: Tokenize;
  private yylval_: TypeGrammar;
  private yyline_ = -1;
  private error_: integer;

  private public_size_ = 0;
  private named_const_value_ = new Map<string, integer>();
  private statements_ = <Statement[]>[];
}

import * as scanner from "../grammar/dongle.js";
import { Token } from "../grammar/dongle.jy.js";

type integer = number;

const tokens = new Map<integer, integer>();
(function () {
  tokens.set(scanner.Tokenize.Action.AC_IF, Token.TK_IF);
  tokens.set(scanner.Tokenize.Action.AC_ELSE, Token.TK_ELSE);
  tokens.set(scanner.Tokenize.Action.AC_FOR, Token.TK_FOR);
  tokens.set(scanner.Tokenize.Action.AC_WHILE, Token.TK_WHILE);
  tokens.set(scanner.Tokenize.Action.AC_DO, Token.TK_DO);
  tokens.set(scanner.Tokenize.Action.AC_CONST, Token.TK_CONST);
  tokens.set(scanner.Tokenize.Action.AC_PUBLIC, Token.TK_PUBLIC);
  tokens.set(scanner.Tokenize.Action.AC_OP_LOGIC_OR, Token.OP_LOGIC_OR);
  tokens.set(scanner.Tokenize.Action.AC_OP_LOGIC_AND, Token.OP_LOGIC_AND);
  tokens.set(scanner.Tokenize.Action.AC_OP_EQ, Token.OP_EQ);
  tokens.set(scanner.Tokenize.Action.AC_OP_NE, Token.OP_NE);
  tokens.set(scanner.Tokenize.Action.AC_OP_LE, Token.OP_LE);
  tokens.set(scanner.Tokenize.Action.AC_OP_GE, Token.OP_GE);
  tokens.set(scanner.Tokenize.Action.AC_OP_SHIFT_LEFT, Token.OP_SHIFT_LEFT);
  tokens.set(scanner.Tokenize.Action.AC_OP_SHIFT_RIGHT, Token.OP_SHIFT_RIGHT);
  tokens.set(
    scanner.Tokenize.Action.AC_OP_SHIFT_RIGHT_U,
    Token.OP_SHIFT_RIGHT_U
  );
})();

function string2array(s: string) {
  const result = <integer[]>[];
  const size = s.length;

  let i = 0;
  while (i < size) {
    const c = <integer>s.codePointAt(i);
    i += c > 0xffff ? 2 : 1;
    result.push(c);
  }

  return result;
}

class Machine {
  constructor() {
    this.yytext = <integer[]>[];
    this.yybol = true;
    this.yyeof = false;

    this.pos = 0;
    this.start = 0;
    this.current = 1 + /* bol */ 1;
    this.state_backup = this.position_backup = -1;
    this.state_stack = <integer[]>[0];
  }

  Initialize(s?: string | Array<integer>, eof = false) {
    if (typeof s === "string") {
      this.yytext = string2array(s);
      this.yyeof = eof;
    } else if (s !== void 0) {
      this.yytext = s;
      this.yyeof = eof;
    } else {
      this.yytext = <integer[]>[];
      this.yyeof = false;
    }

    this.pos = 0;
    this.start = 0;
    this.yybol = true;
    this.current = 1 + /* bol */ 1;
    this.state_backup = this.position_backup = -1;
    this.state_stack = <integer[]>[0];
  }

  PUSH_STACK(start: integer) {
    this.state_stack.push(start);
    this.start = start;
  }

  POP_STACK() {
    const size = this.state_stack.length;
    console.assert(size >= 2);
    this.start = this.state_stack[size - 2];
    this.state_stack.pop();
  }

  BEGIN(start: integer) {
    const size = this.state_stack.length;
    console.assert(size >= 1);
    this.start = this.state_stack[size - 1] = start;
  }

  YYSTART() {
    return this.start;
  }

  YYSIZE() {
    return this.pos;
  }

  YYCHAR(index: number) {
    console.assert(index < this.pos);
    return this.yytext[index];
  }

  YYTEXT() {
    return String.fromCodePoint(...this.yytext.slice(0, this.pos));
  }

  YYINPUT(s?: integer | string | Array<integer>) {
    switch (typeof s) {
      case "number":
        this.yytext.push(s);
        break;

      case "string":
        this.yytext = this.yytext.concat(string2array(s));
        break;

      default:
        if (!s) this.yyeof = true;
        else this.yytext = this.yytext.concat(s);
        break;
    }

    return this.Next_(true);
  }

  YYNEXT() {
    return this.Next_();
  }

  private Next_(input?: boolean) {
    if (input !== true) {
      this.current = 2 * this.start + 1 + (this.yybol ? 1 : 0);
      if (0 !== this.pos) {
        this.yytext = this.yytext.slice(this.pos);
        this.pos = 0;
      }
    }

    const size = this.yytext.length;
    for (;;) {
      if (this.pos >= size) {
        /* EOB */
        if (this.pos === 0) {
          if (this.yyeof) return 0;
          return -1;
        } else if (this.yyeof) {
          break;
        } else {
          return -1;
        }
      }

      let yyc = this.yytext[this.pos];
      if (yyc < 0 || yyc >= scanner.YY_CHARSIZ) yyc = scanner.YY_CHARNIL;
      else yyc = scanner.yy_ec[yyc];

      if (scanner.yy_accept[this.current]) {
        this.state_backup = this.current;
        this.position_backup = this.pos;
      }

      while (
        scanner.yy_chk[scanner.yy_base[this.current] + yyc] !== this.current
      ) {
        if (
          (this.current = scanner.yy_def[this.current]) >=
          scanner.YY_LASTDFA + 2
        )
          yyc = scanner.yy_meta[yyc];
      }

      this.current = scanner.yy_nxt[scanner.yy_base[this.current] + yyc];
      ++this.pos;

      if (scanner.yy_base[this.current] == scanner.YY_JAMBASE) break;
    }

    let action = scanner.yy_accept[this.current];
    if (!action) {
      this.current = this.state_backup;
      this.pos = this.position_backup;
      action = scanner.yy_accept[this.current];
    }
    console.assert(this.pos > 0);
    this.yybol = this.isBol_(this.yytext[this.pos - 1]);
    return action;
  }

  private isBol_(c: integer) {
    return c === 13 || c === 10;
  }

  yytext: Array<integer>;
  yybol: boolean;
  yyeof: boolean;

  pos: integer;
  start: integer;
  current: integer;

  state_backup: integer;
  position_backup: integer;
  state_stack: Array<integer>;
}

export class Tokenize {
  constructor(code: string) {
    this.machine_ = new Machine();
    this.machine_.Initialize(code, true);
  }

  yylex(): integer | [token: integer, value: null | integer | string] {
    for (;;) {
      const action = this.machine_.YYNEXT();
      let token = tokens.get(action);
      if (token) return token;

      switch (action) {
        case 0 /* EOF */:
          if (this.machine_.YYSTART() === scanner.Tokenize.State.SC_MCOMM) {
            throw Error(
              `Tokenize: Unexpected end of file found in comment line: ${this.line_}`
            );
          }
          return 0;

        case scanner.Tokenize.Action.AC_MCOMM_BEGIN:
          this.machine_.BEGIN(scanner.Tokenize.State.SC_MCOMM);
          break;

        case scanner.Tokenize.Action.AC_SCOMM_BEGIN:
          this.machine_.BEGIN(scanner.Tokenize.State.SC_SCOMM);
          break;

        case scanner.Tokenize.Action.AC_NUMBER: {
          let value = 0;
          const YYTEXT = this.machine_.YYTEXT();

          if ("0" === YYTEXT[0]) {
            if ("x" == YYTEXT[1] || "X" == YYTEXT[1]) {
              value = parseInt(YYTEXT.slice(2), 16);
            } else {
              value = parseInt(YYTEXT, 8);
            }
          } else {
            value = parseInt(YYTEXT, 10);
          }

          if (isNaN(value) || value >= 2 ** 32 || value < 0) {
            throw RangeError(`Tokenize: Invalid integer value ${YYTEXT}`);
          }

          return [Token.TK_NUMBER, value | 0];
        }

        case scanner.Tokenize.Action.AC_IDEN:
          return [Token.TK_IDEN, this.machine_.YYTEXT()];

        case scanner.Tokenize.Action.AC_MCOMM_NL:
        case scanner.Tokenize.Action.AC_NEWLINE:
          ++this.line_;
          break;

        case scanner.Tokenize.Action.AC_SCOMM_END:
          this.machine_.BEGIN(scanner.Tokenize.State.INITIAL);
          ++this.line_;
          break;

        case scanner.Tokenize.Action.AC_SCOMM_ANY:
        case scanner.Tokenize.Action.AC_MCOMM_ANY:
        case scanner.Tokenize.Action.AC_SPACE:
          break;

        case scanner.Tokenize.Action.AC_ANY:
          token = this.machine_.YYCHAR(0);
          if (0 == token)
            throw Error(`Tokenize: Invalid NIL(0) found line: ${this.line_}`);
          return token;

        case scanner.Tokenize.Action.AC_MCOMM_END:
          this.machine_.BEGIN(scanner.Tokenize.State.INITIAL);
          break;

        default:
          throw Error(
            `BugFix Unexpected Tokenize action ${action} line: ${
              this.line_
            } TEXT: ${this.machine_.YYTEXT()}`
          );
      }
    }
  }

  private readonly machine_;
  line_ = 1;
}

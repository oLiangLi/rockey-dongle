/**
 * Auto generate, don't modify this file
 */
const enum ArrayType { u8, u16, i32 }
function String2Buffer(type : ArrayType, value : string) : Uint8Array|Uint16Array|Int32Array {
    const buf = Buffer.from(value, 'base64');
    const result = new ArrayBuffer(buf.length);
    buf.copy(Buffer.from(result));
    if(type === ArrayType.u8)
        return new Uint8Array(result);
    else if(type === ArrayType.u16)
        return new Uint16Array(result);
    else if(type === ArrayType.i32)
        return new Int32Array(result);
    else
        throw RangeError();
}

const yy_scenarioName_ = new Map<number, string>();
const yy_stateName  = <(number|string)[]>[];
const yy_eventName  = <(number|string)[]>[];
const yy_actionName = <(number|string)[]>[];

const yy_stateGroupMap_ = new Map<string, Map<string, Set<number>>>();
const yy_eventGroupMap_ = new Map<string, Map<string, Set<number>>>();

export function yyScenarioName(id:number) {
    return yy_scenarioName_.get(id);
}
export function yyStateName(id:number) : [ sc : number, name : string ] {
    id <<= 1;
    return [ <number>yy_stateName[id], <string>yy_stateName[id+1] ];
}
export function yyEventName(id:number) : [ sc : number, name : string ] {
    id = (id-260) << 1;
    return [ <number>yy_eventName[id], <string>yy_eventName[id+1] ];
}
export function yyActionName(id:number) : [ sc : number, name : string ]  {
    id <<= 1;
    return [ <number>yy_actionName[id], <string>yy_actionName[id+1] ];
}

export function yyIsGroupState(sc : string, group : string, value : number) {
    return !!yy_stateGroupMap_.get(sc)?.get(group)?.has(value);
}
export function yyIsGroupEvent(sc : string, group : string, value : number) {
    return !!yy_eventGroupMap_.get(sc)?.get(group)?.has(value);
}


/** Scenario Tokenize ... */
export namespace Tokenize {
	export const enum Name { $$ = 0 }

	export const enum State {
		INITIAL = 0,
		SC_MCOMM = 1,
		SC_SCOMM = 2,

		$Minimum = 0,
		$Maximum = 2
	}

	export const enum Event {
		$Minimum = -1,
		$Maximum = -1
	}

	export const enum Action {
		AC_MCOMM_BEGIN = 1,
		AC_SCOMM_BEGIN = 2,
		AC_NUMBER = 3,
		AC_IF = 4,
		AC_ELSE = 5,
		AC_FOR = 6,
		AC_WHILE = 7,
		AC_DO = 8,
		AC_CONST = 9,
		AC_PUBLIC = 10,
		AC_OP_LOGIC_OR = 11,
		AC_OP_LOGIC_AND = 12,
		AC_OP_EQ = 13,
		AC_OP_NE = 14,
		AC_OP_LE = 15,
		AC_OP_GE = 16,
		AC_OP_SHIFT_LEFT = 17,
		AC_OP_SHIFT_RIGHT = 18,
		AC_OP_SHIFT_RIGHT_U = 19,
		AC_IDEN = 20,
		AC_NEWLINE = 21,
		AC_SPACE = 22,
		AC_ANY = 23,
		AC_MCOMM_END = 24,
		AC_MCOMM_NL = 25,
		AC_MCOMM_ANY = 26,
		AC_SCOMM_END = 27,
		AC_SCOMM_ANY = 28,

		$Minimum = 1,
		$Maximum = 28
	}

}

/**
 * Module implements LexicalScanner
 */
export const
	YY_LASTDFA = 75,
	YY_JAMBASE = 104,
	YY_DEFAULT = 29,
	YY_CHARSIZ = 260,
	YY_CHARNIL = 1;

export const yy_accept = String2Buffer(ArrayType.u8, 'AAAAAAAAAB4XFhUVFxcXAwMXFxcUFBQUFBQUFBcaGRkaHBsbFQ4MAQIDAwARDw0QEhQUCBQUBBQUCxkYGwMTFBQGFBQUBRQUCRQHCgA=');
export const yy_ec = String2Buffer(ArrayType.u8, 'AQEBAQEBAQEBAgMCAgQBAQEBAQEBAQEBAQEBAQEBAQECBQEBAQEGAQEBBwEBAQEICQoKCgoKCgoLCwEBDA0OAQEPDw8PDw8QEBAQEBAQEBAQEBAQEBAQEBEQEAEBAQESAQ8TFBUWFxAYGRAQGhAbHB0QHh8gIRAiERAQASMBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=');
export const yy_meta = String2Buffer(ArrayType.u8, 'AAEBAQEBAQEBAgICAQEBAgMDAwICAgICAwMDAwMDAwMDAwMB');
export const yy_base = String2Buffer(ArrayType.u8, 'AAAAISMoKmdoaGhjWF4oKCsrVi0ARkVGQ0c8RDhoaFdRaGhVaGhoaGgzNgBoaGhoSQA7ADY2AEA5aGhoaABoMjoANTQtADM1ADYAAGhBREYn');
export const yy_def = String2Buffer(ArrayType.u8, 'AEwBTU1OTkxMTExMTExMTExMTExPT09PT09PT0xMTExMTExMTExMTExMTFBMTExMTE9PT09PT09PTExMTFBMT09PT09PT09PT09PTwBMTExM');
export const yy_nxt = String2Buffer(ArrayType.u8, 'AAgJCgsMDQgODxAQERITFBQUCBQVFhcYFBkUFBQaFBQUFBscHh8eHyA9ICIjIiMnKCkpKioqKiwtKy8wKSkqKioqHR0dISEhMTFLSklIR0ZFRENCQUA/Pjw7Ojk4NzY1NDMyLiYlJEwHTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEw=');
export const yy_chk = String2Buffer(ArrayType.u8, 'AAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAwMEBANQBAUFBgYODg8PDxAQEBERDxMTKSkpKioqTU1NTk5OT09JR0ZEQ0JAPzg3NTQyMCMgHxwbGhkYFxYVEg0MCwdMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEw=');

/**
 * Global names ...
 */
yy_actionName.push(-1, '$EOF');

/** Scenario Tokenize ... */
yy_scenarioName_.set(Tokenize.Name.$$, 'Tokenize');

yy_stateName.push(Tokenize.Name.$$, 'INITIAL');
yy_stateName.push(Tokenize.Name.$$, 'SC_MCOMM');
yy_stateName.push(Tokenize.Name.$$, 'SC_SCOMM');

yy_actionName.push(Tokenize.Name.$$, 'AC_MCOMM_BEGIN');
yy_actionName.push(Tokenize.Name.$$, 'AC_SCOMM_BEGIN');
yy_actionName.push(Tokenize.Name.$$, 'AC_NUMBER');
yy_actionName.push(Tokenize.Name.$$, 'AC_IF');
yy_actionName.push(Tokenize.Name.$$, 'AC_ELSE');
yy_actionName.push(Tokenize.Name.$$, 'AC_FOR');
yy_actionName.push(Tokenize.Name.$$, 'AC_WHILE');
yy_actionName.push(Tokenize.Name.$$, 'AC_DO');
yy_actionName.push(Tokenize.Name.$$, 'AC_CONST');
yy_actionName.push(Tokenize.Name.$$, 'AC_PUBLIC');
yy_actionName.push(Tokenize.Name.$$, 'AC_OP_LOGIC_OR');
yy_actionName.push(Tokenize.Name.$$, 'AC_OP_LOGIC_AND');
yy_actionName.push(Tokenize.Name.$$, 'AC_OP_EQ');
yy_actionName.push(Tokenize.Name.$$, 'AC_OP_NE');
yy_actionName.push(Tokenize.Name.$$, 'AC_OP_LE');
yy_actionName.push(Tokenize.Name.$$, 'AC_OP_GE');
yy_actionName.push(Tokenize.Name.$$, 'AC_OP_SHIFT_LEFT');
yy_actionName.push(Tokenize.Name.$$, 'AC_OP_SHIFT_RIGHT');
yy_actionName.push(Tokenize.Name.$$, 'AC_OP_SHIFT_RIGHT_U');
yy_actionName.push(Tokenize.Name.$$, 'AC_IDEN');
yy_actionName.push(Tokenize.Name.$$, 'AC_NEWLINE');
yy_actionName.push(Tokenize.Name.$$, 'AC_SPACE');
yy_actionName.push(Tokenize.Name.$$, 'AC_ANY');
yy_actionName.push(Tokenize.Name.$$, 'AC_MCOMM_END');
yy_actionName.push(Tokenize.Name.$$, 'AC_MCOMM_NL');
yy_actionName.push(Tokenize.Name.$$, 'AC_MCOMM_ANY');
yy_actionName.push(Tokenize.Name.$$, 'AC_SCOMM_END');
yy_actionName.push(Tokenize.Name.$$, 'AC_SCOMM_ANY');

/** Global && check ... */
yy_actionName.push(-1, '$DEFAULT');
console.assert(yy_stateName.length  === 6);
console.assert(yy_eventName.length  === 0);
console.assert(yy_actionName.length === 60);


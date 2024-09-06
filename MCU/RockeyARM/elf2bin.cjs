const fs = require("fs");
const crypto = require("crypto");
const rLANG_MATRIX_TEXT_OFFSET = 0;
const rlTXT_SIZEMAX = 65520;
const rlFillHeader = true;
const rlPaddingFile = process.argv[4] === "--padding-file";

function err(m) {
  throw new Error(m);
}

if (process.argv.length !== 4 && process.argv.length !== 5)
  err(`usage: node  elf2bin.js $input $output`);

function writeString(buf, off, s) {
  const sBuf = Buffer.from(s);
  for (let i = 0; i < sBuf.length; ++i) buf[off + i] = sBuf[i];
}

function Elf32_Ehdr(v) {
  if (v.readUInt32BE(0) !== 0x7f454c46) err("Invalid ELF header.");

  return {
    e_ident: v.subarray(0, 16),
    e_type: v.readUInt16LE(16),
    e_machine: v.readUInt16LE(18),
    e_version: v.readUInt32LE(20),
    e_entry: v.readUInt32LE(24),
    e_phoff: v.readUInt32LE(28),
    e_shoff: v.readUInt32LE(32),
    e_flags: v.readUInt32LE(36),
    e_ehsize: v.readUInt16LE(40),
    e_phentsize: v.readUInt16LE(42),
    e_phnum: v.readUInt16LE(44),
    e_shentsize: v.readUInt16LE(46),
    e_shnum: v.readUInt16LE(48),
    e_shstrndx: v.readUInt16LE(50),
  };
}

function Elf32_Phdr(v) {
  return {
    p_type: v.readUInt32LE(0),
    p_offset: v.readUInt32LE(4),
    p_vaddr: v.readUInt32LE(8),
    p_paddr: v.readUInt32LE(12),
    p_filesz: v.readUInt32LE(16),
    p_memsz: v.readUInt32LE(20),
    p_flags: v.readUInt32LE(24),
    p_align: v.readUInt32LE(28),
  };
}

function Elf2BIN(elfFILE) {
  const ET_EXEC = 2;
  const EM_ARM = 0x28;

  function get(off, size) {
    if (off < 0 || size < 0 || off + size > elfFILE.length || off % 4 !== 0)
      err("invalid offset/size");
    return elfFILE.subarray(off, off + size);
  }

  let eHdr = Elf32_Ehdr(get(0, 52));
  if (eHdr.e_type !== ET_EXEC || eHdr.e_machine !== EM_ARM)
    err(`Invalid ELF file.`);

  if (eHdr.e_phnum !== 1) {
    /* check ldscript ... */
    /***
    let inv = true;
    if (eHdr.e_phnum === 2) {
      const ePHdrData = Elf32_Phdr(get(eHdr.e_phoff + 32, 32));
      if (
        ePHdrData.p_vaddr === 0x68001400 &&
        ePHdrData.p_memsz === 0x14 &&
        ePHdrData.p_filesz === 0
      )
        inv = false;
    }

    if (inv) err(`Invalid ELF file`);
    ***/
  }

  let ePHdrText = Elf32_Phdr(get(eHdr.e_phoff, 32));
  if (
    ePHdrText.p_vaddr !== rLANG_MATRIX_TEXT_OFFSET ||
    ePHdrText.p_flags !== 5 ||
    ePHdrText.p_filesz !== ePHdrText.p_memsz ||
    ePHdrText.p_memsz > rlTXT_SIZEMAX
  )
    err("Invalid .text segment.");

  let binary = get(ePHdrText.p_offset, ePHdrText.p_memsz);
  if (rlFillHeader) crypto.randomBytes(60).copy(binary, 4);

  if (rlPaddingFile)
    binary = Buffer.concat([
      binary,
      crypto.randomBytes(rlTXT_SIZEMAX - binary.length),
    ]);

  binary.writeUint32LE(binary.length, 4);

  return binary;
}

const elfFILE = fs.readFileSync(process.argv[2]);
fs.writeFileSync(process.argv[3], Elf2BIN(elfFILE));

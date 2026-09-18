/* run-varargs.cc —— 把真 toolchain 编出来的 guest ELF 装进 VM_t 跑起来, 验证可变参数约定。
 *
 * 组成:
 *   ① 极简 ELF32/LE/RISC-V 装载器 (读 program header, 把 PT_LOAD 拷到 p_paddr, bss 清零),
 *      并从 .symtab 里找全局符号 `g` 的地址 —— 说明"如何把 toolchain 的产物放进我们的内存映射";
 *   ② 按**最终内存映射**实现的宿主 IMPL (低 64K 不映射 / 映像 576K / 设备区 / 只读区 / 栈 64K);
 *   ③ 断言: 程序以 ecall(SIGILL) 结束, 且 g[] 与**宿主编译同一份源码**得到的结果逐个相同。
 *
 * 用法: run-varargs.exe <varargs.elf>
 */
#include <base/base.h>
#include "rv32im-atomic.hpp"
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

using u32 = std::uint32_t;

/* ---------------- 内存映射常量 (与最终版一致) ---------------- */
static constexpr u32 kImgBase = 0x00010000u, kImgEnd = 0x000A0000u;  /* 程序映像 576K */
static constexpr u32 kDevEnd = 0x000F0000u;                          /* 可写设备区 0xA0000-0xEFFFF */
static constexpr u32 kRomEnd = 0x00100000u;                          /* 只读区 0xF0000-0xFFFFF */
static constexpr u32 kStackBase = 0x00100000u, kStackEnd = 0x00110000u;
static constexpr u32 kSp0 = 0x0010FFE0u;
static constexpr u32 kMemTop = 0x00110000u;

static std::vector<std::uint8_t> g_mem;   /* [0x00000, 0x110000) 的宿主后备内存 */

/* ---------------- 极简 ELF32 装载 ---------------- */
struct Elf32_Ehdr {
  std::uint8_t e_ident[16]; std::uint16_t e_type, e_machine; std::uint32_t e_version;
  std::uint32_t e_entry, e_phoff, e_shoff, e_flags;
  std::uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
};
struct Elf32_Phdr {
  std::uint32_t p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align;
};
struct Elf32_Shdr {
  std::uint32_t sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize;
};
struct Elf32_Sym {
  std::uint32_t st_name, st_value, st_size; std::uint8_t st_info, st_other; std::uint16_t st_shndx;
};

static std::vector<std::uint8_t> slurp(const char* path) {
  std::vector<std::uint8_t> v;
  FILE* f = std::fopen(path, "rb");
  if (!f) return v;
  std::fseek(f, 0, SEEK_END);
  const long n = std::ftell(f);
  std::fseek(f, 0, SEEK_SET);
  v.resize(static_cast<std::size_t>(n));
  const std::size_t got = std::fread(v.data(), 1, v.size(), f);
  std::fclose(f);
  if (got != v.size()) v.clear();
  return v;
}

int main(int argc, char** argv) {
  const char* elfPath = (argc > 1) ? argv[1] : "varargs.elf";
  const std::vector<std::uint8_t> elf = slurp(elfPath);
  if (elf.size() < sizeof(Elf32_Ehdr)) { std::printf("读不到 %s\n", elfPath); return 2; }

  const Elf32_Ehdr* eh = reinterpret_cast<const Elf32_Ehdr*>(elf.data());
  if (eh->e_ident[0] != 0x7f || eh->e_ident[1] != 'E' || eh->e_ident[4] != 1 /*ELFCLASS32*/) {
    std::printf("不是 ELF32: %s\n", elfPath); return 2;
  }

  g_mem.assign(kMemTop, 0);

  /* ① 装载 PT_LOAD 段 */
  int loaded = 0;
  u32 entry = eh->e_entry;
  for (unsigned i = 0; i < eh->e_phnum; ++i) {
    const Elf32_Phdr* ph = reinterpret_cast<const Elf32_Phdr*>(elf.data() + eh->e_phoff + i * eh->e_phentsize);
    if (ph->p_type != 1 /*PT_LOAD*/) continue;
    const u32 dst = ph->p_paddr ? ph->p_paddr : ph->p_vaddr;
    if (dst + ph->p_memsz > kMemTop || ph->p_offset + ph->p_filesz > elf.size()) { std::printf("段越界\n"); return 2; }
    std::memcpy(g_mem.data() + dst, elf.data() + ph->p_offset, ph->p_filesz);
    if (ph->p_memsz > ph->p_filesz) std::memset(g_mem.data() + dst + ph->p_filesz, 0, ph->p_memsz - ph->p_filesz);
    std::printf("  PT_LOAD vaddr=0x%05X filesz=%u memsz=%u flags=%u\n", dst, ph->p_filesz, ph->p_memsz, ph->p_flags);
    ++loaded;
  }
  if (!loaded) { std::printf("没有 PT_LOAD\n"); return 2; }

  /* ② 从 .symtab 里找 `g` */
  u32 gAddr = 0;
  for (unsigned i = 0; i < eh->e_shnum; ++i) {
    const Elf32_Shdr* sh = reinterpret_cast<const Elf32_Shdr*>(elf.data() + eh->e_shoff + i * eh->e_shentsize);
    if (sh->sh_type != 2 /*SHT_SYMTAB*/) continue;
    const Elf32_Shdr* str = reinterpret_cast<const Elf32_Shdr*>(elf.data() + eh->e_shoff + sh->sh_link * eh->e_shentsize);
    for (unsigned k = 0; k * sh->sh_entsize < sh->sh_size; ++k) {
      const Elf32_Sym* sy = reinterpret_cast<const Elf32_Sym*>(elf.data() + sh->sh_offset + k * sh->sh_entsize);
      const char* nm = reinterpret_cast<const char*>(elf.data() + str->sh_offset + sy->st_name);
      if (0 == std::strcmp(nm, "g")) gAddr = sy->st_value;
    }
  }
  if (!gAddr) { std::printf("符号 g 未找到\n"); return 2; }
  std::printf("  entry=0x%05X  g=0x%05X\n", entry, gAddr);

  /* ③ 宿主 IMPL: 最终内存映射 + ecall 停机 */
  struct Impl : machine::hyper::VM_t<Impl> {
    static bool inImg(u32 a, u32 n) { return a >= kImgBase && (static_cast<std::uint64_t>(a) + n) <= kImgEnd; }
    static bool inStack(u32 a, u32 n) { return a >= kStackBase && (static_cast<std::uint64_t>(a) + n) <= kStackEnd; }
    static bool inDev(u32 a, u32 n) { return a >= kImgEnd && (static_cast<std::uint64_t>(a) + n) <= kDevEnd; }
    static bool inRom(u32 a, u32 n) { return a >= kDevEnd && (static_cast<std::uint64_t>(a) + n) <= kRomEnd; }

    u32 get(u32 a, int n) { u32 v = 0; for (int i = 0; i < n; ++i) v |= (u32)g_mem[a + i] << (8 * i); return v; }
    void set(u32 a, u32 v, int n) { for (int i = 0; i < n; ++i) g_mem[a + i] = (std::uint8_t)(v >> (8 * i)); }

    int if_CODE(libmb_t pc, libmb_t* op) {              /* 只有映像区可执行 */
      if (!inImg(pc, 4) || (pc & 3u)) return SIGSEGV;
      *op = get(pc, 4); return 0;
    }
    int mm_LB (libmb_t a, reg_t* v) { if (inImg(a,1)||inStack(a,1)) { v->iv = (int8_t)get(a,1); return 0; } if (inDev(a,1)) { v->uv = 0x00u; return 0; } if (inRom(a,1)) { v->uv = 0u; return 0; } return SIGSEGV; }
    int mm_LBU(libmb_t a, reg_t* v) { if (inImg(a,1)||inStack(a,1)) { v->uv = get(a,1);      return 0; } if (inDev(a,1)) { v->uv = 0x00u; return 0; } if (inRom(a,1)) { v->uv = 0u; return 0; } return SIGSEGV; }
    int mm_LH (libmb_t a, reg_t* v) { if ((a & 1u)) return SIGSEGV; if (inImg(a,2)||inStack(a,2)) { v->iv = (int16_t)get(a,2); return 0; } return SIGSEGV; }
    int mm_LHU(libmb_t a, reg_t* v) { if ((a & 1u)) return SIGSEGV; if (inImg(a,2)||inStack(a,2)) { v->uv = get(a,2); return 0; } return SIGSEGV; }
    int mm_LW (libmb_t a, reg_t* v) {
      if (a & 3u) return SIGSEGV;
      if (inImg(a,4)||inStack(a,4)) { v->uv = get(a,4); return 0; }
      if (inDev(a,4)) { v->uv = 0x55AAFF00u; return 0; }   /* 设备不存在: 按 4 字节重复填充 */
      if (inRom(a,4)) { v->uv = 0u; return 0; }             /* 只读区读出无定义 */
      return SIGSEGV;
    }
    int mm_SB (libmb_t a, libmb_t v) { if (inImg(a,1)||inStack(a,1)) { set(a,v,1); return 0; } if (inDev(a,1)) return 0; return SIGSEGV; }
    int mm_SH (libmb_t a, libmb_t v) { if ((a & 1u)) return SIGSEGV; if (inImg(a,2)||inStack(a,2)) { set(a,v,2); return 0; } if (inDev(a,2)) return 0; return SIGSEGV; }
    int mm_SW (libmb_t a, libmb_t v) { if ((a & 3u)) return SIGSEGV; if (inImg(a,4)||inStack(a,4)) { set(a,v,4); return 0; } if (inDev(a,4)) return 0; return SIGSEGV; }
    int op_GATE(int) { return -ENOSYS; }                     /* 本程序不用门 */
  };

  Impl vm;
  Impl::hart_t hart{};
  hart.pc_ = entry;
  hart.regs_.sp.uv = kSp0;      /* 契约: 入口 sp == 0x10FFE0 (guest 的 _start 也会自己设一次) */
  hart.Enable();
  const int rc = vm.Execv(&hart, 1 << 20);

  /* 期望值 = **宿主编译同一份源码**跑出来的 g[0..6] (整数/指针/double 位模式都是目标无关的);
     g[7] 例外: 它 XOR 的是 `long double` 的字节 —— 那是**目标相关**的:
       RISC-V ilp32: `long double` = binary128 (实测 __LDBL_MANT_DIG__=113, __SIZEOF_LONG_DOUBLE__=16)
                     => 3.25L = 0x4000A000_00000000_00000000_00000000 (sign 0, exp 0x4000, 尾数 1.101b)
                     => 四个 32 位字 XOR = 0x4000A000 = 1073782784  ← ELF 的 .rodata 实测就是这 16 字节
       x86-64/cygwin: `long double` = 80 位扩展 (16 字节存储, 有 6 字节填充) => 3489677312, **不可比**  */
  const u32 expect[24] = {21u, 45u, 6u, 15u, 21u, 300u, 4294705152u, 0x4000A000u, 0u, 0u,
                          100u, 200u, 0,0,0,0,0,0,0,0,0,0,0,0};
  int fail = 0;
  std::printf("rc=%d (期望 %d=SIGILL, 来自结尾的 ecall)  pc=0x%05X  sp=0x%05X  cycles=%llu+%u\n",
              rc, (int)SIGILL, hart.pc_, hart.regs_.sp.uv,
              (unsigned long long)hart.cycles_, (unsigned)hart.cyc_);
  if (rc != SIGILL) { std::printf("  FAIL  程序没有正常结束 (rc != SIGILL)\n"); ++fail; }
  else std::printf("  PASS  程序以 ecall 结束 (VM 的 op_ECALL 默认返回 SIGILL)\n");

  for (int i = 0; i < 24; ++i) {
    u32 got = 0;
    for (int k = 0; k < 4; ++k) got |= (u32)g_mem[gAddr + 4 * i + k] << (8 * k);
    if (got != expect[i]) {
      if (expect[i] || got) { std::printf("  FAIL  g[%d] = %u (期望 %u)\n", i, got, expect[i]); ++fail; }
    }
  }
  if (!fail) std::printf("  PASS  g[0..7] 与宿主编译同一份源码的结果逐个相同 (21/45/6/15/21/300/0x4000A000);\n"
                         "        其中 g[7] 取的是**目标侧** binary128 的位模式 (宿主 x86 的 80 位 long double 不可比)\n");
  std::printf("\n%s (failures=%d)\n", fail ? "有失败" : "全部通过", fail);
  return fail;
}

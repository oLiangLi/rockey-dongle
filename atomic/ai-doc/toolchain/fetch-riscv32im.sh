#!/bin/sh
#
# ATOMC / RV32IM —— 超项目最小子集获取 + 工具链构建
#
# 基准 tag: 2026.06.06(超项目上 2026.06.06 / 2026.06.05 为带签名的两个版本)
#
# 设计原则:
#   ① 只克隆超项目本身, 不取任何子模块;
#   ② 只显式取"我们需要"的子模块, 全部 shallow(--depth 1);
#   ③ 其余子模块永不主动下载 —— 让 make 的惰性自动 init 规则按构建图需要去取;
#   ④ 全程打印"该 tag 声明了什么 / 实际取了什么 / 各占多少体积", 便于审计。
#
# 用法:
#   sh fetch-riscv32im.sh            # 只获取 + 报告
#   sh fetch-riscv32im.sh --build    # 获取后继续构建 binutils + gcc(stage1) + libgcc
#
# 环境变量: TAG / SRC / PREFIX / JOBS
#
set -eu

TAG="${TAG:-2026.06.06}"
SRC="${SRC:-$HOME/MyWork/RISCV/riscv-gnu-toolchain}"
PREFIX="${PREFIX:-$HOME/opt/riscv32im}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"
REPO="https://github.com/riscv-collab/riscv-gnu-toolchain"

# 我们要显式取的三个子模块(理由见 README 的最小集表)
WANTED="binutils gcc musl"

say() { printf '\n=== %s ===\n' "$*"; }

# ---------------------------------------------------------------- ① 超项目本体
say "① 克隆超项目本体 @ $TAG(不取子模块)"
if [ -d "$SRC/.git" ]; then
  echo "已存在, 跳过: $SRC"
else
  # 不加 --recurse-submodules: 缺省即不取任何子模块
  git clone --depth 1 --branch "$TAG" --no-recurse-submodules "$REPO" "$SRC"
fi
cd "$SRC"
echo "HEAD = $(git rev-parse --short HEAD)"

# ---------------------------------------------------------------- ② tag 签名
say "② 校验 tag 签名"
if git tag -v "$TAG" >/dev/null 2>&1; then
  echo "OK: $TAG 签名已验证"
  git tag -v "$TAG" 2>&1 | sed 's/^/  /'
else
  echo "[warn] 无法验证 $TAG 签名 —— 通常是因为签名者公钥不在 keyring 中。"
  echo "       请人工确认(或导入公钥后重试): git tag -v $TAG"
fi

# ---------------------------------------------------------------- ③ 最小子集
say "③ 取最小子集: $WANTED"
# shellcheck disable=SC2086
git submodule update --init --depth 1 $WANTED

# ---------------------------------------------------------------- ④ 审计报告
say "④-a .gitmodules 在该 tag 下声明的全部子模块"
git config -f .gitmodules --get-regexp '^submodule\..*\.path$' 2>/dev/null \
  | awk '{print "  " $2}' || echo "  (无, 或该 tag 无 .gitmodules)"

say "④-b 实际已取的子模块"
git submodule status | sed 's/^/  /'

say "④-c 各目录体积(找到没必要的下载就删掉)"
du -sh -- * 2>/dev/null | sort -h | sed 's/^/  /'

say "④-d 该 tag 的真实组件版本(请回填到方案文档的 pin 表)"
[ -f gcc/gcc/BASE-VER ] \
  && echo "  gcc        : $(cat gcc/gcc/BASE-VER)" \
  || echo "  gcc        : (未取)"
if [ -f binutils/bfd/version.h ]; then
  echo "  binutils   : $(sed -n 's/.*BFD_VERSION_STRING "\(.*\)".*/\1/p' binutils/bfd/version.h)"
else
  echo "  binutils   : (未取)"
fi
[ -f musl/VERSION ] \
  && echo "  musl       : $(cat musl/VERSION)" \
  || echo "  musl       : (未取)"
## pin 的正确查法: `git rev-parse HEAD:<path>`。
## 反例: `git -C <path> rev-parse HEAD` —— 子模块未检出时那只是个空目录,
## git 会向上找到【超项目自己】的 HEAD, 打印出看似合理其实错误的结果。
for m in binutils gcc musl; do
  printf '  %-9s pin(HEAD 记录) : %s\n' "$m" "$(git rev-parse "HEAD:$m" 2>/dev/null || echo '-')"
  if [ -f "$m/.git" ] || [ -d "$m/.git" ]; then
    printf '  %-9s 已检出 commit   : %s\n' "$m" "$(git -C "$m" rev-parse HEAD)"
  else
    printf '  %-9s 已检出 commit   : (未取)\n' "$m"
  fi
done

# ---------------------------------------------------------------- ⑤ 可选构建
if [ "${1:-}" = "--build" ]; then
  say "⑤ 构建 binutils + gcc(stage1) + libgcc(不含 libc)"
  # 只构建 stage1: 官方规则即 --with-newlib --without-headers, 产出 gcc + libgcc, 不含任何 libc
  # 目标三元组必须用 riscv32-unknown-elf(裸机), 不能用 riscv32-unknown-linux-musl(那是 Linux 三元组)
  ./configure \
    --prefix="$PREFIX" \
    --target=riscv32-unknown-elf \
    --with-arch=rv32im \
    --with-abi=ilp32 \
    --with-cmodel=medlow \
    --disable-multilib
  make -j"$JOBS" build-binutils build-gcc1

  say "⑤-b 验收"
  "$PREFIX/bin/riscv32-unknown-elf-gcc" -march=rv32im -mabi=ilp32 \
    -print-multi-lib -print-libgcc-file-name
  echo "-- 以下必须【没有】 __linux__ / __unix__ --"
  "$PREFIX/bin/riscv32-unknown-elf-gcc" -march=rv32im -mabi=ilp32 -dM -E - </dev/null \
    | grep -E 'riscv|linux|unix' || true
  echo "-- 以下应显示 __riscv_mul__ / __riscv_div__ 且不应有 __riscv_f__ / __riscv_d__ --"
  "$PREFIX/bin/riscv32-unknown-elf-gcc" -march=rv32im -mabi=ilp32 -dM -E - </dev/null \
    | grep -E '__riscv_(xlen|mul|div|f|d|c)__' || true
fi

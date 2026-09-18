#!/bin/sh
#
# 把 riscv-gnu-toolchain 精简为 ATOMC / RV32IM 所需的最小子集
#
# 做法: 在我们自己的分支(rLANG-2026.06.06)上重写 .gitmodules, 只保留需要的子模块,
#       并把其余子模块的 gitlink 从索引中移除。于是 `git submodule update --init --recursive`
#       也只可能取到最小子集 —— 精简成为分支的结构性属性, 而不是靠每次传 allow-list。
#
# 最小子集(为什么是这三个, 见同目录 README.md):
#   binutils / gcc  构建图需要(gcc 同时是 soft-fp 运行时源码来源)
#   musl            构建图不需要, 但我们 vendoring 其源码需要
#
# 可重复执行: 子模块清单取自【索引里的 gitlink】, 而不是取自 .gitmodules ——
#   因此本脚本在已经剪过的树上再跑、或在并入新上游 tag 之后再跑, 都成立。
#
# 两个已踩过的坑(勿回退):
#   ① 必须先改完 .gitmodules 并 `git add` 再移除 gitlink; 否则 git 会拒绝:
#      "fatal: please stage your changes to .gitmodules or stash them to proceed"
#   ② 查子模块 pin 必须用 `git rev-parse HEAD:<path>`。子模块目录通常是空目录,
#      `git -C <path> rev-parse HEAD` 会向上找到【超项目自己】的 HEAD, 打印出错误结果。
#
# 用法:
#   sh prune-submodules.sh                 # 剪枝 .gitmodules + 移除 gitlink(不动工作区目录, 不提交)
#   PRUNE_DIRS=1 sh prune-submodules.sh    # 同时删除已检出的无关目录(释放体积)
#   COMMIT=1 sh prune-submodules.sh        # 剪枝后自动提交(默认不提交, 便于复核/签名)
#
# 环境变量: SRC / TAG / BRANCH / KEEP / PRUNE_DIRS / COMMIT
#
set -eu

SRC="${SRC:-$HOME/MyWork/RISCV/riscv-gnu-toolchain}"
TAG="${TAG:-2026.06.06}"
BRANCH="${BRANCH:-rLANG-$TAG}"
KEEP="${KEEP:-binutils gcc musl}"

cd "$SRC" 2>/dev/null || { echo "!! 找不到: $SRC"; exit 1; }

cur=$(git rev-parse --abbrev-ref HEAD)
if [ "$cur" != "$BRANCH" ]; then
  echo "!! 当前分支为 '$cur', 预期 '$BRANCH'。"
  echo "   切过去:  git switch $BRANCH"
  echo "   或覆盖:  BRANCH=$cur sh $0"
  exit 1
fi

[ -f .gitmodules ] || { echo "!! 该分支无 .gitmodules"; exit 1; }

## 备份上游 .gitmodules(仅一次), 并让 git 忽略这个备份文件
if [ ! -f .gitmodules.upstream ]; then
  cp .gitmodules .gitmodules.upstream
  echo "已备份: .gitmodules.upstream"
fi
grep -qxF '.gitmodules.upstream' .git/info/exclude 2>/dev/null \
  || echo '.gitmodules.upstream' >> .git/info/exclude

is_kept() {
  case " $KEEP " in
    *" $1 "*) return 0 ;;
    *)        return 1 ;;
  esac
}

## 子模块清单取自索引的 gitlink(而非 .gitmodules) —— 使本脚本可重复执行
gl=$(mktemp)
trap 'rm -f "$gl"' EXIT
git ls-files --stage | awk '$1 == "160000" { print $4 }' > "$gl"
ngl=$(wc -l < "$gl" | tr -d ' ')

echo
echo "=== 索引中的 gitlink (共 $ngl 个) ==="
sed 's/^/  /' "$gl"

# ---------------------------------------------------------------- 第 1 趟: 剪 .gitmodules
echo
echo "=== 第 1 趟: 从 .gitmodules 移除不需要的声明 ==="
for path in $(cat "$gl"); do
  if is_kept "$path"; then
    echo "  KEEP   $path"
    continue
  fi
  # 该 path 在 .gitmodules 里对应的 section 名
  name=$(git config -f .gitmodules --get-regexp '^submodule\..*\.path$' 2>/dev/null \
         | awk -v p="$path" '$2 == p { sub(/^submodule\./, "", $1); sub(/\.path$/, "", $1); print $1 }')
  if [ -n "$name" ]; then
    git config -f .gitmodules --remove-section "submodule.$name" 2>/dev/null || true
    echo "  PRUNE  $path  (section: $name)"
  else
    echo "         $path  (.gitmodules 中已无声明, 跳过)"
  fi
done

## 关键: 先把 .gitmodules 的改动 stage 住, 否则第 2 趟的 git rm --cached 会被 git 拒绝
git add .gitmodules
echo "  已 stage .gitmodules"

# ---------------------------------------------------------------- 第 2 趟: 移除 gitlink
echo
echo "=== 第 2 趟: 从索引移除 gitlink ==="
for path in $(cat "$gl"); do
  if is_kept "$path"; then
    echo "  KEEP   $path"
    continue
  fi
  if git ls-files --stage -- "$path" | grep -q '^160000'; then
    git rm -q --cached "$path" && echo "  已移除 gitlink $path"
  else
    echo "         $path  (索引中已无 gitlink, 跳过)"
  fi

  if [ "${PRUNE_DIRS:-0}" = "1" ]; then
    case "$path" in
      ""|.|..|/*|*..*)
        echo "    !! 跳过可疑路径, 未删除: '$path'" ;;
      *)
        [ -e "$path" ] && { rm -rf -- "$path"; echo "    已删除目录 $path"; } ;;
    esac
  fi
done

# ---------------------------------------------------------------- 报告
echo
echo "=== 剪枝后: .gitmodules 声明的子模块 ==="
git config -f .gitmodules --get-regexp '^submodule\..*\.path$' 2>/dev/null | sed 's/^/  /' \
  || echo "  (空)"

echo
echo "=== 剪枝后: 索引中的 gitlink ==="
git ls-files --stage | awk '$1 == "160000" { print "  " $4 }'

echo
echo "=== 保留项在 HEAD 上记录的 pin (正确方法: HEAD:<path>) ==="
for m in $KEEP; do
  printf '  %-10s %s\n' "$m" "$(git rev-parse "HEAD:$m" 2>/dev/null || echo '(HEAD 无此路径)')"
done

echo
echo "=== git status ==="
git status --short

if [ "${COMMIT:-0}" = "1" ]; then
  git add .gitmodules
  git commit --no-gpg-sign -m "prune submodules to ATOMC/RV32IM minimal subset: $KEEP"
else
  echo
  echo "未提交。建议:"
  echo "  git add .gitmodules"
  echo "  git commit --no-gpg-sign -m 'prune submodules to ATOMC/RV32IM minimal subset: $KEEP'"
  echo "(本仓分支为 $BRANCH, 不属 feat/AGINX/* —— 是否改用签名提交由你决定;"
  echo " 规范见 ai-doc 方案 §11: feat/AGINX/* 一律无签名。)"
fi

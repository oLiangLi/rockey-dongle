#!/bin/sh
#
# 为 ATOMC / RV32IM 所需的最小源码集合建立本地镜像仓库
#
# 设计要点:
#   ① 只镜像"我们真的要编译的"仓库 —— 超项目本体 + binutils + gcc + musl;
#   ② 每个子模块精确镜像到【超项目在 TAG 上 pin 的那个 commit】(gitlink),
#      而不是分支 tip —— 否则 `git submodule update` 取不到 pin 的 commit;
#   ③ 镜像里保持"上游 URL"这一事实不变: 客户端用 git 的 url.<base>.insteadOf
#      把 https://github.com/... 重定向到本地镜像。这样 .gitmodules 不必改,
#      分支仍可被他人/CI 用上游地址克隆。
#   ④ 默认只取 --depth 1(体积最小); 需要完整历史时用 FULL=1。
#
# 用法:
#   sh mirror-riscv32im.sh              # 建立/刷新镜像, 并打印客户端配置命令
#   FULL=1 sh mirror-riscv32im.sh       # 镜像完整历史(体积大得多)
#
# 环境变量: SRC / TAG / MIRROR / FULL
#
set -eu

SRC="${SRC:-$HOME/MyWork/RISCV/riscv-gnu-toolchain}"
TAG="${TAG:-2026.06.06}"
MIRROR="${MIRROR:-$HOME/git-mirror/riscv32im}"
FULL="${FULL:-0}"

# 最小子集 —— 与 prune-submodules.sh 的 KEEP 必须一致
SUBS="binutils gcc musl"
# 超项目本体在镜像里的目录名
SUPER_NAME="riscv-gnu-toolchain.git"
SUPER_URL="https://github.com/riscv-collab/riscv-gnu-toolchain"

say() { printf '\n=== %s ===\n' "$*"; }

[ -d "$SRC/.git" ] || { echo "!! 找不到超项目: $SRC"; exit 1; }
mkdir -p "$MIRROR"

## 从 TAG 读出各子模块的上游 URL 与 pin 的 commit —— 不依赖任何网络, 也不用我猜
tmpgm=$(mktemp); trap 'rm -f "$tmpgm"' EXIT
git -C "$SRC" show "$TAG:.gitmodules" > "$tmpgm"

say "① 镜像超项目本体"
if [ -d "$MIRROR/$SUPER_NAME" ]; then
  git -C "$MIRROR/$SUPER_NAME" remote update --prune
else
  git clone --mirror "$SUPER_URL" "$MIRROR/$SUPER_NAME"
fi
git -C "$MIRROR/$SUPER_NAME" update-server-info

say "② 镜像最小子集(精确到 pin 的 commit)"
for name in $SUBS; do
  url=$(git config -f "$tmpgm" --get "submodule.$name.url" || true)
  [ -n "$url" ] || { echo "  !! $name: 在 $TAG 的 .gitmodules 里没有该子模块, 跳过"; continue; }

  pin=$(git -C "$SRC" rev-parse "$TAG:$name" 2>/dev/null || true)
  dst="$MIRROR/$(basename "$url" .git).git"

  echo "  --- $name"
  echo "      upstream : $url"
  echo "      pinned   : ${pin:-<未知>}"
  echo "      mirror   : $dst"

  [ -d "$dst" ] || git init --bare -q "$dst"

  # 服务端需要允许按任意(可达的) SHA 取对象, 否则客户端按 pin 的 commit 取不到
  git -C "$dst" config uploadpack.allowAnySHA1InWant true
  git -C "$dst" config uploadpack.allowFilter true
  git -C "$dst" config uploadpack.allowTipSHA1InWant true
  git -C "$dst" config uploadpack.allowReachableSHA1InWant true

  if [ "$FULL" = "1" ]; then
    git -C "$dst" fetch --prune --tags "$url" '+refs/heads/*:refs/heads/*'
  else
    # 先按分支 shallow 取(便宜), 再确认 pin 的 commit 已到位
    git -C "$dst" fetch --depth 1 --no-tags "$url" '+refs/heads/*:refs/heads/*' || true
    if [ -n "$pin" ] && ! git -C "$dst" cat-file -e "$pin^{commit}" 2>/dev/null; then
      echo "      pin 不在 shallow 历史里, 按该 commit 直接补取"
      git -C "$dst" fetch --depth 1 --no-tags "$url" "$pin" || {
        echo "      !! 直接按 SHA 取失败 —— 用 FULL=1 重跑本脚本(取完整历史)"; }
    fi
  fi

  # 把 pin 挂到一个具名分支, 便于客户端普通 fetch 也能命中
  if [ -n "$pin" ] && git -C "$dst" cat-file -e "$pin^{commit}" 2>/dev/null; then
    git -C "$dst" update-ref "refs/heads/rLANG-pin-$TAG" "$pin"
    echo "      OK: $pin 已镜像并挂到 refs/heads/rLANG-pin-$TAG"
  else
    echo "      [warn] $pin 仍未镜像到位"
  fi
  git -C "$dst" update-server-info
done

say "③ 镜像体积"
du -sh "$MIRROR"/* 2>/dev/null | sed 's/^/  /'

## 客户端侧: 把上游 URL 重定向到本地镜像(改本地 git 配置, 不改 .gitmodules)
say "④ 客户端配置 —— 让 .gitmodules 里的上游 URL 自动走本地镜像"
echo "  # 在本仓检出上执行(写成 --global 也可以):"
echo
for name in $SUBS; do
  url=$(git config -f "$tmpgm" --get "submodule.$name.url" || true)
  [ -n "$url" ] || continue
  base="$MIRROR/$(basename "$url" .git).git"
  echo "  git config url.\"file://$base\".insteadOf \"$url\""
done
echo "  git config url.\"file://$MIRROR/$SUPER_NAME\".insteadOf \"$SUPER_URL\""
echo
echo "  # 校验重定向生效(应打印 file:// 路径):"
echo "  git config --get-regexp '^url\\.' "
echo
echo "  # 之后正常的子模块取用会走镜像:"
echo "  git submodule update --init --depth 1 $SUBS"

say "⑤ 若要用 HTTP 提供镜像(而非 file://)"
echo "  cd $MIRROR && python3 -m http.server 8080"
echo "  # 然后把上面的 file://... 换成 http://127.0.0.1:8080/... "
echo "  # 注: dumb-http 依赖各裸仓里的 info/refs —— 本脚本已对每个仓跑过 update-server-info。"

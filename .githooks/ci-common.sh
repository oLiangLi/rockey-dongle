#!/bin/sh
# .githooks/ci-common.sh — post-merge / post-commit 共享: 在 squash merge 后自动跑 CI 快速回归
# 环境: CI_SKIP_RUN=1 跳过; CI_STRICT=1 失败即非零(hook 非阻塞默认: 失败也 exit 0 但打印)
repo="$(git rev-parse --show-toplevel 2>/dev/null)" || exit 0
[ -n "$repo" ] || exit 0
cd "$repo" || exit 0
[ -x "$(command -v node)" ] || { echo "[ci-hook] node 不可用, 跳过"; exit 0; }

## 子模块未初始化时给出可操作提示(base/Build 已改为 submodule)
## 判据用共享构建仓的入口文件 Build/Main.mk —— CI 工具本身已于 2026-09-14 迁入本仓 tools/rockey/LIMIT/ci/
if [ ! -f "$repo/Build/Main.mk" ]; then
  echo "[ci-hook] 子模块未初始化(Build/Main.mk 缺失) — 请先执行: git submodule update --init"
  exit 0
fi
[ "${CI_SKIP_RUN:-0}" = "1" ] && { echo "[ci-hook] CI_SKIP_RUN=1 跳过"; exit 0; }

last=".git/rlang-ci-last"
head="$(git rev-parse HEAD 2>/dev/null)"
[ "$(cat "$last" 2>/dev/null)" = "$head" ] && { echo "[ci-hook] $head 已跑过, 跳过"; exit 0; }

## 关键(GNUPGHOME 的形态, 2026-10-12 定位): MSYS2 会把 POSIX 形态的 GNUPGHOME(本机 /c/Users/liangli/.gnupg)
## 转成 Windows 形态 C:/Users/liangli/.gnupg 再交给原生 node, 而 Git 自带的 gpg 会把后者当**相对路径**:
##   gpg: Fatal: can't create directory '<cwd>/C:/Users/liangli/.gnupg'    (退出码 2)
## ⇒ G1 报"执行失败"; %G? 对全部提交报 N(实测 311 条, 其中 110 条带 gpgsig) ⇒ G3 的防假绿判据命中
## ⇒ 钩子自动 CI 假红 failed=2(从普通 PowerShell 跑 make ci 则全绿)。排除本变量即保持 POSIX 形态。
## 实测: 不排除 5/5 失败; 排除后 5/5 通过(单独只加本行 3/3 通过); 只把 RKEY_GPG 固定成 Git 的 gpg 无效(3/3 仍失败)。
## 保留调用方已有的排除项。
export MSYS2_ENV_CONV_EXCL="${MSYS2_ENV_CONV_EXCL:+$MSYS2_ENV_CONV_EXCL;}GNUPGHOME"

echo "[ci-hook] post-merge/post-commit: 自动 CI 快速回归 @ $head ..."
node tools/rockey/LIMIT/ci/run-ci.cjs
rc=$?
echo "$head" > "$last"
if [ "$rc" -ne 0 ]; then
  echo "[ci-hook] CI 回归失败(rc=$rc) — 请查看上方输出或 .bin/ci-log/ 日志"
  [ "${CI_STRICT:-0}" = "1" ] && exit "$rc"
  exit 0
fi
echo "[ci-hook] CI 回归通过"
exit 0

#!/bin/sh
# .githooks/ci-common.sh — post-merge / post-commit 共享: 在 squash merge 后自动跑 CI 快速回归
# 环境: CI_SKIP_RUN=1 跳过; CI_STRICT=1 失败即非零(hook 非阻塞默认: 失败也 exit 0 但打印)
repo="$(git rev-parse --show-toplevel 2>/dev/null)" || exit 0
[ -n "$repo" ] || exit 0
cd "$repo" || exit 0
[ -x "$(command -v node)" ] || { echo "[ci-hook] node 不可用, 跳过"; exit 0; }
[ "${CI_SKIP_RUN:-0}" = "1" ] && { echo "[ci-hook] CI_SKIP_RUN=1 跳过"; exit 0; }

last=".git/rlang-ci-last"
head="$(git rev-parse HEAD 2>/dev/null)"
[ "$(cat "$last" 2>/dev/null)" = "$head" ] && { echo "[ci-hook] $head 已跑过, 跳过"; exit 0; }

echo "[ci-hook] post-merge/post-commit: 自动 CI 快速回归 @ $head ..."
node Build/tools/ci/run-ci.cjs
rc=$?
echo "$head" > "$last"
if [ "$rc" -ne 0 ]; then
  echo "[ci-hook] CI 回归失败(rc=$rc) — 请查看上方输出或 .bin/ci-log/ 日志"
  [ "${CI_STRICT:-0}" = "1" ] && exit "$rc"
  exit 0
fi
echo "[ci-hook] CI 回归通过"
exit 0

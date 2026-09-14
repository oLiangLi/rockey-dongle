#!/usr/bin/env node
/*! 生成各 JS 页面目录下的 jsCommitHash.js, 并同步共享的 jsWorldEvent.js。
 *!  目标目录: Web/Agent/Tests/js(源) 与 mkey/tools/Tests/js(快照副本)。
 *!  jsCommitHash.js 内容: 当前 HEAD 的完整 hash + 预计算的 4 个 32-bit BE 字(SHA256(hash) 前 16B),
 *!  这样浏览器里不需要 SHA256 实现即可复现"世界事件"判据(见 jsWorldEvent.js)。
 *! 两者都被 .gitignore 忽略, 由 `make jsWrapper` 自动生成; 缺失时 jsWorldEvent.js 优雅降级
 *! (CipherLoader 用自带随机), 因此老页面/离线页面不会因此报错。
 */
"use strict";
const fs = require("fs");
const path = require("path");
const cp = require("child_process");

const root = path.resolve(__dirname, "..", "..", "..", "..");
const src = path.join(root, "Web", "Agent", "Tests", "js", "jsWorldEvent.js");
const targets = [
  path.join(root, "Web", "Agent", "Tests", "js"),
  path.join(root, "mkey", "tools", "Tests", "js"),
];

let hash = "unknown";
try {
  hash = cp.execSync("git rev-parse HEAD", { cwd: root, stdio: ["ignore", "pipe", "ignore"] }).toString().trim();
} catch (e) {
  /* 非 git 工作区: 保留 unknown */
}

let words = null;
try {
  words = require(src).WordsOf(hash);
} catch (e) {
  console.error(`[commitHash] 计算 words 失败: ${e && e.message}`);
}

const body =
  `/*! 构建生成(勿手改) —— 由 tools/rockey/LIMIT/script/commitHash.cjs 写出, 见 js/jsWorldEvent.js */\n` +
  `globalThis.jsCommitHash = ${JSON.stringify(hash)};\n` +
  `globalThis.jsCommitWords = ${JSON.stringify(words)};\n`;

for (const dir of targets) {
  if (!fs.existsSync(dir)) continue;
  /* 同步共享实现(mkey 侧是快照副本, 以 Web 侧为唯一源) */
  const dst = path.join(dir, "jsWorldEvent.js");
  if (path.resolve(dst) !== path.resolve(src)) fs.copyFileSync(src, dst);
  const out = path.join(dir, "jsCommitHash.js");
  fs.writeFileSync(out, body);
  console.log(
    `[commitHash] ${hash} words=${words ? words.map((v) => "0x" + (v >>> 0).toString(16)).join(" ") : "null"}` +
      ` -> ${path.relative(root, out)}${path.resolve(dst) !== path.resolve(src) ? ` (+ sync ${path.relative(root, dst)})` : ""}`,
  );
}

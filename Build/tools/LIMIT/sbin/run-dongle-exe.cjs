// 注意: 本脚本不加 #! shebang(Windows 下会报错), 用 node xxx.cjs 调用。
/**
 * run-dongle-exe.cjs —— 先复制再运行测试程序, 避免"正在运行的 exe 无法被构建覆盖"
 * (用户约定 2026-09-11): 任何真机长任务都应通过本工具启动, 让
 * `.bin/amd64-windows-release/__Testing__dongle__.exe` 始终可被增量构建替换。
 *
 * 用法:
 *   node Build/tools/LIMIT/sbin/run-dongle-exe.cjs [--bin <exe>] [--tag <名>] <参数...>
 *
 *   --bin <exe>  源程序(缺省 .bin/amd64-windows-release/__Testing__dongle__.exe)
 *   --tag <名>   副本名后缀(缺省时间戳), 便于回看"当时用的是哪个二进制"
 *
 * 副本落地: .bin/run/<basename>-<tag|时间戳>.exe(不参与构建, .bin 已被忽略)。
 * 环境变量(WT_RKEY_DEVICE / WT_APP_DONGLE 等)与工作目录原样继承, 退出码原样返回。
 */
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const root = path.resolve(__dirname, "../../../..");
const argv = process.argv.slice(2);
let bin = path.join(root, ".bin/amd64-windows-release/__Testing__dongle__.exe");
let tag = null;
const rest = [];
for (let i = 0; i < argv.length; ++i) {
  const a = argv[i];
  if (a === "--bin") {
    bin = path.resolve(root, argv[++i]);
  } else if (a === "--tag") {
    tag = argv[++i];
  } else {
    rest.push(a);
  }
}

if (!fs.existsSync(bin)) {
  console.error(`[run-dongle-exe] 找不到 ${bin}`);
  process.exit(2);
}

const stamp = (tag || new Date().toISOString().replace(/[-:T]/g, "")).replace(/[^0-9A-Za-z_.-]/g, "_");
const dir = path.join(root, ".bin/run");
fs.mkdirSync(dir, { recursive: true });
const copy = path.join(dir, `${path.basename(bin, ".exe")}-${stamp}.exe`);
fs.copyFileSync(bin, copy);

console.log(
  `[run-dongle-exe] ${new Date().toISOString()} bin=${path.relative(root, bin)} ` +
    `copy=${path.relative(root, copy)} args=${JSON.stringify(rest)}`,
);
const res = spawnSync(copy, rest, { stdio: "inherit", cwd: process.cwd() });
console.log(`[run-dongle-exe] exit=${res.status} signal=${res.signal || ""}`);
process.exit(res.status === null ? 1 : res.status);

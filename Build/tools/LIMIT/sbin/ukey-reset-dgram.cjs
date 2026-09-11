// 注意: 本脚本不加 #! shebang(Windows 下会报错), 用 node xxx.cjs 调用。
/**
 * ukey-reset-dgram.cjs — 用 UDP 报文触发 ukey 软复位/恢复(等效拔插)。
 *
 * 用法(必须在【管理员】shell 里运行, 因为 pnputil 需要提权):
 *   node Build/tools/LIMIT/sbin/ukey-reset-dgram.cjs [InstanceId]
 *
 * 默认只允许测试 ukey 的父 USB 实例:
 *   USB\VID_096E&PID_0209\5&2B27CBDF&0&6
 *
 * 监听 127.0.0.1:12345, 报文内容即动作:
 *   restart (或任意其它) -> pnputil /restart-device   (默认; 等效拔插)
 *   cycle                -> /disable-device + /enable-device
 *   scan                 -> /scan-devices             (找回未枚举/Unknown 的设备)
 *   enable / disable     -> /enable-device / /disable-device
 * 每次动作后打印所有 VID_096E 设备状态。
 *
 * 安全: 实例 ID 必须包含 VID_096E&PID_0209, 否则拒绝执行(绝不触碰同厂
 *       PID_020A 智能卡读卡器或其它设备)。
 */
const dgram = require("dgram");
const { execFileSync } = require("child_process");

const PORT = 12345;
const HOST = "127.0.0.1";
const DEFAULT_INSTANCE = "USB\\VID_096E&PID_0209\\5&2B27CBDF&0&6";
const INSTANCE = process.argv[2] || DEFAULT_INSTANCE;

if (!/VID_096E&PID_0209/i.test(INSTANCE)) {
  console.error(`[refuse] 实例 ID 不含 VID_096E&PID_0209, 拒绝: ${INSTANCE}`);
  process.exit(2);
}

function pnputil(args) {
  try {
    console.log(execFileSync("pnputil.exe", args, { encoding: "utf8" }).trim());
  } catch (e) {
    console.error(`pnputil ${args.join(" ")} failed: ${e.message}`);
    if (e.stdout) console.error(String(e.stdout).trim());
    if (e.stderr) console.error(String(e.stderr).trim());
  }
}

function status() {
  try {
    return execFileSync(
      "powershell.exe",
      [
        "-NoProfile",
        "-Command",
        "Get-PnpDevice | Where-Object { $_.InstanceId -match 'VID_096E' } | " +
          "Select-Object Status,InstanceId | Format-Table -AutoSize | Out-String",
      ],
      { encoding: "utf8" },
    ).trim();
  } catch (e) {
    return `<status error: ${e.message}>`;
  }
}

const srv = dgram.createSocket("udp4");
srv.on("message", (msg, rinfo) => {
  const cmd = msg.toString("utf8").trim().toLowerCase() || "restart";
  console.log(`[${new Date().toISOString()}] udp ${msg.length}B from ${rinfo.address}:${rinfo.port} cmd=${cmd}`);
  switch (cmd) {
    case "cycle":
      pnputil(["/disable-device", INSTANCE]);
      execFileSync("powershell.exe", ["-NoProfile", "-Command", "Start-Sleep -Seconds 2"]);
      pnputil(["/enable-device", INSTANCE]);
      break;
    case "scan":
      pnputil(["/scan-devices"]);
      break;
    case "enable":
      pnputil(["/enable-device", INSTANCE]);
      break;
    case "disable":
      pnputil(["/disable-device", INSTANCE]);
      break;
    case "restart":
    default:
      pnputil(["/restart-device", INSTANCE]);
      break;
  }
  console.log(status());
});
srv.on("error", (e) => console.error(`socket error: ${e.message}`));
srv.bind(PORT, HOST, () => console.log(`listening udp ${HOST}:${PORT}; instance=${INSTANCE}`));

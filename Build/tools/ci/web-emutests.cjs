#!/usr/bin/env node
/*! 网页端 CI: 用本机 Chrome 加载 Web/Agent/Tests 页面,
 *! 点击 EmuCreate → EmuTests, 采集 console/异常, 断言两组新测试通过。
 *! 约束: --user-data-dir 固定为 <root>/.bin/ai-web-user-data, 绝不访问用户默认配置。
 *! 模式: 缺省 --headless=new(无界面); WEB_HEADED=1 时以有界面窗口运行(供人工观察)。
 *! 依赖: Node >=22(内置 WebSocket); Chrome 路径取 CHROME 或常见安装位置。
 */
"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

const root = path.resolve(__dirname, "..", "..", "..");
const testsDir = path.join(root, "Web", "Agent", "Tests");
const profile = path.join(root, ".bin", "ai-web-user-data");
const host = "127.0.0.1";
const httpPort = 8123 + Math.floor(Math.random() * 400);
const cdpPort = 9333 + Math.floor(Math.random() * 400);
fs.mkdirSync(profile, { recursive: true });

function chromePath() {
  const env = process.env.CHROME || process.env.CHROME_PATH;
  if (env && fs.existsSync(env)) return env;
  const cand = [
    // Windows
    process.env.ProgramFiles && process.env.ProgramFiles + "\\Google\\Chrome\\Application\\chrome.exe",
    process.env["ProgramFiles(x86)"] && process.env["ProgramFiles(x86)"] + "\\Google\\Chrome\\Application\\chrome.exe",
    process.env.LOCALAPPDATA && process.env.LOCALAPPDATA + "\\Google\\Chrome\\Application\\chrome.exe",
    // Linux
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/snap/bin/chromium",
    "/opt/google/chrome/chrome",
    // macOS
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
  ].filter(Boolean);
  return cand.find((c) => c && fs.existsSync(c));
}

function mime(p) {
  if (p.endsWith(".js")) return "text/javascript; charset=utf-8";
  if (p.endsWith(".html")) return "text/html; charset=utf-8";
  return "application/octet-stream";
}
const server = http.createServer((req, res) => {
  const u = decodeURIComponent((req.url || "/").split("?")[0]);
  const rel = u === "/" ? "index.html" : u.replace(/^\/+/, "");
  const f = path.join(testsDir, rel);
  if (!f.startsWith(testsDir) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) {
    res.writeHead(404).end("nf");
    return;
  }
  res.writeHead(200, { "content-type": mime(f) });
  fs.createReadStream(f).pipe(res);
});

function delay(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function main() {
  const chrome = chromePath();
  if (!chrome) {
    const msg = "[webci] 跳过: 未找到 Chrome(设 CHROME / CHROME_PATH, 或安装 google-chrome / chromium)";
    if (process.env.CI_STRICT === "1") {
      console.error(msg);
      process.exit(1);
    }
    console.log(msg + " —— CI_STRICT=1 时失败");
    process.exit(0);
  }
  console.log("[webci] chrome = " + chrome);
  await new Promise((r) => server.listen(httpPort, host, r));
  const url = `http://${host}:${httpPort}/index.html`;

  const headed = process.env.WEB_HEADED === "1"; // 缺省 headless; WEB_HEADED=1 有界面
  const args = [
    ...(headed ? [] : ["--headless=new"]),
    `--remote-debugging-port=${cdpPort}`,
    `--user-data-dir=${profile}`,
    "--no-first-run",
    "--no-default-browser-check",
    ...(headed ? [] : ["--disable-extensions", "--disable-gpu"]),
    url,
  ];
  console.log("[webci] chrome " + (headed ? "headed(有界面)" : "headless") + " profile=" + profile);
  const proc = spawn(chrome, args, { stdio: "ignore" });
  process.on("exit", () => proc.kill());

  // 等 CDP
  let wsUrl = null;
  for (let i = 0; i < 60 && !wsUrl; ++i) {
    await delay(250);
    try {
      const list = await new Promise((resolve, reject) => {
        http
          .get({ host, port: cdpPort, path: "/json/list" }, (res) => {
            let d = "";
            res.on("data", (c) => (d += c));
            res.on("end", () => resolve(JSON.parse(d)));
          })
          .on("error", reject);
      });
      const page = list.find((t) => t.type === "page" && t.url.includes("index.html")) || list.find((t) => t.type === "page");
      wsUrl = page && page.webSocketDebuggerUrl;
    } catch (e) {
      /* retry */
    }
  }
  if (!wsUrl) throw Error("CDP 连接失败");

  const ws = new WebSocket(wsUrl);
  await new Promise((res, rej) => {
    ws.onopen = res;
    ws.onerror = rej;
  });
  let seq = 0;
  const pending = new Map();
  const events = [];
  ws.onmessage = (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) {
      const { res, rej } = pending.get(m.id);
      pending.delete(m.id);
      m.error ? rej(Error(JSON.stringify(m.error))) : res(m.result);
    } else if (m.method) {
      events.push({ t: Date.now(), method: m.method, params: m.params });
    }
  };
  const send = (method, params = {}) =>
    new Promise((res, rej) => {
      const id = ++seq;
      pending.set(id, { res, rej });
      ws.send(JSON.stringify({ id, method, params }));
    });
  await send("Runtime.enable");
  await send("Page.enable");

  // 等页面脚本就绪
  await delay(2500);
  const ev = (code) =>
    send("Runtime.evaluate", { expression: code, returnByValue: true, awaitPromise: true }).then((r) => r.result && r.result.value);

  await ev(`document.getElementById('EmuCreate').click(); 'clicked'`);
  console.log("[webci] EmuCreate clicked");
  await delay(4000);
  events.length = 0; // 从 EmuTests 起采集
  await ev(`document.getElementById('EmuTests').click(); 'clicked'`);
  console.log("[webci] EmuTests clicked");
  await delay(10000);

  // 汇总
  const logs = events
    .filter((e) => e.method === "Runtime.consoleAPICalled")
    .map((e) => {
      const args = (e.params.args || []).map((a) => a.value !== undefined ? String(a.value) : a.description || "");
      return `[${e.params.type}] ${args.join(" ")}`;
    });
  const errors = events
    .filter((e) => e.method === "Runtime.exceptionThrown")
    .map((e) => JSON.stringify(e.params.exceptionDetails && e.params.exceptionDetails.text || e.params));
  const hasX = logs.some((l) => l.includes("X509ExtBuilder Tests OK"));
  const hasS = logs.some((l) => l.includes("JsCryptoSmokeTests OK"));
  console.log("[webci] markers: X509ExtBuilder=" + hasX + " JsCryptoSmoke=" + hasS + " exceptions=" + errors.length);
  const interesting = logs.filter((l) => /X509ExtBuilder|JsCryptoSmoke|Uncaught|Test Failed|FAIL/.test(l)).slice(-20);
  console.log("[webci] logs:\n" + interesting.join("\n"));
  if (errors.length) console.log("[webci] exceptions:\n" + errors.slice(0, 10).join("\n"));

  ws.close();
  proc.kill();
  server.close();
  if (!hasX || !hasS || errors.length) {
    console.error("[webci] FAILED");
    process.exit(1);
  }
  console.log("[webci] PASS");
  process.exit(0);
}

main().catch((err) => {
  console.error("[webci]", err && err.stack || err);
  process.exit(1);
});

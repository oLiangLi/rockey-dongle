const crypto = require("crypto");
const http = require("http");
const fs = require("fs");
const PORT = process.env.PORT || "3000";
const path = require("path");
const PSK = crypto
  .createHash("sha256")
  .update(Buffer.from(process.env.PSK || "1234567812345678", "base64"))
  .digest();
const kTick0 = Math.floor(Date.UTC(2020, 0, 1) / 1000);
const EXECV_PATH = process.argv[2] || path.join(__dirname, "RockeyTrust.exe");

const kSizeLimit = 1024 * 1024;
const kPowMask = (1 << 20) - 1;

const vPORT = parseInt(PORT);
if (isNaN(vPORT) || vPORT < 1 || vPORT > 65535) {
  console.error("Invalid port number: " + PORT);
  process.exit(1);
}

function Open(cipher, payload) {
  if (payload.length < 20)
    throw Error(`Invalid payload.size: ${payload.length}`);

  const decipher = crypto.createDecipheriv(
    "chacha20-poly1305",
    cipher.subarray(0, 32),
    cipher.subarray(32, 44),
  );
  decipher.setAAD(cipher.subarray(44));
  decipher.setAuthTag(payload.subarray(payload.length - 16));

  const text = decipher.update(payload.subarray(0, payload.length - 16));
  decipher.final();

  return text;
}

function Seal(cipher, payload) {
  const aead = crypto.createCipheriv(
    "chacha20-poly1305",
    cipher.subarray(0, 32),
    cipher.subarray(32, 44),
  );
  aead.setAAD(cipher.subarray(44));
  return Buffer.concat([aead.update(payload), aead.final(), aead.getAuthTag()]);
}

let service_counter = 0;
let error_counter = 0;
let prev_service_counter = 0;
let prev_error_counter = 0;

/**
 * 缓存4分钟内的请求Token以防止重放攻击 ...
 */
const token_recorder = new Map();

async function List(req, body, reply) {}
async function Factory(req, body, reply) {}
async function Lock(req, body, reply) {}

async function Dashboard(req, body, reply) {}

async function Execv(req, body, reply) {}

async function HandleRequest(req, body) {
  const json = JSON.parse(body.toString("utf-8"));
  if (
    typeof json !== "object" ||
    typeof json.token !== "string" ||
    typeof json.payload !== "string"
  )
    throw Error(`Invalid request body!`);

  const token = Buffer.from(json.token, "base64");
  if (token.length !== 48)
    throw Error(`Invalid token.size (.EQ. 48): ${token.length}`);
  const tick = token.readUint32LE(0);
  const ts = Math.floor(Date.now() / 1000 - (tick + kTick0));

  /**
   ** 要求客户端和服务器端的时间同步精度在2分钟之内 ...
   **/
  if (Math.abs(ts) > 2 * 60) throw Error(`Invalid token.ts: ${ts}`);
  const s_token = token.toString("base64");
  if (token_recorder.has(s_token))
    throw Error(`reduplicative token ${s_token}`);
  token_recorder.set(s_token, tick);

  const check = crypto
    .createHash("sha256")
    .update(token)
    .update(PSK)
    .digest()
    .readUint32LE(0);
  if (0 !== (check & kPowMask))
    throw Error(`Invalid POW ${check.toString(16)}`);

  const cipher = crypto.createHash("sha512").update(token).update(PSK).digest();
  const payload = Open(cipher, Buffer.from(json.payload, "base64"));
  const hash = crypto.createHash("sha256").update(payload).digest();
  if (Buffer.compare(hash, token.subarray(16)))
    throw Error(`Invalid token.hash ${hash.toString("hex")}`);

  const request = JSON.parse(payload.toString("utf-8"));
  const command = request?.cmd;
  let reply = {
    cmd: command,
    nonce: crypto.randomBytes(12).toString("base64"),
  };

  switch (command) {
    case "list":
      await List(req, request, reply);
      break;
    case "factory":
      await Factory(req, request, reply);
      break;
    case "lock":
      await Lock(req, request, reply);
      break;
    case "dashboard":
      await Dashboard(req, request, reply);
      break;
    case "execv":
      await Execv(req, request, reply);
      break;
    default:
      throw Error(`Invalid request.cmd!`);
  }

  return [cipher, reply];
}

async function CheckRuntimeEnv() {
  ///
  /// TODO: LiangLI, 增加对 RockeyTrust.exe 程序的完整性验证 ...
  ///
  try {
    const stat = fs.statSync(EXECV_PATH);
    if (!stat.isFile())
      return Promise.reject(
        Error(`RockeyTrust.exe !stat.isFile() ${EXECV_PATH}`),
      );
    console.log(`RockeyTrust.exe [${EXECV_PATH}] size: ${stat.size}`);
  } catch (err) {
    return Promise.reject(err);
  }
}

async function StartServer() {
  return new Promise(async (resolve, reject) => {
    try {
      const server = http.createServer((req, res) => {
        const tick_start = Date.now();
        const client_ip =
          req.headers["x-real-ip"] ||
          req.headers["x-forwarded-for"] ||
          req.socket.remoteAddress;
        function HeaderDefault() {
          if (
            req.headers["sec-fetch-mode"] === "cors" &&
            req.headers["sec-fetch-site"] !== "same-origin"
          ) {
            return {
              "Access-Control-Allow-Origin": "*",
              "Access-Control-Allow-Methods": "*",
              "Access-Control-Allow-Headers": "Content-Type",
              "Access-Control-Max-Age": 7200,
            };
          } else {
            return {};
          }
        }

        function onError(code, message) {
          if (!res.headersSent) {
            const reply = Buffer.from(
              JSON.stringify({
                status: "error",
                code: code,
                message: message,
              }),
            );

            const hdr = HeaderDefault();
            hdr["Content-Type"] = "application/json";
            hdr["Content-Length"] = reply.length;
            res.writeHead(code, hdr);
            res.end(reply);
          }
          req.destroy();
        }

        if (req.method === "OPTIONS") {
          const hdr = HeaderDefault();
          hdr["Content-Length"] = 0;
          res.writeHead(200, hdr);
          res.end();
          return;
        }

        if (req.method !== "POST") {
          return onError(405, "Method not allowed");
        }

        let size = 0;
        const body = [];
        req.on("data", (chunk) => {
          size += chunk.length;
          if (size < kSizeLimit) body.push(chunk);
        });

        req.on("error", () => {
          return onError(500, "Server error");
        });

        req.on("end", async () => {
          if (size > kSizeLimit)
            return onError(413, "Request entity too large");

          try {
            const [cipher, reply] = await HandleRequest(
              req,
              Buffer.concat(body),
            );
            const result = Buffer.from(
              JSON.stringify({
                payload: Seal(
                  cipher,
                  Buffer.from(JSON.stringify(reply)),
                ).toString("base64"),
              }),
            );

            const hdr = HeaderDefault();
            hdr["Content-Length"] = result.length;
            hdr["Content-Type"] = "application/json";
            res.writeHead(200, hdr);
            res.end(result);
            ++service_counter;
            const tick_end = Date.now();

            console.info(
              `[ I ]${service_counter} client ${client_ip}, cmd ${reply.cmd}, id ${reply.id || "N/A"}, in ${tick_end - tick_start} ms`,
            );
          } catch (err) {
            ++error_counter;
            const tick_end = Date.now();
            console.error(
              `[ E ]${error_counter} client ${client_ip}, in ${tick_end - tick_start} ms, ${err?.stack}`,
            );
            return onError(500, "Server error");
          }
        });
      });

      server.listen(vPORT, "localhost", () => {
        console.log(
          `Server listening on port ${PORT}=>${vPORT}, PSK: ${PSK.subarray(0, 4).toString("hex")}}, EXECV: ${EXECV_PATH}`,
        );
        return resolve(server);
      });
    } catch (err) {
      return reject(err);
    }
  });
}

CheckRuntimeEnv()
  .then(() => StartServer())
  .then((server) => {
    function TaskStatistics() {
      server.getConnections((err, connections) => {
        let timeout = 0;
        const tick = Math.floor(Date.now() / 1000) - kTick0;

        const sc = service_counter - prev_service_counter;
        const ec = error_counter - prev_error_counter;
        prev_service_counter = service_counter;
        prev_error_counter = error_counter;

        for (const [token, ts] of token_recorder) {
          if (Math.abs(tick - ts) > 240) {
            token_recorder.delete(token);
            ++timeout;
          }
        }

        const alive = token_recorder.size;
        console.info(
          `[${new Date().toISOString()}] ${connections} connections, ${timeout} timeout, ${alive} alive, ${sc}/${service_counter} ok, ${ec}/${error_counter} error`,
        );
      });
    }

    setInterval(TaskStatistics, 60 * 1000);
    TaskStatistics();
  })
  .catch((err) => {
    console.error(err.stack);
    process.exit(1);
  });

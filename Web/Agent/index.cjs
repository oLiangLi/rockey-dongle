const http = require("http");
const url = require("url");
const PORT = process.env.PORT || "3000";
const kSizeLimit = 1024 * 1024;

const vPORT = parseInt(PORT);
if (isNaN(vPORT) || vPORT < 1 || vPORT > 65535) {
  console.error("Invalid port number: " + PORT);
  process.exit(1);
}

const HandleRequest = async (req, body) => {
  return new Promise((resolve, reject) => {
    resolve(
      JSON.stringify({
        status: "ok",
        body: body.toString(),
      }),
    );
  });
};

const server = http.createServer((req, res) => {
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
    if (size > kSizeLimit) return onError(413, "Request entity too large");

    try {
      let result = await HandleRequest(req, Buffer.concat(body));
      if (false === result instanceof Buffer) result = Buffer.from(result);
      const hdr = HeaderDefault();
      hdr["Content-Length"] = result.length;
      hdr["Content-Type"] = "application/json";
      res.writeHead(200, hdr);
      res.end(result);
    } catch (err) {
      return onError(500, "Server error");
    }
  });
});

server.listen(vPORT, "localhost", () => {
  console.log("Server listening on port " + PORT);
});

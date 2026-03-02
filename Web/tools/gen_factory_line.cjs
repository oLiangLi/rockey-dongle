const crypto = require("node:crypto");
const path = require("node:path");
const fs = require("node:fs");

const uid = process.argv[2] || "1";

const seed =
  process.argv[3] ||
  "C6D0EA06A62EA430FF6969AE3449B613A42E2741EA802A32DD8C657AC3379F576EFA76B45CFDD6A8924080956F5C9685F363E670E589C722F15912599E198FCB";
const file =
  process.argv[4] ||
  path.join(
    __dirname,
    "../../.bin/arm-RockeyARM-native-release/RockeyTrust.bin",
  );

const BIN_UID = Buffer.alloc(4);
const BIN_SEED = Buffer.from(seed, "hex");
const BIN_FILE = fs.readFileSync(file);

const val_uid = (function () {
  if (uid.slice(0, 2).toLocaleLowerCase() !== "0x") return parseInt(uid, 10);
  return parseInt(uid.slice(2), 16);
})();

process.stderr.write(`UID: ${uid} => ${val_uid}`);
if (val_uid < 1 || val_uid >= 2 ** 32) {
  throw new Error("Invalid uid");
}
BIN_UID.writeUInt32BE(val_uid);

if (BIN_SEED.length !== 64) throw new Error("Invalid seed length");
if (BIN_FILE.length !== 65520) throw new Error("Invalid file length");

const sha256 = crypto
  .createHash("sha256")
  .update(BIN_UID)
  .update(BIN_SEED)
  .update(BIN_FILE)
  .digest();

process.stdout.write(
  `${Buffer.concat([BIN_UID, BIN_SEED, BIN_FILE, sha256]).toString("base64")}\n`,
);

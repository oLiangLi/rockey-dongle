import * as Script from "./index.js";
import * as fs from "node:fs";

(async function () {
  for (const file of process.argv.slice(2)) {
    console.info(`process file ...`);
    const content = fs.readFileSync(file).toString();

    try {
      const result = await Script.Parse(content);
      console.info(`${JSON.stringify(result, null, 2)}`);
    } catch (err) {
      console.error(`Parse script error ${err}`);
    }
  }
})();

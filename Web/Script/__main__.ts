import * as Script from "./index.js";
import * as fs from "node:fs";

(async function(){
  for (const file of process.argv.slice(2)) {
    const content = fs.readFileSync(file).toString();

    try {
      const result = await Script.Parse(content);
      fs.writeFileSync(`${file}.json`, JSON.stringify(result, null, 1));
    } catch (err) {
      console.error(`Parse script error ${err}`);
    }
  }
})();


const fs = require('fs');
const path = require('path');

const kDir0 = process.argv[2] || path.join(__dirname, '../../Agent/Tests/Tests');
const kOutput = process.argv[3] || path.join(__dirname, '../../Agent/Tests/js/jsScriptBundled.js');
const files = fs.readdirSync(kDir0);

const bundles = [];
for(const f of files) {
    const match = f.match(/^([a-z][a-z0-9_]+)\.dongle$/i);
    if(!match)  continue;

    const name = match[1];
    let file = fs.readFileSync(path.join(kDir0, f), 'utf8');
    if(file.charCodeAt(0) === 0xFEFF) file = file.substring(1); /// BOM ...

    bundles.push({
        name,
        file
    });
}

fs.writeFileSync(kOutput, `
(function() {
    const v = new Map();
    ${JSON.stringify(bundles, null, 2)}.forEach((item) => {
        v.set(item.name, item.file);
    });
    globalThis.jsWorld.jsScriptBundled = v;
})();
`);


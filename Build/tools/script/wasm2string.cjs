const fs = require('fs');

if(process.argv.length !== 3)
    throw Error(`usage node wasm2string.cjs <a.wasm>`);

const wasmFile = process.argv[2];
const content = fs.readFileSync(wasmFile);

fs.writeFileSync(wasmFile + '.ts', `
export function Assets() {
    return Buffer.from("${content.toString('base64')}" , 'base64');
}
`);

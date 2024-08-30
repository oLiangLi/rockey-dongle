const fs = require('fs');

const re = /^\s*case\s+(\d+)\s*:.*\r?\n#line.*\r?\n\s+\{\s*\/\*\*@\s*([a-zA-Z_][a-zA-Z0-9_]*)\s+/mg;
const sp40 = "                                            ";

const op = process.argv[2];
if(op !== '--ymc' && op !== '--yc' && op !== '--jy') {
    console.error(`usage node ${process.argv[1]} <--ymc|--yc|--jy> ...`);
    process.exit(100);
}

function solve(file) {
    const actions = new Map();
    let content = fs.readFileSync(file).toString();
    for(;;) {
        const match = re.exec(content);
        if(!match)
            break;
        actions.set(match[2], parseInt(match[1]));
    }

    let text = `
    
/*
 *! XZ1 -- _XDPDA_IMPLEMENT_USER_ACTIONLIST_DECLARE_  BEGIN ...
 */
#ifdef _XDPDA_IMPLEMENT_USER_ACTIONLIST_DECLARE_  
`;

    if(0 !== actions.size) {
        text += "enum {\n";
        for(let [name, value] of actions) {
            if(name.length < 40)
                name = (name + sp40).slice(0, 40);
            text += `    ${name} = ${value},\n`;
        }
        text += "};\n"
    }
    text += `
#endif /* _XDPDA_IMPLEMENT_USER_ACTIONLIST_DECLARE_ */
/*
 *!  XZ1 -- _XDPDA_IMPLEMENT_USER_ACTIONLIST_DECLARE_  END.
 */ 
`;

    if(op === '--ymc' || op === '--jy') {
        const pos = content.search("#ifdef _XDPDA_IMPLEMENT_USER_ACTIONS_DECLARE_");
        if(pos > 0)
            content = content.substring(0, pos);
    }

    if(op === '--jy') {
        const tokens = new Map();
        const begin = content.search('#ifdef _XDPDA_IMPLEMENT_TOKENENUMS_DECLARE_');
        const end = content.substring(begin).search('#endif') + begin;

        if(begin > 0 && end > begin) {
            const re = /^\s*([a-z_][a-z0-9_]*)\s*=\s*(\d+)\s*,?.*$/img;
            const s  = content.slice(begin, end);

            for(;;) {
                const match = re.exec(s);
                if(!match)
                    break;
                tokens.set(match[1], parseInt(match[2]));
            }
        }

        let jy = '\n\n/* auto generate */\n\n';

        let maxToken = 255;
        for(const [, v] of tokens) {
            if(v > maxToken)
                maxToken = v;
        }
        jy += `\nexport const enum Token {\n`;

        for(let [name, value] of tokens) {
            if(name.length < 40)
                name = (name + sp40).slice(0, 40);
            jy += `    ${name} = ${value},\n`;
        }

        jy += `\n$MAX_TOKEN_VALUE = ${maxToken}\n`;
        jy += '\n}\n\n';

        if(actions.size > 0) {
            jy += `\nexport const enum Action {\n`;

            for(let [name, value] of actions) {
                if(name.length < 40)
                    name = (name + sp40).slice(0, 40);
                jy += `    ${name} = ${value},\n`;
            }

            jy += '\n}\n\n';
        }

        fs.writeFileSync(file.replace(/(\.INL)?$/i, '.ts'), jy);
    }

    fs.writeFileSync(file, content + text);
}

const files = process.argv.slice(3);
for(const file of files) {
    solve(file);
}

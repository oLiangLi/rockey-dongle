import { Context } from "./lib/grammar.js";
export async function Parse(script: string) {
  const ctx = await Context.Create(script);
  if (0 !== ctx.yyparse())
    throw Error(`Parse script error line: ${ctx.yyline()}`);

  return {
    size_public : ctx.size_public(),
    code: ctx.code().toString("base64"),
    data: ctx.data(),
  };
}

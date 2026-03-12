import { Context } from "./lib/grammar.js";
export async function Parse(script: string) {
  const ctx = await Context.Create(script);
  if (0 !== ctx.yyparse())
    throw Error(`Parse script error line: ${ctx.yyline()}`);

  const size_public = ctx.size_public();
  const code = ctx.code();

  return {
    size_public,
    code: code.toString("base64"),
  };
}

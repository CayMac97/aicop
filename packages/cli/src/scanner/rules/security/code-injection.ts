import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression, isStringLiteral } from '../../../utils/ast-helpers.js';

const VM_METHODS = new Set(['runInNewContext', 'runInThisContext']);
const MATH_EVAL_METHODS = new Set(['eval', 'evaluate']);
const MATH_OBJ_NAMES = new Set(['mathjs', 'math', 'Math']);

function collectStringConstVars(ast: ParsedAST): Set<string> {
  const vars = new Set<string>();
  walk(ast, {
    VariableDeclarator(rawNode) {
      const node = rawNode as TSESTree.VariableDeclarator;
      if (!node.init || !isStringLiteral(node.init as TSESTree.Expression)) return;
      if (node.id.type !== 'Identifier') return;
      vars.add((node.id as TSESTree.Identifier).name);
    },
  });
  return vars;
}

function argIsDynamic(arg: TSESTree.Node, stringConsts: Set<string>): boolean {
  if (isStringLiteral(arg)) return false;
  if (arg.type === 'Literal') return false;
  if (isIdentifier(arg) && stringConsts.has((arg as TSESTree.Identifier).name)) return false;
  return true;
}

function checkVmRun(node: TSESTree.CallExpression, source: string, filePath: string, stringConsts: Set<string>): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object) || !isIdentifier(me.property)) return null;
  if ((me.object as TSESTree.Identifier).name !== 'vm') return null;
  if (!VM_METHODS.has((me.property as TSESTree.Identifier).name)) return null;
  const arg = node.arguments[0];
  if (!arg || !argIsDynamic(arg, stringConsts)) return null;
  return {
    ruleId: 'security/code-injection',
    severity: 'error',
    message: `code injection risk — user input passed to vm.${(me.property as TSESTree.Identifier).name}()`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Validate all input before executing in vm context. Prefer a sandboxing library with strict resource limits.',
  };
}

function hasAllowlistCheck(source: string, varName: string, line: number): boolean {
  const priorLines = source.split('\n').slice(Math.max(0, line - 10), line).join('\n');
  return priorLines.includes(`.includes(${varName}`) || priorLines.includes(`.has(${varName}`);
}

function checkMathEval(node: TSESTree.CallExpression, source: string, filePath: string, stringConsts: Set<string>): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object) || !isIdentifier(me.property)) return null;
  const obj = (me.object as TSESTree.Identifier).name;
  const method = (me.property as TSESTree.Identifier).name;
  if (!MATH_OBJ_NAMES.has(obj)) return null;
  if (!MATH_EVAL_METHODS.has(method)) return null;
  if (obj === 'Math') return null;
  const arg = node.arguments[0];
  if (!arg || !argIsDynamic(arg, stringConsts)) return null;
  if (isIdentifier(arg)) {
    if (hasAllowlistCheck(source, (arg as TSESTree.Identifier).name, getLine(node))) return null;
  }
  return {
    ruleId: 'security/code-injection',
    severity: 'error',
    message: `code injection risk — user input passed to ${obj}.${method}()`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: obj + '.' + method + '() can execute arbitrary code. Validate and sanitize all input first.',
  };
}

const rule: Rule = {
  id: 'security/code-injection',
  name: 'Code Injection',
  category: 'security',
  severity: 'error',
  description: 'Detects vm.runInNewContext(), vm.runInThisContext(), and math.eval() called with dynamic input',
  why: 'Passing user-controlled data to code execution functions allows attackers to run arbitrary JavaScript on the server.',
  fix: 'Never pass user input to eval or eval-equivalent functions.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const stringConsts = collectStringConstVars(ast);

    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        const vmF = checkVmRun(node, source, filePath, stringConsts);
        if (vmF) { findings.push(vmF); return; }
        const mathF = checkMathEval(node, source, filePath, stringConsts);
        if (mathF) findings.push(mathF);
      },
    });

    return findings;
  },
};

export default rule;

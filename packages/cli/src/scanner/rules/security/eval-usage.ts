import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { isStringLiteral, getLine, getColumn, isIdentifier, isMemberExpression } from '../../../utils/ast-helpers.js';
import { buildExtendedTaintMap, isTaintedExpr } from '../../../utils/taint-tracker.js';

function checkEvalCall(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isIdentifier(node.callee)) return null;
  if ((node.callee as TSESTree.Identifier).name !== 'eval') return null;
  // eval('string literal') is predictable — not a code injection vector
  const arg = node.arguments[0];
  if (arg && isStringLiteral(arg as TSESTree.Expression)) return null;
  return {
    ruleId: 'security/eval-usage',
    severity: 'error',
    message: 'eval() usage detected',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Remove eval(). If you need dynamic code execution, reconsider your design. Parse JSON with JSON.parse() instead.',
  };
}

function checkNewFunction(node: TSESTree.NewExpression, source: string, filePath: string): Finding | null {
  if (!isIdentifier(node.callee)) return null;
  if ((node.callee as TSESTree.Identifier).name !== 'Function') return null;
  const args = node.arguments;
  if (args.length === 0) return null;
  // new Function('static', 'strings') — no dynamic input, not a code injection vector
  if (args.every((a) => isStringLiteral(a as TSESTree.Expression))) return null;
  return {
    ruleId: 'security/eval-usage',
    severity: 'error',
    message: 'new Function() usage detected — equivalent to eval()',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Avoid new Function() as it executes arbitrary code. Refactor to use explicit logic.',
  };
}

function checkTimerWithString(node: TSESTree.CallExpression, source: string, filePath: string, tainted: Set<string>): Finding | null {
  if (!isIdentifier(node.callee)) return null;
  const name = (node.callee as TSESTree.Identifier).name;
  if (name !== 'setTimeout' && name !== 'setInterval') return null;
  const firstArg = node.arguments[0];
  if (!firstArg) return null;
  
  const isString = isStringLiteral(firstArg as TSESTree.Expression);
  const isTainted = isTaintedExpr(firstArg, tainted);
  
  if (!isString && !isTainted) return null;

  return {
    ruleId: 'security/eval-usage',
    severity: 'error',
    message: `${name}() called with a string argument or dynamic input — equivalent to eval()`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: `Pass a function reference instead: ${name}(() => { /* code */ }, delay)`,
  };
}

function checkScriptDocumentWrite(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object) || !isIdentifier(me.property)) return null;
  if ((me.object as TSESTree.Identifier).name !== 'document') return null;
  if ((me.property as TSESTree.Identifier).name !== 'write') return null;
  const arg = node.arguments[0];
  if (!arg) return null;
  const argText = source.slice(node.range?.[0] ?? 0, node.range?.[1] ?? 0);
  if (!argText.includes('<script')) return null;
  return {
    ruleId: 'security/eval-usage',
    severity: 'error',
    message: 'document.write() used to inject a <script> tag',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Dynamically loaded scripts via document.write are a major security risk. Use addEventListener or module imports.',
  };
}

const rule: Rule = {
  id: 'security/eval-usage',
  name: 'Eval Usage',
  category: 'security',
  severity: 'error',
  description: 'Detects eval(), new Function(), and timer functions called with string arguments',
  why: 'eval() and equivalent constructs execute arbitrary code strings, making your application vulnerable to code injection attacks. They also prevent V8 optimizations.',
  fix: 'Eliminate dynamic code execution. Parse data with JSON.parse(), use explicit logic, and pass function references to timers.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const tainted = buildExtendedTaintMap(ast);

    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        const evalF = checkEvalCall(node, source, filePath);
        if (evalF) { findings.push(evalF); return; }
        const timerF = checkTimerWithString(node, source, filePath, tainted);
        if (timerF) { findings.push(timerF); return; }
        const scriptF = checkScriptDocumentWrite(node, source, filePath);
        if (scriptF) findings.push(scriptF);
      },
      NewExpression(rawNode) {
        const finding = checkNewFunction(rawNode as TSESTree.NewExpression, source, filePath);
        if (finding) findings.push(finding);
      },
    });

    return findings;
  },
};

export default rule;

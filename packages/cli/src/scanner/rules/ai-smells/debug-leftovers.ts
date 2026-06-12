import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet, isTestFile } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression } from '../../../utils/ast-helpers.js';

const CONSOLE_METHODS = new Set(['debug', 'trace', 'dir', 'dirxml', 'table']);

function buildParentMap(ast: ParsedAST): Map<TSESTree.Node, TSESTree.Node> {
  const map = new Map<TSESTree.Node, TSESTree.Node>();
  walk(ast, {
    enter(node, parent) { if (parent) map.set(node, parent); },
  });
  return map;
}

const LIFECYCLE_EVENTS = new Set(['uncaughtException', 'unhandledRejection', 'SIGINT', 'SIGTERM', 'exit', 'beforeExit']);

function isProcessOnCall(node: TSESTree.Node): boolean {
  if (node.type !== 'CallExpression') return false;
  const call = node as TSESTree.CallExpression;
  if (!isMemberExpression(call.callee)) return false;
  const me = call.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object) || (me.object as TSESTree.Identifier).name !== 'process') return false;
  if (!isIdentifier(me.property) || (me.property as TSESTree.Identifier).name !== 'on') return false;
  const eventArg = call.arguments[0];
  return eventArg?.type === 'Literal' && LIFECYCLE_EVENTS.has(String((eventArg as TSESTree.Literal).value));
}

function isProcessOnLifecycleCallback(node: TSESTree.Node, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  let current: TSESTree.Node = node;
  for (let i = 0; i < 10; i++) {
    const parent = parentMap.get(current);
    if (!parent) return false;
    if (isProcessOnCall(parent)) return true;
    current = parent;
  }
  return false;
}

function isConsoleAsObjectPropertyValue(node: TSESTree.Node, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  const parent = parentMap.get(node);
  if (!parent) return false;
  // console.log used as a property value in an object: { info: (...args) => console.log(...args) }
  if (parent.type === 'ArrowFunctionExpression' || parent.type === 'FunctionExpression') {
    const grandParent = parentMap.get(parent);
    if (grandParent?.type === 'Property') return true;
  }
  // Direct: { info: console.log }
  if (parent.type === 'Property') return true;
  return false;
}

function isInsideErrorHandler(node: TSESTree.Node, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  let current: TSESTree.Node = node;
  for (let i = 0; i < 20; i++) {
    const parent = parentMap.get(current);
    if (!parent) return false;
    const isFunc = parent.type === 'FunctionDeclaration' || parent.type === 'FunctionExpression' || parent.type === 'ArrowFunctionExpression';
    if (isFunc) {
      const fn = parent as TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression;
      const firstParam = fn.params[0];
      if (firstParam?.type === 'Identifier') {
        const name = (firstParam as TSESTree.Identifier).name;
        if (name === 'err' || name === 'error') return true;
      }
      // Express 4-param error handler: (err, req, res, next)
      if (fn.params.length === 4) return true;
      return false;
    }
    current = parent;
  }
  return false;
}

function checkConsoleCall(
  node: TSESTree.CallExpression,
  source: string,
  filePath: string,
  parentMap: Map<TSESTree.Node, TSESTree.Node>,
): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object) || !isIdentifier(me.property)) return null;
  if ((me.object as TSESTree.Identifier).name !== 'console') return null;
  const method = (me.property as TSESTree.Identifier).name;
  if (!CONSOLE_METHODS.has(method)) return null;
  if (isInsideErrorHandler(node, parentMap)) return null;
  if (isConsoleAsObjectPropertyValue(node, parentMap)) return null;
  if (isProcessOnLifecycleCallback(node, parentMap)) return null;
  return {
    ruleId: 'ai-smell/debug-leftovers',
    severity: 'info',
    message: `console.${method}() found — remove before production`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Replace with a structured logger (pino, winston) or remove if debugging only: import { logger } from "./utils/logger"',
  };
}

function checkDebuggerStatement(node: TSESTree.DebuggerStatement, source: string, filePath: string): Finding {
  return {
    ruleId: 'ai-smell/debug-leftovers',
    severity: 'info',
    message: 'debugger; statement found in source code',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Remove the debugger statement before committing',
  };
}

function checkProcessExit(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.object) || !isIdentifier(me.property)) return null;
  if ((me.object as TSESTree.Identifier).name !== 'process') return null;
  if ((me.property as TSESTree.Identifier).name !== 'exit') return null;
  return {
    ruleId: 'ai-smell/debug-leftovers',
    severity: 'info',
    message: 'process.exit() found — ensure this is intentional and only in CLI/entry point files',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Use process.exit() only in the main entry point of CLI tools. In libraries, throw errors instead.',
  };
}

function checkHardcodedTestData(source: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const patterns: Array<{ re: RegExp; label: string }> = [
    { re: /["']test@example\.com["']/i, label: 'hardcoded test email' },
    { re: /["']password123["']/i, label: 'hardcoded test password' },
  ];
  const lines = source.split('\n');
  lines.forEach((line, idx) => {
    for (const { re, label } of patterns) {
      if (re.test(line)) {
        findings.push({
          ruleId: 'ai-smell/debug-leftovers',
          severity: 'info',
          message: `Hardcoded test data detected: ${label}`,
          file: filePath,
          line: idx + 1,
          column: 0,
          snippet: line.trim(),
          fix: 'Move test data to test fixtures or environment variables',
        });
      }
    }
  });
  return findings;
}

const rule: Rule = {
  id: 'ai-smell/debug-leftovers',
  name: 'Debug Leftovers',
  category: 'ai-smell',
  severity: 'info',
  description: 'Detects console.* calls, debugger statements, and hardcoded test data left in production code',
  why: 'Debug artifacts left in production expose internal implementation details, pollute logs, and indicate the code was not reviewed before shipping.',
  fix: 'Use a structured logger. Remove debugger statements. Move test data to fixture files.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    if (isTestFile(filePath)) return findings;
    const isCLI = source.startsWith('#!') || /[\\/](bin|cli)[\\/]/.test(filePath);
    if (isCLI) return findings;

    const parentMap = buildParentMap(ast);

    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        const consoleF = checkConsoleCall(node, source, filePath, parentMap);
        if (consoleF) { findings.push(consoleF); return; }
        const exitF = checkProcessExit(node, source, filePath);
        if (exitF) findings.push(exitF);
      },
      DebuggerStatement(rawNode) {
        findings.push(checkDebuggerStatement(rawNode as TSESTree.DebuggerStatement, source, filePath));
      },
    });

    findings.push(...checkHardcodedTestData(source, filePath));
    return findings;
  },
};

export default rule;

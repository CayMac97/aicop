import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier } from '../../../utils/ast-helpers.js';

function isFunctionNode(node: TSESTree.Node): node is TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression {
  return node.type === 'FunctionDeclaration' ||
    node.type === 'FunctionExpression' ||
    node.type === 'ArrowFunctionExpression';
}

interface FunctionAsyncInfo {
  isAsync: boolean;
  hasAwait: boolean;
  hasThenCatch: boolean;
  hasCallback: boolean;
  node: TSESTree.Node;
}

function analyzeFunctionAsync(funcNode: TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression): FunctionAsyncInfo {
  const info: FunctionAsyncInfo = {
    isAsync: funcNode.async,
    hasAwait: false,
    hasThenCatch: false,
    hasCallback: false,
    node: funcNode,
  };

  let insideAwait = 0;
  walk(funcNode as TSESTree.Program, {
    enter(node) {
      if (node.type === 'AwaitExpression') insideAwait++;
    },
    exit(node) {
      if (node.type === 'AwaitExpression') insideAwait--;
    },
    AwaitExpression() {
      info.hasAwait = true;
    },
    CallExpression(rawNode) {
      if (insideAwait > 0) return;
      const node = rawNode as TSESTree.CallExpression;
      if (node.callee.type !== 'MemberExpression') return;
      const me = node.callee as TSESTree.MemberExpression;
      if (!isIdentifier(me.property)) return;
      const methodName = (me.property as TSESTree.Identifier).name;
      if (methodName === 'then' || methodName === 'catch') info.hasThenCatch = true;
    },
  });

  return info;
}

function checkAsyncNoAwait(info: FunctionAsyncInfo, source: string, filePath: string): Finding | null {
  if (!info.isAsync || info.hasAwait) return null;
  if (info.hasThenCatch) return null; // mixed pattern caught separately
  return {
    ruleId: 'ai-smell/mixed-async-patterns',
    severity: 'warn',
    message: 'async function never uses await — the async keyword is unnecessary',
    file: filePath,
    line: getLine(info.node),
    column: getColumn(info.node),
    snippet: extractSnippet(source, getLine(info.node)),
    fix: 'Remove the async keyword if no await is needed, or add await for the async operations inside',
  };
}

function checkMixedPatterns(info: FunctionAsyncInfo, source: string, filePath: string): Finding | null {
  if (!info.isAsync || !info.hasAwait || !info.hasThenCatch) return null;
  return {
    ruleId: 'ai-smell/mixed-async-patterns',
    severity: 'warn',
    message: 'Function mixes async/await with .then()/.catch() — inconsistent async patterns',
    file: filePath,
    line: getLine(info.node),
    column: getColumn(info.node),
    snippet: extractSnippet(source, getLine(info.node)),
    fix: 'Pick one style: use async/await with try/catch throughout for consistency',
  };
}

function checkCallbackStyleMixedWithAsync(
  funcNode: TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression,
  info: FunctionAsyncInfo,
  source: string,
  filePath: string,
): Finding | null {
  if (!info.isAsync || !info.hasAwait) return null;
  const params = funcNode.params;
  if (params.length === 0) return null;
  const firstParam = params[0];
  if (firstParam.type !== 'Identifier') return null;
  const firstName = (firstParam as TSESTree.Identifier).name;
  if (firstName !== 'err' && firstName !== 'error') return null;
  return {
    ruleId: 'ai-smell/mixed-async-patterns',
    severity: 'warn',
    message: 'Callback-style function (err, result) uses async/await — mixing callback and Promise patterns',
    file: filePath,
    line: getLine(funcNode),
    column: getColumn(funcNode),
    snippet: extractSnippet(source, getLine(funcNode)),
    fix: 'Convert to Promise-based pattern: use util.promisify() on callback APIs, then async/await throughout',
  };
}

function checkAwaitOnNonPromise(node: TSESTree.AwaitExpression, source: string, filePath: string): Finding | null {
  const arg = node.argument;
  if (arg.type === 'Literal') {
    return {
      ruleId: 'ai-smell/mixed-async-patterns',
      severity: 'warn',
      message: 'await used on a literal value — awaiting non-Promise is a no-op',
      file: filePath,
      line: getLine(node),
      column: getColumn(node),
      snippet: extractSnippet(source, getLine(node)),
      fix: 'Remove the unnecessary await. Only await actual Promise-returning expressions.',
    };
  }
  return null;
}

const rule: Rule = {
  id: 'ai-smell/mixed-async-patterns',
  name: 'Mixed Async Patterns',
  category: 'ai-smell',
  severity: 'warn',
  description: 'Detects functions that mix async/await with .then()/.catch(), async functions without await, and await on non-Promises',
  why: 'Mixed async patterns indicate code assembled from different AI responses. They make error handling unpredictable and make the code harder to read and maintain.',
  fix: 'Standardize on async/await + try/catch. Remove unnecessary async keywords. Avoid mixing then/catch with await in the same function.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    walk(ast, {
      enter(rawNode) {
        if (!isFunctionNode(rawNode)) return;
        const funcNode = rawNode as TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression;
        const info = analyzeFunctionAsync(funcNode);
        const asyncNoAwait = checkAsyncNoAwait(info, source, filePath);
        if (asyncNoAwait) findings.push(asyncNoAwait);
        const mixed = checkMixedPatterns(info, source, filePath);
        if (mixed) findings.push(mixed);
        if (funcNode.type !== 'FunctionDeclaration') {
          const cbMixed = checkCallbackStyleMixedWithAsync(
            funcNode as TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression,
            info, source, filePath,
          );
          if (cbMixed) findings.push(cbMixed);
        }
      },
      AwaitExpression(rawNode) {
        const finding = checkAwaitOnNonPromise(rawNode as TSESTree.AwaitExpression, source, filePath);
        if (finding) findings.push(finding);
      },
    });

    return findings;
  },
};

export default rule;

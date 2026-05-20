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
  walk(funcNode, {
    enter(node) {
      if (node.type === 'AwaitExpression') insideAwait++;
    },
    exit(node) {
      if (node.type === 'AwaitExpression') insideAwait--;
    },
    AwaitExpression() {
      info.hasAwait = true;
    },
    // Pattern A: for await...of counts as using await
    ForOfStatement(rawNode) {
      if ((rawNode as unknown as { await: boolean }).await) info.hasAwait = true;
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

function returnsOnlyCallExpression(funcNode: TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression): boolean {
  const body = funcNode.body;
  if (!body) return false;
  if (body.type !== 'BlockStatement') return body.type === 'CallExpression';
  const stmts = (body as TSESTree.BlockStatement).body.filter((s) => s.type !== 'EmptyStatement');
  if (stmts.length !== 1) return false;
  const only = stmts[0];
  if (only.type !== 'ReturnStatement') return false;
  const arg = (only as TSESTree.ReturnStatement).argument;
  return !!arg && arg.type === 'CallExpression';
}

function isEmptyOrStubBody(funcNode: TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression): boolean {
  const body = funcNode.body;
  if (!body) return true;
  if (body.type !== 'BlockStatement') return false;
  const stmts = (body as TSESTree.BlockStatement).body.filter((s) => s.type !== 'EmptyStatement');
  if (stmts.length === 0) return true;
  // Pattern D: single throw statement (stub function)
  if (stmts.length === 1 && stmts[0].type === 'ThrowStatement') return true;
  return false;
}

// Pattern B: return new Promise(...) — async wrapper around callback API
function returnsNewPromise(funcNode: TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression): boolean {
  const body = funcNode.body;
  if (!body || body.type !== 'BlockStatement') return false;
  const stmts = (body as TSESTree.BlockStatement).body.filter((s) => s.type !== 'EmptyStatement');
  if (stmts.length !== 1) return false;
  const only = stmts[0];
  if (only.type !== 'ReturnStatement') return false;
  const arg = (only as TSESTree.ReturnStatement).argument;
  if (!arg || arg.type !== 'NewExpression') return false;
  const callee = (arg as TSESTree.NewExpression).callee;
  return isIdentifier(callee) && (callee as TSESTree.Identifier).name === 'Promise';
}

function returnsPromiseOrObservable(funcNode: TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression): boolean {
  const returnType = (funcNode as unknown as { returnType?: { typeAnnotation?: TSESTree.Node } }).returnType;
  if (!returnType?.typeAnnotation) return false;
  const ann = returnType.typeAnnotation;
  if (ann.type === 'TSTypeReference') {
    const typeName = (ann as TSESTree.TSTypeReference).typeName;
    if (typeName.type === 'Identifier') {
      const name = (typeName as TSESTree.Identifier).name;
      return name === 'Promise' || name === 'Observable' || name === 'Subscribable';
    }
  }
  return false;
}

const EVENT_LISTENER_METHODS = new Set([
  'on', 'once', 'pipe', 'subscribe', 'addListener', 'handle', 'use',
  // Express/Fastify route methods — async handlers without await are idiomatic
  'get', 'post', 'put', 'delete', 'patch', 'all', 'options', 'head', 'route',
]);

function isEventListenerCallback(
  funcNode: TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression,
  parent: TSESTree.Node | null,
): boolean {
  if (!parent || parent.type !== 'CallExpression') return false;
  const call = parent as TSESTree.CallExpression;
  if (!call.arguments.some((a) => a === (funcNode as unknown))) return false;
  if (call.callee.type !== 'MemberExpression') return false;
  const me = call.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return false;
  return EVENT_LISTENER_METHODS.has((me.property as TSESTree.Identifier).name);
}

function checkAsyncNoAwait(
  info: FunctionAsyncInfo,
  source: string,
  filePath: string,
  implementingClassRanges: Array<[number, number]>,
  parent: TSESTree.Node | null,
): Finding | null {
  if (!info.isAsync || info.hasAwait) return null;
  if (info.hasThenCatch) return null;
  const funcNode = info.node as TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression;
  if (returnsOnlyCallExpression(funcNode)) return null;
  if (isEmptyOrStubBody(funcNode)) return null;
  if (returnsPromiseOrObservable(funcNode)) return null;
  if (returnsNewPromise(funcNode)) return null;
  // Skip methods in classes that implement interfaces (NestJS Guards, Pipes, etc.)
  if (funcNode.range && implementingClassRanges.some(([s, e]) => funcNode.range![0] >= s && funcNode.range![0] <= e)) return null;
  // Pattern C: event listener callbacks passed to .on()/.pipe()/.subscribe() etc.
  if (funcNode.type !== 'FunctionDeclaration' && isEventListenerCallback(funcNode as TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression, parent)) return null;
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
  parent: TSESTree.Node | null,
): Finding | null {
  if (!info.isAsync || !info.hasAwait) return null;
  const params = funcNode.params;
  if (params.length === 0) return null;
  const firstParam = params[0];
  if (firstParam.type !== 'Identifier') return null;
  const firstName = (firstParam as TSESTree.Identifier).name;
  if (firstName !== 'err' && firstName !== 'error') return null;
  // Pattern C: event listener / message handler callbacks — not a real callback-style mix
  if (isEventListenerCallback(funcNode, parent)) return null;
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

    // Pre-collect ranges of classes that implement interfaces (NestJS, etc.)
    const implementingClassRanges: Array<[number, number]> = [];
    walk(ast, {
      enter(rawNode) {
        if (rawNode.type !== 'ClassDeclaration' && rawNode.type !== 'ClassExpression') return;
        const cls = rawNode as TSESTree.ClassDeclaration | TSESTree.ClassExpression;
        if ((cls.implements && cls.implements.length > 0 || cls.superClass) && cls.range) {
          implementingClassRanges.push([cls.range[0], cls.range[1]]);
        }
      },
    });

    walk(ast, {
      enter(rawNode, parent) {
        if (!isFunctionNode(rawNode)) return;
        const funcNode = rawNode as TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression;
        const info = analyzeFunctionAsync(funcNode);
        const asyncNoAwait = checkAsyncNoAwait(info, source, filePath, implementingClassRanges, parent);
        if (asyncNoAwait) findings.push(asyncNoAwait);
        const mixed = checkMixedPatterns(info, source, filePath);
        if (mixed) findings.push(mixed);
        if (funcNode.type !== 'FunctionDeclaration') {
          const cbMixed = checkCallbackStyleMixedWithAsync(
            funcNode as TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression,
            info, source, filePath, parent,
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

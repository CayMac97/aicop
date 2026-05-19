import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier } from '../../../utils/ast-helpers.js';

interface FunctionInfo {
  node: TSESTree.Node;
  hasAwait: boolean;
  hasTryCatch: boolean;
  hasDotCatch: boolean;
  hasThen: boolean;
  hasEmptyCatch: boolean;
  awaitOutsideTry: boolean;
}

function handleCatchClause(clause: TSESTree.CatchClause, info: FunctionInfo, source: string): void {
  const body = clause.body.body;
  const isEmpty = body.length === 0 || (body.length === 1 && body[0]?.type === 'EmptyStatement');
  if (!isEmpty) return;
  const range = clause.body.range;
  if (!range || range.length < 2) { info.hasEmptyCatch = true; return; }
  const catchBodyText = source.slice(range[0] + 1, range[1] - 1);
  if (!catchBodyText.includes('//') && !catchBodyText.includes('/*')) {
    info.hasEmptyCatch = true;
  }
}

function handleCallExpressionForAsync(ce: TSESTree.CallExpression, info: FunctionInfo): void {
  if (ce.callee.type !== 'MemberExpression') return;
  const me = ce.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return;
  const name = (me.property as TSESTree.Identifier).name;
  if (name === 'catch') info.hasDotCatch = true;
  if (name === 'then') info.hasThen = true;
}

function collectFunctionInfo(funcNode: TSESTree.Node, source: string): FunctionInfo {
  const info: FunctionInfo = {
    node: funcNode,
    hasAwait: false,
    hasTryCatch: false,
    hasDotCatch: false,
    hasThen: false,
    hasEmptyCatch: false,
    awaitOutsideTry: false,
  };
  let insideTry = 0;
  let insideAwait = 0;

  walk(funcNode as TSESTree.Program, {
    enter(node) {
      if (node.type === 'TryStatement') { insideTry++; info.hasTryCatch = true; return; }
      if (node.type === 'AwaitExpression') {
        insideAwait++;
        info.hasAwait = true;
        if (insideTry === 0) info.awaitOutsideTry = true;
        return;
      }
      if (node.type === 'CatchClause') {
        handleCatchClause(node as TSESTree.CatchClause, info, source);
        return;
      }
      if (node.type === 'CallExpression' && insideAwait === 0) {
        handleCallExpressionForAsync(node as TSESTree.CallExpression, info);
      }
    },
    exit(node) {
      if (node.type === 'TryStatement') insideTry--;
      if (node.type === 'AwaitExpression') insideAwait--;
    },
  });

  return info;
}

function buildFinding(info: FunctionInfo, message: string, source: string, filePath: string): Finding {
  return {
    ruleId: 'ai-smell/inconsistent-error-handling',
    severity: 'warn',
    message,
    file: filePath,
    line: getLine(info.node),
    column: getColumn(info.node),
    snippet: extractSnippet(source, getLine(info.node)),
    fix: 'Pick one error handling pattern (async/await + try/catch is recommended) and apply it consistently',
  };
}

const rule: Rule = {
  id: 'ai-smell/inconsistent-error-handling',
  name: 'Inconsistent Error Handling',
  category: 'ai-smell',
  severity: 'warn',
  description: 'Detects async functions with mixed try/catch and .catch() patterns, empty catch blocks, and unhandled rejections',
  why: 'Inconsistent error handling makes code difficult to reason about, leads to swallowed exceptions, and indicates the code was assembled from different sources without review.',
  fix: 'Adopt async/await + try/catch throughout. Never leave catch blocks empty. Always handle or re-throw errors.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const seenKeys = new Set<string>();
    const funcTypes = ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'];

    walk(ast, {
      enter(rawNode, parentNode) {
        if (!funcTypes.includes(rawNode.type)) return;
        const funcNode = rawNode as TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression;
        if (!funcNode.async) return;
        if (
          parentNode?.type === 'NewExpression' ||
          parentNode?.type === 'Property'
        ) return;
        const info = collectFunctionInfo(funcNode, source);
        const push = (msg: string): void => {
          const key = `${getLine(info.node)}:${getColumn(info.node)}:${msg}`;
          if (seenKeys.has(key)) return;
          seenKeys.add(key);
          findings.push(buildFinding(info, msg, source, filePath));
        };
        if (info.hasEmptyCatch) {
          push('Async function has an empty catch block — errors are silently swallowed');
        }
        if (info.hasAwait && info.hasThen) {
          push('Async function mixes await and .then() — pick one pattern');
        }
        if (info.hasAwait && info.hasDotCatch) {
          push('Async function mixes await with .catch() — use try/catch instead');
        }
      },
    });

    return findings;
  },
};

export default rule;

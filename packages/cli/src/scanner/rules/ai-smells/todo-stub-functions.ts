import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isStringLiteral, isIdentifier } from '../../../utils/ast-helpers.js';

const TODO_PATTERN = /\/\/\s*(?:TODO|FIXME|HACK|XXX|STUB)\b/i;
const NOT_IMPLEMENTED_PATTERN = /not\s+implemented/i;
const STUB_RETURN_NAMES = /^(?:get|fetch|load|retrieve|find|list|create|update|delete|process|handle|validate)/i;

function isNotImplementedThrow(body: TSESTree.BlockStatement): boolean {
  if (body.body.length !== 1) return false;
  const stmt = body.body[0];
  if (!stmt || stmt.type !== 'ThrowStatement') return false;
  const throwStmt = stmt as TSESTree.ThrowStatement;
  const argument = throwStmt.argument as TSESTree.Node | null;
  if (!argument || argument.type !== 'NewExpression') return false;
  const newExpr = argument as TSESTree.NewExpression;
  if (!isIdentifier(newExpr.callee)) return false;
  if ((newExpr.callee as TSESTree.Identifier).name !== 'Error') return false;
  const msgArg = newExpr.arguments[0];
  if (!msgArg || !isStringLiteral(msgArg as TSESTree.Expression)) return false;
  return NOT_IMPLEMENTED_PATTERN.test(String((msgArg as TSESTree.StringLiteral).value));
}

function isHardcodedPlaceholderReturn(body: TSESTree.BlockStatement, funcName: string): boolean {
  if (!STUB_RETURN_NAMES.test(funcName)) return false;
  if (body.body.length !== 1) return false;
  const stmt = body.body[0];
  if (!stmt || stmt.type !== 'ReturnStatement') return false;
  const ret = stmt as TSESTree.ReturnStatement;
  if (!ret.argument) return false;
  const arg = ret.argument;
  if (arg.type === 'ArrayExpression' && (arg as TSESTree.ArrayExpression).elements.length === 0) return true;
  if (arg.type === 'ObjectExpression') return true;
  return false;
}

function getFunctionName(node: TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression): string {
  if (node.type === 'FunctionDeclaration' && node.id) return node.id.name;
  return '';
}

function checkFunction(
  node: TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression,
  source: string,
  filePath: string,
): Finding | null {
  const body = node.body;
  if (!body || body.type !== 'BlockStatement') return null;
  const funcName = getFunctionName(node);
  if (isNotImplementedThrow(body)) {
    return {
      ruleId: 'ai-smell/todo-stub-functions',
      severity: 'warn',
      message: `Function "${funcName || '(anonymous)'}" is a stub — throws "Not implemented"`,
      file: filePath,
      line: getLine(node),
      column: getColumn(node),
      snippet: extractSnippet(source, getLine(node)),
      fix: 'Implement the function body or remove it if unused',
    };
  }
  if (funcName && isHardcodedPlaceholderReturn(body, funcName)) {
    return {
      ruleId: 'ai-smell/todo-stub-functions',
      severity: 'warn',
      message: `Function "${funcName}" returns a hardcoded placeholder value`,
      file: filePath,
      line: getLine(node),
      column: getColumn(node),
      snippet: extractSnippet(source, getLine(node)),
      fix: 'Implement the actual logic or mark clearly as a mock for testing purposes',
    };
  }
  return null;
}

const rule: Rule = {
  id: 'ai-smell/todo-stub-functions',
  name: 'TODO / Stub Functions',
  category: 'ai-smell',
  severity: 'warn',
  description: 'Detects functions that are stubs: not-implemented throws, hardcoded placeholders, and TODO-only bodies',
  why: 'Stub functions in production code cause silent failures, unexpected behavior, and represent incomplete AI-generated scaffolding that was never filled in.',
  fix: 'Either fully implement the function or remove it. If it\'s intentionally a placeholder, document it clearly and exclude it from the build.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const funcTypes = new Set(['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']);

    // Collect function body line ranges so we only flag TODOs inside functions
    const funcBodyRanges: Array<[number, number]> = [];
    walk(ast, {
      enter(rawNode) {
        if (!funcTypes.has(rawNode.type)) return;
        const fn = rawNode as TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression;
        if (fn.body?.type === 'BlockStatement' && fn.body.loc) {
          funcBodyRanges.push([fn.body.loc.start.line, fn.body.loc.end.line]);
        }
      },
    });

    const lines = source.split('\n');
    lines.forEach((line, idx) => {
      if (!TODO_PATTERN.test(line)) return;
      const lineNum = idx + 1;
      const insideFunction = funcBodyRanges.some(([start, end]) => lineNum > start && lineNum < end);
      if (!insideFunction) return;
      findings.push({
        ruleId: 'ai-smell/todo-stub-functions',
        severity: 'warn',
        message: 'TODO/FIXME/STUB comment found in production code',
        file: filePath,
        line: lineNum,
        column: 0,
        snippet: line.trim(),
        fix: 'Resolve the TODO or track it in your issue tracker, then remove the comment',
      });
    });

    walk(ast, {
      enter(rawNode) {
        if (!funcTypes.has(rawNode.type)) return;
        const funcNode = rawNode as TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression;
        const finding = checkFunction(funcNode, source, filePath);
        if (finding) findings.push(finding);
      },
    });

    return findings;
  },
};

export default rule;

import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn } from '../../../utils/ast-helpers.js';
const WARN_LINE_LIMIT = 60;
const ERROR_LINE_LIMIT = 100;

function countFunctionLines(funcNode: TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression): number {
  const body = funcNode.body;
  if (!body) return 0;
  if (body.type !== 'BlockStatement') return 1;
  const startLine = body.loc.start.line;
  const endLine = body.loc.end.line;
  return endLine - startLine + 1;
}

function getFunctionName(node: TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression): string {
  if (node.type === 'FunctionDeclaration' && node.id) return node.id.name;
  if (node.type === 'FunctionExpression' && node.id) return node.id.name;
  return '(anonymous)';
}

function isFunctionNode(node: TSESTree.Node): node is TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression {
  return node.type === 'FunctionDeclaration' ||
    node.type === 'FunctionExpression' ||
    node.type === 'ArrowFunctionExpression';
}

const rule: Rule = {
  id: 'tech-debt/function-length',
  name: 'Function Length',
  category: 'tech-debt',
  severity: 'warn',
  description: 'Detects functions exceeding 60 lines (warn) or 100 lines (error) — a sign of poor decomposition',
  why: 'Long functions are hard to read, test, and maintain. They typically do too many things. AI models often generate monolithic functions instead of composing smaller ones.',
  fix: 'Split the function into smaller, single-responsibility functions. Aim for functions that fit on one screen.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    walk(ast, {
      enter(rawNode) {
        if (!isFunctionNode(rawNode)) return;
        const funcNode = rawNode as TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression;
        const lines = countFunctionLines(funcNode);
        if (lines <= WARN_LINE_LIMIT) return;
        const funcName = getFunctionName(funcNode);
        const severity = lines > ERROR_LINE_LIMIT ? 'error' : 'warn';
        findings.push({
          ruleId: 'tech-debt/function-length',
          severity,
          message: `Function "${funcName}" is ${lines} lines (warn >${WARN_LINE_LIMIT}, error >${ERROR_LINE_LIMIT})`,
          file: filePath,
          line: getLine(funcNode),
          column: getColumn(funcNode),
          snippet: extractSnippet(source, getLine(funcNode)),
          fix: `Split "${funcName}" into smaller functions, each responsible for one thing`,
        });
      },
    });

    return findings;
  },
};

export default rule;

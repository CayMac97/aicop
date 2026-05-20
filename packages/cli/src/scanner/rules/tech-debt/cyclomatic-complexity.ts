import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn } from '../../../utils/ast-helpers.js';

const COMPLEXITY_INCREMENTORS = new Set([
  'IfStatement', 'ElseStatement', 'ForStatement', 'ForInStatement', 'ForOfStatement',
  'WhileStatement', 'DoWhileStatement', 'SwitchCase', 'CatchClause',
]);

const LOGICAL_OPERATORS = new Set(['&&', '||', '??']);

// A lookup switch: every case has only return/throw/break with no nested logic.
function isLookupSwitch(node: TSESTree.SwitchStatement): boolean {
  return node.cases.every((c) => {
    if (c.consequent.length === 0) return true; // fallthrough
    if (c.consequent.length > 1) return false;
    const stmt = c.consequent[0];
    if (stmt.type === 'ReturnStatement' || stmt.type === 'ThrowStatement' || stmt.type === 'BreakStatement') return true;
    return false;
  });
}

function getFunctionName(node: TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression): string {
  if (node.type === 'FunctionDeclaration' && node.id) return node.id.name;
  if (node.type === 'FunctionExpression' && node.id) return node.id.name;
  return '(anonymous)';
}

function calculateComplexity(funcNode: TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression): number {
  let complexity = 1;
  let nestedFuncDepth = 0;
  const lookupSwitchNodes = new Set<TSESTree.Node>();

  walk(funcNode, {
    enter(node) {
      if (node !== funcNode && isFunctionNode(node)) { nestedFuncDepth++; return; }
      if (nestedFuncDepth > 0) return;
      if (node.type === 'SwitchStatement' && isLookupSwitch(node as TSESTree.SwitchStatement)) {
        for (const c of (node as TSESTree.SwitchStatement).cases) lookupSwitchNodes.add(c);
        return; // count as 1 (the SwitchStatement itself) via the base path
      }
      if (COMPLEXITY_INCREMENTORS.has(node.type) && !lookupSwitchNodes.has(node)) complexity++;
    },
    LogicalExpression(rawNode) {
      if (nestedFuncDepth > 0) return;
      const le = rawNode as TSESTree.LogicalExpression;
      if (LOGICAL_OPERATORS.has(le.operator)) complexity++;
    },
    ConditionalExpression() {
      if (nestedFuncDepth > 0) return;
      complexity++;
    },
    exit(node) {
      if (node !== funcNode && isFunctionNode(node)) nestedFuncDepth--;
    },
  });

  return complexity;
}

function isFunctionNode(node: TSESTree.Node): node is TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression {
  return node.type === 'FunctionDeclaration' ||
    node.type === 'FunctionExpression' ||
    node.type === 'ArrowFunctionExpression';
}

const rule: Rule = {
  id: 'tech-debt/cyclomatic-complexity',
  name: 'Cyclomatic Complexity',
  category: 'tech-debt',
  severity: 'warn',
  description: 'Detects functions with high cyclomatic complexity that are hard to test and maintain',
  why: 'High cyclomatic complexity means many execution paths, requiring more tests and increasing the chance of bugs. Functions above complexity 10 should be split.',
  fix: 'Break complex functions into smaller, focused functions. Extract conditions into well-named predicate functions.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    walk(ast, {
      enter(rawNode) {
        if (!isFunctionNode(rawNode)) return;
        const funcNode = rawNode as TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression;
        const complexity = calculateComplexity(funcNode);
        if (complexity < 12) return;
        const funcName = getFunctionName(funcNode);
        const severity = complexity > 15 ? 'error' : 'warn';
        const message = complexity > 15
          ? `Function "${funcName}" has cyclomatic complexity ${complexity} (limit: 15) — split it up`
          : `Function "${funcName}" has cyclomatic complexity ${complexity} (limit: 15) — consider splitting`;
        findings.push({
          ruleId: 'tech-debt/cyclomatic-complexity',
          severity,
          message,
          file: filePath,
          line: getLine(funcNode),
          column: getColumn(funcNode),
          snippet: extractSnippet(source, getLine(funcNode)),
          fix: 'Extract complex branches into smaller, well-named helper functions',
        });
      },
    });

    return findings;
  },
};

export default rule;

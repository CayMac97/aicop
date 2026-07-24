import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet, isTestFile } from '../../../utils/file-utils.js';
import { getLine, getColumn } from '../../../utils/ast-helpers.js';

function countLines(node: TSESTree.Node): number {
  if (!node.loc) return 0;
  return node.loc.end.line - node.loc.start.line + 1;
}

function getFunctionName(node: TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression): string {
  if (node.type === 'FunctionDeclaration' && node.id) return node.id.name;
  if (node.type === 'FunctionExpression' && node.id) return node.id.name;
  return '(anonymous)';
}

const rule: Rule = {
  id: 'tech-debt/god-functions',
  name: 'God Functions',
  category: 'tech-debt',
  severity: 'error',
  description: 'Detects "God Functions" that do everything (highly complex, deeply nested, very long, and many parameters)',
  why: 'God functions are unmaintainable. They violate the Single Responsibility Principle and are highly prone to bugs.',
  fix: 'Refactor the function into multiple smaller, focused functions or classes.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    if (isTestFile(filePath)) return findings;

    walk(ast, {
      enter(node) {
        if (
          node.type === 'FunctionDeclaration' ||
          node.type === 'FunctionExpression' ||
          node.type === 'ArrowFunctionExpression'
        ) {
          const lines = countLines(node);
          const paramCount = node.params.length;
          
          if (lines > 80 && paramCount >= 5) {
            findings.push({
              ruleId: 'tech-debt/god-functions',
              severity: 'error',
              message: `Function "${getFunctionName(node)}" is a God Function (${lines} lines, ${paramCount} parameters)`,
              file: filePath,
              line: getLine(node),
              column: getColumn(node),
              snippet: extractSnippet(source, getLine(node)),
              fix: 'Extract logic into smaller helper functions or use an options object for parameters',
            });
          }
        }
      },
    });

    return findings;
  },
};

export default rule;

import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn } from '../../../utils/ast-helpers.js';

const NESTING_NODES = new Set([
  'IfStatement', 'ForStatement', 'ForInStatement', 'ForOfStatement',
  'WhileStatement', 'DoWhileStatement', 'TryStatement', 'SwitchStatement',
]);

const WARN_DEPTH = 4;
const ERROR_DEPTH = 6;

interface NestingContext {
  depth: number;
  maxDepth: number;
  deepestNode: TSESTree.Node | null;
}

function isAstNode(val: unknown): val is TSESTree.Node {
  return val !== null && typeof val === 'object' && 'type' in (val as object);
}

function walkChildren(root: TSESTree.Node, ctx: NestingContext): void {
  for (const key of Object.keys(root)) {
    if (key === 'parent' || key === 'tokens' || key === 'comments') continue;
    const val = (root as Record<string, unknown>)[key];
    if (Array.isArray(val)) {
      for (const child of val) {
        if (isAstNode(child)) walkWithDepth(child, ctx);
      }
    } else if (isAstNode(val)) {
      walkWithDepth(val, ctx);
    }
  }
}

function walkWithDepth(root: TSESTree.Node, ctx: NestingContext): void {
  const isNesting = NESTING_NODES.has(root.type);
  if (isNesting) {
    ctx.depth++;
    if (ctx.depth > ctx.maxDepth) {
      ctx.maxDepth = ctx.depth;
      ctx.deepestNode = root;
    }
  }
  walkChildren(root, ctx);
  if (isNesting) ctx.depth--;
}

function isFunctionNode(node: TSESTree.Node): boolean {
  return node.type === 'FunctionDeclaration' ||
    node.type === 'FunctionExpression' ||
    node.type === 'ArrowFunctionExpression';
}

const rule: Rule = {
  id: 'tech-debt/nesting-depth',
  name: 'Nesting Depth',
  category: 'tech-debt',
  severity: 'warn',
  description: 'Detects functions with excessive nesting depth — warn at >3, error at >5 levels deep',
  why: 'Deep nesting is a primary readability problem. It indicates complex conditional logic that should be flattened with early returns, guard clauses, or extracted functions.',
  fix: 'Use early returns to reduce nesting: "if (!condition) return;" instead of wrapping everything in "if (condition) { ... }"',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    walk(ast, {
      enter(rawNode) {
        if (!isFunctionNode(rawNode)) return;
        const ctx: NestingContext = { depth: 0, maxDepth: 0, deepestNode: null };
        walkWithDepth(rawNode, ctx);
        if (ctx.maxDepth <= WARN_DEPTH) return;
        if (!ctx.deepestNode) return;
        const severity = ctx.maxDepth > ERROR_DEPTH ? 'error' : 'warn';
        findings.push({
          ruleId: 'tech-debt/nesting-depth',
          severity,
          message: `Nesting depth of ${ctx.maxDepth} detected (warn: ${WARN_DEPTH + 1}, error: ${ERROR_DEPTH + 1})`,
          file: filePath,
          line: getLine(ctx.deepestNode),
          column: getColumn(ctx.deepestNode),
          snippet: extractSnippet(source, getLine(ctx.deepestNode)),
          fix: 'Use early returns (guard clauses) and extract nested blocks into helper functions',
        });
      },
    });

    return findings;
  },
};

export default rule;

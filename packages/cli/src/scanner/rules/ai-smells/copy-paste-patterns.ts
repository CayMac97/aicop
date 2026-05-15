import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn } from '../../../utils/ast-helpers.js';

interface FunctionBody {
  node: TSESTree.Node;
  normalizedLines: string[];
  startLine: number;
}

const MIN_LINES_FOR_DUPLICATE = 5;

function normalizeStatement(stmt: TSESTree.Statement): string {
  const src = JSON.stringify(stmt);
  return src
    .replace(/"name":"[^"]+"/g, '"name":"$ID"')
    .replace(/"value":"[^"]+"/g, '"value":"$LIT"')
    .replace(/"raw":"[^"]+"/g, '"raw":"$LIT"')
    .replace(/"value":\d+(\.\d+)?/g, '"value":"$NUM"')
    .replace(/"value":true/g, '"value":"$BOOL"')
    .replace(/"value":false/g, '"value":"$BOOL"');
}

function extractFunctionBodies(ast: ParsedAST): FunctionBody[] {
  const bodies: FunctionBody[] = [];
  const funcTypes = new Set(['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']);

  walk(ast, {
    enter(rawNode) {
      if (!funcTypes.has(rawNode.type)) return;
      const funcNode = rawNode as TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression;
      const body = funcNode.body;
      if (!body || body.type !== 'BlockStatement') return;
      const stmts = (body as TSESTree.BlockStatement).body;
      if (stmts.length < MIN_LINES_FOR_DUPLICATE) return;
      bodies.push({
        node: funcNode,
        normalizedLines: stmts.map(normalizeStatement),
        startLine: getLine(funcNode),
      });
    },
  });

  return bodies;
}

function normalizeFuncBody(body: FunctionBody): string {
  return body.normalizedLines.join('|');
}

const rule: Rule = {
  id: 'ai-smell/copy-paste-patterns',
  name: 'Copy-Paste Patterns',
  category: 'ai-smell',
  severity: 'warn',
  description: 'Detects structurally identical function bodies that suggest copy-paste code generation',
  why: 'Duplicate code blocks mean bugs get fixed in one place but not another. AI models frequently generate boilerplate-heavy code that should be extracted into shared utilities.',
  fix: 'Extract the common logic into a shared function or module. Apply DRY (Don\'t Repeat Yourself) principles.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const bodies = extractFunctionBodies(ast);
    const seen = new Map<string, number>();

    for (const body of bodies) {
      const key = normalizeFuncBody(body);
      const existing = seen.get(key);
      if (existing !== undefined) {
        findings.push({
          ruleId: 'ai-smell/copy-paste-patterns',
          severity: 'warn',
          message: `Function body is structurally identical to function at line ${existing} — likely copy-pasted`,
          file: filePath,
          line: body.startLine,
          column: getColumn(body.node),
          snippet: extractSnippet(source, body.startLine),
          fix: 'Extract the shared logic into a reusable function or utility',
        });
      } else {
        seen.set(key, body.startLine);
      }
    }

    return findings;
  },
};

export default rule;

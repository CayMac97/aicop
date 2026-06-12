import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet, isTestFile } from '../../../utils/file-utils.js';
import { getLine, getColumn } from '../../../utils/ast-helpers.js';


interface FunctionBody {
  node: TSESTree.Node;
  name: string;
  normalizedLines: string[];
  startLine: number;
}

const MIN_STMTS_FOR_DUPLICATE = 10;

function getFunctionName(node: TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression): string {
  if (node.type === 'FunctionDeclaration' && node.id) return node.id.name;
  const parent = (node as unknown as { parent?: TSESTree.Node }).parent;
  if (parent?.type === 'VariableDeclarator') {
    const decl = parent as TSESTree.VariableDeclarator;
    if (decl.id.type === 'Identifier') return (decl.id as TSESTree.Identifier).name;
  }
  if (parent?.type === 'Property') {
    const prop = parent as TSESTree.Property;
    if (prop.key.type === 'Identifier') return (prop.key as TSESTree.Identifier).name;
  }
  if (parent?.type === 'AssignmentExpression') {
    const assign = parent as TSESTree.AssignmentExpression;
    if (assign.left.type === 'MemberExpression') {
      const me = assign.left as TSESTree.MemberExpression;
      if (me.property.type === 'Identifier') return (me.property as TSESTree.Identifier).name;
    }
    if (assign.left.type === 'Identifier') return (assign.left as TSESTree.Identifier).name;
  }
  return '<anonymous>';
}

const SKIP_KEYS = new Set(['loc', 'range', 'start', 'end', 'parent']);

function normalizeStatement(stmt: TSESTree.Statement): string {
  const src = JSON.stringify(stmt, (key, val) => (SKIP_KEYS.has(key) ? undefined : val));
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
      if (stmts.length < MIN_STMTS_FOR_DUPLICATE) return;
      bodies.push({
        node: funcNode,
        name: getFunctionName(funcNode),
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
    if (isTestFile(filePath)) return findings;
    const bodies = extractFunctionBodies(ast);
    const seen = new Map<string, { line: number; name: string }>();

    for (const body of bodies) {
      const key = normalizeFuncBody(body);
      const existing = seen.get(key);
      if (existing !== undefined) {
        findings.push({
          ruleId: 'ai-smell/copy-paste-patterns',
          severity: 'warn',
          message: `Function '${body.name}' (line ${body.startLine}) is structurally identical to '${existing.name}' (line ${existing.line}) — likely copy-pasted`,
          file: filePath,
          line: body.startLine,
          column: getColumn(body.node),
          snippet: extractSnippet(source, body.startLine),
          fix: 'Extract the shared logic into a reusable function or utility',
        });
      } else {
        seen.set(key, { line: body.startLine, name: body.name });
      }
    }

    return findings;
  },
};

export default rule;

import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression, isCallExpression } from '../../../utils/ast-helpers.js';

const DB_FIND_METHODS = new Set(['findOne', 'findById', 'findFirst', 'findUnique', 'get', 'first']);

const REQ_RES_PROPS = new Set(['body', 'user', 'params', 'query', 'files', 'locals', 'session', 'cookies', 'headers', 'nextUrl', 'signal', 'url', 'method']);

function isReqOrResAccess(node: TSESTree.MemberExpression): boolean {
  const obj = node.object;
  if (isIdentifier(obj)) {
    const name = (obj as TSESTree.Identifier).name;
    if (name === 'req' || name === 'res' || name === 'request' || name === 'response') return true;
  }
  if (isMemberExpression(obj)) {
    const me = obj as TSESTree.MemberExpression;
    if (isIdentifier(me.object)) {
      const root = (me.object as TSESTree.Identifier).name;
      if (root === 'req' || root === 'res' || root === 'request' || root === 'response') return true;
      if (isIdentifier(me.property) && REQ_RES_PROPS.has((me.property as TSESTree.Identifier).name)) return true;
    }
  }
  return false;
}

function checkArrayIndexAccess(node: TSESTree.MemberExpression, source: string, filePath: string): Finding | null {
  if (!node.computed) return null;
  if (node.property.type !== 'Literal') return null;
  const indexVal = (node.property as TSESTree.Literal).value;
  if (typeof indexVal !== 'number' || indexVal !== 0) return null;
  if (node.object.type !== 'Identifier') return null;
  if (node.optional) return null;

  const varName = (node.object as TSESTree.Identifier).name;

  if (isReqOrResAccess(node)) return null;

  const snippet = extractSnippet(source, getLine(node), 2);
  if (
    snippet.includes(`${varName}.length`) ||
    snippet.includes(`${varName}?.`) ||
    snippet.includes('?.') ||
    snippet.includes('??') ||
    snippet.includes(`${varName} &&`)
  ) return null;

  return {
    ruleId: 'ai-smell/missing-null-checks',
    severity: 'warn',
    message: `accessing ${varName}[0] without a length check`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet,
    fix: `Check array length first: if (${varName}.length > 0) { ... }`,
  };
}

function isDbFindCall(node: TSESTree.CallExpression): boolean {
  if (!isMemberExpression(node.callee)) return false;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return false;
  return DB_FIND_METHODS.has((me.property as TSESTree.Identifier).name);
}

function checkDbResultAccess(ast: ParsedAST, source: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const dbVars = new Set<string>();

  walk(ast, {
    VariableDeclarator(rawNode) {
      const node = rawNode as TSESTree.VariableDeclarator;
      if (!node.init) return;
      let init = node.init;
      if (init.type === 'AwaitExpression') {
        init = (init as TSESTree.AwaitExpression).argument as TSESTree.Expression;
      }
      if (!isCallExpression(init)) return;
      if (!isDbFindCall(init as TSESTree.CallExpression)) return;
      if (node.id.type !== 'Identifier') return;
      dbVars.add((node.id as TSESTree.Identifier).name);
    },
  });

  if (dbVars.size === 0) return findings;

  walk(ast, {
    MemberExpression(rawNode) {
      const node = rawNode as TSESTree.MemberExpression;
      if (!isIdentifier(node.object)) return;
      const varName = (node.object as TSESTree.Identifier).name;
      if (!dbVars.has(varName)) return;
      if (node.optional) return;

      const line = getLine(node);
      const snippet = extractSnippet(source, line, 3);
      if (
        snippet.includes(`if (${varName})`) ||
        snippet.includes(`if (!${varName})`) ||
        snippet.includes(`${varName} &&`) ||
        snippet.includes(`${varName}?.`) ||
        snippet.includes(`${varName} !=`) ||
        snippet.includes(`${varName} ==`)
      ) return;

      findings.push({
        ruleId: 'ai-smell/missing-null-checks',
        severity: 'warn',
        message: `${varName} from DB query may be null — check before accessing`,
        file: filePath,
        line,
        column: getColumn(node),
        snippet,
        fix: `if (!${varName}) return; // or handle the null case`,
      });
    },
  });

  return findings;
}

function checkJsonParseResult(ast: ParsedAST, source: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const jsonVars = new Set<string>();

  walk(ast, {
    VariableDeclarator(rawNode) {
      const node = rawNode as TSESTree.VariableDeclarator;
      if (!node.init) return;
      if (!isCallExpression(node.init)) return;
      const call = node.init as TSESTree.CallExpression;
      if (!isMemberExpression(call.callee)) return;
      const me = call.callee as TSESTree.MemberExpression;
      if (!isIdentifier(me.object) || !isIdentifier(me.property)) return;
      if ((me.object as TSESTree.Identifier).name !== 'JSON') return;
      if ((me.property as TSESTree.Identifier).name !== 'parse') return;
      if (node.id.type !== 'Identifier') return;
      jsonVars.add((node.id as TSESTree.Identifier).name);
    },
  });

  if (jsonVars.size === 0) return findings;

  walk(ast, {
    MemberExpression(rawNode) {
      const node = rawNode as TSESTree.MemberExpression;
      if (!isMemberExpression(node.object)) return;
      const parent = node.object as TSESTree.MemberExpression;
      if (!isIdentifier(parent.object)) return;
      const varName = (parent.object as TSESTree.Identifier).name;
      if (!jsonVars.has(varName)) return;
      if (node.optional || parent.optional) return;

      const line = getLine(node);
      const snippet = extractSnippet(source, line, 3);
      if (
        snippet.includes(`if (${varName})`) ||
        snippet.includes(`${varName} &&`) ||
        snippet.includes(`${varName}?.`) ||
        snippet.includes('try {') ||
        snippet.includes('try{')
      ) return;

      findings.push({
        ruleId: 'ai-smell/missing-null-checks',
        severity: 'warn',
        message: `${varName} from JSON.parse() used without null check — may throw if parse fails`,
        file: filePath,
        line,
        column: getColumn(node),
        snippet,
        fix: `Wrap JSON.parse() in try/catch and check the result before accessing properties`,
      });
    },
  });

  return findings;
}

const rule: Rule = {
  id: 'ai-smell/missing-null-checks',
  name: 'Missing Null Checks',
  category: 'ai-smell',
  severity: 'warn',
  description: 'Detects array[0] access without length checks, unguarded DB query results, and unguarded JSON.parse usage',
  why: 'AI-generated code frequently accesses data without checking for null/undefined first. Empty arrays, missing DB records, and failed JSON parses all produce null/undefined which causes TypeErrors at runtime.',
  fix: 'Check for null before accessing properties. Use optional chaining (?.) for uncertain access.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    walk(ast, {
      MemberExpression(rawNode) {
        const f = checkArrayIndexAccess(rawNode as TSESTree.MemberExpression, source, filePath);
        if (f) findings.push(f);
      },
    });

    findings.push(...checkDbResultAccess(ast, source, filePath));
    findings.push(...checkJsonParseResult(ast, source, filePath));

    return findings;
  },
};

export default rule;

import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression, isCallExpression } from '../../../utils/ast-helpers.js';

const DB_FIND_METHODS = new Set(['findOne', 'findById', 'findFirst', 'findUnique', 'first']);

const REQ_RES_PROPS = new Set(['body', 'user', 'params', 'query', 'files', 'locals', 'session', 'cookies', 'headers', 'nextUrl', 'signal', 'url', 'method']);
const REQ_ROOT_NAMES = new Set(['req', 'res', 'request', 'response']);

function isReqOrResAccess(node: TSESTree.MemberExpression): boolean {
  const obj = node.object;
  if (isIdentifier(obj) && REQ_ROOT_NAMES.has((obj as TSESTree.Identifier).name)) return true;
  if (isMemberExpression(obj)) {
    const me = obj as TSESTree.MemberExpression;
    if (!isIdentifier(me.object)) return false;
    const root = (me.object as TSESTree.Identifier).name;
    return REQ_ROOT_NAMES.has(root) || (isIdentifier(me.property) && REQ_RES_PROPS.has((me.property as TSESTree.Identifier).name));
  }
  return false;
}

function hasNullSafetyInSnippet(snippet: string, varName: string): boolean {
  return snippet.includes(`${varName}.length`)
    || snippet.includes(`${varName}?.`)
    || snippet.includes('?.')
    || snippet.includes('??')
    || snippet.includes(`${varName} &&`)
    || snippet.includes(`${varName}[0] &&`)
    || snippet.includes(`${varName}[0]!`);
}

function checkArrayIndexAccess(
  node: TSESTree.MemberExpression,
  source: string,
  filePath: string,
  mysqlRowsVars: Set<string>,
  forOfVars: Set<string>,
  arrayLiteralVars: Set<string>,
): Finding | null {
  if (!node.computed) return null;
  if (node.property.type !== 'Literal') return null;
  const indexVal = (node.property as TSESTree.Literal).value;
  if (typeof indexVal !== 'number' || indexVal !== 0) return null;
  if (node.object.type !== 'Identifier') return null;
  if (node.optional) return null;

  const varName = (node.object as TSESTree.Identifier).name;
  const line = getLine(node);

  if (mysqlRowsVars.has(varName)) return null;
  if (forOfVars.has(varName)) return null;
  if (arrayLiteralVars.has(varName)) return null;
  if (isReqOrResAccess(node)) return null;
  if (hasSplitAssignment(source, varName, line)) return null;
  if (hasPriorNullGuard(source, varName, line)) return null;

  const snippet = extractSnippet(source, line, 2);
  if (hasNullSafetyInSnippet(snippet, varName)) return null;

  return {
    ruleId: 'ai-smell/missing-null-checks',
    severity: 'warn',
    message: `accessing ${varName}[0] without a length check`,
    file: filePath,
    line,
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

function unwrapAwait(node: TSESTree.Expression | TSESTree.PrivateIdentifier): TSESTree.Expression | TSESTree.PrivateIdentifier {
  return node.type === 'AwaitExpression' ? node.argument : node;
}

function isMysqlQueryCall(node: TSESTree.Node): boolean {
  if (!isCallExpression(node)) return false;
  const call = node as TSESTree.CallExpression;
  if (!isMemberExpression(call.callee)) return false;
  const me = call.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return false;
  const method = (me.property as TSESTree.Identifier).name;
  return method === 'query' || method === 'execute';
}

function collectMysqlRowsVars(ast: ParsedAST): Set<string> {
  const rowsVars = new Set<string>();

  walk(ast, {
    VariableDeclarator(rawNode) {
      const node = rawNode as TSESTree.VariableDeclarator;
      if (!node.init) return;
      const init = unwrapAwait(node.init);
      if (!isMysqlQueryCall(init as TSESTree.Node)) return;
      if (node.id.type === 'ArrayPattern') {
        const first = (node.id as TSESTree.ArrayPattern).elements[0];
        if (first?.type === 'Identifier') rowsVars.add((first as TSESTree.Identifier).name);
      } else if (node.id.type === 'Identifier') {
        rowsVars.add((node.id as TSESTree.Identifier).name);
      }
    },
  });

  return rowsVars;
}

function collectArrayLiteralVars(ast: ParsedAST): Set<string> {
  const vars = new Set<string>();
  walk(ast, {
    VariableDeclarator(rawNode) {
      const node = rawNode as TSESTree.VariableDeclarator;
      if (!node.init || node.init.type !== 'ArrayExpression') return;
      if (node.id.type !== 'Identifier') return;
      const arr = node.init as TSESTree.ArrayExpression;
      if (arr.elements.length > 0) vars.add((node.id as TSESTree.Identifier).name);
    },
    AssignmentExpression(rawNode) {
      const node = rawNode as TSESTree.AssignmentExpression;
      if (node.right.type !== 'ArrayExpression') return;
      if (node.left.type !== 'Identifier') return;
      const arr = node.right as TSESTree.ArrayExpression;
      if (arr.elements.length > 0) vars.add((node.left as TSESTree.Identifier).name);
    },
  });
  return vars;
}

function collectForOfVars(ast: ParsedAST): Set<string> {
  const vars = new Set<string>();
  walk(ast, {
    ForOfStatement(rawNode) {
      const node = rawNode as TSESTree.ForOfStatement;
      if (node.left.type !== 'VariableDeclaration') return;
      for (const decl of (node.left as TSESTree.VariableDeclaration).declarations) {
        if (decl.id.type === 'Identifier') vars.add((decl.id as TSESTree.Identifier).name);
      }
    },
  });
  return vars;
}

function hasSplitAssignment(source: string, varName: string, line: number): boolean {
  const lines = source.split('\n').slice(Math.max(0, line - 10), line + 1);
  const pattern = new RegExp(`\\b${varName}\\b.*\\.split\\(`);
  return lines.some((l) => pattern.test(l));
}

function hasPriorNullGuard(source: string, varName: string, line: number): boolean {
  const allLines = source.split('\n');
  const windowStart = Math.max(0, line - 50);
  const priorSource = allLines.slice(windowStart, line).join('\n');
  return (
    priorSource.includes(`!${varName}`) ||
    priorSource.includes(`if (${varName})`) ||
    priorSource.includes(`if (${varName} `) ||
    priorSource.includes(`${varName}.length`) ||
    priorSource.includes(`${varName} !== null`) ||
    priorSource.includes(`${varName} !== undefined`) ||
    priorSource.includes(`${varName} == null`) ||
    priorSource.includes(`${varName} === null`) ||
    priorSource.includes(`${varName} === undefined`) ||
    priorSource.includes(`${varName}?.`) ||
    priorSource.includes(`${varName} &&`)
  );
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
        || hasPriorNullGuard(source, varName, line)
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

function isJsonParseCall(node: TSESTree.CallExpression): boolean {
  if (!isMemberExpression(node.callee)) return false;
  const me = node.callee as TSESTree.MemberExpression;
  return isIdentifier(me.object) &&
    (me.object as TSESTree.Identifier).name === 'JSON' &&
    isIdentifier(me.property) &&
    (me.property as TSESTree.Identifier).name === 'parse';
}

function isInsideTryBlock(node: TSESTree.Node, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  let current: TSESTree.Node = node;
  for (let depth = 0; depth < 50; depth++) {
    const parent = parentMap.get(current);
    if (!parent) return false;
    if (parent.type === 'TryStatement') {
      const tryStat = parent as TSESTree.TryStatement;
      // Make sure we're in the try block, not the catch/finally
      if (tryStat.block === current) return true;
    }
    current = parent;
  }
  return false;
}

function buildParentMap(ast: ParsedAST): Map<TSESTree.Node, TSESTree.Node> {
  const map = new Map<TSESTree.Node, TSESTree.Node>();
  walk(ast, {
    enter(node, parent) {
      if (parent) map.set(node, parent);
    },
  });
  return map;
}

function checkJsonParseWithoutTryCatch(ast: ParsedAST, source: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const parentMap = buildParentMap(ast);

  walk(ast, {
    CallExpression(rawNode) {
      const node = rawNode as TSESTree.CallExpression;
      if (!isJsonParseCall(node)) return;
      const arg = node.arguments[0];
      if (!arg) return;
      // String literals can't throw SyntaxError (they're always valid JSON if syntactically valid)
      if (arg.type === 'Literal' && typeof (arg as TSESTree.Literal).value === 'string') return;
      if (isInsideTryBlock(node, parentMap)) return;
      findings.push({
        ruleId: 'ai-smell/missing-null-checks',
        severity: 'warn',
        message: 'JSON.parse() without try/catch — throws SyntaxError on invalid input',
        file: filePath,
        line: getLine(node),
        column: getColumn(node),
        snippet: extractSnippet(source, getLine(node)),
        fix: 'Wrap in try/catch: try { const data = JSON.parse(str); } catch (e) { /* handle invalid JSON */ }',
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
    const mysqlRowsVars = collectMysqlRowsVars(ast);
    const forOfVars = collectForOfVars(ast);
    const arrayLiteralVars = collectArrayLiteralVars(ast);

    const flaggedArrayVars = new Set<string>();
    walk(ast, {
      MemberExpression(rawNode) {
        const node = rawNode as TSESTree.MemberExpression;
        if (node.object.type === 'Identifier') {
          const varName = (node.object as TSESTree.Identifier).name;
          if (flaggedArrayVars.has(varName)) return;
          const f = checkArrayIndexAccess(node, source, filePath, mysqlRowsVars, forOfVars, arrayLiteralVars);
          if (f) {
            flaggedArrayVars.add(varName);
            findings.push(f);
          }
        } else {
          const f = checkArrayIndexAccess(node, source, filePath, mysqlRowsVars, forOfVars, arrayLiteralVars);
          if (f) findings.push(f);
        }
      },
    });

    findings.push(...checkDbResultAccess(ast, source, filePath));
    findings.push(...checkJsonParseResult(ast, source, filePath));
    findings.push(...checkJsonParseWithoutTryCatch(ast, source, filePath));

    return findings;
  },
};

export default rule;

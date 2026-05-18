import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { isStringLiteral, getLine, getColumn, isMemberExpression, isIdentifier } from '../../../utils/ast-helpers.js';

const SQL_VERB_PATTERN = /\b(SELECT|INSERT\s+INTO|UPDATE\s+\w|DELETE\s+FROM|DROP\s+TABLE|CREATE\s+TABLE|ALTER\s+TABLE|EXEC(?:UTE)?)\b/i;
const HTML_TAG_PATTERN = /<(?:select|table|input|form|option|textarea)\b/i;
const USER_INPUT_SOURCES = new Set(['params', 'body', 'query', 'headers', 'cookies']);
const PARAMETERIZED_PATTERN = /\?\s*[,)]/;

const DB_CALL_METHODS = new Set(['query', 'execute', 'raw', 'prepare', 'run', 'all', 'get']);
const SAFE_SINK_METHODS = new Set(['log', 'warn', 'error', 'info', 'debug', 'send', 'json', 'render', 'write', 'end', 'format', 'trace', 'dir', 'table', 'print']);
const SAFE_SINK_ROOTS = new Set(['console', 'logger', 'log', 'res', 'response', 'winston', 'pino', 'bunyan']);

function isExpressionNode(node: TSESTree.Expression | TSESTree.PrivateIdentifier): node is TSESTree.Expression {
  return node.type !== 'PrivateIdentifier';
}

function isUserInputExpression(node: TSESTree.Expression): boolean {
  if (!isMemberExpression(node)) return false;
  const me = node as TSESTree.MemberExpression;
  if (!isMemberExpression(me.object)) return false;
  const parent = me.object as TSESTree.MemberExpression;
  if (!isIdentifier(parent.object)) return false;
  const objName = (parent.object as TSESTree.Identifier).name;
  if (!isIdentifier(parent.property)) return false;
  const propName = (parent.property as TSESTree.Identifier).name;
  return objName === 'req' && USER_INPUT_SOURCES.has(propName);
}

function templateHasUserInput(node: TSESTree.TemplateLiteral): boolean {
  return node.expressions.some((expr) => {
    if (isUserInputExpression(expr)) return true;
    if (isIdentifier(expr)) return true;
    return false;
  });
}

function concatHasUserInput(node: TSESTree.BinaryExpression): boolean {
  if (node.operator !== '+') return false;
  if (!isExpressionNode(node.left) || !isExpressionNode(node.right)) return false;
  return isUserInputExpression(node.right) || isUserInputExpression(node.left) ||
    (isIdentifier(node.right) || isIdentifier(node.left));
}

function looksLikeSQL(text: string): boolean {
  if (!SQL_VERB_PATTERN.test(text)) return false;
  if (HTML_TAG_PATTERN.test(text)) return false;
  return true;
}

function isDbCall(node: TSESTree.CallExpression): boolean {
  if (!isMemberExpression(node.callee)) return false;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return false;
  return DB_CALL_METHODS.has((me.property as TSESTree.Identifier).name);
}

function isSafeSinkCall(node: TSESTree.CallExpression): boolean {
  if (!isMemberExpression(node.callee)) return false;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return false;
  if (!SAFE_SINK_METHODS.has((me.property as TSESTree.Identifier).name)) return false;
  let obj: TSESTree.Expression | TSESTree.PrivateIdentifier = me.object;
  while (isMemberExpression(obj)) {
    obj = (obj as TSESTree.MemberExpression).object;
  }
  if (!isIdentifier(obj)) return false;
  return SAFE_SINK_ROOTS.has((obj as TSESTree.Identifier).name.toLowerCase());
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

function findContext(
  sqlNode: TSESTree.Node,
  parentMap: Map<TSESTree.Node, TSESTree.Node>,
): { kind: 'db-call' | 'safe-sink' | 'var'; varName?: string } | null {
  let current = sqlNode;
  for (let depth = 0; depth < 15; depth++) {
    const parent = parentMap.get(current);
    if (!parent) return null;

    if (parent.type === 'CallExpression') {
      const call = parent as TSESTree.CallExpression;
      if (isDbCall(call)) return { kind: 'db-call' };
      if (isSafeSinkCall(call)) return { kind: 'safe-sink' };
      return null;
    }

    if (parent.type === 'VariableDeclarator') {
      const decl = parent as TSESTree.VariableDeclarator;
      if (isIdentifier(decl.id)) return { kind: 'var', varName: (decl.id as TSESTree.Identifier).name };
      return null;
    }

    if (parent.type === 'AssignmentExpression') {
      const assign = parent as TSESTree.AssignmentExpression;
      if (isExpressionNode(assign.left) && isIdentifier(assign.left)) {
        return { kind: 'var', varName: (assign.left as TSESTree.Identifier).name };
      }
      return null;
    }

    if (parent.type === 'FunctionDeclaration' || parent.type === 'FunctionExpression' || parent.type === 'ArrowFunctionExpression') {
      return null;
    }

    current = parent;
  }
  return null;
}

function collectDbCallVars(ast: ParsedAST): Set<string> {
  const vars = new Set<string>();
  walk(ast, {
    CallExpression(rawNode) {
      const call = rawNode as TSESTree.CallExpression;
      if (!isDbCall(call) || call.arguments.length === 0) return;
      const firstArg = call.arguments[0];
      if (firstArg && isIdentifier(firstArg)) {
        vars.add((firstArg as TSESTree.Identifier).name);
      }
    },
  });
  return vars;
}

const rule: Rule = {
  id: 'security/sql-injection',
  name: 'SQL Injection',
  category: 'security',
  severity: 'error',
  description: 'Detects SQL queries built via string concatenation or template literals with user input',
  why: 'SQL injection allows attackers to manipulate your database queries, potentially reading all data, bypassing authentication, or destroying the database.',
  fix: 'Always use parameterized queries or a query builder. Never concatenate user input directly into SQL.',
  fixCode: `// Instead of (VULNERABLE):
const query = "SELECT * FROM users WHERE username = '" + username + "'";
db.query(query, callback);

// Use parameterized query (SAFE):
const query = "SELECT * FROM users WHERE username = ?";
db.query(query, [username], (err, results) => {
  if (err) return next(err);
  // handle results
});

// With mysql2/promise:
const [rows] = await pool.execute('SELECT * FROM users WHERE username = ?', [username]);`,

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const parentMap = buildParentMap(ast);
    const dbCallVars = collectDbCallVars(ast);

    function tryFlag(node: TSESTree.Node, message: string, fixMsg: string): void {
      const line = getLine(node);
      if (PARAMETERIZED_PATTERN.test(extractSnippet(source, line))) return;
      const ctx = findContext(node, parentMap);
      if (!ctx) return;
      if (ctx.kind === 'safe-sink') return;
      if (ctx.kind === 'db-call' || (ctx.kind === 'var' && ctx.varName && dbCallVars.has(ctx.varName))) {
        findings.push({
          ruleId: 'security/sql-injection',
          severity: 'error',
          message,
          file: filePath,
          line,
          column: getColumn(node),
          snippet: extractSnippet(source, line),
          fix: fixMsg,
        });
      }
    }

    walk(ast, {
      TemplateLiteral(rawNode) {
        const node = rawNode as TSESTree.TemplateLiteral;
        const raw = node.quasis.map((q) => q.value.raw).join('');
        if (!looksLikeSQL(raw) || !templateHasUserInput(node)) return;
        tryFlag(node, 'SQL template literal with user input — injection risk',
          'Use parameterized queries: db.query("SELECT * FROM users WHERE id = ?", [id])');
      },
      BinaryExpression(rawNode) {
        const node = rawNode as TSESTree.BinaryExpression;
        if (node.operator !== '+') return;
        const leftStr = isStringLiteral(node.left) ? String((node.left as TSESTree.StringLiteral).value) : '';
        if (!looksLikeSQL(leftStr) || !concatHasUserInput(node)) return;
        tryFlag(node, 'SQL string concat with user input — injection risk',
          'Use parameterized queries or a query builder like Prisma, Knex, or TypeORM');
      },
    });

    return findings;
  },
};

export default rule;

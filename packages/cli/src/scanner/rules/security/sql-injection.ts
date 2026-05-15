import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { isStringLiteral, isTemplateLiteral, getLine, getColumn, isMemberExpression, isIdentifier } from '../../../utils/ast-helpers.js';

const SQL_VERB_PATTERN = /\b(SELECT|INSERT\s+INTO|UPDATE\s+\w|DELETE\s+FROM|DROP\s+TABLE|CREATE\s+TABLE|ALTER\s+TABLE|EXEC(?:UTE)?)\b/i;
const USER_INPUT_SOURCES = new Set(['params', 'body', 'query', 'headers', 'cookies']);
const SAFE_QUERY_METHODS = new Set(['query', 'execute', 'raw', 'knex', 'prepare']);
const PARAMETERIZED_PATTERN = /\?\s*[,)]/;

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
    if (isIdentifier(expr)) return true; // conservative: any identifier in SQL template
    return false;
  });
}

function concatHasUserInput(node: TSESTree.BinaryExpression): boolean {
  if (node.operator !== '+') return false;
  return isUserInputExpression(node.right) || isUserInputExpression(node.left) ||
    (isIdentifier(node.right) || isIdentifier(node.left));
}

function looksLikeSQL(text: string): boolean {
  return SQL_VERB_PATTERN.test(text);
}

function checkTemplate(node: TSESTree.TemplateLiteral, source: string, filePath: string): Finding | null {
  const raw = node.quasis.map((q) => q.value.raw).join('');
  if (!looksLikeSQL(raw)) return null;
  if (!templateHasUserInput(node)) return null;
  return {
    ruleId: 'security/sql-injection',
    severity: 'error',
    message: 'SQL template literal with user input — injection risk',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Use parameterized queries: db.query("SELECT * FROM users WHERE id = ?", [id])',
  };
}

function checkBinaryConcat(node: TSESTree.BinaryExpression, source: string, filePath: string): Finding | null {
  if (node.operator !== '+') return null;
  const leftStr = isStringLiteral(node.left) ? String((node.left as TSESTree.StringLiteral).value) : '';
  if (!looksLikeSQL(leftStr)) return null;
  if (!concatHasUserInput(node)) return null;
  return {
    ruleId: 'security/sql-injection',
    severity: 'error',
    message: 'SQL string concat with user input — injection risk',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Use parameterized queries or a query builder like Prisma, Knex, or TypeORM',
  };
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

    walk(ast, {
      TemplateLiteral(rawNode) {
        const finding = checkTemplate(rawNode as TSESTree.TemplateLiteral, source, filePath);
        if (finding) findings.push(finding);
      },
      BinaryExpression(rawNode) {
        const finding = checkBinaryConcat(rawNode as TSESTree.BinaryExpression, source, filePath);
        if (finding && !PARAMETERIZED_PATTERN.test(extractSnippet(source, getLine(rawNode)))) {
          findings.push(finding);
        }
      },
    });

    return findings;
  },
};

export default rule;

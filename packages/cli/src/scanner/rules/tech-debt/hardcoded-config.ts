import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isStringLiteral, isIdentifier, isMemberExpression } from '../../../utils/ast-helpers.js';
import { isConfigFile, isTestFile } from '../../../utils/file-utils.js';

const PORT_PATTERN = /^(?:PORT|port|Port)$/;
const URL_PATTERN = /^https?:\/\//;
const DB_NAMES = /^(?:mongodb|postgres|mysql|sqlite|redis|localhost)\b/i;

function isPortNumber(value: unknown): boolean {
  if (typeof value !== 'number') return false;
  return value > 0 && value < 65536 && value !== 80 && value !== 443;
}

const KNOWN_PUBLIC_HOSTS = /\b(github\.com|gitlab\.com|npmjs\.com|cdnjs\.cloudflare\.com|unpkg\.com|cdn\.jsdelivr\.net|docs\.|api\.github\.com)\b/;

function looksLikeBaseUrl(value: string): boolean {
  if (!URL_PATTERN.test(value)) return false;
  if (value.includes('localhost')) return false;
  if (value.includes('example.com')) return false;
  if (value.includes('your-')) return false;
  if (value.endsWith('.git')) return false;
  if (KNOWN_PUBLIC_HOSTS.test(value)) return false;
  return true;
}

function looksLikeDbName(value: string): boolean {
  return DB_NAMES.test(value);
}

function checkVariableDeclarator(node: TSESTree.VariableDeclarator, source: string, filePath: string): Finding | null {
  if (!node.init) return null;
  const nameNode = node.id;
  if (nameNode.type !== 'Identifier') return null;
  const name = (nameNode as TSESTree.Identifier).name;
  const init = node.init;

  if (init.type === 'Literal' && isPortNumber((init as TSESTree.Literal).value)) {
    if (PORT_PATTERN.test(name) || /(?:^|[^a-z])port(?:[^a-z]|$)/i.test(name)) {
      return {
        ruleId: 'tech-debt/hardcoded-config',
        severity: 'warn',
        message: `Hardcoded port number ${String((init as TSESTree.Literal).value)} — should come from environment`,
        file: filePath,
        line: getLine(node),
        column: getColumn(node),
        snippet: extractSnippet(source, getLine(node)),
        fix: `const ${name} = parseInt(process.env.PORT ?? "${String((init as TSESTree.Literal).value)}", 10)`,
      };
    }
  }

  if (isStringLiteral(init) && looksLikeBaseUrl(String((init as TSESTree.StringLiteral).value))) {
    return {
      ruleId: 'tech-debt/hardcoded-config',
      severity: 'warn',
      message: `Hardcoded URL "${String((init as TSESTree.StringLiteral).value)}" should come from environment config`,
      file: filePath,
      line: getLine(node),
      column: getColumn(node),
      snippet: extractSnippet(source, getLine(node)),
      fix: `const ${name} = process.env.${name.toUpperCase()} ?? "${String((init as TSESTree.StringLiteral).value)}"`,
    };
  }

  return null;
}

function isLoggingCall(node: TSESTree.CallExpression): boolean {
  if (isMemberExpression(node.callee)) {
    const me = node.callee as TSESTree.MemberExpression;
    if (!isIdentifier(me.object)) return false;
    const obj = (me.object as TSESTree.Identifier).name;
    return obj === 'console' || obj === 'logger' || obj === 'log';
  }
  if (isIdentifier(node.callee)) {
    const name = (node.callee as TSESTree.Identifier).name;
    return name === 'log' || name === 'warn' || name === 'error' || name === 'info' || name === 'debug';
  }
  return false;
}

function checkDbConnectionString(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (isLoggingCall(node)) return null;
  const firstArg = node.arguments[0];
  if (!firstArg || !isStringLiteral(firstArg as TSESTree.Expression)) return null;
  const val = String((firstArg as TSESTree.StringLiteral).value);
  if (!looksLikeDbName(val) || !val.includes('://')) return null;
  return {
    ruleId: 'tech-debt/hardcoded-config',
    severity: 'warn',
    message: `Hardcoded database connection string — should come from environment variable`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Use process.env.DATABASE_URL for all connection strings',
  };
}

const rule: Rule = {
  id: 'tech-debt/hardcoded-config',
  name: 'Hardcoded Configuration',
  category: 'tech-debt',
  severity: 'warn',
  description: 'Detects port numbers, base URLs, and connection strings hardcoded in source code',
  why: 'Hardcoded configuration values cannot be changed without code modifications, making deployment across environments (dev/staging/prod) fragile and error-prone.',
  fix: 'Use environment variables for all configuration. Use dotenv or a config module to load them with sensible defaults.',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    if (isConfigFile(filePath) || isTestFile(filePath)) return [];
    const findings: Finding[] = [];

    walk(ast, {
      VariableDeclarator(rawNode) {
        const finding = checkVariableDeclarator(rawNode as TSESTree.VariableDeclarator, source, filePath);
        if (finding) findings.push(finding);
      },
      CallExpression(rawNode) {
        const finding = checkDbConnectionString(rawNode as TSESTree.CallExpression, source, filePath);
        if (finding) findings.push(finding);
      },
    });

    return findings;
  },
};

export default rule;

import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { isStringLiteral, isLiteral, getLine, getColumn, isIdentifier } from '../../../utils/ast-helpers.js';

function isDocumentationString(value: string): boolean {
  const up = value.toUpperCase();
  if (up.includes('DO NOT USE')) return true;
  if (up.includes('INSTEAD,') || up.includes('INSTEAD ')) return true;
  if (up.includes('REPLACE')) return true;
  if (up.includes('CHANGE THIS')) return true;
  if (up.includes('KEEP IT SAFE')) return true;
  if (value.includes('YOUR_') || value.includes('your_') || value.includes('<YOUR')) return true;
  // All-caps instruction text (>60 chars, no lowercase letters)
  if (value.length > 60 && !/[a-z]/.test(value)) return true;
  return false;
}

const SECRET_VALUE_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /AKIA[0-9A-Z]{16}/, label: 'AWS Access Key ID' },
  { pattern: /sk-[a-zA-Z0-9]{20,}/, label: 'OpenAI API Key' },
  { pattern: /(?:mongodb|postgres|mysql):\/\/[^:]+:[^@]+@/, label: 'Database URL with credentials' },
  { pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/, label: 'Private key' },
  { pattern: /ghp_[a-zA-Z0-9]{36}/, label: 'GitHub Personal Access Token' },
  { pattern: /xoxb-[0-9]+-[a-zA-Z0-9]+/, label: 'Slack Bot Token' },
];

const SECRET_NAME_PATTERNS = /(?:api[_-]?key|apikey|jwt[_-]?secret|secret[_-]?key|[a-z_-]+secret|secret[a-z_-]+|password|passwd|pwd|auth[_-]?token|access[_-]?token|private[_-]?key)/i;
const SECRET_OBJ_KEYS = /^(?:secret|password|passwd|pwd|token|apikey|api[_-]?key|authtoken|auth[_-]?token|privatekey|private[_-]?key|accesskey|access[_-]?key|clientsecret|client[_-]?secret|jwtsecret|jwt[_-]?secret|encryptionkey|encryption[_-]?key)$/i;
const SAFE_PLACEHOLDER_PATTERN = /(?:example|placeholder|test|fake|dummy|sample|mock|todo|changeme|your[_-\s]?)/i;
const PLACEHOLDER_VALUES = /(?:example|placeholder|test|fake|dummy|your[_\-\s]?|<.*?>|xxx)/i;
const MIN_SECRET_VALUE_LENGTH = 8;

function isProcessEnv(node: TSESTree.Node): boolean {
  if (node.type !== 'MemberExpression') return false;
  const me = node as TSESTree.MemberExpression;
  if (me.object.type !== 'MemberExpression') return false;
  const inner = me.object as TSESTree.MemberExpression;
  return inner.object.type === 'Identifier' &&
    (inner.object as TSESTree.Identifier).name === 'process' &&
    inner.property.type === 'Identifier' &&
    (inner.property as TSESTree.Identifier).name === 'env';
}

function checkLiteralForSecrets(node: TSESTree.Literal, source: string, filePath: string): Finding | null {
  const value = String(node.value);
  for (const { pattern, label } of SECRET_VALUE_PATTERNS) {
    if (pattern.test(value)) {
      return {
        ruleId: 'security/hardcoded-secrets',
        severity: 'error',
        message: `hardcoded ${label}`,
        file: filePath,
        line: getLine(node),
        column: getColumn(node),
        snippet: extractSnippet(source, getLine(node)),
        fix: 'Store this value in an environment variable and reference it via process.env.YOUR_KEY_NAME',
      };
    }
  }
  return null;
}

const ERROR_MESSAGE_WORDS = /\b(invalid|incorrect|wrong|failed|error|denied|unauthorized|forbidden|not found|missing|required|expired|bad|no |please|must|cannot|can't|don't|doesn't|enter|provide)\b/i;

function looksLikeNaturalLanguage(value: string): boolean {
  if (value.split(' ').length > 3) return true;
  if (value.split(' ').length >= 2 && ERROR_MESSAGE_WORDS.test(value)) return true;
  return false;
}

function checkVariableNamePattern(name: string, value: string): boolean {
  return (
    SECRET_NAME_PATTERNS.test(name) &&
    value.length >= MIN_SECRET_VALUE_LENGTH &&
    !looksLikeNaturalLanguage(value) &&
    !SAFE_PLACEHOLDER_PATTERN.test(value) &&
    !SAFE_PLACEHOLDER_PATTERN.test(name) &&
    !isDocumentationString(value)
  );
}

function checkObjectProperty(node: TSESTree.Property, source: string, filePath: string): Finding | null {
  if (node.computed) return null;
  if (!isStringLiteral(node.value as TSESTree.Expression)) return null;
  const value = String((node.value as TSESTree.StringLiteral).value);
  if (value.length < MIN_SECRET_VALUE_LENGTH + 1) return null;
  if (PLACEHOLDER_VALUES.test(value)) return null;
  if (isDocumentationString(value)) return null;

  let keyName: string | null = null;
  if (isIdentifier(node.key)) {
    keyName = (node.key as TSESTree.Identifier).name;
  } else if (isStringLiteral(node.key)) {
    keyName = String((node.key as TSESTree.StringLiteral).value);
  }
  if (!keyName || !SECRET_OBJ_KEYS.test(keyName)) return null;

  return {
    ruleId: 'security/hardcoded-secrets',
    severity: 'error',
    message: `hardcoded value in "${keyName}" property`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: `Use process.env.${keyName.toUpperCase()} instead`,
  };
}

const rule: Rule = {
  id: 'security/hardcoded-secrets',
  name: 'Hardcoded Secrets',
  category: 'security',
  severity: 'error',
  description: 'Detects hardcoded API keys, passwords, tokens, and other secrets in source code',
  why: 'Hardcoded secrets are committed to version control, permanently exposing them. Anyone with repository access — including CI systems, future contributors, and leaked backups — will have your credentials.',
  fix: 'Use environment variables (process.env.SECRET_NAME) and a .env file excluded from git. Use a secrets manager for production.',
  fixCode: `// 1. Add to .env file (never commit this file):
JWT_SECRET=use_a_long_random_string_here_min_32_chars

// 2. Add .env to .gitignore:
echo ".env" >> .gitignore

// 3. Replace the hardcoded value in your code:
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT_SECRET environment variable is required');

// 4. Install dotenv if needed: npm install dotenv
// Then at the top of your entry file: require('dotenv').config();`,

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    walk(ast, {
      Literal(rawNode: TSESTree.Node) {
        const node = rawNode as TSESTree.Literal;
        if (!isStringLiteral(node)) return;
        const finding = checkLiteralForSecrets(node, source, filePath);
        if (finding) findings.push(finding);
      },

      Property(rawNode: TSESTree.Node) {
        const node = rawNode as TSESTree.Property;
        const f = checkObjectProperty(node, source, filePath);
        if (f) findings.push(f);
      },

      VariableDeclarator(rawNode: TSESTree.Node) {
        const node = rawNode as TSESTree.VariableDeclarator;
        if (!node.init || !isLiteral(node.init)) return;
        if (isProcessEnv(node.init)) return;
        const nameNode = node.id;
        if (nameNode.type !== 'Identifier') return;
        const name = (nameNode as TSESTree.Identifier).name;
        const rawValue = (node.init as TSESTree.Literal).value;
        if (typeof rawValue !== 'string') return;
        const value = rawValue;
        if (!checkVariableNamePattern(name, value)) return;
        findings.push({
          ruleId: 'security/hardcoded-secrets',
          severity: 'error',
          message: `"${name}" looks like a hardcoded secret`,
          file: filePath,
          line: getLine(node),
          column: getColumn(node),
          snippet: extractSnippet(source, getLine(node)),
          fix: `Use process.env.${name.toUpperCase()} instead`,
        });
      },
    });

    return findings;
  },
};

export default rule;

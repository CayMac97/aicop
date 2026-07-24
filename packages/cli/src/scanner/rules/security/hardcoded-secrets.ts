import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet, isTestFile } from '../../../utils/file-utils.js';
import { isStringLiteral, isLiteral, getLine, getColumn, isIdentifier, isMemberExpression } from '../../../utils/ast-helpers.js';

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
  { pattern: /sk-(?:proj-[a-zA-Z0-9_-]{10,}|[a-zA-Z0-9]{20,})/, label: 'OpenAI API Key' },
  { pattern: /(?:mongodb|postgres|mysql):\/\/[^:]+:[^@]+@/, label: 'Database URL with credentials' },
  { pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/, label: 'Private key' },
  { pattern: /ghp_[a-zA-Z0-9]{36}/, label: 'GitHub Personal Access Token' },
  { pattern: /xoxb-[0-9]+-[a-zA-Z0-9]+/, label: 'Slack Bot Token' },
];

const SECRET_NAME_PATTERNS = /(?:^(?:secret|token)$|api[_-]?key|apikey|jwt[_-]?secret|secret[_-]?key|[a-z_-]+secret|secret[a-z_-]+|password|passwd|pwd|auth[_-]?token|access[_-]?token|private[_-]?key)/i;
const SECRET_OBJ_KEYS = /^(?:secret|password|passwd|pwd|token|apikey|api[_-]?key|authtoken|auth[_-]?token|privatekey|private[_-]?key|accesskey|access[_-]?key|secretkey|secret[_-]?key|clientsecret|client[_-]?secret|jwtsecret|jwt[_-]?secret|encryptionkey|encryption[_-]?key)$/i;
const SAFE_PLACEHOLDER_PATTERN = /(?:example|placeholder|test|fake|dummy|sample|mock|todo|changeme|your[_-\s]?)/i;
const PLACEHOLDER_VALUES = /(?:example|placeholder|test|fake|dummy|your[_\-\s]?|<.*?>|xxx)/i;
// Public keys that are designed to be embedded in client-side code
const PUBLIC_KEY_PATTERN = /^(?:AIzaSy|pk_(?:test|live)_)/;
// Values that are references/names, not actual secrets
const ENV_VAR_NAME_RE = /^[A-Z][A-Z0-9_]{2,}$/;                // JWT_SECRET, API_KEY
const HTTP_HEADER_VALUE_RE = /^(?:authorization|x-[\w-]{1,40}|bearer|content-type|user-agent|set-cookie)$/i;
// Values that are themselves secret-concept names (field names, not actual secret values)
const SECRET_CONCEPT_NAME_RE = /^(?:password|passwd|pwd|secret|token|jwt|apikey|api[_\-]?key|auth[_\-]?token|access[_\-]?token|private[_\-]?key|client[_\-]?secret|refresh[_\-]?token|session[_\-]?secret|bearer)$/i;
// Column/field descriptor: 2-3 word parts only (1-2 separators), all lowercase, no digits
// e.g. 'user_password', 'api_key_field' — but NOT 'super_secret_jwt_key_do_not_share'
const FIELD_DESCRIPTOR_RE = /^[a-z][a-z]*(?:[_-][a-z][a-z]*){1,2}$/;
const MIN_SECRET_VALUE_LENGTH = 8;
// Primitive type names and common validation rule keywords (pipe/colon separated)
const PRIMITIVE_TYPE_RE = /^(?:string|number|boolean|integer|float|null|undefined|any|unknown|object|array|void|never|bigint|symbol|required|optional|nullable|uuid|email|url|date|regex|numeric|alpha)$/i;
const COLON_CONSTRAINT_RE = /^(?:min|max|minlength|maxlength|between|size|digits):[0-9,]+$/i;

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
  if (value.split(' ').length >= 2 && ERROR_MESSAGE_WORDS.test(value)) return true;
  return false;
}

function looksLikeKeyNameNotValue(value: string): boolean {
  // If an uppercase string is long, it's likely a real secret value, not an env var name
  if (value.length >= 24) return false;
  if (ENV_VAR_NAME_RE.test(value)) return true;         // JWT_SECRET, SESSION_SECRET
  if (HTTP_HEADER_VALUE_RE.test(value)) return true;    // Authorization, X-Api-Key
  if (SECRET_CONCEPT_NAME_RE.test(value)) return true;  // 'password', 'client_secret'
  // 'user_password', 'api_key_field' — pure lowercase snake/kebab with separator → column name
  if (FIELD_DESCRIPTOR_RE.test(value) && SECRET_NAME_PATTERNS.test(value)) return true;
  return false;
}

function looksLikeValidationOrTypeRule(value: string): boolean {
  // e.g. 'required|string', 'string|null', 'number|null', 'minlength:8'
  const parts = value.split('|');
  return parts.length >= 1 && parts.every(
    (p) => PRIMITIVE_TYPE_RE.test(p.trim()) || COLON_CONSTRAINT_RE.test(p.trim()),
  );
}

function checkVariableNamePattern(name: string, value: string): boolean {
  return (
    SECRET_NAME_PATTERNS.test(name) &&
    value.length >= MIN_SECRET_VALUE_LENGTH &&
    !looksLikeNaturalLanguage(value) &&
    !SAFE_PLACEHOLDER_PATTERN.test(value) &&
    !SAFE_PLACEHOLDER_PATTERN.test(name) &&
    !isDocumentationString(value) &&
    !looksLikeKeyNameNotValue(value)
  );
}

function checkPropertyLike(node: TSESTree.Property | TSESTree.PropertyDefinition, source: string, filePath: string): Finding | null {
  if (node.computed) return null;
  if (!node.value || !isStringLiteral(node.value as TSESTree.Expression)) return null;
  const value = String((node.value as TSESTree.StringLiteral).value);
  if (value.length < MIN_SECRET_VALUE_LENGTH + 1) return null;
  if (PLACEHOLDER_VALUES.test(value)) return null;
  if (isDocumentationString(value)) return null;
  if (PUBLIC_KEY_PATTERN.test(value)) return null;
  if (looksLikeKeyNameNotValue(value)) return null;
  if (looksLikeNaturalLanguage(value)) return null;
  if (looksLikeValidationOrTypeRule(value)) return null;
  if (value.startsWith('/')) return null;

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
        const f = checkPropertyLike(node, source, filePath);
        if (f) findings.push(f);
      },

      PropertyDefinition(rawNode: TSESTree.Node) {
        const node = rawNode as TSESTree.PropertyDefinition;
        const f = checkPropertyLike(node, source, filePath);
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
        if (PUBLIC_KEY_PATTERN.test(value)) return;
        findings.push({
          ruleId: 'security/hardcoded-secrets',
          severity: 'error',
          message: `hardcoded value in '${name}' variable`,
          file: filePath,
          line: getLine(node),
          column: getColumn(node),
          snippet: extractSnippet(source, getLine(node)),
          fix: `Use process.env.${name.toUpperCase()} instead of hardcoding this value`,
        });
      },

      CallExpression(rawNode: TSESTree.Node) {
        const node = rawNode as TSESTree.CallExpression;
        if (!isMemberExpression(node.callee)) return;
        const me = node.callee as TSESTree.MemberExpression;
        if (!isIdentifier(me.property) || me.property.name !== 'set') return;
        
        const keyArg = node.arguments[0];
        const valArg = node.arguments[1];
        if (!keyArg || !valArg) return;
        if (!isStringLiteral(keyArg as TSESTree.Expression) || !isStringLiteral(valArg as TSESTree.Expression)) return;
        
        const keyName = String((keyArg as TSESTree.StringLiteral).value);
        const value = String((valArg as TSESTree.StringLiteral).value);
        
        if (!SECRET_OBJ_KEYS.test(keyName)) return;
        if (value.length < MIN_SECRET_VALUE_LENGTH + 1) return;
        if (PLACEHOLDER_VALUES.test(value)) return;
        if (isDocumentationString(value)) return;
        if (PUBLIC_KEY_PATTERN.test(value)) return;
        if (looksLikeKeyNameNotValue(value)) return;
        if (looksLikeNaturalLanguage(value)) return;
        if (looksLikeValidationOrTypeRule(value)) return;
        if (value.startsWith('/')) return;
        
        findings.push({
          ruleId: 'security/hardcoded-secrets',
          severity: 'error',
          message: `hardcoded value for "${keyName}" in set()`,
          file: filePath,
          line: getLine(node),
          column: getColumn(node),
          snippet: extractSnippet(source, getLine(node)),
          fix: `Use process.env.${keyName.toUpperCase()} instead`,
        });
      },
    });

    if (isTestFile(filePath)) {
      return findings.map(f => ({
        ...f,
        severity: 'warn',
        message: 'hardcoded secret in test file — use environment variables even in tests',
      }));
    }

    return findings;
  },
};

export default rule;

import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { isStringLiteral, getLine, getColumn, isIdentifier, isMemberExpression, isLiteral } from '../../../utils/ast-helpers.js';

const BROKEN_HASH_ALGORITHMS = new Set(['md5', 'sha1', 'sha-1', 'md4', 'rc4', 'des', '3des', 'rc2']);
const SECURITY_CONTEXT_NAMES = /^(?:token|secret|otp|code|key|salt|nonce|reset|password|passwd|pwd|auth|session|csrf|hash)/i;
const WEAK_HASH_PACKAGES = new Set(['md5', 'sha1', 'md5-node', 'md5.js', 'sha.js', 'sha1-node']);

function checkCreateHash(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return null;
  if ((me.property as TSESTree.Identifier).name !== 'createHash') return null;
  const algArg = node.arguments[0];
  if (!algArg || !isStringLiteral(algArg as TSESTree.Expression)) return null;
  const alg = String((algArg as TSESTree.StringLiteral).value).toLowerCase();
  if (!BROKEN_HASH_ALGORITHMS.has(alg)) return null;
  return {
    ruleId: 'security/weak-crypto',
    severity: 'error',
    message: `"${alg}" is a broken hash algorithm`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Use SHA-256 or SHA-512 for hashing, or bcrypt/argon2/scrypt for passwords: crypto.createHash("sha256")',
  };
}

function checkCreateCipher(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return null;
  const method = (me.property as TSESTree.Identifier).name;
  if (method !== 'createCipher' && method !== 'createCipheriv') return null;
  const algArg = node.arguments[0];
  if (!algArg || !isStringLiteral(algArg as TSESTree.Expression)) return null;
  const alg = String((algArg as TSESTree.StringLiteral).value).toLowerCase();
  if (!alg.includes('rc4') && !alg.includes('des') && !alg.includes('rc2')) return null;
  return {
    ruleId: 'security/weak-crypto',
    severity: 'error',
    message: `"${alg}" is a weak cipher`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Use AES-256-GCM for encryption: crypto.createCipheriv("aes-256-gcm", key, iv)',
  };
}

function isMathRandom(node: TSESTree.CallExpression): boolean {
  if (!isMemberExpression(node.callee)) return false;
  const me = node.callee as TSESTree.MemberExpression;
  return isIdentifier(me.object) &&
    (me.object as TSESTree.Identifier).name === 'Math' &&
    isIdentifier(me.property) &&
    (me.property as TSESTree.Identifier).name === 'random';
}

function containsMathRandom(node: TSESTree.Node): boolean {
  if (node.type === 'CallExpression') {
    const ce = node as TSESTree.CallExpression;
    if (isMathRandom(ce)) return true;
    return containsMathRandom(ce.callee as TSESTree.Node);
  }
  if (node.type === 'MemberExpression') {
    return containsMathRandom((node as TSESTree.MemberExpression).object);
  }
  return false;
}

function mathRandomFinding(node: TSESTree.Node, varName: string, source: string, filePath: string): Finding {
  return {
    ruleId: 'security/weak-crypto',
    severity: 'error',
    message: `Math.random() is not cryptographically secure — use crypto.randomBytes()`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: `const ${varName} = require('crypto').randomBytes(32).toString('hex')`,
  };
}

function checkMd5Call(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isIdentifier(node.callee)) return null;
  if ((node.callee as TSESTree.Identifier).name !== 'md5') return null;
  return {
    ruleId: 'security/weak-crypto',
    severity: 'warn',
    message: 'md5() is cryptographically broken',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Use crypto.createHash("sha256") or bcrypt for passwords',
  };
}

function checkWeakRequire(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isIdentifier(node.callee)) return null;
  if ((node.callee as TSESTree.Identifier).name !== 'require') return null;
  const arg = node.arguments[0];
  if (!arg || !isStringLiteral(arg as TSESTree.Expression)) return null;
  const pkg = String((arg as TSESTree.StringLiteral).value);
  if (!WEAK_HASH_PACKAGES.has(pkg)) return null;
  return {
    ruleId: 'security/weak-crypto',
    severity: 'warn',
    message: `${pkg} package uses broken hash algorithm`,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Use crypto.createHash("sha256") from the built-in crypto module',
  };
}

function checkBcryptSaltRounds(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return null;
  const method = (me.property as TSESTree.Identifier).name;
  if (method !== 'hashSync' && method !== 'hash') return null;

  const saltArg = node.arguments[1];
  if (!saltArg) return null;

  if (isLiteral(saltArg) && typeof (saltArg as TSESTree.Literal).value === 'number') {
    const rounds = (saltArg as TSESTree.Literal).value as number;
    if (rounds >= 10) return null;
    return {
      ruleId: 'security/weak-crypto',
      severity: 'warn',
      message: `bcrypt salt rounds ${rounds} below 10 — too weak`,
      file: filePath,
      line: getLine(node),
      column: getColumn(node),
      snippet: extractSnippet(source, getLine(node)),
      fix: 'Use at least 10 salt rounds: bcrypt.hash(password, 12)',
    };
  }

  if (saltArg.type === 'CallExpression') {
    const call = saltArg as TSESTree.CallExpression;
    if (!isMemberExpression(call.callee)) return null;
    const callMe = call.callee as TSESTree.MemberExpression;
    if (!isIdentifier(callMe.property)) return null;
    const genMethod = (callMe.property as TSESTree.Identifier).name;
    if (genMethod !== 'genSaltSync' && genMethod !== 'genSalt') return null;
    const roundArg = call.arguments[0];
    if (!roundArg || !isLiteral(roundArg)) return null;
    const rounds = (roundArg as TSESTree.Literal).value;
    if (typeof rounds !== 'number' || rounds >= 10) return null;
    return {
      ruleId: 'security/weak-crypto',
      severity: 'warn',
      message: `bcrypt salt rounds ${rounds} below 10 — too weak`,
      file: filePath,
      line: getLine(node),
      column: getColumn(node),
      snippet: extractSnippet(source, getLine(node)),
      fix: 'Use at least 10 salt rounds: bcrypt.genSaltSync(12)',
    };
  }

  return null;
}

const rule: Rule = {
  id: 'security/weak-crypto',
  name: 'Weak Cryptography',
  category: 'security',
  severity: 'error',
  description: 'Detects use of broken hash algorithms (MD5, SHA1), weak ciphers, and Math.random() in security contexts',
  why: 'MD5 and SHA1 are cryptographically broken and can be reversed. Math.random() is predictable and must never be used for security tokens.',
  fix: 'Use SHA-256+ for hashing, AES-256-GCM for encryption, bcrypt/argon2 for passwords, and crypto.randomBytes() for tokens.',
  fixCode: `// Instead of Math.random() for tokens (INSECURE):
const token = Math.random().toString(36).substring(2);

// Use crypto.randomBytes() (SECURE):
const { randomBytes } = require('crypto');
const resetToken = randomBytes(32).toString('hex'); // 64-char hex string

// Instead of MD5/SHA1 for hashing (BROKEN):
const hash = crypto.createHash('md5').update(data).digest('hex');

// Use SHA-256 (SECURE):
const hash = crypto.createHash('sha256').update(data).digest('hex');

// For passwords: use bcrypt (install: npm install bcrypt)
const bcrypt = require('bcrypt');
const passwordHash = await bcrypt.hash(password, 12);
const isValid = await bcrypt.compare(inputPassword, passwordHash);`,

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        const hashF = checkCreateHash(node, source, filePath);
        if (hashF) { findings.push(hashF); return; }
        const cipherF = checkCreateCipher(node, source, filePath);
        if (cipherF) { findings.push(cipherF); return; }
        const md5F = checkMd5Call(node, source, filePath);
        if (md5F) { findings.push(md5F); return; }
        const reqF = checkWeakRequire(node, source, filePath);
        if (reqF) { findings.push(reqF); return; }
        const bcryptF = checkBcryptSaltRounds(node, source, filePath);
        if (bcryptF) findings.push(bcryptF);
      },
      VariableDeclarator(rawNode) {
        const node = rawNode as TSESTree.VariableDeclarator;
        if (!node.init || node.id.type !== 'Identifier') return;
        const varName = (node.id as TSESTree.Identifier).name;
        if (!SECURITY_CONTEXT_NAMES.test(varName)) return;
        if (!containsMathRandom(node.init as TSESTree.Node)) return;
        findings.push(mathRandomFinding(node, varName, source, filePath));
      },
      AssignmentExpression(rawNode) {
        const node = rawNode as TSESTree.AssignmentExpression;
        if (!isIdentifier(node.left)) return;
        const varName = (node.left as TSESTree.Identifier).name;
        if (!SECURITY_CONTEXT_NAMES.test(varName)) return;
        if (!containsMathRandom(node.right)) return;
        findings.push(mathRandomFinding(node, varName, source, filePath));
      },
    });

    return findings;
  },
};

export default rule;

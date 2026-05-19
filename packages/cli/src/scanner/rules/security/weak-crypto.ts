import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { isStringLiteral, getLine, getColumn, isIdentifier, isMemberExpression, isLiteral } from '../../../utils/ast-helpers.js';

const BROKEN_HASH_ALGORITHMS = new Set(['md5', 'sha1', 'sha-1', 'md4', 'rc4', 'des', '3des', 'rc2']);
const SECURITY_CONTEXT_NAMES = /^(?:token|secret|otp|code|key|salt|nonce|reset|password|passwd|pwd|auth|session|csrf|hash)/i;
const WEAK_HASH_PACKAGES = new Set(['md5', 'sha1', 'md5-node', 'md5.js', 'sha.js', 'sha1-node']);
const PASSWORD_CONTEXT = /\b(password|passwd|pwd)\b/i;
const BCRYPT_FIX_SNIPPET = 'Use bcrypt or argon2 for passwords — never SHA-256:\nconst hash = await bcrypt.hash(password, 12)';
const HASH_FIX_CODE = 'Use crypto.createHash("sha256") or crypto.randomBytes() for tokens';

function isPasswordContext(source: string, line: number): boolean {
  return PASSWORD_CONTEXT.test(extractSnippet(source, line, 2));
}

function checkCreateHash(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return null;
  if ((me.property as TSESTree.Identifier).name !== 'createHash') return null;
  const algArg = node.arguments[0];
  if (!algArg || !isStringLiteral(algArg as TSESTree.Expression)) return null;
  const alg = String((algArg as TSESTree.StringLiteral).value).toLowerCase();
  if (!BROKEN_HASH_ALGORITHMS.has(alg)) return null;
  const passwordContext = isPasswordContext(source, getLine(node));
  const isMd5OrSha1 = alg === 'md5' || alg === 'sha1' || alg === 'sha-1';
  const severity = (isMd5OrSha1 && !passwordContext) ? 'warn' : 'error';
  const message = isMd5OrSha1 && !passwordContext
    ? `"${alg}" is cryptographically broken — acceptable for checksums/ETags but not for security`
    : `"${alg}" is a broken hash algorithm`;
  return {
    ruleId: 'security/weak-crypto',
    severity,
    message,
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: passwordContext
      ? 'Use bcrypt or argon2 for passwords'
      : `For checksums/ETags, ${alg} is acceptable. For security contexts, upgrade to SHA-256: crypto.createHash("sha256")`,
    fixCode: passwordContext ? BCRYPT_FIX_SNIPPET : HASH_FIX_CODE,
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
  const passwordContext = isPasswordContext(source, getLine(node));
  return {
    ruleId: 'security/weak-crypto',
    severity: 'warn',
    message: 'md5() is cryptographically broken',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: passwordContext ? 'Use bcrypt or argon2 for passwords' : 'Use stronger crypto primitives',
    fixCode: passwordContext ? BCRYPT_FIX_SNIPPET : HASH_FIX_CODE,
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
    fix: 'Use stronger crypto primitives',
    fixCode: HASH_FIX_CODE,
  };
}

function checkLiteralSaltRounds(saltArg: TSESTree.Node, node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isLiteral(saltArg) || typeof (saltArg as TSESTree.Literal).value !== 'number') return null;
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

function checkGenSaltRounds(saltArg: TSESTree.Node, node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (saltArg.type !== 'CallExpression') return null;
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

function checkBcryptSaltRounds(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return null;
  const method = (me.property as TSESTree.Identifier).name;
  if (method !== 'hashSync' && method !== 'hash') return null;

  const saltArg = node.arguments[1];
  if (!saltArg) return null;

  return checkLiteralSaltRounds(saltArg, node, source, filePath)
    ?? checkGenSaltRounds(saltArg, node, source, filePath);
}

const rule: Rule = {
  id: 'security/weak-crypto',
  name: 'Weak Cryptography',
  category: 'security',
  severity: 'error',
  description: 'Detects use of broken hash algorithms (MD5, SHA1), weak ciphers, and Math.random() in security contexts',
  why: 'MD5 and SHA1 are cryptographically broken and can be reversed. Math.random() is predictable and must never be used for security tokens.',
  fix: 'Use bcrypt/argon2 for passwords, AES-256-GCM for encryption, and crypto.randomBytes() for tokens.',
  fixCode: 'Use bcrypt for passwords, crypto.randomBytes() for tokens.',

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

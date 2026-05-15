import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression, isStringLiteral } from '../../../utils/ast-helpers.js';

function isJwtSignCall(node: TSESTree.CallExpression): boolean {
  if (!isMemberExpression(node.callee)) return false;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return false;
  return (me.property as TSESTree.Identifier).name === 'sign';
}

function hasExpiryInOptions(optionsNode: TSESTree.SpreadElement | TSESTree.Expression): boolean {
  if (optionsNode.type !== 'ObjectExpression') return false;
  const obj = optionsNode as TSESTree.ObjectExpression;
  return obj.properties.some((prop) => {
    if (prop.type !== 'Property') return false;
    const p = prop as TSESTree.Property;
    if (!isIdentifier(p.key)) return false;
    const name = (p.key as TSESTree.Identifier).name;
    return name === 'expiresIn' || name === 'exp';
  });
}

function checkJwtSign(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isJwtSignCall(node)) return null;
  const args = node.arguments;
  if (args.length < 2) return null;
  if (args.length < 3) {
    return {
      ruleId: 'security/jwt-no-expiry',
      severity: 'error',
      message: 'jwt.sign() called without an options object — token never expires',
      file: filePath,
      line: getLine(node),
      column: getColumn(node),
      snippet: extractSnippet(source, getLine(node)),
      fix: 'Add expiry: jwt.sign(payload, secret, { expiresIn: "15m" })',
    };
  }
  const optionsArg = args[2];
  if (!optionsArg) return null;
  if (hasExpiryInOptions(optionsArg)) return null;
  return {
    ruleId: 'security/jwt-no-expiry',
    severity: 'error',
    message: 'jwt.sign() missing expiresIn — token never expires',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Add expiresIn to options: jwt.sign(payload, secret, { expiresIn: "15m" })',
  };
}

function isJwtVerifyCall(node: TSESTree.CallExpression): boolean {
  if (!isMemberExpression(node.callee)) return false;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return false;
  return (me.property as TSESTree.Identifier).name === 'verify';
}

function checkJwtVerify(node: TSESTree.CallExpression, source: string, filePath: string, parent: TSESTree.Node | null): Finding | null {
  if (!isJwtVerifyCall(node)) return null;
  if (!parent) return null;
  const parentType = parent.type;
  const isAssigned = parentType === 'VariableDeclarator' ||
    parentType === 'AssignmentExpression' ||
    parentType === 'ReturnStatement' ||
    parentType === 'AwaitExpression';
  if (isAssigned) return null;
  return {
    ruleId: 'security/jwt-no-expiry',
    severity: 'error',
    message: 'jwt.verify() result not checked',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Always assign and check the result: const decoded = jwt.verify(token, secret)',
  };
}

const rule: Rule = {
  id: 'security/jwt-no-expiry',
  name: 'JWT Without Expiry',
  category: 'security',
  severity: 'error',
  description: 'Detects JWT tokens created without expiry, and jwt.verify() calls with unchecked results',
  why: 'JWTs without expiry are valid forever — if stolen, they grant permanent access. jwt.verify() results must be checked to ensure authentication actually succeeds.',
  fix: 'Always set expiresIn in jwt.sign() options and assign the result of jwt.verify() to a variable inside a try/catch.',
  fixCode: `// Instead of (no expiry — DANGEROUS):
jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET);

// Add expiresIn (SAFE):
const accessToken = jwt.sign(
  { userId: user.id, email: user.email },
  JWT_SECRET,
  { expiresIn: '15m' }  // 15 minutes for access tokens
);

// For refresh tokens:
const refreshToken = jwt.sign(
  { userId: user.id },
  REFRESH_SECRET,
  { expiresIn: '7d' }
);

// Always verify inside try/catch:
try {
  const decoded = jwt.verify(token, JWT_SECRET);
  req.user = decoded;
} catch (err) {
  return res.status(401).json({ error: 'Invalid or expired token' });
}`,

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    walk(ast, {
      CallExpression(rawNode, parent) {
        const node = rawNode as TSESTree.CallExpression;
        const signF = checkJwtSign(node, source, filePath);
        if (signF) { findings.push(signF); return; }
        const verifyF = checkJwtVerify(node, source, filePath, parent);
        if (verifyF) findings.push(verifyF);
      },
    });

    return findings;
  },
};

export default rule;

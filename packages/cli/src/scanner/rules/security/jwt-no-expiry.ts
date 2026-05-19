import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression } from '../../../utils/ast-helpers.js';

function isJwtSignCall(node: TSESTree.CallExpression): boolean {
  if (!isMemberExpression(node.callee)) return false;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return false;
  const methodName = (me.property as TSESTree.Identifier).name;
  if (methodName !== 'sign') return false;
  if (!isIdentifier(me.object)) return false;
  const objName = (me.object as TSESTree.Identifier).name.toLowerCase();
  return objName === 'jwt' || objName === 'jsonwebtoken';
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
      message: 'jwt.sign() missing expiresIn',
      file: filePath,
      line: getLine(node),
      column: getColumn(node),
      snippet: extractSnippet(source, getLine(node)),
      fix: 'Add expiresIn: jwt.sign(payload, secret, { expiresIn: "15m" })',
    };
  }
  const optionsArg = args[2];
  if (!optionsArg || hasExpiryInOptions(optionsArg)) return null;
  return {
    ruleId: 'security/jwt-no-expiry',
    severity: 'error',
    message: 'jwt.sign() missing expiresIn',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Add expiresIn: jwt.sign(payload, secret, { expiresIn: "15m" })',
  };
}

const rule: Rule = {
  id: 'security/jwt-no-expiry',
  name: 'JWT Without Expiry',
  category: 'security',
  severity: 'error',
  description: 'Detects JWT tokens created without expiry',
  why: 'JWTs without expiry remain valid if stolen.',
  fix: 'Set expiresIn in jwt.sign() options.',
  fixCode: `const accessToken = jwt.sign(
  { userId: user.id, email: user.email },
  JWT_SECRET,
  { expiresIn: '15m' }
)`,

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        const finding = checkJwtSign(node, source, filePath);
        if (finding) findings.push(finding);
      },
    });

    return findings;
  },
};

export default rule;

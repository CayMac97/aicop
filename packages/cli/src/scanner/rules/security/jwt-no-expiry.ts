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
    if (prop.type === 'SpreadElement') return true; // spread may include expiresIn — can't tell statically
    if (prop.type !== 'Property') return false;
    const p = prop as TSESTree.Property;
    if (isIdentifier(p.key)) {
      const name = (p.key as TSESTree.Identifier).name;
      return name === 'expiresIn' || name === 'exp';
    }
    if (p.key.type === 'Literal') {
      const name = String((p.key as TSESTree.Literal).value);
      return name === 'expiresIn' || name === 'exp';
    }
    return false;
  });
}

function payloadHasExpClaim(payloadNode: TSESTree.SpreadElement | TSESTree.Expression): boolean {
  if (payloadNode.type !== 'ObjectExpression') return false;
  const obj = payloadNode as TSESTree.ObjectExpression;
  return obj.properties.some((prop) => {
    if (prop.type !== 'Property') return false;
    const p = prop as TSESTree.Property;
    if (isIdentifier(p.key)) {
      return (p.key as TSESTree.Identifier).name === 'exp';
    }
    if (p.key.type === 'Literal') {
      return String((p.key as TSESTree.Literal).value) === 'exp';
    }
    return false;
  });
}

function hasNoneAlgorithm(optionsNode: TSESTree.SpreadElement | TSESTree.Expression): boolean {
  if (optionsNode.type !== 'ObjectExpression') return false;
  const obj = optionsNode as TSESTree.ObjectExpression;
  return obj.properties.some((prop) => {
    if (prop.type !== 'Property') return false;
    const p = prop as TSESTree.Property;
    if (!isIdentifier(p.key)) return false;
    if ((p.key as TSESTree.Identifier).name !== 'algorithm') return false;
    return p.value.type === 'Literal' && (p.value as TSESTree.Literal).value === 'none';
  });
}

// aicop-ignore tech-debt/cyclomatic-complexity
function checkJwtSign(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isJwtSignCall(node)) return null;
  const args = node.arguments;
  if (args.length >= 3 && hasNoneAlgorithm(args[2])) {
    return {
      ruleId: 'security/jwt-no-expiry',
      severity: 'error',
      message: "jwt.sign() using algorithm 'none' — signature verification is disabled",
      file: filePath,
      line: getLine(node),
      column: getColumn(node),
      snippet: extractSnippet(source, getLine(node)),
      fix: "Remove algorithm: 'none'. Use a secure algorithm like 'HS256' or 'RS256'.",
    };
  }
  if (args.length < 2) return null;
  if (args.length < 3) {
    if (args[0].type === 'Identifier') return null; // can't inspect variable payload
    if (payloadHasExpClaim(args[0])) return null;
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
  if (!optionsArg) return null;
  // If the options arg is a variable/identifier, we can't inspect it statically
  if (optionsArg.type === 'Identifier' || optionsArg.type === 'SpreadElement') return null;
  if (hasExpiryInOptions(optionsArg)) return null;
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

function checkCreateSigner(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isIdentifier(node.callee) || node.callee.name !== 'createSigner') return null;
  const args = node.arguments;
  if (args.length === 0) return null;
  const optionsArg = args[0];
  if (optionsArg.type === 'Identifier' || optionsArg.type === 'SpreadElement') return null;
  if (hasExpiryInOptions(optionsArg)) return null;
  return {
    ruleId: 'security/jwt-no-expiry',
    severity: 'error',
    message: 'fast-jwt createSigner() missing expiresIn',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Add expiresIn: createSigner({ key: "secret", expiresIn: 900000 })',
  };
}

function checkJoseSignJWT(node: TSESTree.CallExpression, source: string, filePath: string): Finding | null {
  if (!isMemberExpression(node.callee)) return null;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property) || me.property.name !== 'sign') return null;
  
  let current: TSESTree.Expression = me.object;
  let isSignJWT = false;
  let hasSetExp = false;
  
  while (current) {
    if (current.type === 'NewExpression' && isIdentifier(current.callee) && current.callee.name === 'SignJWT') {
      isSignJWT = true;
      break;
    }
    if (current.type === 'CallExpression' && isMemberExpression(current.callee)) {
      if (isIdentifier(current.callee.property)) {
        if (current.callee.property.name === 'setExpirationTime') {
          hasSetExp = true;
        }
      }
      current = current.callee.object;
    } else {
      break;
    }
  }
  
  if (!isSignJWT || hasSetExp) return null;
  
  return {
    ruleId: 'security/jwt-no-expiry',
    severity: 'error',
    message: 'jose SignJWT created without setExpirationTime()',
    file: filePath,
    line: getLine(node),
    column: getColumn(node),
    snippet: extractSnippet(source, getLine(node)),
    fix: 'Add .setExpirationTime("2h") before .sign()',
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
        
        const fastJwtFinding = checkCreateSigner(node, source, filePath);
        if (fastJwtFinding) findings.push(fastJwtFinding);
        
        const joseFinding = checkJoseSignJWT(node, source, filePath);
        if (joseFinding) findings.push(joseFinding);
      },
    });

    return findings;
  },
};

export default rule;

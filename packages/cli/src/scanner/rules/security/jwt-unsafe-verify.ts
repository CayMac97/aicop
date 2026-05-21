import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression } from '../../../utils/ast-helpers.js';

function chainContainsJwt(node: TSESTree.Expression | TSESTree.PrivateIdentifier): boolean {
  if (isIdentifier(node)) {
    const name = (node as TSESTree.Identifier).name.toLowerCase();
    return name.includes('jwt') || name === 'jsonwebtoken';
  }
  if (isMemberExpression(node)) {
    return chainContainsJwt((node as TSESTree.MemberExpression).object as TSESTree.Expression);
  }
  return false;
}

function isJwtVerifyCall(node: TSESTree.CallExpression): boolean {
  if (!isMemberExpression(node.callee)) return false;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return false;
  if ((me.property as TSESTree.Identifier).name !== 'verify') return false;
  if (node.arguments.length < 2) return false;
  return chainContainsJwt(me.object as TSESTree.Expression);
}

function hasCallback(node: TSESTree.CallExpression): boolean {
  const callback = node.arguments[2];
  return callback?.type === 'ArrowFunctionExpression' || callback?.type === 'FunctionExpression';
}

function isChecked(parent: TSESTree.Node | null, source: string, line: number): boolean {
  if (!parent) return false;
  if (parent.type === 'VariableDeclarator' ||
    parent.type === 'AssignmentExpression' ||
    parent.type === 'ReturnStatement' ||
    parent.type === 'AwaitExpression' ||
    parent.type === 'CallExpression' ||
    parent.type === 'TSAsExpression' ||
    parent.type === 'TSNonNullExpression') return true;
  if (parent.type === 'ExpressionStatement') {
    const ctx = extractSnippet(source, line, 5);
    return ctx.includes('try {') || ctx.includes('try{');
  }
  return false;
}

const rule: Rule = {
  id: 'security/jwt-unsafe-verify',
  name: 'JWT Unsafe Verify',
  category: 'security',
  severity: 'error',
  description: 'Detects jwt.verify() calls whose return value is ignored',
  why: 'Ignoring jwt.verify() return values can leave authentication checks incomplete.',
  fix: 'Assign jwt.verify() to a decoded token or use callback style.',
  fixCode: 'const decoded = jwt.verify(token, secret)',

  check(ast: ParsedAST, source: string, filePath: string): Finding[] {
    const findings: Finding[] = [];

    walk(ast, {
      CallExpression(rawNode, parent) {
        const node = rawNode as TSESTree.CallExpression;
        if (!isJwtVerifyCall(node)) return;
        if (hasCallback(node)) return;
        if (isChecked(parent, source, getLine(node))) return;
        findings.push({
          ruleId: 'security/jwt-unsafe-verify',
          severity: 'error',
          message: 'jwt.verify() return value not checked — verification may silently fail',
          file: filePath,
          line: getLine(node),
          column: getColumn(node),
          snippet: extractSnippet(source, getLine(node)),
          fix: 'Assign decoded token: const decoded = jwt.verify(token, secret)',
        });
      },
    });

    return findings;
  },
};

export default rule;

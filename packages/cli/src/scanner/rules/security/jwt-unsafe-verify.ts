import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression } from '../../../utils/ast-helpers.js';

function isJwtVerifyCall(node: TSESTree.CallExpression): boolean {
  if (!isMemberExpression(node.callee)) return false;
  const me = node.callee as TSESTree.MemberExpression;
  if (!isIdentifier(me.property)) return false;
  if ((me.property as TSESTree.Identifier).name !== 'verify') return false;
  if (node.arguments.length < 2) return false;
  if (isIdentifier(me.object)) {
    const objName = (me.object as TSESTree.Identifier).name.toLowerCase();
    return objName.includes('jwt') || objName === 'jsonwebtoken';
  }
  return true;
}

function hasCallback(node: TSESTree.CallExpression): boolean {
  const callback = node.arguments[2];
  return callback?.type === 'ArrowFunctionExpression' || callback?.type === 'FunctionExpression';
}

function isChecked(parent: TSESTree.Node | null): boolean {
  if (!parent) return false;
  return parent.type === 'VariableDeclarator' ||
    parent.type === 'AssignmentExpression' ||
    parent.type === 'ReturnStatement';
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
        if (isChecked(parent)) return;
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

import { TSESTree } from '@typescript-eslint/typescript-estree';
import { Rule, Finding, ParsedAST } from '../types.js';
import { walk } from '../../ast-walker.js';
import { extractSnippet } from '../../../utils/file-utils.js';
import { getLine, getColumn, isIdentifier, isMemberExpression } from '../../../utils/ast-helpers.js';
import { buildParentMap } from '../../../utils/taint-tracker.js';
import { isStringLiteral } from '../../../utils/ast-helpers.js';
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

function isJwtVerifyCall(node: TSESTree.CallExpression, verifyVars: Set<string>): boolean {
  if (isIdentifier(node.callee)) {
    return verifyVars.has((node.callee as TSESTree.Identifier).name) && node.arguments.length >= 2;
  }
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

function isChecked(node: TSESTree.Node, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  let current: TSESTree.Node | undefined = node;
  while (current) {
    if (
      current.type === 'VariableDeclarator' ||
      current.type === 'AssignmentExpression' ||
      current.type === 'ReturnStatement' ||
      current.type === 'TSAsExpression' ||
      current.type === 'TSNonNullExpression'
    ) {
      return true;
    }
    // CallExpression is checked if it's the parent (e.g. passing to another func), but we only check immediate parent for that
    if (current.type === 'FunctionDeclaration' || current.type === 'FunctionExpression' || current.type === 'ArrowFunctionExpression') {
      break; // stop at function boundary
    }
    const parent: TSESTree.Node | undefined = parentMap.get(current);
    if (parent?.type === 'CallExpression' && current === node) return true;
    if (parent?.type === 'AwaitExpression' && current === node) {
      // If it is awaited, is the await checked?
      return isChecked(parent, parentMap);
    }
    current = parent;
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
    const parentMap = buildParentMap(ast);
    const verifyVars = new Set<string>();

    walk(ast, {
      ImportDeclaration(rawNode) {
        const node = rawNode as TSESTree.ImportDeclaration;
        if (node.source.type === 'Literal' && String(node.source.value).includes('jsonwebtoken')) {
          for (const spec of node.specifiers) {
            if (spec.type === 'ImportSpecifier' && spec.imported.name === 'verify') {
              verifyVars.add(spec.local.name);
            }
          }
        }
      },
      VariableDeclarator(rawNode) {
        const node = rawNode as TSESTree.VariableDeclarator;
        if (node.init && node.init.type === 'CallExpression') {
          const ce = node.init as TSESTree.CallExpression;
          if (isIdentifier(ce.callee) && ce.callee.name === 'require' && ce.arguments[0] && isStringLiteral(ce.arguments[0] as TSESTree.Expression)) {
            if (String((ce.arguments[0] as TSESTree.StringLiteral).value).includes('jsonwebtoken')) {
              if (node.id.type === 'ObjectPattern') {
                for (const prop of node.id.properties) {
                  if (prop.type === 'Property' && isIdentifier(prop.key) && prop.key.name === 'verify' && isIdentifier(prop.value)) {
                    verifyVars.add(prop.value.name);
                  }
                }
              }
            }
          }
        }
      },
      CallExpression(rawNode, parent) {
        const node = rawNode as TSESTree.CallExpression;
        if (!isJwtVerifyCall(node, verifyVars)) return;
        if (hasCallback(node)) return;
        if (isChecked(node, parentMap)) return;
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

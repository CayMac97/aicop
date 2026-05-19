import { TSESTree } from '@typescript-eslint/typescript-estree';
import { walk } from '../scanner/ast-walker.js';
import { ParsedAST } from '../scanner/rules/types.js';
import { isIdentifier, isMemberExpression } from './ast-helpers.js';

const REQ_USER_INPUT_PROPS = new Set(['body', 'query', 'params', 'headers', 'cookies']);

function isDirectUserInputExpr(node: TSESTree.Node): boolean {
  if (!isMemberExpression(node)) return false;
  const me = node as TSESTree.MemberExpression;

  // req.body / req.query etc.
  if (isIdentifier(me.object) && (me.object as TSESTree.Identifier).name === 'req') {
    if (isIdentifier(me.property) && REQ_USER_INPUT_PROPS.has((me.property as TSESTree.Identifier).name)) {
      return true;
    }
  }

  // req.body.field / req.query.field etc.
  if (isMemberExpression(me.object)) {
    const inner = me.object as TSESTree.MemberExpression;
    if (isIdentifier(inner.object) && (inner.object as TSESTree.Identifier).name === 'req') {
      if (isIdentifier(inner.property) && REQ_USER_INPUT_PROPS.has((inner.property as TSESTree.Identifier).name)) {
        return true;
      }
    }
  }

  return false;
}

export function buildTaintMap(ast: ParsedAST): Set<string> {
  const tainted = new Set<string>();

  walk(ast, {
    VariableDeclarator(rawNode) {
      const node = rawNode as TSESTree.VariableDeclarator;
      if (!node.init) return;

      if (node.id.type === 'Identifier') {
        const name = (node.id as TSESTree.Identifier).name;
        if (isDirectUserInputExpr(node.init)) {
          tainted.add(name);
        } else if (isIdentifier(node.init) && tainted.has((node.init as TSESTree.Identifier).name)) {
          tainted.add(name);
        }
        return;
      }

      // const { field1, field2 } = req.body / req.params / etc.
      if (node.id.type === 'ObjectPattern' && isDirectUserInputExpr(node.init)) {
        const pattern = node.id as TSESTree.ObjectPattern;
        for (const prop of pattern.properties) {
          if (prop.type === 'Property' && isIdentifier(prop.value)) {
            tainted.add((prop.value as TSESTree.Identifier).name);
          } else if (prop.type === 'RestElement' && isIdentifier(prop.argument)) {
            tainted.add((prop.argument as TSESTree.Identifier).name);
          }
        }
      }
    },

    AssignmentExpression(rawNode) {
      const node = rawNode as TSESTree.AssignmentExpression;
      if (node.left.type !== 'Identifier') return;
      const name = (node.left as TSESTree.Identifier).name;

      if (isDirectUserInputExpr(node.right)) {
        tainted.add(name);
        return;
      }
      if (isIdentifier(node.right) && tainted.has((node.right as TSESTree.Identifier).name)) {
        tainted.add(name);
      }
    },
  });

  return tainted;
}

export function isTaintedNode(node: TSESTree.Node, tainted: Set<string>): boolean {
  return isIdentifier(node) && tainted.has((node as TSESTree.Identifier).name);
}

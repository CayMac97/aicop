import { TSESTree } from '@typescript-eslint/typescript-estree';
import { walk } from '../scanner/ast-walker.js';
import { ParsedAST } from '../scanner/rules/types.js';
import { isIdentifier, isMemberExpression } from './ast-helpers.js';

const REQ_USER_INPUT_PROPS = new Set(['body', 'query', 'params', 'headers', 'cookies']);

function isDirectUserInputExpr(node: TSESTree.Node): boolean {
  if (node.type === 'TSAsExpression' || node.type === 'TSNonNullExpression') {
    return isDirectUserInputExpr((node as TSESTree.TSAsExpression | TSESTree.TSNonNullExpression).expression);
  }
  if (!isMemberExpression(node)) return false;
  const me = node as TSESTree.MemberExpression;

  if (isIdentifier(me.object) && (me.object as TSESTree.Identifier).name === 'req') {
    if (isIdentifier(me.property) && REQ_USER_INPUT_PROPS.has((me.property as TSESTree.Identifier).name)) {
      return true;
    }
  }

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

export function isTaintedExpr(node: TSESTree.Node, tainted: Set<string>): boolean {
  if (isDirectUserInputExpr(node)) return true;
  if (isTaintedNode(node, tainted)) return true;
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return isTaintedExpr(node.left, tainted) || isTaintedExpr(node.right, tainted);
  }
  if (node.type === 'TemplateLiteral') {
    return node.expressions.some(expr => isTaintedExpr(expr, tainted));
  }
  return false;
}

export function buildTaintMap(ast: ParsedAST): Set<string> {
  const tainted = new Set<string>();

  walk(ast, {
    // aicop-ignore tech-debt/cyclomatic-complexity
    VariableDeclarator(rawNode, parentNode) {
      const node = rawNode as TSESTree.VariableDeclarator;
      if (!node.init) return;

      const isConst =
        parentNode?.type === 'VariableDeclaration' &&
        (parentNode as TSESTree.VariableDeclaration).kind === 'const';

      if (node.id.type === 'Identifier') {
        const name = (node.id as TSESTree.Identifier).name;
        if (isTaintedExpr(node.init, tainted)) {
          tainted.add(name);
        } else if (isConst && tainted.has(name)) {
          tainted.delete(name);
        }
        return;
      }

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

      if (isTaintedExpr(node.right, tainted)) {
        tainted.add(name);
      }
    },
  });

  return tainted;
}

export function isTaintedNode(node: TSESTree.Node, tainted: Set<string>): boolean {
  if (node.type === 'TSAsExpression' || node.type === 'TSNonNullExpression') {
    return isTaintedNode((node as TSESTree.TSAsExpression | TSESTree.TSNonNullExpression).expression, tainted);
  }
  return isIdentifier(node) && tainted.has((node as TSESTree.Identifier).name);
}

export function buildExtendedTaintMap(ast: ParsedAST): Set<string> {
  const tainted = buildTaintMap(ast);

  let functionCount = 0;
  walk(ast, {
    FunctionDeclaration() { functionCount++; },
    ArrowFunctionExpression() { functionCount++; },
    FunctionExpression() { functionCount++; }
  });
  if (functionCount > 500) return tainted;

  const funcCalls = new Map<string, Set<number>>();
  walk(ast, {
    CallExpression(rawNode) {
      const node = rawNode as TSESTree.CallExpression;
      if (node.callee.type === 'Identifier') {
        const funcName = (node.callee as TSESTree.Identifier).name;
        node.arguments.forEach((arg, index) => {
          if (isTaintedNode(arg, tainted) || isTaintedExpr(arg, tainted)) {
            if (!funcCalls.has(funcName)) funcCalls.set(funcName, new Set());
            funcCalls.get(funcName)!.add(index);
          }
        });
      }
    }
  });

  const taintsReturn = new Set<string>();
  walk(ast, {
    FunctionDeclaration(rawNode) {
      const node = rawNode as TSESTree.FunctionDeclaration;
      if (!node.id || !funcCalls.has(node.id.name)) return;
      
      const taintedParams = new Set<string>();
      const taintedArgIndices = funcCalls.get(node.id.name)!;
      
      node.params.forEach((param, index) => {
        if (taintedArgIndices.has(index) && param.type === 'Identifier') {
          taintedParams.add((param as TSESTree.Identifier).name);
        }
      });

      if (taintedParams.size === 0) return;

      let returnsTainted = false;
      walk(node.body, {
        ReturnStatement(retNode) {
          const ret = retNode as TSESTree.ReturnStatement;
          if (ret.argument && isTaintedExpr(ret.argument, taintedParams)) {
            returnsTainted = true;
          }
        }
      });

      if (returnsTainted) {
        taintsReturn.add(node.id.name);
      }
    }
  });

  if (taintsReturn.size > 0) {
    walk(ast, {
      VariableDeclarator(rawNode) {
        const node = rawNode as TSESTree.VariableDeclarator;
        if (!node.init || node.id.type !== 'Identifier') return;
        
        if (node.init.type === 'CallExpression' && node.init.callee.type === 'Identifier') {
          const funcName = (node.init.callee as TSESTree.Identifier).name;
          if (taintsReturn.has(funcName)) {
            tainted.add((node.id as TSESTree.Identifier).name);
          }
        }
      },
      AssignmentExpression(rawNode) {
        const node = rawNode as TSESTree.AssignmentExpression;
        if (node.left.type !== 'Identifier') return;
        
        if (node.right.type === 'CallExpression' && node.right.callee.type === 'Identifier') {
          const funcName = (node.right.callee as TSESTree.Identifier).name;
          if (taintsReturn.has(funcName)) {
            tainted.add((node.left as TSESTree.Identifier).name);
          }
        }
      }
    });
  }

  return tainted;
}

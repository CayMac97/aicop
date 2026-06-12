import { TSESTree } from '@typescript-eslint/typescript-estree';
import { walk } from '../scanner/ast-walker.js';
import { ParsedAST } from '../scanner/rules/types.js';
import { isIdentifier, isMemberExpression } from './ast-helpers.js';
import { crossFileCache } from '../scanner/cross-file/cross-file-resolver.js';
import { resolveLocalModule } from '../scanner/cross-file/module-resolver.js';

export interface TaintResult {
  globalTaints: Set<string>;
  localTaints: Map<TSESTree.Node, Set<string>>;
}

function extractParamNames(param: TSESTree.Node): string[] {
  const names: string[] = [];
  if (param.type === 'Identifier') {
    names.push((param as TSESTree.Identifier).name);
  } else if (param.type === 'ObjectPattern') {
    for (const prop of (param as TSESTree.ObjectPattern).properties) {
      if (prop.type === 'Property') {
        names.push(...extractParamNames(prop.value));
      } else if (prop.type === 'RestElement') {
        names.push(...extractParamNames(prop.argument));
      }
    }
  } else if (param.type === 'ArrayPattern') {
    for (const element of (param as TSESTree.ArrayPattern).elements) {
      if (element) {
        names.push(...extractParamNames(element));
      }
    }
  } else if (param.type === 'AssignmentPattern') {
    names.push(...extractParamNames((param as TSESTree.AssignmentPattern).left));
  } else if (param.type === 'RestElement') {
    names.push(...extractParamNames((param as TSESTree.RestElement).argument));
  }
  return names;
}

function unwrapAwait(node: TSESTree.Node): TSESTree.Node {
  if (node.type === 'AwaitExpression') {
    return (node as TSESTree.AwaitExpression).argument;
  }
  return node;
}

export function buildParentMap(ast: ParsedAST | TSESTree.Node): Map<TSESTree.Node, TSESTree.Node> {
  const map = new Map<TSESTree.Node, TSESTree.Node>();
  walk(ast, {
    enter(node, parent) {
      if (parent) map.set(node, parent);
    },
  });
  return map;
}

export function isDynamicExpr(n: TSESTree.Expression, taintResult: TaintResult, parentMap: Map<TSESTree.Node, TSESTree.Node>): boolean {
  if (isDirectUserInputExpr(n)) return true;
  if (isIdentifier(n) && isNodeContextuallyTainted(n, taintResult, parentMap)) return true;
  if (n.type === 'ArrayExpression') {
    return n.elements.some((e) => e && e.type !== 'SpreadElement' && isDynamicExpr(e as TSESTree.Expression, taintResult, parentMap));
  }
  if (n.type === 'TemplateLiteral') {
    return (n as TSESTree.TemplateLiteral).expressions.some(
      (e) => isDynamicExpr(e as TSESTree.Expression, taintResult, parentMap)
    );
  }
  if (n.type === 'BinaryExpression' && (n as TSESTree.BinaryExpression).operator === '+') {
    const be = n as TSESTree.BinaryExpression;
    return isDynamicExpr(be.left as TSESTree.Expression, taintResult, parentMap) ||
           isDynamicExpr(be.right as TSESTree.Expression, taintResult, parentMap);
  }
  if (n.type === 'CallExpression') {
    const ce = n as TSESTree.CallExpression;
    if (isMemberExpression(ce.callee) && isIdentifier(ce.callee.property)) {
      if (ce.callee.property.name === 'join' && ce.callee.object.type === 'ArrayExpression') {
        return ce.callee.object.elements.some(
          (e) => e && e.type !== 'SpreadElement' && isDynamicExpr(e as TSESTree.Expression, taintResult, parentMap)
        );
      }
      if (isIdentifier(ce.callee.object) && ce.callee.object.name === 'Object' && ce.callee.property.name === 'fromEntries') {
        if (ce.arguments[0]) return isDynamicExpr(ce.arguments[0] as TSESTree.Expression, taintResult, parentMap);
      }
    }
  }
  return false;
}

const REQ_USER_INPUT_PROPS = new Set(['body', 'query', 'params', 'headers', 'cookies']);

export function isDirectUserInputExpr(node: TSESTree.Node): boolean {
  if (node.type === 'TSAsExpression' || node.type === 'TSNonNullExpression') {
    return isDirectUserInputExpr((node as TSESTree.TSAsExpression | TSESTree.TSNonNullExpression).expression);
  }
  if (!isMemberExpression(node)) return false;

  let current: TSESTree.Node = node;
  const properties: string[] = [];

  while (isMemberExpression(current)) {
    const me = current as TSESTree.MemberExpression;
    if (isIdentifier(me.property)) properties.unshift(me.property.name);
    current = me.object;
  }

  if (isIdentifier(current) && current.name === 'req' && properties.length > 0) {
    if (REQ_USER_INPUT_PROPS.has(properties[0])) return true;
  }

  return false;
}

export function isTaintedExpr(node: TSESTree.Node, tainted: Set<string>): boolean {
  if (isDirectUserInputExpr(node)) return true;
  if (isTaintedNode(node, tainted)) return true;
  if (node.type === 'ArrayExpression') {
    return node.elements.some(e => e && e.type !== 'SpreadElement' && isTaintedExpr(e, tainted));
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return isTaintedExpr(node.left, tainted) || isTaintedExpr(node.right, tainted);
  }
  if (node.type === 'TemplateLiteral') {
    return node.expressions.some(expr => isTaintedExpr(expr, tainted));
  }
  if (node.type === 'CallExpression') {
    const call = node as TSESTree.CallExpression;
    if (isMemberExpression(call.callee)) {
      const me = call.callee as TSESTree.MemberExpression;
      if (isIdentifier(me.property)) {
        const method = me.property.name;
        const TAINT_PRESERVING_METHODS = new Set(['trim', 'toLowerCase', 'toUpperCase', 'substring', 'slice', 'replace', 'replaceAll', 'concat', 'toString', 'join', 'split']);
        if (TAINT_PRESERVING_METHODS.has(method)) {
          return isTaintedExpr(me.object, tainted);
        }
        if (isIdentifier(me.object) && me.object.name === 'Object' && method === 'fromEntries') {
          if (call.arguments[0]) return isTaintedExpr(call.arguments[0], tainted);
        }
      }
    }
    if (isIdentifier(call.callee) && (call.callee.name === 'String' || call.callee.name === 'Number')) {
      if (call.arguments[0]) return isTaintedExpr(call.arguments[0], tainted);
    }
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

      if (node.id.type === 'Identifier') {
        const name = (node.id as TSESTree.Identifier).name;
        if (isTaintedExpr(node.init, tainted)) {
          tainted.add(name);
        }
        return;
      }

      if (node.id.type === 'ObjectPattern' && isDirectUserInputExpr(node.init)) {
        const pattern = node.id as TSESTree.ObjectPattern;
        for (const prop of pattern.properties) {
          if (prop.type === 'Property' && isIdentifier(prop.value)) {
            tainted.add((prop.value as TSESTree.Identifier).name);
          } else if (prop.type === 'RestElement') {
            extractParamNames(prop.argument).forEach(name => tainted.add(name));
          }
        }
      }

      if (node.id.type === 'ArrayPattern' && isDirectUserInputExpr(node.init)) {
        extractParamNames(node.id).forEach(name => tainted.add(name));
      }
    },

    AssignmentExpression(rawNode) {
      const node = rawNode as TSESTree.AssignmentExpression;
      if (node.left.type === 'Identifier') {
        const name = (node.left as TSESTree.Identifier).name;
        if (isTaintedExpr(node.right, tainted)) {
          tainted.add(name);
        }
      } else if (node.left.type === 'MemberExpression') {
        const me = node.left as TSESTree.MemberExpression;
        if (isIdentifier(me.object)) {
          if (isTaintedExpr(node.right, tainted)) {
            tainted.add((me.object as TSESTree.Identifier).name);
          }
        }
      }
    },

    CallExpression(rawNode) {
      const node = rawNode as TSESTree.CallExpression;
      if (isMemberExpression(node.callee) && isIdentifier(node.callee.object) && node.callee.object.name === 'Object') {
        if (isIdentifier(node.callee.property) && node.callee.property.name === 'assign') {
          if (node.arguments.length >= 2) {
            const firstArg = node.arguments[0];
            const sources = node.arguments.slice(1);
            if (isIdentifier(firstArg) && sources.some(s => isTaintedExpr(s, tainted))) {
              tainted.add(firstArg.name);
            }
          }
        }
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

export function isArgTainted(node: TSESTree.Node, tainted: Set<string>): boolean {
  if (isTaintedNode(node, tainted) || isTaintedExpr(node, tainted)) return true;
  if (node.type === 'ObjectExpression') {
    return (node as TSESTree.ObjectExpression).properties.some(p => {
      if (p.type === 'Property') return isArgTainted(p.value, tainted);
      if (p.type === 'SpreadElement') return isArgTainted(p.argument, tainted);
      return false;
    });
  }
  if (node.type === 'ArrayExpression') {
    return (node as TSESTree.ArrayExpression).elements.some(e => e && isArgTainted(e, tainted));
  }
  return false;
}

export function isNodeContextuallyTainted(
  node: TSESTree.Node,
  taintResult: TaintResult,
  parentMap: Map<TSESTree.Node, TSESTree.Node>
): boolean {
  if (isTaintedExpr(node, taintResult.globalTaints)) return true;

  let current: TSESTree.Node | undefined = parentMap.get(node);
  while (current) {
    if (current.type === 'FunctionDeclaration' || current.type === 'ArrowFunctionExpression' || current.type === 'FunctionExpression') {
      const localTaints = taintResult.localTaints.get(current);
      if (localTaints && isTaintedExpr(node, localTaints)) return true;
    }
    current = parentMap.get(current);
  }
  return false;
}

export function isArgContextuallyTainted(
  node: TSESTree.Node,
  taintResult: TaintResult,
  parentMap: Map<TSESTree.Node, TSESTree.Node>
): boolean {
  if (isNodeContextuallyTainted(node, taintResult, parentMap)) return true;
  if (node.type === 'ObjectExpression') {
    return (node as TSESTree.ObjectExpression).properties.some(p => {
      if (p.type === 'Property') return isArgContextuallyTainted(p.value, taintResult, parentMap);
      if (p.type === 'SpreadElement') return isArgContextuallyTainted(p.argument, taintResult, parentMap);
      return false;
    });
  }
  if (node.type === 'ArrayExpression') {
    return (node as TSESTree.ArrayExpression).elements.some(e => e && isArgContextuallyTainted(e, taintResult, parentMap));
  }
  return false;
}

export function buildContextualTaintMap(ast: ParsedAST, filePath: string): TaintResult {
  const globalTaints = buildTaintMap(ast);
  const localTaints = new Map<TSESTree.Node, Set<string>>();
  
  // Need parent map for contextual taint checks during iteration
  const parentMap = new Map<TSESTree.Node, TSESTree.Node>();
  walk(ast, {
    enter(node, parent) { if (parent) parentMap.set(node, parent); }
  });

  const imports = new Map<string, { source: string; name: string }>();
  const namespaceImports = new Map<string, string>();
  const localFunctions = new Map<string, TSESTree.Node>();
  
  let functionCount = 0;

  walk(ast, {
    ImportDeclaration(rawNode) {
      const node = rawNode as TSESTree.ImportDeclaration;
      if (node.source.type !== 'Literal' || typeof node.source.value !== 'string') return;
      const source = node.source.value;
      for (const spec of node.specifiers) {
        if (spec.type === 'ImportSpecifier') {
          imports.set(spec.local.name, { source, name: spec.imported.name });
        } else if (spec.type === 'ImportDefaultSpecifier') {
          imports.set(spec.local.name, { source, name: 'default' });
        } else if (spec.type === 'ImportNamespaceSpecifier') {
          namespaceImports.set(spec.local.name, source);
        }
      }
    },
    FunctionDeclaration(rawNode) {
      functionCount++;
      const node = rawNode as TSESTree.FunctionDeclaration;
      if (node.id) localFunctions.set(node.id.name, node);
    },
    VariableDeclarator(rawNode) {
      const node = rawNode as TSESTree.VariableDeclarator;
      if (node.id.type === 'Identifier' && node.init && (node.init.type === 'ArrowFunctionExpression' || node.init.type === 'FunctionExpression')) {
        functionCount++;
        localFunctions.set(node.id.name, node.init);
      }
    }
  });

  if (functionCount > 500) return { globalTaints, localTaints };

  const isCurrentlyTainted = (node: TSESTree.Node, funcContext?: TSESTree.Node): boolean => {
    if (isTaintedExpr(node, globalTaints)) return true;
    let curr = funcContext || parentMap.get(node);
    let isTainted = false;
    while (curr) {
      if (curr.type === 'FunctionDeclaration' || curr.type === 'ArrowFunctionExpression' || curr.type === 'FunctionExpression') {
        const lt = localTaints.get(curr);
        if (lt && isTaintedExpr(node, lt)) {
          isTainted = true;
          break;
        }
      }
      curr = parentMap.get(curr);
    }
    if (isTainted) return true;

    if (node.type === 'ObjectExpression') {
      return (node as TSESTree.ObjectExpression).properties.some(p => {
        if (p.type === 'Property') return isCurrentlyTainted(p.value, funcContext);
        if (p.type === 'SpreadElement') return isCurrentlyTainted(p.argument, funcContext);
        return false;
      });
    }
    if (node.type === 'ArrayExpression') {
      return (node as TSESTree.ArrayExpression).elements.some(e => e && isCurrentlyTainted(e, funcContext));
    }

    return false;
  };

  let changed = true;
  let iterations = 0;
  
  while (changed && iterations < 5) {
    changed = false;
    iterations++;
    
    walk(ast, {
      CallExpression(rawNode) {
        const node = rawNode as TSESTree.CallExpression;
        let funcName: string | null = null;
        if (node.callee.type === 'Identifier') {
          funcName = node.callee.name;
        } else if (node.callee.type === 'MemberExpression') {
          const me = node.callee as TSESTree.MemberExpression;
          if (isIdentifier(me.object) && isIdentifier(me.property)) {
            const nsName = me.object.name;
            if (namespaceImports.has(nsName)) funcName = `${nsName}.${me.property.name}`;
          }
        }
        
        if (!funcName) return;
        
        const targetNode = localFunctions.get(funcName);
        if (!targetNode) return;
        
        // Find which args are tainted
        node.arguments.forEach((arg, index) => {
          if (isCurrentlyTainted(arg)) {
            // @ts-expect-error params exist
            const params = targetNode.params || [];
            const param = params[index];
            if (!param) return;
            
            if (!localTaints.has(targetNode)) localTaints.set(targetNode, new Set());
            const lt = localTaints.get(targetNode)!;
            
            const beforeSize = lt.size;
            extractParamNames(param).forEach(name => lt.add(name));
            if (lt.size > beforeSize) changed = true;
          }
        });
      }
    });

    // Propagate assignments inside functions
    if (changed) {
      for (const [funcNode, lt] of localTaints.entries()) {
        const beforeSize = lt.size;
        // @ts-expect-error body exists
        walk(funcNode.body, {
          VariableDeclarator(vNode) {
            const vd = vNode as TSESTree.VariableDeclarator;
            if (vd.id.type === 'Identifier' && vd.init && isCurrentlyTainted(vd.init, funcNode)) {
              lt.add(vd.id.name);
            }
          },
          AssignmentExpression(aNode) {
            const ae = aNode as TSESTree.AssignmentExpression;
            if (ae.left.type === 'Identifier' && isCurrentlyTainted(ae.right, funcNode)) {
              lt.add(ae.left.name);
            }
          },
          CallExpression(cNode) {
            const call = cNode as TSESTree.CallExpression;
            if (isMemberExpression(call.callee) && isIdentifier(call.callee.object) && call.callee.object.name === 'Object') {
              if (isIdentifier(call.callee.property) && call.callee.property.name === 'assign') {
                if (call.arguments.length >= 2) {
                  const firstArg = call.arguments[0];
                  const sources = call.arguments.slice(1);
                  if (isIdentifier(firstArg) && sources.some(s => isCurrentlyTainted(s, funcNode))) {
                    lt.add(firstArg.name);
                  }
                }
              }
            }
          }
        });
        if (lt.size > beforeSize) changed = true;
      }
    }

    // Find taints returned
    const taintsReturn = new Set<string>();
    for (const [funcName, funcNode] of localFunctions.entries()) {
      const lt = localTaints.get(funcNode);
      if (!lt) continue;
      // @ts-expect-error body exists
      walk(funcNode.body, {
        ReturnStatement(retNode) {
          const ret = retNode as TSESTree.ReturnStatement;
          if (ret.argument && isCurrentlyTainted(ret.argument, funcNode)) {
            taintsReturn.add(funcName);
          }
        }
      });
    }

    // Taint global vars receiving return values
    if (taintsReturn.size > 0) {
      walk(ast, {
        VariableDeclarator(rawNode) {
          const node = rawNode as TSESTree.VariableDeclarator;
          if (!node.init || node.id.type !== 'Identifier') return;
          const unwrapped = unwrapAwait(node.init);
          if (unwrapped.type === 'CallExpression' && isIdentifier(unwrapped.callee) && taintsReturn.has(unwrapped.callee.name)) {
            if (!globalTaints.has(node.id.name)) {
              globalTaints.add(node.id.name);
              changed = true;
            }
          }
        },
        AssignmentExpression(rawNode) {
          const node = rawNode as TSESTree.AssignmentExpression;
          if (node.left.type === 'Identifier') {
            const unwrapped = unwrapAwait(node.right);
            if (unwrapped.type === 'CallExpression' && isIdentifier(unwrapped.callee) && taintsReturn.has(unwrapped.callee.name)) {
              if (!globalTaints.has(node.left.name)) {
                globalTaints.add(node.left.name);
                changed = true;
              }
            }
          }
        }
      });
    }
  }

  return { globalTaints, localTaints };
}

export function buildExtendedTaintMap(ast: ParsedAST, filePath: string): Set<string> {
  return buildContextualTaintMap(ast, filePath).globalTaints;
}

export interface CrossFileCall {
  externalFilePath: string;
  externalNode: TSESTree.Node;
  taintedParams: Set<string>;
  callNode: TSESTree.CallExpression;
  awaitNode?: TSESTree.AwaitExpression;
}

export function getCrossFileTaints(ast: ParsedAST, filePath: string, taintResult: TaintResult): CrossFileCall[] {

  const crossFileCalls: CrossFileCall[] = [];
  
  const imports = new Map<string, { source: string; name: string }>();
  const namespaceImports = new Map<string, string>();
  walk(ast, {
    ImportDeclaration(rawNode) {
      const node = rawNode as TSESTree.ImportDeclaration;
      if (node.source.type !== 'Literal' || typeof node.source.value !== 'string') return;
      const source = node.source.value;
      for (const spec of node.specifiers) {
        if (spec.type === 'ImportSpecifier') {
          imports.set(spec.local.name, { source, name: spec.imported.name });
        } else if (spec.type === 'ImportDefaultSpecifier') {
          imports.set(spec.local.name, { source, name: 'default' });
        } else if (spec.type === 'ImportNamespaceSpecifier') {
          namespaceImports.set(spec.local.name, source);
        }
      }
    }
  });

  walk(ast, {
    CallExpression(rawNode, parentNode) {
      const node = rawNode as TSESTree.CallExpression;
      let importInfo: { source: string; name: string } | undefined;
      
      if (node.callee.type === 'Identifier') {
        const funcName = (node.callee as TSESTree.Identifier).name;
        importInfo = imports.get(funcName);
      } else if (node.callee.type === 'MemberExpression') {
        const me = node.callee as TSESTree.MemberExpression;
        if (isIdentifier(me.object) && isIdentifier(me.property)) {
          const nsName = (me.object as TSESTree.Identifier).name;
          if (namespaceImports.has(nsName)) {
            importInfo = { source: namespaceImports.get(nsName)!, name: (me.property as TSESTree.Identifier).name };
          }
        }
      }

      const instantiatedClasses = new Map<string, string>(); // instanceName -> className
      walk(ast, {
        VariableDeclarator(rawNode) {
          const vNode = rawNode as TSESTree.VariableDeclarator;
          if (vNode.id.type === 'Identifier' && vNode.init && vNode.init.type === 'NewExpression') {
            const newExpr = vNode.init as TSESTree.NewExpression;
            if (newExpr.callee.type === 'Identifier') {
              instantiatedClasses.set(vNode.id.name, newExpr.callee.name);
            }
          }
        }
      });

      if (!importInfo && node.callee.type === 'MemberExpression') {
        const me = node.callee as TSESTree.MemberExpression;
        if (isIdentifier(me.object) && isIdentifier(me.property)) {
          const instanceName = me.object.name;
          if (instantiatedClasses.has(instanceName)) {
            const className = instantiatedClasses.get(instanceName)!;
            const classImport = imports.get(className);
            if (classImport) {
              importInfo = { source: classImport.source, name: className };
              // We will need to look for the method me.property.name inside this class
              (node as any)._methodName = me.property.name;
            }
          }
        }
      }

      if (!importInfo) return;

      const taintedArgIndices = new Set<number>();
      node.arguments.forEach((arg, index) => {
        if (isArgTainted(arg, taintResult.globalTaints)) {
          taintedArgIndices.add(index);
        }
      });

      if (taintedArgIndices.size === 0) return;

      const externalInfo = crossFileCache.getExportInfo(importInfo.source, filePath, importInfo.name);
      if (!externalInfo) return;
      const externalNode = externalInfo.node;
      const externalFilePath = externalInfo.filePath;

      let targetNode = externalNode;
      if ((node as any)._methodName) {
        const methodName = (node as any)._methodName;
        let foundMethod: TSESTree.Node | null = null;
        
        if (targetNode.type === 'ClassDeclaration' || targetNode.type === 'ClassExpression') {
          for (const member of targetNode.body.body) {
            if (member.type === 'MethodDefinition' && isIdentifier(member.key) && member.key.name === methodName) {
              foundMethod = member.value;
              break;
            }
          }
        } else if (targetNode.type === 'FunctionDeclaration' || targetNode.type === 'FunctionExpression' || targetNode.type === 'ArrowFunctionExpression') {
          walk(targetNode.body, {
            AssignmentExpression(aNode) {
              const ae = aNode as TSESTree.AssignmentExpression;
              if (ae.left.type === 'MemberExpression') {
                const me = ae.left;
                if (me.object.type === 'ThisExpression' && isIdentifier(me.property) && me.property.name === methodName) {
                  if (ae.right.type === 'FunctionExpression' || ae.right.type === 'ArrowFunctionExpression') {
                    foundMethod = ae.right;
                  }
                }
              }
            }
          });
        }
        
        if (foundMethod) targetNode = foundMethod;
        else return; // method not found, assume safe or dynamic
      }

      if (targetNode.type !== 'FunctionDeclaration' && targetNode.type !== 'ArrowFunctionExpression' && targetNode.type !== 'FunctionExpression') return;
      
      const taintedParams = new Set<string>();
      // @ts-expect-error params exist on these nodes
      const params = targetNode.params || [];
      params.forEach((param: TSESTree.Node, index: number) => {
        if (taintedArgIndices.has(index)) {
          extractParamNames(param).forEach(name => taintedParams.add(name));
        }
      });

      if (taintedParams.size > 0) {
        let awaitNode: TSESTree.AwaitExpression | undefined;
        if (parentNode && parentNode.type === 'AwaitExpression') {
          awaitNode = parentNode as TSESTree.AwaitExpression;
        }
        crossFileCalls.push({ externalFilePath, externalNode: targetNode, taintedParams, callNode: node, awaitNode });
      }
    }
  });

  return crossFileCalls;
}

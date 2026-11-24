import { TSESTree } from '@typescript-eslint/typescript-estree';
import { walk } from '../scanner/ast-walker.js';
import { ParsedAST } from '../scanner/rules/types.js';

export interface ModuleBindings {
  /** local names bound to the whole module: `const m = require('x')`, `import m from 'x'`, `import * as m from 'x'` */
  namespaces: Set<string>;
  /** local name -> exported name: `const { a: b } = require('x')`, `import { a as b } from 'x'`, `const b = require('x').a` */
  named: Map<string, string>;
}

function moduleNameOf(node: TSESTree.Node | null | undefined, modules: Set<string>): boolean {
  return !!node && node.type === 'Literal' && typeof node.value === 'string' && modules.has(node.value);
}

function isRequireOf(node: TSESTree.Node, modules: Set<string>): boolean {
  return node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'require' && moduleNameOf(node.arguments[0], modules);
}

/** Find the local names a file binds to any of `modules` (anywhere in the file, not only top level). */
export function collectModuleBindings(ast: ParsedAST, modules: Set<string>): ModuleBindings {
  const b: ModuleBindings = { namespaces: new Set(), named: new Map() };
  walk(ast, {
    ImportDeclaration(n) {
      const node = n as TSESTree.ImportDeclaration;
      if (!moduleNameOf(node.source, modules)) return;
      for (const sp of node.specifiers) {
        if (sp.type === 'ImportSpecifier') {
          const imported = sp.imported.type === 'Identifier' ? sp.imported.name : String((sp.imported as unknown as TSESTree.Literal).value);
          b.named.set(sp.local.name, imported);
        } else {
          b.namespaces.add(sp.local.name);
        }
      }
    },
    VariableDeclarator(n) {
      const node = n as TSESTree.VariableDeclarator;
      const init = node.init;
      if (!init) return;
      if (isRequireOf(init, modules)) {
        if (node.id.type === 'Identifier') b.namespaces.add(node.id.name);
        else if (node.id.type === 'ObjectPattern') {
          for (const prop of node.id.properties) {
            if (prop.type === 'Property' && prop.key.type === 'Identifier' && prop.value.type === 'Identifier') {
              b.named.set(prop.value.name, prop.key.name);
            }
          }
        }
      } else if (init.type === 'MemberExpression' && isRequireOf(init.object, modules) && init.property.type === 'Identifier' && node.id.type === 'Identifier') {
        b.named.set(node.id.name, init.property.name);
      }
    },
  });
  return b;
}

/** `callee` calls `exportName` (or one of `exportNames`) of the bound module: m.fn(...) or fn(...) */
export function isBoundModuleCall(callee: TSESTree.Node, bindings: ModuleBindings, exportNames: Set<string>): boolean {
  if (callee.type === 'Identifier') {
    const imported = bindings.named.get(callee.name);
    return imported !== undefined && exportNames.has(imported);
  }
  if (callee.type === 'MemberExpression' && callee.property.type === 'Identifier' && exportNames.has(callee.property.name)) {
    const obj = callee.object;
    if (obj.type === 'Identifier') return bindings.namespaces.has(obj.name);
    if (obj.type === 'CallExpression' && obj.callee.type === 'Identifier' && obj.callee.name === 'require') return true;
  }
  return false;
}

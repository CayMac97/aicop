import { TSESTree } from '@typescript-eslint/typescript-estree';
import { walk } from '../ast-walker.js';
import { globalSymbolTable } from './global-symbol-table.js';
import { crossFileCache, isNodeSafe } from './cross-file-resolver.js';

export function runPhase1(ast: TSESTree.Node | TSESTree.Program, filePath: string) {
  const localDeclarations = new Map<string, TSESTree.Node>();

  // First pass: collect local declarations
  walk(ast, {
    FunctionDeclaration(node) {
      const decl = node as TSESTree.FunctionDeclaration;
      if (decl.id) {
        localDeclarations.set(decl.id.name, decl);
      }
    },
    VariableDeclarator(node) {
      const decl = node as TSESTree.VariableDeclarator;
      if (decl.id.type === 'Identifier' && decl.init) {
        if (
          decl.init.type === 'ArrowFunctionExpression' ||
          decl.init.type === 'FunctionExpression'
        ) {
          localDeclarations.set(decl.id.name, decl.init);
        }
      }
    }
  });

  // Second pass: resolve exports
  walk(ast, {
    ExportNamedDeclaration(node) {
      const declNode = node as TSESTree.ExportNamedDeclaration;
      
      if (declNode.source && declNode.source.type === 'Literal') {
        const sourceModule = declNode.source.value as string;
        for (const specifier of declNode.specifiers) {
          if (specifier.type === 'ExportSpecifier') {
            const localName = specifier.local.name;
            const exportedName = specifier.exported.name;
            const resolvedNode = crossFileCache.getExport(sourceModule, filePath, localName);
            if (resolvedNode) {
              const isSafe = isNodeSafe(resolvedNode, exportedName);
              globalSymbolTable.addExport(filePath, exportedName, resolvedNode, isSafe);
            }
          }
        }
      } else {
        // Handle export { foo, bar as baz }
        for (const specifier of declNode.specifiers) {
          if (specifier.type === 'ExportSpecifier') {
            const localName = specifier.local.name;
            const exportedName = specifier.exported.name;
            const resolvedNode = localDeclarations.get(localName);
            if (resolvedNode) {
              const isSafe = isNodeSafe(resolvedNode, exportedName);
              globalSymbolTable.addExport(filePath, exportedName, resolvedNode, isSafe);
            }
          }
        }
      }

      const decl = declNode.declaration;
      if (!decl) return;

      if (decl.type === 'FunctionDeclaration' && decl.id) {
        const isSafe = isNodeSafe(decl, decl.id.name);
        globalSymbolTable.addExport(filePath, decl.id.name, decl, isSafe);
      } else if (decl.type === 'VariableDeclaration') {
        for (const declarator of decl.declarations) {
          if (declarator.id.type === 'Identifier' && declarator.init) {
            if (
              declarator.init.type === 'ArrowFunctionExpression' ||
              declarator.init.type === 'FunctionExpression'
            ) {
              const isSafe = isNodeSafe(declarator.init, declarator.id.name);
              globalSymbolTable.addExport(filePath, declarator.id.name, declarator.init, isSafe);
            }
          }
        }
      }
    },
    ExportDefaultDeclaration(node) {
      const decl = (node as TSESTree.ExportDefaultDeclaration).declaration;
      if (
        decl.type === 'FunctionDeclaration' ||
        decl.type === 'ArrowFunctionExpression' ||
        decl.type === 'FunctionExpression'
      ) {
        const isSafe = isNodeSafe(decl, 'default');
        globalSymbolTable.addExport(filePath, 'default', decl, isSafe);
      } else if (decl.type === 'Identifier') {
        const localName = (decl as TSESTree.Identifier).name;
        const resolvedNode = localDeclarations.get(localName);
        if (resolvedNode) {
          const isSafe = isNodeSafe(resolvedNode, 'default');
          globalSymbolTable.addExport(filePath, 'default', resolvedNode, isSafe);
        }
      }
    }
  });
}

import { TSESTree } from '@typescript-eslint/typescript-estree';
import { walk } from '../ast-walker.js';
import { globalSymbolTable } from './global-symbol-table.js';
import { crossFileCache } from './cross-file-resolver.js';

export function runPhase1(ast: TSESTree.Node | TSESTree.Program, filePath: string) {
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
              globalSymbolTable.addExport(filePath, exportedName, resolvedNode);
            }
          }
        }
      }

      const decl = declNode.declaration;
      if (!decl) return;

      if (decl.type === 'FunctionDeclaration' && decl.id) {
        globalSymbolTable.addExport(filePath, decl.id.name, decl);
      } else if (decl.type === 'VariableDeclaration') {
        for (const declarator of decl.declarations) {
          if (declarator.id.type === 'Identifier' && declarator.init) {
            // Check if init is an arrow function or function expression
            if (
              declarator.init.type === 'ArrowFunctionExpression' ||
              declarator.init.type === 'FunctionExpression'
            ) {
              globalSymbolTable.addExport(filePath, declarator.id.name, declarator.init);
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
        globalSymbolTable.addExport(filePath, 'default', decl);
      }
    }
  });
}

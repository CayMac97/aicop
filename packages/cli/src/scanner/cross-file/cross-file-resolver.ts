import { TSESTree, parse } from '@typescript-eslint/typescript-estree';
import { readFileContent } from '../../utils/file-utils.js';
import { resolveLocalModule } from './module-resolver.js';
import { walk } from '../ast-walker.js';
import { PARSE_OPTIONS } from '../scan-file.js';
export interface ExportInfo {
  filePath: string;
  name: string;
  node: TSESTree.Node;
  isSafe: boolean;
}
import { LRUCache } from '../../utils/lru-cache.js';

export function isNodeSafe(node: TSESTree.Node, name: string): boolean {
  if (/escape|sanitize|validate|clean|check/i.test(name)) {
    return true;
  }
  let safe = false;
  if (node.type === 'FunctionDeclaration' || node.type === 'ArrowFunctionExpression' || node.type === 'FunctionExpression') {
    const funcNode = node as any;
    if (funcNode.body) {
      walk(funcNode.body, {
        CallExpression(cNode) {
          const call = cNode as TSESTree.CallExpression;
          let calleeName = '';
          if (call.callee.type === 'Identifier') calleeName = call.callee.name;
          else if (call.callee.type === 'MemberExpression' && call.callee.property.type === 'Identifier') {
            calleeName = call.callee.property.name;
          }
          if (calleeName && /escape|sanitize|validate|clean|check/i.test(calleeName)) {
            safe = true;
          }
        }
      });
    }
  }
  return safe;
}

class CrossFileCache {
  // LRUCache<absoluteFilePath, Map<exportName, ExportInfo>>
  private parsedFiles = new LRUCache<string, Map<string, ExportInfo>>(50);
  private fileSources = new LRUCache<string, string>(50);

  public clear(): void {
    this.parsedFiles.clear();
    this.fileSources.clear();
  }

  public initWithSources(sources: Record<string, string>): void {
    for (const [filePath, source] of Object.entries(sources)) {
      this.fileSources.set(filePath, source);
    }
  }

  public getFileSource(filePath: string): string | null {
    return this.fileSources.get(filePath) || null;
  }

  public getExportInfo(importPath: string, currentFilePath: string, exportName: string): ExportInfo | null {
    const absolutePath = resolveLocalModule(importPath, currentFilePath);
    if (!this.parsedFiles.has(absolutePath)) {
      this.parseAndCacheFile(absolutePath);
    }

    const fileExports = this.parsedFiles.get(absolutePath);
    if (!fileExports) return null;

    return fileExports.get(exportName) || null;
  }

  public getExport(importPath: string, currentFilePath: string, exportName: string): TSESTree.Node | null {
    const info = this.getExportInfo(importPath, currentFilePath, exportName);
    return info ? info.node : null;
  }

  private parseAndCacheFile(rawFilePath: string) {
    const filePath = rawFilePath.replace(/\\/g, '/');
    const exportsMap = new Map<string, ExportInfo>();
    this.parsedFiles.set(filePath, exportsMap); // set immediately to prevent infinite recursion on circular imports

    let source = '';
    try {
      source = this.getFileSource(filePath) || readFileContent(filePath);
      this.fileSources.set(filePath, source);
    } catch {
      return; // Could not read file
    }

    let ast: TSESTree.Program;
    try {
      ast = parse(source, { ...PARSE_OPTIONS, jsx: true });
    } catch {
      try {
        ast = parse(source, { ...PARSE_OPTIONS, jsx: false });
      } catch {
        return; // Parse error
      }
    }

    const _this = this;

    const localDeclarations = new Map<string, TSESTree.Node>();
    walk(ast, {
      FunctionDeclaration(node) {
        const decl = node as TSESTree.FunctionDeclaration;
        if (decl.id) localDeclarations.set(decl.id.name, decl);
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

    walk(ast, {
      ExportNamedDeclaration(node) {
        const decl = (node as TSESTree.ExportNamedDeclaration);
        
        if (decl.declaration) {
          const d = decl.declaration;
          if (d.type === 'FunctionDeclaration' && d.id) {
            const isSafe = isNodeSafe(d, d.id.name);
            exportsMap.set(d.id.name, { filePath, name: d.id.name, node: d, isSafe });
          } else if (d.type === 'VariableDeclaration') {
            for (const declarator of d.declarations) {
              if (declarator.id.type === 'Identifier' && declarator.init) {
                if (
                  declarator.init.type === 'ArrowFunctionExpression' ||
                  declarator.init.type === 'FunctionExpression'
                ) {
                  const isSafe = isNodeSafe(declarator.init, declarator.id.name);
                  exportsMap.set(declarator.id.name, { filePath, name: declarator.id.name, node: declarator.init, isSafe });
                }
              }
            }
          }
        }
        
        if (decl.source && decl.source.type === 'Literal') {
          const sourceModule = (decl.source as TSESTree.StringLiteral).value;
          for (const specifier of decl.specifiers) {
            if (specifier.type === 'ExportSpecifier') {
              const localName = specifier.local.name;
              const exportedName = specifier.exported.name;
              const extInfo = _this.getExportInfo(sourceModule, filePath, localName);
              if (extInfo) {
                const isSafe = isNodeSafe(extInfo.node, exportedName);
                exportsMap.set(exportedName, { filePath: extInfo.filePath, name: exportedName, node: extInfo.node, isSafe });
              }
            }
          }
        } else {
          for (const specifier of decl.specifiers) {
            if (specifier.type === 'ExportSpecifier') {
              const localName = specifier.local.name;
              const exportedName = specifier.exported.name;
              const resolvedNode = localDeclarations.get(localName);
              if (resolvedNode) {
                const isSafe = isNodeSafe(resolvedNode, exportedName);
                exportsMap.set(exportedName, { filePath, name: exportedName, node: resolvedNode, isSafe });
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
          exportsMap.set('default', { filePath, name: 'default', node: decl, isSafe });
        } else if (decl.type === 'Identifier') {
          const localName = (decl as TSESTree.Identifier).name;
          const resolvedNode = localDeclarations.get(localName);
          if (resolvedNode) {
            const isSafe = isNodeSafe(resolvedNode, 'default');
            exportsMap.set('default', { filePath, name: 'default', node: resolvedNode, isSafe });
          }
        }
      },
      ExportAllDeclaration(node) {
        const decl = node as TSESTree.ExportAllDeclaration;
        if (decl.source && decl.source.type === 'Literal') {
          const sourceModule = decl.source.value as string;
          const absolutePath = resolveLocalModule(sourceModule, filePath);
          if (absolutePath) {
            if (!_this.parsedFiles.has(absolutePath)) {
              _this.parseAndCacheFile(absolutePath);
            }
            const sourceExports = _this.parsedFiles.get(absolutePath);
            if (sourceExports) {
              for (const [name, info] of sourceExports.entries()) {
                if (name !== 'default') {
                  exportsMap.set(name, info);
                }
              }
            }
          }
        }
      },
      AssignmentExpression(node) {
        const expr = node as TSESTree.AssignmentExpression;
        if (expr.left.type === 'MemberExpression') {
          const me = expr.left as TSESTree.MemberExpression;
          if (me.object.type === 'Identifier' && me.object.name === 'module' && me.property.type === 'Identifier' && me.property.name === 'exports') {
            if (expr.right.type === 'FunctionExpression' || expr.right.type === 'ArrowFunctionExpression' || expr.right.type === 'Identifier') {
              const rightNode = expr.right.type === 'Identifier' ? (localDeclarations.get(expr.right.name) || expr.right) : expr.right;
              const isSafe = isNodeSafe(rightNode, 'default');
              exportsMap.set('default', { filePath, name: 'default', node: rightNode, isSafe });
            } else if (expr.right.type === 'ObjectExpression') {
              for (const prop of expr.right.properties) {
                if (prop.type === 'Property' && prop.key.type === 'Identifier') {
                  const rightNode = prop.value.type === 'Identifier' ? (localDeclarations.get(prop.value.name) || prop.value) : prop.value;
                  const isSafe = isNodeSafe(rightNode, prop.key.name);
                  exportsMap.set(prop.key.name, { filePath, name: prop.key.name, node: rightNode, isSafe });
                }
              }
            }
          } else if (me.object.type === 'MemberExpression') {
            const meObj = me.object as TSESTree.MemberExpression;
            if (meObj.object.type === 'Identifier' && meObj.object.name === 'module' && meObj.property.type === 'Identifier' && meObj.property.name === 'exports' && me.property.type === 'Identifier') {
              const name = me.property.name;
              const rightNode = expr.right.type === 'Identifier' ? (localDeclarations.get(expr.right.name) || expr.right) : expr.right;
              const isSafe = isNodeSafe(rightNode, name);
              exportsMap.set(name, { filePath, name, node: rightNode, isSafe });
            }
          } else if (me.object.type === 'Identifier' && me.object.name === 'exports' && me.property.type === 'Identifier') {
            const name = me.property.name;
            const rightNode = expr.right.type === 'Identifier' ? (localDeclarations.get(expr.right.name) || expr.right) : expr.right;
            const isSafe = isNodeSafe(rightNode, name);
            exportsMap.set(name, { filePath, name, node: rightNode, isSafe });
          }
        }
      }
    });
  }
}

export const crossFileCache = new CrossFileCache();

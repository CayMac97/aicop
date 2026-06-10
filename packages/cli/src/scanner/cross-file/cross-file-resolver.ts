import { TSESTree, parse } from '@typescript-eslint/typescript-estree';
import { readFileContent } from '../../utils/file-utils.js';
import { resolveLocalModule } from './module-resolver.js';
import { walk } from '../ast-walker.js';
import { PARSE_OPTIONS } from '../scan-file.js';
import { globalSymbolTable, ExportInfo } from './global-symbol-table.js';

class CrossFileCache {
  // Map<absoluteFilePath, Map<exportName, ExportInfo>>
  private parsedFiles = new Map<string, Map<string, ExportInfo>>();
  private fileSources = new Map<string, string>();

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
    if (!absolutePath) return null;

    const globalExport = globalSymbolTable.getExport(absolutePath, exportName);
    if (globalExport) return globalExport;

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

  private parseAndCacheFile(filePath: string) {
    const exportsMap = new Map<string, ExportInfo>();
    this.parsedFiles.set(filePath, exportsMap); // set immediately to prevent infinite recursion on circular imports

    let source = '';
    try {
      source = readFileContent(filePath);
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
    walk(ast, {
      ExportNamedDeclaration(node) {
        const decl = (node as TSESTree.ExportNamedDeclaration);
        
        if (decl.declaration) {
          const d = decl.declaration;
          if (d.type === 'FunctionDeclaration' && d.id) {
            exportsMap.set(d.id.name, { filePath, name: d.id.name, node: d });
            globalSymbolTable.addExport(filePath, d.id.name, d);
          } else if (d.type === 'VariableDeclaration') {
            for (const declarator of d.declarations) {
              if (declarator.id.type === 'Identifier' && declarator.init) {
                if (
                  declarator.init.type === 'ArrowFunctionExpression' ||
                  declarator.init.type === 'FunctionExpression'
                ) {
                  exportsMap.set(declarator.id.name, { filePath, name: declarator.id.name, node: declarator.init });
                  globalSymbolTable.addExport(filePath, declarator.id.name, declarator.init);
                }
              }
            }
          }
        }
        
        if (decl.source) {
          const sourceModule = (decl.source as TSESTree.StringLiteral).value;
          for (const specifier of decl.specifiers) {
            if (specifier.type === 'ExportSpecifier') {
              const localName = specifier.local.name;
              const exportedName = specifier.exported.name;
              const resolvedNode = _this.getExport(sourceModule, filePath, localName);
              if (resolvedNode) {
                exportsMap.set(exportedName, { filePath, name: exportedName, node: resolvedNode });
                globalSymbolTable.addExport(filePath, exportedName, resolvedNode);
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
          exportsMap.set('default', { filePath, name: 'default', node: decl });
          globalSymbolTable.addExport(filePath, 'default', decl);
        }
      }
    });
  }
}

export const crossFileCache = new CrossFileCache();

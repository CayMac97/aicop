import { TSESTree } from '@typescript-eslint/typescript-estree';

export interface ExportInfo {
  filePath: string;
  name: string;
  node: TSESTree.Node; // The FunctionDeclaration, ArrowFunctionExpression, etc.
  isSafe?: boolean;
}

export class GlobalSymbolTable {
  // Map<filePath, Map<exportName, ExportInfo>>
  private table = new Map<string, Map<string, ExportInfo>>();
  public clear(): void {
    this.table.clear();
  }

  public addExport(filePath: string, name: string, node: TSESTree.Node, isSafe: boolean = false, originalFilePath?: string) {
    const normalizedPath = filePath.replace(/\\/g, '/');
    let fileExports = this.table.get(normalizedPath);
    if (!fileExports) {
      fileExports = new Map();
      this.table.set(normalizedPath, fileExports);
    }
    fileExports.set(name, { filePath: originalFilePath ? originalFilePath.replace(/\\/g, '/') : normalizedPath, name, node, isSafe });
  }

  public getExport(filePath: string, name: string): ExportInfo | null {
    const normalizedPath = filePath.replace(/\\/g, '/');
    const fileExports = this.table.get(normalizedPath);
    if (!fileExports) return null;
    return fileExports.get(name) || null;
  }

  public getTable() {
    return this.table;
  }

  public setTable(table: Map<string, Map<string, ExportInfo>>) {
    this.table = table;
  }
}

export const globalSymbolTable = new GlobalSymbolTable();

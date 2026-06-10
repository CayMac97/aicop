import path from 'path';
import fs from 'fs';

const EXTENSIONS = ['.ts', '.js', '.tsx', '.jsx', '.cjs', '.mjs'];

function statFile(p: string): boolean {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

function statDir(p: string): boolean {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
}

const moduleCache = new Map<string, string | null>();

export function clearModuleCache(): void {
  moduleCache.clear();
}

/**
 * Resolves a module import path to an absolute file path.
 * Does not resolve npm modules, only local project files (e.g., './utils/db' or '../services/auth').
 */
export function resolveLocalModule(importPath: string, currentFilePath: string): string | null {
  if (!importPath.startsWith('.')) {
    // It's likely a node_modules package or alias. We currently only support relative paths.
    // Future improvement: support tsconfig paths/aliases (e.g., '@utils/db')
    return null;
  }

  const baseDir = path.dirname(currentFilePath);
  const targetPath = path.resolve(baseDir, importPath);
  const cacheKey = targetPath;

  if (moduleCache.has(cacheKey)) {
    return moduleCache.get(cacheKey)!;
  }

  // 1. Exact match (e.g., importPath already has extension)
  if (statFile(targetPath)) {
    const result = targetPath.replace(/\\/g, '/');
    moduleCache.set(cacheKey, result);
    return result;
  }

  // 2. Try adding extensions
  for (const ext of EXTENSIONS) {
    const withExt = targetPath + ext;
    if (statFile(withExt)) {
      const result = withExt.replace(/\\/g, '/');
      moduleCache.set(cacheKey, result);
      return result;
    }
  }

  // 3. Try index files (e.g., targetPath is a directory)
  if (statDir(targetPath)) {
    for (const ext of EXTENSIONS) {
      const indexFile = path.join(targetPath, 'index' + ext);
      if (statFile(indexFile)) {
        const result = indexFile.replace(/\\/g, '/');
        moduleCache.set(cacheKey, result);
        return result;
      }
    }
  }

  moduleCache.set(cacheKey, null);
  return null;
}

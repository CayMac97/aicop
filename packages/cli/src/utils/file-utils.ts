import path from 'node:path';
import fs from 'fs-extra';

/** Read a file's content as UTF-8 string */
export function readFileContent(filePath: string): string {
  try {
    return fs.readFileSync(filePath, 'utf-8');
  } catch (err) {
    throw new Error(`Failed to read file "${filePath}": ${String(err)}`);
  }
}

/** Get a path relative to a base directory */
export function getRelativePath(filePath: string, basePath: string = process.cwd()): string {
  return path.relative(basePath, filePath).replace(/\\/g, '/');
}

/** Check if a file is a TypeScript file */
export function isTypeScriptFile(filePath: string): boolean {
  return /\.(ts|tsx)$/.test(filePath);
}

/** Check if a file is a JavaScript or TypeScript source file */
export function isSupportedFile(filePath: string): boolean {
  return /\.(ts|tsx|js|jsx|mjs|cjs)$/.test(filePath);
}

/** Check if a file is a test file */
export function isTestFile(filePath: string): boolean {
  const normalizedPath = filePath.replace(/\\/g, '/');
  return (
    /\.(test|spec)\.(ts|tsx|js|jsx)$/i.test(normalizedPath) ||
    /\/__tests__\//i.test(normalizedPath) ||
    /\/tests?\//i.test(normalizedPath) ||
    /\/test-?[a-zA-Z0-9_-]*\//i.test(normalizedPath)
  );
}

/** Check if a file is a config file */
export function isConfigFile(filePath: string): boolean {
  return (
    /\.config\.(ts|js)$/.test(filePath) ||
    /^config\.(ts|js)$/.test(path.basename(filePath))
  );
}

/**
 * Extract a snippet of source code around a given line number.
 * Returns the target line plus `contextLines` lines of surrounding context.
 */
export function extractSnippet(source: string, line: number, contextLines = 1): string {
  const lines = source.split('\n');
  const startIdx = Math.max(0, line - 1 - contextLines);
  const endIdx = Math.min(lines.length - 1, line - 1 + contextLines);
  return lines.slice(startIdx, endIdx + 1).join('\n');
}

/** Count non-empty, non-comment lines in source */
export function countLogicalLines(source: string): number {
  return source
    .split('\n')
    .filter((line) => {
      const trimmed = line.trim();
      return trimmed.length > 0 && !trimmed.startsWith('//') && !trimmed.startsWith('*');
    }).length;
}

/** Write content to a file, creating directories as needed */
export async function writeFile(filePath: string, content: string): Promise<void> {
  try {
    await fs.ensureDir(path.dirname(filePath));
    await fs.writeFile(filePath, content, 'utf-8');
  } catch (err) {
    throw new Error(`Failed to write ${filePath}: ${String(err)}`);
  }
}

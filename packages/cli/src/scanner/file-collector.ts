import { glob } from 'glob';
import path from 'node:path';
import { statSync } from 'node:fs';
import { VibescanConfig } from './rules/types.js';
import { logger } from '../utils/logger.js';

const DEFAULT_INCLUDE = ['**/*.{ts,tsx,js,jsx,mjs,cjs}'];
const DEFAULT_EXCLUDE = [
  '**/node_modules/**',
  '**/dist/**',
  '**/build/**',
  '**/.next/**',
  '**/coverage/**',
  '**/*.min.js',
  '**/*.min.css',
  '**/*.bundle.js',
  '**/*.chunk.js',
  '**/*.d.ts',
  '**/vendor/**',
  '**/public/js/**',
  '**/public/lib/**',
  '**/assets/js/**',
];

const MAX_FILE_BYTES = 500 * 1024;

function formatSize(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${Math.round(bytes / 1024)} KB`;
}

function withinSizeLimit(filePath: string): boolean {
  try {
    const { size } = statSync(filePath);
    if (size > MAX_FILE_BYTES) {
      logger.warn(`Skipping large file: ${path.basename(filePath)} (${formatSize(size)})`);
      return false;
    }
    return true;
  } catch {
    return true;
  }
}

export interface FileCollectorOptions {
  scanPath: string;
  config: VibescanConfig;
  ignorePatterns?: string[];
}

function resolveScanBase(scanPath: string): { base: string; singleFile: string | null } {
  try {
    const stats = statSync(scanPath);
    if (stats.isFile()) {
      return { base: path.dirname(scanPath), singleFile: scanPath };
    }
    return { base: scanPath, singleFile: null };
  } catch (err) {
    logger.debug(`Could not stat path "${scanPath}": ${String(err)}`);
    return { base: scanPath, singleFile: null };
  }
}

export async function collectFiles(options: FileCollectorOptions): Promise<string[]> {
  const { scanPath, config, ignorePatterns = [] } = options;
  try {
    const { base, singleFile } = await resolveScanBase(scanPath);

    if (singleFile) {
      logger.debug(`Single file scan: ${singleFile}`);
      return withinSizeLimit(singleFile) ? [singleFile] : [];
    }

    const includePatterns = config.include.length > 0 ? config.include : DEFAULT_INCLUDE;
    const excludePatterns = [
      ...DEFAULT_EXCLUDE,
      ...config.exclude,
      ...ignorePatterns,
    ];

    logger.debug(`Scanning ${base} with ${includePatterns.length} include patterns`);

    const results: string[] = [];
    for (const pattern of includePatterns) {
      const matches = await glob(pattern, {
        cwd: base,
        ignore: excludePatterns,
        absolute: true,
        nodir: true,
      });
      results.push(...matches);
    }

    const unique = [...new Set(results)].sort().filter(withinSizeLimit);
    logger.debug(`Found ${unique.length} files to scan`);
    return unique;
  } catch (err) {
    throw new Error(`File collection failed: ${String(err)}`);
  }
}

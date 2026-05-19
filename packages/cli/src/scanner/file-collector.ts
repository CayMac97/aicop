import { glob } from 'glob';
import path from 'node:path';
import { statSync, openSync, readSync, closeSync } from 'node:fs';
import { VibescanConfig } from './rules/types.js';
import { logger } from '../utils/logger.js';

const DEFAULT_EXCLUDE = [
  '**/node_modules/**',
  '**/dist/**',
  '**/build/**',
  '**/.next/**',
  '**/coverage/**',
  '**/*.d.ts',
  '**/public/js/**',
];

const EXAMPLES_EXCLUDE = [
  '**/examples/**',
  '**/example/**',
  '**/demo/**',
  '**/demos/**',
  '**/sample/**',
  '**/samples/**',
  '**/fixtures/**',
  '**/__fixtures__/**',
];

const MAX_FILE_BYTES = 500 * 1024;
const MEDIUM_FILE_BYTES = 100 * 1024;
const LARGE_NONTS_BYTES = 200 * 1024;
const BABEL_MIN_BYTES = 50 * 1024;

const VENDOR_DIRS = new Set([
  'vendor', 'vendors', 'libs', 'third-party', 'thirdparty',
  'bower_components', 'jspm_packages', 'external', 'extern',
  'themes',
]);

const VENDOR_LIBS = new Set([
  'jquery', 'bootstrap', 'lodash', 'underscore', 'moment',
  'backbone', 'angular', 'react', 'vue', 'ember', 'polymer',
  'modernizr', 'foundation', 'materialize', 'bulma',
  'd3', 'three', 'chart', 'plotly', 'highcharts',
  'carousel', 'slick', 'isotope', 'masonry',
  'magnific', 'fancybox', 'lightbox', 'swiper',
  'sjcl', 'forge', 'jsencrypt',
  'sockjs', 'signalr',
  'datatables', 'select2', 'chosen', 'typeahead',
  'tinymce', 'ckeditor', 'quill', 'codemirror',
  'leaflet', 'mapbox', 'openlayers',
  'ionicons', 'feather',
]);

const KNOWN_LIB_SUFFIXES = new Set([
  'min', 'js', 'ts', 'jsx', 'tsx', 'mjs', 'cjs', 'esm', 'umd',
  'dev', 'prod', 'development', 'production', 'bundle', 'slim',
  'full', 'legacy', 'core', 'base', 'lite', 'compact', 'modern',
  'common', 'browser', 'node', 'amd', 'compat', 'polyfill', 'all',
]);

function hasVendorDirSegment(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  const segments = normalized.split('/');
  return segments.some((s) => VENDOR_DIRS.has(s.toLowerCase()));
}

function isMinifiedFilename(filename: string): boolean {
  const lower = filename.toLowerCase();
  return lower.includes('.min.') || lower.endsWith('.bundle.js') || lower.endsWith('.chunk.js');
}

function hasKnownLibToken(filename: string): boolean {
  const lower = filename.toLowerCase();

  if (
    lower.includes('socket.io') ||
    lower.includes('crypto-js') ||
    lower.includes('font-awesome') ||
    lower.includes('owl.carousel')
  ) return true;

  const lastDot = lower.lastIndexOf('.');
  const stem = lastDot >= 0 ? lower.slice(0, lastDot) : lower;
  if (VENDOR_LIBS.has(stem)) return true;

  const tokens = lower.split(/[.\-_@]+/).filter((t) => t.length > 0);
  for (let i = 0; i < tokens.length; i++) {
    if (!VENDOR_LIBS.has(tokens[i])) continue;
    const rest = tokens.slice(i + 1).filter((t) => t.length > 0);
    const allNumericOrSuffix = rest.every((t) => /^\d+$/.test(t) || KNOWN_LIB_SUFFIXES.has(t));
    if (allNumericOrSuffix) return true;
  }
  return false;
}

function isVendorContent(snippet: string): boolean {
  if (!snippet) return false;
  const firstNonEmpty = snippet.split('\n').map((l) => l.trim()).find((l) => l.length > 0);
  if (!firstNonEmpty) return false;
  if (firstNonEmpty.startsWith('/*!')) return true;
  if (snippet.includes('@license')) return true;
  if (/Licensed under .{3,60} License/i.test(snippet)) return true;
  if ((snippet.match(/@author\b/g) ?? []).length >= 2) return true;
  return false;
}

function isDefinitelyBundle(snippet: string): boolean {
  if (!snippet) return false;
  const trimmed = snippet.trimStart();
  if (trimmed.startsWith('(function(') && trimmed.includes(')(jQuery)')) return true;
  if (
    /^["']use strict["'];function _typeof\b/.test(trimmed) ||
    trimmed.includes('_toConsumableArray') ||
    trimmed.includes('asyncGeneratorStep') ||
    trimmed.includes('_asyncToGenerator') ||
    trimmed.includes('regeneratorRuntime') ||
    trimmed.includes('_classCallCheck') ||
    trimmed.includes('_createClass')
  ) return true;
  return false;
}

function isBabelBundle(snippet: string): boolean {
  if (!snippet) return false;
  const trimmed = snippet.trimStart();
  return trimmed.startsWith('[function(') || trimmed.startsWith('(function(') || trimmed.includes('!function(');
}

function readFirstBytes(filePath: string, n: number): string {
  try {
    const fd = openSync(filePath, 'r');
    const buf = Buffer.alloc(n);
    const bytesRead = readSync(fd, buf, 0, n, 0);
    closeSync(fd);
    return buf.toString('utf-8', 0, bytesRead);
  } catch {
    return '';
  }
}

export function isVendorFile(filePath: string, source: string, sizeBytes?: number): boolean {
  const ext = path.extname(filePath).toLowerCase();
  const bytes = sizeBytes !== undefined ? sizeBytes : getFileSizeBytes(filePath);

  if (bytes > LARGE_NONTS_BYTES && ext !== '.ts' && ext !== '.tsx') return true;

  if (hasVendorDirSegment(filePath)) return true;
  const filename = path.basename(filePath);
  if (isMinifiedFilename(filename)) return true;
  if (hasKnownLibToken(filename)) return true;

  const snippet = source ? source.slice(0, 300) : readFirstBytes(filePath, 300);
  if (isVendorContent(snippet)) return true;
  if (isDefinitelyBundle(snippet)) return true;
  if (bytes > BABEL_MIN_BYTES && isBabelBundle(snippet)) return true;

  return false;
}

export function getFileSizeBytes(filePath: string): number {
  try {
    return statSync(filePath).size;
  } catch {
    return 0;
  }
}

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

export { MEDIUM_FILE_BYTES };

export interface FileCollectorOptions {
  scanPath: string;
  config: VibescanConfig;
  ignorePatterns?: string[];
  includeExamples?: boolean;
}

function matchesExcludePattern(filePath: string, pattern: string): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  const p = pattern.replace(/\\/g, '/');
  // **/dir/** → check for /dir/ segment
  const segMatch = p.match(/^\*\*\/([^*]+)\/\*\*$/);
  if (segMatch) return normalized.includes(`/${segMatch[1]}/`);
  // **/*.ext or **/*.{ext1,ext2}
  const extMatch = p.match(/^\*\*\/\*\.(.+)$/);
  if (extMatch) {
    const ext = extMatch[1];
    if (ext.startsWith('{') && ext.endsWith('}')) {
      const exts = ext.slice(1, -1).split(',');
      return exts.some((e) => normalized.endsWith(`.${e.trim()}`));
    }
    return normalized.endsWith(`.${ext}`);
  }
  // **/dir/ → check segment
  const dirMatch = p.match(/^\*\*\/([^*]+)\/$/);
  if (dirMatch) return normalized.includes(`/${dirMatch[1]}/`);
  return false;
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
  const { scanPath, config, ignorePatterns = [], includeExamples } = options;
  try {
    const { base, singleFile } = await resolveScanBase(scanPath);

    if (singleFile) {
      logger.debug(`Single file scan: ${singleFile}`);
      // For explicit single-file scans only apply user-defined excludes, not built-in defaults
      const userExcludes = [...config.exclude, ...ignorePatterns];
      const normalizedFile = singleFile.replace(/\\/g, '/');
      if (userExcludes.some((pat) => matchesExcludePattern(normalizedFile, pat))) return [];
      return withinSizeLimit(singleFile) ? [singleFile] : [];
    }

    const includePatterns = config.include.length > 0 ? config.include : ['**/*.{ts,tsx,js,jsx,mjs,cjs}'];
    const excludePatterns = [
      ...DEFAULT_EXCLUDE,
      ...(includeExamples ? [] : EXAMPLES_EXCLUDE),
      ...config.exclude,
      ...ignorePatterns,
    ];

    logger.debug(`Scanning ${base} with ${includePatterns.length} include patterns`);

    // Normalize to forward slashes so glob exclude patterns match on Windows
    const normalizedBase = base.replace(/\\/g, '/');
    const normalizedExcludes = excludePatterns.map((p) => p.replace(/\\/g, '/'));

    const results: string[] = [];
    for (const pattern of includePatterns) {
      const matches = await glob(pattern, {
        cwd: normalizedBase,
        ignore: normalizedExcludes,
        absolute: true,
        nodir: true,
      });
      // Normalize returned paths to forward slashes for consistent downstream handling
      results.push(...matches.map((m) => m.replace(/\\/g, '/')));
    }

    const unique = [...new Set(results)].sort().filter(withinSizeLimit);
    logger.debug(`Found ${unique.length} files to scan`);
    return unique;
  } catch (err) {
    throw new Error(`File collection failed: ${String(err)}`);
  }
}

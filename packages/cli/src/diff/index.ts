import simpleGit from 'simple-git';
import { scan } from '../scanner/index.js';
import { ScanResult, ScanOptions } from '../scanner/rules/types.js';
import { explainFindings, buildDiffHeader } from './explainer.js';
import { logger } from '../utils/logger.js';

/**
 * Run aicop on only files changed since the given git ref.
 *
 * @param ref - Git ref to compare against (e.g. "main", "HEAD~1", a commit SHA)
 * @param options - Scan options (config, severity, etc.)
 * @param onProgress - Optional progress callback forwarded to the scanner
 * @returns ScanResult containing only the changed files' findings
 */
export async function scanDiff(
  ref: string,
  options: ScanOptions,
  onProgress?: (file: string) => void,
): Promise<{ result: ScanResult; diffHeader: string }> {
  const git = simpleGit(process.cwd());

  let changedFiles: string[] = [];
  try {
    const diffSummary = await git.diff(['--name-only', '--relative', ref, '--']);
    const stagedSummary = await git.diff(['--name-only', '--relative', '--cached', '--']);
    changedFiles = [
      ...diffSummary.split('\n'),
      ...stagedSummary.split('\n'),
    ].map((f) => f.trim()).filter(Boolean);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.warn(`Git diff failed: ${message}`);
    process.stderr.write(`⚠ Could not diff against '${ref}' — running full scan instead. Use 'aicop diff --ref <branch>' to specify a branch.\n`);
    const result = await scan(options, onProgress);
    return { result, diffHeader: `Could not compute diff from ${ref}` };
  }

  if (changedFiles.length === 0) {
    logger.info(`No changed files found since ${ref}`);
  }

  const supportedExtensions = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
  const filteredFiles = changedFiles.filter((f) => supportedExtensions.test(f));

  if (filteredFiles.length === 0) {
    return {
      result: { files: [], aiScore: 100, errorCount: 0, warnCount: 0, infoCount: 0, filesScanned: 0, scanDurationMs: 0, categoryScores: { security: 100, aiSmell: 100, techDebt: 100 }, topIssues: [], skippedVendorFiles: 0, parseErrors: 0, totalFindings: 0, filesWithIssues: 0 },
      diffHeader: buildDiffHeader(ref, []),
    };
  }

  const diffOptions: ScanOptions = {
    ...options,
    path: process.cwd(),
    config: {
      ...options.config,
      include: filteredFiles.length > 0 ? filteredFiles : options.config.include,
    },
  };

  const result = await scan(diffOptions, onProgress);

  // Enrich findings with diff context
  for (const fileResult of result.files) {
    fileResult.findings = explainFindings(fileResult.findings);
  }

  const diffHeader = buildDiffHeader(ref, filteredFiles);
  return { result, diffHeader };
}

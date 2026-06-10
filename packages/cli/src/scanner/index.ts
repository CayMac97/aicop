import path from 'node:path';
import os from 'node:os';
import { Worker } from 'node:worker_threads';
import { collectFiles } from './file-collector.js';
import { logger } from '../utils/logger.js';
import { FileScanResult, ScanResult, ScanOptions } from './rules/types.js';
import { isVendorFile, getFileSizeBytes, MEDIUM_FILE_BYTES } from './file-collector.js';
import { readFileContent, getRelativePath } from '../utils/file-utils.js';
import { getEnabledRules, scanFile, PARSE_OPTIONS } from './scan-file.js';
import { clearModuleCache } from './cross-file/module-resolver.js';
import { crossFileCache } from './cross-file/cross-file-resolver.js';
import { globalSymbolTable } from './cross-file/global-symbol-table.js';
import { parse } from '@typescript-eslint/typescript-estree';
import { runPhase1 } from './cross-file/phase1-parser.js';

function chunkArray<T>(arr: T[], size: number): T[][] {
  const chunks = [];
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size));
  }
  return chunks;
}

function computeTopIssues(files: FileScanResult[]): Array<{ ruleId: string; fileCount: number }> {
  const ruleFileCounts = new Map<string, Set<string>>();
  for (const file of files) {
    for (const finding of file.findings) {
      const existing = ruleFileCounts.get(finding.ruleId) ?? new Set();
      existing.add(file.filePath);
      ruleFileCounts.set(finding.ruleId, existing);
    }
  }
  return Array.from(ruleFileCounts.entries())
    .map(([ruleId, files]) => ({ ruleId, fileCount: files.size }))
    .sort((a, b) => b.fileCount - a.fileCount)
    .slice(0, 5);
}

interface AIScoreResult {
  aiScore: number;
  categoryScores: { security: number; aiSmell: number; techDebt: number };
}

function computeAIScore(files: FileScanResult[]): AIScoreResult {
  const perfect = { aiScore: 100, categoryScores: { security: 100, aiSmell: 100, techDebt: 100 } };
  if (files.length === 0) return perfect;
  if (files.filter((f) => !f.parseError).length === 0) return perfect;

  const allFindings = files.flatMap((f) => f.findings);

  // security/error: weight 3×, security/warn: weight 1.5×
  const secErrCount = allFindings.filter((f) => f.ruleId.startsWith('security/') && f.severity === 'error').length;
  const secWarnCount = allFindings.filter((f) => f.ruleId.startsWith('security/') && f.severity === 'warn').length;
  const secErrPenalty = Math.min(secErrCount * 3, 60);
  const secWarnPenalty = Math.min(secWarnCount * 1.5, 20);

  // ai-smell/*: weight 1× (info-only findings don't penalise the score)
  const aiSmellCount = allFindings.filter((f) => f.ruleId.startsWith('ai-smell/') && f.severity !== 'info').length;
  const aiSmellPenalty = Math.min(aiSmellCount * 1, 20);

  // tech-debt/*: weight 0.5× (info excluded)
  const techDebtCount = allFindings.filter((f) => f.ruleId.startsWith('tech-debt/') && f.severity !== 'info').length;
  const techDebtPenalty = Math.min(techDebtCount * 0.5, 10);

  const total = secErrPenalty + secWarnPenalty + aiSmellPenalty + techDebtPenalty;
  const aiScore = Math.max(0, Math.floor(100 - total));

  const secScore = Math.max(0, Math.floor(100 - secErrCount * 5 - secWarnCount * 2.5));
  const aiSmellScore = Math.max(0, Math.floor(100 - aiSmellCount * 2));
  const techScore = Math.max(0, Math.floor(100 - techDebtCount * 1));

  return {
    aiScore,
    categoryScores: { security: secScore, aiSmell: aiSmellScore, techDebt: techScore },
  };
}

export async function scan(options: ScanOptions, onProgress?: (file: string) => void): Promise<ScanResult> {
  clearModuleCache();
  crossFileCache.clear();
  globalSymbolTable.clear();
  const startTime = Date.now();
  const { config, noAiScore, ruleId, includeVendor } = options;
  try {
    const files = await collectFiles({
      scanPath: options.path,
      config,
      ignorePatterns: options.ignore,
      includeExamples: options.includeExamples || config.includeExamples,
    });

    const enabledRules = getEnabledRules(config, ruleId);
    logger.debug(`Running ${enabledRules.length} rules on ${files.length} files`);

    const basePath = process.cwd();
    const fileResults: FileScanResult[] = [];
    let skippedVendorFiles = 0;

    const filesToScan: string[] = [];
    
    // Sort files deterministically
    files.sort();

    for (const filePath of files) {
      if (!includeVendor) {
        const sizeBytes = getFileSizeBytes(filePath);
        if (sizeBytes < MEDIUM_FILE_BYTES) {
          let preloadedSource = '';
          try { preloadedSource = readFileContent(filePath); } catch {}
          if (isVendorFile(filePath, preloadedSource, sizeBytes)) {
            skippedVendorFiles++;
            continue;
          }
        } else {
          if (isVendorFile(filePath, '', sizeBytes)) {
            skippedVendorFiles++;
            continue;
          }
        }
      }
      filesToScan.push(filePath);
    }

    const preloadedSources: Record<string, string> = {};
    logger.debug('Running Phase 1: building global symbol table...');
    for (const filePath of filesToScan) {
      try {
        const source = readFileContent(filePath);
        preloadedSources[filePath] = source;
        const ext = path.extname(filePath).toLowerCase();
        let ast;
        try {
          ast = parse(source, { ...PARSE_OPTIONS, jsx: ext === '.jsx' || ext === '.tsx' });
        } catch {
          try { ast = parse(source, { ...PARSE_OPTIONS, jsx: true }); } catch { continue; }
        }
        runPhase1(ast, filePath);
      } catch { /* ignore unreadable files */ }
    }
    logger.debug('Phase 1 complete.');
    crossFileCache.initWithSources(preloadedSources);

    if (filesToScan.length < 20) {
      // Sequential scan
      for (const filePath of filesToScan) {
        onProgress?.(getRelativePath(filePath, basePath));
        const result = scanFile(filePath, basePath, enabledRules, config, 'info', noAiScore, undefined, options.includeTests);
        fileResults.push(result);
      }
    } else {
      // Parallel scan
      const numCpus = os.cpus().length || 4;
      const chunkSize = Math.max(1, Math.ceil(filesToScan.length / numCpus));
      const chunks = chunkArray(filesToScan, chunkSize);

      const workerResults: FileScanResult[][] = [];
      const workers = chunks.map((chunk, i) => {
        workerResults.push([]);
        return new Promise<void>((resolve, reject) => {
          const worker = new Worker(__filename, {
             workerData: {
                files: chunk,
                basePath,
                config,
                minSeverity: 'info',
                noAiScore,
                includeTests: options.includeTests ?? false,
                ruleId: options.ruleId,
                preloadedSources
             }
          });
          worker.on('message', (msg) => {
             if (msg.type === 'result') {
                onProgress?.(msg.result.relativePath);
                workerResults[i].push(msg.result);
             } else if (msg.type === 'done') {
                resolve();
             }
          });
          worker.on('error', reject);
          worker.on('exit', (code) => {
             if (code !== 0) reject(new Error(`Worker stopped with exit code ${code}`));
          });
        });
      });
      await Promise.all(workers);
      fileResults.push(...workerResults.flat());
    }

    const allFindings = fileResults.flatMap((f) => f.findings);
    const filesWithIssues = fileResults.filter((f) => f.findings.length > 0).length;
    const parseErrors = fileResults.filter((f) => f.parseError != null).length;
    const { aiScore, categoryScores } = computeAIScore(fileResults);

    return {
      files: fileResults,
      totalFindings: allFindings.length,
      errorCount: allFindings.filter((f) => f.severity === 'error').length,
      warnCount: allFindings.filter((f) => f.severity === 'warn').length,
      infoCount: allFindings.filter((f) => f.severity === 'info').length,
      aiScore,
      categoryScores,
      scanDurationMs: Date.now() - startTime,
      filesScanned: fileResults.length,
      filesWithIssues,
      topIssues: computeTopIssues(fileResults),
      skippedVendorFiles,
      parseErrors,
    };
  } catch (err) {
    throw new Error(`Scan failed: ${String(err)}`);
  }
}

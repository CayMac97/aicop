import { parse } from '@typescript-eslint/typescript-estree';
import path from 'node:path';
import { collectFiles } from './file-collector.js';
import { getAllRules, getRuleById } from './rules/index.js';
import { runContextAnalysis } from './context-analyzer.js';
import { computeAiScore } from './rules/ai-smells/ai-confidence-scorer.js';
import { readFileContent, getRelativePath } from '../utils/file-utils.js';
import { logger } from '../utils/logger.js';
import { Rule, Finding, FileScanResult, ScanResult, ScanOptions, VibescanConfig, Severity } from './rules/types.js';

const PARSE_OPTIONS = {
  jsx: true,
  loc: true,
  range: true,
  comment: true,
  tokens: false,
  errorOnUnknownASTType: false,
  allowInvalidAST: true,
  loggerFn: false as const,
} as const;

function getEnabledRules(config: VibescanConfig, ruleId?: string): Rule[] {
  const allRules = getAllRules();
  return allRules.filter((rule) => {
    if (ruleId && rule.id !== ruleId) return false;
    const configSeverity = config.rules[rule.id];
    return configSeverity !== 'off';
  });
}

const TEST_FILE_RE = /[/\\](?:test|tests|spec|__tests__)[/\\](?!fixtures[/\\])|\.(?:test|spec)\.[jt]sx?$/i;

function applyConfigSeverity(finding: Finding, config: VibescanConfig): Finding {
  const configured = config.rules[finding.ruleId];
  if (!configured || configured === 'off') return finding;
  return { ...finding, severity: configured as Severity };
}

function downgradeInTestFile(finding: Finding, filePath: string): Finding {
  if (!TEST_FILE_RE.test(filePath)) return finding;
  if (finding.ruleId === 'security/hardcoded-secrets') {
    return { ...finding, severity: 'warn', message: 'hardcoded secret in test file — use environment variables even in tests' };
  }
  return finding;
}

function meetsMinSeverity(finding: Finding, minSeverity: Severity): boolean {
  const order: Record<Severity, number> = { error: 0, warn: 1, info: 2 };
  return order[finding.severity] <= order[minSeverity];
}

function scanFile(
  filePath: string,
  basePath: string,
  rules: Rule[],
  config: VibescanConfig,
  minSeverity: Severity,
  noAiScore: boolean,
): FileScanResult {
  const relativePath = getRelativePath(filePath, basePath);
  let source = '';
  try {
    source = readFileContent(filePath);
  } catch (err) {
    logger.warn(`Could not read file ${relativePath}: ${String(err)}`);
    return { filePath, relativePath, findings: [], aiScore: 0, parseError: String(err) };
  }

  let ast;
  try {
    const ext = path.extname(filePath).toLowerCase();
    const useJsx = ext === '.jsx' || ext === '.tsx';
    ast = parse(source, { ...PARSE_OPTIONS, jsx: useJsx });
  } catch (err) {
    logger.debug(`Parse error in ${relativePath}: ${String(err)}`);
    return { filePath, relativePath, findings: [], aiScore: 0, parseError: `Parse error: ${String(err)}` };
  }

  const rawFindings: Finding[] = [];

  for (const rule of rules) {
    try {
      const ruleFindings = rule.check(ast, source, filePath);
      rawFindings.push(...ruleFindings);
    } catch (err) {
      logger.debug(`Rule ${rule.id} failed on ${relativePath}: ${String(err)}`);
    }
  }

  const contextFindings = runContextAnalysis(source, filePath);
  rawFindings.push(...contextFindings);

  const findings = rawFindings
    .map((f) => applyConfigSeverity(f, config))
    .map((f) => downgradeInTestFile(f, filePath))
    .filter((f) => meetsMinSeverity(f, minSeverity))
    .sort((a, b) => {
      const order = { error: 0, warn: 1, info: 2 };
      const sevDiff = order[a.severity] - order[b.severity];
      return sevDiff !== 0 ? sevDiff : a.line - b.line;
    });

  const aiScore = noAiScore ? 0 : computeAiScore(findings);

  return { filePath, relativePath, findings, aiScore };
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

function computeVibeScore(files: FileScanResult[]): number {
  if (files.length === 0) return 100;
  const scoredFiles = files.filter((f) => !f.parseError);
  if (scoredFiles.length === 0) return 100;
  const allFindings = files.flatMap((f) => f.findings);
  const avgAiScore = scoredFiles.reduce((sum, f) => sum + f.aiScore, 0) / scoredFiles.length;
  const secErrCount = allFindings.filter(
    (f) => f.ruleId.startsWith('security/') && f.severity === 'error',
  ).length;
  const secWarnCount = allFindings.filter(
    (f) => f.ruleId.startsWith('security/') && f.severity === 'warn',
  ).length;
  const penalty = secErrCount * 12 + secWarnCount * 6 + Math.round(avgAiScore * 0.7);
  return Math.max(0, 100 - penalty);
}

export async function scan(options: ScanOptions, onProgress?: (file: string) => void): Promise<ScanResult> {
  const startTime = Date.now();
  const { config, severity, noAiScore, ruleId } = options;
  try {
    const files = await collectFiles({
      scanPath: options.path,
      config,
      ignorePatterns: options.ignore,
    });

    const enabledRules = getEnabledRules(config, ruleId);
    logger.debug(`Running ${enabledRules.length} rules on ${files.length} files`);

    const basePath = process.cwd();
    const fileResults: FileScanResult[] = [];

    for (const filePath of files) {
      onProgress?.(getRelativePath(filePath, basePath));
      const result = scanFile(filePath, basePath, enabledRules, config, severity, noAiScore);
      fileResults.push(result);
    }

    const allFindings = fileResults.flatMap((f) => f.findings);
    const filesWithIssues = fileResults.filter((f) => f.findings.length > 0).length;

    return {
      files: fileResults,
      totalFindings: allFindings.length,
      errorCount: allFindings.filter((f) => f.severity === 'error').length,
      warnCount: allFindings.filter((f) => f.severity === 'warn').length,
      infoCount: allFindings.filter((f) => f.severity === 'info').length,
      vibeScore: computeVibeScore(fileResults),
      scanDurationMs: Date.now() - startTime,
      filesScanned: files.length,
      filesWithIssues,
      topIssues: computeTopIssues(fileResults),
    };
  } catch (err) {
    throw new Error(`Scan failed: ${String(err)}`);
  }
}

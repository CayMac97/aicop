import { parse } from '@typescript-eslint/typescript-estree';
import path from 'node:path';
import { collectFiles } from './file-collector.js';
import { getAllRules } from './rules/index.js';
import { runContextAnalysis } from './context-analyzer.js';
import { computeAiScore } from './rules/ai-smells/ai-confidence-scorer.js';
import { readFileContent, getRelativePath } from '../utils/file-utils.js';
import { logger } from '../utils/logger.js';
import { Rule, Finding, FileScanResult, ScanResult, ScanOptions, VibescanConfig, Severity } from './rules/types.js';
import { isVendorFile, getFileSizeBytes, MEDIUM_FILE_BYTES } from './file-collector.js';

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

const TEST_FILE_RE = /[/\\](?:test|tests|spec|__tests__|e2e|mocks?|__mocks__)[/\\](?!fixtures[/\\])|\.(?:test|spec|e2e-spec|fixture)\.[jt]sx?$/i;

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

function applyIgnoreComments(findings: Finding[], source: string): Finding[] {
  const lines = source.split('\n');
  return findings.filter((f) => {
    const lineIdx = f.line - 1;
    const sameLine = lines[lineIdx] ?? '';
    const sameLineMatch = sameLine.match(/\/\/\s*aicop-ignore(?:\s+(\S+))?/);
    if (sameLineMatch) {
      const specifiedRule = sameLineMatch[1];
      if (!specifiedRule || specifiedRule === f.ruleId) return false;
    }
    const prevLine = lineIdx > 0 ? (lines[lineIdx - 1] ?? '').trim() : '';
    if (prevLine === '// aicop-ignore') return false;
    if (prevLine === `// aicop-ignore ${f.ruleId}`) return false;
    return true;
  });
}

function isSkippedInTestFile(finding: Finding, filePath: string): boolean {
  if (!TEST_FILE_RE.test(filePath)) return false;
  return finding.ruleId === 'security/missing-rate-limit' || finding.ruleId === 'security/csrf-missing';
}

function meetsMinSeverity(finding: Finding, minSeverity: Severity): boolean {
  const order: Record<Severity, number> = { error: 0, warn: 1, info: 2 };
  return order[finding.severity] <= order[minSeverity];
}

function isImportWarn(finding: Finding): boolean {
  if (finding.severity !== 'warn') return false;
  if (finding.ruleId === 'security/xxe-injection') {
    return finding.message.includes('XML parser can be vulnerable');
  }
  if (finding.ruleId === 'security/insecure-deserialization') {
    return finding.message.includes('can deserialize executable code');
  }
  return false;
}

function suppressImportWarnings(findings: Finding[]): Finding[] {
  const concreteRules = new Set(
    findings
      .filter((finding) => finding.severity === 'error')
      .filter((finding) => finding.ruleId === 'security/xxe-injection' || finding.ruleId === 'security/insecure-deserialization')
      .map((finding) => finding.ruleId),
  );
  if (concreteRules.size === 0) return findings;
  return findings.filter((finding) => !concreteRules.has(finding.ruleId) || !isImportWarn(finding));
}

function scanFile(
  filePath: string,
  basePath: string,
  rules: Rule[],
  config: VibescanConfig,
  minSeverity: Severity,
  noAiScore: boolean,
  preloadedSource?: string,
): FileScanResult {
  const relativePath = getRelativePath(filePath, basePath);
  let source = '';
  try {
    source = preloadedSource ?? readFileContent(filePath);
  } catch (err) {
    logger.warn(`Could not read file ${relativePath}: ${String(err)}`);
    return { filePath, relativePath, findings: [], aiScore: 0, parseError: String(err) };
  }

  let ast;
  try {
    const ext = path.extname(filePath).toLowerCase();
    const useJsx = ext === '.jsx' || ext === '.tsx';
    try {
      ast = parse(source, { ...PARSE_OPTIONS, jsx: useJsx });
    } catch {
      ast = parse(source, { ...PARSE_OPTIONS, jsx: true });
    }
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

  const findings = applyIgnoreComments(suppressImportWarnings(rawFindings), source)
    .map((f) => applyConfigSeverity(f, config))
    .map((f) => downgradeInTestFile(f, filePath))
    .filter((f) => !isSkippedInTestFile(f, filePath))
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
  const aiScore = Math.max(0, Math.round(100 - total));

  const secScore = Math.max(0, Math.round(100 - secErrCount * 5 - secWarnCount * 2.5));
  const aiSmellScore = Math.max(0, Math.round(100 - aiSmellCount * 2));   // aiSmellCount already excludes info
  const techScore = Math.max(0, Math.round(100 - techDebtCount * 1)); // techDebtCount already excludes info

  return {
    aiScore,
    categoryScores: { security: secScore, aiSmell: aiSmellScore, techDebt: techScore },
  };
}

export async function scan(options: ScanOptions, onProgress?: (file: string) => void): Promise<ScanResult> {
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

    for (const filePath of files) {
      let preloadedSource: string | undefined;
      if (!includeVendor) {
        const sizeBytes = getFileSizeBytes(filePath);
        if (sizeBytes < MEDIUM_FILE_BYTES) {
          try { preloadedSource = readFileContent(filePath); } catch { preloadedSource = undefined; }
        }
        if (isVendorFile(filePath, preloadedSource ?? '', sizeBytes)) {
          skippedVendorFiles++;
          logger.debug(`Skipping vendor file: ${getRelativePath(filePath, basePath)}`);
          continue;
        }
      }

      onProgress?.(getRelativePath(filePath, basePath));
      // Always collect at 'info' so all findings are in the result;
      // display-layer filtering happens in buildDisplayResult.
      const result = scanFile(filePath, basePath, enabledRules, config, 'info', noAiScore, preloadedSource);
      fileResults.push(result);
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

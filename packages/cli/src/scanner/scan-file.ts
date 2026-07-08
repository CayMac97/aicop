import { parse, TSESTree } from '@typescript-eslint/typescript-estree';
import path from 'node:path';
import picomatch from 'picomatch';
import { Rule, Finding, FileScanResult, VibescanConfig, Severity } from './rules/types.js';
import { runContextAnalysis } from './context-analyzer.js';
import { computeAiScore } from './rules/ai-smells/ai-confidence-scorer.js';
import { readFileContent, getRelativePath } from '../utils/file-utils.js';
import { logger } from '../utils/logger.js';
import { getAllRules } from './rules/index.js';

export const PARSE_OPTIONS = {
  jsx: true,
  loc: true,
  range: true,
  comment: true,
  tokens: false,
  errorOnUnknownASTType: false,
  allowInvalidAST: true,
  loggerFn: false as const,
} as const;

export function getEnabledRules(config: VibescanConfig, ruleId?: string): Rule[] {
  const allRules = getAllRules();
  return allRules.filter((rule) => {
    if (ruleId && rule.id !== ruleId) return false;
    const configSeverity = config.rules[rule.id];
    return configSeverity !== 'off';
  });
}

export function applyTestOverrides(finding: Finding, config: VibescanConfig, filePath: string, includeTests: boolean): Finding | null {
  if (includeTests || !config.testPatterns || config.testPatterns.length === 0 || !config.testOverrides) {
    return finding;
  }
  
  const isTest = picomatch.isMatch(filePath.replace(/\\/g, '/'), config.testPatterns, { dot: true });
  if (!isTest) return finding;

  const override = config.testOverrides[finding.ruleId];
  if (!override) return finding;
  if (override === 'off') return null;

  return { ...finding, severity: override };
}

export function applyIgnoreComments(findings: Finding[], source: string): Finding[] {
  const lines = source.split('\n');
  return findings.filter((f) => {
    const lineIdx = f.line - 1;
    const sameLine = lines[lineIdx] ?? '';
    const sameLineMatch = sameLine.match(/\/\/\s*aicop-ignore(?:\s+(\S+))?/);
    if (sameLineMatch) {
      const specifiedRule = sameLineMatch[1];
      if (specifiedRule === f.ruleId) return false;
      if (!specifiedRule && !f.ruleId.startsWith('security/')) return false;
    }
    const prevLine = lineIdx > 0 ? (lines[lineIdx - 1] ?? '').trim() : '';
    const prevLineMatch = prevLine.match(/^\/\/\s*aicop-ignore(?:\s+(\S+))?/);
    if (prevLineMatch) {
      const specifiedRule = prevLineMatch[1];
      if (specifiedRule === f.ruleId) return false;
      if (!specifiedRule && !f.ruleId.startsWith('security/')) return false;
    }
    return true;
  });
}

export function applyConfigSeverity(finding: Finding, config: VibescanConfig): Finding {
  const configured = config.rules[finding.ruleId];
  if (!configured || configured === 'off') return finding;
  const SEV_ORDER: Record<string, number> = { error: 0, warn: 1, info: 2 };
  const SEV_BY_ORDER = ['error', 'warn', 'info'] as const;
  const configLevel = SEV_ORDER[configured] ?? 1;
  const findingLevel = SEV_ORDER[finding.severity] ?? 1;
  const finalLevel = Math.min(configLevel, findingLevel);
  return { ...finding, severity: SEV_BY_ORDER[finalLevel] ?? finding.severity };
}

export function meetsMinSeverity(finding: Finding, minSeverity: Severity): boolean {
  const order: Record<Severity, number> = { error: 0, warn: 1, info: 2 };
  return order[finding.severity] <= order[minSeverity];
}

export function isImportWarn(finding: Finding): boolean {
  if (finding.severity !== 'warn') return false;
  if (finding.ruleId === 'security/xxe-injection') {
    return finding.message.includes('XML parser can be vulnerable');
  }
  if (finding.ruleId === 'security/insecure-deserialization') {
    return finding.message.includes('can deserialize executable code');
  }
  return false;
}

export function suppressImportWarnings(findings: Finding[]): Finding[] {
  const concreteRules = new Set(
    findings
      .filter((finding) => finding.severity === 'error')
      .filter((finding) => finding.ruleId === 'security/xxe-injection' || finding.ruleId === 'security/insecure-deserialization')
      .map((finding) => finding.ruleId),
  );
  if (concreteRules.size === 0) return findings;
  return findings.filter((finding) => !concreteRules.has(finding.ruleId) || !isImportWarn(finding));
}

export function scanFile(
  filePath: string,
  basePath: string,
  rules: Rule[],
  config: VibescanConfig,
  minSeverity: Severity,
  noAiScore: boolean,
  preloadedSource?: string,
  preloadedAst?: TSESTree.Program,
  includeTests?: boolean,
): FileScanResult {
  const relativePath = getRelativePath(filePath, basePath);
  let source = '';
  try {
    source = preloadedSource ?? readFileContent(filePath);
  } catch (err) {
    logger.warn(`Could not read file ${relativePath}: ${String(err)}`);
    return { filePath, relativePath, findings: [], aiScore: 0, parseError: String(err) };
  }

  let ast = preloadedAst;
  if (!ast) {
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
  }

  const rawFindings: Finding[] = [];

  for (const rule of rules) {
    try {
      const result = rule.check(ast, source, filePath);
      if (result && Array.isArray(result)) {
        rawFindings.push(...result);
      } else if (result) {
        rawFindings.push(result as Finding);
      }
    } catch (err) {
      logger.debug(`Rule ${rule.id} failed on ${relativePath}: ${String(err)}`);
    }
  }

  const contextFindings = runContextAnalysis(source, filePath);
  rawFindings.push(...contextFindings);

  const findings = applyIgnoreComments(suppressImportWarnings(rawFindings), source)
    .map((f) => applyConfigSeverity(f, config))
    .map((f) => applyTestOverrides(f, config, filePath, includeTests ?? false))
    .filter((f): f is Finding => f !== null)
    .filter((f) => meetsMinSeverity(f, minSeverity))
    .sort((a, b) => {
      const order = { error: 0, warn: 1, info: 2 };
      const sevDiff = order[a.severity] - order[b.severity];
      return sevDiff !== 0 ? sevDiff : a.line - b.line;
    });

  const aiScore = noAiScore ? 0 : computeAiScore(findings);
  return { filePath, relativePath, findings, aiScore };
}

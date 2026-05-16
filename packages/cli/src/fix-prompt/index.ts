import path from 'path';
import { ScanResult, Finding, Severity } from '../scanner/rules/types.js';
import { getRuleById } from '../scanner/rules/index.js';

export interface FixPromptOptions {
  minSeverity: 'error' | 'warn' | 'info';
  includeSnippets: boolean;
  targetPath?: string;
}

const SEVERITY_ORDER: Record<Severity, number> = { error: 0, warn: 1, info: 2 };

function severityAboveOrEqual(finding: Finding, min: Severity): boolean {
  return SEVERITY_ORDER[finding.severity] <= SEVERITY_ORDER[min];
}

function displayPath(filePath: string, targetPath?: string): string {
  if (!targetPath) return filePath;
  try {
    const rel = path.relative(targetPath, filePath);
    return rel.length < filePath.length ? rel : filePath;
  } catch {
    return filePath;
  }
}

function groupBySeverityThenRule(findings: Finding[], minSeverity: Severity): Map<Severity, Map<string, Finding[]>> {
  const bySeverity = new Map<Severity, Map<string, Finding[]>>();

  for (const finding of findings) {
    if (!severityAboveOrEqual(finding, minSeverity)) continue;
    const ruleMap = bySeverity.get(finding.severity) ?? new Map<string, Finding[]>();
    const ruleFindings = ruleMap.get(finding.ruleId) ?? [];
    ruleFindings.push(finding);
    ruleMap.set(finding.ruleId, ruleFindings);
    bySeverity.set(finding.severity, ruleMap);
  }

  for (const ruleMap of bySeverity.values()) {
    for (const [ruleId, ruleFindings] of ruleMap) {
      ruleMap.set(ruleId, ruleFindings.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line));
    }
  }

  return bySeverity;
}

function renderSectionHeader(severity: Severity, count: number): string {
  if (severity === 'error') return `CRITICAL ERRORS — ${count} issues`;
  if (severity === 'warn') return `WARNINGS — ${count} issues`;
  return `INFO — ${count} issues`;
}

function summarizeFinding(finding: Finding): string {
  const compact = finding.message.replace(/\s+/g, ' ').trim();
  return compact.length > 90 ? `${compact.slice(0, 87)}...` : compact;
}

function strategyForRule(ruleId: string, findings: Finding[]): string {
  const rule = getRuleById(ruleId);
  if (ruleId === 'security/weak-crypto') {
    return 'Use bcrypt for passwords, crypto.randomBytes() for tokens.';
  }
  const findingFixCode = findings.find((finding) => finding.fixCode)?.fixCode;
  if (findingFixCode) return findingFixCode;
  if (rule?.fixCode) return rule.fixCode;
  const findingFix = findings.find((finding) => finding.fix)?.fix;
  return findingFix ?? rule?.fix ?? 'Apply the safest minimal fix for this rule.';
}

function estimateComplexity(total: number): string {
  if (total <= 5) return 'Low';
  if (total <= 15) return 'Medium';
  if (total <= 30) return 'High';
  return 'Very High';
}

export function generateFixPrompt(scanResult: ScanResult, options: FixPromptOptions): string {
  const { minSeverity = 'warn', targetPath } = options;
  const allFindings = scanResult.files.flatMap((file) => file.findings);
  const filtered = allFindings.filter((finding) => severityAboveOrEqual(finding, minSeverity));

  if (filtered.length === 0) {
    return [
      'No issues found.',
      '',
      `VibeCop scanned ${scanResult.filesScanned} file${scanResult.filesScanned !== 1 ? 's' : ''}.`,
      `VibeScore: ${scanResult.vibeScore}/100`,
    ].join('\n');
  }

  const bySeverity = groupBySeverityThenRule(filtered, minSeverity);
  const affectedFiles = new Set(filtered.map((finding) => finding.file)).size;
  const errorCount = filtered.filter((finding) => finding.severity === 'error').length;
  const warnCount = filtered.filter((finding) => finding.severity === 'warn').length;
  const lines: string[] = [
    'Please fix the following VibeCop findings.',
    'Only change the listed files and preserve behavior.',
    '',
  ];
  const severityOrder: Severity[] = ['error', 'warn', 'info'];

  for (const severity of severityOrder) {
    const ruleMap = bySeverity.get(severity);
    if (!ruleMap || ruleMap.size === 0) continue;
    const total = [...ruleMap.values()].reduce((sum, findings) => sum + findings.length, 0);
    lines.push(renderSectionHeader(severity, total));
    lines.push('');

    for (const [ruleId, findings] of ruleMap) {
      lines.push(`[${ruleId}] — ${findings.length} occurrence${findings.length !== 1 ? 's' : ''}`);
      lines.push(`Fix strategy: ${strategyForRule(ruleId, findings)}`);
      lines.push('');

      for (const finding of findings) {
        lines.push(`  → ${displayPath(finding.file, targetPath)} line ${finding.line} — ${summarizeFinding(finding)}`);
      }

      lines.push('');
    }
  }

  lines.push('OVERVIEW');
  lines.push(`Total issues: ${filtered.length}`);
  lines.push(`Files affected: ${affectedFiles}`);
  if (errorCount > 0) lines.push(`Critical errors: ${errorCount}`);
  if (warnCount > 0) lines.push(`Warnings: ${warnCount}`);
  lines.push(`Estimated complexity: ${estimateComplexity(filtered.length)}`);
  lines.push('Run "vibecop scan ." after applying fixes.');

  return lines.join('\n');
}

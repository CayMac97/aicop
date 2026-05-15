import path from 'path';
import { ScanResult, Finding, Severity } from '../scanner/rules/types.js';
import { getRuleById } from '../scanner/rules/index.js';

export interface FixPromptOptions {
  /** Minimum severity to include in the prompt */
  minSeverity: 'error' | 'warn' | 'info';
  /** Whether to include code snippets from the scan results */
  includeSnippets: boolean;
  /** Target path used in the scan (for relative path display) */
  targetPath?: string;
}

const SEVERITY_ORDER: Record<Severity, number> = { error: 0, warn: 1, info: 2 };

function severityAboveOrEqual(finding: Finding, min: Severity): boolean {
  return SEVERITY_ORDER[finding.severity] <= SEVERITY_ORDER[min];
}

function groupBySeverityThenFile(
  findings: Finding[],
  minSeverity: Severity,
): Map<Severity, Map<string, Finding[]>> {
  const bySev = new Map<Severity, Map<string, Finding[]>>();

  for (const f of findings) {
    if (!severityAboveOrEqual(f, minSeverity)) continue;
    if (!bySev.has(f.severity)) bySev.set(f.severity, new Map());
    const byFile = bySev.get(f.severity)!;
    if (!byFile.has(f.file)) byFile.set(f.file, []);
    byFile.get(f.file)!.push(f);
  }

  // Sort findings within each file by line number
  for (const byFile of bySev.values()) {
    for (const [filePath, fileFindigs] of byFile) {
      byFile.set(filePath, fileFindigs.sort((a, b) => a.line - b.line));
    }
  }

  return bySev;
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

function renderFindingBlock(finding: Finding, includeSnippets: boolean): string {
  const rule = getRuleById(finding.ruleId);
  const lines: string[] = [];

  lines.push(`Line ${finding.line} | [${finding.ruleId}]`);
  lines.push(`Issue:   ${finding.message}`);

  if (includeSnippets && finding.snippet?.trim()) {
    lines.push(`Current code:`);
    lines.push(`  ${finding.snippet.trim()}`);
  }

  // Prefer rule-level fixCode, fall back to finding-level fix, then rule fix
  const fixCode = rule?.fixCode;
  const fixDesc = finding.fix ?? rule?.fix;

  if (fixCode) {
    lines.push(`Fix:`);
    fixCode.split('\n').forEach((l) => lines.push(`  ${l}`));
  } else if (fixDesc) {
    lines.push(`Fix:     ${fixDesc}`);
  }

  if (rule?.why) {
    lines.push(`Reason:  ${rule.why}`);
  }

  return lines.join('\n');
}

function renderSectionHeader(severity: Severity, count: number): string {
  const divider = '='.repeat(60);
  if (severity === 'error') {
    return `\n${divider}\n=== CRITICAL ERRORS (fix these first) — ${count} issue${count !== 1 ? 's' : ''} ===\n${divider}`;
  }
  if (severity === 'warn') {
    return `\n${divider}\n=== WARNINGS (fix after errors) — ${count} issue${count !== 1 ? 's' : ''} ===\n${divider}`;
  }
  return `\n${divider}\n=== INFO (consider fixing) — ${count} issue${count !== 1 ? 's' : ''} ===\n${divider}`;
}

function estimateComplexity(total: number): string {
  if (total <= 5) return 'Low (30–60 minutes)';
  if (total <= 15) return 'Medium (1–2 hours)';
  if (total <= 30) return 'High (2–4 hours)';
  return 'Very High (may require refactoring)';
}

/**
 * Generate an AI-ready fix prompt from a scan result.
 */
export function generateFixPrompt(
  scanResult: ScanResult,
  options: FixPromptOptions,
): string {
  const { minSeverity = 'warn', includeSnippets = true, targetPath } = options;

  // Flatten all findings from all files
  const allFindings: Finding[] = scanResult.files.flatMap((f) => f.findings);
  const filtered = allFindings.filter((f) => severityAboveOrEqual(f, minSeverity));

  if (filtered.length === 0) {
    return [
      '✅ No issues found — your code is clean!',
      '',
      `VibeCop scanned ${scanResult.filesScanned} file${scanResult.filesScanned !== 1 ? 's' : ''} and found no issues matching the requested severity.`,
      `VibeScore: ${scanResult.vibeScore}/100`,
    ].join('\n');
  }

  const bySev = groupBySeverityThenFile(filtered, minSeverity);
  const affectedFiles = new Set(filtered.map((f) => f.file)).size;
  const errorCount = filtered.filter((f) => f.severity === 'error').length;
  const warnCount = filtered.filter((f) => f.severity === 'warn').length;

  const lines: string[] = [];

  // Header
  lines.push('Please fix the following issues found by VibeCop in my codebase.');
  lines.push('Fix all issues in the exact files and lines mentioned.');
  lines.push('Do not change anything that is not listed here.');
  lines.push('Preserve all existing functionality.');
  lines.push('');

  const severityOrder: Severity[] = ['error', 'warn', 'info'];

  for (const sev of severityOrder) {
    const byFile = bySev.get(sev);
    if (!byFile || byFile.size === 0) continue;

    const sevTotal = [...byFile.values()].reduce((acc, arr) => acc + arr.length, 0);
    lines.push(renderSectionHeader(sev, sevTotal));

    for (const [filePath, findings] of byFile) {
      lines.push('');
      lines.push(`FILE: ${displayPath(filePath, targetPath)}`);
      lines.push('─'.repeat(50));

      for (const finding of findings) {
        lines.push('');
        lines.push(renderFindingBlock(finding, includeSnippets));
      }
    }
  }

  // Overview footer
  lines.push('');
  lines.push('='.repeat(60));
  lines.push('=== OVERVIEW ===');
  lines.push('='.repeat(60));
  lines.push(`Total issues to fix: ${filtered.length}`);
  lines.push(`Files affected:      ${affectedFiles}`);
  if (errorCount > 0) lines.push(`Critical errors:     ${errorCount}`);
  if (warnCount > 0) lines.push(`Warnings:            ${warnCount}`);
  lines.push(`Estimated complexity: ${estimateComplexity(filtered.length)}`);
  lines.push('');
  lines.push('After applying all fixes above, run "vibecop scan ." again to verify.');
  const rawTarget = Math.min(100, scanResult.vibeScore + Math.round(filtered.length * 2.5));
  const targetScoreStr = rawTarget >= 100 ? '100' : `${rawTarget}+`;
  lines.push(`Expected result: 0 Errors, VibeScore ${targetScoreStr}/100`);

  return lines.join('\n');
}

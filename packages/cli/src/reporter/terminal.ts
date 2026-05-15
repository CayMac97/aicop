import chalk from 'chalk';
import { ScanResult, FileScanResult, Finding, Severity } from '../scanner/rules/types.js';
import { getScoreEmoji } from '../scanner/rules/ai-smells/ai-confidence-scorer.js';

const SEVERITY_ICON: Record<Severity, string> = {
  error: '✗',
  warn: '⚠',
  info: 'ℹ',
};

const SEVERITY_COLOR: Record<Severity, (s: string) => string> = {
  error: chalk.red,
  warn: chalk.yellow,
  info: chalk.blue,
};

const SEVERITY_LABEL: Record<Severity, string> = {
  error: 'ERROR',
  warn: 'WARN ',
  info: 'INFO ',
};

function formatSeverityPrefix(severity: Severity): string {
  const icon = SEVERITY_ICON[severity];
  const label = SEVERITY_LABEL[severity];
  return SEVERITY_COLOR[severity](`${icon} ${label}`);
}

function formatFileHeader(file: FileScanResult, ci: boolean): string {
  const fileLine = `── ${file.relativePath} `;
  const scoreLabel = `AI Score: ${file.aiScore}/100 ${getScoreEmoji(file.aiScore)}`;
  if (ci) return `${fileLine}${scoreLabel}`;
  return chalk.bold.white(fileLine) + chalk.gray('─'.repeat(Math.max(0, 60 - fileLine.length))) + ' ' + scoreLabel;
}

function formatFinding(finding: Finding, ci: boolean): string {
  const lines: string[] = [];
  const prefix = ci ? `[${finding.severity.toUpperCase()}]` : formatSeverityPrefix(finding.severity);
  lines.push(`${prefix}  [${finding.ruleId}]  line ${finding.line}`);

  const snippetLines = finding.snippet.split('\n');
  for (const sl of snippetLines) {
    const formatted = ci ? `| ${sl}` : chalk.dim(`│  ${sl}`);
    lines.push(formatted);
  }
  lines.push(ci ? `| ^ ${finding.message}` : chalk.dim(`│  ^ `) + finding.message);

  if (finding.fix) {
    const fixLabel = ci ? 'FIX:' : chalk.bold.green('FIX:');
    lines.push(ci ? `| ${fixLabel} ${finding.fix}` : chalk.dim('│  ') + fixLabel + ' ' + finding.fix);
  }

  lines.push(ci ? '' : chalk.dim('│'));
  return lines.join('\n');
}

function formatFileSectionHeader(file: FileScanResult, ci: boolean): string {
  return formatFileHeader(file, ci);
}

function renderFileSeparator(ci: boolean): string {
  if (ci) return '';
  return chalk.gray('─'.repeat(72));
}

export function formatBySeverity(result: ScanResult, severity: Severity, ci: boolean): string {
  const sections: string[] = [];

  for (const file of result.files) {
    const findings = file.findings.filter((f) => f.severity === severity);
    if (findings.length === 0) continue;

    sections.push(formatFileSectionHeader(file, ci));
    for (const finding of findings) {
      sections.push(formatFinding(finding, ci));
    }
    sections.push('');
  }

  if (sections.length === 0) {
    return chalk.dim(`  No ${severity} findings.\n`);
  }

  const separator = renderFileSeparator(ci);
  if (separator) sections.push(separator);
  return sections.join('\n');
}

export function formatTerminal(result: ScanResult, ci: boolean): string {
  const sections: string[] = [];
  const separator = renderFileSeparator(ci);

  for (const file of result.files) {
    if (file.findings.length === 0 && !file.parseError) continue;
    sections.push(formatFileSectionHeader(file, ci));

    if (file.parseError) {
      const msg = ci ? `[WARN] Could not parse file: ${file.parseError}` : chalk.yellow(`⚠ Could not parse: ${file.parseError}`);
      sections.push(msg);
      sections.push('');
      continue;
    }

    for (const finding of file.findings) {
      sections.push(formatFinding(finding, ci));
    }
    sections.push('');
  }

  if (separator) sections.push(separator);
  return sections.join('\n');
}

import chalk from 'chalk';
import boxen from 'boxen';
import fs from 'fs';
import path from 'path';
import { ScanResult } from '../scanner/rules/types.js';


const BASELINE_FILE = '.aicop-baseline.json';

export interface BaselineData {
  vibeScore: number;
  errorCount: number;
  warnCount: number;
  filesScanned: number;
  date: string;
}

export function readBaseline(cwd: string): BaselineData | null {
  try {
    const raw = fs.readFileSync(path.join(cwd, BASELINE_FILE), 'utf-8');
    return JSON.parse(raw) as BaselineData;
  } catch {
    return null;
  }
}

export function writeBaseline(cwd: string, result: ScanResult): void {
  const data: BaselineData = {
    vibeScore: result.vibeScore,
    errorCount: result.errorCount,
    warnCount: result.warnCount,
    filesScanned: result.filesScanned,
    date: new Date().toISOString().slice(0, 10),
  };
  fs.writeFileSync(path.join(cwd, BASELINE_FILE), JSON.stringify(data, null, 2));
}

function formatScoreDelta(current: number, baseline: number): string {
  const delta = current - baseline;
  if (delta === 0) return chalk.dim('  (no change from baseline)');
  if (delta < 0) return chalk.green(`  ↓ ${Math.abs(delta)} pts better than baseline (was ${baseline})`);
  return chalk.red(`  ↑ ${delta} pts worse than baseline (was ${baseline})`);
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function vibeScoreLabel(score: number): string {
  if (score >= 85) return 'Production ready';
  if (score >= 65) return 'Mostly clean';
  if (score >= 40) return 'Needs attention';
  if (score >= 15) return 'Heavy AI-smell';
  return 'Needs rewrite';
}

function vibeScoreEmoji(score: number): string {
  if (score >= 85) return '🟢';
  if (score >= 65) return '🟡';
  if (score >= 40) return '🟠';
  return '🔴';
}

function scoreColor(score: number): (s: string) => string {
  if (score >= 80) return chalk.green;
  if (score >= 60) return chalk.yellow;
  if (score >= 40) return chalk.hex('#FFA500');
  return chalk.red;
}

function buildSummaryContent(result: ScanResult): string {
  const lines: string[] = [];
  const pad = (label: string, value: string, width = 28): string =>
    `   ${label.padEnd(width)}${value}`;

  lines.push('');
  lines.push(pad('Files scanned:', `${result.filesScanned}`) + `      Time: ${formatDuration(result.scanDurationMs)}`);
  lines.push(pad('Files with issues:', `${result.filesWithIssues}`));
  lines.push('');

  const errLine = `   🔴 Errors:   ${String(result.errorCount).padStart(4)}   ${chalk.red('(must fix before production)')}`;
  const warnLine = `   🟡 Warnings: ${String(result.warnCount).padStart(4)}   ${chalk.yellow('(should fix)')}`;
  const infoLine = `   🔵 Info:     ${String(result.infoCount).padStart(4)}   ${chalk.blue('(consider fixing)')}`;

  lines.push(errLine);
  lines.push(warnLine);
  lines.push(infoLine);
  if (result.parseErrors > 0) {
    lines.push(`   ⚠  Parse errors: ${result.parseErrors} ${result.parseErrors === 1 ? 'file' : 'files'} could not be parsed (excluded from score)`);
  }
  lines.push('');

  if (result.categoryScores) {
    const cs = result.categoryScores;
    lines.push(pad('Security Score:', `${scoreColor(cs.security)(`${cs.security}/100`)}`));
    lines.push(pad('AI-Smell Score:', `${scoreColor(cs.aiSmell)(`${cs.aiSmell}/100`)}`));
    lines.push(pad('Tech-Debt Score:', `${scoreColor(cs.techDebt)(`${cs.techDebt}/100`)}`));
    lines.push('   ' + chalk.dim('─'.repeat(32)));
  }

  const score = result.vibeScore;
  const label = vibeScoreLabel(score);
  const emoji = vibeScoreEmoji(score);
  const colorFn = scoreColor(score);
  lines.push(`   Overall AIScore™: ${colorFn(`${score}/100`)}  ${emoji}  "${label}"`);

  const baseline = readBaseline(process.cwd());
  if (baseline) {
    lines.push(formatScoreDelta(score, baseline.vibeScore));
  }
  lines.push('');

  if (result.topIssues.length > 0) {
    lines.push('   Top issues:');
    result.topIssues.slice(0, 5).forEach((issue, i) => {
      lines.push(`   ${i + 1}. ${issue.ruleId} (${issue.fileCount} ${issue.fileCount === 1 ? 'file' : 'files'})`);
    });
    lines.push('');
  }

  if (result.skippedVendorFiles > 0) {
    lines.push(chalk.blue(`   ℹ  ${result.skippedVendorFiles} vendor/library ${result.skippedVendorFiles === 1 ? 'file' : 'files'} skipped  —  run with --include-vendor to scan them`));
  }
  lines.push('   ' + chalk.dim('Run aicop scan --format html for a visual report  ·  aicop baseline to save this score'));
  return lines.join('\n');
}

function buildCiSummary(result: ScanResult): string {
  const lines: string[] = [
    '',
    '=== SCAN COMPLETE ===',
    `Files scanned: ${result.filesScanned}  Time: ${formatDuration(result.scanDurationMs)}`,
    `Files with issues: ${result.filesWithIssues}`,
    `Errors: ${result.errorCount}  Warnings: ${result.warnCount}  Info: ${result.infoCount}${result.parseErrors > 0 ? `  Parse errors: ${result.parseErrors}` : ''}`,
    `AIScore: ${result.vibeScore}/100 (${vibeScoreLabel(result.vibeScore)})`,
    ...(result.categoryScores ? [
      `Security Score: ${result.categoryScores.security}/100`,
      `AI-Smell Score: ${result.categoryScores.aiSmell}/100`,
      `Tech-Debt Score: ${result.categoryScores.techDebt}/100`,
    ] : []),
  ];
  if (result.topIssues.length > 0) {
    lines.push('Top issues:');
    result.topIssues.forEach((issue, i) => {
      lines.push(`  ${i + 1}. ${issue.ruleId} (${issue.fileCount} ${issue.fileCount === 1 ? 'file' : 'files'})`);
    });
  }
  if (result.skippedVendorFiles > 0) {
    lines.push(`Vendor files skipped: ${result.skippedVendorFiles} (use --include-vendor to scan them)`);
  }
  return lines.join('\n');
}

export function renderSummary(result: ScanResult, ci: boolean): string {
  if (ci) return buildCiSummary(result);

  const content = buildSummaryContent(result);
  return boxen(content, {
    title: chalk.bold(' SCAN COMPLETE '),
    titleAlignment: 'center',
    padding: 0,
    margin: { top: 1, bottom: 1, left: 0, right: 0 },
    borderStyle: 'round',
    borderColor: 'gray',
    width: 72,
  });
}

export function renderHeader(fileCount: number, ruleCount: number, version: string, ci: boolean): string {
  if (ci) return `=== AICop v${version} | Files: ${fileCount} | Rules: ${ruleCount} ===`;
  const content = ` AICop v${version}  •  ${ruleCount} rules active `;
  return boxen(content, {
    padding: 0,
    margin: { top: 1, bottom: 1, left: 0, right: 0 },
    borderStyle: 'round',
    borderColor: 'gray',
  });
}

export function renderFixPromptHint(targetArg: string): string {
  const t = targetArg === '.' || targetArg === '' ? '.' : path.basename(targetArg);
  const content =
    chalk.bold('💡 Run ') +
    chalk.cyan.bold(`aicop fix-prompt ${t}`) +
    chalk.bold(' to generate an AI') + '\n' +
    '   prompt that fixes all issues automatically';
  return boxen(content, {
    padding: { top: 0, bottom: 0, left: 1, right: 1 },
    margin: { top: 0, bottom: 1, left: 0, right: 0 },
    borderStyle: 'round',
    borderColor: 'cyan',
    width: 72,
  });
}

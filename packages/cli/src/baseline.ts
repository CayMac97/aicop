import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import { ScanResult } from './scanner/rules/types.js';

const BASELINE_FILE = '.aicop-baseline.json';

export interface BaselineData {
  version: string;
  savedAt: string;
  aiScore: number;
  errorCount: number;
  warnCount: number;
  infoCount: number;
  filesScanned: number;
}

export function getBaselinePath(cwd: string = process.cwd()): string {
  return path.join(cwd, BASELINE_FILE);
}

export function loadBaseline(cwd: string = process.cwd()): BaselineData | null {
  const p = getBaselinePath(cwd);
  try {
    const raw = fs.readFileSync(p, 'utf8');
    return JSON.parse(raw) as BaselineData;
  } catch {
    return null;
  }
}

export function saveBaseline(result: ScanResult, version: string, cwd: string = process.cwd()): void {
  const data: BaselineData = {
    version,
    savedAt: new Date().toISOString(),
    aiScore: result.aiScore,
    errorCount: result.errorCount,
    warnCount: result.warnCount,
    infoCount: result.infoCount,
    filesScanned: result.filesScanned,
  };
  fs.writeFileSync(getBaselinePath(cwd), JSON.stringify(data, null, 2), 'utf8');
}

export function clearBaseline(cwd: string = process.cwd()): boolean {
  const p = getBaselinePath(cwd);
  try {
    fs.unlinkSync(p);
    return true;
  } catch {
    return false;
  }
}

export function formatBaselineDelta(current: number, baseline: BaselineData): string {
  const delta = current - baseline.aiScore;
  const savedDate = new Date(baseline.savedAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });

  if (delta === 0) {
    return chalk.dim(`   Baseline: no change (${baseline.aiScore}/100 on ${savedDate})`);
  }
  if (delta < 0) {
    // Score went down = improvement
    return chalk.green(`   Baseline: ↓ ${Math.abs(delta)} pts better than baseline (was ${baseline.aiScore}/100 on ${savedDate})`);
  }
  // Score went up = regression
  return chalk.red(`   Baseline: ↑ +${delta} pts worse than baseline (was ${baseline.aiScore}/100 on ${savedDate})`);
}

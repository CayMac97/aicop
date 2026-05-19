/**
 * CLI helper utilities extracted from index.ts to keep the entry point focused.
 * Contains: clipboard, interactive grouped output, watch mode.
 */
import chalk from 'chalk';
import path from 'path';
import { createInterface } from 'readline';
import { formatBySeverity } from './reporter/terminal.js';
import { report } from './reporter/index.js';
import { Severity, ScanResult, ScanOptions, VibescanConfig } from './scanner/rules/types.js';
import { generateFixPrompt } from './fix-prompt/index.js';

function openHtmlReport(result: ScanResult, version: string, onDone: () => void): void {
  const htmlPath = path.resolve('.aicop/report.html');
  process.stdout.write(chalk.dim('\n  Generating HTML report\u2026\n'));
  report(result, { format: 'html', ci: false, outputPath: htmlPath, version })
    .then(() => {
      const { exec } = require('child_process') as typeof import('child_process');
      const openCmd = process.platform === 'win32'
        ? `start "" "${htmlPath}"`
        : process.platform === 'darwin'
          ? `open "${htmlPath}"`
          : `xdg-open "${htmlPath}"`;
      exec(openCmd);
      process.stdout.write(chalk.green('  \u2713 Ge\u00f6ffnet im Browser\n\n'));
      onDone();
    })
    .catch(() => {
      process.stdout.write(chalk.red('  \u2717 HTML-Report konnte nicht erstellt werden\n\n'));
      onDone();
    });
}

/**
 * Copy text to the system clipboard using platform-native commands.
 * Windows → clip | macOS → pbcopy | Linux → xclip or xsel
 */
export function copyToClipboard(text: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const { exec } = require('child_process') as typeof import('child_process');
    let cmd: string;
    if (process.platform === 'win32') {
      cmd = 'clip';
    } else if (process.platform === 'darwin') {
      cmd = 'pbcopy';
    } else {
      cmd = 'xclip -selection clipboard || xsel --clipboard --input';
    }
    const proc = exec(cmd, (err) => {
      if (err) reject(new Error(`Clipboard copy failed: ${err.message}`));
      else resolve();
    });
    proc.stdin?.write(text, 'utf-8');
    proc.stdin?.end();
  });
}

interface GroupEntry {
  key: string;
  label: string;
  sev: Severity;
  count: number;
  colorFn: (s: string) => string;
}

export function showInteractiveGroups(result: ScanResult, targetPath?: string, version?: string): Promise<void> {
  const groups: GroupEntry[] = [
    { key: 'e', label: 'Errors',   sev: 'error', count: result.errorCount, colorFn: chalk.red },
    { key: 'w', label: 'Warnings', sev: 'warn',  count: result.warnCount,  colorFn: chalk.yellow },
    { key: 'i', label: 'Info',     sev: 'info',  count: result.infoCount,  colorFn: chalk.blue },
  ];

  process.stdout.write('\n');
  for (const g of groups) {
    if (g.count > 0) {
      process.stdout.write(`  ${g.colorFn('●')} ${g.label.padEnd(10)} ${g.colorFn(`(${g.count})`)}${chalk.dim(` — press ${g.key.toUpperCase()} to expand`)}\n`);
    } else {
      process.stdout.write(`  ${chalk.green('✓')} ${g.label.padEnd(10)} ${chalk.dim('(0) — clean')}\n`);
    }
  }

  const hasAny = result.errorCount > 0 || result.warnCount > 0 || result.infoCount > 0;
  if (hasAny) {
    process.stdout.write(`  ${chalk.magenta('✦')} ${'Fix Prompt'.padEnd(10)} ${chalk.dim('— press P to generate AI prompt')}\n`);
  }
  process.stdout.write(`  ${chalk.cyan('◉')} ${'HTML Report'.padEnd(10)} ${chalk.dim('— press H to open in browser')}\n`);

  process.stdout.write('\n');

  const prompt = hasAny
    ? chalk.dim('  [E]rrors  [W]arnings  [I]nfo  [P]rompt  [H]tml  [Q]uit  › ')
    : chalk.dim('  [H]tml  [Q]uit  › ');

  return new Promise<void>((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    rl.on('SIGINT', () => { process.stdout.write('\n'); rl.close(); });

    const ask = (): void => {
      rl.question(prompt, (raw) => {
        const key = raw.trim().toLowerCase();
        const group = groups.find((g) => g.key === key);
        if (group) {
          process.stdout.write('\n' + formatBySeverity(result, group.sev, false) + '\n');
          ask();
        } else if (key === 'p') {
          const prompt = generateFixPrompt(result, {
            minSeverity: 'warn',
            includeSnippets: true,
            targetPath,
          });
          process.stdout.write('\n' + prompt + '\n');
          ask();
        } else if (key === 'h') {
          openHtmlReport(result, version ?? '1.0.0', ask);
        } else {
          rl.close();
        }
      });
    };

    ask();
    rl.on('close', resolve);
  });
}

export async function runWatch(
  targetPath: string,
  runScan: (t: string, o: unknown) => Promise<void>,
  opts: unknown,
): Promise<void> {
  try {
    const chokidar = await import('chokidar');
    process.stdout.write(chalk.cyan(`👁  Watching ${targetPath} for changes…\n`));
    await runScan(targetPath, opts);
    chokidar.default
      .watch(targetPath, { ignored: /node_modules|dist|build/, persistent: true, ignoreInitial: true })
      .on('change', async (changedPath) => {
        process.stdout.write(chalk.dim(`\n↩  ${path.relative(process.cwd(), changedPath)} changed — re-scanning…\n`));
        await runScan(targetPath, opts);
      });
  } catch (err) {
    process.stderr.write(`Watch mode error: ${String(err)}\n`);
    process.exit(1);
  }
}

export interface CliOptions {
  fix?: boolean;
  watch?: boolean;
  ci?: boolean;
  format: string;
  output?: string;
  severity: string;
  ignore?: string[];
  aiScore?: boolean;
  rule?: string[];
  config?: string;
  debug?: boolean;
  includeVendor?: boolean;
  includeExamples?: boolean;
}

export function buildScanOptions(targetPath: string, config: VibescanConfig, opts: CliOptions, minSeverity: Severity): ScanOptions {
  return {
    path: targetPath,
    config,
    severity: minSeverity,
    format: (opts.format as ScanOptions['format']) ?? 'terminal',
    output: opts.output,
    ci: Boolean(opts.ci),
    fix: Boolean(opts.fix),
    noAiScore: opts.aiScore === false,
    watch: Boolean(opts.watch),
    ruleId: opts.rule?.[0],
    ignore: opts.ignore,
    includeVendor: Boolean(opts.includeVendor),
    includeExamples: Boolean(opts.includeExamples),
  };
}

export function buildDisplayResult(result: ScanResult, displaySeverity: Severity): { displayResult: ScanResult; hiddenInfoCount: number } {
  const sevOrder: Record<Severity, number> = { error: 0, warn: 1, info: 2 };
  const maxSev = sevOrder[displaySeverity];
  // hiddenInfoCount drives the hint "run with --severity info to see per-file locations"
  const hiddenInfoCount = maxSev < sevOrder['info'] ? result.infoCount : 0;
  const needsFiltering = hiddenInfoCount > 0 || (maxSev < sevOrder['warn'] && result.warnCount > 0);
  if (!needsFiltering) return { displayResult: result, hiddenInfoCount: 0 };
  const displayResult: ScanResult = {
    ...result,
    files: result.files.map((f) => ({
      ...f,
      findings: f.findings.filter((x) => sevOrder[x.severity] <= maxSev),
    })),
    warnCount: maxSev >= sevOrder['warn'] ? result.warnCount : 0,
    infoCount: maxSev >= sevOrder['info'] ? result.infoCount : 0,
  };
  return { displayResult, hiddenInfoCount };
}

export function isInteractiveSession(opts: CliOptions, ci: boolean): boolean {
  return (opts.format ?? 'terminal') === 'terminal' && !ci && process.stdout.isTTY && process.stdin.isTTY;
}

export function shouldShowFixPromptHint(result: ScanResult, opts: CliOptions, ci: boolean): boolean {
  return !ci
    && !opts.output
    && (result.errorCount > 0 || result.warnCount > 0)
    && (opts.format ?? 'terminal') === 'terminal';
}

/**
 * CLI helper utilities extracted from index.ts to keep the entry point focused.
 * Contains: clipboard, interactive grouped output, watch mode.
 */
import chalk from 'chalk';
import path from 'path';
import { createInterface } from 'readline';
import { formatBySeverity } from './reporter/terminal.js';
import { Severity, ScanResult } from './scanner/rules/types.js';
import { generateFixPrompt } from './fix-prompt/index.js';

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

export function showInteractiveGroups(result: ScanResult, targetPath?: string): Promise<void> {
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

  if (!hasAny) { process.stdout.write('\n'); return Promise.resolve(); }

  process.stdout.write('\n');

  return new Promise<void>((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    rl.on('SIGINT', () => { process.stdout.write('\n'); rl.close(); });

    const ask = (): void => {
      rl.question(chalk.dim('  [E]rrors  [W]arnings  [I]nfo  [P]rompt  [Q]uit  › '), (raw) => {
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

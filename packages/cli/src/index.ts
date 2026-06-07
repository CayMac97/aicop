import { isMainThread, parentPort, workerData } from 'node:worker_threads';
if (!isMainThread && parentPort) {
  const { scanFile, getEnabledRules } = require('./scanner/scan-file.js') as typeof import('./scanner/scan-file.js');
  const data = workerData as any;
  const rules = getEnabledRules(data.config);
  for (const file of data.files) {
    const result = scanFile(file, data.basePath, rules, data.config, data.minSeverity, data.noAiScore, undefined, data.includeTests);
    parentPort.postMessage({ type: 'result', result });
  }
  parentPort.postMessage({ type: 'done' });
  process.exit(0);
}

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import path from 'path';
import { existsSync } from 'fs';
import { scan } from './scanner/index.js';
import { scanDiff } from './diff/index.js';
import { report, printHeader } from './reporter/index.js';
import { renderSummary, renderFixPromptHint, writeBaseline, readBaseline } from './reporter/summary.js';
import { loadConfig } from './config/loader.js';
import { DEFAULT_CONFIG } from './config/defaults.js';
import { LogLevel, setLogLevel, setCiMode } from './utils/logger.js';
import { getAllRules, getRuleCount } from './scanner/rules/index.js';
import { ScanOptions, ScanResult, Severity } from './scanner/rules/types.js';
import type { OutputFormat } from './reporter/index.js';
import { writeFile } from './utils/file-utils.js';
import { generateFixPrompt } from './fix-prompt/index.js';
import { copyToClipboard, showInteractiveGroups, runWatch, CliOptions, buildScanOptions, buildDisplayResult, isInteractiveSession, shouldShowFixPromptHint } from './cli-helpers.js';

declare const __AISCOP_VERSION__: string | undefined;
const VERSION: string = (typeof __AISCOP_VERSION__ !== 'undefined' ? __AISCOP_VERSION__ : null)
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  ?? (require('../package.json') as { version: string }).version;

const program = new Command();

function addScanOptions(cmd: Command): Command {
  return cmd
    .argument('[path]', 'Path to scan (file or directory)', '.')
    .option('--fix', 'Auto-fix simple issues where possible')
    .option('--dry-run', 'Show what would be fixed without modifying files')
    .option('--watch', 'Watch for file changes and re-scan')
    .option('--ci', 'CI mode — no colors, no spinners, exit code reflects threshold status')
    .option('--format <format>', 'Output format: terminal | html | json', 'terminal')
    .option('--output <path>', 'Write report to file instead of stdout')
    .option('--severity <level>', 'Minimum severity to report: error | warn | info', 'warn')
    .option('--config <path>', 'Path to config file')
    .option('--debug', 'Enable debug logging')
    .option('--include-vendor', 'Include vendor/library files in scan')
    .option('--include-examples', 'Include examples/, demo/, fixtures/ directories in scan (excluded by default)')
    .option('--include-tests', 'Treat test files like production code (disables test-specific downgrades)')
    .option('--explain', 'Explain why a finding triggered (shows matched pattern and confidence)')
    .action(async (targetPath: string, opts: CliOptions) => {
      await runScan(targetPath, opts);
    });
}

addScanOptions(
  program
    .name('aicop')
    .description('🛡️ AICop — AI code quality & security scanner')
    .version(VERSION, '-v, --version', 'Output the current version')
    .enablePositionalOptions(),
);

program
  .command('init')
  .description('Generate a .aicoprc.json config file in the current directory')
  .action(async () => {
    const configPath = path.join(process.cwd(), '.aicoprc.json');
    const { writeFile: wf } = await import('./utils/file-utils.js');
    await wf(configPath, JSON.stringify(DEFAULT_CONFIG, null, 2));
    process.stdout.write(chalk.green('✓') + ` .aicoprc.json created at ${configPath}\n`);
    process.stdout.write(chalk.dim('Edit this file to customize rules, thresholds, and output settings.\n'));
    process.stdout.write(chalk.dim('Tip: aicop also auto-discovers .aicoprc.js, aicop.config.js, or an "aicop" key in package.json\n'));
  });

program
  .command('baseline')
  .description('Save the current AIScore as a baseline for future comparison')
  .option('--path <path>', 'Path to scan for baseline', '.')
  .option('--config <path>', 'Config file path')
  .action(async (opts: { path: string; config?: string }) => {
    const config = await loadConfig(process.cwd(), opts.config);
    const spinner = ora(chalk.dim('Scanning for baseline...')).start();
    try {
      const result = await scan({
        path: path.resolve(opts.path),
        config,
        severity: 'info',
        format: 'terminal',
        ci: false,
        fix: false,
        noAiScore: false,
        watch: false,
      });
      spinner.stop();
      writeBaseline(process.cwd(), result);
      process.stdout.write(
        chalk.green('✓') + ` Baseline saved: AIScore™ ${chalk.bold(String(result.aiScore))}/100 ` +
        chalk.dim(`(${result.errorCount} errors, ${result.warnCount} warnings, ${result.filesScanned} files)\n`) +
        chalk.dim('  Every future scan will show the delta against this baseline.\n')
      );
      const existing = readBaseline(process.cwd());
      void existing;
    } catch (err) {
      spinner.fail('Baseline scan failed');
      process.stderr.write(String(err) + '\n');
      process.exit(1);
    }
  });

async function detectDefaultBranch(): Promise<string> {
  try {
    const git = (await import('simple-git')).default(process.cwd());
    const result = await git.raw(['symbolic-ref', 'refs/remotes/origin/HEAD']);
    const trimmed = result.trim();
    const parts = trimmed.split('/');
    return parts[parts.length - 1] || 'HEAD~1';
  } catch {
    return 'HEAD~1';
  }
}

program
  .command('diff [ref]')
  .description('Scan only files changed since <ref> (default: auto-detected default branch)')
  .option('--ci', 'CI mode')
  .option('--format <format>', 'Output format', 'terminal')
  .option('--output <path>', 'Write report to file')
  .option('--severity <level>', 'Minimum severity', 'info')
  .option('--config <path>', 'Config file path')
  .action(async (ref: string | undefined, opts: Partial<CliOptions>) => {
    const gitRef = ref ?? await detectDefaultBranch();
    const config = await loadConfig(process.cwd(), opts.config);
    const ci = Boolean(opts.ci);
    if (ci) setCiMode(true);

    const scanOptions: ScanOptions = {
      path: '.',
      config,
      severity: (opts.severity as Severity) ?? 'info',
      format: (opts.format as ScanOptions['format']) ?? 'terminal',
      ci,
      fix: false,
      noAiScore: false,
      watch: false,
    };

    const spinner = ci ? null : ora(`Comparing with ${gitRef}...`).start();
    try {
      const { result, diffHeader } = await scanDiff(gitRef, scanOptions);
      spinner?.succeed('Diff scan complete');
      process.stdout.write(chalk.bold.cyan(diffHeader) + '\n\n');
      await report(result, {
        format: (opts.format as OutputFormat) ?? 'terminal',
        ci,
        outputPath: opts.output,
        version: VERSION,
      });
      process.exit(exitCode(result, ci));
    } catch (err) {
      spinner?.fail('Diff scan failed');
      process.stderr.write(String(err) + '\n');
      process.exit(1);
    }
  });

program
  .command('rules')
  .description('List all available rules')
  .option('--category <cat>', 'Filter by category: security | ai-smell | tech-debt')
  .action((opts: { category?: string }) => {
    const rules = getAllRules().filter((r) => !opts.category || r.category === opts.category);
    process.stdout.write(chalk.bold.white(`\n Available Rules (${rules.length})\n\n`));
    let currentCategory = '';
    for (const rule of rules) {
      if (rule.category !== currentCategory) {
        currentCategory = rule.category;
        process.stdout.write(chalk.bold.cyan(`  ${currentCategory}\n`));
      }
      const sev = rule.severity === 'error' ? chalk.red(rule.severity) : rule.severity === 'warn' ? chalk.yellow(rule.severity) : chalk.blue(rule.severity);
      process.stdout.write(`    ${chalk.white(rule.id.padEnd(44))} ${sev}\n`);
      process.stdout.write(chalk.dim(`      ${rule.description}\n`));
    }
    process.stdout.write('\n');
  });

program
  .command('report')
  .description('Convert an existing JSON scan result to HTML or terminal format')
  .requiredOption('--input <path>', 'Path to JSON scan result')
  .option('--format <format>', 'Output format: terminal | html', 'html')
  .option('--output <path>', 'Output file path')
  .action(async (opts: { input: string; format: string; output?: string }) => {
    const { readFileContent } = await import('./utils/file-utils.js');
    const raw = await readFileContent(opts.input);
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      process.stderr.write(chalk.red(`\nInvalid JSON in ${opts.input}\n`));
      process.exit(1);
    }
    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    await report(parsed.files ? parsed as never : { ...parsed, files: [] } as never, {
      format: opts.format as OutputFormat,
      ci: false,
      outputPath: opts.output,
      version: VERSION,
    });
  });

program
  .command('fix-prompt [path]')
  .description('Generate an AI fix prompt for all issues found in the target path')
  .option('--severity <level>', 'Minimum severity to include: error | warn | info', 'warn')
  .option('--output <file>', 'Write prompt to a file instead of printing to terminal')
  .option('--clipboard', 'Copy the generated prompt to the system clipboard')
  .option('--no-snippets', 'Omit code snippets from the prompt')
  .option('--config <path>', 'Path to config file')
  .action(async (targetPath: string | undefined, opts: {
    severity: string;
    output?: string;
    clipboard?: boolean;
    snippets?: boolean;
    config?: string;
  }) => {
    const target = targetPath ?? '.';
    const resolvedTarget = path.resolve(process.cwd(), target);

    if (!existsSync(resolvedTarget)) {
      process.stderr.write(chalk.red(`\nPath not found: ${resolvedTarget}\n`));
      process.exit(2);
    }

    const config = await loadConfig(process.cwd(), opts.config);
    const spinner = ora(chalk.dim('Scanning for issues...')).start();

    try {
      const result = await scan({
        path: resolvedTarget,
        config,
        severity: 'info', // always scan all, filter in generator
        format: 'terminal',
        ci: true,
        fix: false,
        noAiScore: true,
        watch: false,
      });
      spinner.succeed(chalk.green(`Scanned ${result.filesScanned} files`));

      const prompt = generateFixPrompt(result, {
        minSeverity: (opts.severity as Severity) ?? 'warn',
        includeSnippets: opts.snippets !== false,
        targetPath: resolvedTarget,
      });

      if (opts.clipboard) {
        await copyToClipboard(prompt);
        process.stdout.write(chalk.green('\n✅ Fix prompt copied to clipboard!\n'));
        process.stdout.write(chalk.dim('   Paste it into Claude, Cursor, ChatGPT, or any AI assistant.\n\n'));
        return;
      }

      if (opts.output) {
        await writeFile(opts.output, prompt);
        process.stdout.write(chalk.green(`\n✅ Fix prompt saved to: ${opts.output}\n\n`));
        return;
      }

      process.stdout.write('\n');
      process.stdout.write(chalk.bold.cyan('━'.repeat(72)) + '\n');
      process.stdout.write(chalk.bold.white('  🤖 AICop AI Fix Prompt\n'));
      process.stdout.write(chalk.dim('  Copy this prompt and paste it into Claude, Cursor, or ChatGPT\n'));
      process.stdout.write(chalk.bold.cyan('━'.repeat(72)) + '\n\n');
      process.stdout.write(prompt + '\n\n');
      process.stdout.write(chalk.dim('  Tip: Run with ') + chalk.cyan('--clipboard') + chalk.dim(' to copy automatically, or ') + chalk.cyan('--output prompt.txt') + chalk.dim(' to save to file.\n\n'));
    } catch (err) {
      spinner.fail('Scan failed');
      process.stderr.write(String(err) + '\n');
      process.exit(1);
    }
  });

function getBadgeColor(score: number): string {
  if (score >= 85) return 'brightgreen';
  if (score >= 70) return 'yellow';
  if (score >= 50) return 'orange';
  return 'red';
}

function getScoreEmoji(score: number): string {
  if (score >= 90) return '🟢';
  if (score >= 70) return '🟡';
  if (score >= 50) return '🟠';
  return '🔴';
}

program
  .command('badge [path]')
  .description('Generate an AIScore badge URL for your README')
  .option('--style <style>', 'Badge style: flat | flat-square | for-the-badge', 'flat')
  .option('--output <format>', 'Output format: markdown | url', 'markdown')
  .option('--config <path>', 'Config file path')
  .action(async (targetPath: string | undefined, opts: { style: string; output: string; config?: string }) => {
    const target = targetPath ?? '.';
    const resolvedTarget = path.resolve(process.cwd(), target);
    if (!existsSync(resolvedTarget)) {
      process.stderr.write(chalk.red(`\nPath not found: ${resolvedTarget}\n`));
      process.exit(2);
    }
    const config = await loadConfig(process.cwd(), opts.config);
    const spinner = ora(chalk.dim('Scanning for AIScore…')).start();
    try {
      const result = await scan({
        path: resolvedTarget,
        config,
        severity: 'info',
        format: 'terminal',
        ci: true,
        fix: false,
        noAiScore: false,
        watch: false,
      });
      spinner.succeed(chalk.green(`Scanned ${result.filesScanned} files`));
      const score = result.aiScore;
      const color = getBadgeColor(score);
      const badgeUrl = `https://img.shields.io/badge/AIScore-${score}%2F100-${color}?label=AICop&style=${opts.style}`;
      const markdown = `[![AIScore](${badgeUrl})](https://github.com/CayMac97/aicop)`;
      const scoreEmoji = getScoreEmoji(score);
      const W = 63;
      const line = (inner: string): string => `│${inner.padEnd(W - 2)}│`;
      process.stdout.write('\n');
      process.stdout.write('┌' + '─'.repeat(W - 2) + '┐\n');
      process.stdout.write(line('  AICop Badge generated!') + '\n');
      process.stdout.write(line('') + '\n');
      process.stdout.write(line(`  AIScore: ${score}/100 ${scoreEmoji}`) + '\n');
      process.stdout.write(line('') + '\n');
      process.stdout.write(line('  Add this to your README.md:') + '\n');
      process.stdout.write(line('') + '\n');
      process.stdout.write(line(`  ${markdown}`) + '\n');
      process.stdout.write(line('') + '\n');
      let clipLine = '  (Could not copy to clipboard automatically)';
      try {
        await copyToClipboard(markdown);
        clipLine = '  Copied to clipboard! ✅';
      } catch { /* clipboard unavailable */ }
      process.stdout.write(line(clipLine) + '\n');
      process.stdout.write('└' + '─'.repeat(W - 2) + '┘\n\n');
      if (opts.output === 'url') {
        process.stdout.write(badgeUrl + '\n');
      } else {
        process.stdout.write(markdown + '\n');
      }
      process.exit(0);
    } catch (err) {
      spinner.fail('Scan failed');
      process.stderr.write(String(err) + '\n');
      process.exit(1);
    }
  });

program
  .command('scan [path]')
  .description('Scan a directory or file for security, AI-smell and tech-debt issues')
  .option('--ci', 'CI mode — no colors, no spinners, exit code reflects threshold status')
  .option('--format <format>', 'Output format: terminal | html | json', 'terminal')
  .option('--output <path>', 'Write report to file instead of stdout')
  .option('--severity <level>', 'Minimum severity to report: error | warn | info', 'warn')
  .option('--ignore <patterns...>', 'Additional glob patterns to exclude')
  .option('--fix', 'Auto-fix simple issues where possible')
  .option('--dry-run', 'Show what would be fixed without modifying files')
  .option('--no-ai-score', 'Omit per-file AI smell scores')
  .option('--rule <rules...>', 'Only run specific rules')
  .option('--config <path>', 'Path to config file')
  .option('--watch', 'Watch for file changes and re-scan')
  .option('--debug', 'Enable debug logging')
  .option('--include-vendor', 'Include vendor/library files in scan')
  .option('--include-examples', 'Include examples/, demo/, fixtures/ directories in scan (excluded by default)')
  .option('--include-tests', 'Treat test files like production code (disables test-specific downgrades)')
  .option('--explain', 'Explain why a finding triggered (shows matched pattern and confidence)')
  .action(async (targetPath: string | undefined, opts: CliOptions) => {
    await runScan(targetPath ?? '.', opts);
  });

async function writeOutput(displayResult: ScanResult, opts: CliOptions, ci: boolean, targetPath: string, isInteractive: boolean): Promise<void> {
  const format = opts.format as OutputFormat;
  const isFileOutput = format !== 'terminal' || Boolean(opts.output);
  if (isInteractive && !isFileOutput) {
    process.stdout.write(renderSummary(displayResult, false) + '\n');
    await showInteractiveGroups(displayResult, targetPath, VERSION, opts.explain);
  } else {
    await report(displayResult, { format, ci, outputPath: opts.output, version: VERSION, explain: opts.explain });
    if (isInteractive) {
      process.stdout.write(renderSummary(displayResult, false) + '\n');
    }
  }
}

async function handleScanResult(result: ScanResult, opts: CliOptions, ci: boolean, targetPath: string, displaySeverity: Severity = 'warn'): Promise<void> {
  const { displayResult, hiddenInfoCount } = buildDisplayResult(result, displaySeverity);
  const isInteractive = isInteractiveSession(opts, ci);
  try {
    await writeOutput(displayResult, opts, ci, targetPath, isInteractive);
    if (shouldShowFixPromptHint(displayResult, opts, ci)) {
      process.stdout.write(renderFixPromptHint(targetPath) + '\n');
    }
    if (hiddenInfoCount > 0 && !ci && !opts.output) {
      process.stdout.write(chalk.blue(`\nℹ  ${hiddenInfoCount} info finding${hiddenInfoCount === 1 ? '' : 's'} — run with --severity info to see per-file locations\n`));
    }
    const code = exitCode(displayResult, ci);
    if (ci && code !== 0) {
      process.stderr.write(`\nThreshold exceeded — exit code ${code}\n`);
    }
    process.exit(code);
  } catch (err) {
    throw new Error(`Report failed: ${String(err)}`);
  }
}

async function runScan(targetPath: string, opts: CliOptions): Promise<void> {
  const ci = Boolean(opts.ci);
  if (ci) setCiMode(true);
  if (opts.debug) setLogLevel(LogLevel.DEBUG);

  const resolvedTarget = path.resolve(process.cwd(), targetPath);
  if (!existsSync(resolvedTarget)) {
    process.stderr.write(chalk.red(`\nPath not found: ${resolvedTarget}\n`) + chalk.dim('  Make sure the path exists and is accessible.\n\n'));
    process.exit(2);
  }

  const config = await loadConfig(resolvedTarget, opts.config);
  if (opts.ignore && opts.ignore.length > 0) {
    config.exclude.push(...opts.ignore);
  }

  const displaySeverity: Severity = (opts.severity as Severity) ?? 'warn';
  const scanOptions = buildScanOptions(resolvedTarget, config, opts, displaySeverity);

  const isFileFormat = (opts.format as string) === 'json' || (opts.format as string) === 'html';
  const spinner = (ci || isFileFormat) ? null : ora(chalk.dim('Collecting files...')).start();
  const ruleCount = getRuleCount();

  const onProgress = (file: string): void => {
    if (spinner) spinner.text = chalk.dim(`Scanning… ${path.basename(file)}`);
  };

  if (!ci && !isFileFormat) {
    spinner?.stop();
    printHeader(0, ruleCount, VERSION, ci);
    spinner?.start(chalk.dim('Collecting files...'));
  }

  try {
    let result = await scan(scanOptions, onProgress);
    if (result.filesScanned === 0) {
      spinner?.fail(chalk.yellow('No scannable files found'));
      const target = path.resolve(targetPath);
      const noFilesMsg =
        chalk.yellow('\n  ⚠  No JS/TS files found in ') + chalk.bold(target) + '\n' +
        chalk.dim('     AICop scans: .ts .tsx .js .jsx .mjs .cjs .mts .cts\n\n');
      if (isFileFormat) {
        process.stderr.write(noFilesMsg);
      } else {
        process.stdout.write(noFilesMsg);
      }
      process.exit(0);
    }

    if (opts.fix || opts.dryRun) {
      const { applyFixes } = await import('./fixer/index.js');
      await applyFixes(result, { dryRun: opts.dryRun });
      if (!opts.dryRun) {
         const rescanResult = await scan(scanOptions, onProgress);
         Object.assign(result, rescanResult);
      }
    }

    spinner?.succeed(chalk.green(`Scanned ${result.filesScanned} files in ${result.scanDurationMs}ms`));
    await handleScanResult(result, opts, ci, resolvedTarget, displaySeverity);
  } catch (err) {
    spinner?.fail('Scan failed');
    process.stderr.write(String(err) + '\n');
    process.exit(1);
  }
}

function exitCode(result: { errorCount: number; warnCount: number; aiScore: number }, ci: boolean): number {
  if (!ci) return 0;
  if (result.errorCount > 0) return 1;
  return 0;
}

program.hook('preAction', (_thisCommand, actionCommand) => {
  const opts = actionCommand.opts<CliOptions & { watch?: boolean }>();
  if (opts.watch) {
    const args = actionCommand.args;
    const targetPath = args[0] ?? '.';
    void runWatch(targetPath, runScan as (t: string, o: unknown) => Promise<void>, opts);
    process.exitCode = 0;
  }
});

program.parse(process.argv);

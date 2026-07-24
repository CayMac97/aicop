import chokidar from 'chokidar';
import chalk from 'chalk';
import path from 'path';
import { scan } from '../scanner/index.js';
import { loadConfig } from '../config/loader.js';
import { report } from '../reporter/index.js';
import { renderSummary } from '../reporter/summary.js';
import { buildDisplayResult } from '../cli-helpers.js';

export async function runAgentWatcher(targetPath: string): Promise<void> {
  const resolvedTarget = path.resolve(process.cwd(), targetPath);
  const config = await loadConfig(process.cwd());

  console.log(chalk.blue(`\n👀 AICop Native Agent initialized. Watching for changes in ${resolvedTarget}...\n`));

  const watcher = chokidar.watch(resolvedTarget, {
    ignored: config.exclude,
    persistent: true,
    ignoreInitial: true,
  });

  let isScanning = false;

  watcher.on('change', async (filePath) => {
    if (isScanning) return;
    
    // Only scan supported files
    if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(filePath)) return;

    isScanning = true;
    console.log(chalk.dim(`\nFile changed: ${filePath}`));
    console.log(chalk.dim('Triggering instantaneous AICop scan...'));

    try {
      const result = await scan({
        path: filePath, // Just scan the changed file for extreme speed
        config,
        severity: 'info',
        format: 'terminal',
        ci: false,
        fix: false,
        noAiScore: false,
        watch: false,
      });

      const { displayResult } = buildDisplayResult(result, 'warn');
      
      if (displayResult.errorCount > 0 || displayResult.warnCount > 0) {
        console.log(chalk.yellow('\n⚠️ Issues detected during edit:\n'));
        await report(displayResult, { format: 'terminal', ci: false, version: '1.1.2' });
        console.log(renderSummary(displayResult, false));
      } else {
        console.log(chalk.green('✅ Clean. Vibe coding nominal.'));
      }
    } catch (err) {
      console.error(chalk.red(`\nScan failed on change: ${String(err)}`));
    } finally {
      isScanning = false;
    }
  });

  watcher.on('error', (error) => {
    console.error(chalk.red(`Watcher error: ${error}`));
  });
}

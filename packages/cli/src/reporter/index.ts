import { ScanResult } from '../scanner/rules/types.js';
import { formatTerminal } from './terminal.js';
import { formatJson } from './json.js';
import { formatHtml } from './html.js';
import { renderSummary, renderHeader } from './summary.js';
import { writeFile } from '../utils/file-utils.js';
import { logger } from '../utils/logger.js';

export type OutputFormat = 'terminal' | 'html' | 'json';

export interface ReporterOptions {
  format: OutputFormat;
  ci: boolean;
  outputPath?: string;
  version: string;
}

export async function report(result: ScanResult, options: ReporterOptions): Promise<void> {
  const { format, ci, outputPath, version } = options;
  try {
    if (format === 'json') {
      const json = formatJson(result);
      if (outputPath) {
        await writeFile(outputPath, json);
        logger.info(`JSON report written to ${outputPath}`);
      } else {
        process.stdout.write(json + '\n');
      }
      return;
    }

    if (format === 'html') {
      const html = formatHtml(result, version);
      const dest = outputPath ?? '.vibescan/report.html';
      await writeFile(dest, html);
      logger.info(`HTML report written to ${dest}`);
      return;
    }

    const body = formatTerminal(result, ci);
    const summary = renderSummary(result, ci);

    if (outputPath) {
      const combined = stripAnsi(body + '\n' + summary);
      await writeFile(outputPath, combined);
      logger.info(`Report written to ${outputPath}`);
      return;
    }

    process.stdout.write(body + '\n');
    process.stdout.write(summary + '\n');
  } catch (err) {
    throw new Error(`Report generation failed: ${String(err)}`);
  }
}

export function printHeader(fileCount: number, ruleCount: number, version: string, ci: boolean): void {
  const header = renderHeader(fileCount, ruleCount, version, ci);
  process.stdout.write(header + '\n');
}

function stripAnsi(str: string): string {
  // eslint-disable-next-line no-control-regex
  return str.replace(/\x1b\[[0-9;]*m/g, '');
}

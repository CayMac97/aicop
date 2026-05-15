import * as path from 'path';

export interface Finding {
  ruleId: string;
  severity: 'error' | 'warn' | 'info';
  message: string;
  file: string;
  line: number;
  column: number;
  snippet: string;
  fix?: string;
}

export interface FileScanResult {
  filePath: string;
  relativePath: string;
  findings: Finding[];
  aiScore: number;
  parseError?: string;
}

export interface ScanResult {
  files: FileScanResult[];
  totalFindings: number;
  errorCount: number;
  warnCount: number;
  infoCount: number;
  vibeScore: number;
  scanDurationMs: number;
  filesScanned: number;
  filesWithIssues: number;
}

interface VibeCopLib {
  scan: (options: {
    path: string;
    config: unknown;
    severity: string;
    format: string;
    ci: boolean;
    fix: boolean;
    noAiScore: boolean;
    watch: boolean;
  }) => Promise<ScanResult>;
  loadConfig: (searchFrom?: string) => Promise<unknown>;
  DEFAULT_CONFIG: unknown;
  generateFixPrompt: (scanResult: ScanResult, options: {
    minSeverity: 'error' | 'warn' | 'info';
    includeSnippets: boolean;
    targetPath?: string;
  }) => string;
}

function loadLib(): VibeCopLib {
  const libPath = path.join(__dirname, '..', '..', 'cli', 'dist', 'lib.js');
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    return require(libPath) as VibeCopLib;
  } catch (err) {
    throw new Error(
      `VibeCop: could not load scanner library from ${libPath}.\n` +
      `Run 'npm run build' in packages/cli first.\n` +
      String(err),
    );
  }
}

export async function scanFile(
  filePath: string,
  minSeverity: 'info' | 'warn' | 'error' = 'warn',
): Promise<{ findings: Finding[]; vibeScore: number }> {
  const lib = loadLib();
  const config = await lib.loadConfig(path.dirname(filePath));
  const result = await lib.scan({
    path: filePath,
    config,
    severity: minSeverity,
    format: 'terminal',
    ci: true,
    fix: false,
    noAiScore: false,
    watch: false,
  });
  const findings = result.files.flatMap((f) => f.findings);
  return { findings, vibeScore: result.vibeScore };
}

export async function generateFixPromptForFile(
  filePath: string,
): Promise<string> {
  const lib = loadLib();
  const config = await lib.loadConfig(path.dirname(filePath));
  const result = await lib.scan({
    path: filePath,
    config,
    severity: 'info',
    format: 'terminal',
    ci: true,
    fix: false,
    noAiScore: true,
    watch: false,
  });
  return lib.generateFixPrompt(result, {
    minSeverity: 'warn',
    includeSnippets: true,
    targetPath: path.dirname(filePath),
  });
}

export async function scanDirectory(
  dirPath: string,
  minSeverity: 'info' | 'warn' | 'error' = 'warn',
): Promise<ScanResult> {
  const lib = loadLib();
  const config = await lib.loadConfig(dirPath);
  return lib.scan({
    path: dirPath,
    config,
    severity: minSeverity,
    format: 'terminal',
    ci: true,
    fix: false,
    noAiScore: false,
    watch: false,
  });
}

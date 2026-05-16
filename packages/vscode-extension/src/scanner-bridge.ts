import * as path from 'path';
import * as fs from 'fs';

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

interface FixPromptOptions {
  minSeverity: 'error' | 'warn' | 'info';
  includeSnippets: boolean;
  targetPath?: string;
}

interface AICopLib {
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
  generateFixPrompt: (scanResult: ScanResult, options: FixPromptOptions) => string;
}

let cachedLib: AICopLib | null = null;

export function computeFileVibeScore(findings: Finding[]): number {
  const secErrCount = findings.filter((f) => f.ruleId.startsWith('security/') && f.severity === 'error').length;
  const secErrPenalty = Math.min(
    Math.min(secErrCount, 3) * 8 +
    Math.max(0, Math.min(secErrCount - 3, 3)) * 5 +
    Math.max(0, secErrCount - 6) * 3,
    50,
  );
  const secWarnPenalty = Math.min(findings.filter((f) => f.ruleId.startsWith('security/') && f.severity === 'warn').length * 3, 15);
  const aiErrPenalty   = Math.min(findings.filter((f) => f.ruleId.startsWith('ai-smell/') && f.severity === 'error').length * 5, 10);
  const aiWarnPenalty  = Math.min(findings.filter((f) => f.ruleId.startsWith('ai-smell/') && f.severity === 'warn').length, 10);
  const techPenalty    = Math.min(findings.filter((f) => f.ruleId.startsWith('tech-debt/') && f.severity === 'warn').length * 0.5, 5);
  return Math.max(0, Math.round(100 - (secErrPenalty + secWarnPenalty + aiErrPenalty + aiWarnPenalty + techPenalty)));
}

function loadLib(): AICopLib {
  if (cachedLib) return cachedLib;
  const libPath = path.join(__dirname, '..', '..', 'cli', 'dist', 'lib.js');
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    cachedLib = require(libPath) as AICopLib;
    return cachedLib;
  } catch (err) {
    throw new Error(
      `AICop: could not load scanner from ${libPath} — run 'npm run build' in packages/cli first.\n${String(err)}`,
    );
  }
}

function mergeRuleOverrides(
  config: unknown,
  overrides: Record<string, string>,
): unknown {
  if (!overrides || Object.keys(overrides).length === 0) return config;
  const base = config as Record<string, unknown>;
  return {
    ...base,
    rules: { ...(base['rules'] as Record<string, unknown> ?? {}), ...overrides },
  };
}

export async function scanFile(
  filePath: string,
  minSeverity: 'info' | 'warn' | 'error' = 'warn',
  ruleOverrides: Record<string, string> = {},
): Promise<{ findings: Finding[]; vibeScore: number }> {
  const lib = loadLib();
  const rawConfig = await lib.loadConfig(path.dirname(filePath));
  const config = mergeRuleOverrides(rawConfig, ruleOverrides);
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
  return { findings: result.files.flatMap((f) => f.findings), vibeScore: result.vibeScore };
}

export async function scanDirectory(
  dirPath: string,
  minSeverity: 'info' | 'warn' | 'error' = 'warn',
  ruleOverrides: Record<string, string> = {},
): Promise<ScanResult> {
  const lib = loadLib();
  const rawConfig = await lib.loadConfig(dirPath);
  const config = mergeRuleOverrides(rawConfig, ruleOverrides);
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

export interface BaselineData {
  vibeScore: number;
  errorCount: number;
  warnCount: number;
  filesScanned: number;
  date?: string;
  savedAt?: string;
}

export function loadBaseline(workspaceRoot: string): BaselineData | null {
  const p = path.join(workspaceRoot, '.aicop-baseline.json');
  try {
    const raw = fs.readFileSync(p, 'utf8');
    return JSON.parse(raw) as BaselineData;
  } catch {
    return null;
  }
}

export function saveBaseline(workspaceRoot: string, result: ScanResult): void {
  const data: BaselineData = {
    vibeScore: result.vibeScore,
    errorCount: result.errorCount,
    warnCount: result.warnCount,
    filesScanned: result.filesScanned,
    date: new Date().toISOString().slice(0, 10),
  };
  fs.writeFileSync(
    path.join(workspaceRoot, '.aicop-baseline.json'),
    JSON.stringify(data, null, 2),
    'utf8',
  );
}

export async function generateFixPromptForFile(filePath: string): Promise<string> {
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

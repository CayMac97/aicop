import { TSESTree } from '@typescript-eslint/typescript-estree';

/** The parsed AST program node */
export type ParsedAST = TSESTree.Program;

/** Finding severity levels */
export type Severity = 'error' | 'warn' | 'info';

/** Rule categories */
export type Category = 'security' | 'ai-smell' | 'tech-debt';

/** A single finding produced by a rule */
export interface Finding {
  ruleId: string;
  severity: Severity;
  message: string;
  file: string;
  line: number;
  column: number;
  snippet: string;
  fix?: string;
  fixCode?: string;
}

/** Interface every rule must implement */
export interface Rule {
  id: string;
  name: string;
  category: Category;
  severity: Severity;
  description: string;
  why: string;
  fix: string;
  /** Optional concrete code example used by the fix-prompt generator */
  fixCode?: string;
  check(ast: ParsedAST, source: string, filePath: string): Finding[];
}

/** Scan result for a single file */
export interface FileScanResult {
  filePath: string;
  relativePath: string;
  findings: Finding[];
  aiScore: number;
  parseError?: string;
}

/** Overall scan result across all files */
export interface ScanResult {
  files: FileScanResult[];
  totalFindings: number;
  errorCount: number;
  warnCount: number;
  infoCount: number;
  vibeScore: number;
  categoryScores?: {
    security: number;
    aiSmell: number;
    techDebt: number;
  };
  scanDurationMs: number;
  filesScanned: number;
  filesWithIssues: number;
  topIssues: Array<{ ruleId: string; fileCount: number }>;
  skippedVendorFiles: number;
  parseErrors: number;
}

/** Threshold configuration */
export interface Thresholds {
  maxErrors: number;
  maxWarnings: number;
  minAIScore: number;
}

/** Output configuration */
export interface OutputConfig {
  format: 'terminal' | 'html' | 'json';
  htmlReportPath: string;
}

/** AICop configuration file structure */
export interface VibescanConfig {
  version: string;
  include: string[];
  exclude: string[];
  rules: Record<string, Severity | 'off'>;
  thresholds: Thresholds;
  output: OutputConfig;
  includeExamples?: boolean;
}

/** CLI scan options assembled from args + config */
export interface ScanOptions {
  path: string;
  config: VibescanConfig;
  format: 'terminal' | 'html' | 'json';
  output?: string;
  severity: Severity;
  ci: boolean;
  fix: boolean;
  noAiScore: boolean;
  watch: boolean;
  ruleId?: string;
  ignore?: string[];
  includeVendor?: boolean;
  includeExamples?: boolean;
}

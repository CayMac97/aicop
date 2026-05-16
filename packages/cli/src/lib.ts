/**
 * AICop programmatic API — imported by the VSCode extension and other tools.
 * Does NOT include Commander / chalk / ora (no CLI boilerplate).
 */
export { scan } from './scanner/index.js';
export { loadConfig } from './config/loader.js';
export { DEFAULT_CONFIG } from './config/defaults.js';
export { generateFixPrompt } from './fix-prompt/index.js';
export type {
  ScanOptions,
  ScanResult,
  FileScanResult,
  Finding,
  Severity,
  VibescanConfig,
} from './scanner/rules/types.js';
export type { FixPromptOptions } from './fix-prompt/index.js';

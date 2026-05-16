import { VibescanConfig, Severity } from '../scanner/rules/types.js';
import { DEFAULT_CONFIG } from './defaults.js';

const VALID_SEVERITIES = new Set<string>(['error', 'warn', 'info', 'off']);
const VALID_FORMATS = new Set<string>(['terminal', 'html', 'json']);

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  config: VibescanConfig;
}

function validateRules(rules: unknown): string[] {
  const errors: string[] = [];
  if (!rules || typeof rules !== 'object' || Array.isArray(rules)) {
    errors.push('"rules" must be an object');
    return errors;
  }
  for (const [key, value] of Object.entries(rules as Record<string, unknown>)) {
    if (typeof value !== 'string' || !VALID_SEVERITIES.has(value)) {
      errors.push(`Rule "${key}" has invalid severity "${String(value)}" — must be error | warn | info | off`);
    }
  }
  return errors;
}

function validateThresholds(thresholds: unknown): string[] {
  const errors: string[] = [];
  if (!thresholds || typeof thresholds !== 'object' || Array.isArray(thresholds)) {
    return errors;
  }
  const t = thresholds as Record<string, unknown>;
  if (t.maxErrors !== undefined && typeof t.maxErrors !== 'number') {
    errors.push('"thresholds.maxErrors" must be a number');
  }
  if (t.maxWarnings !== undefined && typeof t.maxWarnings !== 'number') {
    errors.push('"thresholds.maxWarnings" must be a number');
  }
  if (t.minAIScore !== undefined && typeof t.minAIScore !== 'number') {
    errors.push('"thresholds.minAIScore" must be a number');
  }
  return errors;
}

function validateOutput(output: unknown): string[] {
  if (!output || typeof output !== 'object' || Array.isArray(output)) return [];
  const o = output as Record<string, unknown>;
  if (o.format !== undefined && !VALID_FORMATS.has(String(o.format))) {
    return [`"output.format" must be terminal | html | json, got "${String(o.format)}"`];
  }
  return [];
}

function mergeWithDefaults(obj: Record<string, unknown>): VibescanConfig {
  return {
    version: String(obj.version ?? DEFAULT_CONFIG.version),
    include: Array.isArray(obj.include) ? obj.include as string[] : DEFAULT_CONFIG.include,
    exclude: Array.isArray(obj.exclude) ? obj.exclude as string[] : DEFAULT_CONFIG.exclude,
    rules: { ...DEFAULT_CONFIG.rules, ...(obj.rules as Record<string, Severity | 'off'> ?? {}) },
    thresholds: { ...DEFAULT_CONFIG.thresholds, ...(obj.thresholds as VibescanConfig['thresholds'] ?? {}) },
    output: { ...DEFAULT_CONFIG.output, ...(obj.output as VibescanConfig['output'] ?? {}) },
  };
}

export function validateConfig(raw: unknown): ValidationResult {
  const errors: string[] = [];

  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { valid: false, errors: ['Config must be an object'], config: DEFAULT_CONFIG };
  }

  const obj = raw as Record<string, unknown>;

  if (obj.version !== undefined && obj.version !== '1') {
    errors.push(`Unknown config version "${String(obj.version)}" — only "1" is supported`);
  }

  if (obj.rules !== undefined) {
    errors.push(...validateRules(obj.rules));
  }

  if (obj.thresholds !== undefined) {
    errors.push(...validateThresholds(obj.thresholds));
  }

  if (obj.output !== undefined) {
    errors.push(...validateOutput(obj.output));
  }

  if (errors.length > 0) {
    return { valid: false, errors, config: DEFAULT_CONFIG };
  }

  return { valid: true, errors: [], config: mergeWithDefaults(obj) };
}

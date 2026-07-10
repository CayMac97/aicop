import { parentPort, workerData } from 'node:worker_threads';
import { scanFile, getEnabledRules, PARSE_OPTIONS } from './scan-file.js';
import { VibescanConfig, Severity } from './rules/types.js';
import { parse } from '@typescript-eslint/typescript-estree';
import path from 'node:path';

export interface WorkerData {
  files: string[];
  basePath: string;
  config: VibescanConfig;
  minSeverity: Severity;
  noAiScore: boolean;
  includeTests: boolean;
  ruleId?: string;
}

if (parentPort) {
  const data = workerData as WorkerData;
  const rules = getEnabledRules(data.config, data.ruleId);

  for (const file of data.files) {
    try {
      const result = scanFile(file, data.basePath, rules, data.config, data.minSeverity, data.noAiScore, undefined, undefined, data.includeTests);
      parentPort.postMessage({ type: 'result', result });
    } catch (err) {
      parentPort.postMessage({ type: 'result', result: { filePath: file, relativePath: file, findings: [], aiScore: 0, parseError: String(err) }});
    }
  }

  parentPort.postMessage({ type: 'done' });
}
